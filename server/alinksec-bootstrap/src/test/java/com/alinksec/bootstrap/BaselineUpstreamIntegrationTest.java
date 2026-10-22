package com.alinksec.bootstrap;

import com.alinksec.common.util.*;
import com.alinksec.gateway.rest.*;
import com.alinksec.service.baseline.*;
import com.alinksec.service.command.CommandService;
import com.alinksec.service.config.*;
import com.alinksec.service.library.*;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.sun.net.httpserver.HttpServer;
import com.zaxxer.hikari.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.aop.framework.ProxyFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.test.web.servlet.*;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.annotation.AnnotationTransactionAttributeSource;
import org.springframework.transaction.interceptor.TransactionInterceptor;
import java.io.*;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.util.zip.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;

/** Real HTTP publisher, crypto, migrations, multi-connection transactions and REST/RBAC.
 * The same suite runs against SQLite and the PostgreSQL application role. */
class BaselineUpstreamIntegrationTest {
    @TempDir Path root;
    HikariDataSource pool;JdbcTemplate jdbc;DataSourceTransactionManager manager;
    BaselineUpstreamService service;BaselinePackageService baseline;ScapPackageService scap;
    BaselineUpstreamProperties props;BaselineUpstreamProperties.Source publisher;
    HttpServer http;ExecutorService httpWorkers;MockMvc mvc;
    KeyPair keys;String base,sourceId,code,scapCode;
    AtomicReference<byte[]> index=new AtomicReference<>(new byte[0]);
    Map<String,byte[]> artifacts=new ConcurrentHashMap<>();
    AtomicInteger requests=new AtomicInteger(),conditional=new AtomicInteger(),artifactRequests=new AtomicInteger();
    volatile CountDownLatch artifactStarted,artifactContinue;
    volatile int artifactStatus=200;
    volatile boolean forcedNotModified;
    FeedDownload downloader;
    static final String SECRET="upstream-integration-secret-at-least-32-bytes";
    @BeforeEach void setup()throws Exception{
        boolean pg="postgres".equals(System.getProperty("alinksec.integration.database"));
        var config=new HikariConfig();config.setJdbcUrl(pg?System.getenv("ALINKSEC_INTEGRATION_PG_URL"):"jdbc:sqlite:"+root.resolve("db"));
        if(pg){config.setUsername(System.getenv("ALINKSEC_INTEGRATION_PG_USER"));config.setPassword(System.getenv("ALINKSEC_INTEGRATION_PG_PASSWORD"));}
        else{config.addDataSourceProperty("transaction_mode","IMMEDIATE");config.addDataSourceProperty("busy_timeout",5000);config.addDataSourceProperty("foreign_keys",true);}
        config.setMaximumPoolSize(4);config.setMinimumIdle(1);pool=new HikariDataSource(config);
        if(!pg)new SqliteDatabaseConfiguration.SqliteMigrationBeanPostProcessor().postProcessAfterInitialization(pool,"dataSource");
        jdbc=new JdbcTemplate(pool);manager=new DataSourceTransactionManager(pool);
        String suffix=UUID.randomUUID().toString().replace("-","");sourceId="upstream-"+suffix;code="UP-"+suffix;scapCode="SC-"+suffix;
        http=HttpServer.create(new InetSocketAddress("127.0.0.1",0),0);httpWorkers=Executors.newCachedThreadPool();http.setExecutor(httpWorkers);
        http.createContext("/index.json",exchange->{
            requests.incrementAndGet();String etag="\""+ScapPackage.digest(index.get())+"\"";
            if(forcedNotModified||etag.equals(exchange.getRequestHeaders().getFirst("If-None-Match"))){conditional.incrementAndGet();exchange.sendResponseHeaders(304,-1);}
            else{byte[] bytes=index.get();exchange.getResponseHeaders().set("ETag",etag);exchange.sendResponseHeaders(200,bytes.length);exchange.getResponseBody().write(bytes);}exchange.close();
        });
        http.createContext("/artifacts/",exchange->{
            artifactRequests.incrementAndGet();
            if(artifactStarted!=null){artifactStarted.countDown();try{artifactContinue.await(10,TimeUnit.SECONDS);}catch(InterruptedException e){Thread.currentThread().interrupt();}}
            byte[] bytes=artifacts.getOrDefault(exchange.getRequestURI().getPath(),new byte[0]);
            if(artifactStatus==302){exchange.getResponseHeaders().set("Location",base+"/redirect-target");exchange.sendResponseHeaders(302,-1);}
            else{exchange.sendResponseHeaders(artifactStatus,bytes.length);exchange.getResponseBody().write(bytes);}exchange.close();
        });
        http.start();base="http://127.0.0.1:"+http.getAddress().getPort();keys=KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        publisher=new BaselineUpstreamProperties.Source();publisher.setId(sourceId);publisher.setName("Signed baseline fixture");publisher.setUrl(base+"/index.json");publisher.setPublicKey(Base64.getEncoder().encodeToString(keys.getPublic().getEncoded()));publisher.setEnabled(true);publisher.setScopes(List.of("baseline:"+code,"scap:"+scapCode));
        props=new BaselineUpstreamProperties();props.setSources(List.of(publisher));
        var platform=new AlinkSecProperties();platform.getDatabase().setType(pg?"postgres":"sqlite");var commands=mock(CommandService.class);
        var tasks=transactional(new BaselineTaskService(jdbc,commands,new DatabaseDialect(platform)));baseline=transactional(new BaselinePackageService(jdbc,tasks));
        var resolver=mock(ScapResolver.class);when(resolver.resolve(any())).thenAnswer(call->{ScapPackage content=call.getArgument(0);return new ScapResolver.Resolved(content,JsonUtils.write(Map.of("resolver","protocol fixture","sourceCanonicalSha256",content.sha256())));});
        scap=transactional(new ScapPackageService(jdbc,transactional(new ScapTaskService(jdbc,commands,new DatabaseDialect(platform))),resolver,manager));
        var library=new LibraryProperties();library.setWorkDir(root.resolve("downloads").toString());downloader=new FeedDownload(new LibraryFiles(library,platform),library);
        service=new BaselineUpstreamService(jdbc,manager,props,downloader,baseline,scap);service.initialize();
        var holder=mock(JwtSecretHolder.class);when(holder.secret()).thenReturn(SECRET);
        mvc=MockMvcBuilders.standaloneSetup(new BaselineUpstreamController(service),new BaselineController(null,null,baseline,null))
                .setControllerAdvice(new RestExceptionHandler()).addInterceptors(new JwtAuthInterceptor(holder)).build();
    }
    @AfterEach void close()throws Exception{
        if(artifactContinue!=null)artifactContinue.countDown();
        if(service!=null){service.close();for(int n=0;n<200&&jdbc.queryForObject("SELECT count(*) FROM t_baseline_upstream_attempt WHERE source_id=? AND outcome IN ('running','queued')",Integer.class,sourceId)>0;n++)Thread.sleep(10);}
        if(http!=null)http.stop(0);if(httpWorkers!=null)httpWorkers.shutdownNow();
        if(jdbc!=null){
            var ids=jdbc.queryForList("SELECT id,template_id FROM t_baseline_package WHERE code=?",code);
            for(String table:List.of("t_baseline_upstream_attempt","t_baseline_upstream_release","t_baseline_upstream_receipt"))jdbc.update("DELETE FROM "+table+" WHERE source_id=?",sourceId);
            jdbc.update("DELETE FROM t_baseline_upstream_source WHERE id=?",sourceId);
            for(var row:ids)if(row.get("template_id")!=null){jdbc.update("DELETE FROM t_baseline_item WHERE template_id=?",row.get("template_id"));jdbc.update("UPDATE t_baseline_package SET template_id=NULL WHERE id=?",row.get("id"));jdbc.update("DELETE FROM t_baseline_template WHERE id=?",row.get("template_id"));}
            jdbc.update("DELETE FROM t_baseline_package WHERE code=?",code);jdbc.update("DELETE FROM t_baseline_package_gate WHERE code=?",code);
            jdbc.update("DELETE FROM t_scap_package_review WHERE package_id IN (SELECT id FROM t_scap_package WHERE code=?)",scapCode);jdbc.update("DELETE FROM t_scap_package WHERE code=?",scapCode);jdbc.update("DELETE FROM t_scap_package_gate WHERE code=?",scapCode);
        }
        if(pool!=null)pool.close();
    }
    @SuppressWarnings("unchecked") <T>T transactional(T target){var proxy=new ProxyFactory(target);proxy.addAdvice(new TransactionInterceptor(manager,new AnnotationTransactionAttributeSource()));return (T)proxy.getProxy();}
    Path repo(){Path path=Path.of("").toAbsolutePath();while(!Files.exists(path.resolve("deploy/baseline")))path=path.getParent();return path;}
    byte[] baseline(String version,int os)throws Exception{var doc=(ObjectNode)JsonUtils.mapper().readTree(repo().resolve("deploy/baseline/packages/"+(os==1?"linux":"windows")+"-baseline.json").toFile());doc.put("code",code).put("version",version);return JsonUtils.write(doc).getBytes(StandardCharsets.UTF_8);}
    byte[] renameScap(byte[] bytes)throws Exception{var out=new ByteArrayOutputStream();try(var zip=new ZipInputStream(new ByteArrayInputStream(bytes));var writer=new ZipOutputStream(out)){for(var entry=zip.getNextEntry();entry!=null;entry=zip.getNextEntry()){byte[] content=zip.readAllBytes();if(entry.getName().equals("alinksec-scap.json")){var doc=(ObjectNode)JsonUtils.mapper().readTree(content);doc.put("code",scapCode);content=JsonUtils.write(doc).getBytes(StandardCharsets.UTF_8);}writer.putNextEntry(new ZipEntry(entry.getName()));writer.write(content);writer.closeEntry();}}return out.toByteArray();}
    ObjectNode release(String kind,String version,int os,byte[] bytes){String hash=ScapPackage.digest(bytes),path="/artifacts/"+hash;artifacts.put(path,bytes);return (ObjectNode)JsonUtils.read(JsonUtils.write(Map.of("kind",kind,"code",kind.equals("baseline")?code:scapCode,"version",version,"osType",os,"url",base+path,"sha256",hash,"size",bytes.length,"status","active")));}
    byte[] signed(long sequence,long expires,List<ObjectNode> releases)throws Exception{byte[] payload=JsonUtils.write(Map.of("sourceId",sourceId,"sequence",sequence,"generatedAt",Instant.now().minusSeconds(1).toString(),"expiresAt",Instant.ofEpochMilli(expires).toString(),"releases",releases)).getBytes(StandardCharsets.UTF_8);var signer=Signature.getInstance("Ed25519");signer.initSign(keys.getPrivate());signer.update(payload);return JsonUtils.write(Map.of("formatVersion",1,"payload",Base64.getEncoder().encodeToString(payload),"signature",Base64.getEncoder().encodeToString(signer.sign()))).getBytes(StandardCharsets.UTF_8);}
    void index(long sequence,ObjectNode... releases)throws Exception{index.set(signed(sequence,System.currentTimeMillis()+3_600_000,List.of(releases)));}
    Map<String,Object> run()throws Exception{
        String id=null;for(int n=0;n<200&&id==null;n++){try{id=service.trigger(sourceId,7L).get("attemptId");}catch(IllegalArgumentException e){if(!e.getMessage().contains("正在执行"))throw e;Thread.sleep(10);}}
        assertNotNull(id);return await(id);
    }
    Map<String,Object> await(String id)throws Exception{for(int n=0;n<3000;n++){var rows=jdbc.queryForList("SELECT * FROM t_baseline_upstream_attempt WHERE id=?",id);if(rows.size()==1&&!List.of("running","queued").contains(rows.get(0).get("outcome")))return rows.get(0);Thread.sleep(10);}fail("upstream worker did not finish");return null;}
    List<Map<String,Object>> releases(){return jdbc.queryForList("SELECT * FROM t_baseline_upstream_release WHERE source_id=? ORDER BY kind,version",sourceId);}
    String token(String role){return JwtUtil.sign(SECRET,Map.of("uid",7,"username","fixture","role",role),3600);}
    JsonNode response(MvcResult result)throws Exception{return JsonUtils.mapper().readTree(result.getResponse().getContentAsByteArray());}
    @Test void importsBothOperatingSystemsAndScapIdempotentlyWithRawEvidence()throws Exception{
        byte[] linux=baseline("1",1),windows=baseline("2",2),scapBytes=renameScap(new ScapIntegrationTest().content("1"));
        index(1,release("baseline","1",1,linux),release("baseline","2",2,windows),release("scap","1",1,scapBytes));
        assertEquals("success",run().get("outcome"));assertEquals("success",run().get("outcome"));assertEquals(3,releases().size());assertTrue(conditional.get()>0);
        for(var row:releases()){assertEquals("imported",row.get("state"));String id=row.get("package_id").toString();var pkg=row.get("kind").equals("baseline")?baseline.detail(id):scap.detail(id);assertEquals("candidate",pkg.get("status"));assertEquals(1,((List<?>)pkg.get("upstream")).size());assertEquals(row.get("sha256"),ScapPackage.digest(service.artifact(sourceId,row.get("id").toString())));assertArrayEquals(index.get(),service.receipt(sourceId,row.get("first_receipt").toString()));}
        int downloads=artifactRequests.get();assertEquals("success",run().get("outcome"));assertEquals(downloads,artifactRequests.get());
        assertEquals(0,jdbc.queryForObject("SELECT count(*) FROM t_baseline_template WHERE package_id IN (SELECT package_id FROM t_baseline_upstream_release WHERE source_id=?)",Integer.class,sourceId));
    }
    @Test void rollbackEquivocationMutationWithdrawalAndExpiryPreserveExistingContent()throws Exception{
        var entry=release("baseline","1",1,baseline("1",1));index(2,entry);assertEquals("success",run().get("outcome"));String pkg=releases().get(0).get("package_id").toString();String frozen=baseline.detail(pkg).get("content_sha256").toString();
        index(1,entry);assertEquals("index_rollback",run().get("issue"));index(2);assertEquals("index_rollback",run().get("issue"));
        var changed=entry.deepCopy().put("sha256","b".repeat(64));index(3,changed);assertEquals("release_changed",run().get("issue"));assertEquals(2L,((Number)service.detail(sourceId).get("sequence")).longValue());
        entry.put("status","withdrawn");index(3,entry);assertEquals("success",run().get("outcome"));assertThrows(IllegalArgumentException.class,()->baseline.review(pkg,true,"approved",7L));
        entry.put("status","active");index(4,entry);assertEquals("release_changed",run().get("issue"));assertEquals(frozen,baseline.detail(pkg).get("content_sha256"));
        var second=release("baseline","2",1,baseline("2",1));index(4,second);assertEquals("success",run().get("outcome"));String secondPkg=releases().stream().filter(r->r.get("version").equals("2")).findFirst().orElseThrow().get("package_id").toString();
        baseline.review(secondPkg,true,"approved before expiry",7L);
        jdbc.update("UPDATE t_baseline_upstream_receipt SET expires_at=? WHERE source_id=? AND sequence=4",System.currentTimeMillis()-1,sourceId);
        assertThrows(IllegalArgumentException.class,()->baseline.test(secondPkg,List.of("any-host"),7L));assertThrows(IllegalArgumentException.class,()->baseline.publish(secondPkg,"publish",7L));
        index.set(signed(5,System.currentTimeMillis()-1,List.of(second)));assertEquals("index_invalid",run().get("issue"));assertEquals("approved",baseline.detail(secondPkg).get("status"));
    }
    @Test void downloadFailuresAreBoundedRetryableAndNeverCreatePartialCandidates()throws Exception{
        byte[] bytes=baseline("1",1);var entry=release("baseline","1",1,bytes);artifacts.put(new java.net.URI(entry.path("url").asText()).getPath(),"corrupt".getBytes(StandardCharsets.UTF_8));index(1,entry);
        for(int n=0;n<3;n++)assertEquals("artifact_digest",run().get("issue"));assertEquals(3,((Number)releases().get(0).get("attempts")).intValue());assertNull(releases().get(0).get("package_id"));
        int calls=artifactRequests.get();run();assertEquals(calls,artifactRequests.get());
        service.retry(sourceId,releases().get(0).get("id").toString(),7L);artifacts.put(new java.net.URI(entry.path("url").asText()).getPath(),bytes);assertEquals("success",run().get("outcome"));assertEquals("imported",releases().get(0).get("state"));
        artifactStatus=302;var second=release("baseline","2",1,baseline("2",1));index(2,entry,second);assertEquals("artifact_download",run().get("issue"));assertEquals(1,releases().stream().filter(r->r.get("state").equals("imported")).count());
    }
    @Test void disableDuringDownloadAndCompetingLeaseCannotCommitStaleContent()throws Exception{
        index(1,release("baseline","1",1,baseline("1",1)));artifactStarted=new CountDownLatch(1);artifactContinue=new CountDownLatch(1);
        String attempt=service.trigger(sourceId,7L).get("attemptId");assertTrue(artifactStarted.await(10,TimeUnit.SECONDS));long revision=((Number)service.detail(sourceId).get("revision")).longValue();
        service.schedule(sourceId,new BaselineUpstreamService.Schedule(revision,false,3_600_000,"stop during fetch"),7L);artifactContinue.countDown();assertEquals("source_changed",await(attempt).get("issue"));assertNull(releases().get(0).get("package_id"));
        service.schedule(sourceId,new BaselineUpstreamService.Schedule(revision+1,true,3_600_000,"resume"),7L);Thread.sleep(30);
        jdbc.update("UPDATE t_baseline_upstream_gate SET lease_owner='other-process',lease_until=? WHERE id=1",System.currentTimeMillis()+240_000);int before=requests.get();assertEquals("worker_busy",run().get("issue"));assertEquals(before,requests.get());
        jdbc.update("UPDATE t_baseline_upstream_gate SET lease_until=0 WHERE id=1");assertEquals("success",run().get("outcome"));assertEquals("imported",releases().get(0).get("state"));
    }
    @Test void restUsesJwtRolesOptimisticRevisionsAndVerifiedDownloads()throws Exception{
        String prefix="/api/baseline/upstreams/"+sourceId;
        assertEquals(401,mvc.perform(get(prefix)).andReturn().getResponse().getStatus());
        for(String role:List.of("viewer","operator")){assertEquals(200,mvc.perform(get(prefix).header("Authorization","Bearer "+token(role))).andReturn().getResponse().getStatus());assertEquals(403,mvc.perform(post(prefix+"/sync").header("Authorization","Bearer "+token(role))).andReturn().getResponse().getStatus());}
        String plan=JsonUtils.write(Map.of("revision",0,"enabled",true,"intervalMs",3_600_000,"note","admin plan"));
        assertEquals(200,mvc.perform(put(prefix+"/schedule").header("Authorization","Bearer "+token("admin")).contentType("application/json").content(plan)).andReturn().getResponse().getStatus());
        assertEquals(400,mvc.perform(put(prefix+"/schedule").header("Authorization","Bearer "+token("admin")).contentType("application/json").content(plan)).andReturn().getResponse().getStatus());
        index(1,release("baseline","1",1,baseline("1",1)));var result=mvc.perform(post(prefix+"/sync").header("Authorization","Bearer "+token("admin"))).andReturn();assertEquals(200,result.getResponse().getStatus());await(response(result).path("data").path("attemptId").asText());
        var release=releases().get(0);var downloaded=mvc.perform(get(prefix+"/releases/"+release.get("id")+"/artifact").header("Authorization","Bearer "+token("viewer"))).andReturn().getResponse();
        assertEquals(200,downloaded.getStatus());assertEquals("no-store",downloaded.getHeader("Cache-Control"));assertEquals("nosniff",downloaded.getHeader("X-Content-Type-Options"));assertEquals(release.get("sha256"),downloaded.getHeader("X-Content-SHA256"));assertArrayEquals(service.artifact(sourceId,release.get("id").toString()),downloaded.getContentAsByteArray());
        var snapshots=new LinkedHashMap<String,Object>();snapshots.put("imported",snapshot(release));
        var withdrawal=release("baseline","1",1,baseline("1",1)).put("status","withdrawn");index(2,withdrawal);assertEquals("success",run().get("outcome"));snapshots.put("withdrawn",snapshot(release));
        var failing=release("baseline","2",1,baseline("2",1));artifacts.put(new java.net.URI(failing.path("url").asText()).getPath(),"corrupt".getBytes(StandardCharsets.UTF_8));index(3,withdrawal,failing);assertEquals("artifact_digest",run().get("issue"));snapshots.put("failed",snapshot(release));
        long revision=((Number)service.detail(sourceId).get("revision")).longValue();service.schedule(sourceId,new BaselineUpstreamService.Schedule(revision,false,3_600_000,"pause updates"),7L);snapshots.put("paused",snapshot(release));
        String output=System.getenv("ALINKSEC_BASELINE_UPSTREAM_FIXTURES");if(output!=null){Path path=Path.of(output);Files.createDirectories(path);Files.writeString(path.resolve(System.getProperty("alinksec.integration.database","sqlite")+".json"),JsonUtils.write(snapshots));}

    }
    Map<String,Object> snapshot(Map<String,Object> release){return Map.of("sources",service.list(),"detail",service.detail(sourceId),"candidate",baseline.detail(release.get("package_id").toString()),"artifactBase64",Base64.getEncoder().encodeToString(service.artifact(sourceId,release.get("id").toString())),"receiptBase64",Base64.getEncoder().encodeToString(service.receipt(sourceId,release.get("first_receipt").toString())));}
    @Test void quotaFailureIsAtomicAndExplicitRetryCanRecover()throws Exception{
        props.setMaxArtifactBytes(2L<<20);
        var entries=new ArrayList<ObjectNode>();
        for(String version:List.of("1","2")){
            var doc=(ObjectNode)JsonUtils.mapper().readTree(baseline(version,1));var original=(ObjectNode)doc.path("items").get(0);var items=doc.putArray("items");
            for(int n=0;n<400;n++)items.add(original.deepCopy().put("code","CAP-"+n).put("ruleId","capacity-rule-"+n).put("remediation","x".repeat(4000)));
            entries.add(release("baseline",version,1,JsonUtils.write(doc).getBytes(StandardCharsets.UTF_8)));
        }
        index(1,entries.toArray(ObjectNode[]::new));assertEquals("artifact_capacity",run().get("issue"));
        var failed=releases().stream().filter(r->r.get("state").equals("failed")).findFirst().orElseThrow();assertNull(failed.get("package_id"));
        assertEquals(1,jdbc.queryForObject("SELECT count(*) FROM t_baseline_package WHERE code=?",Integer.class,code));
        props.setMaxArtifactBytes(4L<<20);service.retry(sourceId,failed.get("id").toString(),7L);assertEquals("success",run().get("outcome"));assertEquals(2,releases().stream().filter(r->r.get("state").equals("imported")).count());
    }
    @Test void trustRotationPreservesSequenceAndRequiresFreshIndexAndExplicitEnable()throws Exception{
        var entry=release("baseline","1",1,baseline("1",1));index(1,entry);assertEquals("success",run().get("outcome"));String pkg=releases().get(0).get("package_id").toString(),firstReceipt=releases().get(0).get("first_receipt").toString();
        Thread.sleep(30);service.close();keys=KeyPairGenerator.getInstance("Ed25519").generateKeyPair();publisher.setPublicKey(Base64.getEncoder().encodeToString(keys.getPublic().getEncoded()));
        service=new BaselineUpstreamService(jdbc,manager,props,downloader,baseline,scap);service.initialize();
        assertEquals(0,((Number)service.detail(sourceId).get("enabled")).intValue());assertEquals(1L,((Number)service.detail(sourceId).get("sequence")).longValue());
        assertThrows(IllegalArgumentException.class,()->baseline.review(pkg,true,"stale trust",7L));
        long revision=((Number)service.detail(sourceId).get("revision")).longValue();service.schedule(sourceId,new BaselineUpstreamService.Schedule(revision,true,3_600_000,"reviewed rotated key"),7L);
        index(1,entry);assertEquals("index_rollback",run().get("issue"));index(2,entry);assertEquals("success",run().get("outcome"));
        assertEquals(firstReceipt,releases().get(0).get("first_receipt"));assertNotEquals(firstReceipt,releases().get(0).get("current_receipt"));assertEquals("approved",baseline.review(pkg,true,"fresh trust verified",7L).get("status"));
        jdbc.update("UPDATE t_baseline_upstream_receipt SET expires_at=? WHERE source_id=?",System.currentTimeMillis()-1,sourceId);forcedNotModified=true;assertEquals("index_expired",run().get("issue"));
    }
    @Test void actualNativeScapResolutionRetainsSignedOriginalAndDerivedIdentity()throws Exception{
        String fixture=System.getenv("ALINKSEC_SCAP_FIXTURE_ZIP");Assumptions.assumeTrue(fixture!=null,"native resolution runs in the dedicated upstream CI job");
        service.close();var platform=new AlinkSecProperties();platform.getDatabase().setType("sqlite");var library=new LibraryProperties();library.setWorkDir(root.resolve("native-downloads").toString());
        var realScap=transactional(new ScapPackageService(jdbc,mock(ScapTaskService.class),new ScapResolver(),manager));
        service=new BaselineUpstreamService(jdbc,manager,props,new FeedDownload(new LibraryFiles(library,platform),library),baseline,realScap);service.initialize();
        byte[] bytes=renameScap(Files.readAllBytes(Path.of(fixture)));String version=ScapPackage.read(bytes).manifest().path("version").asText();index(1,release("scap",version,1,bytes));assertEquals("success",run().get("outcome"));var release=releases().get(0);var pkg=realScap.detail(release.get("package_id").toString());assertTrue(((JsonNode)pkg.get("resolution")).path("resolver").asText().contains("OpenSCAP"));assertArrayEquals(bytes,realScap.source(pkg.get("id").toString()));assertEquals(ScapPackage.digest(bytes),release.get("sha256"));assertEquals("candidate",pkg.get("status"));
    }
}
