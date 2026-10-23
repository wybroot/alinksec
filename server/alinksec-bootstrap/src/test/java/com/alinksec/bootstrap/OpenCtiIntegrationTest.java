package com.alinksec.bootstrap;

import com.alinksec.common.util.*;
import com.alinksec.gateway.rest.*;
import com.alinksec.service.config.*;
import com.alinksec.service.library.*;
import com.alinksec.service.scan.VulnMatchService;
import com.alinksec.service.virus.VirusDbService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.sun.net.httpserver.HttpServer;
import com.zaxxer.hikari.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.test.web.servlet.*;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;

/** Real bounded HTTP, production catalog transactions and resolved-route auth on both databases. */
class OpenCtiIntegrationTest {
    @TempDir Path root;
    HikariDataSource pool; JdbcTemplate jdbc; LibraryProperties props; LibraryFiles files;
    LibraryCatalog catalog; LibrarySyncService sync; LibrarySchedule schedules; OpenCtiProperties limits;
    OpenCtiService service; LibraryProperties.Source source; FeedDownload downloader; VirusDbService virus;
    HttpServer http; ExecutorService workers; MockMvc mvc; String base,id,hash,otherHash; boolean pg; Long actor;
    long previousReleaseId; List<Map<String,Object>> previousReleaseStates;
    volatile int status=200; volatile String principal="11111111-1111-4111-8111-111111111111";
    volatile Function<JsonNode,byte[]> response;
    final AtomicInteger requests=new AtomicInteger(),redirectTarget=new AtomicInteger();
    static final String SECRET="opencti-integration-jwt-secret-32-bytes",KEY="fixture-opencti-key";
    @BeforeEach void setup() throws Exception {
        pg="postgres".equals(System.getProperty("alinksec.integration.database"));
        var config=new HikariConfig();config.setJdbcUrl(pg?System.getenv("ALINKSEC_INTEGRATION_PG_URL"):"jdbc:sqlite:"+root.resolve("db"));
        if(pg){config.setUsername(System.getenv("ALINKSEC_INTEGRATION_PG_USER"));config.setPassword(System.getenv("ALINKSEC_INTEGRATION_PG_PASSWORD"));}
        else{config.addDataSourceProperty("transaction_mode","IMMEDIATE");config.addDataSourceProperty("busy_timeout",5000);config.addDataSourceProperty("foreign_keys",true);}
        config.setMaximumPoolSize(3);config.setMinimumIdle(1);pool=new HikariDataSource(config);
        if(!pg)new SqliteDatabaseConfiguration.SqliteMigrationBeanPostProcessor().postProcessAfterInitialization(pool,"dataSource");
        jdbc=new JdbcTemplate(pool);
        previousReleaseId=jdbc.queryForObject("SELECT COALESCE(max(id),0) FROM t_virus_db",Long.class);
        previousReleaseStates=jdbc.queryForList("SELECT * FROM t_security_feed_state WHERE source_id IN ('_signature-release','_legacy-signature')");
        actor=jdbc.queryForObject("INSERT INTO t_user(username,password_hash,role_id,status) VALUES (?,'unused',1,1) RETURNING id",Long.class,"opencti-"+UUID.randomUUID());
        id="opencti-"+UUID.randomUUID();hash=sha(id);otherHash=sha(id+"other");
        http=HttpServer.create(new InetSocketAddress("127.0.0.1",0),0);workers=Executors.newCachedThreadPool();http.setExecutor(workers);
        http.createContext("/",exchange->{
            requests.incrementAndGet();
            try{
                if(exchange.getRequestURI().getPath().equals("/redirect-target"))redirectTarget.incrementAndGet();
                if(status==302){exchange.getResponseHeaders().set("Location",base+"/redirect-target");exchange.sendResponseHeaders(302,-1);return;}
                if(status!=200){exchange.sendResponseHeaders(status,-1);return;}
                if(!"POST".equals(exchange.getRequestMethod())||!Objects.equals("Bearer "+source.getApiKey(),exchange.getRequestHeaders().getFirst("Authorization"))){exchange.sendResponseHeaders(401,-1);return;}
                var request=JsonUtils.mapper().readTree(exchange.getRequestBody());
                if(!OpenCtiAdapter.QUERY.equals(request.path("query").asText())||request.path("variables").path("first").asInt()!=200){exchange.sendResponseHeaders(400,-1);return;}
                byte[] body=response.apply(request);exchange.getResponseHeaders().set("Content-Type","application/json");
                exchange.sendResponseHeaders(200,body.length);exchange.getResponseBody().write(body);
            }finally{exchange.close();}
        });http.start();base="http://127.0.0.1:"+http.getAddress().getPort();
        props=new LibraryProperties();props.setWorkDir(root.resolve("work").toString());
        source=new LibraryProperties.Source();source.setId(id);source.setType("opencti");source.setUrl(base+"/graphql");
        source.setApiKey(KEY);source.setOpenctiTag("alinksec-approved");source.setEnabled(true);props.setSources(List.of(source));
        var platform=new AlinkSecProperties();platform.getDatabase().setType(pg?"postgres":"sqlite");platform.getSignature().setStorageDir(root.resolve("signatures").toString());
        files=spy(new LibraryFiles(props,platform));catalog=new LibraryCatalog(jdbc,props,files,new DatabaseDialect(platform),new DataSourceTransactionManager(pool));
        schedules=new LibrarySchedule(props,jdbc);limits=new OpenCtiProperties();downloader=new FeedDownload(files,props);virus=mock(VirusDbService.class);
        sync=new LibrarySyncService(props,catalog,virus,downloader,jdbc,mock(VulnMatchService.class),schedules,new VendorAdvisoryProperties(),limits);
        service=sync.nativeOpenCti(id);sync.validate();response=q->bytes(page(List.of(node(1,hash)),false,1,"cursor-1"));
        var holder=mock(JwtSecretHolder.class);when(holder.secret()).thenReturn(SECRET);
        mvc=MockMvcBuilders.standaloneSetup(new LibraryController(sync,catalog,props,schedules)).setControllerAdvice(new RestExceptionHandler())
                .addInterceptors(new JwtAuthInterceptor(holder)).build();
    }
    @AfterEach void cleanup() throws Exception {
        if(sync!=null)sync.close();if(http!=null)http.stop(0);if(workers!=null)workers.shutdownNow();
        if(jdbc!=null){
            // These tests exercise committed multi-connection publication. Restore the shared
            // PostgreSQL release metadata too, so later channel tests do not receive our fixture DB.
            jdbc.update("DELETE FROM t_virus_db WHERE id>?",previousReleaseId);
            jdbc.update("DELETE FROM t_security_feed_state WHERE source_id IN ('_signature-release','_legacy-signature')");
            if(previousReleaseStates!=null)for(var row:previousReleaseStates){
                var columns=new ArrayList<>(row.keySet());
                jdbc.update("INSERT INTO t_security_feed_state ("+String.join(",",columns.stream().map(c->"\""+c+"\"").toList())+") VALUES ("+String.join(",",Collections.nCopies(columns.size(),"?"))+")",columns.stream().map(row::get).toArray());
            }
            for(String sid:List.of(id,id+"-other"))for(String table:List.of("t_opencti_indicator","t_opencti_source","t_security_hash","t_security_rule","t_security_governance_event","t_security_feed_run","t_security_feed_state","t_security_feed_schedule","t_security_source_lifecycle"))
                jdbc.update("DELETE FROM "+table+" WHERE source_id=?",sid);
            jdbc.update("DELETE FROM t_user WHERE id=?",actor);
        }
        if(files!=null)files.close();if(pool!=null)pool.close();
    }
    static byte[] bytes(Object value){return JsonUtils.write(value).getBytes(StandardCharsets.UTF_8);}
    static String sha(String value){return OpenCtiAdapter.digest(value.getBytes(StandardCharsets.UTF_8));}
    static String iid(int n){return "22222222-2222-4222-8222-"+String.format("%012d",n);}
    ObjectNode node(int n,String digest){
        var v=JsonUtils.mapper().createObjectNode();v.put("id",iid(n));v.put("standard_id","indicator--"+iid(n));v.put("name","Reviewed indicator "+n);
        v.put("created_at","2026-01-01T00:00:00Z");v.putNull("modified");v.put("pattern_type","stix");v.put("pattern_version","2.1");
        v.put("pattern","[file:hashes.'SHA-256' = '"+digest+"']");v.put("revoked",false);v.put("confidence",80);
        v.put("valid_from","2026-01-01T00:00:00Z");v.putNull("valid_until");v.put("x_opencti_detection",true);
        v.putArray("objectLabel").addObject().put("value","alinksec-approved");return v;
    }
    ObjectNode page(List<ObjectNode> nodes,boolean more,int count,String cursor){
        var root=JsonUtils.mapper().createObjectNode();var data=root.putObject("data");data.putObject("me").put("id",principal);data.putObject("about").put("version","7.261021.1");
        var connection=data.putObject("indicators");connection.putObject("pageInfo").put("hasNextPage",more).put("endCursor",cursor).put("globalCount",count);
        var edges=connection.putArray("edges");for(var node:nodes){var edge=edges.addObject();edge.put("cursor","cursor-"+Integer.parseInt(node.path("id").asText().substring(24)));edge.set("node",node);}
        return root;
    }
    String version(){return jdbc.queryForObject("SELECT version FROM t_security_feed_state WHERE source_id='_signature-release'",String.class);}
    int ownHashes(){return jdbc.queryForObject("SELECT count(*) FROM t_security_hash WHERE source_id=?",Integer.class,id);}
    String snapshot(){return JsonUtils.write(jdbc.queryForList("SELECT * FROM t_opencti_indicator WHERE source_id=? ORDER BY indicator_id",id));}
    void otherSource() throws IOException {catalog.signatures(id+"-other",new SignaturePackage("",Map.of(otherHash,SignaturePackage.checkedHash(otherHash,"Fixture.Other",3)),List.of()),true,actor);}
    String token(String role){return JwtUtil.sign(SECRET,Map.of("uid",actor,"username","fixture","role",role),3600);}
    JsonNode data(String path,String role) throws Exception {
        var result=mvc.perform(get(path).header("Authorization","Bearer "+token(role))).andReturn().getResponse();assertEquals(200,result.getStatus(),result.getContentAsString());
        return JsonUtils.mapper().readTree(result.getContentAsByteArray()).path("data");
    }
    @Test void completePagesDeduplicateHashesAndArchiveSelectedFieldsWithVerifiableDigests() throws Exception {
        var revoked=node(3,otherHash).put("revoked",true);
        response=q->q.path("variables").path("after").isNull()?bytes(page(List.of(node(1,hash)),true,3,"cursor-1")):bytes(page(List.of(node(2,hash),revoked),false,3,"cursor-3"));
        var result=service.sync(source);assertEquals(1,result.get("entryCount"));assertEquals(2,requests.get());assertEquals(1,ownHashes());
        var state=service.state(id);assertEquals(3,((Number)state.get("visible_count")).intValue());assertEquals(2,((Number)state.get("page_count")).intValue());
        for(var row:jdbc.queryForList("SELECT * FROM t_opencti_indicator WHERE source_id=?",id))assertEquals(sha(row.get("document").toString()),row.get("document_sha256"));
        assertEquals(1,JsonUtils.read(JsonUtils.write(state.get("statistics"))).path("revoked").asInt());
        String original=version();service.sync(source);assertEquals(original,version());
        assertTrue(jdbc.queryForObject("SELECT snapshot FROM t_security_governance_event WHERE source_id=? ORDER BY id DESC LIMIT 1",String.class,id).contains("page_sha256"));
    }
    @Test void revocationOmissionAndCompleteEmptyCollectionsRemoveOnlyTheirOwnContribution() throws Exception {
        otherSource();service.sync(source);assertEquals(1,ownHashes());
        response=q->bytes(page(List.of(node(2,hash).put("revoked",true)),false,1,"cursor-2"));service.sync(source);assertEquals(0,ownHashes());
        assertEquals(1,jdbc.queryForObject("SELECT count(*) FROM t_security_hash WHERE source_id=?",Integer.class,id+"-other"));
        assertThrows(IllegalArgumentException.class,()->service.detail(id,iid(1)));
        response=q->bytes(page(List.of(),false,0,""));service.sync(source);assertEquals(0,((Number)service.indicators(id,1,20).get("total")).intValue());
        jdbc.update("DELETE FROM t_security_hash WHERE source_id=?",id+"-other");service.sync(source);
        assertEquals(0,jdbc.queryForObject("SELECT hash_count FROM t_virus_db ORDER BY id DESC LIMIT 1",Integer.class));
        Path packagePath=root.resolve("empty.zip");var row=jdbc.queryForMap("SELECT package_key FROM t_virus_db ORDER BY id DESC LIMIT 1");files.copyTo("signature",row.get("package_key").toString(),packagePath);
        try(var zip=new java.util.zip.ZipFile(packagePath.toFile())){assertEquals(0,JsonUtils.mapper().readTree(zip.getInputStream(zip.getEntry("manifest.json"))).path("hash_count").asInt());assertEquals(0,zip.getInputStream(zip.getEntry("hashes.txt")).readAllBytes().length);}
    }
    @Test void failedSecondPageChangingCountsRepeatedCursorsAndErrorsNeverPartiallyCommit() throws Exception {
        service.sync(source);String prior=snapshot(),release=version();
        List<Function<JsonNode,byte[]>> invalid=List.of(
                q->q.path("variables").path("after").isNull()?bytes(page(List.of(node(2,otherHash)),true,2,"cursor-2")):bytes(Map.of("errors",List.of(Map.of("message",KEY)))),
                q->q.path("variables").path("after").isNull()?bytes(page(List.of(node(2,otherHash)),true,2,"cursor-2")):bytes(page(List.of(node(3,otherHash)),false,3,"cursor-3")),
                q->bytes(page(List.of(node(2,otherHash)),true,2,"cursor-2")),
                q->bytes(page(List.of(node(2,otherHash)),false,2,"cursor-2")),
                q->bytes(page(List.of(node(2,otherHash),node(2,otherHash)),false,2,"cursor-2")),
                q->bytes(page(List.of(node(2,otherHash).put("confidence","high")),false,1,"cursor-2")),
                q->"{\"data\":".getBytes(StandardCharsets.UTF_8));
        for(var bad:invalid){response=bad;assertThrows(Exception.class,()->service.sync(source));assertEquals(prior,snapshot());assertEquals(release,version());}
        sync.sync(source);String statusJson=JsonUtils.write(sync.status());assertFalse(statusJson.contains(KEY));assertFalse(statusJson.contains(base));
    }
    @Test void redirectsHttpFailuresTimeoutsAndBodyLimitsKeepTheAcceptedRelease() throws Exception {
        service.sync(source);String prior=snapshot(),release=version();
        for(int code:List.of(302,304,401,403,500)){status=code;assertThrows(Exception.class,()->service.sync(source));assertEquals(prior,snapshot());assertEquals(release,version());}
        assertEquals(0,redirectTarget.get());status=200;
        response=q->new byte[(int)OpenCtiAdapter.MAX_PAGE_BYTES+1];assertThrows(Exception.class,()->service.sync(source));assertEquals(prior,snapshot());
        limits.setMaxPages(1);response=q->bytes(page(List.of(node(2,otherHash)),true,2,"cursor-2"));assertThrows(Exception.class,()->service.sync(source));assertEquals(release,version());
        limits.setMaxPages(128);limits.setRequestTimeoutMs(1000);
        response=q->{try{Thread.sleep(1300);}catch(InterruptedException e){Thread.currentThread().interrupt();}return bytes(page(List.of(node(2,otherHash)),false,1,"cursor-2"));};
        assertThrows(Exception.class,()->service.sync(source));assertEquals(release,version());
    }
    @Test void endpointPolicyTypeAndPrincipalArePinnedWhileSameAccountKeysCanRotate() throws Exception {
        service.sync(source);String release=version();int before=requests.get();
        source.setOpenctiTag("different");assertThrows(IllegalArgumentException.class,()->service.sync(source));assertEquals(before,requests.get());
        assertThrows(IllegalArgumentException.class,()->schedules.update(id,true,7_200_000L));source.setOpenctiTag("alinksec-approved");
        source.setUrl(base+"/changed/graphql");assertThrows(IllegalArgumentException.class,()->service.sync(source));source.setUrl(base+"/graphql");
        source.setType("hashes");sync.sync(source);assertEquals(before,requests.get());assertEquals("failed",jdbc.queryForObject("SELECT status FROM t_security_feed_state WHERE source_id=?",String.class,id));source.setType("opencti");
        principal="33333333-3333-4333-8333-333333333333";assertThrows(IllegalArgumentException.class,()->service.sync(source));assertEquals(release,version());
        principal="11111111-1111-4111-8111-111111111111";source.setApiKey("rotated-key");service.sync(source);assertEquals(release,version());
    }
    @Test void publicationFailureRollsBackRawEvidenceSourceRevisionAndEffectiveHashes() throws Exception {
        service.sync(source);String prior=snapshot(),release=version();long revision=((Number)jdbc.queryForMap("SELECT revision FROM t_opencti_source WHERE source_id=?",id).get("revision")).longValue();
        response=q->bytes(page(List.of(node(2,otherHash)),false,1,"cursor-2"));
        doThrow(new IOException("fixture storage failure")).when(files).put(eq("signature"),anyString(),any(Path.class));
        assertThrows(IOException.class,()->service.sync(source));assertEquals(prior,snapshot());assertEquals(release,version());assertEquals(1,ownHashes());
        assertEquals(revision,jdbc.queryForObject("SELECT revision FROM t_opencti_source WHERE source_id=?",Long.class,id));
        doCallRealMethod().when(files).put(eq("signature"),anyString(),any(Path.class));service.sync(source);assertNotEquals(release,version());
    }
    @Test void mergedCapacityFailurePreservesTheCompleteOldSnapshot() throws Exception {
        otherSource();service.sync(source);String prior=snapshot(),release=version();props.setMaxHashes(2);
        response=q->bytes(page(List.of(node(1,hash),node(2,sha(id+"third"))),false,2,"cursor-2"));
        assertThrows(IllegalArgumentException.class,()->service.sync(source));assertEquals(prior,snapshot());assertEquals(release,version());assertEquals(1,ownHashes());
    }
    @Test void localExpirySurvivesRestartAndRemovedConfigurationWithoutAnyNetworkPull() throws Exception {
        otherSource();Instant then=Instant.now().minusSeconds(120),deadline=then.plusSeconds(30);
        response=q->bytes(page(List.of(node(1,hash).put("valid_until",deadline.toString()),node(2,hash).put("valid_from",Instant.now().plusSeconds(3600).toString())),false,2,"cursor-2"));
        new OpenCtiService(catalog,downloader,jdbc,limits,Clock.fixed(then,ZoneOffset.UTC)).sync(source);assertEquals(1,ownHashes());
        int before=requests.get();source.setEnabled(false);props.setSources(List.of());
        assertTrue(service.hasExpired());sync.scheduled();verify(virus,timeout(5000)).pushToAllAgents();assertEquals(before,requests.get());assertEquals(0,ownHashes());assertFalse(service.hasExpired());
        assertEquals("expired",service.detail(id,iid(1)).get("reason"));assertEquals("future",service.detail(id,iid(2)).get("reason"));
        assertEquals(1,jdbc.queryForObject("SELECT count(*) FROM t_security_hash WHERE source_id=?",Integer.class,id+"-other"));
        assertEquals(1,jdbc.queryForObject("SELECT count(*) FROM t_security_governance_event WHERE source_id=? AND operation='opencti_expiry'",Integer.class,id));
        assertSame(service,sync.nativeOpenCti(id));assertEquals(2,data("/api/libraries/sources/"+id+"/indicators","viewer").path("total").asInt());
    }
    @Test void expiryPublicationFailureIsVisibleAtomicAndRetried() throws Exception {
        Instant then=Instant.now().minusSeconds(120);response=q->bytes(page(List.of(node(1,hash).put("valid_until",then.plusSeconds(30).toString())),false,1,"cursor-1"));
        new OpenCtiService(catalog,downloader,jdbc,limits,Clock.fixed(then,ZoneOffset.UTC)).sync(source);String prior=snapshot(),release=version();
        doThrow(new IOException("private storage diagnostic")).when(files).put(eq("signature"),anyString(),any(Path.class));
        assertThrows(IOException.class,()->service.expireNext());assertEquals(prior,snapshot());assertEquals(release,version());assertTrue(service.hasExpired());
        assertFalse(service.state(id).get("expiry_error").toString().isBlank());assertFalse(service.state(id).toString().contains("private"));
        doCallRealMethod().when(files).put(eq("signature"),anyString(),any(Path.class));service.expireNext();assertEquals(0,ownHashes());assertEquals("",service.state(id).get("expiry_error"));
    }
    @Test void deliveryFailureKeepsCommittedSuccessAndUnchangedSyncRetriesDelivery() throws Exception {
        doThrow(new IllegalStateException("private delivery diagnostic")).when(virus).pushToAllAgents();sync.sync(source);
        assertEquals("success",jdbc.queryForObject("SELECT status FROM t_security_feed_state WHERE source_id=?",String.class,id));assertEquals(1,ownHashes());
        assertEquals(1,((Number)service.state(id).get("delivery_deferred")).intValue());String release=version();
        doNothing().when(virus).pushToAllAgents();sync.sync(source);assertEquals(release,version());verify(virus,times(2)).pushToAllAgents();
        assertEquals(0,((Number)service.state(id).get("delivery_deferred")).intValue());
    }
    @Test void removedConfigurationStillRetriesAndClearsDurableNativeDeliveryStatus() throws Exception {
        doThrow(new IllegalStateException("private delivery diagnostic")).when(virus).pushToAllAgents();sync.sync(source);
        assertEquals(1,((Number)service.state(id).get("delivery_deferred")).intValue());int pulls=requests.get();
        props.setSources(List.of());doNothing().when(virus).pushToAllAgents();sync.scheduled();
        verify(virus,timeout(5000).times(2)).pushToAllAgents();
        long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(5);
        while(((Number)service.state(id).get("delivery_deferred")).intValue()!=0 && System.nanoTime()<deadline)Thread.sleep(10);
        assertEquals(0,((Number)service.state(id).get("delivery_deferred")).intValue());assertEquals(pulls,requests.get());
        assertEquals(0,((Number)catalog.selectionDelivery().get("signature_pending")).intValue());
    }
    @Test void retirementWhileTheRequestIsInFlightPreventsLateCommitAndKeepsEvidence() throws Exception {
        service.sync(source);String prior=snapshot();var entered=new CountDownLatch(1);var proceed=new CountDownLatch(1);
        response=q->{entered.countDown();try{if(!proceed.await(10,TimeUnit.SECONDS))throw new IllegalStateException("fixture latch");}catch(InterruptedException e){throw new IllegalStateException(e);}return bytes(page(List.of(node(2,otherHash)),false,1,"cursor-2"));};
        var future=workers.submit(()->{assertThrows(IllegalArgumentException.class,()->service.sync(source));});
        try{assertTrue(entered.await(5,TimeUnit.SECONDS));catalog.retire(id,actor,"Fixture retired");}finally{proceed.countDown();}
        future.get(10,TimeUnit.SECONDS);assertEquals(prior,snapshot());assertEquals(0,service.state(id).get("candidate_hashes"));assertEquals(false,service.detail(id,iid(1)).get("effective"));
    }
    @Test void staleInFlightSnapshotCannotOverwriteANewerCompleteSnapshot() throws Exception {
        service.sync(source);var entered=new CountDownLatch(1);var proceed=new CountDownLatch(1);var first=new AtomicInteger();
        response=q->{if(first.getAndIncrement()==0){entered.countDown();try{if(!proceed.await(10,TimeUnit.SECONDS))throw new IllegalStateException("fixture latch");}catch(InterruptedException e){throw new IllegalStateException(e);}return bytes(page(List.of(node(2,otherHash)),false,1,"cursor-2"));}return bytes(page(List.of(node(3,hash)),false,1,"cursor-3"));};
        var future=workers.submit(()->assertThrows(OpenCtiAdapter.Failure.class,()->service.sync(source)));
        try{assertTrue(entered.await(5,TimeUnit.SECONDS));service.sync(source);}finally{proceed.countDown();}
        future.get(10,TimeUnit.SECONDS);assertEquals(iid(3),service.indicators(id,1,20).get("items") instanceof List<?> list?((Map<?,?>)list.get(0)).get("indicator_id"):null);
        assertThrows(IllegalArgumentException.class,()->service.detail(id,iid(2)));
    }
    @Test void principalAndVersionDriftAcrossPagesAbortBeforeAnyReplacement() throws Exception {
        service.sync(source);String prior=snapshot(),release=version();
        for(String kind:List.of("principal","version")){
            response=q->{if(q.path("variables").path("after").isNull())return bytes(page(List.of(node(2,otherHash)),true,2,"cursor-2"));
                var next=page(List.of(node(3,otherHash)),false,2,"cursor-3");
                next.withObject("/data/"+(kind.equals("principal")?"me":"about")).put(kind.equals("principal")?"id":"version",kind.equals("principal")?"44444444-4444-4444-8444-444444444444":"7.261021.2");return bytes(next);};
            assertThrows(OpenCtiAdapter.Failure.class,()->service.sync(source));assertEquals(prior,snapshot());assertEquals(release,version());
        }
    }
    @Test void currentEvidenceBudgetRejectsOversizedCollectionsAndStoredTamperingIsVisible() throws Exception {
        service.sync(source);String prior=snapshot(),release=version();limits.setMaxSnapshotBytes(1024);
        response=q->bytes(page(List.of(node(2,otherHash).put("name","x".repeat(512)),node(3,otherHash)),false,2,"cursor-3"));
        assertThrows(OpenCtiAdapter.Failure.class,()->service.sync(source));assertEquals(prior,snapshot());assertEquals(release,version());
        jdbc.update("UPDATE t_opencti_indicator SET document='{}' WHERE source_id=?",id);
        assertThrows(IllegalStateException.class,()->service.detail(id,iid(1)));assertThrows(IllegalStateException.class,()->service.indicators(id,1,20));
    }
    @Test void readRolesSeeDecisionsAndSelectedEvidenceButCannotChangeSources() throws Exception {
        var unsupported=node(2,otherHash).put("pattern","[file:hashes.'SHA-256' = '"+otherHash+"'] OR [file:name = 'x']");
        response=q->bytes(page(List.of(node(1,hash),unsupported,node(3,otherHash).put("revoked",true)),false,3,"cursor-3"));sync.sync(source);
        String prefix="/api/libraries/sources/"+id;
        for(String role:List.of("viewer","operator","admin")){
            assertEquals(3,data(prefix+"/indicators",role).path("total").asInt());data(prefix+"/indicators/"+iid(1),role);
            if(!role.equals("admin"))for(String path:List.of(prefix,"/api/%6cibraries/sources/"+id,"/api/libraries;matrix=x/sources/"+id))
                assertEquals(403,mvc.perform(post(URI.create(path+"/sync")).header("Authorization","Bearer "+token(role))).andReturn().getResponse().getStatus());
        }
        assertEquals(401,mvc.perform(get(prefix+"/indicators")).andReturn().getResponse().getStatus());
        assertEquals(400,mvc.perform(get(prefix+"/indicators?page=-1").header("Authorization","Bearer "+token("viewer"))).andReturn().getResponse().getStatus());
        capture("status.json",data("/api/libraries","viewer"));capture("indicators.json",data(prefix+"/indicators","viewer"));capture("indicator.json",data(prefix+"/indicators/"+iid(1),"viewer"));
    }
    void capture(String name,Object document)throws IOException{
        String target=System.getenv("ALINKSEC_OPENCTI_FIXTURES");if(target==null||target.isBlank()||pg)return;
        Path folder=Path.of(target);Files.createDirectories(folder);Files.writeString(folder.resolve(name),JsonUtils.write(document));
    }
}
