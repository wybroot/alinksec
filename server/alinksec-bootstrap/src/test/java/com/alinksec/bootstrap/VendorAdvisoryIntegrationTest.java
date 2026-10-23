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
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.zip.GZIPOutputStream;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;

/** Real HTTP, raw bytes, multi-connection SQLite/PostgreSQL transactions and resolved-route RBAC. */
class VendorAdvisoryIntegrationTest {
    @TempDir Path root;
    HikariDataSource pool; JdbcTemplate jdbc; LibraryProperties props; LibraryFiles files;
    LibraryCatalog catalog; LibrarySyncService sync; LibrarySchedule schedules; VendorAdvisoryProperties limits;
    VendorAdvisoryService service; LibraryProperties.Source source; HttpServer http; ExecutorService workers;
    VulnMatchService assetMatcher;
    MockMvc mvc; String base,id,cve; boolean pg; Long actor;
    final Map<String,byte[]> bodies=new ConcurrentHashMap<>();
    final AtomicInteger requests=new AtomicInteger(),conditional=new AtomicInteger(),redirectTarget=new AtomicInteger();
    volatile int status=200; volatile boolean force304;
    static final String SECRET="native-advisory-integration-secret-32-bytes";
    @BeforeEach void setup() throws Exception {
        pg="postgres".equals(System.getProperty("alinksec.integration.database"));
        var config=new HikariConfig();config.setJdbcUrl(pg?System.getenv("ALINKSEC_INTEGRATION_PG_URL"):"jdbc:sqlite:"+root.resolve("db"));
        if (pg) { config.setUsername(System.getenv("ALINKSEC_INTEGRATION_PG_USER"));config.setPassword(System.getenv("ALINKSEC_INTEGRATION_PG_PASSWORD")); }
        else { config.addDataSourceProperty("transaction_mode","IMMEDIATE");config.addDataSourceProperty("busy_timeout",5000);config.addDataSourceProperty("foreign_keys",true); }
        config.setMaximumPoolSize(3);config.setMinimumIdle(1);pool=new HikariDataSource(config);
        if (!pg) new SqliteDatabaseConfiguration.SqliteMigrationBeanPostProcessor().postProcessAfterInitialization(pool,"dataSource");
        jdbc=new JdbcTemplate(pool);
        actor=jdbc.queryForObject("INSERT INTO t_user(username,password_hash,role_id,status) VALUES (?,'unused',1,1) RETURNING id",Long.class,"native-"+UUID.randomUUID());
        String suffix=UUID.randomUUID().toString().replace("-","");id="vendor-"+suffix;
        cve="CVE-2098-"+Long.toUnsignedString(UUID.randomUUID().getMostSignificantBits()).substring(0,12);
        http=HttpServer.create(new InetSocketAddress("127.0.0.1",0),0);workers=Executors.newCachedThreadPool();http.setExecutor(workers);
        http.createContext("/",exchange->{
            requests.incrementAndGet();String path=exchange.getRequestURI().getPath();
            if (path.equals("/redirect-target")) redirectTarget.incrementAndGet();
            byte[] body=bodies.getOrDefault(path,new byte[0]);String etag="\""+digest(body)+"\"";
            if (status==302) { exchange.getResponseHeaders().set("Location",base+"/redirect-target");exchange.sendResponseHeaders(302,-1); }
            else if (force304 || etag.equals(exchange.getRequestHeaders().getFirst("If-None-Match"))) { conditional.incrementAndGet();exchange.sendResponseHeaders(304,-1); }
            else { exchange.getResponseHeaders().set("ETag",etag);exchange.sendResponseHeaders(status,body.length);exchange.getResponseBody().write(body); }
            exchange.close();
        });http.start();base="http://127.0.0.1:"+http.getAddress().getPort();
        props=new LibraryProperties();props.setWorkDir(root.resolve("work").toString());
        source=new LibraryProperties.Source();source.setId(id);source.setType("ubuntu-usn");source.setUrl(base+"/notices/USN-1-1.json");source.setEnabled(true);props.setSources(List.of(source));
        var platform=new AlinkSecProperties();platform.getDatabase().setType(pg?"postgres":"sqlite");
        files=new LibraryFiles(props,platform);catalog=new LibraryCatalog(jdbc,props,files,new DatabaseDialect(platform),new DataSourceTransactionManager(pool));
        schedules=new LibrarySchedule(props,jdbc);limits=new VendorAdvisoryProperties();
        var downloader=new FeedDownload(files,props);
        assetMatcher=mock(VulnMatchService.class);
        sync=new LibrarySyncService(props,catalog,mock(VirusDbService.class),downloader,jdbc,assetMatcher,schedules,limits);
        service=sync.nativeAdvisories(id);sync.validate();
        var holder=mock(JwtSecretHolder.class);when(holder.secret()).thenReturn(SECRET);
        mvc=MockMvcBuilders.standaloneSetup(new LibraryController(sync,catalog,props,schedules)).setControllerAdvice(new RestExceptionHandler())
                .addInterceptors(new JwtAuthInterceptor(holder)).build();
    }
    @AfterEach void close() throws Exception {
        if (sync!=null) sync.close();if (http!=null) http.stop(0);if (workers!=null) workers.shutdownNow();
        if (jdbc!=null) {
            for (String table:List.of("t_vuln_finding","t_asset_software")) jdbc.update("DELETE FROM "+table+" WHERE agent_id=?",id+"-host");
            jdbc.update("DELETE FROM t_agent WHERE agent_id=?",id+"-host");
            for (String table:List.of("t_vendor_contribution","t_vendor_document","t_vendor_sync_state","t_security_governance_event","t_security_cve","t_security_feed_run","t_security_feed_state","t_security_feed_schedule","t_security_source_lifecycle"))
                jdbc.update("DELETE FROM "+table+" WHERE source_id=?",id);
            jdbc.update("DELETE FROM t_cve_db WHERE cve_id=?",cve);
            jdbc.update("DELETE FROM t_user WHERE id=?",actor);
        }
        if(files!=null)files.close();if(pool!=null)pool.close();
    }
    static byte[] bytes(Object document) { return JsonUtils.write(document).getBytes(StandardCharsets.UTF_8); }
    static String digest(byte[] raw) { try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw)); } catch(Exception e) { throw new IllegalStateException(e); } }
    byte[] usn(String document,String title,boolean present) {
        return bytes(Map.of("id",document,"title",title,"published","2026-10-01T01:02:03Z","description","Native publisher fixture, not a live patch result.",
                "cves_ids",present?List.of(cve):List.of(),"release_packages",Map.of("jammy",List.of(Map.of("name","libnss3","version","2:3.98-1","is_source",false)))));
    }
    List<Map<String,Object>> archives() { return jdbc.queryForList("SELECT * FROM t_vendor_document WHERE source_id=? ORDER BY imported_at DESC,id DESC",id); }
    JsonNode declaration() { return JsonUtils.read(jdbc.queryForObject("SELECT document FROM t_security_cve WHERE source_id=? AND cve_id=?",String.class,id,cve)); }
    String token(String role) { return JwtUtil.sign(SECRET,Map.of("uid",actor,"username","fixture","role",role),3600); }
    JsonNode getData(String path,String role) throws Exception {
        var result=mvc.perform(get(path).header("Authorization","Bearer "+token(role))).andReturn();assertEquals(200,result.getResponse().getStatus());
        return JsonUtils.mapper().readTree(result.getResponse().getContentAsByteArray()).path("data");
    }
    @Test void rawArchiveShaProvenanceAndConditionalResponsesAreIdempotent() throws Exception {
        byte[] raw=usn("USN-1-1","NSS fixture",true);bodies.put("/notices/USN-1-1.json",raw);
        assertEquals(1,service.sync(source));assertEquals(1,service.sync(source));assertTrue(conditional.get()>0);assertEquals(1,archives().size());
        var archive=archives().get(0);assertEquals(digest(raw),archive.get("sha256"));assertArrayEquals(raw,service.raw(id,archive.get("id").toString()));
        JsonNode provenance=JsonUtils.read(jdbc.queryForObject("SELECT provenance FROM t_security_cve WHERE source_id=? AND cve_id=?",String.class,id,cve));
        assertEquals("native_vendor_advisory",provenance.path("ingestion").asText());assertFalse(provenance.path("signature_verified").asBoolean());
        assertEquals(archive.get("id"),provenance.path("raw_documents").get(0).path("id").asText());assertEquals("configured_mirror",archive.get("origin_kind"));
        assertTrue(declaration().path("affected").isEmpty());assertTrue(declaration().path("vendor_advisories").size()>0);
    }
    @Test void publisherDocumentsForOneCveAggregateAndOmissionDoesNotEraseOtherContributions() throws Exception {
        source.setUrl(base);limits.setDocumentsPerSync(1);
        String published=Instant.now().toString();
        bodies.put("/notices.json",bytes(Map.of("notices",List.of(Map.of("id","USN-1-1","published",published),Map.of("id","USN-1-2","published",published)))));
        bodies.put("/notices/USN-1-1.json",usn("USN-1-1","First",true));bodies.put("/notices/USN-1-2.json",usn("USN-1-2","Second",true));
        service.sync(source);assertEquals(1,((Number)service.state(id).get("pending_count")).intValue());
        service.sync(source);assertEquals(0,((Number)service.state(id).get("pending_count")).intValue());assertEquals(2,declaration().path("vendor_advisories").size());
        bodies.put("/notices/USN-1-1.json",usn("USN-1-1","No CVE in first",false));
        jdbc.update("UPDATE t_vendor_document SET checked_at=? WHERE source_id=? AND document_id='USN-1-1'",Instant.EPOCH.toString(),id);
        service.sync(source);assertEquals(1,declaration().path("vendor_advisories").size());assertEquals("USN-1-2",declaration().path("vendor_advisories").get(0).path("advisory_id").asText());
        bodies.put("/notices/USN-1-2.json",usn("USN-1-2","No CVE in second",false));
        jdbc.update("UPDATE t_vendor_document SET checked_at=? WHERE source_id=? AND document_id='USN-1-2'",Instant.EPOCH.toString(),id);
        service.sync(source);assertEquals("not_reaffirmed",declaration().path("native_presence").asText());assertTrue(declaration().path("affected").isEmpty());
        assertNotEquals("withdrawn",declaration().path("status").asText());assertEquals(4,archives().size());
    }
    @Test void malformedOversizedRedirectedAndUncached304PreserveAcceptedContent() throws Exception {
        bodies.put("/notices/USN-1-1.json",usn("USN-1-1","Accepted",true));service.sync(source);String frozen=JsonUtils.write(declaration());
        bodies.put("/notices/USN-1-1.json","{\"id\":\"wrong\"}".getBytes(StandardCharsets.UTF_8));assertThrows(Exception.class,()->service.sync(source));
        status=302;assertThrows(Exception.class,()->service.sync(source));assertEquals(0,redirectTarget.get());status=200;
        limits.setMaxDocumentBytes(1024);bodies.put("/notices/USN-1-1.json",new byte[1025]);assertThrows(Exception.class,()->service.sync(source));
        assertEquals(frozen,JsonUtils.write(declaration()));assertEquals(1,archives().size());
        jdbc.update("DELETE FROM t_vendor_contribution WHERE source_id=?",id);jdbc.update("DELETE FROM t_vendor_document WHERE source_id=?",id);
        force304=true;assertThrows(Exception.class,()->service.sync(source));assertEquals(0,archives().size());
    }
    @Test void partiallyCommittedRoundRechecksAssetsAndReportsDurableCounts() {
        source.setUrl(base);String now=Instant.now().toString();
        bodies.put("/notices.json",bytes(Map.of("notices",List.of(Map.of("id","USN-1-1","published",now),Map.of("id","USN-1-2","published",now)))));
        bodies.put("/notices/USN-1-1.json",usn("USN-1-1","Accepted before failure",true));
        bodies.put("/notices/USN-1-2.json",bytes(Map.of("id","invalid")));
        sync.sync(source);verify(assetMatcher).matchAll(0);
        assertEquals(1,archives().size());var state=jdbc.queryForMap("SELECT * FROM t_security_feed_state WHERE source_id=?",id);
        assertEquals("failed",state.get("status"));assertEquals(1,((Number)state.get("entry_count")).intValue());
        assertEquals(1,((Number)service.state(id).get("pending_count")).intValue());
        assertEquals("failed",jdbc.queryForObject("SELECT status FROM t_security_feed_run WHERE source_id=?",String.class,id));
        bodies.put("/notices/USN-1-2.json",usn("USN-1-2","Accepted on retry",true));
        doThrow(new IllegalStateException("private matcher diagnostic")).when(assetMatcher).matchAll(0);
        sync.sync(source);assertEquals(2,archives().size());
        String message=jdbc.queryForObject("SELECT error FROM t_security_feed_state WHERE source_id=?",String.class,id);
        assertTrue(message.contains("资产重新比对失败"));assertFalse(message.contains("private"));
        doReturn(0).when(assetMatcher).matchAll(0);sync.sync(source);verify(assetMatcher,times(3)).matchAll(0);
        assertEquals("success",jdbc.queryForObject("SELECT status FROM t_security_feed_state WHERE source_id=?",String.class,id));
    }
    @Test void nativeScopeIsPinnedAndRetirementBlocksFurtherCommitsButKeepsRawEvidence() throws Exception {
        bodies.put("/notices/USN-1-1.json",usn("USN-1-1","Accepted",true));service.sync(source);String archive=archives().get(0).get("id").toString();
        source.setUrl(base+"/other/notices/USN-1-1.json");int prior=requests.get();assertThrows(IllegalArgumentException.class,()->service.sync(source));assertEquals(prior,requests.get());
        source.setUrl(base+"/notices/USN-1-1.json");source.setType("cve-json");
        sync.sync(source);assertEquals(prior,requests.get());assertEquals("failed",jdbc.queryForObject("SELECT status FROM t_security_feed_state WHERE source_id=?",String.class,id));
        assertTrue(service.configurationIssue(source).contains("来源标识"));assertThrows(IllegalArgumentException.class,()->schedules.update(id,true,7_200_000L));
        source.setType("ubuntu-usn");catalog.retire(id,actor,"Fixture retired");
        assertThrows(IllegalArgumentException.class,()->service.sync(source));assertNotNull(service.raw(id,archive));assertEquals(1,archives().size());
    }
    @Test void archiveAndContributionChangesRollbackTogetherWhenMergedCveExceedsCapacity() throws Exception {
        source.setUrl(base);limits.setDocumentsPerSync(1);
        String published=Instant.now().toString();
        bodies.put("/notices.json",bytes(Map.of("notices",List.of(Map.of("id","USN-1-1","published",published),Map.of("id","USN-1-2","published",published)))));
        var first=(ObjectNode)JsonUtils.read(new String(usn("USN-1-1","First",true),StandardCharsets.UTF_8));
        var pkgs=first.withObject("/release_packages").putArray("jammy");
        for(int n=0;n<500;n++)pkgs.addObject().put("name","package-"+n+"x".repeat(160)).put("version","1".repeat(150)).put("is_source",false);
        bodies.put("/notices/USN-1-1.json",bytes(first));service.sync(source);String frozen=JsonUtils.write(declaration());
        first.put("id","USN-1-2");bodies.put("/notices/USN-1-2.json",bytes(first));
        assertThrows(Exception.class,()->service.sync(source));assertEquals(1,archives().size());assertEquals(frozen,JsonUtils.write(declaration()));
        assertEquals(1,jdbc.queryForObject("SELECT count(*) FROM t_vendor_contribution WHERE source_id=?",Integer.class,id));
    }
    @Test void rawRetentionKeepsAuditDigestsAndDetectsStoredBodyTampering() throws Exception {
        limits.setRetainRawVersions(1);
        for(int n=0;n<3;n++){bodies.put("/notices/USN-1-1.json",usn("USN-1-1","Revision "+n,true));service.sync(source);}
        assertEquals(3,archives().size());assertEquals(1,archives().stream().filter(a->a.get("raw_base64")!=null).count());
        var old=archives().stream().filter(a->a.get("raw_base64")==null).findFirst().orElseThrow();assertThrows(IllegalArgumentException.class,()->service.raw(id,old.get("id").toString()));
        var current=archives().stream().filter(a->a.get("raw_base64")!=null).findFirst().orElseThrow();
        jdbc.update("UPDATE t_vendor_document SET raw_base64=? WHERE id=?",Base64.getEncoder().encodeToString("tampered".getBytes(StandardCharsets.UTF_8)),current.get("id"));
        assertThrows(IllegalStateException.class,()->service.raw(id,current.get("id").toString()));assertEquals(3,service.documents(id,1,20).get("total"));
    }
    @Test void archiveBudgetRollbackKeepsPreviousBodyCurrentFlagAndContributions() throws Exception {
        bodies.put("/notices/USN-1-1.json",usn("USN-1-1","Accepted",true));service.sync(source);
        var original=archives().get(0);String frozen=JsonUtils.write(declaration());limits.setMaxArchiveBytes(32L<<20);
        // Inject existing archive usage at the configured limit, without allocating a large dummy payload.
        jdbc.update("UPDATE t_vendor_document SET size_bytes=? WHERE id=?",32L<<20,original.get("id"));
        bodies.put("/notices/USN-1-1.json",usn("USN-1-1","Over budget",true));assertThrows(IllegalArgumentException.class,()->service.sync(source));
        assertEquals(1,archives().size());assertEquals(1,((Number)archives().get(0).get("current_version")).intValue());
        assertEquals(frozen,JsonUtils.write(declaration()));assertEquals(original.get("sha256"),digest(service.raw(id,original.get("id").toString())));
        jdbc.update("UPDATE t_vendor_document SET size_bytes=? WHERE id=?",((Number)original.get("size_bytes")).longValue(),original.get("id"));
        service.sync(source);assertEquals(2,archives().size());
    }
    @Test void compressedTrackerIsArchivedAsReceivedAndOnlySelectedSourcePackagesBecomeMetadata() throws Exception {
        source.setType("debian-tracker");source.setUrl(base+"/tracker/data/json");source.setVendorPackages(List.of("openssl"));
        byte[] json=bytes(Map.of("openssl",Map.of(cve,Map.of("description","Source status","releases",Map.of("bookworm",Map.of("status","resolved","fixed_version","3.0.0","urgency","medium"))))));
        var output=new ByteArrayOutputStream();try(var gzip=new GZIPOutputStream(output)){gzip.write(json);}byte[] raw=output.toByteArray();bodies.put("/tracker/data/json",raw);
        service.sync(source);assertTrue(declaration().path("affected").isEmpty());assertEquals("source",declaration().path("vendor_advisories").get(0).path("package_scope").asText());
        assertArrayEquals(raw,service.raw(id,archives().get(0).get("id").toString()));
    }
    @Test void redhatChangesDiscoveryAndExplicitBinaryStatusDriveExactVersionFindingsOnly() throws Exception {
        source.setType("redhat-csaf");source.setUrl(base);
        var product=new LibraryProperties.VendorProduct();product.setProductId("rhel-product");product.setDistroId("rhel");product.setDistroVersion("9.3");source.setVendorProducts(List.of(product));
        String now=Instant.now().toString();
        bodies.put("/changes.csv",("\"2024/rhsa-2024_0001.json\",\""+now+"\"\n").getBytes(StandardCharsets.UTF_8));
        ObjectNode advisory=(ObjectNode)JsonUtils.read("""
                {"document":{"csaf_version":"2.0","title":"Native RPM boundary","tracking":{"id":"RHSA-2024:0001","version":"1","current_release_date":"2026-10-01T01:02:03Z"}},
                 "product_tree":{"branches":[{"product":{"product_id":"binary","name":"thunderbird-0:115.6.0-1.el9_3.x86_64","product_identification_helper":{"purl":"pkg:rpm/redhat/thunderbird@115.6.0-1.el9_3?arch=x86_64"}}}],
                 "relationships":[{"category":"default_component_of","product_reference":"binary","relates_to_product_reference":"rhel-product","full_product_name":{"product_id":"installed"}}]},
                 "vulnerabilities":[{"cve":"REPLACE","product_status":{"known_affected":["installed"]},"scores":[{"cvss_v3":{"baseScore":8.8}}]}]}
                """.replace("REPLACE",cve));
        bodies.put("/2024/rhsa-2024_0001.json",bytes(advisory));service.sync(source);
        assertEquals("=0:115.6.0-1.el9_3",declaration().path("affected").get(0).path("vrange").asText());
        assertEquals("",declaration().path("affected").get(0).path("fixed_version").asText());
        jdbc.update("INSERT INTO t_agent(agent_id,hostname,os_type,os_version,machine_id,software_collection_status,distro_id,distro_version) VALUES (?, 'native-fixture',1,'fixture',?,'complete','rhel','9.3')",id+"-host",id);
        jdbc.update("INSERT INTO t_asset_software(agent_id,name,version,source,architecture) VALUES (?,'thunderbird','0:115.6.0-1.el9_3','rpm','x86_64')",id+"-host");
        var matcher=new VulnMatchService(jdbc,new DataSourceTransactionManager(pool));matcher.matchAgent(id+"-host",0);
        assertEquals(1,jdbc.queryForObject("SELECT count(*) FROM t_vuln_finding WHERE agent_id=? AND cve_id=? AND current_match=true",Integer.class,id+"-host",cve));
        jdbc.update("UPDATE t_asset_software SET version='0:115.5.0-1.el9_3' WHERE agent_id=?",id+"-host");matcher.matchAgent(id+"-host",0);
        assertEquals(0,jdbc.queryForObject("SELECT count(*) FROM t_vuln_finding WHERE agent_id=? AND current_match=true",Integer.class,id+"-host"));
        jdbc.update("UPDATE t_asset_software SET version='0:115.6.0-1.el9_3' WHERE agent_id=?",id+"-host");
        ((ObjectNode)advisory.path("vulnerabilities").get(0)).putObject("product_status").putArray("fixed").add("installed");
        bodies.put("/2024/rhsa-2024_0001.json",bytes(advisory));jdbc.update("UPDATE t_vendor_document SET checked_at=? WHERE source_id=?",Instant.EPOCH.toString(),id);service.sync(source);matcher.matchAgent(id+"-host",0);
        assertEquals("not_affected",declaration().path("affected").get(0).path("evidence").path("assessment").asText());
        assertEquals(0,jdbc.queryForObject("SELECT count(*) FROM t_vuln_finding WHERE agent_id=? AND current_match=true",Integer.class,id+"-host"));
    }
    @Test void microsoftUpdatesConstructValidatedMonthlyPathsAndIgnoreRemoteCvrfUrls() throws Exception {
        source.setType("msrc-cvrf");source.setUrl(base);
        String now=Instant.now().toString();
        bodies.put("/updates",bytes(Map.of("value",List.of(Map.of("ID","2024-Apr","CurrentReleaseDate",now,"CvrfUrl",base+"/redirect-target")))));
        bodies.put("/cvrf/2024-Apr",bytes(Map.of("DocumentTracking",Map.of("Identification",Map.of("ID",Map.of("Value","2024-Apr")),"CurrentReleaseDate",now,"Version","1"),
                "DocumentTitle",Map.of("Value","Microsoft monthly fixture"),"Vulnerability",List.of(Map.of("CVE",cve,"Title",Map.of("Value","KB metadata"),
                "Remediations",List.of(Map.of("Type",2,"Description",Map.of("Value","5030000"),"FixedBuild","10.0.1","ProductID",List.of("windows-product"))))))));
        service.sync(source);assertEquals(0,redirectTarget.get());assertTrue(declaration().path("affected").isEmpty());
        assertEquals("5030000",declaration().path("vendor_advisories").get(0).path("remediations").get(0).path("description").asText());
        assertEquals(1,archives().size());
        bodies.put("/updates",bytes(Map.of("value",List.of(Map.of("ID","../redirect-target","CurrentReleaseDate",now)))));
        assertThrows(IllegalArgumentException.class,()->service.sync(source));assertEquals(0,redirectTarget.get());assertEquals(1,archives().size());
    }
    @Test void resolvedRoutesPermitReadOnlyRawAccessAndRejectViewerAndOperatorMutations() throws Exception {
        bodies.put("/notices/USN-1-1.json",usn("USN-1-1","Role boundary",true));sync.sync(source);
        String prefix="/api/libraries/sources/"+id,archive=archives().get(0).get("id").toString();
        for(String role:List.of("viewer","operator","admin")) {
            assertEquals(1,getData(prefix+"/advisories",role).path("total").asInt());getData(prefix+"/advisories/"+archive,role);
            var raw=mvc.perform(get(prefix+"/advisories/"+archive+"/raw").header("Authorization","Bearer "+token(role))).andReturn().getResponse();
            assertEquals(200,raw.getStatus());assertEquals(digest(raw.getContentAsByteArray()),raw.getHeader("X-Content-SHA256"));assertEquals("nosniff",raw.getHeader("X-Content-Type-Options"));
            if (!role.equals("admin")) for(String path:List.of(prefix,"/api/%6cibraries/sources/"+id,"/api/libraries;matrix=x/sources/"+id))
                assertEquals(403,mvc.perform(post(java.net.URI.create(path+"/sync")).header("Authorization","Bearer "+token(role))).andReturn().getResponse().getStatus());
        }
        assertEquals(401,mvc.perform(get(prefix+"/advisories")).andReturn().getResponse().getStatus());
        assertEquals(400,mvc.perform(get(prefix+"/advisories?page=-1").header("Authorization","Bearer "+token("viewer"))).andReturn().getResponse().getStatus());
        assertThrows(IllegalArgumentException.class,()->catalog.cves("manual",List.of(JsonUtils.read("{\"cve_id\":\""+cve+"\",\"severity\":1,\"affected\":[],\"provenance\":{\"verification\":\"parsed_transport_document\"}}"))));
        capture("status.json",getData("/api/libraries","viewer"));capture("documents.json",getData(prefix+"/advisories","viewer"));
        capture("document.json",getData(prefix+"/advisories/"+archive,"viewer"));
        capture("raw.json",Map.of("base64",Base64.getEncoder().encodeToString(service.raw(id,archive)),"sha256",archives().get(0).get("sha256")));
    }
    void capture(String name,Object document) throws IOException {
        String target=System.getenv("ALINKSEC_VENDOR_ADVISORY_FIXTURES");if(target==null||target.isBlank()||pg)return;
        Path folder=Path.of(target);Files.createDirectories(folder);Files.writeString(folder.resolve(name),JsonUtils.write(document));
    }
}
