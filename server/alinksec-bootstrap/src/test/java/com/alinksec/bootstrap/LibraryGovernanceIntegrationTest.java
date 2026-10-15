package com.alinksec.bootstrap;

import com.alinksec.common.util.JsonUtils;
import com.alinksec.service.library.*;
import com.alinksec.service.config.*;
import com.zaxxer.hikari.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.zip.*;
import static org.junit.jupiter.api.Assertions.*;

/** Real SQLite/PostgreSQL lifecycle transactions, retirement publication and competing imports. */
class LibraryGovernanceIntegrationTest {
    @TempDir Path root;
    HikariDataSource pool; JdbcTemplate jdbc; LibraryProperties props; LibraryFiles files;
    LibraryCatalog catalog; DatabaseDialect dialect; DataSourceTransactionManager manager;
    TransactionTemplate tx; long actor; String cve;
    List<String> sources=new ArrayList<>();
    List<String> agents=new ArrayList<>();
    @BeforeEach void setup() throws Exception {
        boolean pg="postgres".equals(System.getProperty("alinksec.integration.database"));
        var config=new HikariConfig();
        config.setJdbcUrl(pg?System.getenv("ALINKSEC_INTEGRATION_PG_URL"):"jdbc:sqlite:"+root.resolve("db"));
        if(pg) { config.setUsername(System.getenv("ALINKSEC_INTEGRATION_PG_USER")); config.setPassword(System.getenv("ALINKSEC_INTEGRATION_PG_PASSWORD")); }
        else { config.addDataSourceProperty("transaction_mode","IMMEDIATE"); config.addDataSourceProperty("busy_timeout",5000); config.addDataSourceProperty("foreign_keys",true); }
        config.setMaximumPoolSize(2); config.setMinimumIdle(1); pool=new HikariDataSource(config);
        if(!pg) new SqliteDatabaseConfiguration.SqliteMigrationBeanPostProcessor().postProcessAfterInitialization(pool,"dataSource");
        jdbc=new JdbcTemplate(pool); manager=new DataSourceTransactionManager(pool); tx=new TransactionTemplate(manager);
        var platform=new AlinkSecProperties(); platform.getDatabase().setType(pg?"postgres":"sqlite");
        platform.getSignature().setStorageDir(root.resolve("signatures").toString());
        props=new LibraryProperties(); props.setWorkDir(root.resolve("work").toString()); files=new LibraryFiles(props,platform);
        dialect=new DatabaseDialect(platform); catalog=new LibraryCatalog(jdbc,props,files,dialect,manager);
        actor=jdbc.queryForObject("INSERT INTO t_user(username,password_hash,role_id,status) VALUES (?,'unused',1,1) RETURNING id",Long.class,"governance-"+UUID.randomUUID());
        cve="CVE-2099-"+String.format("%019d",UUID.randomUUID().getMostSignificantBits() & Long.MAX_VALUE);
    }
    @AfterEach void close() {
        if(jdbc!=null) {
            for(String agent:agents) { jdbc.update("DELETE FROM t_agent_download_token WHERE agent_id=?",agent); jdbc.update("DELETE FROM t_agent WHERE agent_id=?",agent); }
            jdbc.update("DELETE FROM t_security_governance_event WHERE cve_id=?",cve);
            jdbc.update("DELETE FROM t_security_cve WHERE cve_id=?",cve); jdbc.update("DELETE FROM t_cve_db WHERE cve_id=?",cve);
            for(String source:sources) for(String table:List.of("t_security_governance_event","t_security_hash","t_security_rule","t_security_feed_state","t_security_feed_schedule","t_security_source_lifecycle"))
                jdbc.update("DELETE FROM "+table+" WHERE source_id=?",source);
            jdbc.update("DELETE FROM t_virus_db WHERE imported_by=?",actor); jdbc.update("DELETE FROM t_user WHERE id=?",actor);
        }
        if(files!=null) files.close(); if(pool!=null) pool.close();
    }
    String source(String prefix) { String id=prefix+"-"+UUID.randomUUID(); sources.add(id); return id; }
    com.fasterxml.jackson.databind.JsonNode document(String title) {
        return JsonUtils.read(JsonUtils.write(Map.of("cve_id",cve,"severity",3,"title",title,"affected",List.of())));
    }
    String digest(String source) { return String.valueOf(catalog.declarations(cve).stream().filter(row->source.equals(row.get("source_id"))).findFirst().orElseThrow().get("documentDigest")); }
    SignaturePackage hashes(String hash) { return new SignaturePackage("",Map.of(hash,SignaturePackage.checkedHash(hash,"Fixture."+root.getFileName(),3)),List.of()); }
    Map<String,Object> latest() { return jdbc.queryForMap("SELECT * FROM t_virus_db ORDER BY id DESC LIMIT 1"); }
    @Test void selectedWithdrawalKeepsPriorityAndRequiresExplicitLocalReinstatementAfterRefresh() {
        String a=source("a"),z=source("z");
        catalog.cves(z,List.of(document("Lower priority")),actor); catalog.cves(a,List.of(document("Original declaration")),actor);
        String original=digest(a);
        catalog.decideCve(a,cve,true,original,actor,"Incorrect applicability");
        assertEquals("withdrawn",jdbc.queryForObject("SELECT rule_status FROM t_cve_db WHERE cve_id=?",String.class,cve));
        assertEquals(a,jdbc.queryForObject("SELECT rule_source_id FROM t_cve_db WHERE cve_id=?",String.class,cve));
        catalog.cves(a,List.of(document("New upstream text")),actor);
        assertEquals("withdrawn",jdbc.queryForObject("SELECT rule_status FROM t_cve_db WHERE cve_id=?",String.class,cve));
        assertThrows(IllegalArgumentException.class,()->catalog.decideCve(a,cve,false,original,actor,"Stale confirmation"));
        catalog.decideCve(a,cve,false,digest(a),actor,"Independent corrected review");
        assertEquals("active",jdbc.queryForObject("SELECT rule_status FROM t_cve_db WHERE cve_id=?",String.class,cve));
        var events=(List<Map<String,Object>>)catalog.governanceHistory(a,1,20).get("list");
        assertEquals(4,events.size());
        assertTrue(events.stream().anyMatch(e->JsonUtils.write(e.get("snapshot")).contains("Original declaration")));
        assertEquals(1,((List<?>)catalog.governanceHistory(a,2,3).get("list")).size());
    }
    @Test void upstreamWithdrawalCannotBeLocallyOverriddenAndInvalidBatchLeavesNoAudit() {
        String source=source("upstream");
        var withdrawn=(com.fasterxml.jackson.databind.node.ObjectNode)document("Upstream withdrawn");
        withdrawn.put("status","withdrawn").put("withdrawal_reason","Upstream rejected the advisory");
        catalog.cves(source,List.of(withdrawn),actor);
        catalog.decideCve(source,cve,true,digest(source),actor,"Local confirmation");
        assertThrows(IllegalArgumentException.class,()->catalog.decideCve(source,cve,false,digest(source),actor,"Override upstream"));
        var bad=withdrawn.deepCopy(); bad.put("withdrawal_reason","");
        assertThrows(IllegalArgumentException.class,()->catalog.cves(source,List.of(document("Would overwrite"),bad),actor));
        assertEquals(2,jdbc.queryForObject("SELECT count(*) FROM t_security_governance_event WHERE source_id=?",Integer.class,source));
        assertThrows(IllegalArgumentException.class,()->catalog.decideCve(source,cve,true,digest(source),null,"No user"));
    }
    @Test void removedSourceCanBeRetiredWithFallbackAndCannotBeEnabledOrReimported() throws Exception {
        String a=source("a"),z=source("z");
        catalog.cves(a,List.of(document("Selected")),actor); catalog.cves(z,List.of(document("Fallback")),actor);
        assertFalse((Boolean)catalog.governanceSources().stream().filter(row->a.equals(row.get("id"))).findFirst().orElseThrow().get("configured"));
        catalog.retire(a,actor,"No longer a configured provider");
        assertEquals(z,jdbc.queryForObject("SELECT rule_source_id FROM t_cve_db WHERE cve_id=?",String.class,cve));
        assertEquals(1,jdbc.queryForObject("SELECT count(*) FROM t_security_cve WHERE source_id=?",Integer.class,a));
        assertThrows(IllegalArgumentException.class,()->catalog.cves(a,List.of(document("Late import")),actor));
        var configured=new LibraryProperties.Source(); configured.setId(a); configured.setEnabled(true); props.setSources(List.of(configured));
        var schedule=new LibrarySchedule(props,jdbc);
        assertFalse(schedule.reset(a).enabled());
        assertThrows(IllegalArgumentException.class,()->schedule.update(a,true,300000L));
        assertThrows(IllegalArgumentException.class,()->catalog.retire(a,actor,"Duplicate"));
    }
    @Test void disabledOrDemotedAdministratorCannotChangeLifecycleAndOversizeBatchIsAtomic() {
        String source=source("authority"); catalog.cves(source,List.of(document("Current")),actor);
        jdbc.update("UPDATE t_user SET status=0 WHERE id=?",actor);
        assertThrows(IllegalArgumentException.class,()->catalog.decideCve(source,cve,true,digest(source),actor,"Disabled account"));
        jdbc.update("UPDATE t_user SET status=1,role_id=(SELECT id FROM t_role WHERE name='operator') WHERE id=?",actor);
        assertThrows(IllegalArgumentException.class,()->catalog.retire(source,actor,"Demoted account"));
        assertFalse(catalog.isRetired(source));
        assertEquals("active",jdbc.queryForObject("SELECT rule_status FROM t_cve_db WHERE cve_id=?",String.class,cve));
        var huge=(com.fasterxml.jackson.databind.node.ObjectNode)document("Too large"); huge.put("extra","x".repeat(256*1024));
        assertThrows(IllegalArgumentException.class,()->catalog.cves(source,List.of(document("Candidate"),huge),actor));
        assertThrows(IllegalArgumentException.class,()->catalog.cves(source,List.of(document("Duplicate one"),document("Duplicate two")),actor));
        assertEquals(1,jdbc.queryForObject("SELECT count(*) FROM t_security_governance_event WHERE source_id=?",Integer.class,source));
        assertEquals("Current",JsonUtils.read(jdbc.queryForObject("SELECT document FROM t_security_cve WHERE source_id=? AND cve_id=?",String.class,source,cve)).path("title").asText());
    }
    @Test void competingDifferentSourcesRetainDeterministicWholeCvePriority() throws Exception {
        String a=source("a"),z=source("z");
        var other=new LibraryCatalog(jdbc,props,files,dialect,manager); var workers=Executors.newFixedThreadPool(2); var start=new CountDownLatch(1);
        try {
            var preferred=workers.submit(()->{start.await(); return catalog.cves(a,List.of(document("Preferred")),actor);});
            var alternate=workers.submit(()->{start.await(); return other.cves(z,List.of(document("Alternate")),actor);});
            start.countDown(); assertEquals(1,preferred.get(10,TimeUnit.SECONDS)); assertEquals(1,alternate.get(10,TimeUnit.SECONDS));
            assertEquals(a,jdbc.queryForObject("SELECT rule_source_id FROM t_cve_db WHERE cve_id=?",String.class,cve));
            assertEquals(2,jdbc.queryForObject("SELECT count(*) FROM t_security_cve WHERE cve_id=?",Integer.class,cve));
        } finally { workers.shutdownNow(); assertTrue(workers.awaitTermination(5,TimeUnit.SECONDS)); }
    }
    @Test void lastSignatureRetirementPublishesEmptyReleaseAndPreservesHistoricalSource() throws Exception {
        String source=source("hashes"); catalog.signatures(source,hashes("b".repeat(64)),false,actor);
        String old=String.valueOf(latest().get("db_version"));
        String agent="governance-agent-"+UUID.randomUUID(); agents.add(agent);
        jdbc.update("INSERT INTO t_agent(agent_id,hostname,os_type) VALUES (?, ?,1)",agent,agent);
        var tokens=new com.alinksec.service.download.AgentDownloadTokenService(jdbc,dialect);
        String oldKey=String.valueOf(latest().get("package_key")),token=tokens.issue(agent,"virus-db",oldKey);
        var guard=new SignatureCommandGuard(jdbc,tokens,new AlinkSecProperties());
        var queued=com.alinksec.proto.Command.newBuilder().setSignatureUpdate(com.alinksec.proto.CmdSignatureUpdate.newBuilder()
                .setDbVersion(old).setSha256(String.valueOf(latest().get("sha256"))).setDownloadUrl("expired-fixture-url")).build();
        assertTrue(tokens.isAuthorized(token,"virus-db",oldKey));
        assertNotEquals("expired-fixture-url",guard.prepareDelivery(agent,queued).getSignatureUpdate().getDownloadUrl());
        var result=catalog.retire(source,actor,"Withdraw last known hash");
        assertTrue((Boolean)result.get("changed"));
        assertEquals(0,((Number)latest().get("hash_count")).intValue());
        assertNotEquals(old,latest().get("db_version"));
        assertEquals(1,jdbc.queryForObject("SELECT count(*) FROM t_security_hash WHERE source_id=?",Integer.class,source));
        assertFalse(tokens.isAuthorized(token,"virus-db",oldKey));
        assertThrows(IllegalArgumentException.class,()->guard.prepareDelivery(agent,queued));
        try(var in=new ZipInputStream(files.download("signature",String.valueOf(latest().get("package_key"))).resource().getInputStream())) {
            ZipEntry entry; boolean found=false;
            while((entry=in.getNextEntry())!=null) if(entry.getName().equals("hashes.txt")) { assertEquals(0,in.readAllBytes().length); found=true; }
            assertTrue(found);
        }
        assertThrows(IllegalArgumentException.class,()->catalog.signatures(source,hashes("c".repeat(64)),false,actor));
    }
    @Test void outerRetirementRollbackCleansCandidateAndPreservesActiveRelease() throws Exception {
        String source=source("hashes"); catalog.signatures(source,hashes("b".repeat(64)),false,actor);
        String old=String.valueOf(latest().get("db_version"));
        tx.executeWithoutResult(s->{try{catalog.retire(source,actor,"Rolled back retirement");}catch(IOException e){throw new UncheckedIOException(e);}s.setRollbackOnly();});
        assertFalse(catalog.isRetired(source)); assertEquals(old,latest().get("db_version"));
        try(var paths=Files.list(root.resolve("signatures"))) { assertEquals(1,paths.count()); }
        assertEquals(0,jdbc.queryForObject("SELECT count(*) FROM t_security_governance_event WHERE source_id=?",Integer.class,source));
    }
    @Test void failingRetirementPublicationRollsBackLifecycleAuditAndActiveVersion() throws Exception {
        String source=source("hashes"); catalog.signatures(source,hashes("b".repeat(64)),false,actor);
        String old=String.valueOf(latest().get("db_version")); props.getStorage().setBackend("s3");
        assertThrows(IOException.class,()->catalog.retire(source,actor,"Provider stopped"));
        assertFalse(catalog.isRetired(source)); assertEquals(old,latest().get("db_version"));
        assertEquals(0,jdbc.queryForObject("SELECT count(*) FROM t_security_governance_event WHERE source_id=?",Integer.class,source));
    }
    @Test void outerRollbackKeepsDeclarationAuthorityAndCursorTogether() {
        String source=source("nvd");
        jdbc.update("INSERT INTO t_security_feed_state(source_id,kind,cursor) VALUES (?,'nvd','2026-01-01T00:00:00Z')",source);
        tx.executeWithoutResult(s->{catalog.cveWindow(source,List.of(document("Candidate")),java.time.Instant.parse("2026-02-01T00:00:00Z")); s.setRollbackOnly();});
        assertEquals(0,jdbc.queryForObject("SELECT count(*) FROM t_security_cve WHERE source_id=?",Integer.class,source));
        assertEquals("2026-01-01T00:00:00Z",jdbc.queryForObject("SELECT cursor FROM t_security_feed_state WHERE source_id=?",String.class,source));
        assertEquals(0,jdbc.queryForObject("SELECT count(*) FROM t_security_governance_event WHERE source_id=?",Integer.class,source));
    }
    @Test void competingRetirementAndImportCannotRestoreRetiredAuthority() throws Exception {
        String source=source("race"); catalog.cves(source,List.of(document("Initial")),actor);
        var other=new LibraryCatalog(jdbc,props,files,dialect,manager); var workers=Executors.newFixedThreadPool(2); var start=new CountDownLatch(1);
        try {
            var retire=workers.submit(()->{start.await(); catalog.retire(source,actor,"Retire competing provider"); return true;});
            var refresh=workers.submit(()->{start.await(); try{other.cves(source,List.of(document("Late import")),actor);}catch(IllegalArgumentException expected){} return true;});
            start.countDown(); assertTrue(retire.get(10,TimeUnit.SECONDS)); assertTrue(refresh.get(10,TimeUnit.SECONDS));
            assertTrue(catalog.isRetired(source));
            assertEquals("retired",jdbc.queryForObject("SELECT rule_status FROM t_cve_db WHERE cve_id=?",String.class,cve));
        } finally { workers.shutdownNow(); assertTrue(workers.awaitTermination(5,TimeUnit.SECONDS)); }
    }
    Map<String,Object> consoleSnapshot(String a,String z) {
        var status=new LinkedHashMap<String,Object>();
        status.put("sources",List.of()); status.put("signature",Map.of()); status.put("storage","local");
        status.put("managedCveCount",1); status.put("matchableCveCount",0); status.put("running",false);
        status.put("governanceSources",catalog.governanceSources().stream().filter(row->Set.of(a,z).contains(row.get("id"))).toList());
        return Map.of("status",status,"rules",catalog.cveRules(cve,1,20),"declarations",catalog.declarations(cve),"history",catalog.governanceHistory(a,1,20));
    }
    @Test void captureRealConsoleLifecycleResponses() throws Exception {
        String a=source("a"),z=source("z");
        catalog.cves(a,List.of(document("Browser governance declaration")),actor);
        catalog.cves(z,List.of(document("Alternative declaration")),actor);
        var stages=new LinkedHashMap<String,Object>(); stages.put("active",consoleSnapshot(a,z));
        catalog.decideCve(a,cve,true,digest(a),actor,"Browser fixture withdrawal"); stages.put("withdrawn",consoleSnapshot(a,z));
        catalog.decideCve(a,cve,false,digest(a),actor,"Browser fixture independent reinstatement"); stages.put("restored",consoleSnapshot(a,z));
        catalog.retire(a,actor,"Browser fixture retired provider"); stages.put("retired",consoleSnapshot(a,z));
        String output=System.getenv("ALINKSEC_GOVERNANCE_FIXTURE_DIR");
        if(output!=null && !output.isBlank()) {
            Path directory=Path.of(output); Files.createDirectories(directory);
            String database="postgres".equals(System.getProperty("alinksec.integration.database"))?"postgres":"sqlite";
            Files.writeString(directory.resolve("console-"+database+".json"),JsonUtils.write(Map.of("database",database,"source",a,"cve",cve,"stages",stages)));
        }
        assertEquals(2,((List<?>)((Map<?,?>)stages.get("retired")).get("declarations")).size());
    }

}
