package com.alinksec.bootstrap;

import com.alinksec.common.util.JsonUtils;
import com.alinksec.proto.*;
import com.alinksec.service.library.*;
import com.alinksec.service.agent.AgentRepository;
import com.alinksec.service.command.CommandService;
import com.alinksec.service.config.*;
import com.alinksec.service.download.AgentDownloadTokenService;
import com.alinksec.service.virus.VirusDbService;
import com.zaxxer.hikari.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.support.DefaultTransactionDefinition;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.net.*;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/** Real publication, delivery, tokens and rollback in both supported databases.
 * An outer rollback restores shared PostgreSQL fixtures after each test. */
class SignatureDeltaIntegrationTest {
    @TempDir Path root;
    HikariDataSource pool; JdbcTemplate jdbc; LibraryCatalog catalog; LibraryFiles files;
    AlinkSecProperties platform; LibraryProperties props; DataSourceTransactionManager manager;
    TransactionStatus transaction; AgentDownloadTokenService tokens; SignatureCommandGuard guard;
    String agent;
    @BeforeEach void setup() {
        boolean pg="postgres".equals(System.getProperty("alinksec.integration.database"));
        var c=new HikariConfig();c.setJdbcUrl(pg?System.getenv("ALINKSEC_INTEGRATION_PG_URL"):"jdbc:sqlite:"+root.resolve("db"));
        if(pg){c.setUsername(System.getenv("ALINKSEC_INTEGRATION_PG_USER"));c.setPassword(System.getenv("ALINKSEC_INTEGRATION_PG_PASSWORD"));}
        else{c.addDataSourceProperty("foreign_keys",true);c.addDataSourceProperty("busy_timeout",5000);}
        c.setMaximumPoolSize(2);c.setMinimumIdle(1);pool=new HikariDataSource(c);
        if(!pg)new SqliteDatabaseConfiguration.SqliteMigrationBeanPostProcessor().postProcessAfterInitialization(pool,"dataSource");
        jdbc=new JdbcTemplate(pool); manager=new DataSourceTransactionManager(pool);
        transaction=manager.getTransaction(new DefaultTransactionDefinition());
        jdbc.update("DELETE FROM t_command WHERE type='signature_update'");
        for(String table:List.of("t_security_hash","t_security_rule","t_virus_db"))jdbc.update("DELETE FROM "+table);
        jdbc.update("DELETE FROM t_security_feed_state WHERE source_id IN ('_signature-release','_legacy-signature')");
        platform=new AlinkSecProperties();platform.getDatabase().setType(pg?"postgres":"sqlite");platform.getSignature().setStorageDir(root.resolve("signatures").toString());
        props=new LibraryProperties();props.setWorkDir(root.resolve("work").toString());
        files=new LibraryFiles(props,platform);var dialect=new DatabaseDialect(platform);
        catalog=new LibraryCatalog(jdbc,props,files,dialect,manager);tokens=new AgentDownloadTokenService(jdbc,dialect);guard=new SignatureCommandGuard(jdbc,tokens,platform);
        agent="delta-"+UUID.randomUUID();jdbc.update("INSERT INTO t_agent(agent_id,hostname,ip,os_type,status) VALUES(?,?,'192.0.2.55',1,1)",agent,"增量更新验收");
    }
    @AfterEach void close(){if(transaction!=null && !transaction.isCompleted())manager.rollback(transaction);if(files!=null)files.close();if(pool!=null)pool.close();}
    static String hash(String text) {
        try{return HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8)));}
        catch(Exception e){throw new IllegalStateException(e);}
    }
    Map<String,SignaturePackage.Hash> hashes(int count) {
        Map<String,SignaturePackage.Hash> result=new TreeMap<>();
        for(int i=0;i<count;i++){String h=hash("harmless-delta-"+i);result.put(h,SignaturePackage.checkedHash(h,"Fixture."+i,3));}return result;
    }
    Map<String,Object> publish(String version,Map<String,SignaturePackage.Hash> hashes,String rule) throws Exception {
        var rules=rule.isEmpty()?List.<com.fasterxml.jackson.databind.JsonNode>of():List.of(JsonUtils.read("{\"name\":\""+rule+"\",\"strings\":[{\"value\":\""+(rule.equals("Old.Rule")?"before-only":"after-only")+"\"}]}"));
        catalog.signatures("manual",new SignaturePackage(version,hashes,rules),true,null);
        return jdbc.queryForMap("SELECT * FROM t_virus_db ORDER BY id DESC LIMIT 1");
    }
    Command command(Map<String,Object> row) {
        return Command.newBuilder().setSignatureUpdate(CmdSignatureUpdate.newBuilder().setDbVersion(String.valueOf(row.get("db_version"))).setSha256(String.valueOf(row.get("sha256")))).build();
    }
    Map<String,String> query(String url) {
        Map<String,String> q=new HashMap<>();for(String pair:URI.create(url).getRawQuery().split("&")){String[] p=pair.split("=",2);q.put(p[0],URLDecoder.decode(p[1],StandardCharsets.UTF_8));}return q;
    }
    Map<String,Object> status() {
        var virus=new VirusDbService(jdbc,mock(CommandService.class),platform,tokens,catalog,files,props);
        var sync=new LibrarySyncService(props,catalog,virus,new FeedDownload(files,props),jdbc,mock(com.alinksec.service.scan.VulnMatchService.class),new LibrarySchedule(props,jdbc));
        try{return sync.status();}finally{sync.close();}
    }
    @Test void adjacentDeltaBindsContentAndDeliveryCapabilitiesAndScopedTokens() throws Exception {
        var original=hashes(1000);var base=publish("delta-base",original,"Old.Rule");var baseStatus=status();
        var updated=new TreeMap<>(original);updated.remove(hash("harmless-delta-3"));String changed=hash("harmless-delta-4");updated.put(changed,SignaturePackage.checkedHash(changed,"Changed.Metadata",5));String added=hash("new-harmless-entry");updated.put(added,SignaturePackage.checkedHash(added,"Added.Fixture",4));
        var target=publish("delta-target",updated,"New.Rule");
        assertEquals("delta-base",target.get("delta_base_version"));assertEquals(base.get("content_sha256"),target.get("delta_base_content_sha256"));
        assertTrue(((Number)target.get("delta_size")).longValue()*5<((Number)target.get("size")).longValue()*4);
        var old=guard.prepareDelivery(agent,command(target)).getSignatureUpdate();assertEquals(0,old.getUpdateContract());assertTrue(old.getDeltaUrl().isEmpty());
        var repository=new AgentRepository(jdbc,new DatabaseDialect(platform));repository.signatureUpdateContract(agent,99);assertEquals(0,jdbc.queryForObject("SELECT signature_update_contract FROM t_agent WHERE agent_id=?",Integer.class,agent));
        repository.signatureUpdateContract(agent,1);repository.virusContract(agent,2,"delta-base");
        var delivered=guard.prepareDelivery(agent,command(target)).getSignatureUpdate();assertEquals(1,delivered.getUpdateContract());assertEquals(target.get("content_sha256"),delivered.getContentSha256());assertFalse(delivered.getDeltaUrl().isEmpty());
        var deltaQuery=query(delivered.getDeltaUrl());assertTrue(tokens.isAuthorized(deltaQuery.get("token"),"virus-db",deltaQuery.get("packageKey")));assertFalse(tokens.isAuthorized(deltaQuery.get("token"),"virus-db",String.valueOf(target.get("package_key"))));
        var replay=guard.prepareDelivery(agent,command(target)).getSignatureUpdate();assertNotEquals(delivered.getDeltaUrl(),replay.getDeltaUrl());
        jdbc.update("UPDATE t_agent SET virus_db_version='unknown' WHERE agent_id=?",agent);assertTrue(guard.prepareDelivery(agent,command(target)).getSignatureUpdate().getDeltaUrl().isEmpty());
        capture(base,target,baseStatus,status());
        publish("delta-newest",updated,"");assertThrows(IllegalArgumentException.class,()->guard.prepareDelivery(agent,command(target)));assertFalse(tokens.isAuthorized(deltaQuery.get("token"),"virus-db",deltaQuery.get("packageKey")));
    }
    @Test void missingOrChangedBaseUsesVerifiedFullReleaseAndSmallDeltaIsNotPublished() throws Exception {
        var initial=hashes(1000);var base=publish("base",initial,"");
        Files.writeString(files.localPath("signature",String.valueOf(base.get("package_key"))),"corrupt");
        var next=new TreeMap<>(initial);next.remove(next.firstKey());var full=publish("full",next,"");assertEquals("",full.get("delta_key"));assertTrue(String.valueOf(full.get("content_sha256")).matches("[a-f0-9]{64}"));
        var tiny=publish("tiny",hashes(1),"");assertEquals("",tiny.get("delta_key"));
        try(var paths=Files.list(root.resolve("work/tmp"))){assertEquals(0,paths.count());}
    }
    @Test void rollbackRemovesCompleteAndDeltaCandidates() throws Exception {
        var entries=hashes(1000);publish("rollback-base",entries,"");entries.remove(entries.keySet().iterator().next());var target=publish("rollback-target",entries,"");assertFalse(String.valueOf(target.get("delta_key")).isEmpty());
        manager.rollback(transaction);
        assertEquals(0,jdbc.queryForObject("SELECT count(*) FROM t_virus_db WHERE db_version IN ('rollback-base','rollback-target')",Integer.class));
        try(var paths=Files.list(root.resolve("signatures"))){assertEquals(0,paths.count());}
    }
    @Test void retentionProtectsDeltaTokensAndDeletesBothHistoricalArtifacts() throws Exception {
        props.setRetainVersions(2);props.setRetainDays(1);
        var entries=hashes(1000);publish("retained-base",entries,"");
        entries.remove(entries.keySet().iterator().next());var historical=publish("retained-delta",entries,"");
        assertFalse(String.valueOf(historical.get("delta_key")).isEmpty());
        entries.remove(entries.keySet().iterator().next());publish("newer",entries,"");
        entries.remove(entries.keySet().iterator().next());publish("current",entries,"");
        jdbc.update("UPDATE t_virus_db SET imported_at=?",new DatabaseDialect(platform).timestamp(java.time.Instant.now().minusSeconds(10*86400)));
        tokens.issue(agent,"virus-db",String.valueOf(historical.get("delta_key")));
        assertEquals(1,catalog.pruneSignatures());assertTrue(Files.exists(files.localPath("signature",String.valueOf(historical.get("package_key")))));
        jdbc.update("DELETE FROM t_agent_download_token WHERE agent_id=?",agent);
        assertEquals(1,catalog.pruneSignatures());assertFalse(Files.exists(files.localPath("signature",String.valueOf(historical.get("package_key")))));assertFalse(Files.exists(files.localPath("signature",String.valueOf(historical.get("delta_key")))));
        assertEquals(2,jdbc.queryForObject("SELECT count(*) FROM t_virus_db",Integer.class));
    }
    void capture(Map<String,Object> base,Map<String,Object> target,Map<String,Object> fullOnly,Map<String,Object> current) throws Exception {
        String directory=System.getenv("ALINKSEC_SIGNATURE_FIXTURE_DIR");if(directory==null||directory.isBlank())return;Path dest=Path.of(directory);Files.createDirectories(dest);
        for(var entry:Map.of("base.zip",base.get("package_key"),"target.zip",target.get("package_key"),"delta.zip",target.get("delta_key")).entrySet())Files.copy(files.localPath("signature",String.valueOf(entry.getValue())),dest.resolve(entry.getKey()),StandardCopyOption.REPLACE_EXISTING);
        Files.writeString(dest.resolve("release.json"),JsonUtils.write(Map.of("producer","actual-java-publisher","version",target.get("db_version"),"sha256",target.get("sha256"),"delta_sha256",target.get("delta_sha256"),"base_version",target.get("delta_base_version"),"base_content_sha256",target.get("delta_base_content_sha256"),"content_sha256",target.get("content_sha256"),"base_sha256",base.get("sha256"),"checks",List.of("adjacent-canonical-delta","metadata-change-add-remove-and-rule-replacement","content-pins","capability-and-base-delivery-recheck","scoped-delta-and-full-token","fresh-replay-token"))));
        Files.writeString(dest.resolve("status.json"),JsonUtils.write(current));Files.writeString(dest.resolve("full-only.json"),JsonUtils.write(fullOnly));
    }
}
