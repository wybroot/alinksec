package com.alinksec.bootstrap;

import com.alinksec.common.util.JsonUtils;
import com.alinksec.proto.RptHeartbeat;
import com.alinksec.service.virus.YaraService;
import com.zaxxer.hikari.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.jdbc.core.JdbcTemplate;
import java.nio.file.*;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

class YaraIntegrationTest {
    @TempDir Path root;
    HikariDataSource pool;JdbcTemplate jdbc;YaraService service;String a,b;
    @BeforeEach void setup() {
        boolean pg="postgres".equals(System.getProperty("alinksec.integration.database"));
        var cfg=new HikariConfig();cfg.setJdbcUrl(pg?System.getenv("ALINKSEC_INTEGRATION_PG_URL"):"jdbc:sqlite:"+root.resolve("db"));
        if(pg){cfg.setUsername(System.getenv("ALINKSEC_INTEGRATION_PG_USER"));cfg.setPassword(System.getenv("ALINKSEC_INTEGRATION_PG_PASSWORD"));}
        else{cfg.addDataSourceProperty("foreign_keys",true);cfg.addDataSourceProperty("busy_timeout",10000);}
        cfg.setMaximumPoolSize(2);cfg.setMinimumIdle(1);pool=new HikariDataSource(cfg);
        if(!pg)new SqliteDatabaseConfiguration.SqliteMigrationBeanPostProcessor().postProcessAfterInitialization(pool,"dataSource");
        jdbc=new JdbcTemplate(pool);service=new YaraService(jdbc);
        a="yara-a-"+UUID.randomUUID();b="yara-b-"+UUID.randomUUID();
        jdbc.update("INSERT INTO t_agent(agent_id,hostname,ip,os_type,status,virus_execution_contract) VALUES(?,?,?,1,1,2)",a,"Linux YARA 验收","192.0.2.40");
        jdbc.update("INSERT INTO t_agent(agent_id,hostname,ip,os_type,status,virus_execution_contract) VALUES(?,?,?,2,1,2)",b,"Windows YARA 验收","192.0.2.41");
    }
    @AfterEach void close(){if(jdbc!=null)for(String id:List.of(a,b))jdbc.update("DELETE FROM t_agent WHERE agent_id=?",id);if(pool!=null)pool.close();}
    static Map<String,Object> coverage(String state) {
        var d=new LinkedHashMap<String,Object>();d.put("state",state);d.put("version",state.equals("ready")?"YARA 4.5.8/sha256:"+"a".repeat(64):"");d.put("last_issue","");d.put("realtime",true);
        d.put("observed_at",System.currentTimeMillis()/1000);d.put("last_scan_at",0);d.put("scans",3);d.put("failures",0);return d;
    }
    void heartbeat(String id,Map<String,Object> d){service.heartbeat(id,RptHeartbeat.newBuilder().setYaraContract(1).setYaraStatus(JsonUtils.write(d)).build());}
    Map<String,Object> row(String id){return ((List<Map<String,Object>>)service.status(1,100).get("items")).stream().filter(x->id.equals(x.get("agent_id"))).findFirst().orElseThrow();}
    @Test void readinessSeparatesDisabledUnavailableUnsupportedOfflineAndStale() {
        assertEquals("unsupported",row(a).get("state"));assertThrows(IllegalArgumentException.class,()->YaraService.requireReady(jdbc,a));
        heartbeat(a,coverage("ready"));assertEquals("YARA 4.5.8/sha256:"+"a".repeat(64),YaraService.requireReady(jdbc,a));
        var failed=coverage("unavailable");failed.put("last_issue","yara_rules_changed");failed.put("failures",2);heartbeat(b,failed);capture("ready");
        assertThrows(IllegalArgumentException.class,()->YaraService.requireReady(jdbc,b));
        heartbeat(a,coverage("disabled"));assertEquals("disabled",row(a).get("state"));
        heartbeat(a,coverage("ready"));jdbc.update("UPDATE t_yara_status SET observed_at=1 WHERE agent_id=?",a);assertEquals("stale",row(a).get("state"));
        var old=coverage("ready");old.put("observed_at",1);heartbeat(a,old);assertEquals("stale",row(a).get("state"));
        old.put("observed_at",System.currentTimeMillis()/1000+120);heartbeat(a,old);assertEquals("stale",row(a).get("state"));capture("stale");
        service.heartbeat(a,RptHeartbeat.getDefaultInstance());jdbc.update("UPDATE t_agent SET status=2 WHERE agent_id=?",b);assertEquals("unsupported",row(a).get("state"));assertEquals("offline",row(b).get("state"));capture("unsupported");
    }
    @Test void malformedMetadataCannotForgeReadinessOrLeakEndpointCredentials() {
        heartbeat(a,coverage("ready"));var original=row(a).get("coverage");
        for(var change:List.of(Map.of("state","all-clean"),Map.of("version","fake"),Map.of("version","YARA bad\nversion"),Map.of("version","YARA "+"x".repeat(256)),Map.of("last_issue","arbitrary"),Map.of("scans",-1),Map.of("failures",4),Map.of("realtime","true"),Map.of("observed_at",Long.MAX_VALUE))) {
            var d=coverage("ready");d.putAll(change);assertThrows(IllegalArgumentException.class,()->heartbeat(a,d));assertEquals(original,row(a).get("coverage"));
        }
        var extra=coverage("ready");extra.put("address","secret endpoint");extra.put("server_cert_sha256","secret credential");heartbeat(a,extra);assertFalse(JsonUtils.write(row(a)).contains("secret"));
        assertThrows(IllegalArgumentException.class,()->service.heartbeat(a,RptHeartbeat.newBuilder().setYaraContract(1).setYaraStatus("x".repeat(2049)).build()));
        assertThrows(IllegalArgumentException.class,()->service.status(0,20));assertThrows(IllegalArgumentException.class,()->service.status(1,101));
        service.heartbeat(a,RptHeartbeat.newBuilder().setYaraContract(99).setYaraStatus("ignored").build());assertEquals("unsupported",row(a).get("state"));
        jdbc.update("DELETE FROM t_agent WHERE agent_id=?",a);assertEquals(0,jdbc.queryForObject("SELECT count(*) FROM t_yara_status WHERE agent_id=?",Integer.class,a));
    }
    void capture(String name) {
        String directory=System.getenv("ALINKSEC_YARA_BROWSER_FIXTURES");if(directory==null||directory.isBlank())return;
        try{var dest=Path.of(directory);Files.createDirectories(dest);Files.writeString(dest.resolve(name+".json"),JsonUtils.write(service.status(1,100)));if(name.equals("ready"))Files.writeString(dest.resolve("hosts.json"),JsonUtils.write(new com.alinksec.service.query.HostQueryService(jdbc).list(null,null,null,1,100)));}catch(Exception ex){throw new IllegalStateException(ex);}
    }
}
