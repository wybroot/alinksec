package com.alinksec.bootstrap;

import com.alinksec.common.util.JsonUtils;
import com.alinksec.proto.RptHeartbeat;
import com.alinksec.service.protect.FileWatchService;
import com.zaxxer.hikari.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.jdbc.core.JdbcTemplate;
import java.nio.file.*;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

class FileWatchIntegrationTest {
    @TempDir Path root;
    HikariDataSource pool;JdbcTemplate jdbc;FileWatchService service;String a,b;
    @BeforeEach void setup() {
        boolean pg="postgres".equals(System.getProperty("alinksec.integration.database"));
        var cfg=new HikariConfig();cfg.setJdbcUrl(pg?System.getenv("ALINKSEC_INTEGRATION_PG_URL"):"jdbc:sqlite:"+root.resolve("db"));
        if(pg){cfg.setUsername(System.getenv("ALINKSEC_INTEGRATION_PG_USER"));cfg.setPassword(System.getenv("ALINKSEC_INTEGRATION_PG_PASSWORD"));}
        else{cfg.addDataSourceProperty("foreign_keys",true);cfg.addDataSourceProperty("busy_timeout",10000);}
        cfg.setMaximumPoolSize(2);cfg.setMinimumIdle(1);pool=new HikariDataSource(cfg);
        if(!pg)new SqliteDatabaseConfiguration.SqliteMigrationBeanPostProcessor().postProcessAfterInitialization(pool,"dataSource");
        jdbc=new JdbcTemplate(pool);service=new FileWatchService(jdbc);
        a="file-watch-a-"+UUID.randomUUID();b="file-watch-b-"+UUID.randomUUID();
        jdbc.update("INSERT INTO t_agent(agent_id,hostname,ip,os_type,status) VALUES(?,?,?,1,1)",a,"Linux 文件监控验收","192.0.2.30");
        jdbc.update("INSERT INTO t_agent(agent_id,hostname,ip,os_type,status) VALUES(?,?,?,2,1)",b,"Windows 文件监控验收","192.0.2.31");
    }
    @AfterEach void close(){if(jdbc!=null)for(String id:List.of(a,b))jdbc.update("DELETE FROM t_agent WHERE agent_id=?",id);if(pool!=null)pool.close();}
    static Map<String,Object> coverage(String state,String issue) {
        var d=new LinkedHashMap<String,Object>();d.put("state",state);d.put("issue",issue);d.put("recovery_issue","");d.put("backend","inotify");d.put("recovering",false);
        for(String k:List.of("last_event_at","last_sync_at","last_sweep_at"))d.put(k,System.currentTimeMillis());
        for(String k:List.of("roots","watches","pending","dropped","gaps"))d.put(k,1);
        return d;
    }
    void heartbeat(String id,Map<String,Object> d){service.heartbeat(id,RptHeartbeat.newBuilder().setFileWatchContract(1).setFileWatchStatus(JsonUtils.write(d)).build());}
    Map<String,Object> row(String id){return ((List<Map<String,Object>>)service.status(1,100).get("items")).stream().filter(x->id.equals(x.get("agent_id"))).findFirst().orElseThrow();}
    @Test void coverageSeparatesNativeRecoveryGapsAndOldOfflineAgents() {
        assertEquals("unsupported",row(a).get("state"));heartbeat(a,coverage("watching",""));assertEquals("watching",row(a).get("state"));
        var windows=coverage("degraded","kernel_overflow_or_error");windows.put("backend","ReadDirectoryChangesW");windows.put("dropped",42);windows.put("gaps",3);heartbeat(b,windows);assertEquals("degraded",row(b).get("state"));capture("coverage");
        var recovering=coverage("watching","");recovering.put("recovering",true);heartbeat(a,recovering);assertEquals("recovering",row(a).get("state"));capture("recovering");
        var incomplete=coverage("watching","");incomplete.put("recovery_issue","directory_unreadable");heartbeat(a,incomplete);assertEquals("degraded",row(a).get("state"));
        jdbc.update("UPDATE t_file_watch_status SET observed_at=1 WHERE agent_id=?",a);assertEquals("stale",row(a).get("state"));
        var stalled=coverage("watching","");stalled.put("last_sync_at",1);heartbeat(a,stalled);assertEquals("stalled",row(a).get("state"));capture("stalled");
        heartbeat(a,coverage("disabled",""));assertEquals("disabled",row(a).get("state"));
        service.heartbeat(a,RptHeartbeat.getDefaultInstance());jdbc.update("UPDATE t_agent SET status=2 WHERE agent_id=?",b);
        assertEquals("unsupported",row(a).get("state"));assertEquals("offline",row(b).get("state"));capture("unsupported");
    }
    @Test void malformedOversizedAndUnknownContractsCannotForgeCoverage() {
        heartbeat(a,coverage("watching",""));var original=row(a).get("coverage");
        for(var change:List.of(Map.of("state","all-clean"),Map.of("issue","arbitrary"),Map.of("watches",1025),Map.of("pending",2049),Map.of("gaps",-1),Map.of("last_sync_at","123"),Map.of("recovering","true"),Map.of("backend","fake"),Map.of("recovery_issue","unknown"))) {
            var d=coverage("watching","");d.putAll(change);assertThrows(IllegalArgumentException.class,()->heartbeat(a,d));assertEquals(original,row(a).get("coverage"));
        }
        assertThrows(IllegalArgumentException.class,()->service.heartbeat(a,RptHeartbeat.newBuilder().setFileWatchContract(1).setFileWatchStatus("x".repeat(4097)).build()));
        assertThrows(IllegalArgumentException.class,()->service.status(0,20));assertThrows(IllegalArgumentException.class,()->service.status(1,101));
        service.heartbeat(a,RptHeartbeat.newBuilder().setFileWatchContract(99).setFileWatchStatus("ignored").build());assertEquals("unsupported",row(a).get("state"));
        assertEquals("unsupported",row(b).get("state"));
    }
    @Test void futureTimestampsDoNotAdvertiseCurrentCoverageAndDeletionCascades() {
        var d=coverage("watching","");d.put("last_sync_at",System.currentTimeMillis()+120000);heartbeat(a,d);assertEquals("stalled",row(a).get("state"));
        heartbeat(a,coverage("watching",""));jdbc.update("UPDATE t_file_watch_status SET observed_at=? WHERE agent_id=?",System.currentTimeMillis()+120000,a);assertEquals("stale",row(a).get("state"));
        jdbc.update("DELETE FROM t_agent WHERE agent_id=?",a);assertEquals(0,jdbc.queryForObject("SELECT count(*) FROM t_file_watch_status WHERE agent_id=?",Integer.class,a));
    }
    void capture(String name) {
        String directory=System.getenv("ALINKSEC_FILE_WATCH_BROWSER_FIXTURES");if(directory==null||directory.isBlank())return;
        try{var dest=Path.of(directory);Files.createDirectories(dest);Files.writeString(dest.resolve(name+".json"),JsonUtils.write(service.status(1,100)));}catch(Exception ex){throw new IllegalStateException(ex);}
    }
}
