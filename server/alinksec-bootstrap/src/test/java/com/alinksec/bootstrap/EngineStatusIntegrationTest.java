package com.alinksec.bootstrap;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.jdbc.core.JdbcTemplate;
import java.nio.file.Path;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

/** Database fixtures verify runtime classification; native probes are exercised by CI scenarios. */
class EngineStatusIntegrationTest {
    @TempDir Path root;
    HikariDataSource pool;
    JdbcTemplate jdbc;
    String agent;
    @BeforeEach void setup(){
        boolean pg="postgres".equals(System.getProperty("alinksec.integration.database"));
        var config=new HikariConfig();
        config.setJdbcUrl(pg?System.getenv("ALINKSEC_INTEGRATION_PG_URL"):"jdbc:sqlite:"+root.resolve("engine-status.db"));
        if(pg){config.setUsername(System.getenv("ALINKSEC_INTEGRATION_PG_USER"));config.setPassword(System.getenv("ALINKSEC_INTEGRATION_PG_PASSWORD"));}
        else{config.addDataSourceProperty("transaction_mode","IMMEDIATE");config.addDataSourceProperty("busy_timeout",10000);config.addDataSourceProperty("foreign_keys",true);}
        config.setMaximumPoolSize(1);config.setMinimumIdle(1);pool=new HikariDataSource(config);
        if(!pg)new SqliteDatabaseConfiguration.SqliteMigrationBeanPostProcessor().postProcessAfterInitialization(pool,"dataSource");
        jdbc=new JdbcTemplate(pool);agent="engine-runtime-"+UUID.randomUUID();
        jdbc.update("INSERT INTO t_agent(agent_id,hostname,ip,os_type,status) VALUES(?,?,?,2,1)",agent,agent,"192.0.2.41");
    }
    @AfterEach void close(){
        try{if(jdbc!=null)jdbc.update("DELETE FROM t_agent WHERE agent_id=?",agent);}
        finally{if(pool!=null)pool.close();}
    }
    @Test void engineRuntimeReadinessIsIndependentOfTheUnappliedFleetFlag(){
        var service=new com.alinksec.service.protect.EngineStatusService(jdbc);
        var keys=List.of("file_watch","windows_login","clamav","yara","scap");
        jdbc.update("UPDATE t_agent SET os_type=2,protect_enabled=TRUE WHERE agent_id=?",agent);
        var before=service.engines();long now=System.currentTimeMillis();
        try {
            for(String key:keys){
                var detail=new HashMap<String,Object>();
                detail.put("state",key.equals("file_watch")?"watching":key.equals("windows_login")?"polling":"ready");
                detail.put("observed_at",now/1000);detail.put("last_sync_at",now);detail.put("last_poll_at",now);
                detail.put("roots",1);detail.put("watches",1);detail.put("audit_success",true);detail.put("audit_failure",true);
                jdbc.update("INSERT INTO t_"+key+"_status(agent_id,contract,coverage,observed_at) VALUES(?,1,?,?)",agent,com.alinksec.common.util.JsonUtils.write(detail),now);
            }
            var ready=service.engines();
            for(String key:keys){
                long baseline=((Number)before.stream().filter(row->key.equals(row.get("key"))).findFirst().orElseThrow().get("ready")).longValue();
                assertEquals(baseline+1,((Number)ready.stream().filter(row->key.equals(row.get("key"))).findFirst().orElseThrow().get("ready")).longValue(),key);
            }
            jdbc.update("UPDATE t_agent SET protect_enabled=FALSE WHERE agent_id=?",agent);
            assertEquals(ready,service.engines(),"Fleet flag is not evidence that these independently reported engines stopped");
            jdbc.update("UPDATE t_agent SET protect_enabled=TRUE WHERE agent_id=?",agent);
            for(String key:keys)jdbc.update("UPDATE t_"+key+"_status SET coverage=? WHERE agent_id=?",com.alinksec.common.util.JsonUtils.write(Map.of("state","disabled","observed_at",now/1000,"last_sync_at",now,"last_poll_at",now)),agent);
            var disabled=service.engines();
            for(String key:keys){
                long baseline=((Number)before.stream().filter(row->key.equals(row.get("key"))).findFirst().orElseThrow().get("ready")).longValue();
                assertEquals(baseline,((Number)disabled.stream().filter(row->key.equals(row.get("key"))).findFirst().orElseThrow().get("ready")).longValue(),key);
            }
            jdbc.update("UPDATE t_agent SET protect_enabled=FALSE WHERE agent_id=?",agent);
            assertEquals(disabled,service.engines(),"Own disabled reports remain disabled independently of the fleet flag");
        } finally {
            for(String key:keys)jdbc.update("DELETE FROM t_"+key+"_status WHERE agent_id=?",agent);
        }
    }
}
