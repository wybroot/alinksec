package com.alinksec.bootstrap;

import com.alinksec.common.util.JsonUtils;
import com.alinksec.proto.*;
import com.alinksec.service.alert.SecurityEventService;
import com.alinksec.service.config.*;
import com.alinksec.service.notify.NotifyService;
import com.alinksec.service.command.CommandService;
import com.alinksec.service.report.ReportDispatcher;
import com.alinksec.service.query.AlertQueryService;
import com.zaxxer.hikari.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import java.nio.file.*;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class WindowsRansomIntegrationTest {
    @TempDir Path root;
    HikariDataSource pool;JdbcTemplate jdbc;ReportDispatcher dispatcher;AlertQueryService query;
    NotifyService notify;String a,b;
    @BeforeEach void setup() throws Exception {
        boolean pg="postgres".equals(System.getProperty("alinksec.integration.database"));
        var cfg=new HikariConfig();cfg.setJdbcUrl(pg?System.getenv("ALINKSEC_INTEGRATION_PG_URL"):"jdbc:sqlite:"+root.resolve("db"));
        if(pg){cfg.setUsername(System.getenv("ALINKSEC_INTEGRATION_PG_USER"));cfg.setPassword(System.getenv("ALINKSEC_INTEGRATION_PG_PASSWORD"));}
        else{cfg.addDataSourceProperty("transaction_mode","IMMEDIATE");cfg.addDataSourceProperty("busy_timeout",10000);cfg.addDataSourceProperty("foreign_keys",true);}
        cfg.setMaximumPoolSize(2);cfg.setMinimumIdle(1);pool=new HikariDataSource(cfg);
        if(!pg)new SqliteDatabaseConfiguration.SqliteMigrationBeanPostProcessor().postProcessAfterInitialization(pool,"dataSource");
        jdbc=new JdbcTemplate(pool);
        a="win-ransom-a-"+UUID.randomUUID();b="win-ransom-b-"+UUID.randomUUID();
        for(String id:List.of(a,b))jdbc.update("INSERT INTO t_agent(agent_id,hostname,ip,os_type,status) VALUES(?,?,?,2,1)",id,"Windows 勒索归因验收","192.0.2.20");
        var props=new AlinkSecProperties();props.getDatabase().setType(pg?"postgres":"sqlite");notify=mock(NotifyService.class);
        var alerts=new SecurityEventService(jdbc,notify,new DatabaseDialect(props));
        query=new AlertQueryService(jdbc);
        dispatcher=new ReportDispatcher(mock(com.alinksec.service.heartbeat.HeartbeatService.class),mock(com.alinksec.service.asset.AssetService.class),alerts,mock(CommandService.class),mock(com.alinksec.service.baseline.BaselineResultService.class),mock(com.alinksec.service.scan.ScanResultService.class),mock(com.alinksec.service.virus.VirusResultService.class),mock(com.alinksec.service.fix.FixResultService.class),mock(com.alinksec.service.metrics.MetricsForwarder.class),mock(com.alinksec.service.log.LogBatchService.class),jdbc,new DatabaseDialect(props),new DataSourceTransactionManager(pool),mock(com.alinksec.service.fix.WindowsUpdateService.class));
    }
    @AfterEach void close(){if(jdbc!=null){for(String id:List.of(a,b)){jdbc.update("DELETE FROM t_alert WHERE agent_id=?",id);jdbc.update("DELETE FROM t_agent WHERE agent_id=?",id);}}if(pool!=null)pool.close();}
    Report event(String state,String birth,String path) {
        var detail=new LinkedHashMap<String,Object>();
        var attribution=new LinkedHashMap<String,Object>();
        attribution.put("source","windows_kernel_file_etw");attribution.put("status",state);
        var identity=Map.of("pid",1234,"created_filetime",birth,"image","C:\\fixture\\writer.exe");
        if(state.equals("attributed"))attribution.put("process",identity);
        else attribution.put("reason",state.equals("ambiguous")?"multiple_writers":"no_observed_write");
        attribution.put("writes",state.equals("unattributed")?List.of():List.of(Map.of("path",path,"at","2026-10-18T12:00:00Z","operation","write","process",identity)));
        detail.put("attribution",attribution);detail.put("files",List.of(path));
        var event=RptSecurityEvent.newBuilder().setRuleId("PR-0010").setRuleName("勒索诱饵防护").setType("decoy_tamper")
                .setSeverity(Severity.SEV_CRITICAL).setActionTaken(state.equals("attributed")?"killed":"alert_only")
                .setDetail(JsonUtils.write(detail)).setEventTs(System.currentTimeMillis());
        return Report.newBuilder().setAgentId(b).setReportId(UUID.randomUUID().toString()).setSecurityEvent(event).build();
    }
    List<Map<String,Object>> rows(String agent) {return (List<Map<String,Object>>)query.list(null,null,agent,null,1,100).get("list");}
    @Test void processReuseUnknownAndDifferentFilesRetainSeparateEvidence() {
        for(var r:List.of(event("attributed","134000000000000001","C:\\data\\one"),event("attributed","134000000000000002","C:\\data\\one"),
                event("unattributed","","C:\\data\\one"),event("ambiguous","","C:\\data\\one"),event("attributed","134000000000000001","C:\\data\\two")))dispatcher.dispatch(a,r);
        assertEquals(5,rows(a).size());assertTrue(rows(b).isEmpty());
        dispatcher.dispatch(a,event("attributed","134000000000000001","C:\\data\\one"));
        assertEquals(5,rows(a).size());assertEquals(6,rows(a).stream().mapToInt(r->((Number)r.get("count")).intValue()).sum());
        var identities=rows(a).stream().map(r->JsonUtils.read((String)r.get("detail")).path("attribution").path("process").path("created_filetime").asText()).toList();
        assertTrue(identities.contains("134000000000000001"));assertTrue(identities.contains("134000000000000002"));
        String directory=System.getenv("ALINKSEC_WINDOWS_RANSOM_BROWSER_FIXTURES");
        if(directory!=null&&!directory.isBlank())try{var dst=Path.of(directory);Files.createDirectories(dst);Files.writeString(dst.resolve("alerts.json"),JsonUtils.write(Map.of("list",rows(a),"total",5)));}catch(Exception e){throw new IllegalStateException(e);}
    }
    @Test void evidenceAndTransportReceiptRollbackTogether() {
        var report=event("attributed","134000000000000001","C:\\data\\rollback");
        doThrow(new IllegalStateException("controlled persistence failure")).when(notify).onAlert(anyString(),anyString(),anyString(),anyInt(),anyString(),anyString());
        assertThrows(IllegalStateException.class,()->dispatcher.dispatch(a,report));assertTrue(rows(a).isEmpty());
        reset(notify);dispatcher.dispatch(a,report);dispatcher.dispatch(a,report);
        assertEquals(1,rows(a).size());assertEquals(1,((Number)rows(a).get(0).get("count")).intValue());
    }
}
