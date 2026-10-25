package com.alinksec.bootstrap;

import com.alinksec.common.util.JsonUtils;
import com.alinksec.proto.*;
import com.alinksec.service.alert.SecurityEventService;
import com.alinksec.service.config.AlinkSecProperties;
import com.alinksec.service.config.DatabaseDialect;
import com.alinksec.service.notify.NotifyService;
import com.alinksec.service.protect.WindowsLoginService;
import com.alinksec.service.protect.PolicyStoreService;
import com.alinksec.service.protect.ProtectRuleService;
import com.alinksec.service.command.CommandService;
import com.alinksec.service.report.ReportDispatcher;
import com.zaxxer.hikari.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import java.nio.file.*;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class WindowsLoginIntegrationTest {
    @TempDir Path root;
    HikariDataSource pool;JdbcTemplate jdbc;WindowsLoginService service;ReportDispatcher dispatcher;
    NotifyService notify;String a,b;PolicyStoreService policies;ProtectRuleService rules;
    @BeforeEach void setup() throws Exception {
        boolean pg="postgres".equals(System.getProperty("alinksec.integration.database"));
        var cfg=new HikariConfig();cfg.setJdbcUrl(pg?System.getenv("ALINKSEC_INTEGRATION_PG_URL"):"jdbc:sqlite:"+root.resolve("db"));
        if(pg){cfg.setUsername(System.getenv("ALINKSEC_INTEGRATION_PG_USER"));cfg.setPassword(System.getenv("ALINKSEC_INTEGRATION_PG_PASSWORD"));}
        else{cfg.addDataSourceProperty("transaction_mode","IMMEDIATE");cfg.addDataSourceProperty("busy_timeout",10000);cfg.addDataSourceProperty("foreign_keys",true);}
        cfg.setMaximumPoolSize(2);cfg.setMinimumIdle(1);pool=new HikariDataSource(cfg);
        if(!pg)new SqliteDatabaseConfiguration.SqliteMigrationBeanPostProcessor().postProcessAfterInitialization(pool,"dataSource");
        jdbc=new JdbcTemplate(pool);service=new WindowsLoginService(jdbc);
        a="win-login-a-"+UUID.randomUUID();b="win-login-b-"+UUID.randomUUID();
        for(String id:List.of(a,b))jdbc.update("INSERT INTO t_agent(agent_id,hostname,ip,os_type,status) VALUES(?,?,?,2,1)",id,"Windows 登录验收","192.0.2.20");
        var props=new AlinkSecProperties();props.getDatabase().setType(pg?"postgres":"sqlite");notify=mock(NotifyService.class);
        var alerts=new SecurityEventService(jdbc,notify,new DatabaseDialect(props));
        dispatcher=new ReportDispatcher(mock(com.alinksec.service.heartbeat.HeartbeatService.class),mock(com.alinksec.service.asset.AssetService.class),alerts,mock(CommandService.class),mock(com.alinksec.service.baseline.BaselineResultService.class),mock(com.alinksec.service.scan.ScanResultService.class),mock(com.alinksec.service.virus.VirusResultService.class),mock(com.alinksec.service.fix.FixResultService.class),mock(com.alinksec.service.metrics.MetricsForwarder.class),mock(com.alinksec.service.log.LogBatchService.class),jdbc,new DatabaseDialect(props),new DataSourceTransactionManager(pool),mock(com.alinksec.service.fix.WindowsUpdateService.class),mock(com.alinksec.service.evidence.EvidenceService.class));
        policies=new PolicyStoreService(jdbc,mock(CommandService.class));policies.init();rules=new ProtectRuleService(jdbc,mock(CommandService.class),policies);
    }
    @AfterEach void close(){if(jdbc!=null){for(String id:List.of(a,b)){jdbc.update("DELETE FROM t_alert WHERE agent_id=?",id);jdbc.update("DELETE FROM t_agent WHERE agent_id=?",id);}}if(pool!=null)pool.close();}
    static Map<String,Object> coverage(String state,String issue){var d=new LinkedHashMap<String,Object>();d.put("state",state);d.put("issue",issue);for(String k:List.of("last_poll_at","last_event_at"))d.put(k,System.currentTimeMillis());for(String k:List.of("cursor","active_blocks","block_failures","coverage_gaps","discarded_events","rules","retained_events"))d.put(k,1);d.put("audit_success",true);d.put("audit_failure",true);return d;}
    void heartbeat(String agent,String state,String issue){service.heartbeat(agent,RptHeartbeat.newBuilder().setWindowsLoginContract(1).setWindowsLoginStatus(JsonUtils.write(coverage(state,issue))).build());}
    Report event(String agent,String identity){var d=Map.of("id",identity,"generation","b".repeat(32),"record_id",42,"logon_type",10,"source_ip","198.51.100.8","account","LAB\\user","event_id",4625,"trigger","windows_bruteforce","windows_ports",List.of(3389));return Report.newBuilder().setAgentId(agent).setReportId(identity+"-windows-login").setSecurityEvent(RptSecurityEvent.newBuilder().setRuleId("PR-0004").setRuleName("Windows 登录防护").setType("login_crack").setSeverity(Severity.SEV_HIGH).setActionTaken("blocked_ip").setDetail(JsonUtils.write(d)).setEventTs(System.currentTimeMillis())).build();}
    Map<String,Object> row(String id){return ((List<Map<String,Object>>)service.status(1,100).get("items")).stream().filter(x->id.equals(x.get("agent_id"))).findFirst().orElseThrow();}
    @Test void receiptsAndAlertsCommitTogetherAndDeduplicateBeyondTransportWindow(){
        var report=event(a,"a".repeat(64));
        doThrow(new IllegalStateException("synthetic post-insert failure")).when(notify).onAlert(anyString());
        assertThrows(IllegalStateException.class,()->dispatcher.dispatch(a,report));
        assertEquals(0,jdbc.queryForObject("SELECT count(*) FROM t_windows_login_receipt WHERE agent_id=?",Integer.class,a));assertEquals(0,jdbc.queryForObject("SELECT count(*) FROM t_alert WHERE agent_id=?",Integer.class,a));
        reset(notify);dispatcher.dispatch(a,report);dispatcher.dispatch(a,report);
        jdbc.update("DELETE FROM t_report_dedup");dispatcher.dispatch(a,report);
        assertEquals(1,jdbc.queryForObject("SELECT count FROM t_alert WHERE agent_id=? AND rule_id='PR-0004'",Integer.class,a));
        dispatcher.dispatch(b,report.toBuilder().setAgentId(b).build());assertEquals(1,jdbc.queryForObject("SELECT count(*) FROM t_windows_login_receipt WHERE agent_id=?",Integer.class,b));
    }
    @Test void invalidEventScopeCannotCommitOrBeAcknowledged(){
        var r=event(a,"c".repeat(64));var bad=r.toBuilder().setSecurityEvent(r.getSecurityEvent().toBuilder().setType("login_anomaly")).build();
        assertThrows(IllegalArgumentException.class,()->dispatcher.dispatch(a,bad));assertEquals(0,jdbc.queryForObject("SELECT count(*) FROM t_windows_login_receipt WHERE agent_id=?",Integer.class,a));
        dispatcher.dispatch(a,r);assertEquals(1,jdbc.queryForObject("SELECT count(*) FROM t_alert WHERE agent_id=?",Integer.class,a));
    }
    @Test void targetCoverageSeparatesOldOfflineStaleStalledAndDisabled(){
        assertEquals("unsupported",row(a).get("state"));heartbeat(a,"polling","");assertEquals("polling",row(a).get("state"));
        heartbeat(b,"failed","security_read_failed");assertEquals("failed",row(b).get("state"));capture("coverage");
        jdbc.update("UPDATE t_windows_login_status SET observed_at=1 WHERE agent_id=?",a);assertEquals("stale",row(a).get("state"));
        var d=coverage("polling","");d.put("last_poll_at",1);service.heartbeat(a,RptHeartbeat.newBuilder().setWindowsLoginContract(1).setWindowsLoginStatus(JsonUtils.write(d)).build());assertEquals("stalled",row(a).get("state"));
        jdbc.update("UPDATE t_agent SET status=2 WHERE agent_id=?",a);assertEquals("offline",row(a).get("state"));
        service.heartbeat(b,RptHeartbeat.getDefaultInstance());assertEquals("unsupported",row(b).get("state"));capture("unsupported");
        jdbc.update("UPDATE t_agent SET status=1 WHERE agent_id=?",a);heartbeat(a,"disabled","");assertEquals("disabled",row(a).get("state"));
        assertThrows(IllegalArgumentException.class,()->service.status(0,20));assertThrows(IllegalArgumentException.class,()->service.status(1,101));
    }
    @Test void windowsRuleIsSeparateExplicitOptInAndValidated(){
        var rule=rules.listRules().stream().filter(x->x.get("rule_id").equals("PR-0004")).findFirst().orElseThrow();assertEquals(false,rule.get("enabled"));
        var m=(Map<String,Object>)rule.get("match");assertEquals(List.of("windows"),m.get("platforms"));assertFalse(m.containsKey("ssh_ports"));
        for(var invalid:List.of(Map.of("windows_contract",2),Map.of("windows_contract",1,"platforms",List.of("linux")),Map.of("windows_contract",1,"platforms",List.of("windows"),"windows_ports",List.of(0)),Map.of("windows_contract",1,"platforms",List.of("windows"),"windows_logon_types",List.of(2)),Map.of("windows_contract",1,"platforms",List.of("windows"),"ssh_ports",List.of(22)))) assertThrows(IllegalArgumentException.class,()->rules.updateRule("PR-0004",Map.of("match",invalid)));
        assertEquals(false,rules.listRules().stream().filter(x->x.get("rule_id").equals("PR-0004")).findFirst().orElseThrow().get("enabled"));capture("rules");
    }
    void capture(String name){String directory=System.getenv("ALINKSEC_WINDOWS_LOGIN_BROWSER_FIXTURES");if(directory==null||directory.isBlank())return;try{var dest=Path.of(directory);Files.createDirectories(dest);Files.writeString(dest.resolve(name+".json"),JsonUtils.write(Map.of("status",service.status(1,100),"rules",rules.listRules())));}catch(Exception ex){throw new IllegalStateException(ex);}}
}
