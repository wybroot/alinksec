package com.alinksec.bootstrap;

import com.alinksec.common.util.JsonUtils;
import com.alinksec.proto.*;
import com.alinksec.service.command.CommandService;
import com.alinksec.service.config.*;
import com.alinksec.service.scan.*;
import com.alinksec.service.query.VulnQueryService;
import com.zaxxer.hikari.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class WeakPasswordIntegrationTest {
    @TempDir Path root;
    HikariDataSource pool;JdbcTemplate jdbc;TransactionTemplate tx;
    ScanTaskService tasks;ScanResultService results;VulnQueryService query;
    String a,b;List<Long> created=new ArrayList<>();Map<String,Command> commands=new ConcurrentHashMap<>();
    @BeforeEach void setup() throws Exception {
        boolean pg="postgres".equals(System.getProperty("alinksec.integration.database"));
        var cfg=new HikariConfig();cfg.setJdbcUrl(pg?System.getenv("ALINKSEC_INTEGRATION_PG_URL"):"jdbc:sqlite:"+root.resolve("db"));
        if(pg){cfg.setUsername(System.getenv("ALINKSEC_INTEGRATION_PG_USER"));cfg.setPassword(System.getenv("ALINKSEC_INTEGRATION_PG_PASSWORD"));}
        else{cfg.addDataSourceProperty("transaction_mode","IMMEDIATE");cfg.addDataSourceProperty("busy_timeout",10000);cfg.addDataSourceProperty("foreign_keys",true);}
        cfg.setMaximumPoolSize(2);cfg.setMinimumIdle(1);pool=new HikariDataSource(cfg);
        if(!pg)new SqliteDatabaseConfiguration.SqliteMigrationBeanPostProcessor().postProcessAfterInitialization(pool,"dataSource");
        jdbc=new JdbcTemplate(pool);tx=new TransactionTemplate(new DataSourceTransactionManager(pool));
        a="weak-a-"+UUID.randomUUID();b="weak-b-"+UUID.randomUUID();
        for(String agent:List.of(a,b))jdbc.update("INSERT INTO t_agent(agent_id,hostname,ip,os_type,status,weak_password_contract) VALUES(?,?,?,1,1,1)",agent,"口令检测主机","192.0.2.20");
        var props=new AlinkSecProperties();props.getDatabase().setType(pg?"postgres":"sqlite");
        var service=mock(CommandService.class);
        when(service.dispatchAfterCommit(anyString(),any(Command.Builder.class),any())).thenAnswer(inv->{String id=UUID.randomUUID().toString();Command cmd=((Command.Builder)inv.getArgument(1)).setCmdId(id).build();commands.put(inv.getArgument(0),cmd);jdbc.update("INSERT INTO t_command(cmd_id,agent_id,type,payload) VALUES(?,?,'vuln_scan',?)",id,inv.getArgument(0),JsonUtils.write(Map.of("command_b64",Base64.getEncoder().encodeToString(cmd.toByteArray()))));return id;});
        tasks=new ScanTaskService(jdbc,service,mock(VulnMatchService.class),new DatabaseDialect(props));results=new ScanResultService(jdbc);query=new VulnQueryService(jdbc);
    }
    @AfterEach void close(){if(jdbc!=null){for(long id:created){jdbc.update("DELETE FROM t_weakpwd_finding WHERE task_id=?",id);jdbc.update("DELETE FROM t_port_finding WHERE task_id=?",id);jdbc.update("DELETE FROM t_scan_task WHERE id=?",id);}for(String agent:List.of(a,b)){jdbc.update("DELETE FROM t_command WHERE agent_id=?",agent);jdbc.update("DELETE FROM t_agent WHERE agent_id=?",agent);}}if(pool!=null)pool.close();}
    long task(List<String> agents){long id=tx.execute(s->tasks.createTask("离线口令检测",agents,true,false,false,null));created.add(id);return id;}
    RptScanResult report(long id,String agent,boolean hit){
        var r=RptScanResult.newBuilder().setTaskId(Long.toString(id)).setCommandId(commands.get(agent).getCmdId()).setExecutionContract(1).setPortStatus("not_requested")
            .setWeakPasswordCoverage(WeakPasswordCoverage.newBuilder().setStatus("complete").setDictionaryVersion(ScanResultService.DICTIONARY_VERSION).setDictionarySha256(ScanResultService.DICTIONARY_SHA256).setAccountsSeen(1).setAccountsChecked(1).setCandidatesTested(hit?2:100));
        if(hit)r.addWeakPasswords(WeakPwdFinding.newBuilder().setAccount("local-fixture").setType("system_weak").setPassword("PUBLIC-SYNTHETIC-SECRET"));return r.build();
    }
    void accept(String agent,RptScanResult r){tx.executeWithoutResult(s->results.onResult(agent,r));}
    int number(String column,long id){return jdbc.queryForObject("SELECT "+column+" FROM t_scan_task WHERE id=?",Integer.class,id);}
    @Test void firstResultAndZeroFindingResultAreImmutableAndRedacted(){
        long id=task(List.of(a,b));accept(a,report(id,a,true));accept(a,report(id,a,false));assertEquals(50,number("progress",id));
        assertEquals(1,jdbc.queryForObject("SELECT count(*) FROM t_weakpwd_finding WHERE task_id=?",Integer.class,id));
        String evidence=jdbc.queryForObject("SELECT evidence FROM t_scan_task_agent WHERE task_id=? AND agent_id=?",String.class,id,a);
        assertFalse(evidence.contains("PUBLIC-SYNTHETIC-SECRET"));assertFalse(JsonUtils.write(query.weakpwdFindings(1,100)).contains("PUBLIC-SYNTHETIC-SECRET"));
        accept(b,report(id,b,false));accept(b,report(id,b,true));assertEquals(2,number("status",id));assertEquals(100,number("progress",id));
        assertEquals(1,jdbc.queryForObject("SELECT count(*) FROM t_weakpwd_finding WHERE task_id=?",Integer.class,id));
        capture("complete");
    }
    @Test void foreignHostAndWrongCommandCannotSubmitEvidence(){
        long id=task(List.of(a));accept(b,report(id,a,true));accept(a,report(id,a,true).toBuilder().setCommandId(UUID.randomUUID().toString()).build());
        assertEquals(0,number("progress",id));assertEquals(0,jdbc.queryForObject("SELECT count(*) FROM t_weakpwd_finding WHERE task_id=?",Integer.class,id));
    }
    @Test void unsupportedMixedHostIsExplicitAndTaskCannotPass(){
        jdbc.update("UPDATE t_agent SET os_type=2,weak_password_contract=0 WHERE agent_id=?",b);long id=task(List.of(a,b));
        assertFalse(commands.containsKey(b));assertEquals("unsupported",jdbc.queryForObject("SELECT weak_status FROM t_scan_task_agent WHERE task_id=? AND agent_id=?",String.class,id,b));
        accept(a,report(id,a,false));assertEquals(3,number("status",id));assertEquals(100,number("progress",id));capture("unsupported");
    }
    @Test void invalidCoverageRollsBackAndPartialCoverageDoesNotPass(){
        long id=task(List.of(a));var r=report(id,a,false);var c=r.getWeakPasswordCoverage().toBuilder().setAccountsFailed(1).setAccountsChecked(0).addIssues("scan_budget_exhausted");
        assertThrows(IllegalArgumentException.class,()->accept(a,r.toBuilder().setWeakPasswordCoverage(c).build()));assertEquals(0,number("progress",id));
        accept(a,r.toBuilder().setWeakPasswordCoverage(c.setStatus("partial")).build());assertEquals(3,number("status",id));capture("partial");
    }
    @Test void lateEvidenceRetainsTimeoutAndHistoricalStatus(){
        long id=task(List.of(a));jdbc.update("UPDATE t_scan_task SET status=3 WHERE id=?",id);jdbc.update("UPDATE t_scan_task_agent SET state='timeout',weak_status='failed' WHERE task_id=?",id);
        accept(a,report(id,a,true));assertEquals(3,number("status",id));assertEquals(1,jdbc.queryForObject("SELECT late FROM t_scan_task_agent WHERE task_id=?",Integer.class,id));capture("late");
    }
    @Test void duplicateConcurrentReportsAcceptExactlyOneResult() throws Exception {
        long id=task(List.of(a));var r=report(id,a,true);var executor=Executors.newFixedThreadPool(2);
        try{var x=executor.submit(()->accept(a,r));var y=executor.submit(()->accept(a,r));x.get(10,TimeUnit.SECONDS);y.get(10,TimeUnit.SECONDS);}finally{executor.shutdownNow();}
        assertEquals(1,jdbc.queryForObject("SELECT count(*) FROM t_weakpwd_finding WHERE task_id=?",Integer.class,id));assertEquals(2,number("status",id));
    }
    @Test void legacyResultIsUnsupportedAndCannotPersistPassword(){
        long id=task(List.of(a));accept(a,report(id,a,true).toBuilder().setExecutionContract(0).clearCommandId().build());assertEquals(3,number("status",id));assertEquals(0,jdbc.queryForObject("SELECT count(*) FROM t_weakpwd_finding WHERE task_id=?",Integer.class,id));
    }
    @Test void unsupportedLegacyReceiptCannotBeOverwrittenByLaterModernEvidence(){
        long id=task(List.of(a));accept(a,report(id,a,true).toBuilder().setExecutionContract(0).clearCommandId().build());
        accept(a,report(id,a,true));assertEquals(3,number("status",id));
        assertEquals(0,jdbc.queryForObject("SELECT count(*) FROM t_weakpwd_finding WHERE task_id=?",Integer.class,id));
        assertFalse(JsonUtils.write(query.scanCoverage(null,1,100)).contains("PUBLIC-SYNTHETIC-SECRET"));
    }
    @Test void failedCommandFinishesOnlyItsMemberAndLateEvidenceCannotReopenTask(){
        long id=task(List.of(a,b));var lifecycle=new com.alinksec.service.command.BulkTaskCommandLifecycle(jdbc);
        tx.executeWithoutResult(s->lifecycle.onTerminal(a,commands.get(a).getCmdId(),com.alinksec.service.command.CommandLifecycleListener.TerminalState.FAILED,"busy"));
        assertEquals(1,number("status",id));assertEquals(50,number("progress",id));
        accept(b,report(id,b,false));assertEquals(3,number("status",id));
        accept(a,report(id,a,true));assertEquals(3,number("status",id));
        assertEquals(1,jdbc.queryForObject("SELECT late FROM t_scan_task_agent WHERE task_id=? AND agent_id=?",Integer.class,id,a));
    }
    @Test void downgradedAgentCannotReceiveQueuedWeakPasswordCommand(){
        long id=task(List.of(a));jdbc.update("UPDATE t_agent SET weak_password_contract=0 WHERE agent_id=?",a);
        var lifecycle=new com.alinksec.service.command.BulkTaskCommandLifecycle(jdbc);
        assertThrows(IllegalStateException.class,()->lifecycle.prepareDelivery(a,commands.get(a)));
        assertEquals(1,number("status",id));
    }
    @Test void timeoutAndLateReportKeepFailureAndPreciseMemberState(){
        long id=task(List.of(a));
        jdbc.update("UPDATE t_scan_task SET created_at=? WHERE id=?",java.sql.Timestamp.from(java.time.Instant.now().minusSeconds(3600)),id);
        tx.executeWithoutResult(s->tasks.sweepTimeout());
        assertEquals(3,number("status",id));assertEquals(100,number("progress",id));
        assertEquals("timeout",jdbc.queryForObject("SELECT state FROM t_scan_task_agent WHERE task_id=?",String.class,id));
        accept(a,report(id,a,false));assertEquals(3,number("status",id));
        assertEquals(1,jdbc.queryForObject("SELECT late FROM t_scan_task_agent WHERE task_id=?",Integer.class,id));
    }
    void capture(String name){String path=System.getenv("ALINKSEC_WEAKPWD_BROWSER_FIXTURES");if(path==null || path.isBlank())return;try{Path dir=Path.of(path);Files.createDirectories(dir);Files.writeString(dir.resolve(name+".json"),JsonUtils.write(Map.of("coverage",query.scanCoverage(null,1,100),"findings",query.weakpwdFindings(1,100))));}catch(Exception e){throw new IllegalStateException(e);}}
}
