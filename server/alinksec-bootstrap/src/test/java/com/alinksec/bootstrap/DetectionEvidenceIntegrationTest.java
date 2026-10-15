package com.alinksec.bootstrap;

import com.alinksec.common.util.JsonUtils;
import com.alinksec.proto.*;
import com.alinksec.service.command.CommandService;
import com.alinksec.service.config.*;
import com.alinksec.service.protect.PolicyStoreService;
import com.alinksec.service.query.VirusQueryService;
import com.alinksec.service.virus.*;
import com.alinksec.service.command.CommandLifecycleListener.TerminalState;
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

/** Real database transactions, immutable scan evidence and acknowledged file state. */
class DetectionEvidenceIntegrationTest {
    @TempDir Path root;
    HikariDataSource pool; JdbcTemplate jdbc; TransactionTemplate tx;
    VirusTaskService tasks; VirusResultService results; VirusActionService actions; VirusCommandLifecycle lifecycle; VirusQueryService query;
    long actor,release; String a,b,version; List<Long> created=new ArrayList<>();
    Map<String,Command> commands=new ConcurrentHashMap<>();
    @BeforeEach void setup() throws Exception {
        boolean pg="postgres".equals(System.getProperty("alinksec.integration.database"));
        var cfg=new HikariConfig(); cfg.setJdbcUrl(pg?System.getenv("ALINKSEC_INTEGRATION_PG_URL"):"jdbc:sqlite:"+root.resolve("db"));
        if(pg) { cfg.setUsername(System.getenv("ALINKSEC_INTEGRATION_PG_USER")); cfg.setPassword(System.getenv("ALINKSEC_INTEGRATION_PG_PASSWORD")); }
        else { cfg.addDataSourceProperty("transaction_mode","IMMEDIATE"); cfg.addDataSourceProperty("busy_timeout",10000); cfg.addDataSourceProperty("foreign_keys",true); }
        cfg.setMaximumPoolSize(2); cfg.setMinimumIdle(1); pool=new HikariDataSource(cfg);
        if(!pg) new SqliteDatabaseConfiguration.SqliteMigrationBeanPostProcessor().postProcessAfterInitialization(pool,"dataSource");
        jdbc=new JdbcTemplate(pool); tx=new TransactionTemplate(new DataSourceTransactionManager(pool));
        var props=new AlinkSecProperties(); props.getDatabase().setType(pg?"postgres":"sqlite"); var dialect=new DatabaseDialect(props);
        actor=jdbc.queryForObject("INSERT INTO t_user(username,password_hash,role_id,status) VALUES(?,'unused',1,1) RETURNING id",Long.class,"detection-"+UUID.randomUUID());
        a="detect-a-"+UUID.randomUUID(); b="detect-b-"+UUID.randomUUID(); version="detect-"+UUID.randomUUID().toString().substring(0,24);
        for(String agent:List.of(a,b)) jdbc.update("INSERT INTO t_agent(agent_id,hostname,ip,os_type,os_version,arch,status,virus_execution_contract,virus_db_version) VALUES(?,?,?,1,'Ubuntu 24.04','amd64',1,2,?)",agent,"检测主机","192.0.2.10",version);
        release=jdbc.queryForObject("INSERT INTO t_virus_db(db_version,package_key,sha256,size,hash_count,rule_count) VALUES(?,?,'"+"a".repeat(64)+"',1,1,0) RETURNING id",Long.class,version,version+".zip");
        var command=mock(CommandService.class);
        when(command.dispatchAfterCommit(anyString(),any(Command.Builder.class),any())).thenAnswer(inv->{ String id=UUID.randomUUID().toString(); commands.put(id,((Command.Builder)inv.getArgument(1)).setCmdId(id).setIssuedAt(System.currentTimeMillis()).build()); return id; });
        var policy=new PolicyStoreService(jdbc,command); policy.init();
        tasks=new VirusTaskService(jdbc,command,dialect); results=new VirusResultService(jdbc); actions=new VirusActionService(jdbc,command,policy); lifecycle=new VirusCommandLifecycle(jdbc,results); query=new VirusQueryService(jdbc,dialect);
    }
    @AfterEach void close() {
        if(jdbc!=null) {
            for(long task:created) { jdbc.update("DELETE FROM t_virus_action_evidence WHERE finding_id IN (SELECT id FROM t_virus_finding WHERE task_id=?)",task); jdbc.update("DELETE FROM t_virus_finding WHERE task_id=?",task); jdbc.update("DELETE FROM t_virus_task_agent WHERE task_id=?",task); jdbc.update("DELETE FROM t_virus_scan_task WHERE id=?",task); }
            jdbc.update("DELETE FROM t_virus_whitelist WHERE created_by=?",actor); jdbc.update("DELETE FROM t_virus_db WHERE id=?",release);
            for(String agent:List.of(a,b)) { jdbc.update("DELETE FROM t_virus_action_evidence WHERE agent_id=?",agent); jdbc.update("DELETE FROM t_virus_finding WHERE agent_id=?",agent); jdbc.update("DELETE FROM t_agent WHERE agent_id=?",agent); }
            jdbc.update("DELETE FROM t_user WHERE id=?",actor);
            jdbc.update("UPDATE t_virus_state SET realtime_enabled=1,realtime_action='quarantine' WHERE id=1");
        }
        if(pool!=null) pool.close();
    }
    long task(List<String> agents) { long id=tx.execute(s->tasks.createTask("检测证据",agents,3,List.of("/tmp/harmless.sh"),actor)); created.add(id); return id; }
    RptVirusResult report(long task,boolean finding,RptVirusResult.Status status) {
        var r=RptVirusResult.newBuilder().setTaskId(Long.toString(task)).setMode(RptVirusResult.Mode.CUSTOM).setExecutionContract(2).setStatus(status).setDbVersion(version).setFilesScanned(1).setFilesSeen(1).setBytesRead(12).setCoverage("SHA256; internal rule head 2MiB; archives not expanded");
        if(status!=RptVirusResult.Status.COMPLETE) r.setFilesFailed(1).addIssues(VirusScanIssue.newBuilder().setPath("/tmp/missing").setCode("unreadable"));
        if(finding) r.addFindings(VirusFinding.newBuilder().setPath("/tmp/harmless.sh").setSha256("b".repeat(64)).setName("Harmless.Fixture").setSize(12).setEngine("hash").setSeverity(Severity.SEV_HIGH).setActionTaken("alert_only"));
        return r.build();
    }
    long finding(long task) { return jdbc.queryForObject("SELECT id FROM t_virus_finding WHERE task_id=?",Long.class,task); }
    String command(long finding,String action) {
        var outcome=tx.execute(s->actions.act(List.of(finding),action,actor)); return ((List<String>)outcome.get("commands")).get(0);
    }
    void receipt(String command,Map<Long,Boolean> succeeded,TerminalState terminal) {
        var items=succeeded.entrySet().stream().map(e->Map.of("finding_id",Long.toString(e.getKey()),"success",e.getValue(),"quarantine_id",e.getValue()?"c".repeat(32):"","error",e.getValue()?"":"identity_changed")).toList();
        tx.executeWithoutResult(s->lifecycle.onTerminal(a,command,terminal,JsonUtils.write(Map.of("virus_action_contract",2,"results",items))));
    }
    @Test void duplicateFirstResultCannotOverwriteFindingsOrAdvanceProgress() {
        long task=task(List.of(a,b)); tx.executeWithoutResult(s->results.onResult(a,report(task,true,RptVirusResult.Status.COMPLETE)));
        long finding=finding(task); tx.executeWithoutResult(s->results.onResult(a,report(task,false,RptVirusResult.Status.COMPLETE)));
        assertEquals(finding,finding(task)); assertEquals(50,jdbc.queryForObject("SELECT progress FROM t_virus_scan_task WHERE id=?",Integer.class,task));
        tx.executeWithoutResult(s->results.onResult(b,report(task,false,RptVirusResult.Status.COMPLETE)));
        assertEquals(2,jdbc.queryForObject("SELECT status FROM t_virus_scan_task WHERE id=?",Integer.class,task));
    }
    @Test void outsiderAndUnknownTaskCannotCreateFindings() {
        long task=task(List.of(a)); tx.executeWithoutResult(s->results.onResult(b,report(task,true,RptVirusResult.Status.COMPLETE)));
        tx.executeWithoutResult(s->results.onResult(a,report(Long.MAX_VALUE,true,RptVirusResult.Status.COMPLETE)));
        assertEquals(0,jdbc.queryForObject("SELECT count(*) FROM t_virus_finding WHERE task_id=?",Integer.class,task));
        assertEquals(0,jdbc.queryForObject("SELECT progress FROM t_virus_scan_task WHERE id=?",Integer.class,task));
    }
    @Test void partialCoverageIsVisibleAndCannotClaimSuccessfulCompletion() {
        long task=task(List.of(a)); var partial=report(task,true,RptVirusResult.Status.PARTIAL);
        assertThrows(IllegalArgumentException.class,()->tx.executeWithoutResult(s->results.onResult(a,partial.toBuilder().setStatus(RptVirusResult.Status.COMPLETE).build())));
        tx.executeWithoutResult(s->results.onResult(a,partial)); assertEquals(3,jdbc.queryForObject("SELECT status FROM t_virus_scan_task WHERE id=?",Integer.class,task));
        var evidence=query.taskEvidence(task).get(0); assertEquals("partial",evidence.get("state")); assertTrue(JsonUtils.write(evidence).contains("unreadable")); assertFalse(JsonUtils.write(evidence).contains("report_b64"));
    }
    @Test void timedOutLateEvidenceIsRetainedWithoutReopeningTask() {
        long task=task(List.of(a)); jdbc.update("UPDATE t_virus_scan_task SET status=3 WHERE id=?",task); jdbc.update("UPDATE t_virus_task_agent SET state='timeout' WHERE task_id=?",task);
        tx.executeWithoutResult(s->results.onResult(a,report(task,true,RptVirusResult.Status.COMPLETE)));
        assertEquals(3,jdbc.queryForObject("SELECT status FROM t_virus_scan_task WHERE id=?",Integer.class,task)); assertEquals(1,((Number)query.taskEvidence(task).get(0).get("late")).intValue());
    }
    @Test void pendingActionDoesNotChangePhysicalStateAndFailurePreservesIt() {
        long task=task(List.of(a)); tx.executeWithoutResult(s->results.onResult(a,report(task,true,RptVirusResult.Status.COMPLETE))); long finding=finding(task); String command=command(finding,"quarantine");
        assertEquals(0,jdbc.queryForObject("SELECT status FROM t_virus_finding WHERE id=?",Integer.class,finding));
        assertThrows(IllegalArgumentException.class,()->command(finding,"delete")); receipt(command,Map.of(finding,false),TerminalState.FAILED);
        assertEquals(0,jdbc.queryForObject("SELECT status FROM t_virus_finding WHERE id=?",Integer.class,finding)); assertEquals("failed",query.actionHistory(finding).get(0).get("state"));
    }
    @Test void successfulReceiptBindsQuarantineObjectAndSupportsRestore() throws Exception {
        long task=task(List.of(a)); tx.executeWithoutResult(s->results.onResult(a,report(task,true,RptVirusResult.Status.COMPLETE))); long finding=finding(task); String command=command(finding,"quarantine");
        receipt(command,Map.of(finding,true),TerminalState.DONE); assertEquals(1,jdbc.queryForObject("SELECT status FROM t_virus_finding WHERE id=?",Integer.class,finding));
        String restore=command(finding,"restore"); assertEquals("c".repeat(32),commands.get(restore).getVirusAction().getTargets(0).getQuarantineId());
        receipt(restore,Map.of(finding,true),TerminalState.DONE); assertEquals(3,jdbc.queryForObject("SELECT status FROM t_virus_finding WHERE id=?",Integer.class,finding));
        capture("restored",task);
    }
    @Test void wrongTargetOrMissingReceiptCannotMarkActionSuccessful() {
        long task=task(List.of(a)); tx.executeWithoutResult(s->results.onResult(a,report(task,true,RptVirusResult.Status.COMPLETE))); long finding=finding(task); String command=command(finding,"delete");
        receipt(command,Map.of(finding+1,true),TerminalState.DONE); assertEquals(0,jdbc.queryForObject("SELECT status FROM t_virus_finding WHERE id=?",Integer.class,finding));
        assertEquals("failed",query.actionHistory(finding).get(0).get("state"));
    }
    @Test void timeoutAndRepeatedReceiptsDoNotInventConfirmedState() {
        long task=task(List.of(a)); tx.executeWithoutResult(s->results.onResult(a,report(task,true,RptVirusResult.Status.COMPLETE))); long finding=finding(task); String command=command(finding,"delete");
        receipt(command,Map.of(),TerminalState.TIMEOUT); receipt(command,Map.of(finding,true),TerminalState.DONE);
        assertEquals(0,jdbc.queryForObject("SELECT status FROM t_virus_finding WHERE id=?",Integer.class,finding)); assertEquals("timeout",query.actionHistory(finding).get(0).get("state"));
    }
    @Test void legacyAgentEmptyReleaseInvalidPathAndDisabledActorAreRefused() {
        jdbc.update("UPDATE t_agent SET virus_execution_contract=0 WHERE agent_id=?",a); assertThrows(IllegalArgumentException.class,()->task(List.of(a)));
        jdbc.update("UPDATE t_agent SET virus_execution_contract=2 WHERE agent_id=?",a);
        assertThrows(IllegalArgumentException.class,()->tx.execute(s->tasks.createTask("bad",List.of(a),3,List.of(" "),actor)));
        jdbc.update("UPDATE t_virus_db SET hash_count=0 WHERE id=?",release); assertThrows(IllegalArgumentException.class,()->task(List.of(a)));
        jdbc.update("UPDATE t_user SET status=0 WHERE id=?",actor); assertThrows(IllegalArgumentException.class,()->tx.executeWithoutResult(s->actions.updateRealtime(false,"alert_only",actor)));
    }
    @Test void whitelistIsIdempotentAndDoesNotEraseEvidenceOrPhysicalState() {
        long task=task(List.of(a)); tx.executeWithoutResult(s->results.onResult(a,report(task,true,RptVirusResult.Status.COMPLETE))); long finding=finding(task);
        tx.executeWithoutResult(s->actions.act(List.of(finding),"whitelist",actor)); tx.executeWithoutResult(s->actions.act(List.of(finding),"whitelist",actor));
        assertEquals(1,jdbc.queryForObject("SELECT count(*) FROM t_virus_whitelist WHERE created_by=?",Integer.class,actor)); assertEquals(0,jdbc.queryForObject("SELECT status FROM t_virus_finding WHERE id=?",Integer.class,finding));
        assertThrows(IllegalArgumentException.class,()->tx.executeWithoutResult(s->actions.addWhitelistEntry("path","relative",null,actor)));
        assertThrows(IllegalArgumentException.class,()->tx.executeWithoutResult(s->actions.addWhitelistEntry("path","/",null,actor)));
    }
    @Test void queuedCommandsRecheckVersionAndCurrentActor() {
        long task=task(List.of(a)); Command scan=commands.values().stream().filter(Command::hasVirusScan).findFirst().orElseThrow();
        jdbc.update("UPDATE t_virus_db SET db_version=? WHERE id=?",version+"-new",release);
        assertThrows(IllegalArgumentException.class,()->tx.execute(s->lifecycle.prepareDelivery(a,scan)));
        jdbc.update("UPDATE t_virus_db SET db_version=? WHERE id=?",version,release);
        jdbc.update("UPDATE t_user SET status=0 WHERE id=?",actor);
        assertThrows(IllegalArgumentException.class,()->tx.execute(s->lifecycle.prepareDelivery(a,scan)));
    }
    @Test void concurrentDuplicatesRetainOneEvidenceAndExactHostProgress() throws Exception {
        long task=task(List.of(a,b)); var workers=Executors.newFixedThreadPool(2);
        try {
            List<Future<?>> futures=new ArrayList<>(); for(int i=0;i<6;i++) { String agent=i%2==0?a:b; futures.add(workers.submit(()->tx.executeWithoutResult(s->results.onResult(agent,report(task,true,RptVirusResult.Status.COMPLETE))))); }
            for(var f:futures) f.get(20,TimeUnit.SECONDS);
        } finally { workers.shutdownNow(); }
        assertEquals(2,jdbc.queryForObject("SELECT count(*) FROM t_virus_finding WHERE task_id=?",Integer.class,task)); assertEquals(100,jdbc.queryForObject("SELECT progress FROM t_virus_scan_task WHERE id=?",Integer.class,task));
    }
    @Test void expiredOfflineActionsAllowFreshReviewAndCannotReplay() {
        long task=task(List.of(a)); tx.executeWithoutResult(s->results.onResult(a,report(task,true,RptVirusResult.Status.COMPLETE)));long id=finding(task);String command=command(id,"quarantine");
        jdbc.update("UPDATE t_virus_action_evidence SET created_at=? WHERE command_id=?",java.time.Instant.now().minusSeconds(960).toString(),command);
        tx.executeWithoutResult(s->tasks.sweepTimeout());assertEquals("timeout",query.actionHistory(id).get(0).get("state"));
        assertThrows(IllegalArgumentException.class,()->tx.execute(s->lifecycle.prepareDelivery(a,commands.get(command))));
        String fresh=command(id,"quarantine");assertNotEquals(command,fresh);
    }
    @Test void realtimeDeduplicatesAndRetainsInitialActionAfterManualRestore() {
        String raw=JsonUtils.write(Map.ofEntries(Map.entry("execution_contract",2),Map.entry("source","realtime_guard"),Map.entry("path","/tmp/realtime.sh"),Map.entry("sha256","d".repeat(64)),Map.entry("name","Realtime.Harmless"),Map.entry("engine","hash"),Map.entry("size",12),Map.entry("action","quarantined"),Map.entry("quarantine_id","c".repeat(32))));
        var event=RptSecurityEvent.newBuilder().setType("virus").setSeverity(Severity.SEV_HIGH).setDetail(raw).build();
        tx.executeWithoutResult(s->results.onRealtime(a,event,"realtime-id")); tx.executeWithoutResult(s->results.onRealtime(a,event,"realtime-id"));
        assertEquals(1,jdbc.queryForObject("SELECT count(*) FROM t_virus_finding WHERE agent_id=?",Integer.class,a));
        long id=jdbc.queryForObject("SELECT id FROM t_virus_finding WHERE agent_id=?",Long.class,a);
        receipt(command(id,"restore"),Map.of(id,true),TerminalState.DONE);
        assertEquals(raw,jdbc.queryForObject("SELECT initial_evidence FROM t_virus_finding WHERE id=?",String.class,id));
        assertEquals("quarantined",((com.fasterxml.jackson.databind.JsonNode)query.actionHistory(id).get(1).get("evidence")).path("action").asText());
        tx.executeWithoutResult(s->results.onRealtime(a,event.toBuilder().setDetail("{\"source\":\"realtime_guard\"}").build(),"legacy"));
        assertEquals(1,jdbc.queryForObject("SELECT count(*) FROM t_virus_finding WHERE agent_id=?",Integer.class,a));
    }
    @Test void partialBatchReceiptsConfirmOnlyTheirSuccessfulTargets() {
        long task=task(List.of(a));
        var first=report(task,true,RptVirusResult.Status.COMPLETE);
        var two=first.toBuilder().setFilesScanned(2).setFilesSeen(2).addFindings(first.getFindings(0).toBuilder().setPath("/tmp/second.sh")).build();
        tx.executeWithoutResult(s->results.onResult(a,two));
        var ids=jdbc.queryForList("SELECT id FROM t_virus_finding WHERE task_id=? ORDER BY id",Long.class,task);
        var outcome=tx.execute(s->actions.act(ids,"quarantine",actor)); String command=((List<String>)outcome.get("commands")).get(0);
        receipt(command,Map.of(ids.get(0),true,ids.get(1),false),TerminalState.FAILED);
        assertEquals(1,jdbc.queryForObject("SELECT status FROM t_virus_finding WHERE id=?",Integer.class,ids.get(0)));
        assertEquals(0,jdbc.queryForObject("SELECT status FROM t_virus_finding WHERE id=?",Integer.class,ids.get(1)));
        assertEquals("succeeded",query.actionHistory(ids.get(0)).get(0).get("state")); assertEquals("failed",query.actionHistory(ids.get(1)).get(0).get("state"));
    }
    @Test void reportFailureRollsBackDedupAndAuthenticatedHostScopesReplay() {
        var props=new AlinkSecProperties(); props.getDatabase().setType("postgres".equals(System.getProperty("alinksec.integration.database"))?"postgres":"sqlite");
        var dispatcher=new com.alinksec.service.report.ReportDispatcher(mock(com.alinksec.service.heartbeat.HeartbeatService.class),mock(com.alinksec.service.asset.AssetService.class),mock(com.alinksec.service.alert.SecurityEventService.class),mock(CommandService.class),mock(com.alinksec.service.baseline.BaselineResultService.class),mock(com.alinksec.service.scan.ScanResultService.class),results,mock(com.alinksec.service.fix.FixResultService.class),mock(com.alinksec.service.metrics.MetricsForwarder.class),mock(com.alinksec.service.log.LogBatchService.class),jdbc,new DatabaseDialect(props),new DataSourceTransactionManager(pool));
        long task=task(List.of(a,b)); String id="rollback-"+UUID.randomUUID();
        var report=Report.newBuilder().setAgentId(b).setReportId(id).setVirusResult(report(task,true,RptVirusResult.Status.PARTIAL).toBuilder().setStatus(RptVirusResult.Status.COMPLETE)).build();
        assertThrows(IllegalArgumentException.class,()->dispatcher.dispatch(a,report));
        assertEquals(0,jdbc.queryForObject("SELECT count(*) FROM t_virus_finding WHERE task_id=?",Integer.class,task));
        var valid=report.toBuilder().setVirusResult(report(task,true,RptVirusResult.Status.COMPLETE)).build();
        dispatcher.dispatch(a,valid); dispatcher.dispatch(b,valid); dispatcher.dispatch(a,valid);
        assertEquals(2,jdbc.queryForObject("SELECT count(*) FROM t_virus_finding WHERE task_id=?",Integer.class,task));
        assertEquals(100,jdbc.queryForObject("SELECT progress FROM t_virus_scan_task WHERE id=?",Integer.class,task));
    }
    @Test void obsoletePolicyCannotReplayAndRollbackKeepsCurrentSnapshot() {
        var guard=new com.alinksec.service.protect.PolicyCommandGuard(jdbc);
        var row=jdbc.queryForMap("SELECT version,CAST(content AS TEXT) AS content FROM t_policy_state WHERE id=1");
        var old=Command.newBuilder().setPolicySync(CmdPolicySync.newBuilder().setPolicyVersion("v"+row.get("version")).setPolicyJson((String)row.get("content"))).build();
        tx.executeWithoutResult(s->{ actions.updateRealtime(false,"alert_only",actor); s.setRollbackOnly(); });
        assertEquals(old,tx.execute(s->guard.prepareDelivery(a,old)));
        tx.executeWithoutResult(s->actions.updateRealtime(false,"alert_only",actor));
        assertThrows(IllegalArgumentException.class,()->tx.execute(s->guard.prepareDelivery(a,old)));
    }
    @Test void capturedConsoleLifecycleUsesActualCommittedDatabaseResponses() throws Exception {
        jdbc.update("INSERT INTO t_virus_finding(agent_id,path,name,sha256,size,engine,severity,action_taken,status) VALUES(?,'/tmp/legacy.sh','Legacy.Allowlist',?,12,'hash',3,'whitelisted',4)",b,"e".repeat(64));
        long task=task(List.of(a,b)); tx.executeWithoutResult(s->results.onResult(a,report(task,true,RptVirusResult.Status.PARTIAL))); tx.executeWithoutResult(s->results.onResult(b,report(task,false,RptVirusResult.Status.COMPLETE)));
        long id=finding(task); Map<String,Object> stages=new LinkedHashMap<>(); stages.put("active",snapshot(task,id));
        String failed=command(id,"quarantine"); stages.put("pending",snapshot(task,id)); receipt(failed,Map.of(id,false),TerminalState.FAILED); stages.put("failed",snapshot(task,id));
        receipt(command(id,"quarantine"),Map.of(id,true),TerminalState.DONE); stages.put("quarantined",snapshot(task,id));
        receipt(command(id,"restore"),Map.of(id,true),TerminalState.DONE); stages.put("restored",snapshot(task,id));
        tx.executeWithoutResult(s->actions.act(List.of(id),"whitelist",actor)); tx.executeWithoutResult(s->actions.updateRealtime(false,"alert_only",actor)); stages.put("whitelisted",snapshot(task,id));
        String directory=System.getenv("ALINKSEC_DETECTION_FIXTURE_DIR"); if(directory!=null && !directory.isBlank()) {
            Path path=Path.of(directory); Files.createDirectories(path); Files.writeString(path.resolve("console-"+("postgres".equals(System.getProperty("alinksec.integration.database"))?"postgres":"sqlite")+".json"),JsonUtils.write(Map.of("stages",stages,"finding",id,"task",task,"agent",a)));
        }
    }
    Map<String,Object> snapshot(long task,long finding) {
        return Map.of("stats",query.stats(),"findings",query.findings(null,null,1,100),"tasks",query.tasks(1,100),"evidence",query.taskEvidence(task),"history",query.actionHistory(finding),"db",query.dbVersions(),"whitelist",query.whitelist());
    }
    void capture(String state,long task) throws Exception {
        String directory=System.getenv("ALINKSEC_DETECTION_FIXTURE_DIR"); if(directory==null || directory.isBlank()) return;
        Path path=Path.of(directory); Files.createDirectories(path);
        Files.writeString(path.resolve(state+".json"),JsonUtils.write(Map.of("stats",query.stats(),"findings",query.findings(null,null,1,100),"tasks",query.tasks(1,100),"evidence",query.taskEvidence(task),"history",query.actionHistory(finding(task)),"db",query.dbVersions(),"whitelist",query.whitelist())));
    }
}
