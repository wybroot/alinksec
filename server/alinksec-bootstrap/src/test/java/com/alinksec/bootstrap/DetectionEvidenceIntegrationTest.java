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
    void clamHeartbeat(String agent,String version) {
        var d=ClamavIntegrationTest.coverage("ready");d.put("version",version);
        new ClamavService(jdbc).heartbeat(agent,RptHeartbeat.newBuilder().setClamavContract(1).setClamavStatus(JsonUtils.write(d)).build());
    }
    long clamTask(List<String> agents) {
        long id=tx.execute(s->tasks.createTask("ClamAV 测试",agents,3,List.of("/tmp"),actor,"clamav"));created.add(id);return id;
    }
    RptVirusResult clamReport(long task,String v) {
        return report(task,true,RptVirusResult.Status.COMPLETE).toBuilder().setExecutionContract(3).setScanEngine("clamav").setDbVersion(v).setCoverage("ClamAV INSTREAM of stable regular files <=20MiB; daemon archive/recursion/time limits apply; symlinks, special files, virtual/container filesystems and Agent work directory excluded; pinned reported engine version is not a complete signature corpus digest").clearFindings().addFindings(VirusFinding.newBuilder().setPath("/tmp/clam-marker").setName("Harmless.ClamFixture").setSha256("b".repeat(64)).setSize(12).setSeverity(Severity.SEV_HIGH).setEngine("clamav").setEngineVersion(v).setActionTaken("alert_only")).build();
    }
    @Test void clamavPinsPerHostVersionsWithoutBuiltinLibraryAndPreservesEvidence() throws Exception {
        String va="ClamAV 1.4.6/fixture-a",vb="ClamAV 1.4.6/fixture-b";
        clamHeartbeat(a,va);clamHeartbeat(b,vb);jdbc.update("UPDATE t_virus_db SET hash_count=0,rule_count=0 WHERE id=?",release);
        long task=clamTask(List.of(a,b));
        for(Command command:commands.values())if(command.hasVirusScan()) {
            assertEquals(3,command.getVirusScan().getExecutionContract());assertEquals("clamav",command.getVirusScan().getEngine());
            String agent=jdbc.queryForObject("SELECT agent_id FROM t_virus_task_agent WHERE command_id=?",String.class,command.getCmdId());
            assertEquals(agent.equals(a)?va:vb,command.getVirusScan().getExpectedDbVersion());
            assertNotNull(tx.execute(s->lifecycle.prepareDelivery(agent,command)));
        }
        assertThrows(IllegalArgumentException.class,()->tx.executeWithoutResult(s->results.onResult(a,report(task,true,RptVirusResult.Status.COMPLETE))));
        assertThrows(IllegalArgumentException.class,()->tx.executeWithoutResult(s->results.onResult(a,clamReport(task,vb))));
        tx.executeWithoutResult(s->results.onResult(a,clamReport(task,va)));
        tx.executeWithoutResult(s->results.onResult(b,clamReport(task,vb).toBuilder().clearFindings().build()));
        assertEquals(2,jdbc.queryForObject("SELECT status FROM t_virus_scan_task WHERE id=?",Integer.class,task));
        assertEquals("clamav",jdbc.queryForObject("SELECT engine FROM t_virus_finding WHERE task_id=?",String.class,task));
        assertTrue(JsonUtils.write(query.taskEvidence(task)).contains("expected_engine_version"));assertTrue(JsonUtils.write(query.taskEvidence(task)).contains("clamav"));
        assertFalse(JsonUtils.write(query.taskEvidence(task)).contains("report_b64"));
        String action=command(finding(task),"quarantine");receipt(action,Map.of(finding(task),true),TerminalState.DONE);
        assertEquals(1,jdbc.queryForObject("SELECT status FROM t_virus_finding WHERE task_id=?",Integer.class,task));
        capture("clamav",task);
        String directory=System.getenv("ALINKSEC_CLAMAV_BROWSER_FIXTURES");
        if(directory!=null&&!directory.isBlank()){Path dest=Path.of(directory);Files.createDirectories(dest);Files.writeString(dest.resolve("task.json"),JsonUtils.write(snapshot(task,finding(task))));}
    }
    @Test void clamavDeliveryRechecksReadinessAndVersionAndBuiltinRejectsClamav() {
        assertThrows(IllegalArgumentException.class,()->clamTask(List.of(a)));
        clamHeartbeat(a,"ClamAV 1.4.6/a");long task=clamTask(List.of(a));
        Command command=commands.values().stream().filter(Command::hasVirusScan).findFirst().orElseThrow();
        clamHeartbeat(a,"ClamAV 1.4.6/b");assertThrows(IllegalArgumentException.class,()->tx.execute(s->lifecycle.prepareDelivery(a,command)));
        clamHeartbeat(a,"ClamAV 1.4.6/a");jdbc.update("UPDATE t_clamav_status SET observed_at=1 WHERE agent_id=?",a);
        assertThrows(IllegalArgumentException.class,()->tx.execute(s->lifecycle.prepareDelivery(a,command)));
        long builtin=task(List.of(b));assertThrows(IllegalArgumentException.class,()->tx.executeWithoutResult(s->results.onResult(b,clamReport(builtin,"ClamAV 1.4.6/a"))));
        var failure=clamReport(task,"ClamAV 1.4.6/b").toBuilder().clearFindings().setFilesScanned(0).setStatus(RptVirusResult.Status.FAILED).setFilesFailed(1).addIssues(VirusScanIssue.newBuilder().setCode("clamav_version_changed")).build();
        tx.executeWithoutResult(s->results.onResult(a,failure));assertEquals(3,jdbc.queryForObject("SELECT status FROM t_virus_scan_task WHERE id=?",Integer.class,task));
    }
    void yaraHeartbeat(String agent,String version) {
        var d=YaraIntegrationTest.coverage("ready");d.put("version",version);
        new YaraService(jdbc).heartbeat(agent,RptHeartbeat.newBuilder().setYaraContract(1).setYaraStatus(JsonUtils.write(d)).build());
    }
    long yaraTask(List<String> agents) {
        long id=tx.execute(s->tasks.createTask("YARA 测试",agents,3,List.of("/tmp"),actor,"yara"));created.add(id);return id;
    }
    RptVirusResult yaraReport(long task,String v) {
        return report(task,true,RptVirusResult.Status.COMPLETE).toBuilder().setExecutionContract(4).setScanEngine("yara").setDbVersion(v).setCoverage("Native YARA isolated memory scan; exact UTF8 rule source SHA256 pinned; no includes or archive expansion").clearFindings().addFindings(VirusFinding.newBuilder().setPath("/tmp/clam-marker").setName("Harmless_YaraFixture").addMatchedRules("Harmless_YaraFixture").addMatchedRules("Harmless_SecondRule").setSha256("b".repeat(64)).setSize(12).setSeverity(Severity.SEV_HIGH).setEngine("yara").setEngineVersion(v).setActionTaken("alert_only")).build();
    }
    @Test void yaraPinsPerHostVersionsWithoutBuiltinLibraryAndPreservesEvidence() throws Exception {
        String va="YARA 4.5.8/sha256:"+"a".repeat(64),vb="YARA 4.5.8/sha256:"+"b".repeat(64);
        yaraHeartbeat(a,va);yaraHeartbeat(b,vb);jdbc.update("UPDATE t_virus_db SET hash_count=0,rule_count=0 WHERE id=?",release);
        long task=yaraTask(List.of(a,b));
        for(Command command:commands.values())if(command.hasVirusScan()) {
            assertEquals(4,command.getVirusScan().getExecutionContract());assertEquals("yara",command.getVirusScan().getEngine());
            String agent=jdbc.queryForObject("SELECT agent_id FROM t_virus_task_agent WHERE command_id=?",String.class,command.getCmdId());
            assertEquals(agent.equals(a)?va:vb,command.getVirusScan().getExpectedDbVersion());
            assertNotNull(tx.execute(s->lifecycle.prepareDelivery(agent,command)));
        }
        assertThrows(IllegalArgumentException.class,()->tx.executeWithoutResult(s->results.onResult(a,report(task,true,RptVirusResult.Status.COMPLETE))));
        assertThrows(IllegalArgumentException.class,()->tx.executeWithoutResult(s->results.onResult(a,yaraReport(task,vb))));
        assertThrows(IllegalArgumentException.class,()->tx.executeWithoutResult(s->results.onResult(a,yaraReport(task,va).toBuilder().setFindings(0,yaraReport(task,va).getFindings(0).toBuilder().clearMatchedRules()).build())));
        assertThrows(IllegalArgumentException.class,()->tx.executeWithoutResult(s->results.onResult(a,yaraReport(task,va).toBuilder().setFindings(0,yaraReport(task,va).getFindings(0).toBuilder().addMatchedRules("Harmless_YaraFixture")).build())));
        tx.executeWithoutResult(s->results.onResult(a,yaraReport(task,va)));
        tx.executeWithoutResult(s->results.onResult(b,yaraReport(task,vb).toBuilder().clearFindings().build()));
        assertEquals(2,jdbc.queryForObject("SELECT status FROM t_virus_scan_task WHERE id=?",Integer.class,task));
        assertEquals("yara",jdbc.queryForObject("SELECT engine FROM t_virus_finding WHERE task_id=?",String.class,task));
        assertTrue(JsonUtils.write(query.taskEvidence(task)).contains("expected_engine_version"));assertTrue(JsonUtils.write(query.taskEvidence(task)).contains("yara"));
        assertFalse(JsonUtils.write(query.taskEvidence(task)).contains("report_b64"));
        String action=command(finding(task),"quarantine");receipt(action,Map.of(finding(task),true),TerminalState.DONE);
        assertEquals(1,jdbc.queryForObject("SELECT status FROM t_virus_finding WHERE task_id=?",Integer.class,task));
        String initial=jdbc.queryForObject("SELECT initial_evidence FROM t_virus_finding WHERE task_id=?",String.class,task);
        assertTrue(initial.contains("Harmless_SecondRule"));
        String restore=command(finding(task),"restore");receipt(restore,Map.of(finding(task),true),TerminalState.DONE);
        assertEquals(initial,jdbc.queryForObject("SELECT initial_evidence FROM t_virus_finding WHERE task_id=?",String.class,task));
        capture("yara",task);
        String directory=System.getenv("ALINKSEC_YARA_BROWSER_FIXTURES");
        if(directory!=null&&!directory.isBlank()){Path dest=Path.of(directory);Files.createDirectories(dest);Files.writeString(dest.resolve("task.json"),JsonUtils.write(snapshot(task,finding(task))));}
    }
    @Test void yaraRealtimeRetainsValidatedMatchedRulesAndRejectsMalformedEvidence() {
        var data=new LinkedHashMap<String,Object>();
        data.put("execution_contract",2);data.put("source","realtime_guard");data.put("path","/tmp/yara-realtime");data.put("sha256","d".repeat(64));data.put("name","Harmless_YaraFixture");data.put("matched_rules",List.of("Harmless_YaraFixture","Harmless_SecondRule"));data.put("engine","yara");data.put("engine_version","YARA 4.5.8/sha256:"+"a".repeat(64));data.put("size",12);data.put("action","quarantined");data.put("quarantine_id","c".repeat(32));
        var event=RptSecurityEvent.newBuilder().setType("virus").setSeverity(Severity.SEV_HIGH).setDetail(JsonUtils.write(data)).build();
        tx.executeWithoutResult(s->results.onRealtime(a,event,"yara-realtime"));tx.executeWithoutResult(s->results.onRealtime(a,event,"yara-realtime"));
        assertEquals(1,jdbc.queryForObject("SELECT count(*) FROM t_virus_finding WHERE agent_id=?",Integer.class,a));
        assertTrue(jdbc.queryForObject("SELECT initial_evidence FROM t_virus_finding WHERE agent_id=?",String.class,a).contains("Harmless_SecondRule"));
        for(var change:List.of(Map.of("matched_rules",List.of()),Map.of("matched_rules",List.of("wrong_first")),Map.of("matched_rules",List.of("Harmless_YaraFixture","Harmless_YaraFixture")),Map.of("engine_version","YARA wrong"),Map.of("size",(20L<<20)+1))){var bad=new LinkedHashMap<>(data);bad.putAll(change);assertThrows(IllegalArgumentException.class,()->tx.executeWithoutResult(s->results.onRealtime(a,event.toBuilder().setDetail(JsonUtils.write(bad)).build(),"bad-yara")));}
    }
    @Test void yaraDeliveryRechecksReadinessAndVersionAndBuiltinRejectsYara() {
        assertThrows(IllegalArgumentException.class,()->yaraTask(List.of(a)));
        yaraHeartbeat(a,"YARA 4.5.8/sha256:"+"a".repeat(64));long task=yaraTask(List.of(a));
        Command command=commands.values().stream().filter(Command::hasVirusScan).findFirst().orElseThrow();
        yaraHeartbeat(a,"YARA 4.5.8/sha256:"+"b".repeat(64));assertThrows(IllegalArgumentException.class,()->tx.execute(s->lifecycle.prepareDelivery(a,command)));
        yaraHeartbeat(a,"YARA 4.5.8/sha256:"+"a".repeat(64));jdbc.update("UPDATE t_yara_status SET observed_at=1 WHERE agent_id=?",a);
        assertThrows(IllegalArgumentException.class,()->tx.execute(s->lifecycle.prepareDelivery(a,command)));
        long builtin=task(List.of(b));assertThrows(IllegalArgumentException.class,()->tx.executeWithoutResult(s->results.onResult(b,yaraReport(builtin,"YARA 4.5.8/sha256:"+"a".repeat(64)))));
        var failure=yaraReport(task,"YARA 4.5.8/sha256:"+"b".repeat(64)).toBuilder().clearFindings().setFilesScanned(0).setStatus(RptVirusResult.Status.FAILED).setFilesFailed(1).addIssues(VirusScanIssue.newBuilder().setCode("yara_version_changed")).build();
        tx.executeWithoutResult(s->results.onResult(a,failure));assertEquals(3,jdbc.queryForObject("SELECT status FROM t_virus_scan_task WHERE id=?",Integer.class,task));
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
        jdbc.update("UPDATE t_virus_db SET db_version=? WHERE id=?","new-"+version.substring(4),release);
        assertThrows(IllegalArgumentException.class,()->tx.execute(s->lifecycle.prepareDelivery(a,scan)));
        jdbc.update("UPDATE t_virus_db SET db_version=? WHERE id=?",version,release);
        jdbc.update("UPDATE t_user SET status=0 WHERE id=?",actor);
        assertThrows(IllegalArgumentException.class,()->tx.execute(s->lifecycle.prepareDelivery(a,scan)));
    }
    long boundedTask(List<String> agents,VirusTaskService.ScanBudget budget,Long retry) {
        long id=tx.execute(s->tasks.createTask("受限复核",agents,3,List.of("/tmp/missing"),actor,"builtin",budget,retry));created.add(id);return id;
    }
    @Test void configuredBudgetReachesCommandAndQueuedDeliveryKeepsOriginalDeadline() {
        var budget=new VirusTaskService.ScanBudget(120,17,4096);
        long id=boundedTask(List.of(a),budget,null);
        Command command=commands.values().stream().filter(c->c.hasVirusScan() && c.getVirusScan().getTaskId().equals(Long.toString(id))).findFirst().orElseThrow();
        assertEquals(120,command.getVirusScan().getTimeLimitSec());assertEquals(17,command.getVirusScan().getMaxFiles());assertEquals(4096,command.getVirusScan().getMaxTotalBytes());
        var queued=command.toBuilder().setIssuedAt(System.currentTimeMillis()-30000).build();
        int remaining=tx.execute(s->lifecycle.prepareDelivery(a,queued)).getVirusScan().getTimeLimitSec();
        assertTrue(remaining>=88 && remaining<=90);
        assertThrows(IllegalArgumentException.class,()->tx.execute(s->lifecycle.prepareDelivery(a,command.toBuilder().setIssuedAt(System.currentTimeMillis()-121000).build())));
        Command oneSecond=command.toBuilder().setIssuedAt(System.currentTimeMillis()).setVirusScan(command.getVirusScan().toBuilder().setTimeLimitSec(1)).build();
        assertEquals(1,tx.execute(s->lifecycle.prepareDelivery(a,oneSecond)).getVirusScan().getTimeLimitSec());
        assertThrows(IllegalArgumentException.class,()->tx.execute(s->lifecycle.prepareDelivery(a,oneSecond.toBuilder().setIssuedAt(System.currentTimeMillis()-1100).build())));
        assertEquals(120,JsonUtils.read((String)jdbc.queryForObject("SELECT CAST(scope AS TEXT) FROM t_virus_scan_task WHERE id=?",String.class,id)).path("time_limit_sec").asInt());
    }
    @Test void invalidBudgetsCannotCreateOrDispatchTasks() {
        for(long[] b:List.of(new long[]{0,1,1},new long[]{7201,1,1},new long[]{1,0,1},new long[]{1,100001,1},new long[]{1,1,0},new long[]{1,1,(20L<<30)+1}))
            assertThrows(IllegalArgumentException.class,()->new VirusTaskService.ScanBudget((int)b[0],(int)b[1],b[2]));
        assertTrue(commands.isEmpty());assertEquals(0,jdbc.queryForObject("SELECT count(*) FROM t_virus_scan_task",Integer.class));
    }
    @Test void restBudgetRequiresIntegralBoundedFieldsAndRetryId() {
        var controller=new com.alinksec.gateway.rest.VirusController(query,tasks,actions,mock(VirusDbService.class),mock(com.alinksec.service.download.AgentDownloadTokenService.class));
        var request=mock(jakarta.servlet.http.HttpServletRequest.class);when(request.getAttribute("uid")).thenReturn(actor);
        var body=(com.fasterxml.jackson.databind.node.ObjectNode)JsonUtils.read(JsonUtils.write(Map.of("agentIds",List.of(a),"mode",3,"paths",List.of("/tmp"),"engine","builtin")));
        for(String raw:List.of("null","{}","{\"timeLimitSec\":\"60\",\"maxFiles\":100,\"maxTotalBytes\":1024}","{\"timeLimitSec\":60.5,\"maxFiles\":100,\"maxTotalBytes\":1024}","{\"timeLimitSec\":60,\"maxFiles\":100,\"maxTotalBytes\":21474836481}")) {
            body.set("budget",JsonUtils.read(raw));assertThrows(IllegalArgumentException.class,()->tx.execute(s->controller.createTask(body,request)));
        }
        body.remove("budget");body.put("retryOf","1");
        assertThrows(IllegalArgumentException.class,()->tx.execute(s->controller.createTask(body,request)));
        assertTrue(commands.isEmpty());
    }
    @Test void restTaskRouteBindsFiltersAndPaginationThroughMvc() throws Exception {
        task(List.of(a));task(List.of(a));task(List.of(b));
        var controller=new com.alinksec.gateway.rest.VirusController(query,tasks,actions,mock(VirusDbService.class),mock(com.alinksec.service.download.AgentDownloadTokenService.class));
        var mvc=org.springframework.test.web.servlet.setup.MockMvcBuilders.standaloneSetup(controller).build();
        var response=mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get("/api/virus/tasks").param("page","2").param("size","1").param("agentId",a).param("engine","builtin").param("status","1")).andReturn().getResponse();
        assertEquals(200,response.getStatus());
        var body=JsonUtils.read(response.getContentAsString());assertEquals(0,body.path("code").asInt());
        assertEquals(2,body.path("data").path("total").asInt());assertEquals(1,body.path("data").path("list").size());
    }
    @Test void retryPinsNewTaskAndPreservesOriginalEvidenceWhileRejectingDuplicatePendingRetry() {
        long original=task(List.of(a,b));
        tx.executeWithoutResult(s->results.onResult(a,report(original,false,RptVirusResult.Status.PARTIAL)));
        tx.executeWithoutResult(s->results.onResult(b,report(original,false,RptVirusResult.Status.COMPLETE)));
        String before=JsonUtils.write(query.taskEvidence(original));
        var budget=new VirusTaskService.ScanBudget(60,100,1048576);
        assertThrows(IllegalArgumentException.class,()->boundedTask(List.of(b),budget,original));
        assertThrows(IllegalArgumentException.class,()->boundedTask(List.of(a),budget,original+99999));
        long retry=boundedTask(List.of(a),budget,original);
        assertThrows(IllegalArgumentException.class,()->boundedTask(List.of(a),budget,original));
        assertEquals(original,JsonUtils.read(jdbc.queryForObject("SELECT CAST(scope AS TEXT) FROM t_virus_scan_task WHERE id=?",String.class,retry)).path("retry_of").asLong());
        tx.executeWithoutResult(s->results.onResult(a,report(retry,false,RptVirusResult.Status.COMPLETE)));
        assertEquals(before,JsonUtils.write(query.taskEvidence(original)));
        assertEquals(2,jdbc.queryForObject("SELECT status FROM t_virus_scan_task WHERE id=?",Integer.class,retry));
    }
    @Test void retryCannotTargetPendingOrUnrelatedHostOrChangeEngine() {
        long original=task(List.of(a));var budget=VirusTaskService.ScanBudget.defaults();
        assertThrows(IllegalArgumentException.class,()->boundedTask(List.of(a),budget,original));
        tx.executeWithoutResult(s->results.onResult(a,report(original,false,RptVirusResult.Status.PARTIAL)));
        assertThrows(IllegalArgumentException.class,()->boundedTask(List.of(b),budget,original));
        assertThrows(IllegalArgumentException.class,()->tx.execute(s->tasks.createTask("bad",List.of(a),3,List.of("/tmp"),actor,"yara",budget,original)));
    }
    @Test void taskFiltersAndPaginationRetainExactTotalsAndActor() {
        long first=task(List.of(a));long second=task(List.of(b));long third=task(List.of(a,b));
        tx.executeWithoutResult(s->results.onResult(a,report(first,false,RptVirusResult.Status.COMPLETE)));
        var page=query.tasks(1,1,a,"builtin",1);
        assertEquals(1L,page.get("total"));assertEquals(third,((Number)((List<Map<String,Object>>)page.get("list")).get(0).get("id")).longValue());
        var all=query.tasks(2,1,a,"builtin",null);
        assertEquals(2L,all.get("total"));assertEquals(first,((Number)((List<Map<String,Object>>)all.get("list")).get(0).get("id")).longValue());
        assertNotNull(((List<Map<String,Object>>)all.get("list")).get(0).get("username"));
        assertEquals(0L,query.tasks(1,20,a+"' OR 1=1 --",null,null).get("total"));
        assertThrows(IllegalArgumentException.class,()->query.tasks(1,20,null,"bad",null));
        assertThrows(IllegalArgumentException.class,()->query.tasks(1,20,null,null,9));
    }
    @Test void sweepExpiresShortBudgetWithoutWaitingForTwoHoursAndKeepsOtherTaskPending() {
        long shortTask=boundedTask(List.of(a),new VirusTaskService.ScanBudget(60,100,1048576),null);
        long normal=task(List.of(b));
        var props=new AlinkSecProperties();props.getDatabase().setType("postgres".equals(System.getProperty("alinksec.integration.database"))?"postgres":"sqlite");
        var cutoff=new DatabaseDialect(props).timestampBefore(java.time.Duration.ofSeconds(400));
        for(long id:List.of(shortTask,normal))jdbc.update("UPDATE t_virus_scan_task SET created_at=? WHERE id=?",cutoff,id);
        tx.executeWithoutResult(s->tasks.sweepTimeout());
        assertEquals("timeout",query.taskEvidence(shortTask).get(0).get("state"));
        assertEquals(3,jdbc.queryForObject("SELECT status FROM t_virus_scan_task WHERE id=?",Integer.class,shortTask));
        assertEquals("pending",query.taskEvidence(normal).get(0).get("state"));
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
        var actionIds=(List<String>)outcome.get("actionIds");
        assertEquals(2,actionIds.size());
        assertTrue(query.actionReceipts(actionIds).stream().allMatch(row->"pending".equals(row.get("state"))));
        receipt(command,Map.of(ids.get(0),true,ids.get(1),false),TerminalState.FAILED);
        assertEquals(1,jdbc.queryForObject("SELECT status FROM t_virus_finding WHERE id=?",Integer.class,ids.get(0)));
        assertEquals(0,jdbc.queryForObject("SELECT status FROM t_virus_finding WHERE id=?",Integer.class,ids.get(1)));
        assertEquals("succeeded",query.actionHistory(ids.get(0)).get(0).get("state")); assertEquals("failed",query.actionHistory(ids.get(1)).get(0).get("state"));
        var receipts=query.actionReceipts(actionIds);
        assertEquals(Set.of("succeeded","failed"),new HashSet<>(receipts.stream().map(row->row.get("state")).toList()));
        for(var row:receipts) {
            assertEquals(actor,((Number)row.get("actor")).longValue());
            assertEquals(a,row.get("agent_id")); assertEquals("检测主机",row.get("hostname"));
            assertTrue(((com.fasterxml.jackson.databind.JsonNode)row.get("request_evidence")).path("path").asText().startsWith("/tmp/"));
        }
        var original=JsonUtils.write(receipts);
        tx.execute(s->actions.act(List.of(ids.get(0)),"whitelist",actor));
        assertEquals(original,JsonUtils.write(query.actionReceipts(actionIds)),"later actions must not replace this batch's receipts");
    }

    @Test void actionReceiptLookupIsBoundedAndWhitelistReceiptsDoNotClaimFileChanges() throws Exception {
        long task=task(List.of(a));tx.executeWithoutResult(s->results.onResult(a,report(task,true,RptVirusResult.Status.COMPLETE)));
        long id=finding(task);
        var outcome=tx.execute(s->actions.act(List.of(id),"whitelist",actor));
        var ids=(List<String>)outcome.get("actionIds");assertEquals(1,ids.size());
        assertEquals("committed",query.actionReceipts(ids).get(0).get("state"));
        assertNull(query.actionReceipts(ids).get(0).get("receipt"));
        assertEquals(0,jdbc.queryForObject("SELECT status FROM t_virus_finding WHERE id=?",Integer.class,id));
        for(var invalid:List.of(List.<String>of(),List.of(ids.get(0),ids.get(0)),List.of("' OR 1=1 --"),java.util.stream.IntStream.range(0,33).mapToObj(i->UUID.randomUUID().toString()).toList()))
            assertThrows(IllegalArgumentException.class,()->query.actionReceipts(invalid));
        assertTrue(query.actionReceipts(List.of(UUID.randomUUID().toString())).isEmpty());
        var controller=new com.alinksec.gateway.rest.VirusController(query,tasks,actions,mock(VirusDbService.class),mock(com.alinksec.service.download.AgentDownloadTokenService.class));
        var mvc=org.springframework.test.web.servlet.setup.MockMvcBuilders.standaloneSetup(controller).build();
        var response=mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get("/api/virus/findings/actions/receipts").param("ids",String.join(",",ids))).andReturn().getResponse();
        assertEquals(200,response.getStatus());assertEquals(ids.get(0),JsonUtils.read(response.getContentAsString()).path("data").get(0).path("id").asText());
    }

    @Test void taskFindingsFiltersKeepExactTotalsAndStablePaginationThroughMvc() throws Exception {
        long one=task(List.of(a,b)),two=task(List.of(a));
        tx.executeWithoutResult(s->{results.onResult(a,report(one,true,RptVirusResult.Status.COMPLETE));results.onResult(b,report(one,true,RptVirusResult.Status.COMPLETE));results.onResult(a,report(two,true,RptVirusResult.Status.COMPLETE));});
        assertEquals(2L,query.findings(null,null,one,1,1).get("total"));
        var first=(List<Map<String,Object>>)query.findings(null,null,one,1,1).get("list");
        var second=(List<Map<String,Object>>)query.findings(null,null,one,2,1).get("list");
        assertNotEquals(first.get(0).get("id"),second.get(0).get("id"));
        assertEquals(1L,query.findings(0,a,one,1,20).get("total"));
        assertEquals(0L,query.findings(null,a+"' OR 1=1 --",one,1,20).get("total"));
        assertTrue(((List<?>)query.findings(null,null,one,Integer.MAX_VALUE,100).get("list")).isEmpty());
        assertThrows(IllegalArgumentException.class,()->query.findings(null,null,0L,1,20));
        var controller=new com.alinksec.gateway.rest.VirusController(query,tasks,actions,mock(VirusDbService.class),mock(com.alinksec.service.download.AgentDownloadTokenService.class));
        var mvc=org.springframework.test.web.servlet.setup.MockMvcBuilders.standaloneSetup(controller).build();
        var response=mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get("/api/virus/findings").param("taskId",Long.toString(one)).param("agentId",a).param("page","1").param("size","20")).andReturn().getResponse();
        assertEquals(200,response.getStatus());assertEquals(1,JsonUtils.read(response.getContentAsString()).path("data").path("total").asInt());
    }

    @Test void dispositionConsoleUsesCommittedBatchIdsAndPerFileReceipts() throws Exception {
        long task=task(List.of(a));var report=report(task,true,RptVirusResult.Status.COMPLETE);
        tx.executeWithoutResult(s->results.onResult(a,report.toBuilder().setFilesScanned(2).setFilesSeen(2).addFindings(report.getFindings(0).toBuilder().setPath("/tmp/second.sh")).build()));
        var ids=jdbc.queryForList("SELECT id FROM t_virus_finding WHERE task_id=? ORDER BY id",Long.class,task);
        var stages=new LinkedHashMap<String,Object>();stages.put("active",snapshot(task,ids.get(0)));
        var batch=tx.execute(s->actions.act(ids,"quarantine",actor));var actionIds=(List<String>)batch.get("actionIds");
        stages.put("pending",Map.of("console",snapshot(task,ids.get(0)),"receipts",query.actionReceipts(actionIds)));
        String command=((List<String>)batch.get("commands")).get(0);receipt(command,Map.of(ids.get(0),true,ids.get(1),false),TerminalState.FAILED);
        stages.put("partial",Map.of("console",snapshot(task,ids.get(0)),"receipts",query.actionReceipts(actionIds)));
        var restore=tx.execute(s->actions.act(List.of(ids.get(0)),"restore",actor));receipt(((List<String>)restore.get("commands")).get(0),Map.of(ids.get(0),true),TerminalState.DONE);
        stages.put("restored",Map.of("console",snapshot(task,ids.get(0)),"receipts",query.actionReceipts((List<String>)restore.get("actionIds"))));
        var whitelist=tx.execute(s->actions.act(List.of(ids.get(1)),"whitelist",actor));
        stages.put("whitelisted",Map.of("console",snapshot(task,ids.get(0)),"receipts",query.actionReceipts((List<String>)whitelist.get("actionIds"))));
        String output=System.getProperty("alinksec.virus.disposition.fixture");
        if(output!=null) Files.writeString(Path.of(output),JsonUtils.write(Map.of("task",task,"findingIds",ids,"batch",batch,"restore",restore,"whitelist",whitelist,"stages",stages)));
        assertEquals(Set.of("succeeded","failed"),new HashSet<>(query.actionReceipts(actionIds).stream().map(row->row.get("state")).toList()));
    }
    @Test void reportFailureRollsBackDedupAndAuthenticatedHostScopesReplay() {
        var props=new AlinkSecProperties(); props.getDatabase().setType("postgres".equals(System.getProperty("alinksec.integration.database"))?"postgres":"sqlite");
        var dispatcher=new com.alinksec.service.report.ReportDispatcher(mock(com.alinksec.service.heartbeat.HeartbeatService.class),mock(com.alinksec.service.asset.AssetService.class),mock(com.alinksec.service.alert.SecurityEventService.class),mock(CommandService.class),mock(com.alinksec.service.baseline.BaselineResultService.class),mock(com.alinksec.service.scan.ScanResultService.class),results,mock(com.alinksec.service.fix.FixResultService.class),mock(com.alinksec.service.metrics.MetricsForwarder.class),mock(com.alinksec.service.log.LogBatchService.class),jdbc,new DatabaseDialect(props),new DataSourceTransactionManager(pool),mock(com.alinksec.service.fix.WindowsUpdateService.class),mock(com.alinksec.service.evidence.EvidenceService.class));
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
