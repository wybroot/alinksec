package com.alinksec.bootstrap;

import com.alinksec.common.util.JsonUtils;
import com.alinksec.proto.*;
import com.alinksec.service.command.*;
import com.alinksec.service.config.*;
import com.alinksec.service.download.AgentDownloadTokenService;
import com.alinksec.service.fix.*;
import com.alinksec.service.query.FixQueryService;
import com.zaxxer.hikari.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class WindowsUpdateIntegrationTest {
    @TempDir Path root;
    HikariDataSource pool;JdbcTemplate jdbc;TransactionTemplate tx;DatabaseDialect dialect;
    CommandService commands;WindowsUpdateService updates;FixTaskService fixes;FixResultService results;FixQueryService query;
    String agent,other,reviewerName;long creator,reviewer,viewer;AtomicBoolean online=new AtomicBoolean(true);
    BlockingQueue<Command> delivered=new LinkedBlockingQueue<>();
    Map<String,Object> stages=new LinkedHashMap<>();
    @BeforeEach void setup() {
        boolean pg="postgres".equals(System.getProperty("alinksec.integration.database"));
        var cfg=new HikariConfig();cfg.setJdbcUrl(pg?System.getenv("ALINKSEC_INTEGRATION_PG_URL"):"jdbc:sqlite:"+root.resolve("db"));
        if(pg){cfg.setUsername(System.getenv("ALINKSEC_INTEGRATION_PG_USER"));cfg.setPassword(System.getenv("ALINKSEC_INTEGRATION_PG_PASSWORD"));}
        else{cfg.addDataSourceProperty("transaction_mode","IMMEDIATE");cfg.addDataSourceProperty("busy_timeout",10000);cfg.addDataSourceProperty("foreign_keys",true);}
        cfg.setMaximumPoolSize(2);cfg.setMinimumIdle(1);pool=new HikariDataSource(cfg);
        if(!pg)new SqliteDatabaseConfiguration.SqliteMigrationBeanPostProcessor().postProcessAfterInitialization(pool,"dataSource");
        jdbc=new JdbcTemplate(pool);var manager=new DataSourceTransactionManager(pool);tx=new TransactionTemplate(manager);
        var props=new AlinkSecProperties();props.getDatabase().setType(pg?"postgres":"sqlite");dialect=new DatabaseDialect(props);
        String suffix=UUID.randomUUID().toString();agent="wu-a-"+suffix;other="wu-b-"+suffix;reviewerName="wu-reviewer-"+suffix;
        creator=account("wu-creator-"+suffix,1);reviewer=account(reviewerName,3);viewer=account("wu-viewer-"+suffix,2);
        for(String id:List.of(agent,other))jdbc.update("INSERT INTO t_agent(agent_id,hostname,ip,os_type,status,windows_update_contract) VALUES (?,?,?,2,1,1)",id,id.equals(agent)?"Windows 更新验收":"其他 Windows 主机","192.0.2.28");
        var sender=mock(CommandSender.class);when(sender.send(anyString(),any())).thenAnswer(call->{if(!online.get())return false;delivered.add(call.getArgument(1));return true;});
        var patches=mock(PatchRepoService.class);var listeners=new ArrayList<CommandLifecycleListener>();listeners.add(new PackageRepairCommandGuard(jdbc,patches,dialect));
        commands=new CommandService(new CommandRepository(jdbc,dialect),sender,new AgentDownloadTokenService(jdbc,dialect),props,listeners,manager);
        updates=new WindowsUpdateService(jdbc,commands,dialect);listeners.add(updates);
        fixes=new FixTaskService(jdbc,commands,patches,dialect,manager);results=new FixResultService(jdbc);query=new FixQueryService(jdbc);
    }
    @AfterEach void cleanup() throws Exception {
        if(commands!=null){commands.close();var worker=(ThreadPoolExecutor)org.springframework.test.util.ReflectionTestUtils.getField(commands,"deliveryWorker");assertTrue(worker.awaitTermination(10,TimeUnit.SECONDS));}
        if(jdbc!=null){for(String id:List.of(agent,other)){jdbc.update("DELETE FROM t_fix_record WHERE agent_id=?",id);jdbc.update("DELETE FROM t_command WHERE agent_id=?",id);jdbc.update("DELETE FROM t_vuln_finding WHERE agent_id=?",id);jdbc.update("DELETE FROM t_agent WHERE agent_id=?",id);}jdbc.update("DELETE FROM t_fix_task WHERE created_by=?",creator);jdbc.update("DELETE FROM t_user WHERE id IN (?,?,?)",creator,reviewer,viewer);}
        if(pool!=null)pool.close();
    }
    long account(String name,int role){return jdbc.queryForObject("INSERT INTO t_user(username,password_hash,role_id,status) VALUES (?,'unused',?,1) RETURNING id",Long.class,name,role);}
    Map<String,Object> update(int rev){return Map.of("update_id","12345678-1234-1234-1234-123456789abc","revision",rev,"title","Windows 安全更新验收 KB1234567","kb",List.of("1234567"),"size",1024,"eula_digest","b".repeat(64),"eligible",true,"reason","");}
    Map<String,Object> snapshot(int rev){return Map.of("contract",1,"status","complete","error","","host_identity","a".repeat(64),"reboot_required",false,"updates",List.of(update(rev)));}
    Command take() throws Exception {
        Command c=delivered.poll(10,TimeUnit.SECONDS);assertNotNull(c,"command not delivered");
        // sender is invoked immediately before the SENT transaction commits.
        long until=System.nanoTime()+TimeUnit.SECONDS.toNanos(5);
        while(jdbc.queryForObject("SELECT status FROM t_command WHERE cmd_id=?",Integer.class,c.getCmdId())==0 && System.nanoTime()<until)Thread.sleep(10);
        return c;
    }
    Command scan() throws Exception { tx.execute(s->updates.scan(List.of(agent),creator));return take(); }
    long discover() throws Exception {
        Command c=scan();tx.executeWithoutResult(s->updates.onSnapshot(agent,RptWindowsUpdate.newBuilder().setScanId(c.getWindowsUpdateScan().getScanId()).setSnapshot(JsonUtils.write(snapshot(7))).build()));
        return ((Number)updates.candidates(agent).get(0).get("id")).longValue();
    }
    long create(long candidate){return ((Number)tx.execute(s->updates.createTask(List.of(Map.of("agentId",agent,"candidateId",candidate)),reviewerName,null,null,creator)).get("taskId")).longValue();}
    FixResultItem result(String ref,String phase,boolean success,boolean verified,boolean reboot) {
        var evidence=Map.of("contract",1,"host_identity","a".repeat(64),"update_id","12345678-1234-1234-1234-123456789abc","revision",7,"phase",phase,"installed",success,"reboot_required",reboot,"result_code",0,"hresult",0);
        return FixResultItem.newBuilder().setRefId(ref).setSuccess(success).setVerified(verified).setRebootRequired(reboot).setLog("Windows 原生更新受控执行证据").setExecutionEvidence(JsonUtils.write(evidence)).build();
    }
    int state(long task){return jdbc.queryForObject("SELECT status FROM t_fix_record WHERE task_id=? AND agent_id=?",Integer.class,task,agent);}
    void capture(String stage) {
        var hosts=(List<Map<String,Object>>)updates.hosts(1,100).get("items");
        var tasks=(List<Map<String,Object>>)query.tasks(1,100).get("list");
        var selected=tasks.stream().filter(t->t.get("created_by") instanceof Number n && n.longValue()==creator).toList();
        var details=new LinkedHashMap<String,Object>();for(var t:selected)details.put(String.valueOf(t.get("id")),query.taskRecords(((Number)t.get("id")).longValue()));
        stages.put(stage,Map.of("hosts",Map.of("items",hosts.stream().filter(h->agent.equals(h.get("agent_id")) || other.equals(h.get("agent_id"))).toList(),"total",2),"candidates",updates.candidates(agent),"tasks",Map.of("list",selected,"total",selected.size()),"records",details));
    }
    @Test void discoveryAndExactApprovedInstallPreserveRebootAndCveBoundaries() throws Exception {
        long candidate=discover();capture("discovered");long task=create(candidate);capture("pending_approval");
        assertThrows(IllegalArgumentException.class,()->tx.execute(s->fixes.approve(task,creator)));
        assertThrows(IllegalArgumentException.class,()->tx.execute(s->fixes.approve(task,viewer)));
        tx.execute(s->fixes.approve(task,reviewer));Command install=take();assertEquals(FixItem.FixType.WINDOWS_UPDATE,install.getVulnFix().getFixes(0).getType());
        var pin=JsonUtils.read(install.getVulnFix().getFixes(0).getPayload());assertEquals(7,pin.path("update").path("revision").asInt());assertTrue(pin.path("dispatch_deadline_unix_ms").asLong()>System.currentTimeMillis());
        assertThrows(IllegalArgumentException.class,()->tx.execute(s->fixes.cancel(task,creator,"changed plan")));
        jdbc.update("INSERT INTO t_vuln_finding(task_id,agent_id,cve_id,software,installed_version,severity,status) VALUES (0,?,'CVE-2099-1234567','fixture','1',3,0)",agent);
        String ref=String.valueOf(candidate);var pending=RptFixResult.newBuilder().setTaskId(String.valueOf(task)).addResults(result(ref,"pending_reboot",true,false,true)).build();
        tx.executeWithoutResult(s->results.onResult(other,pending));assertEquals(0,state(task));
        tx.executeWithoutResult(s->results.onResult(agent,pending));assertEquals(6,state(task));assertEquals(5,jdbc.queryForObject("SELECT status FROM t_fix_task WHERE id=?",Integer.class,task));capture("pending_reboot");
        tx.executeWithoutResult(s->results.onResult(agent,pending));assertEquals(1,WindowsUpdateResult.receipts(jdbc,agent,pending).size());
        assertThrows(IllegalArgumentException.class,()->create(candidate));
        var verified=RptFixResult.newBuilder().setTaskId(String.valueOf(task)).addResults(result(ref,"verified",true,true,false)).build();
        tx.executeWithoutResult(s->results.onResult(agent,verified));assertEquals(1,state(task));assertEquals(2,jdbc.queryForObject("SELECT status FROM t_fix_task WHERE id=?",Integer.class,task));
        tx.executeWithoutResult(s->results.onResult(agent,pending));assertEquals(1,state(task));
        assertEquals(0,jdbc.queryForObject("SELECT status FROM t_vuln_finding WHERE agent_id=? AND cve_id='CVE-2099-1234567'",Integer.class,agent));capture("verified");
        String output=System.getenv("ALINKSEC_WINDOWS_UPDATE_BROWSER_FIXTURES");if(output!=null&&!output.isBlank()){Path dir=Path.of(output);Files.createDirectories(dir);Files.writeString(dir.resolve("workflow.json"),JsonUtils.write(Map.of("stages",stages,"agent",agent,"creator",creator,"reviewer",reviewer,"viewer",viewer,"reviewerName",reviewerName)));}
    }
    @Test void firstScanEvidenceOwnsTheTargetAndNewFailuresInvalidateOldCoverage() throws Exception {
        Command c=scan();String id=c.getWindowsUpdateScan().getScanId();
        tx.executeWithoutResult(s->updates.onSnapshot(other,RptWindowsUpdate.newBuilder().setScanId(id).setSnapshot(JsonUtils.write(snapshot(7))).build()));assertTrue(updates.candidates(agent).isEmpty());
        var duplicate=new LinkedHashMap<>(snapshot(7));duplicate.put("updates",List.of(update(7),update(7)));
        assertThrows(IllegalArgumentException.class,()->tx.executeWithoutResult(s->updates.onSnapshot(agent,RptWindowsUpdate.newBuilder().setScanId(id).setSnapshot(JsonUtils.write(duplicate)).build())));assertTrue(updates.candidates(agent).isEmpty());
        tx.executeWithoutResult(s->updates.onSnapshot(agent,RptWindowsUpdate.newBuilder().setScanId(id).setSnapshot(JsonUtils.write(snapshot(7))).build()));
        tx.executeWithoutResult(s->updates.onSnapshot(agent,RptWindowsUpdate.newBuilder().setScanId(id).setSnapshot(JsonUtils.write(snapshot(8))).build()));
        long candidate=((Number)updates.candidates(agent).get(0).get("id")).longValue();long task=create(candidate);
        Command next=scan();
        tx.executeWithoutResult(s->updates.onSnapshot(agent,RptWindowsUpdate.newBuilder().setScanId(next.getWindowsUpdateScan().getScanId()).setSnapshot(JsonUtils.write(Map.of("contract",1,"status","failed","error","wua_scan_failed"))).build()));
        assertTrue(updates.candidates(agent).isEmpty());assertThrows(IllegalArgumentException.class,()->tx.execute(s->fixes.approve(task,reviewer)));
    }
    @Test void offlineReplayRevalidatesCapabilityAndWindowWithoutSending() throws Exception {
        long candidate=discover();long task=create(candidate);online.set(false);tx.execute(s->fixes.approve(task,reviewer));
        // Wait until the single delivery worker has attempted the offline send.
        commands.close();var worker=(ThreadPoolExecutor)org.springframework.test.util.ReflectionTestUtils.getField(commands,"deliveryWorker");assertTrue(worker.awaitTermination(10,TimeUnit.SECONDS));
        jdbc.update("UPDATE t_agent SET windows_update_contract=0 WHERE agent_id=?",agent);online.set(true);commands.deliverPending(agent);
        assertTrue(delivered.isEmpty());assertEquals(5,state(task));
        assertThrows(IllegalArgumentException.class,()->tx.execute(s->updates.scan(List.of(agent),creator)));
    }
    @Test void unconfirmedInstallOnlyAdvancesAfterExactVerifiedEvidence() throws Exception {
        long candidate=discover();long task=create(candidate);tx.execute(s->fixes.approve(task,reviewer));take();
        String ref=String.valueOf(candidate);var uncertain=RptFixResult.newBuilder().setTaskId(String.valueOf(task)).addResults(result(ref,"uncertain",false,false,false)).build();
        tx.executeWithoutResult(s->results.onResult(agent,uncertain));assertEquals(7,state(task));
        var wrong=JsonUtils.read(result(ref,"verified",true,true,false).getExecutionEvidence(),Map.class);wrong.put("revision",8);
        var bad=RptFixResult.newBuilder().setTaskId(String.valueOf(task)).addResults(result(ref,"verified",true,true,false).toBuilder().setExecutionEvidence(JsonUtils.write(wrong))).build();
        assertThrows(IllegalArgumentException.class,()->tx.executeWithoutResult(s->results.onResult(agent,bad)));assertEquals(7,state(task));
        tx.executeWithoutResult(s->results.onResult(agent,RptFixResult.newBuilder().setTaskId(String.valueOf(task)).addResults(result(ref,"verified",true,true,false)).build()));assertEquals(1,state(task));
    }
    @Test void manualClosureRequiresOwnerAndDoesNotClaimInstallationOrReopenOnReplay() throws Exception {
        long candidate=discover();long task=create(candidate);tx.execute(s->fixes.approve(task,reviewer));take();
        var r=RptFixResult.newBuilder().setTaskId(String.valueOf(task)).addResults(result(String.valueOf(candidate),"uncertain",false,false,false)).build();
        tx.executeWithoutResult(s->results.onResult(agent,r));assertEquals(7,state(task));
        assertThrows(IllegalArgumentException.class,()->tx.executeWithoutResult(s->updates.endReview(task,viewer,"已人工检查主机",true)));
        assertThrows(IllegalArgumentException.class,()->tx.executeWithoutResult(s->updates.endReview(task,creator,"已人工检查主机",false)));
        tx.executeWithoutResult(s->updates.endReview(task,creator,"人工检查确认目标已被其他更新取代",true));assertEquals(8,state(task));
        assertEquals(List.of(task+"-"+candidate+"-closed"),WindowsUpdateResult.receipts(jdbc,agent,r));
        tx.executeWithoutResult(s->results.onResult(agent,RptFixResult.newBuilder().setTaskId(String.valueOf(task)).addResults(result(String.valueOf(candidate),"verified",true,true,false)).build()));
        assertEquals(8,state(task));assertEquals(3,jdbc.queryForObject("SELECT status FROM t_fix_task WHERE id=?",Integer.class,task));
    }
    @Test void maintenanceWindowAndUndeliveredCancellationNeverInstall() throws Exception {
        long candidate=discover();
        var created=tx.execute(s->updates.createTask(List.of(Map.of("agentId",agent,"candidateId",candidate)),reviewerName,OffsetDateTime.now().plusMinutes(2).toString(),OffsetDateTime.now().plusMinutes(5).toString(),creator));
        long task=((Number)created.get("taskId")).longValue();
        assertEquals("waiting_window",tx.execute(s->fixes.approve(task,reviewer)).get("state"));assertTrue(delivered.isEmpty());
        tx.execute(s->fixes.cancel(task,creator,"维护计划变更"));assertEquals(4,jdbc.queryForObject("SELECT status FROM t_fix_task WHERE id=?",Integer.class,task));
        long next=create(candidate);jdbc.update("UPDATE t_fix_task SET window_start=?,window_end=? WHERE id=?",dialect.timestamp(Instant.now().minusSeconds(120)),dialect.timestamp(Instant.now().minusSeconds(60)),next);
        assertThrows(IllegalArgumentException.class,()->tx.execute(s->fixes.approve(next,reviewer)));
        fixes.dispatchWindowReached();assertTrue(delivered.isEmpty());assertEquals(5,state(next));
    }
    @Test void sentTimeoutCanRecordLateVerificationAndTamperedCommandsCannotDeliver() throws Exception {
        long candidate=discover();long task=create(candidate);tx.execute(s->fixes.approve(task,reviewer));Command c=take();
        var guard=new PackageRepairCommandGuard(jdbc,mock(PatchRepoService.class),dialect);
        var bad=c.toBuilder().setVulnFix(c.getVulnFix().toBuilder().setFixes(0,c.getVulnFix().getFixes(0).toBuilder().setType(FixItem.FixType.CONFIG))).build();
        assertThrows(IllegalArgumentException.class,()->tx.execute(s->guard.prepareDelivery(agent,bad)));
        jdbc.update("UPDATE t_fix_task SET started_at=? WHERE id=?",dialect.timestamp(Instant.now().minusSeconds(1900)),task);fixes.sweepTimeout();assertEquals(5,state(task));
        tx.executeWithoutResult(s->results.onResult(agent,RptFixResult.newBuilder().setTaskId(String.valueOf(task)).addResults(result(String.valueOf(candidate),"verified",true,true,false)).build()));
        assertEquals(1,state(task));assertEquals(2,jdbc.queryForObject("SELECT status FROM t_fix_task WHERE id=?",Integer.class,task));
    }
}
