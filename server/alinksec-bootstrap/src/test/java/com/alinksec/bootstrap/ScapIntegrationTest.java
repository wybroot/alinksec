package com.alinksec.bootstrap;

import com.alinksec.common.util.JsonUtils;
import com.alinksec.proto.*;
import com.alinksec.service.baseline.*;
import com.alinksec.service.command.CommandService;
import com.alinksec.service.command.CommandLifecycleListener;
import com.alinksec.service.config.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.aop.framework.ProxyFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.*;
import org.springframework.transaction.annotation.AnnotationTransactionAttributeSource;
import org.springframework.transaction.interceptor.TransactionInterceptor;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.sql.DriverManager;
import java.util.*;
import java.util.zip.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/** Real SQLite migration and transaction boundaries. Reports here are protocol
 * fixtures; native SCC evidence is required by the separate platform jobs. */
class ScapIntegrationTest {
    @TempDir Path root;
    SingleConnectionDataSource source;
    JdbcTemplate jdbc;
    DataSourceTransactionManager manager;
    ScapTaskService tasks;
    ScapPackageService packages;
    ScapCommandGuard guard;
    List<Command> sent;
    static final String PIN="a".repeat(64), BENCHMARK="xccdf_org.alinksec_benchmark_fixture", PROFILE="xccdf_org.alinksec_profile_fixture";
    static final List<String> OUTCOMES=List.of("pass","fail","error","unknown","notapplicable","notchecked","notselected","informational","fixed");
    @BeforeEach void setup() throws Exception {
        source=new SingleConnectionDataSource(DriverManager.getConnection("jdbc:sqlite:"+root.resolve("db.sqlite")),true);
        new SqliteDatabaseConfiguration.SqliteMigrationBeanPostProcessor().postProcessAfterInitialization(source,"dataSource");
        jdbc=new JdbcTemplate(source);manager=new DataSourceTransactionManager(source);
        var props=new AlinkSecProperties();props.getDatabase().setType("sqlite");
        var commands=mock(CommandService.class);sent=new ArrayList<>();
        doAnswer(invocation->{String id=UUID.randomUUID().toString();sent.add(((Command.Builder)invocation.getArgument(1)).setCmdId(id).build());return id;})
                .when(commands).dispatchAfterCommit(anyString(),any(Command.Builder.class),any());
        tasks=transactional(new ScapTaskService(jdbc,commands,new DatabaseDialect(props)));
        packages=transactional(new ScapPackageService(jdbc,tasks));guard=new ScapCommandGuard(jdbc);
        jdbc.update("INSERT INTO t_agent(agent_id,hostname,os_type,os_version,status,machine_id) VALUES('linux','Linux fixture',1,'ubuntu 24.04',1,'scap-fixture')");
        ready("ready",PIN);
    }
    @AfterEach void close(){source.destroy();}
    @SuppressWarnings("unchecked") <T>T transactional(T target){var proxy=new ProxyFactory(target);proxy.addAdvice(new TransactionInterceptor(manager,new AnnotationTransactionAttributeSource()));return(T)proxy.getProxy();}
    void ready(String state,String pin){
        ScapReadiness.heartbeat(jdbc,"linux",RptHeartbeat.newBuilder().setScapContract(1).setScapStatus(JsonUtils.write(Map.of("state",state,"version","5.15","runtime_sha256",pin,"observed_at",System.currentTimeMillis()/1000,"last_issue",""))).build());
    }
    byte[] content(String version)throws Exception{
        String xml="<Benchmark xmlns='http://checklists.nist.gov/xccdf/1.2' id='"+BENCHMARK+"'><Profile id='"+PROFILE+"'/>";
        for(String status:OUTCOMES)xml+="<Rule id='xccdf_org.alinksec_rule_"+status+"'><title>"+status+"</title></Rule>";
        xml+="</Benchmark>";
        String manifest=JsonUtils.write(Map.of("schemaVersion",1,"code","FIXTURE","version",version,"name","SCAP fixture","osType",1,"osVersionPattern","ubuntu.*","benchmarkFile","fixture.xml","benchmarkId",BENCHMARK,"profileId",PROFILE));
        try(var out=new ByteArrayOutputStream();var zip=new ZipOutputStream(out)){
            for(var file:Map.of("alinksec-scap.json",manifest,"fixture.xml",xml).entrySet()){zip.putNextEntry(new ZipEntry(file.getKey()));zip.write(file.getValue().getBytes(StandardCharsets.UTF_8));zip.closeEntry();}
            zip.finish();return out.toByteArray();
        }
    }
    Map<String,Object> decision(Map<String,Object> row,String action){return packages.decide(row.get("id").toString(),new ScapPackageService.Decision(((Number)row.get("revision")).intValue(),action,"Protocol boundary fixture",List.of("linux")),7L);}
    Map<String,Object> approved()throws Exception{return decision(packages.importContent(content("1"),7L),"approve");}
    RptScapResult.Builder report(String task){
        var command=sent.stream().filter(c->c.getScapScan().getTaskId().equals(task)).findFirst().orElseThrow();var scan=command.getScapScan();
        var report=RptScapResult.newBuilder().setTaskId(task).setCommandId(command.getCmdId()).setExecutionContract(1).setEngine("SCC").setEngineVersion("5.15").setRuntimeSha256(PIN)
                .setContentSha256(scan.getContentSha256()).setBenchmarkId(BENCHMARK).setProfileId(PROFILE).setState("complete").setSourceResultSha256("b".repeat(64));
        for(String status:OUTCOMES)report.addRules(ScapRuleResult.newBuilder().setRuleId("xccdf_org.alinksec_rule_"+status).setResult(status).setWeight(1));
        return report.addScores(ScapScore.newBuilder().setSystem("urn:xccdf:scoring:default").setValue(50).setMaximum(100));
    }
    void accept(String task,RptScapResult report){new org.springframework.transaction.support.TransactionTemplate(manager).executeWithoutResult(status->ScapResults.accept(jdbc,"linux",report));}

    @Test void immutableSnapshotsKeepNineOutcomesAndFirstActualResult()throws Exception{
        var tested=decision(approved(),"test");String task=tested.get("last_test_task").toString();
        byte[] frozen=tasks.content(task);assertArrayEquals(packages.content(tested.get("id").toString()),frozen);
        assertFalse(ScapTaskService.testReady(jdbc,task));
        var actual=report(task).build();accept(task,actual);
        var evidence=JsonUtils.read(new String(ScapResults.export(jdbc,task,"linux"),StandardCharsets.UTF_8));
        assertEquals(9,evidence.path("rules").size());for(String status:OUTCOMES)assertEquals(1,evidence.path("counts").path(status).asInt());
        assertFalse(ScapTaskService.testReady(jdbc,task));
        assertThrows(IllegalArgumentException.class,()->decision(packages.detail(tested.get("id").toString()),"publish"));
        byte[] original=ScapResults.export(jdbc,task,"linux");accept(task,actual.toBuilder().setState("failed").setIssue("scap_timeout").clearRules().clearScores().clearSourceResultSha256().build());assertArrayEquals(original,ScapResults.export(jdbc,task,"linux"));
        decision(packages.detail(tested.get("id").toString()),"withdraw");assertArrayEquals(frozen,tasks.content(task));
    }
    @Test void publishRequiresBoundCompleteTestAndQueuedCommandsRecheckPinnedEngine()throws Exception{
        var tested=decision(approved(),"test");String task=tested.get("last_test_task").toString();var report=report(task);
        for(int n=0;n<report.getRulesCount();n++)report.setRules(n,report.getRules(n).toBuilder().setResult(n==1?"fail":"pass"));
        var command=sent.get(0);assertEquals(command,guard.prepareDelivery("linux",command));
        ready("ready","c".repeat(64));assertThrows(IllegalArgumentException.class,()->guard.prepareDelivery("linux",command));ready("ready",PIN);
        assertThrows(IllegalArgumentException.class,()->accept(task,report.clone().setProfileId(PROFILE+"-other").build()));
        assertThrows(IllegalArgumentException.class,()->accept(task,report.clone().setRuntimeSha256("c".repeat(64)).build()));
        assertThrows(IllegalArgumentException.class,()->accept(task,report.clone().removeRules(0).build()));
        accept(task,report.build());assertTrue(ScapTaskService.testReady(jdbc,task));
        var published=decision(packages.detail(tested.get("id").toString()),"publish");
        String regular=tasks.create(published.get("id").toString(),List.of("linux"),"Regular fixture",8L,false);
        assertNotEquals(task,regular);assertEquals("running",tasks.detail(regular).get("state"));
        decision(published,"withdraw");assertThrows(IllegalArgumentException.class,()->tasks.create(published.get("id").toString(),List.of("linux"),"Invalid fixture",8L,false));
        assertNotNull(tasks.content(regular));
    }
    @Test void staleUnavailableAndCrossHostEvidenceCannotBecomePublishedResults()throws Exception{
        var approved=approved();ready("unavailable",PIN);assertThrows(IllegalArgumentException.class,()->decision(approved,"test"));
        ready("ready",PIN);jdbc.update("UPDATE t_scap_status SET observed_at=observed_at-100000");assertThrows(IllegalArgumentException.class,()->decision(approved,"test"));ready("ready",PIN);
        var tested=decision(approved,"test");String task=tested.get("last_test_task").toString();var report=report(task);
        assertThrows(IllegalArgumentException.class,()->ScapResults.accept(jdbc,"other",report.build()));
        guard.onTerminal("linux",sent.get(0).getCmdId(),CommandLifecycleListener.TerminalState.TIMEOUT,"");
        assertEquals("partial",tasks.detail(task).get("state"));assertThrows(IllegalArgumentException.class,()->ScapResults.export(jdbc,task,"linux"));
        accept(task,report.build());assertEquals("complete",tasks.detail(task).get("state"));
        jdbc.update("UPDATE t_scap_task SET snapshot='{}' WHERE id=?",task);assertThrows(IllegalArgumentException.class,()->tasks.detail(task));
    }
    @Test void conflictingImportAndStaleRevisionRollBackWithoutDispatch()throws Exception{
        byte[] bytes=content("1");var row=packages.importContent(bytes,7L);assertEquals(row.get("id"),packages.importContent(bytes,8L).get("id"));
        var approved=decision(row,"approve");assertThrows(IllegalArgumentException.class,()->decision(row,"reject"));
        assertEquals(2,jdbc.queryForObject("SELECT count(*) FROM t_scap_package_review",Integer.class));assertTrue(sent.isEmpty());
        assertThrows(IllegalArgumentException.class,()->packages.importContent(content("1").clone(),null));
        assertThrows(IllegalArgumentException.class,()->tasks.create(approved.get("id").toString(),List.of("linux","linux"),"Duplicate",7L,true));
        assertEquals(0,jdbc.queryForObject("SELECT count(*) FROM t_scap_task",Integer.class));assertTrue(sent.isEmpty());
    }
}
