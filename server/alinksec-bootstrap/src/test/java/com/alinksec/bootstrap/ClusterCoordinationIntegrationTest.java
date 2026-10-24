package com.alinksec.bootstrap;

import com.alinksec.common.util.JsonUtils;
import com.alinksec.proto.*;
import com.alinksec.service.cluster.*;
import com.alinksec.service.cert.CertService;
import com.alinksec.service.config.*;
import com.alinksec.service.library.LibraryProperties;
import com.alinksec.service.baseline.BaselineUpstreamProperties;
import com.alinksec.service.report.ReportDispatcher;
import com.alinksec.service.log.LogBatchService;
import com.alinksec.service.command.CommandService;
import com.alinksec.service.asset.AssetService;
import com.alinksec.service.alert.SecurityEventService;
import com.alinksec.service.scan.VulnMatchService;
import com.alinksec.service.notify.NotifyService;
import com.zaxxer.hikari.*;
import com.rabbitmq.client.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.test.util.ReflectionTestUtils;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/** Real restricted PostgreSQL, authenticated Redis and durable RabbitMQ; run in the isolated cluster CI job. */
@EnabledIfEnvironmentVariable(named="ALINKSEC_CLUSTER_TEST_REQUIRED",matches="true")
class ClusterCoordinationIntegrationTest {
    @TempDir Path root;
    HikariDataSource pool;JdbcTemplate jdbc;DataSourceTransactionManager manager;
    AlinkSecProperties app;LibraryProperties libraries;CertService certificates;MockEnvironment environment;
    DatabaseDialect dialect;String deployment,agent,token;Long actor;
    Node a,b;final List<Node> nodes=new ArrayList<>();
    record Node(ClusterProperties properties,RedisLeases redis,RabbitTransport rabbit,ClusterRuntime runtime,
                ClusterSessions sessions,ClusterWork work,ClusterSlots slots){}
    @BeforeEach void setup() throws Exception {
        var config=new HikariConfig();config.setJdbcUrl(required("ALINKSEC_INTEGRATION_PG_URL"));
        config.setUsername(required("ALINKSEC_INTEGRATION_PG_USER"));config.setPassword(required("ALINKSEC_INTEGRATION_PG_PASSWORD"));
        config.setMaximumPoolSize(8);config.setMinimumIdle(1);config.setConnectionTimeout(3000);
        pool=new HikariDataSource(config);jdbc=new JdbcTemplate(pool);jdbc.setQueryTimeout(8);manager=new DataSourceTransactionManager(pool);
        for(String table:List.of("t_cluster_session","t_cluster_ingress","t_cluster_work","t_cluster_job_slot","t_cluster_node"))jdbc.update("DELETE FROM "+table);
        jdbc.update("UPDATE t_cluster_state SET deployment_id='',configuration_sha256='',next_sequence=0 WHERE id=1");
        deployment=UUID.randomUUID().toString();Files.writeString(root.resolve(".cluster-deployment-id"),deployment);
        app=new AlinkSecProperties();app.getServer().setCertDir(root.resolve("certs").toString());app.getServer().setWebTlsDir(root.resolve("web-tls").toString());
        app.getSignature().setStorageDir(root.resolve("signature").toString());app.getPatch().setStorageDir(root.resolve("patch").toString());app.getUpgrade().setStorageDir(root.resolve("upgrade").toString());
        libraries=new LibraryProperties();libraries.setWorkDir(root.resolve("libraries").toString());
        certificates=new CertService(app);ReflectionTestUtils.invokeMethod(certificates,"init");Files.writeString(root.resolve("jwt.secret"),"cluster-integration-secret-".repeat(2));
        Files.setPosixFilePermissions(root.resolve("jwt.secret"),java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));
        environment=new MockEnvironment().withProperty("spring.datasource.url",config.getJdbcUrl()).withProperty("spring.datasource.username",config.getUsername());
        dialect=new DatabaseDialect(app);a=node("node-a");b=node("node-b");
        agent=UUID.randomUUID().toString();jdbc.update("INSERT INTO t_agent(agent_id,hostname,os_type,status) VALUES(?,'Cluster fixture',1,1)",agent);
        actor=jdbc.queryForObject("INSERT INTO t_user(username,password_hash,role_id,status) VALUES(?,'unused',1,1) RETURNING id",Long.class,"cluster-"+UUID.randomUUID());
        token=a.sessions.claim(agent);
    }
    private static String required(String name){String value=System.getenv(name);assertNotNull(value,name);assertFalse(value.isBlank(),name);return value;}
    Node node(String id) {
        var properties=new ClusterProperties(dialect==null?new DatabaseDialect(app):dialect);
        properties.setEnabled(true);properties.setDeploymentId(deployment);properties.setNodeId(id);properties.setSharedDir(root.toString());
        properties.setRedisUri(required("ALINKSEC_CLUSTER_TEST_REDIS_URI"));properties.setRabbitUri(required("ALINKSEC_CLUSTER_TEST_RABBIT_URI"));properties.validate();
        var redis=new RedisLeases(properties);var rabbit=new RabbitTransport(properties);
        var runtime=new ClusterRuntime(properties,jdbc,manager,pool,certificates,app,libraries,new BaselineUpstreamProperties(),environment,redis,rabbit);
        var sessions=new ClusterSessions(properties,new AgentFence(properties,pool),redis,runtime);
        var result=new Node(properties,redis,rabbit,runtime,sessions,new ClusterWork(properties,runtime,jdbc,manager),new ClusterSlots(properties,runtime,jdbc,manager));
        nodes.add(result);runtime.initialize();return result;
    }
    @AfterEach void close() throws Exception {
        for(var node:nodes){node.runtime.close();node.rabbit.close();node.redis.close();}
        if(a!=null){var factory=new ConnectionFactory();factory.setUri(a.properties.getRabbitUri());try(var connection=factory.newConnection();var channel=connection.createChannel()){channel.queueDelete(a.rabbit.queueName());}}
        if(jdbc!=null && agent!=null){jdbc.update("DELETE FROM t_agent_log WHERE agent_id=?",agent);jdbc.update("DELETE FROM t_asset_port WHERE agent_id=?",agent);jdbc.update("DELETE FROM t_alert_notify_delivery WHERE alert_no LIKE 'cluster-%'");jdbc.update("DELETE FROM t_alert WHERE agent_id=?",agent);jdbc.update("DELETE FROM t_notify_channel WHERE name LIKE 'cluster-%'");jdbc.update("DELETE FROM t_agent WHERE agent_id=?",agent);if(actor!=null)jdbc.update("DELETE FROM t_user WHERE id=?",actor);}
        if(pool!=null)pool.close();
    }
    Report logs(String id,String text){return Report.newBuilder().setAgentId(agent).setReportId(id).setLogBatch(RptLogBatch.newBuilder().setSource("cluster").addLines(LogLine.newBuilder().setContent(text).setTs(System.currentTimeMillis()))).build();}
    Report ports(String id,int port){return Report.newBuilder().setAgentId(agent).setReportId(id).setAsset(RptAssetSnapshot.newBuilder().addCollected("ports").addPorts(PortInfo.newBuilder().setPort(port).setProtocol("tcp"))).build();}
    ReportDispatcher dispatcher(LogBatchService logs) {
        var assets=new AssetService(jdbc,new VulnMatchService(jdbc,manager),mock(SecurityEventService.class));
        return new ReportDispatcher(mock(com.alinksec.service.heartbeat.HeartbeatService.class),assets,mock(SecurityEventService.class),mock(CommandService.class),mock(com.alinksec.service.baseline.BaselineResultService.class),mock(com.alinksec.service.scan.ScanResultService.class),mock(com.alinksec.service.virus.VirusResultService.class),mock(com.alinksec.service.fix.FixResultService.class),mock(com.alinksec.service.metrics.MetricsForwarder.class),logs,jdbc,dialect,manager,mock(com.alinksec.service.fix.WindowsUpdateService.class),mock(com.alinksec.service.evidence.EvidenceService.class));
    }
    ClusterReportIngress ingress(Node node){return ingress(node,new LogBatchService(jdbc,dialect));}
    ClusterReportIngress ingress(Node node,LogBatchService logs){return new ClusterReportIngress(node.properties,jdbc,manager,node.rabbit,dispatcher(logs),node.runtime);}
    void admit(ClusterReportIngress ingress,Report report){assertTrue(a.sessions.current(agent,token,()->ingress.admit(agent,report)));}
    String hint(String report){return jdbc.queryForObject("SELECT id FROM t_cluster_ingress WHERE agent_id=? AND report_id=?",String.class,agent,report);}
    Map<String,Object> row(String report){return jdbc.queryForMap("SELECT * FROM t_cluster_ingress WHERE id=?",hint(report));}
    long logCount(){return jdbc.queryForObject("SELECT COUNT(*) FROM t_agent_log WHERE agent_id=?",Long.class,agent);}
    static void await(CountDownLatch latch){try{assertTrue(latch.await(5,TimeUnit.SECONDS));}catch(InterruptedException failure){Thread.currentThread().interrupt();throw new IllegalStateException(failure);}}

    @Test void duplicateNodeAndMismatchedMaterialFailBeforeReplacingLiveProbe()throws Exception {
        String before=Files.readString(root.resolve(".cluster-probes/node-a"));
        assertEquals("cluster_node_id_in_use",assertThrows(ClusterUnavailable.class,()->node("node-a")).getMessage());
        assertEquals(before,Files.readString(root.resolve(".cluster-probes/node-a")));assertTrue(a.runtime.ready());
        environment.withProperty("ALINKSEC_JWT_SECRET","different-secret-".repeat(4));
        assertEquals("cluster_configuration_mismatch",assertThrows(ClusterUnavailable.class,()->node("node-c")).getMessage());
        environment.setProperty("ALINKSEC_JWT_SECRET","");
        Path probe=root.resolve(".cluster-probes/node-a");Files.move(probe,probe.resolveSibling("saved"));
        try{assertEquals("cluster_shared_storage_mismatch",assertThrows(ClusterUnavailable.class,()->node("node-d")).getMessage());}
        finally{Files.move(probe.resolveSibling("saved"),probe);}
        assertEquals(0,jdbc.queryForObject("SELECT COUNT(*) FROM t_cluster_node WHERE node_id IN ('node-c','node-d')",Integer.class));
    }
    @Test void replacementFencesOldStreamAndOldReleaseCannotDeleteNewLease() {
        String replacement=b.sessions.claim(agent);AtomicInteger applied=new AtomicInteger();
        assertThrows(ClusterUnavailable.class,()->a.sessions.current(agent,token,()->{return applied.incrementAndGet();}));
        a.sessions.release(agent,token);assertTrue(b.redis.current(agent,replacement));
        assertEquals(1,b.sessions.current(agent,replacement,()->{return applied.incrementAndGet();}));assertEquals(1,applied.get());
    }
    @Test void inFlightCommitBoundaryRejectsReplacementUntilTheOwnerFinishes()throws Exception {
        var entered=new CountDownLatch(1);var finish=new CountDownLatch(1);var executor=Executors.newSingleThreadExecutor();
        try {
            var current=executor.submit(()->a.sessions.current(agent,token,()->{entered.countDown();await(finish);return true;}));await(entered);
            assertEquals("agent_fence_busy",assertThrows(ClusterUnavailable.class,()->b.sessions.claim(agent)).getMessage());
            assertTrue(a.redis.current(agent,token));finish.countDown();assertTrue(current.get(5,TimeUnit.SECONDS));
            assertNotEquals(token,b.sessions.claim(agent));
        }finally{finish.countDown();executor.shutdownNow();}
    }
    @Test void replacedNodeIncarnationCannotContinueUsingAnOtherwiseCurrentAgentToken() {
        jdbc.update("UPDATE t_cluster_node SET incarnation=? WHERE node_id='node-a'",UUID.randomUUID().toString());
        AtomicInteger applied=new AtomicInteger();assertThrows(ClusterUnavailable.class,()->a.sessions.current(agent,token,()->{return applied.incrementAndGet();}));
        assertEquals(0,applied.get());a.runtime.heartbeat();assertFalse(a.runtime.ready());assertEquals("cluster_node_replaced",a.runtime.status().get("issue"));
    }
    @Test void sqlAdmissionPreservesPerAgentOrderAndDeduplicatesIdenticalReports() {
        var first=ingress(a);var second=ingress(b);
        for(int i=1;i<=3;i++)admit(first,ports("ordered-"+i,1000+i));
        admit(first,ports("ordered-1",1001));assertThrows(IllegalArgumentException.class,()->admit(first,ports("ordered-1",9999)));
        for(int i=1;i<=3;i++){
            second.processHint(hint("ordered-3"));
            assertEquals(1000+i,jdbc.queryForObject("SELECT port FROM t_asset_port WHERE agent_id=?",Integer.class,agent));
        }
        second.processHint(hint("ordered-1"));assertEquals(3,jdbc.queryForObject("SELECT COUNT(*) FROM t_cluster_ingress WHERE state='applied'",Integer.class));
        assertEquals(0,jdbc.queryForObject("SELECT COUNT(*) FROM t_cluster_ingress WHERE state='applied' AND content_b64<>''",Integer.class));
    }
    @Test void actualBrokerRedeliveryAfterCommitBeforeAckDoesNotApplyLogTwice()throws Exception {
        var receiver=ingress(b);admit(ingress(a),logs("ack-loss","one durable log"));String id=hint("ack-loss");a.rabbit.publish(id);
        var factory=new ConnectionFactory();factory.setUri(a.properties.getRabbitUri());
        try(var connection=factory.newConnection()){
            var channel=connection.createChannel();var message=channel.basicGet(a.rabbit.queueName(),false);assertNotNull(message);
            assertEquals(id,new String(message.getBody(),StandardCharsets.US_ASCII));receiver.processHint(id);assertEquals(1,logCount());
            channel.abort(); // Actual delivery remains unacknowledged after the SQL commit.
        }
        long until=System.nanoTime()+TimeUnit.SECONDS.toNanos(5);boolean received=false;
        while(!received && System.nanoTime()<until){received=b.rabbit.receive(0,receiver::processHint);if(!received)Thread.sleep(20);}
        assertTrue(received);assertEquals(1,logCount());assertEquals("applied",row("ack-loss").get("state"));
    }
    @Test void businessRollbackRetryAndPoisonQuarantineDoNotLoseOrPartiallyApplyFacts() {
        AtomicBoolean fail=new AtomicBoolean(true);
        var service=new LogBatchService(jdbc,dialect){@Override public void onBatch(String id,RptLogBatch batch){super.onBatch(id,batch);if(fail.getAndSet(false))throw new IllegalStateException("controlled failure after insert");}};
        var receiver=ingress(b,service);admit(ingress(a),logs("rollback","rollback then commit"));receiver.processHint(hint("rollback"));
        assertEquals(0,logCount());assertEquals("retry",row("rollback").get("state"));
        jdbc.update("UPDATE t_cluster_ingress SET next_attempt_at=0 WHERE id=?",hint("rollback"));receiver.processHint(hint("rollback"));assertEquals(1,logCount());
        admit(ingress(a),logs("poison","original content"));admit(ingress(a),logs("after-poison","following valid report"));
        jdbc.update("UPDATE t_cluster_ingress SET content_b64='AAAA' WHERE id=?",hint("poison"));
        for(int i=0;i<5;i++){jdbc.update("UPDATE t_cluster_ingress SET next_attempt_at=0 WHERE id=?",hint("poison"));receiver.processHint(hint("poison"));}
        assertEquals("dead",row("poison").get("state"));assertEquals("report_rejected",row("poison").get("error_code"));
        receiver.processHint(hint("after-poison"));assertEquals(2,logCount());
    }
    @Test void revokedHostCannotApplyQueuedFactsAndAdministratorRetriesBindMetadataAndCurrentRole() {
        var receiver=ingress(b);admit(ingress(a),logs("revoked","retained while disabled"));jdbc.update("UPDATE t_agent SET status=3 WHERE agent_id=?",agent);
        receiver.processHint(hint("revoked"));assertEquals(0,logCount());assertEquals("agent_revoked",row("revoked").get("error_code"));
        var console=new ClusterConsoleService(a.properties,a.runtime,a.rabbit,jdbc,manager);String hash=row("revoked").get("content_sha256").toString();
        assertThrows(IllegalArgumentException.class,()->console.retry(hint("revoked"),new ClusterConsoleService.Retry(hash,"host disabled"),actor));
        jdbc.update("UPDATE t_agent SET status=1 WHERE agent_id=?",agent);
        assertThrows(IllegalArgumentException.class,()->console.retry(hint("revoked"),new ClusterConsoleService.Retry("0".repeat(64),"stale review"),actor));
        jdbc.update("UPDATE t_user SET role_id=3 WHERE id=?",actor);assertThrows(IllegalArgumentException.class,()->console.status(actor));
        jdbc.update("UPDATE t_user SET role_id=1 WHERE id=?",actor);var captured=console.status(actor);
        assertFalse(JsonUtils.write(captured).contains("content_b64"));assertFalse(JsonUtils.write(captured).contains(a.properties.getRedisUri()));
        capture("dead",captured);console.retry(hint("revoked"),new ClusterConsoleService.Retry(hash,"host independently re-enabled"),actor);
        assertEquals(1,((Number)row("revoked").get("replay_count")).intValue());receiver.processHint(hint("revoked"));assertEquals(1,logCount());capture("healthy",console.status(actor));
    }
    @Test void pendingAndHistoryCapacitiesRejectAdmissionUntilRetainedFactsAreEligibleForCleanup() {
        a.properties.setMaxPendingReports(10);a.properties.setMaxHistoryReports(10);var receiver=ingress(a);
        for(int i=0;i<10;i++)admit(receiver,logs("quota-"+i,"bounded record"));
        assertThrows(ClusterUnavailable.class,()->admit(receiver,logs("over-quota","rejected")));
        for(int i=0;i<10;i++)receiver.processHint(hint("quota-"+i));
        assertThrows(ClusterUnavailable.class,()->admit(receiver,logs("retained","dedup window retained")));
        jdbc.update("UPDATE t_cluster_ingress SET finished_at=?",ClusterRuntime.databaseTime(jdbc)-600_001);receiver.cleanup();
        admit(receiver,logs("after-retention","space released"));assertEquals(1,jdbc.queryForObject("SELECT COUNT(*) FROM t_cluster_ingress",Integer.class));
    }
    @Test void oldLongWorkerCannotPublishAfterLeaseTakeoverAndLiveWorkerIsNotRecovered()throws Exception {
        var entered=new CountDownLatch(1);var resume=new CountDownLatch(1);var enteredB=new CountDownLatch(1);var resumeB=new CountDownLatch(1);
        var executor=Executors.newFixedThreadPool(2);
        try {
            var old=executor.submit(()->a.work.library(()->{entered.countDown();await(resume);ClusterWork.update(jdbc,"UPDATE t_cluster_state SET next_sequence=99 WHERE id=1");return true;},false));await(entered);
            assertFalse(b.work.library(()->true,false));
            jdbc.update("INSERT INTO t_security_feed_state(source_id,kind,status) VALUES('cluster-live','hashes','running') ON CONFLICT(source_id) DO UPDATE SET status='running'");
            var recoveryCatalog=mock(com.alinksec.service.library.LibraryCatalog.class);
            when(recoveryCatalog.selectionDelivery()).thenReturn(Map.of("signature_pending",0,"match_pending",0));
            var startup=new com.alinksec.service.library.LibrarySyncService(libraries,recoveryCatalog,mock(com.alinksec.service.virus.VirusDbService.class),mock(com.alinksec.service.library.FeedDownload.class),jdbc,mock(VulnMatchService.class),mock(com.alinksec.service.library.LibrarySchedule.class));
            ReflectionTestUtils.setField(startup,"clusterWork",b.work);
            try{startup.validate();startup.scheduled();assertEquals("running",jdbc.queryForObject("SELECT status FROM t_security_feed_state WHERE source_id='cluster-live'",String.class));}
            finally{startup.close();jdbc.update("DELETE FROM t_security_feed_state WHERE source_id='cluster-live'");}
            jdbc.update("UPDATE t_cluster_work SET lease_until=0 WHERE name='library-sync'");
            var replacement=executor.submit(()->b.work.library(()->{ClusterWork.update(jdbc,"UPDATE t_cluster_state SET next_sequence=42 WHERE id=1");enteredB.countDown();await(resumeB);return true;},false));await(enteredB);
            String current=jdbc.queryForObject("SELECT token FROM t_cluster_work WHERE name='library-sync'",String.class);resume.countDown();
            assertInstanceOf(ClusterUnavailable.class,assertThrows(ExecutionException.class,()->old.get(5,TimeUnit.SECONDS)).getCause());
            assertEquals(current,jdbc.queryForObject("SELECT token FROM t_cluster_work WHERE name='library-sync'",String.class));
            assertEquals(42,jdbc.queryForObject("SELECT next_sequence FROM t_cluster_state WHERE id=1",Integer.class));resumeB.countDown();assertTrue(replacement.get(5,TimeUnit.SECONDS));
            jdbc.update("INSERT INTO t_security_feed_state(source_id,kind,status) VALUES('cluster-live','hashes','running')");
            var survivor=new com.alinksec.service.library.LibrarySyncService(libraries,recoveryCatalog,mock(com.alinksec.service.virus.VirusDbService.class),mock(com.alinksec.service.library.FeedDownload.class),jdbc,mock(VulnMatchService.class),mock(com.alinksec.service.library.LibrarySchedule.class));
            ReflectionTestUtils.setField(survivor,"clusterWork",b.work);
            try{survivor.scheduled();assertEquals("failed",jdbc.queryForObject("SELECT status FROM t_security_feed_state WHERE source_id='cluster-live'",String.class));}
            finally{survivor.close();jdbc.update("DELETE FROM t_security_feed_state WHERE source_id='cluster-live'");}
        }finally{resume.countDown();resumeB.countDown();executor.shutdownNow();}
    }
    @Test void naturalSchedulerSlotCommitsOnceAcrossReplicasAndFailedWorkRollsBackAdmission()throws Exception {
        var executor=Executors.newFixedThreadPool(2);var begin=new CountDownLatch(1);
        try {
            List<Future<?>> futures=new ArrayList<>();
            for(Node node:List.of(a,b))futures.add(executor.submit(()->{await(begin);node.slots.once("fixture","same-slot",()->jdbc.update("UPDATE t_cluster_state SET next_sequence=next_sequence+1 WHERE id=1"));}));
            begin.countDown();for(var future:futures)future.get(5,TimeUnit.SECONDS);
            assertEquals(1,jdbc.queryForObject("SELECT next_sequence FROM t_cluster_state WHERE id=1",Integer.class));
            assertThrows(IllegalStateException.class,()->a.slots.once("fixture","rollback",()->{jdbc.update("UPDATE t_cluster_state SET next_sequence=99 WHERE id=1");throw new IllegalStateException();}));
            b.slots.once("fixture","rollback",()->jdbc.update("UPDATE t_cluster_state SET next_sequence=next_sequence+1 WHERE id=1"));
            assertEquals(2,jdbc.queryForObject("SELECT next_sequence FROM t_cluster_state WHERE id=1",Integer.class));
        }finally{executor.shutdownNow();}
    }
    @Test void webhookClaimPreventsConcurrentSendsAndRetriesKeepTheSameIdempotencyKey()throws Exception {
        var requests=new AtomicInteger();var response=new AtomicInteger(500);var keys=new CopyOnWriteArrayList<String>();
        var http=com.sun.net.httpserver.HttpServer.create(new java.net.InetSocketAddress("127.0.0.1",0),0);
        http.createContext("/hook",exchange->{try{exchange.getRequestBody().readAllBytes();keys.add(exchange.getRequestHeaders().getFirst("Idempotency-Key"));requests.incrementAndGet();exchange.sendResponseHeaders(response.get(),-1);}finally{exchange.close();}});http.start();
        var executor=Executors.newFixedThreadPool(2);
        try {
            String alert="cluster-"+UUID.randomUUID();
            jdbc.update("INSERT INTO t_alert(alert_no,agent_id,event_type,severity,title,detail) VALUES(?,?,'fixture',4,'Harmless alert','{}')",alert,agent);
            jdbc.update("INSERT INTO t_notify_channel(name,webhook_url) VALUES(?,?)",alert,"http://127.0.0.1:"+http.getAddress().getPort()+"/hook");
            var first=new NotifyService(jdbc);var second=new NotifyService(jdbc);
            ReflectionTestUtils.setField(first,"clusterProperties",a.properties);ReflectionTestUtils.setField(second,"clusterProperties",b.properties);
            var start=new CountDownLatch(1);List<Future<?>> futures=new ArrayList<>();
            for(var service:List.of(first,second))futures.add(executor.submit(()->{await(start);service.onAlert(alert,agent,"fixture",4,"Harmless alert","");}));
            start.countDown();for(var future:futures)future.get(10,TimeUnit.SECONDS);assertEquals(1,requests.get());
            jdbc.update("UPDATE t_alert_notify_delivery SET next_attempt_at=0 WHERE alert_no=?",alert);response.set(204);
            first.onAlert(alert,agent,"fixture",4,"Harmless alert","");second.onAlert(alert,agent,"fixture",4,"Harmless alert","");
            assertEquals(2,requests.get());assertEquals(1,new HashSet<>(keys).size());assertNotNull(keys.getFirst());
            assertEquals(2,jdbc.queryForObject("SELECT attempts FROM t_alert_notify_delivery WHERE alert_no=?",Integer.class,alert));
            assertNotNull(jdbc.queryForObject("SELECT delivered_at FROM t_alert_notify_delivery WHERE alert_no=?",Object.class,alert));
        }finally{executor.shutdownNow();http.stop(0);}
    }
    @Test void redisLoginFailureBudgetIsSharedByReplicasAndSuccessResetsIt() {
        var first=new ClusterLoginLimiter(a.properties,a.redis);var second=new ClusterLoginLimiter(b.properties,b.redis);String ip="198.51.100.42";
        for(int i=0;i<5;i++){assertTrue(second.apply(ip,"check"));assertTrue((i%2==0?first:second).apply(ip,"failure"));}
        assertFalse(first.apply(ip,"check"));assertFalse(second.apply(ip,"check"));first.apply(ip,"success");assertTrue(second.apply(ip,"check"));
    }
    void capture(String name,Map<String,Object> value) {
        String output=System.getenv("ALINKSEC_CLUSTER_FIXTURES");if(output==null)return;
        try{Path path=Path.of(output);Files.createDirectories(path);Files.writeString(path.resolve("console-"+name+".json"),JsonUtils.write(value));}
        catch(java.io.IOException failure){throw new java.io.UncheckedIOException(failure);}
    }
}
