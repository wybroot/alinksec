package com.alinksec.bootstrap;

import com.alinksec.common.util.JwtUtil;
import com.alinksec.gateway.rest.*;
import com.alinksec.proto.*;
import com.alinksec.service.config.*;
import com.alinksec.service.user.UserService;
import com.alinksec.service.asset.AssetService;
import com.alinksec.service.alert.SecurityEventService;
import com.alinksec.service.query.AlertQueryService;
import com.alinksec.service.notify.NotifyService;
import com.alinksec.service.report.ReportDispatcher;
import com.zaxxer.hikari.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.mock.web.*;
import java.nio.file.Path;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class ReviewDefectsIntegrationTest {
    @TempDir Path dir;
    HikariDataSource pool;JdbcTemplate jdbc;TransactionTemplate tx;DatabaseDialect dialect;UserService users;
    String agent,username;long admin,viewer;
    static final String SECRET="a-review-test-signing-secret-32-bytes", PASSWORD="Initial-test-password-123";
    @BeforeEach void setup() {
        boolean pg="postgres".equals(System.getProperty("alinksec.integration.database"));
        var config=new HikariConfig();config.setJdbcUrl(pg?System.getenv("ALINKSEC_INTEGRATION_PG_URL"):"jdbc:sqlite:"+dir.resolve("db"));
        if(pg){config.setUsername(System.getenv("ALINKSEC_INTEGRATION_PG_USER"));config.setPassword(System.getenv("ALINKSEC_INTEGRATION_PG_PASSWORD"));}
        else{config.addDataSourceProperty("transaction_mode","IMMEDIATE");config.addDataSourceProperty("busy_timeout",10000);config.addDataSourceProperty("foreign_keys",true);}
        config.setMaximumPoolSize(1);config.setMinimumIdle(1);pool=new HikariDataSource(config);
        if(!pg)new SqliteDatabaseConfiguration.SqliteMigrationBeanPostProcessor().postProcessAfterInitialization(pool,"dataSource");
        jdbc=new JdbcTemplate(pool);tx=new TransactionTemplate(new DataSourceTransactionManager(pool));
        var props=new AlinkSecProperties();props.getDatabase().setType(pg?"postgres":"sqlite");dialect=new DatabaseDialect(props);users=new UserService(jdbc,tx.getTransactionManager());
        username="review-"+UUID.randomUUID().toString().substring(0,8);agent=username;
        jdbc.update("INSERT INTO t_agent(agent_id,hostname,ip,os_type,status) VALUES(?,?,?,1,1)",agent,agent,"192.0.2.40");
        String hash=new org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder().encode(PASSWORD);
        for(String role:List.of("admin","viewer"))jdbc.update("INSERT INTO t_user(username,password_hash,role_id,status) VALUES(?,?,(SELECT id FROM t_role WHERE name=?),1)",username+role,hash,role);
        admin=jdbc.queryForObject("SELECT id FROM t_user WHERE username=?",Long.class,username+"admin");viewer=jdbc.queryForObject("SELECT id FROM t_user WHERE username=?",Long.class,username+"viewer");
    }
    @AfterEach void close(){if(jdbc!=null){jdbc.update("DELETE FROM t_alert WHERE agent_id=?",agent);jdbc.update("DELETE FROM t_agent WHERE agent_id=?",agent);jdbc.update("DELETE FROM t_user_session WHERE user_id IN(SELECT id FROM t_user WHERE username LIKE ?)",username+"%");jdbc.update("DELETE FROM t_user WHERE username LIKE ?",username+"%");}if(pool!=null)pool.close();}
    String token(String role){var p=users.login(username+role,PASSWORD,"127.0.0.1").orElseThrow();String sid=tx.execute(s->users.createSession(p,3600));return JwtUtil.sign(SECRET,Map.of("uid",p.id(),"username",p.username(),"role","admin","sid",sid),3600);}
    MockHttpServletResponse access(String token,String method,String path,UserService service)throws Exception{
        var holder=mock(JwtSecretHolder.class);when(holder.secret()).thenReturn(SECRET);
        var request=new MockHttpServletRequest(method,path);request.addHeader("Authorization","Bearer "+token);
        var response=new MockHttpServletResponse();new JwtAuthInterceptor(holder,service).preHandle(request,response,new Object());return response;
    }
    String sid(String token){return (String)JwtUtil.verify(SECRET,token).get("sid");}
    @Test void liveRoleLogoutDisableAndRestartRevokePrivileges()throws Exception {
        String view=token("viewer");assertEquals(403,access(view,"POST","/api/protect/rules",users).getStatus());
        assertEquals(403,access(view,"GET","/api/users",users).getStatus());
        users.logout(sid(view),viewer);assertEquals(401,access(view,"GET","/api/hosts",new UserService(jdbc,tx.getTransactionManager())).getStatus());
        String old=token("admin");jdbc.update("UPDATE t_user SET role_id=(SELECT id FROM t_role WHERE name='viewer') WHERE id=?",admin);
        assertEquals(401,access(old,"POST","/api/protect/rules",new UserService(jdbc,tx.getTransactionManager())).getStatus());
        String active=token("viewer");jdbc.update("UPDATE t_user SET status=0 WHERE id=?",viewer);assertEquals(401,access(active,"GET","/api/hosts",users).getStatus());
        assertEquals(401,access(JwtUtil.sign(SECRET,Map.of("uid",admin,"role","admin"),3600),"GET","/api/hosts",users).getStatus());
    }
    @Test void unsupportedDatabaseRoleCannotLoginCreateOrReuseASession()throws Exception{
        long role=jdbc.queryForObject("SELECT COALESCE(MAX(id),0)+1 FROM t_role",Long.class);
        String name="custom-"+UUID.randomUUID().toString().substring(0,8),session=UUID.randomUUID().toString();
        jdbc.update("INSERT INTO t_role(id,name,permissions) VALUES(?,?,'[]')",role,name);
        try {
            jdbc.update("UPDATE t_user SET role_id=? WHERE id=?",role,viewer);
            jdbc.update("INSERT INTO t_user_session(session_id,user_id,auth_version,role_name,expires_at) VALUES(?,?,0,?,?)",session,viewer,name,System.currentTimeMillis()/1000+3600);
            var profile=new UserService.UserProfile(viewer,username+"viewer",null,name,"[]",0);
            String token=JwtUtil.sign(SECRET,Map.of("uid",viewer,"sid",session,"role","admin"),3600);
            assertAll(()->assertTrue(users.login(username+"viewer",PASSWORD,"").isEmpty()),
                    ()->assertThrows(IllegalArgumentException.class,()->tx.execute(s->users.createSession(profile,3600))),
                    ()->assertThrows(IllegalArgumentException.class,()->users.authenticate(viewer,session)),
                    ()->assertEquals(401,access(token,"GET","/api/hosts",users).getStatus()));
        }finally{
            jdbc.update("UPDATE t_user SET role_id=(SELECT id FROM t_role WHERE name='viewer') WHERE id=?",viewer);
            jdbc.update("DELETE FROM t_role WHERE id=?",role);
        }
    }
    @Test void changePasswordRequiresOldPasswordAndRevokesAllSessions()throws Exception{
        String first=token("viewer"),second=token("viewer");assertThrows(IllegalArgumentException.class,()->tx.executeWithoutResult(s->users.changePassword(viewer,"wrong",PASSWORD+"new")));
        tx.executeWithoutResult(s->users.changePassword(viewer,PASSWORD,PASSWORD+"new"));
        assertTrue(users.login(username+"viewer",PASSWORD,"").isEmpty());assertTrue(users.login(username+"viewer",PASSWORD+"new","").isPresent());
        assertEquals(401,access(first,"GET","/api/hosts",new UserService(jdbc,tx.getTransactionManager())).getStatus());assertEquals(401,access(second,"GET","/api/hosts",users).getStatus());
        assertThrows(IllegalArgumentException.class,()->tx.executeWithoutResult(s->users.updateUser(admin,"viewer",0,null,admin)));
        tx.executeWithoutResult(s->users.updateUser(viewer,"operator",1,PASSWORD+"reset",admin));assertTrue(users.login(username+"viewer",PASSWORD+"reset","").isPresent());
    }
    @Test void auditWriteFailureDoesNotRollbackAccountChangesOrSessionRevocation(){
        String first=token("viewer");
        var failingSql=spy(jdbc);
        // Execute a real constraint violation as the application role, without
        // DDL permissions or mocks that conceal PostgreSQL's aborted transaction.
        doAnswer(i->jdbc.update("INSERT INTO t_audit_log(method,path,status) VALUES(NULL,?,200)",username))
                .when(failingSql).update(contains("INSERT INTO t_audit_log"),any(Object[].class));
        var failingAudit=new UserService(failingSql,tx.getTransactionManager());
        assertTrue(failingAudit.login(username+"viewer",PASSWORD,"127.0.0.1").isPresent());
        assertTrue(failingAudit.login(username+"viewer","wrong-password","127.0.0.1").isEmpty());
        String password=PASSWORD+"changed";
        assertDoesNotThrow(()->tx.executeWithoutResult(s->failingAudit.changePassword(viewer,PASSWORD,password)));
        boolean passwordChanged=new org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder().matches(password,jdbc.queryForObject("SELECT password_hash FROM t_user WHERE id=?",String.class,viewer));
        boolean passwordSessionsRevoked=jdbc.queryForObject("SELECT count(*) FROM t_user_session WHERE session_id=?",Integer.class,sid(first))==0;
        assertDoesNotThrow(()->tx.executeWithoutResult(s->failingAudit.createUser(username+"created","test",PASSWORD,"viewer",admin)));
        long created=jdbc.queryForObject("SELECT count(*) FROM t_user WHERE username=?",Long.class,username+"created");
        var profile=users.login(username+"viewer",passwordChanged?password:PASSWORD,"").orElseThrow();
        String second=tx.execute(s->users.createSession(profile,3600));
        assertDoesNotThrow(()->tx.executeWithoutResult(s->failingAudit.updateUser(viewer,"operator",0,null,admin)));
        var account=jdbc.queryForMap("SELECT u.status,r.name AS role FROM t_user u JOIN t_role r ON r.id=u.role_id WHERE u.id=?",viewer);
        assertAll(()->assertTrue(passwordChanged,"password change silently rolled back"),
                ()->assertTrue(passwordSessionsRevoked,"old password sessions survived"),
                ()->assertEquals(1L,created,"creation silently rolled back"),
                ()->assertEquals(0,((Number)account.get("status")).intValue()),
                ()->assertEquals("operator",account.get("role")),
                ()->assertEquals(0,jdbc.queryForObject("SELECT count(*) FROM t_user_session WHERE session_id=?",Integer.class,second)));
    }
    @Test void successfulAccountMutationsRetainAuditMetadata(){
        tx.executeWithoutResult(s->users.createUser(username+"created","test",PASSWORD,"viewer",admin));
        tx.executeWithoutResult(s->users.changePassword(viewer,PASSWORD,PASSWORD+"changed"));
        tx.executeWithoutResult(s->users.updateUser(viewer,"operator",0,null,admin));
        var actions=jdbc.queryForList("SELECT method FROM t_audit_log WHERE uid IN (?,?)",String.class,admin,viewer);
        assertEquals(Set.of("user_created","password_changed","user_updated"),new HashSet<>(actions));
        assertEquals(1,jdbc.queryForObject("SELECT count(*) FROM t_audit_log WHERE uid=? AND method='password_changed' AND path='/api/auth/password' AND body_digest IS NULL",Integer.class,viewer));
    }
    RptAssetSnapshot ports(long sequence,AssetCollection.Status state,int port){
        var b=RptAssetSnapshot.newBuilder().setSequence(sequence).addCollected("ports").addCollections(AssetCollection.newBuilder().setCategory("ports").setStatus(state).setCollectedAt(1000-sequence));
        if(port>0)b.addPorts(PortInfo.newBuilder().setPort(port).setProtocol("tcp"));return b.build();
    }
    @Test void assetSequenceSurvivesReorderingAndFailuresPreserveSuccessfulRows(){
        var assets=new AssetService(jdbc,mock(com.alinksec.service.scan.VulnMatchService.class),mock(SecurityEventService.class));
        tx.executeWithoutResult(s->assets.replaceSnapshot(agent,ports(2,AssetCollection.Status.COMPLETE,82)));
        tx.executeWithoutResult(s->assets.replaceSnapshot(agent,ports(1,AssetCollection.Status.COMPLETE,81)));
        assertEquals(82,jdbc.queryForObject("SELECT port FROM t_asset_port WHERE agent_id=?",Integer.class,agent));
        tx.executeWithoutResult(s->assets.replaceSnapshot(agent,ports(3,AssetCollection.Status.FAILED,0)));
        assertEquals(82,jdbc.queryForObject("SELECT port FROM t_asset_port WHERE agent_id=?",Integer.class,agent));assertEquals("failed",jdbc.queryForObject("SELECT status FROM t_asset_collection_state WHERE agent_id=? AND category='ports'",String.class,agent));
        tx.executeWithoutResult(s->assets.replaceSnapshot(agent,RptAssetSnapshot.newBuilder().setSequence(10).addCollected("processes").addCollections(AssetCollection.newBuilder().setCategory("processes").setStatus(AssetCollection.Status.COMPLETE)).build()));
        tx.executeWithoutResult(s->assets.replaceSnapshot(agent,ports(4,AssetCollection.Status.COMPLETE,0)));
        assertEquals(0,jdbc.queryForObject("SELECT count(*) FROM t_asset_port WHERE agent_id=?",Integer.class,agent));
        tx.executeWithoutResult(s->assets.replaceSnapshot(agent,ports(0,AssetCollection.Status.COMPLETE,80)));assertEquals(0,jdbc.queryForObject("SELECT count(*) FROM t_asset_port WHERE agent_id=?",Integer.class,agent));
    }
    ReportDispatcher dispatcher(SecurityEventService events){
        return new ReportDispatcher(mock(com.alinksec.service.heartbeat.HeartbeatService.class),mock(AssetService.class),events,mock(com.alinksec.service.command.CommandService.class),mock(com.alinksec.service.baseline.BaselineResultService.class),mock(com.alinksec.service.scan.ScanResultService.class),mock(com.alinksec.service.virus.VirusResultService.class),mock(com.alinksec.service.fix.FixResultService.class),mock(com.alinksec.service.metrics.MetricsForwarder.class),mock(com.alinksec.service.log.LogBatchService.class),jdbc,dialect,new DataSourceTransactionManager(pool),mock(com.alinksec.service.fix.WindowsUpdateService.class),mock(com.alinksec.service.evidence.EvidenceService.class));
    }
    @Test void failedReportAndDedupRollbackTogetherAndRetryExactlyOnce(){
        var events=spy(new SecurityEventService(jdbc,mock(NotifyService.class),dialect));
        doThrow(new IllegalStateException("injected write failure")).doCallRealMethod().when(events).onEvent(anyString(),any());
        var dispatcher=dispatcher(events);
        var report=Report.newBuilder().setAgentId(agent).setReportId(UUID.randomUUID().toString()).setReliable(true).setSecurityEvent(RptSecurityEvent.newBuilder().setRuleId("test").setRuleName("test").setType("process").setActionTaken("alert_only").setSeverity(Severity.SEV_HIGH)).build();
        assertThrows(IllegalStateException.class,()->dispatcher.dispatch(agent,report));assertEquals(0,jdbc.queryForObject("SELECT count(*) FROM t_alert WHERE agent_id=?",Integer.class,agent));
        dispatcher.dispatch(agent,report);dispatcher.dispatch(agent,report);
        assertEquals(1,jdbc.queryForObject("SELECT count(*) FROM t_alert WHERE agent_id=?",Integer.class,agent));assertEquals(1,jdbc.queryForObject("SELECT count FROM t_alert WHERE agent_id=?",Integer.class,agent));
    }
    @Test void offlineIncidentIsSingleMaintenanceSuppressedAndRecoveryClosesIt()throws Exception{
        var props=new AlinkSecProperties();props.getDatabase().setType(System.getProperty("alinksec.integration.database","sqlite"));
        var policy=mock(com.alinksec.service.protect.PolicyStoreService.class);when(policy.currentVersion()).thenReturn("");
        var heartbeats=new com.alinksec.service.heartbeat.HeartbeatService(new com.alinksec.service.agent.AgentRepository(jdbc,dialect),mock(com.alinksec.service.command.CommandService.class),props,policy,mock(com.alinksec.service.virus.VirusDbService.class),mock(com.alinksec.service.protect.WindowsLoginService.class),mock(com.alinksec.service.protect.FileWatchService.class),mock(com.alinksec.service.virus.ClamavService.class),mock(com.alinksec.service.virus.YaraService.class),jdbc);
        var field=heartbeats.getClass().getDeclaredField("securityEvents");field.setAccessible(true);field.set(heartbeats,new SecurityEventService(jdbc,mock(NotifyService.class),dialect));
        jdbc.update("UPDATE t_agent SET last_heartbeat=?,maintenance_until=? WHERE agent_id=?",dialect.timestampBefore(java.time.Duration.ofSeconds(120)),System.currentTimeMillis()/1000+3600,agent);
        tx.executeWithoutResult(s->heartbeats.markOfflineAgents());assertEquals(0,jdbc.queryForObject("SELECT count(*) FROM t_alert WHERE agent_id=?",Integer.class,agent));
        jdbc.update("UPDATE t_agent SET maintenance_until=0 WHERE agent_id=?",agent);
        tx.executeWithoutResult(s->heartbeats.markOfflineAgents());tx.executeWithoutResult(s->heartbeats.markOfflineAgents());assertEquals(1,jdbc.queryForObject("SELECT count(*) FROM t_alert WHERE agent_id=?",Integer.class,agent));
        tx.executeWithoutResult(s->heartbeats.onHeartbeat(agent,RptHeartbeat.newBuilder().build()));assertEquals(2,jdbc.queryForObject("SELECT status FROM t_alert WHERE agent_id=?",Integer.class,agent));
        jdbc.update("UPDATE t_agent SET status=4,last_heartbeat=? WHERE agent_id=?",dialect.timestampBefore(java.time.Duration.ofSeconds(120)),agent);
        tx.executeWithoutResult(s->heartbeats.markOfflineAgents());
        jdbc.update("UPDATE t_agent SET status=1,deleted=TRUE WHERE agent_id=?",agent);tx.executeWithoutResult(s->heartbeats.markOfflineAgents());
        jdbc.update("UPDATE t_agent SET status=0,deleted=FALSE,last_heartbeat=NULL WHERE agent_id=?",agent);tx.executeWithoutResult(s->heartbeats.markOfflineAgents());
        assertEquals(1,jdbc.queryForObject("SELECT count(*) FROM t_alert WHERE agent_id=?",Integer.class,agent));
    }
    @Test void healthyDatabaseSatisfiesRealReadinessProbe(){
        var readiness=new com.alinksec.service.cluster.BusinessReadiness(pool);try{assertTrue(readiness.ready());assertEquals(1,jdbc.queryForObject("SELECT count(*) FROM t_report_dedup WHERE report_id='business-readiness-probe'",Integer.class));
            if(dialect.isSqlite()){jdbc.execute("PRAGMA query_only=ON");assertFalse(readiness.ready());jdbc.execute("PRAGMA query_only=OFF");assertTrue(readiness.ready());}
        }finally{readiness.close();}
    }
    @Test void successfulActionAggregateIsIndependentOfAlertPageAndRetries(){
        long before=jdbc.queryForObject("SELECT count(*) FROM t_automatic_response WHERE received_at>=?",Long.class,System.currentTimeMillis()-java.time.Duration.ofDays(30).toMillis());
        var dispatcher=dispatcher(new SecurityEventService(jdbc,mock(NotifyService.class),dialect));
        var succeeded=new ArrayList<String>();
        for(int i=0;i<30;i++){
            String id=UUID.randomUUID().toString();String action=i%2==0?"killed":"alert_only";
            var report=Report.newBuilder().setAgentId(agent).setReportId(id).setReliable(true).setSecurityEvent(RptSecurityEvent.newBuilder().setRuleId("response-test").setRuleName("response-test").setType("process").setSeverity(Severity.SEV_HIGH).setActionTaken(action)).build();
            dispatcher.dispatch(agent,report);dispatcher.dispatch(agent,report);if(action.equals("killed"))succeeded.add(id);
        }
        for(String id:succeeded.subList(0,3))jdbc.update("UPDATE t_automatic_response SET received_at=? WHERE agent_id=? AND report_id=?",System.currentTimeMillis()-java.time.Duration.ofDays(45).toMillis(),agent,id);
        var summary=new com.alinksec.service.query.DashboardQueryService(jdbc,dialect).summary();
        long actual=((Number)((Map<?,?>)summary.get("alerts")).get("automated30d")).longValue();
        assertEquals(before+12L,actual);assertEquals(15,jdbc.queryForObject("SELECT count(*) FROM t_automatic_response WHERE agent_id=?",Integer.class,agent));
    }
    @Test void adminCreationAndStaleUpdatesHaveExplicitBoundaries(){
        assertThrows(IllegalArgumentException.class,()->tx.executeWithoutResult(s->users.createUser(username+"new","test",PASSWORD,"admin",viewer)));
        tx.executeWithoutResult(s->users.createUser(username+"new","test",PASSWORD,"viewer",admin));
        long id=jdbc.queryForObject("SELECT id FROM t_user WHERE username=?",Long.class,username+"new");
        tx.executeWithoutResult(s->users.updateUser(id,"operator",1,null,admin,0L));
        assertThrows(IllegalArgumentException.class,()->tx.executeWithoutResult(s->users.updateUser(id,"viewer",0,null,admin,0L)));
        assertFalse(users.users(1,100).toString().contains("password_hash"));
    }
    @Test void invalidSoftwareMetadataCannotClaimCompleteOrEraseRetainedInventory(){
        var matches=mock(com.alinksec.service.scan.VulnMatchService.class);
        var assets=new AssetService(jdbc,matches,mock(SecurityEventService.class));
        var metadata=SoftwareInventory.newBuilder().setStatus(SoftwareInventory.Status.COMPLETE)
                .setSource("dpkg").setDistroId("debian").setDistroVersion("12").setPackageRepairContract(2);
        var complete=RptAssetSnapshot.newBuilder().setSequence(1).addCollected("software")
                .addCollections(AssetCollection.newBuilder().setCategory("software").setStatus(AssetCollection.Status.COMPLETE))
                .setSoftwareInventory(metadata).addSoftware(SoftwareInfo.newBuilder().setName("openssl")
                        .setVersion("3.0.1-1").setSource("dpkg").setArchitecture("amd64")).build();
        tx.executeWithoutResult(s->assets.replaceSnapshot(agent,complete));
        long revision=jdbc.queryForObject("SELECT software_revision FROM t_agent WHERE agent_id=?",Long.class,agent);
        var invalid=complete.toBuilder().setSequence(2).setSoftwareInventory(metadata.clone().setSource("invalid-source")).build();
        tx.executeWithoutResult(s->assets.replaceSnapshot(agent,invalid));
        assertEquals("failed",jdbc.queryForObject("SELECT status FROM t_asset_collection_state WHERE agent_id=? AND category='software'",String.class,agent));
        assertEquals("invalid_software_inventory",jdbc.queryForObject("SELECT error FROM t_asset_collection_state WHERE agent_id=? AND category='software'",String.class,agent));
        var missing=complete.toBuilder().setSequence(3).clearSoftwareInventory().clearSoftware().build();
        tx.executeWithoutResult(s->assets.replaceSnapshot(agent,missing));
        assertEquals("failed",jdbc.queryForObject("SELECT software_collection_status FROM t_agent WHERE agent_id=?",String.class,agent));
        assertEquals("software_inventory_missing",jdbc.queryForObject("SELECT error FROM t_asset_collection_state WHERE agent_id=? AND category='software'",String.class,agent));
        assertEquals(1,jdbc.queryForObject("SELECT count(*) FROM t_asset_software WHERE agent_id=?",Integer.class,agent));
        assertEquals(revision,jdbc.queryForObject("SELECT software_revision FROM t_agent WHERE agent_id=?",Long.class,agent));
        verify(matches,times(3)).matchAgent(agent,0L);
        tx.executeWithoutResult(s->assets.replaceSnapshot(agent,complete.toBuilder().setSequence(4).clearSoftware().build()));
        assertEquals(0,jdbc.queryForObject("SELECT count(*) FROM t_asset_software WHERE agent_id=?",Integer.class,agent));
        assertEquals("complete",jdbc.queryForObject("SELECT status FROM t_asset_collection_state WHERE agent_id=? AND category='software'",String.class,agent));
    }
    @Test void partialContainerSourcesPreserveUnavailableSource(){
        var assets=new AssetService(jdbc,mock(com.alinksec.service.scan.VulnMatchService.class),mock(SecurityEventService.class));
        var complete=RptAssetSnapshot.newBuilder().setSequence(1).addCollected("containers").addCollections(AssetCollection.newBuilder().setCategory("containers").setStatus(AssetCollection.Status.COMPLETE)).addContainerSources("docker").addContainerSources("kubernetes").addContainers(ContainerInfo.newBuilder().setContainerId("d-old").setName("docker-old").setOrchestrator("docker")).addContainers(ContainerInfo.newBuilder().setContainerId("k-old").setName("kubernetes-old").setOrchestrator("kubernetes")).build();
        tx.executeWithoutResult(s->assets.replaceSnapshot(agent,complete));
        var partial=RptAssetSnapshot.newBuilder().setSequence(2).addCollected("containers").addCollections(AssetCollection.newBuilder().setCategory("containers").setStatus(AssetCollection.Status.PARTIAL).setError("orchestrator_unavailable")).addContainerSources("docker").addContainers(ContainerInfo.newBuilder().setContainerId("d-new").setName("docker-new").setOrchestrator("docker")).build();
        tx.executeWithoutResult(s->assets.replaceSnapshot(agent,partial));
        var ids=jdbc.queryForList("SELECT container_id FROM t_asset_container WHERE agent_id=?",String.class,agent);assertEquals(Set.of("k-old","d-new"),new HashSet<>(ids));
        var empty=partial.toBuilder().setSequence(3).clearContainers().build();tx.executeWithoutResult(s->assets.replaceSnapshot(agent,empty));assertEquals(List.of("k-old"),jdbc.queryForList("SELECT container_id FROM t_asset_container WHERE agent_id=?",String.class,agent));
        assertThrows(IllegalArgumentException.class,()->tx.executeWithoutResult(s->assets.replaceSnapshot(agent,RptAssetSnapshot.newBuilder().setSequence(4).build())));
    }
    @Test void onlyConfirmedAutomaticIsolationCountsOnce(){
        jdbc.update("UPDATE t_agent SET isolation_contract=1 WHERE agent_id=?",agent);
        var leases=new com.alinksec.service.protect.IsolationLeaseService(jdbc);
        var pulse=RptIsolationState.newBuilder().setLeaseId("a".repeat(32)).setGeneration(1).setRevision(1).setCommandId("local-"+"a".repeat(32)).setPhase("applying").setDeadline(System.currentTimeMillis()+10000).setAutomatic(true);
        tx.executeWithoutResult(s->leases.observe(agent,pulse.build()));assertEquals(0,jdbc.queryForObject("SELECT count(*) FROM t_automatic_response WHERE agent_id=?",Integer.class,agent));
        pulse.setPhase("active").setRevision(2).setNonce("b".repeat(32));tx.executeWithoutResult(s->leases.observe(agent,pulse.build()));assertEquals(0,jdbc.queryForObject("SELECT count(*) FROM t_automatic_response WHERE agent_id=?",Integer.class,agent));
        pulse.setConfirmed(true).setRevision(3);tx.executeWithoutResult(s->leases.observe(agent,pulse.build()));tx.executeWithoutResult(s->leases.observe(agent,pulse.build()));assertEquals(1,jdbc.queryForObject("SELECT count(*) FROM t_automatic_response WHERE agent_id=?",Integer.class,agent));
    }
    @Test void alertFiltersIncludeOlderOpenRowsAndInvalidOffsetsNeverQueryUnbounded(){
        for(int i=0;i<105;i++)jdbc.update("INSERT INTO t_alert(alert_no,agent_id,event_type,severity,severity_source,title,detail,status) VALUES(?,?,?,5,'agent_proto_v1','test','{}',?)",UUID.randomUUID().toString(),agent,"process",i==0?0:2);
        var query=new AlertQueryService(jdbc);var page=query.list(0,4,agent,null,1,100);assertEquals(1L,page.get("total"));
        assertThrows(IllegalArgumentException.class,()->query.list(null,null,agent,null,1,-1));assertThrows(IllegalArgumentException.class,()->query.list(null,null,agent,null,Integer.MAX_VALUE,100));
        assertEquals(5,((List<?>)query.list(null,null,agent,null,2,100).get("list")).size());
    }
}
