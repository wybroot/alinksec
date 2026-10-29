package com.alinksec.bootstrap;

import com.alinksec.proto.*;
import com.alinksec.service.query.*;
import com.alinksec.service.asset.AssetService;
import com.alinksec.service.alert.SecurityEventService;
import com.alinksec.service.scan.VulnMatchService;
import com.alinksec.service.baseline.BaselinePackageFormat;
import com.alinksec.common.util.JsonUtils;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class DefectRepairIntegrationTest {
 @TempDir Path root;
 LibraryGovernanceIntegrationTest f;
 String agent="defect-host";
 @BeforeEach void setup() throws Exception {
  f=new LibraryGovernanceIntegrationTest();f.root=root;f.setup();f.agents.add(agent);
  f.jdbc.update("INSERT INTO t_agent(agent_id,hostname,os_type,status,os_version) VALUES(?, 'Defect host',1,1,'ubuntu 24.04')",agent);
 }
 @AfterEach void close(){if(f!=null) f.close();}
 @SuppressWarnings("unchecked") List<Map<String,Object>> rows(Map<String,Object> page){return (List<Map<String,Object>>)page.get("list");}
 @Test void openAlertsBeyondFirstHundredAndSeparateAcknowledgement() {
  for(int i=0;i<103;i++) f.jdbc.update("INSERT INTO t_alert(alert_no,agent_id,event_type,severity,title,detail,status,last_time) VALUES(?,?,'process',3,'fixture','{}',?,?)","defect-"+i,agent,i<100?2:(i==101?1:0),i<100?"2026-10-29 12:00:00":"2026-10-28 12:00:00");
  var service=new AlertQueryService(f.jdbc);
  assertEquals(3L,service.list(-1,null,agent,null,1,20).get("total"));
  var first=rows(service.list(-1,null,agent,null,1,2));var second=rows(service.list(-1,null,agent,null,2,2));
  assertEquals(2,first.size());assertEquals(1,second.size());assertNotEquals(first.get(0).get("id"),second.get(0).get("id"));
  long id=((Number)first.get(0).get("id")).longValue();
  assertTrue(service.close(id,f.actor,"ignore","ignore"));
  assertEquals(3,f.jdbc.queryForObject("SELECT status FROM t_alert WHERE id=?",Integer.class,id));
  assertFalse(service.close(id,f.actor,"ack","acknowledge"));
  assertEquals(0,f.jdbc.queryForObject("SELECT count(*) FROM t_command",Integer.class));
  f.jdbc.update("DELETE FROM t_alert WHERE agent_id=?",agent);
 }
 @Test void failedDockerRetainsRowsWhileCompleteEmptyKubernetesClearsOnlyItsSource() {
  var service=new AssetService(f.jdbc,mock(VulnMatchService.class),mock(SecurityEventService.class));
  var initial=RptAssetSnapshot.newBuilder().setCollectionContract(1).addCollected("containers")
   .addCollectionAttempts(attempt("docker",AssetCollectionAttempt.Status.COMPLETE))
   .addCollectionAttempts(attempt("kubernetes",AssetCollectionAttempt.Status.COMPLETE))
   .addContainers(ContainerInfo.newBuilder().setContainerId("docker-1").setName("old docker").setOrchestrator("docker"))
   .addContainers(ContainerInfo.newBuilder().setContainerId("kube-1").setName("old pod").setOrchestrator("kubernetes")).build();
  service.replaceSnapshot(agent,initial);
  service.replaceSnapshot(agent,RptAssetSnapshot.newBuilder().setCollectionContract(1).addCollected("containers")
   .addCollectionAttempts(attempt("docker",AssetCollectionAttempt.Status.FAILED))
   .addCollectionAttempts(attempt("kubernetes",AssetCollectionAttempt.Status.COMPLETE)).build());
  assertEquals(List.of("docker"),f.jdbc.queryForList("SELECT orchestrator FROM t_asset_container WHERE agent_id=?",String.class,agent));
  assertEquals("failed",f.jdbc.queryForObject("SELECT status FROM t_asset_collection WHERE agent_id=? AND source='docker'",String.class,agent));
  assertNotNull(f.jdbc.queryForObject("SELECT succeeded_at FROM t_asset_collection WHERE agent_id=? AND source='docker'",String.class,agent));
  service.replaceSnapshot(agent,RptAssetSnapshot.newBuilder().setCollectionContract(1).addCollected("containers").build());
  assertEquals(1,f.jdbc.queryForObject("SELECT count(*) FROM t_asset_container WHERE agent_id=?",Integer.class,agent));
  service.replaceSnapshot(agent,RptAssetSnapshot.newBuilder().setCollectionContract(1).addCollected("containers").addCollectionAttempts(attempt("docker",AssetCollectionAttempt.Status.COMPLETE)).build());
  assertEquals(0,f.jdbc.queryForObject("SELECT count(*) FROM t_asset_container WHERE agent_id=?",Integer.class,agent));
 }
 AssetCollectionAttempt attempt(String source,AssetCollectionAttempt.Status status){return AssetCollectionAttempt.newBuilder().setSource(source).setStatus(status).setError(status==AssetCollectionAttempt.Status.COMPLETE?"":"fixture_failure").build();}
 @Test void groupsFilterCountAndMembershipAreConsistent() {
  var service=new HostQueryService(f.jdbc);
  long id=((Number)service.saveGroup(null,"Group A").get("id")).longValue();
  assertEquals(0L,service.list(null,null,null,1,20,id).get("total"));
  service.assignGroup(agent,id);
  assertEquals(1L,service.list(null,null,null,1,20,id).get("total"));
  assertEquals("Group A",rows(service.list(null,null,null,1,20,id)).get(0).get("group_name"));
  assertEquals(0L,service.list(null,null,null,1,20,0L).get("total"));
  service.saveGroup(id,"Renamed");service.deleteGroup(id);
  assertEquals(1L,service.list(null,null,null,1,20,0L).get("total"));
  assertThrows(IllegalArgumentException.class,()->service.assignGroup(agent,id));
 }
 @Test void groupsRemainConsistentAcrossPages() {
  var service=new HostQueryService(f.jdbc);
  long group=((Number)service.saveGroup(null,"Paged group").get("id")).longValue();
  for(int i=0;i<21;i++) {
   String id="paged-"+i; f.agents.add(id);
   f.jdbc.update("INSERT INTO t_agent(agent_id,hostname,os_type,status,group_id) VALUES(?,?,1,1,?)",id,id,group);
  }
  assertEquals(21L,service.list(null,null,null,1,20,group).get("total"));
  assertEquals(20,rows(service.list(null,null,null,1,20,group)).size());
  assertEquals(1,rows(service.list(null,null,null,2,20,group)).size());
  service.assignGroup("paged-20",0L);
  assertEquals(20L,service.list(null,null,null,2,20,group).get("total"));
  assertEquals(0,rows(service.list(null,null,null,2,20,group)).size());
  service.deleteGroup(group);
 }
 @Test void repairDefinitionIsBoundToAuditedTargetAndCheck() throws Exception {
  Path file=Path.of("deploy/baseline/account-permissions-package.json");
  try(var in=Files.newInputStream(file)){assertEquals(2,BaselinePackageFormat.read(in).document().path("items").size());}
  var check=JsonUtils.read("{\"type\":\"file_perm\",\"target\":\"/etc/passwd\",\"perm\":\"0644\"}");
  var fix=JsonUtils.read("{\"risk\":\"auto\",\"steps\":[{\"action\":\"chmod\",\"path\":\"/etc/shadow\",\"mode\":\"0644\"}]}");
  assertThrows(IllegalArgumentException.class,()->BaselinePackageFormat.validateFix(fix,check,1));
  assertThrows(IllegalArgumentException.class,()->BaselinePackageFormat.validateFix(fix,check,2));
 }
 @Test void reviewedPackagePersistsRepairDefinition() throws Exception {
  var service=new com.alinksec.service.baseline.BaselinePackageService(f.jdbc,mock(com.alinksec.service.baseline.BaselineTaskService.class));
  try(var in=Files.newInputStream(Path.of("deploy/baseline/account-permissions-package.json"))) {
   var imported=service.importPackage(in,f.actor);
   var reviewed=service.review((String)imported.get("id"),true,"Reviewed bounded file modes",f.actor);
   assertEquals(2,f.jdbc.queryForObject("SELECT count(*) FROM t_baseline_item WHERE template_id=? AND fix_spec IS NOT NULL",Integer.class,reviewed.get("template_id")));
  }
  // Fixture DB is discarded; remove actor references before shared fixture cleanup.
  f.jdbc.update("UPDATE t_baseline_package SET imported_by=NULL,reviewed_by=NULL");
 }
 @Test void upgradeBatchKeepsQueuedAndConfirmedOutcomesSeparate() {
  f.jdbc.update("UPDATE t_agent SET upgrade_contract=1,arch='amd64' WHERE agent_id=?",agent);
  long pkg=f.jdbc.queryForObject("INSERT INTO t_agent_upgrade_package(version,platform,package_key,sha256,size) VALUES('test','linux-amd64','test.bin',?,1) RETURNING id",Long.class,"a".repeat(64));
  var commands=mock(com.alinksec.service.command.CommandService.class);
  when(commands.dispatchAfterCommit(eq(agent),any(Command.Builder.class),eq(f.actor))).thenAnswer(invocation->{
   f.jdbc.update("INSERT INTO t_command(cmd_id,agent_id,type,payload,status) VALUES('upgrade-test',?,'agent_upgrade','{}',0)",agent);return "upgrade-test";
  });
  var tokens=mock(com.alinksec.service.download.AgentDownloadTokenService.class);
  when(tokens.issue(anyString(),anyString(),anyString())).thenReturn("fixture-token");
  var service=new com.alinksec.service.upgrade.UpgradeService(f.jdbc,commands,new com.alinksec.service.config.AlinkSecProperties(),tokens);
  String batch=(String)service.dispatch(pkg,List.of(agent),f.actor).get("batchId");
  assertEquals(1L,service.targets(pkg,1).get("total"));
  assertEquals("unverified",rows(service.batchTargets(batch,1)).get(0).get("confirmation"));
  var evidence=Map.of("version","test","sha256","a".repeat(64),"success",true,"complete",true,"message","health verified");
  f.jdbc.update("UPDATE t_command SET status=4,result=? WHERE cmd_id='upgrade-test'",JsonUtils.write(Map.of("code",0,"message",JsonUtils.write(evidence))));
  assertEquals("verified",rows(service.batchTargets(batch,1)).get(0).get("confirmation"));
  f.jdbc.update("UPDATE t_command SET result=? WHERE cmd_id='upgrade-test'",JsonUtils.write(Map.of("code",0,"message","legacy done")));
  assertEquals("unverified",rows(service.batchTargets(batch,1)).get(0).get("confirmation"));
 }

 @Test void alertResponsePinsEvidenceAndRejectsOfflineOrUnsupportedTargets() {
  long id=f.jdbc.queryForObject("INSERT INTO t_alert(alert_no,agent_id,event_type,severity,title,detail) VALUES('response-alert',?,'process',3,'original threat','{}') RETURNING id",Long.class,agent);
  var commands=mock(com.alinksec.service.command.CommandService.class);
  var service=new com.alinksec.service.alert.AlertResponseService(f.jdbc,commands);
  assertThrows(IllegalArgumentException.class,()->service.dispatch(id,"isolate",f.actor));
  f.jdbc.update("UPDATE t_agent SET isolation_contract=1,status=2 WHERE agent_id=?",agent);
  assertThrows(IllegalArgumentException.class,()->service.dispatch(id,"isolate",f.actor));
  verifyNoInteractions(commands);
  f.jdbc.update("UPDATE t_agent SET status=1 WHERE agent_id=?",agent);
  when(commands.dispatchAfterCommit(eq(agent),any(Command.Builder.class),eq(f.actor))).thenAnswer(invocation->{
   var command=(Command.Builder)invocation.getArgument(1);
   assertEquals(CmdProtectAction.Action.ISOLATE_HOST,command.getProtectAction().getAction());
   assertTrue(command.getProtectAction().getReason().contains("#"+id));
   f.jdbc.update("INSERT INTO t_command(cmd_id,agent_id,type,payload,status) VALUES('alert-response-command',?,'protect_action','{}',0)",agent);
   return "alert-response-command";
  });
  assertEquals("pending",service.dispatch(id,"isolate",f.actor).get("state"));
  assertEquals(0,f.jdbc.queryForObject("SELECT status FROM t_alert WHERE id=?",Integer.class,id));
  f.jdbc.update("UPDATE t_alert SET title='changed later' WHERE id=?",id);
  var response=rows(service.list(id,1)).getFirst();
  assertTrue(response.get("evidence").toString().contains("original threat"));
  assertEquals(0,((Number)response.get("command_status")).intValue());
  assertThrows(IllegalArgumentException.class,()->service.dispatch(id,"kill",f.actor));
  f.jdbc.update("DELETE FROM t_alert_response WHERE alert_id=?",id);
  f.jdbc.update("DELETE FROM t_alert WHERE id=?",id);
 }

}
