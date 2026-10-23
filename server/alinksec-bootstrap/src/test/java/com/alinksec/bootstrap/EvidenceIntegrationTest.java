package com.alinksec.bootstrap;

import com.alinksec.common.util.JsonUtils;
import com.alinksec.proto.*;
import com.alinksec.service.command.*;
import com.alinksec.service.config.AlinkSecProperties;
import com.alinksec.service.download.AgentDownloadTokenService;
import com.alinksec.service.evidence.*;
import com.google.protobuf.ByteString;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.zip.*;
import java.io.*;
import static org.junit.jupiter.api.Assertions.*;

/** Real SQLite / restricted PostgreSQL transactions and durable command rows. */
class EvidenceIntegrationTest {
    @TempDir Path root;
    LibraryGovernanceIntegrationTest f;
    EvidenceService evidence;
    EvidenceCommandGuard guard;
    CommandService commands;
    String agent,other;
    Map<String,Command> sent=new ConcurrentHashMap<>();
    @BeforeEach void setup()throws Exception {
        f=new LibraryGovernanceIntegrationTest();f.root=root;f.setup();
        guard=new EvidenceCommandGuard(f.jdbc,f.dialect);
        commands=new CommandService(new CommandRepository(f.jdbc,f.dialect),(id,command)->{sent.put(command.getCmdId(),command);return true;},
                new AgentDownloadTokenService(f.jdbc,f.dialect),new AlinkSecProperties(),List.of(guard),f.manager);
        evidence=new EvidenceService(f.jdbc,f.dialect,commands,f.manager);
        agent=host("诊断主机",1);other=host("Other",2);
    }
    String host(String name,int os) {
        String id=UUID.randomUUID().toString();f.agents.add(id);
        f.jdbc.update("INSERT INTO t_agent(agent_id,hostname,os_type,status,evidence_contract,last_heartbeat) VALUES(?,?,?,1,1,?)",id,name,os,f.dialect.timestamp(Instant.now()));return id;
    }
    @AfterEach void close() {
        if(commands!=null)commands.close();
        if(f!=null && f.jdbc!=null) {
            for(String id:f.agents){f.jdbc.update("DELETE FROM t_evidence_request WHERE agent_id=?",id);f.jdbc.update("DELETE FROM t_command WHERE agent_id=?",id);f.jdbc.update("DELETE FROM t_virus_finding WHERE agent_id=?",id);}
            f.close();
        }
    }
    Map<String,Object> request(String kind,Long finding) {return evidence.create(new EvidenceService.Request(agent,kind,finding,"排查工单 SEC-123"),f.actor);}
    Command command(Map<String,Object> row) throws Exception {
        String key=(String)row.get("command_id");long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(5);
        while(!sent.containsKey(key) && System.nanoTime()<deadline)Thread.sleep(10);
        assertTrue(sent.containsKey(key),"durable command not delivered");return sent.get(key);
    }
    byte[] zip(String request,String target)throws IOException {
        var buffer=new ByteArrayOutputStream();try(var zip=new ZipOutputStream(buffer,StandardCharsets.UTF_8)) {
            for(var entry:Map.of("runtime.json",JsonUtils.write(Map.of("format",1,"requestId",request,"agentId",target)),"heartbeat.json","{}","README.txt","Harmless diagnostic fixture").entrySet()) {
                zip.putNextEntry(new ZipEntry(entry.getKey()));zip.write(entry.getValue().getBytes(StandardCharsets.UTF_8));zip.closeEntry();
            }
        }return buffer.toByteArray();
    }
    Report result(Map<String,Object> row,byte[] bytes) {
        String key=(String)row.get("id");return Report.newBuilder().setAgentId(agent).setReportId(key+"-evidence").setTs(System.currentTimeMillis())
                .setEvidence(RptEvidence.newBuilder().setRequestId(key).setCommandId((String)row.get("command_id")).setExecutionContract(1)
                        .setKind((String)row.get("kind")).setCollectedAt(System.currentTimeMillis()).setContent(ByteString.copyFrom(bytes)).setSha256(EvidenceService.sha(bytes))).build();
    }
    Map<String,Object> row(String id){return f.jdbc.queryForMap("SELECT * FROM t_evidence_request WHERE id=?",id);}
    Map<String,Object> row(Map<String,Object> request){return row((String)request.get("id"));}
    void ready(Map<String,Object> request)throws Exception {evidence.accept(agent,result(request,zip((String)request.get("id"),agent)));}
    long sample(byte[] content) {
        return f.jdbc.queryForObject("INSERT INTO t_virus_finding(agent_id,path,name,sha256,size,engine,severity,status,quarantine_id) VALUES(?,'/tmp/harmless-sample','Fixture',?,?,'hash',3,1,?) RETURNING id",Long.class,agent,EvidenceService.sha(content),content.length,"a".repeat(32));
    }
    @Test void exactDiagnosticBytesSurviveServiceRestartAndDownloadsArePrivateAuditedAndBounded()throws Exception {
        var request=request("diagnostic",null);var command=command(request);assertEquals("diagnostic",command.getEvidenceCollect().getKind());
        assertEquals("pending",row(request).get("state"));ready(request);
        var restarted=new EvidenceService(f.jdbc,f.dialect,commands,f.manager);
        var download=restarted.download((String)request.get("id"),f.actor);
        assertArrayEquals(Base64.getDecoder().decode((String)row(request).get("content_b64")),download.bytes());assertEquals(EvidenceService.sha(download.bytes()),download.sha256());
        assertTrue(download.filename().endsWith("-diagnostic.zip"));assertEquals(1L,((Number)row(request).get("download_count")).longValue());
        assertEquals(f.actor,((Number)row(request).get("last_download_by")).longValue());
        assertFalse(restarted.history(f.actor).getFirst().containsKey("content_b64"));
        var receipt=evidence.receipt(agent,result(request,download.bytes())).orElseThrow();assertEquals(download.sha256(),receipt.getContentSha256());
        assertTrue(evidence.receipt(other,result(request,download.bytes())).isEmpty());
    }
    @Test void ackDoneNeverMarksEvidenceReadyAndDurableRequestCanBeDeliveredAfterRestart()throws Exception {
        var request=request("diagnostic",null);Command sent=command(request);
        commands.onAck(agent,RptAck.newBuilder().setCmdId(sent.getCmdId()).setStage(RptAck.Stage.DONE).build());
        assertEquals("pending",row(request).get("state"));assertThrows(IllegalArgumentException.class,()->evidence.download((String)request.get("id"),f.actor));
        assertTrue(evidence.receipt(agent,result(request,zip((String)request.get("id"),agent))).isEmpty());
        ready(request);assertEquals("ready",row(request).get("state"));
    }
    @Test void quarantineSampleIsBoundToExistingCaptureAndExportDoesNotChangeFinding()throws Exception {
        byte[] content="Harmless captured sample".getBytes(StandardCharsets.UTF_8);long finding=sample(content);
        var request=request("quarantine_sample",finding);var command=command(request).getEvidenceCollect();
        assertEquals("a".repeat(32),command.getQuarantineId());assertEquals(EvidenceService.sha(content),command.getExpectedSha256());
        evidence.accept(agent,result(request,content));var file=evidence.download((String)request.get("id"),f.actor);
        assertArrayEquals(content,file.bytes());assertTrue(file.filename().endsWith(".sample.bin"));
        assertEquals(1,f.jdbc.queryForObject("SELECT status FROM t_virus_finding WHERE id=?",Integer.class,finding));
        evidence.delete((String)request.get("id"),f.actor);assertEquals(1,f.jdbc.queryForObject("SELECT COUNT(*) FROM t_virus_finding WHERE id=?",Integer.class,finding));
    }
    @Test void unknownWrongAgentWrongCommandDigestAndPayloadIdentityAreRejectedAtomically()throws Exception {
        var request=request("diagnostic",null);command(request);var valid=result(request,zip((String)request.get("id"),agent));
        assertThrows(IllegalArgumentException.class,()->evidence.accept(other,valid));
        assertThrows(IllegalArgumentException.class,()->evidence.accept(agent,valid.toBuilder().setReportId(UUID.randomUUID().toString()).build()));
        assertThrows(IllegalArgumentException.class,()->evidence.accept(agent,valid.toBuilder().setEvidence(valid.getEvidence().toBuilder().setCommandId(UUID.randomUUID().toString())).build()));
        assertThrows(IllegalArgumentException.class,()->evidence.accept(agent,valid.toBuilder().setEvidence(valid.getEvidence().toBuilder().setSha256("0".repeat(64))).build()));
        assertThrows(IllegalArgumentException.class,()->evidence.accept(agent,result(request,zip((String)request.get("id"),other))));
        assertEquals("pending",row(request).get("state"));assertEquals("",row(request).get("content_b64"));
    }
    @Test void duplicateResultsCannotReplacePreviouslyAcceptedBytes()throws Exception {
        var request=request("diagnostic",null);command(request);ready(request);String hash=(String)row(request).get("content_sha256");
        evidence.accept(agent,result(request,"different bytes".getBytes(StandardCharsets.UTF_8)));
        assertEquals(hash,row(request).get("content_sha256"));assertEquals("ready",row(request).get("state"));
    }
    @Test void requestAndDownloadRecheckCurrentAdministratorAndAgentCapability()throws Exception {
        var request=request("diagnostic",null);command(request);ready(request);
        for(String change:List.of("status=0","status=1,role_id=2","status=1,role_id=3")) {
            f.jdbc.update("UPDATE t_user SET "+change+" WHERE id=?",f.actor);
            assertThrows(IllegalArgumentException.class,()->evidence.history(f.actor));
            assertThrows(IllegalArgumentException.class,()->evidence.download((String)request.get("id"),f.actor));
            assertThrows(IllegalArgumentException.class,()->request("diagnostic",null));
        }
        f.jdbc.update("UPDATE t_user SET status=1,role_id=1 WHERE id=?",f.actor);
        for(String change:List.of("evidence_contract=0","evidence_contract=1,status=2","status=1,deleted=true")) {
            f.jdbc.update("UPDATE t_agent SET "+change+" WHERE agent_id=?",agent);
            assertThrows(IllegalArgumentException.class,()->request("diagnostic",null));
        }
    }
    @Test void deliveryGuardRejectsRevokedAuthorityCapabilityAndChangedSample()throws Exception {
        long finding=sample(new byte[]{1,2,3});var request=request("quarantine_sample",finding);var command=command(request);
        f.jdbc.update("UPDATE t_user SET status=0 WHERE id=?",f.actor);assertThrows(IllegalArgumentException.class,()->guard.prepareDelivery(agent,command));
        f.jdbc.update("UPDATE t_user SET status=1 WHERE id=?",f.actor);f.jdbc.update("UPDATE t_agent SET evidence_contract=0 WHERE agent_id=?",agent);assertThrows(IllegalArgumentException.class,()->guard.prepareDelivery(agent,command));
        f.jdbc.update("UPDATE t_agent SET evidence_contract=1 WHERE agent_id=?",agent);f.jdbc.update("UPDATE t_virus_finding SET status=3 WHERE id=?",finding);assertThrows(IllegalArgumentException.class,()->guard.prepareDelivery(agent,command));
    }
    @Test void expiredAndFailedEvidenceNeverExposesPartialBytes()throws Exception {
        var request=request("diagnostic",null);command(request);f.jdbc.update("UPDATE t_evidence_request SET deadline=? WHERE id=?",System.currentTimeMillis()-1,request.get("id"));
        ready(request);assertEquals("expired",row(request).get("state"));assertEquals("",row(request).get("content_b64"));
        assertThrows(IllegalArgumentException.class,()->evidence.download((String)request.get("id"),f.actor));
        var failed=request("diagnostic",null);command(failed);var result=result(failed,new byte[0]);
        evidence.accept(agent,result.toBuilder().setEvidence(result.getEvidence().toBuilder().clearSha256().setErrorCode("collection_unavailable_or_limit_exceeded")).build());
        assertEquals("failed",row(failed).get("state"));assertEquals(0L,((Number)row(failed).get("size_bytes")).longValue());
    }
    @Test void oversizeArchiveTraversalAndChangedStoredContentAreRejected()throws Exception {
        var request=request("diagnostic",null);command(request);
        assertThrows(IllegalArgumentException.class,()->evidence.accept(agent,result(request,new byte[(1<<20)+1])));
        var buffer=new ByteArrayOutputStream();try(var zip=new ZipOutputStream(buffer)){zip.putNextEntry(new ZipEntry("../escape"));zip.write(1);zip.closeEntry();}
        assertThrows(IllegalArgumentException.class,()->evidence.accept(agent,result(request,buffer.toByteArray())));
        ready(request);f.jdbc.update("UPDATE t_evidence_request SET content_b64=? WHERE id=?",Base64.getEncoder().encodeToString(new byte[]{1}),request.get("id"));
        assertThrows(IllegalStateException.class,()->evidence.download((String)request.get("id"),f.actor));
        assertEquals(0L,((Number)row(request).get("download_count")).longValue());
    }
    @Test void quotaAndRetentionAreTransactionalAndNeverClaimAStoredFile()throws Exception {
        var request=request("diagnostic",null);command(request);f.jdbc.update("UPDATE t_evidence_request SET size_bytes=? WHERE id=?",EvidenceService.MAX_STORED_BYTES,request.get("id"));
        ready(request);assertEquals("failed",row(request).get("state"));assertEquals("storage_quota_exceeded",row(request).get("error_code"));
        f.jdbc.update("UPDATE t_evidence_request SET expires_at=? WHERE id=?",System.currentTimeMillis()-1,request.get("id"));
        evidence.expire();assertTrue(evidence.history(f.actor).isEmpty());
    }
    @Test void competingRequestsHaveOnePendingWinnerAndNoOrphanCommand()throws Exception {
        var workers=Executors.newFixedThreadPool(2);var start=new CountDownLatch(1);
        Callable<Boolean> job=()->{start.await();try{request("diagnostic",null);return true;}catch(IllegalArgumentException e){return false;}};
        try {var one=workers.submit(job);var two=workers.submit(job);start.countDown();assertNotEquals(one.get(10,TimeUnit.SECONDS),two.get(10,TimeUnit.SECONDS));
            assertEquals(1,f.jdbc.queryForObject("SELECT COUNT(*) FROM t_evidence_request WHERE agent_id=?",Integer.class,agent));
            assertEquals(1,f.jdbc.queryForObject("SELECT COUNT(*) FROM t_command WHERE agent_id=?",Integer.class,agent));
        } finally {workers.shutdownNow();assertTrue(workers.awaitTermination(5,TimeUnit.SECONDS));}
    }
    @Test void capturesAreRealDatabaseMetadataAndFilesForBrowserValidation()throws Exception {
        var request=request("diagnostic",null);command(request);ready(request);var download=evidence.download((String)request.get("id"),f.actor);
        byte[] sample="Harmless central evidence fixture".getBytes(StandardCharsets.UTF_8);var sampleRequest=request("quarantine_sample",sample(sample));command(sampleRequest);evidence.accept(agent,result(sampleRequest,sample));
        var expired=request("diagnostic",null);command(expired);f.jdbc.update("UPDATE t_evidence_request SET deadline=? WHERE id=?",System.currentTimeMillis()-1,expired.get("id"));evidence.expire();
        var failed=request("diagnostic",null);var failedCommand=command(failed);commands.onAck(agent,RptAck.newBuilder().setCmdId(failedCommand.getCmdId()).setStage(RptAck.Stage.FAILED).setCode(1).setMessage("controlled unavailable fixture").build());
        var pending=request("diagnostic",null);command(pending);
        String output=System.getenv("ALINKSEC_EVIDENCE_FIXTURES");if(output==null)return;
        var directory=Path.of(output);Files.createDirectories(directory);String mode=f.dialect.isSqlite()?"sqlite":"postgres";
        Files.write(directory.resolve("diagnostic-"+mode+".zip"),download.bytes());Files.write(directory.resolve("sample-"+mode+".bin"),sample);
        Files.writeString(directory.resolve("console-"+mode+".json"),JsonUtils.write(Map.of("database",mode,"targets",evidence.targets(f.actor),"history",evidence.history(f.actor),"samples",evidence.samples(agent,f.actor),"agent",agent)),StandardCharsets.UTF_8);
    }
}
