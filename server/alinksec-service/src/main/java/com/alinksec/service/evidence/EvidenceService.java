package com.alinksec.service.evidence;

import com.alinksec.proto.*;
import com.alinksec.service.command.CommandService;
import com.alinksec.service.config.DatabaseDialect;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.*;
import java.util.*;
import java.util.zip.ZipInputStream;

/** Byte-bound, authenticated evidence. Payloads share the database transaction
 * and backup boundary; there is no public storage URL or orphan file window. */
@Service
public class EvidenceService {
    public static final int MAX_BYTES=1<<20, MAX_REQUESTS=200;
    public static final long MAX_STORED_BYTES=64L<<20;
    private static final String COLUMNS="id,agent_id,kind,finding_id,quarantine_id,original_path,expected_sha256,reason,actor,command_id,state,error_code,created_at,deadline,expires_at,collected_at,received_at,content_sha256,size_bytes,download_count,last_download_by,last_download_at";
    private final JdbcTemplate jdbc;
    private final DatabaseDialect database;
    private final CommandService commands;
    private final TransactionTemplate tx;
    public EvidenceService(JdbcTemplate jdbc,DatabaseDialect database,CommandService commands,PlatformTransactionManager manager) {
        this.jdbc=jdbc;this.database=database;this.commands=commands;this.tx=new TransactionTemplate(manager);
    }
    public record Request(String agentId,String kind,Long findingId,String reason){}
    public record Download(byte[] bytes,String sha256,String filename){}
    public static void admin(JdbcTemplate jdbc,Long actor) {
        if(actor==null || actor<=0 || jdbc.update("UPDATE t_user SET status=status WHERE id=? AND status=1",actor)!=1
                || jdbc.queryForObject("SELECT COUNT(*) FROM t_user u JOIN t_role r ON r.id=u.role_id WHERE u.id=? AND r.name='admin'",Integer.class,actor)!=1)
            throw new IllegalArgumentException("需要当前有效管理员");
    }
    public static void gate(JdbcTemplate jdbc) {
        if(jdbc.update("UPDATE t_evidence_gate SET revision=revision+1 WHERE id=1")!=1)throw new IllegalStateException("取证锁不存在");
    }
    public static void id(String id) {
        if(id==null || !id.matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"))throw new IllegalArgumentException("取证标识无效");
    }
    public static String sha(byte[] bytes) {
        try{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));}
        catch(java.security.NoSuchAlgorithmException e){throw new IllegalStateException(e);}
    }
    private void clean(long now) {
        jdbc.update("UPDATE t_evidence_request SET state='expired',error_code='request_expired' WHERE state='pending' AND deadline<=?",now);
        jdbc.update("DELETE FROM t_evidence_request WHERE expires_at<=?",now);
    }
    public List<Map<String,Object>> targets(Long actor) {
        return tx.execute(s->{admin(jdbc,actor);return jdbc.queryForList("SELECT agent_id,hostname,os_type,status,evidence_contract,last_heartbeat FROM t_agent WHERE deleted=false AND status<>4 ORDER BY hostname,agent_id LIMIT 1000");});
    }
    public List<Map<String,Object>> samples(String agent,Long actor) {
        if(agent==null || agent.length()>64)throw new IllegalArgumentException("主机标识无效");
        return tx.execute(s->{admin(jdbc,actor);return jdbc.queryForList("SELECT f.id,f.path,f.sha256,f.size,f.quarantine_id,f.created_at FROM t_virus_finding f JOIN t_agent a ON a.agent_id=f.agent_id WHERE f.agent_id=? AND a.deleted=false AND a.status<>4 AND f.status=1 AND f.quarantine_id<>'' ORDER BY f.id DESC LIMIT 200",agent);});
    }
    public List<Map<String,Object>> history(Long actor) {
        return tx.execute(s->{admin(jdbc,actor);gate(jdbc);clean(System.currentTimeMillis());return jdbc.queryForList("SELECT "+COLUMNS+" FROM t_evidence_request ORDER BY created_at DESC,id DESC LIMIT "+MAX_REQUESTS);});
    }
    public Map<String,Object> create(Request body,Long actor) {
        if(body==null || body.agentId()==null || body.agentId().isBlank() || body.agentId().length()>64
                || !Set.of("diagnostic","quarantine_sample").contains(body.kind()==null?"":body.kind())
                || body.reason()==null || body.reason().isBlank() || body.reason().length()>256
                || body.reason().codePoints().anyMatch(Character::isISOControl))throw new IllegalArgumentException("请选择主机、采集类型并填写 1 至 256 字用途");
        if(body.kind().equals("diagnostic") && body.findingId()!=null)throw new IllegalArgumentException("诊断包不能指定样本");
        return tx.execute(s->{
            admin(jdbc,actor);gate(jdbc);long now=System.currentTimeMillis();clean(now);
            if(jdbc.queryForObject("SELECT COUNT(*) FROM t_evidence_request",Integer.class)>=MAX_REQUESTS)throw new IllegalArgumentException("取证记录已达 200 条，请先清理旧记录");
            if(jdbc.queryForObject("SELECT COUNT(*) FROM t_agent WHERE agent_id=? AND deleted=false AND status=1 AND evidence_contract=1 AND os_type IN (1,2) AND last_heartbeat>=?",Integer.class,
                    body.agentId(),database.timestampBefore(Duration.ofMinutes(2)))!=1)throw new IllegalArgumentException("需要最近在线且支持取证协议的 Linux／Windows Agent");
            if(jdbc.queryForObject("SELECT COUNT(*) FROM t_evidence_request WHERE agent_id=? AND state='pending'",Integer.class,body.agentId())>0)throw new IllegalArgumentException("该主机已有待完成取证");
            String capture="",path="",digest="";
            if(body.kind().equals("quarantine_sample")) {
                if(body.findingId()==null)throw new IllegalArgumentException("请选择已隔离样本");
                var found=jdbc.queryForList("SELECT * FROM t_virus_finding WHERE id=? AND agent_id=? AND status=1",body.findingId(),body.agentId());
                if(found.size()!=1)throw new IllegalArgumentException("样本已变化，请刷新");
                var sample=found.getFirst();capture=Objects.toString(sample.get("quarantine_id"),"");path=Objects.toString(sample.get("path"),"");digest=Objects.toString(sample.get("sha256"),"");
                if(!capture.matches("[0-9a-f]{32}") || !digest.matches("[0-9a-f]{64}") || path.isBlank() || path.length()>4096
                        || !(sample.get("size") instanceof Number size) || size.longValue()<0 || size.longValue()>MAX_BYTES)throw new IllegalArgumentException("样本缺少有效捕获身份或超过 1 MiB 上限");
            }
            String key=UUID.randomUUID().toString();long deadline=now+Duration.ofMinutes(10).toMillis();
            jdbc.update("INSERT INTO t_evidence_request(id,agent_id,kind,finding_id,quarantine_id,original_path,expected_sha256,reason,actor,created_at,deadline,expires_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                    key,body.agentId(),body.kind(),body.findingId(),capture,path,digest,body.reason().trim(),actor,now,deadline,now+Duration.ofDays(30).toMillis());
            String command=commands.dispatchAfterCommit(body.agentId(),Command.newBuilder().setEvidenceCollect(CmdEvidenceCollect.newBuilder()
                    .setRequestId(key).setExecutionContract(1).setKind(body.kind()).setQuarantineId(capture).setOriginalPath(path).setExpectedSha256(digest).setDeadline(deadline)),actor);
            jdbc.update("UPDATE t_evidence_request SET command_id=? WHERE id=?",command,key);
            return jdbc.queryForMap("SELECT "+COLUMNS+" FROM t_evidence_request WHERE id=?",key);
        });
    }
    public void accept(String agent,Report report) {
        var result=report.getEvidence();id(result.getRequestId());
        if(!report.getReportId().equals(result.getRequestId()+"-evidence") || result.getExecutionContract()!=1 || result.getContent().size()>MAX_BYTES
                || result.getCollectedAt()<=0 || result.getCollectedAt()>System.currentTimeMillis()+60000)throw new IllegalArgumentException("取证结果身份无效");
        tx.executeWithoutResult(s->{
            var rows=jdbc.queryForList("SELECT * FROM t_evidence_request WHERE id=? AND agent_id=? AND command_id=?",result.getRequestId(),agent,result.getCommandId());
            if(rows.size()!=1)throw new IllegalArgumentException("取证结果不属于该主机和指令");
            var row=rows.getFirst();admin(jdbc,((Number)row.get("actor")).longValue());gate(jdbc);
            row=jdbc.queryForMap("SELECT * FROM t_evidence_request WHERE id=?",result.getRequestId());
            if(jdbc.queryForObject("SELECT COUNT(*) FROM t_agent WHERE agent_id=? AND deleted=false AND status IN (1,2)",Integer.class,agent)!=1)throw new IllegalArgumentException("取证主机已停用或删除");
            if(!row.get("kind").equals(result.getKind()))throw new IllegalArgumentException("取证类型不匹配");
            if(!row.get("state").equals("pending"))return;
            long now=System.currentTimeMillis();
            if(((Number)row.get("deadline")).longValue()<=now) {jdbc.update("UPDATE t_evidence_request SET state='expired',error_code='request_expired' WHERE id=?",result.getRequestId());return;}
            if(result.getCollectedAt()<((Number)row.get("created_at")).longValue()-60000 || result.getCollectedAt()>((Number)row.get("deadline")).longValue())throw new IllegalArgumentException("取证采集时间无效");
            if(!result.getErrorCode().isEmpty()) {
                if(!result.getErrorCode().equals("collection_unavailable_or_limit_exceeded") || !result.getContent().isEmpty() || !result.getSha256().isEmpty())throw new IllegalArgumentException("取证失败回执无效");
                jdbc.update("UPDATE t_evidence_request SET state='failed',error_code=?,received_at=? WHERE id=?",result.getErrorCode(),now,result.getRequestId());return;
            }
            byte[] bytes=result.getContent().toByteArray();String hash=sha(bytes);
            if(!hash.equals(result.getSha256()))throw new IllegalArgumentException("取证内容摘要不匹配");
            if(result.getKind().equals("quarantine_sample") && !hash.equals(row.get("expected_sha256")))throw new IllegalArgumentException("样本与请求时捕获身份不符");
            if(result.getKind().equals("diagnostic"))diagnostic(bytes,result.getRequestId(),agent);
            long stored=jdbc.queryForObject("SELECT COALESCE(SUM(size_bytes),0) FROM t_evidence_request",Long.class);
            if(stored+bytes.length>MAX_STORED_BYTES) {jdbc.update("UPDATE t_evidence_request SET state='failed',error_code='storage_quota_exceeded',received_at=? WHERE id=?",now,result.getRequestId());return;}
            jdbc.update("UPDATE t_evidence_request SET state='ready',content_b64=?,content_sha256=?,size_bytes=?,collected_at=?,received_at=? WHERE id=? AND state='pending'",
                    Base64.getEncoder().encodeToString(bytes),hash,bytes.length,result.getCollectedAt(),now,result.getRequestId());
        });
    }
    private static void diagnostic(byte[] bytes,String request,String agent) {
        Set<String> names=new HashSet<>();int total=0;byte[] runtime=null;
        try(var zip=new ZipInputStream(new ByteArrayInputStream(bytes),StandardCharsets.UTF_8)) {
            java.util.zip.ZipEntry entry;
            while((entry=zip.getNextEntry())!=null) {
                if(entry.isDirectory() || !Set.of("runtime.json","heartbeat.json","README.txt").contains(entry.getName()) || !names.add(entry.getName()))throw new IllegalArgumentException("诊断包条目无效");
                byte[] content=zip.readNBytes((128<<10)+1);total+=content.length;
                if(content.length>128<<10 || total>256<<10)throw new IllegalArgumentException("诊断包解压超过限制");
                if(entry.getName().equals("runtime.json"))runtime=content;
            }
            if(names.size()!=3 || runtime==null)throw new IllegalArgumentException("诊断包不完整");
            var identity=com.alinksec.common.util.JsonUtils.read(new String(runtime,StandardCharsets.UTF_8));
            if(identity.path("format").asInt()!=1 || !identity.path("requestId").asText().equals(request) || !identity.path("agentId").asText().equals(agent))throw new IllegalArgumentException("诊断包身份不符");
        } catch(IOException e){throw new IllegalArgumentException("诊断包格式无效");}
    }
    public Download download(String key,Long actor) {
        id(key);return tx.execute(s->{admin(jdbc,actor);gate(jdbc);
            var rows=jdbc.queryForList("SELECT kind,state,expires_at,content_b64,content_sha256,size_bytes FROM t_evidence_request WHERE id=?",key);
            if(rows.size()!=1 || !rows.getFirst().get("state").equals("ready") || ((Number)rows.getFirst().get("expires_at")).longValue()<=System.currentTimeMillis())throw new IllegalArgumentException("文件未就绪或已过期");
            var row=rows.getFirst();String encoded=(String)row.get("content_b64");if(encoded.length()>((MAX_BYTES+2)/3)*4)throw new IllegalStateException("取证内容超过上限");
            byte[] bytes=Base64.getDecoder().decode(encoded);String hash=sha(bytes);
            if(bytes.length!=((Number)row.get("size_bytes")).longValue() || bytes.length>MAX_BYTES || !hash.equals(row.get("content_sha256")))throw new IllegalStateException("取证文件完整性校验失败");
            jdbc.update("UPDATE t_evidence_request SET download_count=download_count+1,last_download_by=?,last_download_at=? WHERE id=?",actor,System.currentTimeMillis(),key);
            return new Download(bytes,hash,"alinksec-"+key+(row.get("kind").equals("diagnostic")?"-diagnostic.zip":"-quarantine.sample.bin"));
        });
    }
    public void delete(String key,Long actor) {
        id(key);tx.executeWithoutResult(s->{admin(jdbc,actor);gate(jdbc);
            if(jdbc.update("DELETE FROM t_evidence_request WHERE id=? AND state<>'pending'",key)!=1)throw new IllegalArgumentException("记录不存在或仍在采集中");
        });
    }
    public Optional<CmdEvidenceReceipt> receipt(String agent,Report report) {
        if(!report.hasEvidence())return Optional.empty();
        var result=report.getEvidence();
        var rows=jdbc.queryForList("SELECT state,content_sha256 FROM t_evidence_request WHERE id=? AND agent_id=? AND command_id=? AND kind=?",
                result.getRequestId(),agent,result.getCommandId(),result.getKind());
        if(rows.size()!=1 || rows.getFirst().get("state").equals("pending"))return Optional.empty();
        if(rows.getFirst().get("state").equals("ready") && !rows.getFirst().get("content_sha256").equals(result.getSha256()))return Optional.empty();
        return Optional.of(CmdEvidenceReceipt.newBuilder().setRequestId(result.getRequestId()).setCommandId(result.getCommandId()).setContentSha256(result.getSha256()).build());
    }
    @Scheduled(fixedDelay=60000) public void expire() {
        long now=System.currentTimeMillis();
        if(jdbc.queryForObject("SELECT COUNT(*) FROM t_evidence_request WHERE (state='pending' AND deadline<=?) OR expires_at<=?",Integer.class,now,now)>0)
            tx.executeWithoutResult(s->{gate(jdbc);clean(now);});
    }
}
