package com.alinksec.service.virus;

import com.alinksec.common.util.JsonUtils;
import com.alinksec.proto.RptVirusResult;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.time.Instant;
import java.security.MessageDigest;
import java.util.*;

/** The first bounded result from a task member is immutable, including zero findings. */
@Service
public class VirusResultService {
    private final JdbcTemplate jdbc;
    public VirusResultService(JdbcTemplate jdbc) { this.jdbc=jdbc; }
    @Transactional
    public void onRealtime(String agent,com.alinksec.proto.RptSecurityEvent event,String reportId) {
        if(!event.getType().equals("virus") || event.getDetail().length()>8192) return;
        com.fasterxml.jackson.databind.JsonNode data;
        try { data=JsonUtils.read(event.getDetail()); } catch(IllegalArgumentException e) { return; }
        if(data==null || !data.isObject()) return;
        if(data.path("execution_contract").asInt()!=2 || !data.path("source").asText().equals("realtime_guard")) return;
        String path=VirusExecution.path(data.path("path").asText()),hash=VirusExecution.hash(data.path("sha256").asText());
        String name=data.path("name").asText(),engine=data.path("engine").asText(),action=data.path("action").asText(),qid=data.path("quarantine_id").asText();
        long size=data.path("size").asLong(-1); int severity=event.getSeverityValue();
        if(name.isBlank() || name.length()>255 || !Set.of("hash","rule","clamav").contains(engine) || !Set.of("alert_only","quarantined").contains(action) || size<0 || size>(500L<<20) || severity<1 || severity>5 || !qid.isEmpty() && !qid.matches("[0-9a-f]{32}") || action.equals("quarantined") && qid.isEmpty()) throw new IllegalArgumentException("周期检测证据无效");
        if(engine.equals("clamav") && (size>(20L<<20) || !ClamavService.validVersion(data.path("engine_version").asText())))throw new IllegalArgumentException("ClamAV 周期检测证据无效");
        String key; try { key=HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(reportId.isBlank()?event.toByteArray():reportId.getBytes(java.nio.charset.StandardCharsets.UTF_8))); } catch(Exception e) { throw new IllegalStateException(e); }
        VirusExecution.lock(jdbc);
        if(jdbc.queryForObject("SELECT count(*) FROM t_virus_finding WHERE agent_id=? AND event_key=?",Integer.class,agent,key)>0) return;
        String error=data.path("action_error").asText(); if(error.length()>128) error=error.substring(0,128);
        jdbc.update("INSERT INTO t_virus_finding(task_id,agent_id,path,name,sha256,size,engine,severity,action_taken,status,quarantine_id,action_error,event_key,initial_evidence) VALUES(NULL,?,?,?,?,?,?,?,?,?,?,?,?,?)",agent,path,name,hash,size,engine,severity,action,action.equals("quarantined")?1:0,qid,error,key,event.getDetail());
    }
    @Transactional
    public void onResult(String agent,RptVirusResult result) {
        VirusExecution.lock(jdbc);
        long task; try { task=Long.parseLong(result.getTaskId()); } catch(NumberFormatException e) { return; }
        var members=jdbc.queryForList("SELECT m.state,m.evidence_sha256,t.status,t.mode,t.expected_db_version,t.scan_engine,m.expected_engine_version FROM t_virus_task_agent m JOIN t_virus_scan_task t ON t.id=m.task_id WHERE m.task_id=? AND m.agent_id=?",task,agent);
        if(members.size()!=1 || !String.valueOf(members.get(0).get("evidence_sha256")).isEmpty()) return;
        var member=members.get(0);
        boolean clamav="clamav".equals(member.get("scan_engine"));
        String engine=clamav?"clamav":"builtin";
        String expected=String.valueOf(member.get(clamav?"expected_engine_version":"expected_db_version"));
        if(clamav && !result.getScanEngine().equals("clamav") || !clamav && !Set.of("","builtin").contains(result.getScanEngine()))throw new IllegalArgumentException("扫描引擎与任务不同");
        if(result.getDbVersion().length()>256)throw new IllegalArgumentException("扫描版本过长");
        if(result.getSerializedSize()>2<<20 || result.getFindingsCount()>1000 || result.getIssuesCount()>32 || result.getCoverage().length()>2000 || result.getExecutionContract()!=(clamav?3:2) || result.getStatus()==RptVirusResult.Status.UNKNOWN || result.getStatus()==RptVirusResult.Status.UNRECOGNIZED || result.getModeValue()+1!=((Number)member.get("mode")).intValue()) throw new IllegalArgumentException("病毒扫描回报契约或大小无效");
        if(result.getStatus()!=RptVirusResult.Status.FAILED && !result.getDbVersion().equals(expected)) throw new IllegalArgumentException("扫描使用的特征库与任务固定版本不同");
        if(result.getFilesScanned()<0 || result.getFilesSeen()<0 || result.getFilesFailed()<0 || result.getFilesSkipped()<0 || result.getDurationMs()<0 || result.getDurationMs()>7260000 || result.getFilesScanned()>result.getFilesSeen() || result.getFindingsCount()>result.getFilesScanned() || result.getFilesScanned()>100000 || result.getFilesSeen()>100000 || result.getFilesFailed()>400000 || result.getFilesSkipped()>400000 || result.getBytesRead()<0 || result.getBytesRead()>(20L<<30)+(64<<10)) throw new IllegalArgumentException("扫描计数超过任务预算");
        if(result.getStatus()==RptVirusResult.Status.COMPLETE && (result.getFilesFailed()!=0 || result.getBudgetExhausted())) throw new IllegalArgumentException("失败或预算耗尽不能声称完成");
        Set<String> paths=new HashSet<>();
        for(var f:result.getFindingsList()) {
            VirusExecution.path(f.getPath()); VirusExecution.hash(f.getSha256());
            if(clamav && (!result.getDbVersion().equals(expected)||f.getSize()>(20L<<20)||!ClamavService.validVersion(f.getEngineVersion())||!f.getEngineVersion().equals(expected)))throw new IllegalArgumentException("ClamAV 检出版本无效");
            if(!paths.add(f.getPath()) || f.getName().isBlank() || f.getName().length()>255 || !(clamav?f.getEngine().equals("clamav"):Set.of("hash","rule").contains(f.getEngine())) || f.getSeverityValue()<1 || f.getSeverityValue()>5 || f.getSize()<0 || f.getSize()>(500L<<20) || !Set.of("quarantined","alert_only").contains(f.getActionTaken()) || f.getActionError().length()>128 || !f.getQuarantineId().isEmpty() && !f.getQuarantineId().matches("[0-9a-f]{32}") || f.getActionTaken().equals("quarantined") && f.getQuarantineId().isEmpty()) throw new IllegalArgumentException("检出证据无效");
        }
        for(var issue:result.getIssuesList()) if(issue.getPath().length()>4096 || !issue.getCode().matches("[a-z_]{1,64}")) throw new IllegalArgumentException("扫描错误证据无效");
        boolean late=!"pending".equals(member.get("state")) || ((Number)member.get("status")).intValue()!=1;
        String evidence=JsonUtils.write(Map.ofEntries(
            Map.entry("execution_contract",result.getExecutionContract()),Map.entry("scan_engine",engine),Map.entry("expected_engine_version",expected),Map.entry("status",result.getStatus().name()),Map.entry("db_version",result.getDbVersion()),Map.entry("files_scanned",result.getFilesScanned()),Map.entry("files_seen",result.getFilesSeen()),Map.entry("files_skipped",result.getFilesSkipped()),Map.entry("files_failed",result.getFilesFailed()),Map.entry("bytes_read",result.getBytesRead()),Map.entry("duration_ms",result.getDurationMs()),Map.entry("coverage",result.getCoverage()),Map.entry("budget_exhausted",result.getBudgetExhausted()),Map.entry("issues",result.getIssuesList().stream().map(i->Map.of("path",i.getPath(),"code",i.getCode())).toList()),Map.entry("report_b64",Base64.getEncoder().encodeToString(result.toByteArray()))));
        String digest; try { digest=HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(result.toByteArray())); } catch(Exception e) { throw new IllegalStateException(e); }
        jdbc.update("UPDATE t_virus_task_agent SET state=?,evidence=?,evidence_sha256=?,received_at=?,late=? WHERE task_id=? AND agent_id=? AND evidence_sha256=''",result.getStatus().name().toLowerCase(Locale.ROOT),evidence,digest,Instant.now().toString(),late?1:0,task,agent);
        // Whitelist changes after execution never remove accepted detection/action evidence.
        for(var f:result.getFindingsList()) jdbc.update("INSERT INTO t_virus_finding(task_id,agent_id,path,name,sha256,size,engine,severity,action_taken,status,quarantine_id,action_error,initial_evidence) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",task,agent,f.getPath(),f.getName(),f.getSha256().toLowerCase(Locale.ROOT),f.getSize(),f.getEngine(),f.getSeverityValue(),f.getActionTaken(),f.getActionTaken().equals("quarantined")?1:0,f.getQuarantineId(),f.getActionError(),JsonUtils.write(Map.of("source","scan","action",f.getActionTaken(),"quarantine_id",f.getQuarantineId(),"action_error",f.getActionError(),"sha256",f.getSha256(),"db_version",result.getDbVersion(),"engine",f.getEngine(),"engine_version",f.getEngineVersion())));
        advanceProgress(task);
    }
    void advanceProgress(long task) {
        Integer total=jdbc.queryForObject("SELECT count(*) FROM t_virus_task_agent WHERE task_id=?",Integer.class,task);
        if(total==null || total==0) return;
        int terminal=jdbc.queryForObject("SELECT count(*) FROM t_virus_task_agent WHERE task_id=? AND state<>'pending'",Integer.class,task);
        int failures=jdbc.queryForObject("SELECT count(*) FROM t_virus_task_agent WHERE task_id=? AND state NOT IN ('pending','complete')",Integer.class,task);
        jdbc.update("UPDATE t_virus_scan_task SET progress=? WHERE id=?",100*terminal/total,task);
        if(terminal==total) jdbc.update("UPDATE t_virus_scan_task SET status=?,finished_at=CURRENT_TIMESTAMP WHERE id=? AND status=1",failures==0?2:3,task);
    }
}
