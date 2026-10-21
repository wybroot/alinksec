package com.alinksec.service.baseline;

import com.alinksec.common.util.JsonUtils;
import com.alinksec.proto.RptScapResult;
import org.springframework.jdbc.core.JdbcTemplate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Called inside the report transaction, including report deduplication. */
public final class ScapResults {
    private ScapResults() {}
    public static void accept(JdbcTemplate jdbc,String agent,RptScapResult report) {
        if (report.getExecutionContract()!=1 || !List.of("complete","failed").contains(report.getState())
                || !report.getEngine().equals("SCC") || !ScapStore.ISSUES.contains(report.getIssue())
                || report.getDurationMs()<0 || report.getDurationMs()>1800000 || report.getRulesCount()>ScapPackage.MAX_RULES
                || report.getScoresCount()>16) throw new IllegalArgumentException("SCAP 结果契约无效");
        var task=ScapStore.one(jdbc,"UPDATE t_scap_task SET state=state WHERE id=? RETURNING *",report.getTaskId());
        var snapshot=ScapStore.taskSnapshot(task);
        var target=ScapStore.one(jdbc,"SELECT * FROM t_scap_task_agent WHERE task_id=? AND agent_id=?",report.getTaskId(),agent);
        var manifest=snapshot.path("content").path("manifest");
        boolean scoped=false;for (var id:snapshot.path("agentIds")) if (id.asText().equals(agent)) scoped=true;
        if (!scoped || !target.get("command_id").equals(report.getCommandId()) || !task.get("content_sha256").equals(report.getContentSha256())
                || !manifest.path("benchmarkId").asText().equals(report.getBenchmarkId()) || !manifest.path("profileId").asText().equals(report.getProfileId())
                || !snapshot.path("runtimePins").path(agent).asText().equals(target.get("runtime_sha256")))
            throw new IllegalArgumentException("SCAP 结果不属于当前主机和任务快照");
        // Preserve the first actual result, including a failed execution. A
        // terminal command placeholder without evidence may accept a late report.
        if (!target.get("evidence_sha256").toString().isEmpty()) return;
        boolean complete=report.getState().equals("complete");
        if (complete) {
            if (!report.getIssue().isEmpty() || !report.getEngineVersion().equals("5.12")
                    || !report.getRuntimeSha256().equals(target.get("runtime_sha256")) || !ScapStore.hash(report.getSourceResultSha256()))
                throw new IllegalArgumentException("SCAP 原生执行身份不完整");
        } else if (report.getIssue().isEmpty() || report.getRulesCount()!=0 || report.getScoresCount()!=0 || !report.getSourceResultSha256().isEmpty()
                || !report.getEngineVersion().isEmpty()&&!report.getEngineVersion().equals("5.12")
                || !report.getRuntimeSha256().isEmpty()&&!ScapStore.hash(report.getRuntimeSha256())) {
            throw new IllegalArgumentException("SCAP 失败结果不得附带部分成功结论");
        }
        var expected=new HashSet<String>();
        for (var rule:snapshot.path("content").path("rules")) expected.add(rule.path("id").asText());
        Map<String,Integer> counts=new LinkedHashMap<>();
        for (String outcome:List.of("pass","fail","error","unknown","notapplicable","notchecked","notselected","informational","fixed")) counts.put(outcome,0);
        List<Map<String,Object>> rules=new ArrayList<>(),scores=new ArrayList<>();
        var seen=new HashSet<String>();
        for (var rule:report.getRulesList()) {
            if (!expected.contains(rule.getRuleId()) || !seen.add(rule.getRuleId()) || !ScapStore.OUTCOMES.contains(rule.getResult())
                    || !finite(rule.getWeight()) || rule.getWeight()<0 || rule.getWeight()>1000000)
                throw new IllegalArgumentException("SCAP 规则结果无效、重复或超出范围");
            counts.compute(rule.getResult(),(key,value)->value+1);
            Map<String,Object> value=new LinkedHashMap<>();value.put("ruleId",rule.getRuleId());value.put("result",rule.getResult());value.put("weight",rule.getWeight());rules.add(value);
        }
        if (complete && (!expected.equals(seen) || report.getScoresCount()==0)) throw new IllegalArgumentException("SCAP 结果缺少完整规则集合或原生得分");
        var systems=new HashSet<String>();
        for (var score:report.getScoresList()) {
            if (score.getSystem().isBlank() || score.getSystem().length()>256 || !score.getSystem().contains(":") || !systems.add(score.getSystem())
                    || !finite(score.getValue()) || !finite(score.getMaximum()) || score.getValue()<0 || score.getMaximum()<0
                    || score.getValue()>score.getMaximum() || score.getMaximum()>1000000) throw new IllegalArgumentException("SCAP 原生得分无效");
            Map<String,Object> value=new LinkedHashMap<>();value.put("system",score.getSystem());value.put("value",score.getValue());value.put("maximum",score.getMaximum());scores.add(value);
        }
        Map<String,Object> evidence=new LinkedHashMap<>();
        evidence.put("schemaVersion",1);evidence.put("taskId",report.getTaskId());evidence.put("commandId",report.getCommandId());evidence.put("agentId",agent);
        evidence.put("contentSha256",report.getContentSha256());evidence.put("benchmarkId",report.getBenchmarkId());evidence.put("profileId",report.getProfileId());
        evidence.put("engine",report.getEngine());evidence.put("engineVersion",report.getEngineVersion());evidence.put("runtimeSha256",report.getRuntimeSha256());
        evidence.put("state",report.getState());evidence.put("issue",report.getIssue());evidence.put("durationMs",report.getDurationMs());
        evidence.put("sourceResultSha256",report.getSourceResultSha256());evidence.put("rules",rules);evidence.put("scores",scores);evidence.put("counts",counts);
        String saved=JsonUtils.write(evidence);
        jdbc.update("UPDATE t_scap_task_agent SET state=?,issue=?,evidence_sha256=?,evidence=?,finished_at=CURRENT_TIMESTAMP WHERE task_id=? AND agent_id=? AND evidence_sha256=''",
                report.getState(),report.getIssue(),ScapStore.digest(saved),saved,report.getTaskId(),agent);
        ScapStore.advance(jdbc,report.getTaskId());
    }
    public static byte[] export(JdbcTemplate jdbc,String task,String agent) {
        var source=ScapStore.one(jdbc,"SELECT * FROM t_scap_task WHERE id=?",task);ScapStore.taskSnapshot(source);
        var row=ScapStore.one(jdbc,"SELECT evidence,evidence_sha256 FROM t_scap_task_agent WHERE task_id=? AND agent_id=?",task,agent);
        String evidence=row.get("evidence").toString();
        if (!ScapStore.digest(evidence).equals(row.get("evidence_sha256"))) throw new IllegalArgumentException("尚无有效的 SCAP Agent 结果");
        return evidence.getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }
    private static boolean finite(double value) {return Double.isFinite(value);}
}
