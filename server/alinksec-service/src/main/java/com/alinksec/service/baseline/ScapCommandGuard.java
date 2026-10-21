package com.alinksec.service.baseline;

import com.alinksec.common.util.JsonUtils;
import com.alinksec.proto.Command;
import com.alinksec.service.command.CommandLifecycleListener;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

/** Revalidate native readiness and immutable delivery, including queued work. */
@Component
public class ScapCommandGuard implements CommandLifecycleListener {
    private final JdbcTemplate jdbc;
    public ScapCommandGuard(JdbcTemplate jdbc) {this.jdbc=jdbc;}
    @Override public Command prepareDelivery(String agent,Command command) {
        if (!command.hasScapScan()) return command;
        var scan=command.getScapScan();
        var task=ScapStore.one(jdbc,"SELECT * FROM t_scap_task WHERE id=?",scan.getTaskId());
        var snapshot=ScapStore.taskSnapshot(task);
        var target=ScapStore.one(jdbc,"SELECT * FROM t_scap_task_agent WHERE task_id=? AND agent_id=? AND command_id=?",scan.getTaskId(),agent,command.getCmdId());
        var manifest=snapshot.path("content").path("manifest");
        if (!target.get("state").equals("pending") || !target.get("evidence_sha256").toString().isEmpty()
                || scan.getExecutionContract()!=1 || scan.getContentZip().size()>ScapPackage.MAX_ARCHIVE
                || !scan.getContentSha256().equals(task.get("content_sha256"))
                || !ScapPackage.digest(scan.getContentZip().toByteArray()).equals(scan.getContentSha256())
                || !scan.getBenchmarkId().equals(manifest.path("benchmarkId").asText()) || !scan.getProfileId().equals(manifest.path("profileId").asText())
                || !scan.getRuntimeSha256().equals(snapshot.path("runtimePins").path(agent).asText())
                || !scan.getRuntimeSha256().equals(target.get("runtime_sha256")))
            throw new IllegalArgumentException("SCAP 排队指令与任务快照不一致或已结束");
        var ready=ScapReadiness.requireReady(jdbc,agent);
        if (!JsonUtils.read(ready.get("coverage").toString()).path("runtime_sha256").asText().equals(scan.getRuntimeSha256()))
            throw new IllegalArgumentException("SCAP 本地引擎已变化，请创建新的核查任务");
        return command;
    }
    @Override public void beforeAck(String agent,String commandId) {lock(agent,commandId);}
    private String lock(String agent,String commandId) {
        var tasks=jdbc.queryForList("SELECT task_id FROM t_scap_task_agent WHERE agent_id=? AND command_id=?",String.class,agent,commandId);
        if (tasks.size()!=1) return null;
        String task=tasks.get(0);jdbc.update("UPDATE t_scap_task SET state=state WHERE id=?",task);return task;
    }
    @Override public void onTerminal(String agent,String commandId,TerminalState state,String message) {
        if (state==TerminalState.DONE) return;
        String task=lock(agent,commandId);if (task==null) return;
        jdbc.update("UPDATE t_scap_task_agent SET state=?,issue=?,finished_at=CURRENT_TIMESTAMP WHERE task_id=? AND agent_id=? AND command_id=? AND evidence_sha256='' AND state='pending'",
                state==TerminalState.TIMEOUT?"timeout":"failed",state==TerminalState.TIMEOUT?"command_timeout":"command_failed",task,agent,commandId);
        ScapStore.advance(jdbc,task);
    }
}
