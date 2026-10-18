package com.alinksec.service.command;

import com.alinksec.common.util.JsonUtils;
import com.alinksec.proto.Command;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

import java.util.Base64;

/** Resource admission can reject work before any result exists. Keep task
 * summaries consistent with the authenticated command's failed terminal state. */
@Component
public class BulkTaskCommandLifecycle implements CommandLifecycleListener {
    private final JdbcTemplate jdbc;

    public BulkTaskCommandLifecycle(JdbcTemplate jdbc) { this.jdbc = jdbc; }

    @Override public Command prepareDelivery(String agent,Command command) {
        if(command.hasVulnScan() && command.getVulnScan().getExecutionContract()==1 && command.getVulnScan().getIncludeWeakPassword()
            && jdbc.queryForObject("SELECT count(*) FROM t_agent WHERE agent_id=? AND os_type=1 AND weak_password_contract=1 AND deleted=false AND status NOT IN (3,4)",Integer.class,agent)!=1)
            throw new IllegalStateException("目标不再支持 Linux 本地弱口令字典检测，请更新 Agent 后重试");
        return command;
    }

    @Override
    public void onTerminal(String agent, String commandId, TerminalState state, String message) {
        if (state == TerminalState.DONE) return;
        var rows = jdbc.queryForList("SELECT CAST(payload AS TEXT) AS payload FROM t_command WHERE cmd_id=? AND agent_id=? AND type IN ('baseline_check','vuln_scan')", commandId, agent);
        if (rows.size() != 1) return;
        Command command;
        long task;
        try {
            String encoded = JsonUtils.read(String.valueOf(rows.get(0).get("payload"))).path("command_b64").asText();
            if (encoded.length() > 8 * 1024 * 1024) return;
            command = Command.parseFrom(Base64.getDecoder().decode(encoded));
            if (!command.hasBaselineCheck() && !command.hasVulnScan()) return;
            task = Long.parseLong(command.hasBaselineCheck() ? command.getBaselineCheck().getTaskId() : command.getVulnScan().getTaskId());
            if (task <= 0 || !command.getCmdId().equals(commandId)) return;
        } catch (Exception invalid) { return; }
        // Table names come only from the parsed command kind. Never let a
        // receipt select an unrelated task or overwrite completion/cancellation.
        String table = command.hasBaselineCheck() ? "t_baseline_task" : "t_scan_task";
        var tasks = jdbc.queryForList("SELECT CAST(scope AS TEXT) AS scope FROM " + table + " WHERE id=?", task);
        if (tasks.size() != 1) return;
        try {
            var ids = JsonUtils.read(String.valueOf(tasks.get(0).get("scope"))).path("agent_ids");
            if (!ids.isArray()) return;
            boolean member = false;
            for (var id : ids) if (id.isTextual() && agent.equals(id.asText())) member = true;
            if (!member) return;
        } catch (RuntimeException invalid) { return; }
        if(command.hasVulnScan()) {
            jdbc.update("UPDATE t_scan_task SET progress=progress WHERE id=?",task);
            int updated=jdbc.update("UPDATE t_scan_task_agent SET state=?,weak_status=CASE WHEN weak_status='pending' THEN 'failed' ELSE weak_status END WHERE task_id=? AND agent_id=? AND command_id=? AND state='pending' AND evidence_sha256=''",state==TerminalState.TIMEOUT?"timeout":"failed",task,agent,commandId);
            if(updated>0 || jdbc.queryForObject("SELECT count(*) FROM t_scan_task_agent WHERE task_id=?",Integer.class,task)>0) {
                com.alinksec.service.scan.ScanResultService.advanceProgress(jdbc,task);return;
            }
        }
        jdbc.update("UPDATE " + table + " SET status=3,finished_at=CURRENT_TIMESTAMP WHERE id=? AND status IN (0,1)", task);
    }
}
