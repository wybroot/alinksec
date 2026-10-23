package com.alinksec.service.evidence;

import com.alinksec.proto.Command;
import com.alinksec.service.command.CommandLifecycleListener;
import com.alinksec.service.config.DatabaseDialect;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import java.time.Duration;

@Component
public class EvidenceCommandGuard implements CommandLifecycleListener {
    private final JdbcTemplate jdbc;
    private final DatabaseDialect database;
    public EvidenceCommandGuard(JdbcTemplate jdbc,DatabaseDialect database){this.jdbc=jdbc;this.database=database;}
    @Override public Command prepareDelivery(String agent,Command command) {
        if(!command.hasEvidenceCollect())return command;
        var request=command.getEvidenceCollect();
        var rows=jdbc.queryForList("SELECT * FROM t_evidence_request WHERE id=? AND command_id=? AND agent_id=? AND state='pending'",request.getRequestId(),command.getCmdId(),agent);
        if(rows.size()!=1)throw new IllegalArgumentException("取证请求已结束或不存在");
        var row=rows.getFirst();EvidenceService.admin(jdbc,((Number)row.get("actor")).longValue());
        if(((Number)row.get("deadline")).longValue()<=System.currentTimeMillis() || request.getDeadline()!=((Number)row.get("deadline")).longValue()
                || request.getExecutionContract()!=1 || !row.get("kind").equals(request.getKind()) || !row.get("original_path").equals(request.getOriginalPath())
                || !row.get("quarantine_id").equals(request.getQuarantineId()) || !row.get("expected_sha256").equals(request.getExpectedSha256()))throw new IllegalArgumentException("取证请求已过期或内容已变化");
        if(jdbc.queryForObject("SELECT COUNT(*) FROM t_agent WHERE agent_id=? AND status=1 AND deleted=false AND evidence_contract=1 AND last_heartbeat>=?",Integer.class,agent,database.timestampBefore(Duration.ofMinutes(2)))!=1)throw new IllegalArgumentException("Agent 取证能力或在线状态已变化");
        if(request.getKind().equals("quarantine_sample") && jdbc.queryForObject("SELECT COUNT(*) FROM t_virus_finding WHERE id=? AND agent_id=? AND status=1 AND quarantine_id=? AND path=? AND sha256=?",Integer.class,
                row.get("finding_id"),agent,request.getQuarantineId(),request.getOriginalPath(),request.getExpectedSha256())!=1)throw new IllegalArgumentException("隔离样本已变化");
        return command;
    }
    @Override public void onTerminal(String agent,String command,TerminalState state,String message) {
        if(state==TerminalState.DONE)return; // ACK never proves file collection.
        if(jdbc.queryForObject("SELECT COUNT(*) FROM t_evidence_request WHERE command_id=? AND agent_id=? AND state='pending'",Integer.class,command,agent)==0)return;
        EvidenceService.gate(jdbc);
        jdbc.update("UPDATE t_evidence_request SET state='failed',error_code=? WHERE agent_id=? AND command_id=? AND state='pending'",
                state==TerminalState.TIMEOUT?"command_timeout":"command_failed",agent,command);
    }
}
