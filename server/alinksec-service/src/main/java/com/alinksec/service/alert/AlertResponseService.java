package com.alinksec.service.alert;

import com.alinksec.common.util.JsonUtils;
import com.alinksec.proto.CmdProtectAction;
import com.alinksec.proto.Command;
import com.alinksec.service.command.CommandService;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Explicit host actions with immutable alert evidence; acknowledgement is separate. */
@Service
public class AlertResponseService {
    private final JdbcTemplate jdbc;
    private final CommandService commands;
    public AlertResponseService(JdbcTemplate jdbc, CommandService commands) { this.jdbc=jdbc; this.commands=commands; }

    @Transactional
    public Map<String,Object> dispatch(long alertId, String action, Long user) {
        if (!Set.of("isolate", "restore").contains(action == null ? "" : action)) throw new IllegalArgumentException("仅支持明确的主机隔离或解除隔离");
        var rows=jdbc.queryForList("""
            SELECT t.id,t.agent_id,t.event_type,t.title,CAST(t.detail AS TEXT) AS detail,t.action_taken,t.last_time,
                   a.hostname,a.status,a.isolation_contract,a.isolation_status
            FROM t_alert t JOIN t_agent a ON a.agent_id=t.agent_id
            WHERE t.id=? AND t.status<>9 AND a.deleted=false AND a.status<>4
            """,alertId);
        if (rows.size()!=1) throw new IllegalArgumentException("告警或关联主机不存在");
        var evidence=rows.getFirst();String agent=String.valueOf(evidence.get("agent_id"));
        if (((Number)evidence.get("status")).intValue()!=1) throw new IllegalArgumentException("主机离线或未激活，未下发安全动作");
        if (((Number)evidence.get("isolation_contract")).intValue()!=1) throw new IllegalArgumentException("主机未声明受支持的安全隔离能力");
        int state=((Number)evidence.get("isolation_status")).intValue();
        if (action.equals("isolate") ? !Set.of(0,4).contains(state) : !Set.of(1,2,4,5,6).contains(state)) throw new IllegalArgumentException("主机当前隔离状态不允许此操作，请刷新");
        String command=commands.dispatchAfterCommit(agent,Command.newBuilder().setProtectAction(CmdProtectAction.newBuilder()
            .setAction(action.equals("isolate")?CmdProtectAction.Action.ISOLATE_HOST:CmdProtectAction.Action.RESTORE_ISOLATION)
            .setIsolationContract(1).setReason("告警 #"+alertId+" 的显式主机响应："+action)),user);
        jdbc.update("INSERT INTO t_alert_response(alert_id,agent_id,command_id,action,evidence,created_by) VALUES(?,?,?,?,?,?)",
            alertId,agent,command,action,JsonUtils.write(evidence),user);
        return Map.of("commandId",command,"agentId",agent,"state","pending");
    }

    public Map<String,Object> list(long alertId,int page) {
        List<Map<String,Object>> rows=jdbc.queryForList("""
            SELECT r.command_id,r.agent_id,r.action,r.evidence,r.created_at,c.status AS command_status,c.result,
                   a.hostname,a.status AS host_status,a.isolation_status,a.isolation_error,a.isolation_seen_at,
                   a.isolation_lease_command_id,a.isolation_command_id
            FROM t_alert_response r LEFT JOIN t_command c ON c.cmd_id=r.command_id
            LEFT JOIN t_agent a ON a.agent_id=r.agent_id WHERE r.alert_id=?
            ORDER BY r.created_at DESC,r.command_id DESC LIMIT 20 OFFSET ?
            """,alertId,(Math.max(page,1)-1)*20);
        return Map.of("total",jdbc.queryForObject("SELECT count(*) FROM t_alert_response WHERE alert_id=?",Long.class,alertId),"list",rows);
    }
}
