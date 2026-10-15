package com.alinksec.service.protect;

import com.alinksec.proto.CmdProtectAction;
import com.alinksec.proto.Command;
import com.alinksec.service.command.CommandLifecycleListener;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

/** Persists host isolation independently from the Agent online/offline status. */
@Component
public class IsolationCommandLifecycleListener implements CommandLifecycleListener {

    public static final short NORMAL = 0;
    public static final short ISOLATING = 1;
    public static final short ISOLATED = 2;
    public static final short RESTORING = 3;
    public static final short ISOLATE_FAILED = 4;
    public static final short RESTORE_FAILED = 5;
    public static final short UNKNOWN = 6;

    private final JdbcTemplate jdbc;

    public IsolationCommandLifecycleListener(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @Override
    public void onDispatched(String agentId, Command command) {
        if (command.getPayloadCase() != Command.PayloadCase.PROTECT_ACTION) {
            return;
        }
        CmdProtectAction.Action action = command.getProtectAction().getAction();
        if (action == CmdProtectAction.Action.ISOLATE_HOST) {
            requireContract(agentId,command);
            begin(agentId, command.getCmdId(), ISOLATING, NORMAL, ISOLATE_FAILED, "主机当前不可隔离");
        } else if (action == CmdProtectAction.Action.RESTORE_ISOLATION) {
            safeRestore(agentId,command);
            begin(agentId, command.getCmdId(), RESTORING, ISOLATED, RESTORE_FAILED, "主机当前未处于隔离状态");
        }
    }

    private Command safeRestore(String agentId,Command command) {
        var rows=jdbc.queryForList("SELECT os_type,isolation_contract,isolation_generation FROM t_agent WHERE agent_id=? AND deleted=false AND status<>4",agentId);
        if(rows.size()!=1) throw new IllegalArgumentException("主机不存在或已禁用");
        var host=rows.getFirst();
        int contract=((Number)host.get("isolation_contract")).intValue();
        if(contract!=1 && (((Number)host.get("os_type")).intValue()==2 || ((Number)host.get("isolation_generation")).longValue()>0))
            throw new IllegalArgumentException("当前 Agent 无法安全确认隔离恢复；请恢复支持隔离契约的原生服务，旧版 Windows 隔离需管理员核对原防火墙策略");
        return command.toBuilder().setProtectAction(command.getProtectAction().toBuilder().setIsolationContract(contract==1?1:0)).build();
    }

    private void requireContract(String agentId,Command command) {
        Integer available=jdbc.queryForObject("SELECT count(*) FROM t_agent WHERE agent_id=? AND deleted=false AND status<>4 AND isolation_contract=1",Integer.class,agentId);
        if(command.getProtectAction().getIsolationContract()!=1 || available==null || available!=1)
            throw new IllegalArgumentException("主机需要支持失联自动撤销的原生 Agent 隔离契约 1；请先升级并连接原生服务");
    }
    @Override public Command prepareDelivery(String agentId,Command command) {
        if(command.hasProtectAction() && command.getProtectAction().getAction()==CmdProtectAction.Action.ISOLATE_HOST) requireContract(agentId,command);
        if(command.hasProtectAction() && command.getProtectAction().getAction()==CmdProtectAction.Action.RESTORE_ISOLATION) return safeRestore(agentId,command);
        return command;
    }

    @Override
    public void onTerminal(String agentId, String cmdId, TerminalState state, String message) {
        if (state == TerminalState.DONE) {
            complete(agentId, cmdId, ISOLATING, ISOLATED, null, true);
            complete(agentId, cmdId, RESTORING, NORMAL, null, true);
            return;
        }
        String error = truncate(message == null || message.isBlank()
                ? (state == TerminalState.TIMEOUT ? "指令执行超时" : "Agent 执行失败")
                : message);
        complete(agentId, cmdId, ISOLATING, ISOLATE_FAILED, error, false);
        complete(agentId, cmdId, RESTORING, RESTORE_FAILED, error, false);
    }

    private void begin(String agentId, String cmdId, short target, short allowedA, short allowedB,
                       String invalidMessage) {
        if(target==ISOLATING) {
            int rows=jdbc.update("""
                UPDATE t_agent SET isolation_status=?,isolation_command_id=?,isolation_lease_command_id=?,
                    isolation_error=NULL,isolation_automatic=false,isolation_seen_at=NULL,isolation_updated_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP
                WHERE agent_id=? AND deleted=false AND status<>4 AND isolation_contract=1 AND isolation_status IN (0,4)
                """,target,cmdId,cmdId,agentId);
            if(rows==0) throw new IllegalArgumentException(invalidMessage);
            return;
        }
        int rows = jdbc.update("""
                UPDATE t_agent
                SET isolation_status = ?, isolation_command_id = ?, isolation_error = NULL,
                    isolation_updated_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
                WHERE agent_id = ? AND status <> 4 AND isolation_status IN (?, ?, 1, 4, 6)
                """, target, cmdId, agentId, allowedA, allowedB);
        if (rows == 0) {
            throw new IllegalArgumentException(invalidMessage);
        }
    }

    private void complete(String agentId, String cmdId, short expected, short target, String error, boolean legacyOnly) {
        jdbc.update("""
                UPDATE t_agent
                SET isolation_status = ?, isolation_command_id = NULL, isolation_error = ?,
                    isolation_updated_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
                WHERE agent_id = ? AND isolation_command_id = ? AND isolation_status = ?
                """ + (legacyOnly?" AND isolation_contract<>1":""), target, error, agentId, cmdId, expected);
    }

    private static String truncate(String value) {
        return value.length() <= 512 ? value : value.substring(0, 512);
    }
}
