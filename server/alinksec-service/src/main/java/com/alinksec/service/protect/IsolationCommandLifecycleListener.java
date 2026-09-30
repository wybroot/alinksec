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
            begin(agentId, command.getCmdId(), ISOLATING, NORMAL, ISOLATE_FAILED, "主机当前不可隔离");
        } else if (action == CmdProtectAction.Action.RESTORE_ISOLATION) {
            begin(agentId, command.getCmdId(), RESTORING, ISOLATED, RESTORE_FAILED, "主机当前未处于隔离状态");
        }
    }

    @Override
    public void onTerminal(String agentId, String cmdId, TerminalState state, String message) {
        if (state == TerminalState.DONE) {
            complete(agentId, cmdId, ISOLATING, ISOLATED, null);
            complete(agentId, cmdId, RESTORING, NORMAL, null);
            return;
        }
        String error = truncate(message == null || message.isBlank()
                ? (state == TerminalState.TIMEOUT ? "指令执行超时" : "Agent 执行失败")
                : message);
        complete(agentId, cmdId, ISOLATING, ISOLATE_FAILED, error);
        complete(agentId, cmdId, RESTORING, RESTORE_FAILED, error);
    }

    private void begin(String agentId, String cmdId, short target, short allowedA, short allowedB,
                       String invalidMessage) {
        int rows = jdbc.update("""
                UPDATE t_agent
                SET isolation_status = ?, isolation_command_id = ?, isolation_error = NULL,
                    isolation_updated_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
                WHERE agent_id = ? AND status <> 4 AND isolation_status IN (?, ?)
                """, target, cmdId, agentId, allowedA, allowedB);
        if (rows == 0) {
            throw new IllegalArgumentException(invalidMessage);
        }
    }

    private void complete(String agentId, String cmdId, short expected, short target, String error) {
        jdbc.update("""
                UPDATE t_agent
                SET isolation_status = ?, isolation_command_id = NULL, isolation_error = ?,
                    isolation_updated_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
                WHERE agent_id = ? AND isolation_command_id = ? AND isolation_status = ?
                """, target, error, agentId, cmdId, expected);
    }

    private static String truncate(String value) {
        return value.length() <= 512 ? value : value.substring(0, 512);
    }
}
