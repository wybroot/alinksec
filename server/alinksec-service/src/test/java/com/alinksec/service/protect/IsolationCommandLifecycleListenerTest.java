package com.alinksec.service.protect;

import com.alinksec.proto.CmdProtectAction;
import com.alinksec.proto.Command;
import com.alinksec.service.command.CommandLifecycleListener;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.jdbc.core.JdbcTemplate;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class IsolationCommandLifecycleListenerTest {

    @Test
    void isolateDispatchStartsTrackedTransition() {
        JdbcTemplate jdbc = mock(JdbcTemplate.class);
        when(jdbc.update(org.mockito.ArgumentMatchers.anyString(),
                eq(IsolationCommandLifecycleListener.ISOLATING), eq("cmd-1"), eq("agent-1"),
                eq(IsolationCommandLifecycleListener.NORMAL),
                eq(IsolationCommandLifecycleListener.ISOLATE_FAILED))).thenReturn(1);
        IsolationCommandLifecycleListener listener = new IsolationCommandLifecycleListener(jdbc);

        listener.onDispatched("agent-1", command("cmd-1", CmdProtectAction.Action.ISOLATE_HOST));

        ArgumentCaptor<String> sql = ArgumentCaptor.forClass(String.class);
        verify(jdbc).update(sql.capture(), eq(IsolationCommandLifecycleListener.ISOLATING),
                eq("cmd-1"), eq("agent-1"), eq(IsolationCommandLifecycleListener.NORMAL),
                eq(IsolationCommandLifecycleListener.ISOLATE_FAILED));
        assertTrue(sql.getValue().contains("isolation_command_id = ?"));
        assertTrue(sql.getValue().contains("isolation_status IN (?, ?)"));
    }

    @Test
    void staleOrConcurrentTransitionIsRejected() {
        JdbcTemplate jdbc = mock(JdbcTemplate.class);
        IsolationCommandLifecycleListener listener = new IsolationCommandLifecycleListener(jdbc);

        assertThrows(IllegalArgumentException.class,
                () -> listener.onDispatched("agent-1",
                        command("cmd-2", CmdProtectAction.Action.RESTORE_ISOLATION)));
    }

    @Test
    void doneAckCompletesOnlyItsTrackedIsolationCommand() {
        JdbcTemplate jdbc = mock(JdbcTemplate.class);
        IsolationCommandLifecycleListener listener = new IsolationCommandLifecycleListener(jdbc);

        listener.onTerminal("agent-1", "cmd-1", CommandLifecycleListener.TerminalState.DONE, "ok");

        ArgumentCaptor<String> sql = ArgumentCaptor.forClass(String.class);
        verify(jdbc).update(sql.capture(), eq(IsolationCommandLifecycleListener.ISOLATED),
                org.mockito.ArgumentMatchers.isNull(), eq("agent-1"), eq("cmd-1"),
                eq(IsolationCommandLifecycleListener.ISOLATING));
        assertTrue(sql.getValue().contains("isolation_command_id = ?"));
    }

    @Test
    void timeoutKeepsRestoreFailureDistinctFromConnectivity() {
        JdbcTemplate jdbc = mock(JdbcTemplate.class);
        IsolationCommandLifecycleListener listener = new IsolationCommandLifecycleListener(jdbc);

        listener.onTerminal("agent-1", "cmd-2", CommandLifecycleListener.TerminalState.TIMEOUT,
                "指令 ACK 超时");

        verify(jdbc).update(org.mockito.ArgumentMatchers.anyString(),
                eq(IsolationCommandLifecycleListener.RESTORE_FAILED), eq("指令 ACK 超时"),
                eq("agent-1"), eq("cmd-2"), eq(IsolationCommandLifecycleListener.RESTORING));
    }

    private static Command command(String cmdId, CmdProtectAction.Action action) {
        return Command.newBuilder()
                .setCmdId(cmdId)
                .setProtectAction(CmdProtectAction.newBuilder().setAction(action))
                .build();
    }
}
