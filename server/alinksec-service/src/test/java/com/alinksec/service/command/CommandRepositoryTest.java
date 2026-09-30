package com.alinksec.service.command;

import com.alinksec.proto.RptAck;
import com.alinksec.service.config.AlinkSecProperties;
import com.alinksec.service.config.DatabaseDialect;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.jdbc.core.JdbcTemplate;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class CommandRepositoryTest {

    @Test
    void timeoutOnlyUpdatesCommandsThatAreStillSent() {
        JdbcTemplate jdbc = mock(JdbcTemplate.class);
        CommandRepository repository = new CommandRepository(jdbc, database());

        repository.markTimeout("command-a");

        ArgumentCaptor<String> sql = ArgumentCaptor.forClass(String.class);
        verify(jdbc).update(sql.capture(), org.mockito.ArgumentMatchers.eq(CommandRepository.ST_TIMEOUT),
                org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.eq("command-a"),
                org.mockito.ArgumentMatchers.eq(CommandRepository.ST_SENT));
        assertTrue(sql.getValue().contains("status = ?"));
    }

    @Test
    void receivedAckIsScopedToAuthenticatedAgent() {
        JdbcTemplate jdbc = mock(JdbcTemplate.class);
        CommandRepository repository = new CommandRepository(jdbc, database());
        RptAck ack = RptAck.newBuilder().setCmdId("command-b").setStage(RptAck.Stage.RECEIVED).build();

        repository.onAck("agent-a", ack);

        ArgumentCaptor<String> sql = ArgumentCaptor.forClass(String.class);
        verify(jdbc).update(sql.capture(), org.mockito.ArgumentMatchers.eq(CommandRepository.ST_RECEIVED),
                org.mockito.ArgumentMatchers.eq("command-b"), org.mockito.ArgumentMatchers.eq("agent-a"));
        assertTrue(sql.getValue().contains("cmd_id = ? AND agent_id = ?"));
    }

    @Test
    void terminalAckIsScopedToAuthenticatedAgent() {
        JdbcTemplate jdbc = mock(JdbcTemplate.class);
        CommandRepository repository = new CommandRepository(jdbc, database());
        RptAck ack = RptAck.newBuilder().setCmdId("command-b").setStage(RptAck.Stage.DONE).build();

        repository.onAck("agent-a", ack);

        ArgumentCaptor<String> sql = ArgumentCaptor.forClass(String.class);
        verify(jdbc).update(sql.capture(), org.mockito.ArgumentMatchers.eq(CommandRepository.ST_DONE),
                org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.eq("command-b"),
                org.mockito.ArgumentMatchers.eq("agent-a"));
        assertTrue(sql.getValue().contains("cmd_id = ? AND agent_id = ?"));
    }

    private static DatabaseDialect database() {
        return new DatabaseDialect(new AlinkSecProperties());
    }
}
