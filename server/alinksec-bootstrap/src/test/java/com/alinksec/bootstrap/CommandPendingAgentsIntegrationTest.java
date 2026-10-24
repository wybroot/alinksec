package com.alinksec.bootstrap;

import com.alinksec.service.command.CommandRepository;
import com.alinksec.service.config.AlinkSecProperties;
import com.alinksec.service.config.DatabaseDialect;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.SingleConnectionDataSource;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

class CommandPendingAgentsIntegrationTest {
    @Test void batchLookupExcludesOtherOwnersAndTerminalCommandsAndBoundsParameters() {
        var source=new SingleConnectionDataSource("jdbc:sqlite::memory:",true);
        try {
            var jdbc=new JdbcTemplate(source);
            jdbc.execute("CREATE TABLE t_command(agent_id TEXT,status INTEGER)");
            jdbc.execute("CREATE INDEX idx_cmd_agent_status ON t_command(agent_id,status)");
            jdbc.update("INSERT INTO t_command VALUES ('local-a',0),('local-a',0),('local-b',0),('other-owner',0),('completed',4),('sent',1)");
            var repository=new CommandRepository(jdbc,new DatabaseDialect(new AlinkSecProperties()));
            assertEquals(List.of("local-a","local-b"),repository.findPendingAgents(List.of("local-b","completed","local-a","sent")));
            assertEquals(List.of(),repository.findPendingAgents(List.of()));
            // Parameters remain values even if an authenticated id is malformed.
            assertEquals(List.of(),repository.findPendingAgents(List.of("') OR 1=1 --")));
            assertThrows(IllegalArgumentException.class,()->repository.findPendingAgents(java.util.Collections.nCopies(257,"local-a")));
        } finally { source.destroy(); }
    }
}
