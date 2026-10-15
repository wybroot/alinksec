package com.alinksec.service.fix;

import com.alinksec.service.config.AlinkSecProperties;
import com.alinksec.service.config.DatabaseDialect;
import com.alinksec.service.command.CommandService;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class FixTaskServiceTest {

    @Test
    void rejectsDuplicateFindingBeforeQueryingDatabase() {
        JdbcTemplate jdbc = mock(JdbcTemplate.class);
        FixTaskService service = new FixTaskService(jdbc, mock(CommandService.class), mock(PatchRepoService.class), database(), mock(org.springframework.transaction.PlatformTransactionManager.class));
        Map<String, Object> item = Map.of("agentId", "agent-a", "findingId", 11);

        assertThrows(IllegalArgumentException.class, () ->
                service.createPackageTask(null, List.of(item, item), "admin", null, null, 7L));

        verifyNoInteractions(jdbc);
    }

    @Test
    void rejectsAlreadyHandledFinding() {
        JdbcTemplate jdbc = mock(JdbcTemplate.class);
        PatchRepoService patches = mock(PatchRepoService.class);
        FixTaskService service = new FixTaskService(jdbc, mock(CommandService.class), patches, database(), mock(org.springframework.transaction.PlatformTransactionManager.class));
        when(jdbc.queryForList(org.mockito.ArgumentMatchers.contains("WHERE u.id=?"), org.mockito.ArgumentMatchers.eq(7L)))
                .thenReturn(List.of(Map.of("username","admin")));
        when(jdbc.queryForList(org.mockito.ArgumentMatchers.contains("WHERE u.username=?"), org.mockito.ArgumentMatchers.eq("admin")))
                .thenReturn(List.of(Map.of("id",7L,"username","admin")));
        when(jdbc.queryForList(org.mockito.ArgumentMatchers.contains("WHERE f.id IN"), org.mockito.ArgumentMatchers.eq(11L)))
                .thenReturn(List.of(Map.of("id",11L,"agent_id","agent-a","status",3,"current_match",true)));

        var error = assertThrows(IllegalArgumentException.class, () ->
                service.createPackageTask(null,
                        List.of(Map.of("agentId", "agent-a", "findingId", 11)),
                        "admin", null, null, 7L));

        org.junit.jupiter.api.Assertions.assertTrue(error.getMessage().contains("已处置"));
        verifyNoInteractions(patches);
    }

    private static DatabaseDialect database() {
        return new DatabaseDialect(new AlinkSecProperties());
    }
}
