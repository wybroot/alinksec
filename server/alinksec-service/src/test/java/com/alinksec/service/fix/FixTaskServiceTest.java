package com.alinksec.service.fix;

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
        FixTaskService service = new FixTaskService(jdbc, mock(CommandService.class), mock(PatchRepoService.class));
        Map<String, Object> item = Map.of("agentId", "agent-a", "findingId", 11);

        assertThrows(IllegalArgumentException.class, () ->
                service.createPackageTask(null, List.of(item, item), "admin", null, null, 7L));

        verifyNoInteractions(jdbc);
    }

    @Test
    void rejectsAlreadyHandledFinding() {
        JdbcTemplate jdbc = mock(JdbcTemplate.class);
        PatchRepoService patches = mock(PatchRepoService.class);
        FixTaskService service = new FixTaskService(jdbc, mock(CommandService.class), patches);
        when(jdbc.queryForList(anyString(), anyString())).thenReturn(List.of(
                Map.of("id", 11L, "agent_id", "agent-a", "status", 3)));

        assertThrows(IllegalArgumentException.class, () ->
                service.createPackageTask(null,
                        List.of(Map.of("agentId", "agent-a", "findingId", 11)),
                        "admin", null, null, 7L));

        verifyNoInteractions(patches);
    }
}
