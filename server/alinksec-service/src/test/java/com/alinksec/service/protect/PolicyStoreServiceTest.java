package com.alinksec.service.protect;

import com.alinksec.common.util.JsonUtils;
import com.alinksec.service.command.CommandService;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class PolicyStoreServiceTest {
    @Test
    void aggregatesTypedProtectionRulesAndKeepsDisabledRulesForHotUpdates() {
        JdbcTemplate jdbc = mock(JdbcTemplate.class);
        when(jdbc.queryForList(contains("type IN"))).thenReturn(List.of(
                Map.of("rule_id","PR-0002","name","file","type","file_integrity","match","{\"paths\":[\"/etc/passwd\"]}","actions","[\"alert\"]","severity",3,"enabled",false),
                Map.of("rule_id","PR-0003","name","SSH","type","login","match","{\"ssh_ports\":[22]}","actions","[\"alert\"]","severity",3,"enabled",true)));
        when(jdbc.queryForObject(startsWith("UPDATE t_policy_state"), eq(Long.class), anyString())).thenReturn(2L);
        when(jdbc.queryForObject(startsWith("SELECT version"),eq(Long.class))).thenReturn(2L);
        when(jdbc.queryForObject(startsWith("SELECT CAST"),eq(String.class))).thenReturn("{}");
        new PolicyStoreService(jdbc,mock(CommandService.class)).rebuild();
        var snapshot = org.mockito.ArgumentCaptor.forClass(String.class);
        verify(jdbc).queryForObject(startsWith("UPDATE t_policy_state"),eq(Long.class),snapshot.capture());
        var json = JsonUtils.read(snapshot.getValue());
        assertEquals("PR-0002",json.path("file_rules").get(0).path("id").asText());
        assertFalse(json.path("file_rules").get(0).path("enabled").asBoolean());
        assertEquals("PR-0003",json.path("login_rules").get(0).path("id").asText());
        assertTrue(json.path("process_rules").isArray());
    }
}
