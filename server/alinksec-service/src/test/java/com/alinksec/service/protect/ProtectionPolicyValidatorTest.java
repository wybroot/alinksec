package com.alinksec.service.protect;

import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

class ProtectionPolicyValidatorTest {
    @Test
    void acceptsBoundedLinuxFileAndSshRules() {
        assertDoesNotThrow(() -> ProtectionPolicyValidator.validate("file_integrity", Map.of("paths", List.of("/etc/passwd"), "max_file_bytes", 1048576), List.of("alert", "restore")));
        assertDoesNotThrow(() -> ProtectionPolicyValidator.validate("login", Map.of("trusted_ips", List.of("192.0.2.0/24", "2001:db8::/32", "::ffff:192.0.2.0/120"), "timezone", "Asia/Shanghai", "ssh_ports", List.of(22,2222)), List.of("alert", "block_ip")));
    }

    @Test
    void rejectsInvalidLimitsPathsResponsesAndNonliteralNetworks() {
        for (Map<String,Object> config : List.<Map<String,Object>>of(Map.of("paths", List.of("relative")), Map.of("paths", List.of()), Map.of("paths", List.of("/file"), "max_file_bytes", 1048577))) {
            assertThrows(IllegalArgumentException.class, () -> ProtectionPolicyValidator.validate("file_integrity", config, List.of("alert")));
        }
        for (Map<String,Object> config : List.<Map<String,Object>>of(Map.of("failure_threshold",1), Map.of("window_sec",0), Map.of("block_duration_sec",3601), Map.of("ssh_ports",List.of(0)), Map.of("trusted_ips",List.of("example.com")), Map.of("trusted_ips",List.of("127.1")), Map.of("trusted_ips",List.of("192.0.2.1/33")), Map.of("timezone",123), Map.of("timezone","unknown/zone"), Map.of("off_hours_enabled","true"))) {
            assertThrows(IllegalArgumentException.class, () -> ProtectionPolicyValidator.validate("login", config, List.of("alert")));
        }
        assertThrows(IllegalArgumentException.class, () -> ProtectionPolicyValidator.validate("login",Map.of(),List.of("restore")));
        assertThrows(IllegalArgumentException.class, () -> ProtectionPolicyValidator.validate("login",Map.of("trusted_ips",List.of("beef")),List.of("alert")));
        assertThrows(IllegalArgumentException.class, () -> ProtectionPolicyValidator.validate("login",Map.of("timezone","+08:00"),List.of("alert")));
    }

    @Test
    void invalidRuleUpdateDoesNotWriteOrRebuildThePolicy() {
        JdbcTemplate jdbc = mock(JdbcTemplate.class);
        PolicyStoreService policy = mock(PolicyStoreService.class);
        when(jdbc.queryForList(anyString(), eq("PR-0003"))).thenReturn(List.of(Map.of("type","login","match","{}","actions","[\"alert\"]")));
        ProtectRuleService service = new ProtectRuleService(jdbc, mock(com.alinksec.service.command.CommandService.class), policy);
        assertThrows(IllegalArgumentException.class, () -> service.updateRule("PR-0003",Map.of("match",Map.of("ssh_ports",List.of(0)))));
        verify(jdbc,never()).update(anyString(),any(Object[].class));
        verifyNoInteractions(policy);
    }
}
