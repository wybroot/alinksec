package com.alinksec.service.alert;

import com.alinksec.common.util.JsonUtils;
import com.alinksec.proto.RptSecurityEvent;
import com.alinksec.proto.Severity;
import com.alinksec.service.notify.NotifyService;
import com.alinksec.service.config.AlinkSecProperties;
import com.alinksec.service.config.DatabaseDialect;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.jdbc.core.JdbcTemplate;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class SecurityEventServiceTest {

    @Mock private JdbcTemplate jdbc;
    @Mock private NotifyService notifyService;

    @Test
    void processEventsUseTheProcessInstanceKeyForAggregation() {
        SecurityEventService service = new SecurityEventService(jdbc, notifyService, database());
        RptSecurityEvent event = RptSecurityEvent.newBuilder()
                .setRuleId("PR-0001")
                .setRuleName("EDR miner process block")
                .setType("process")
                .setSeverity(Severity.SEV_CRITICAL)
                .setDetail(JsonUtils.write(java.util.Map.of("process_key", "4321:1720000000000")))
                .build();

        service.onEvent("agent-1", event);

        ArgumentCaptor<String> fingerprint = ArgumentCaptor.forClass(String.class);
        verify(jdbc).update(org.mockito.ArgumentMatchers.startsWith("UPDATE t_alert"), any(String.class),
                eq(""), eq("agent-1"), eq("PR-0001"), fingerprint.capture());
        assertEquals("process:PR-0001:4321:1720000000000", fingerprint.getValue());
    }

    @Test
    void legacyProcessEventsKeepTheRuleLevelAggregationKey() {
        SecurityEventService service = new SecurityEventService(jdbc, notifyService, database());
        RptSecurityEvent event = RptSecurityEvent.newBuilder()
                .setRuleId("PR-0001")
                .setType("process")
                .setSeverity(Severity.SEV_HIGH)
                .setDetail("{}")
                .build();

        service.onEvent("agent-1", event);

        ArgumentCaptor<String> fingerprint = ArgumentCaptor.forClass(String.class);
        verify(jdbc).update(org.mockito.ArgumentMatchers.startsWith("UPDATE t_alert"), any(String.class),
                eq(""), eq("agent-1"), eq("PR-0001"), fingerprint.capture());
        assertEquals("process:PR-0001", fingerprint.getValue());
    }

    private static DatabaseDialect database() {
        return new DatabaseDialect(new AlinkSecProperties());
    }

    @Test
    void fileAndLoginEventsUseTheirTargetAndPreserveFingerprintAndLatestAction() {
        for (String type : java.util.List.of("file_tamper", "login_crack", "login_anomaly")) {
            JdbcTemplate targetJdbc = org.mockito.Mockito.mock(JdbcTemplate.class);
            String key = type.equals("file_tamper") ? "path" : "source_ip";
            String value = type.equals("file_tamper") ? "/etc/passwd" : "203.0.113.8";
            String expected = type + ":PR-test:" + value;
            SecurityEventService service = new SecurityEventService(targetJdbc, notifyService, database());
            service.onEvent("agent-1", RptSecurityEvent.newBuilder().setRuleId("PR-test").setType(type)
                    .setSeverity(Severity.SEV_HIGH).setDetail(JsonUtils.write(java.util.Map.of(key, value)))
                    .setActionTaken("restored").build());
            ArgumentCaptor<String> detail = ArgumentCaptor.forClass(String.class);
            verify(targetJdbc).update(org.mockito.ArgumentMatchers.startsWith("UPDATE t_alert"), detail.capture(),
                    eq("restored"), eq("agent-1"), eq("PR-test"), eq(expected));
            assertEquals(expected, JsonUtils.read(detail.getValue()).path("fingerprint").asText());
            assertEquals(value, JsonUtils.read(detail.getValue()).path(key).asText());
        }
    }
}
