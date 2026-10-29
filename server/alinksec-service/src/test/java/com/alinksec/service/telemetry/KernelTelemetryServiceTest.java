package com.alinksec.service.telemetry;

import com.alinksec.proto.RptSecurityEvent;
import com.alinksec.service.alert.SecurityEventService;
import com.alinksec.service.config.AlinkSecProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class KernelTelemetryServiceTest {

    private SecurityEventService securityEventService;
    private AlinkSecProperties properties;
    private JdbcTemplate jdbc;
    private KernelTelemetryService service;

    @BeforeEach
    void setUp() {
        securityEventService = mock(SecurityEventService.class);
        properties = new AlinkSecProperties();
        jdbc = mock(JdbcTemplate.class);
        service = new KernelTelemetryService(securityEventService, properties, jdbc);
    }

    @Test
    void testIngestFalcoEventSuccess() {
        String falcoJson = """
                {
                    "output": "15:20:30.123456 Notice Shell spawned in container (user=root container_id=c123456789ab container_name=web-app image=nginx:latest cmdline=bash)",
                    "priority": "Notice",
                    "rule": "Terminal shell in container",
                    "time": "2026-10-29T15:20:30.123456789Z",
                    "output_fields": {
                        "container.id": "c123456789ab",
                        "container.name": "web-app",
                        "container.image.repository": "nginx:latest",
                        "proc.cmdline": "bash",
                        "proc.name": "bash",
                        "proc.pid": 1234,
                        "nodename": "node-k8s-01"
                    },
                    "tags": ["container", "mitre_execution", "T1059"]
                }
                """;

        when(jdbc.queryForList(anyString(), eq(String.class), eq("node-k8s-01"), eq("node-k8s-01")))
                .thenReturn(List.of("AGT-NODE-01"));

        boolean result = service.ingestFalcoEvent(falcoJson);
        assertTrue(result);

        ArgumentCaptor<String> agentCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<RptSecurityEvent> eventCaptor = ArgumentCaptor.forClass(RptSecurityEvent.class);

        verify(securityEventService, times(1)).onEvent(agentCaptor.capture(), eventCaptor.capture());
        assertEquals("AGT-NODE-01", agentCaptor.getValue());

        RptSecurityEvent event = eventCaptor.getValue();
        assertEquals("process", event.getType());
        assertEquals("falco-terminal-shell-in-container", event.getRuleId());
        assertEquals("Falco: Terminal shell in container", event.getRuleName());
        assertEquals(2, event.getSeverityValue()); // Notice -> 2 (medium)
        assertTrue(event.getDetail().contains("falco_ebpf"));
        assertTrue(event.getDetail().contains("c123456789ab"));
        assertTrue(event.getDetail().contains("T1059"));
    }

    @Test
    void testIngestElkeidPrivilegeEscalationEvent() {
        String elkeidJson = """
                {
                    "data_type": 604,
                    "exe": "/tmp/exp",
                    "pid": 4567,
                    "ppid": 1000,
                    "uid": 1001,
                    "nodename": "db-server-01",
                    "pid_tree": "1:systemd -> 1000:bash -> 4567:exp"
                }
                """;

        when(jdbc.queryForList(anyString(), eq(String.class), eq("db-server-01"), eq("db-server-01")))
                .thenReturn(List.of("AGT-DB-01"));

        boolean result = service.ingestElkeidEvent(elkeidJson);
        assertTrue(result);

        ArgumentCaptor<String> agentCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<RptSecurityEvent> eventCaptor = ArgumentCaptor.forClass(RptSecurityEvent.class);

        verify(securityEventService, times(1)).onEvent(agentCaptor.capture(), eventCaptor.capture());
        assertEquals("AGT-DB-01", agentCaptor.getValue());

        RptSecurityEvent event = eventCaptor.getValue();
        assertEquals(4, event.getSeverityValue()); // 604 update_cred -> critical (4)
        assertEquals("Elkeid: Privilege Escalation (update_cred)", event.getRuleName());
        assertTrue(event.getDetail().contains("1:systemd -> 1000:bash -> 4567:exp"));
    }

    @Test
    void testTelemetryHealthDisabledByDefault() {
        properties.getTelemetry().setEnabled(false);
        Map<String, Object> health = service.getTelemetryHealth();
        assertEquals("disabled", health.get("status"));
        assertTrue(health.get("message").toString().contains("未启用"));
    }

    @Test
    void testTelemetryHealthActiveWhenEnabledAndEventsArrived() {
        properties.getTelemetry().setEnabled(true);
        service.ingestFalcoEvent("{\"rule\":\"test_rule\",\"priority\":\"INFO\",\"output_fields\":{}}");

        Map<String, Object> health = service.getTelemetryHealth();
        assertEquals("healthy", health.get("status"));
        @SuppressWarnings("unchecked")
        Map<String, Object> probes = (Map<String, Object>) health.get("probes");
        assertTrue(probes.containsKey("falco"));
    }
}
