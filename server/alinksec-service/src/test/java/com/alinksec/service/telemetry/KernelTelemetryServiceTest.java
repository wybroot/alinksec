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
        assertEquals(3, event.getSeverityValue()); // Notice -> 3 (medium)
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
        assertEquals(5, event.getSeverityValue()); // 604 update_cred -> critical (5)
        assertEquals("Elkeid: Privilege Escalation (update_cred)", event.getRuleName());
        assertTrue(event.getDetail().contains("1:systemd -> 1000:bash -> 4567:exp"));
    }

    @Test
    void testFalcoStandardHostnameAndHostSentinel() {
        // R71: 顶层 hostname; R74: container.id = "host" 哨兵应判定为 host 宿主机事件
        String falcoJson = """
                {
                    "hostname": "prod-worker-99",
                    "priority": "Warning",
                    "rule": "Write below etc",
                    "output_fields": {
                        "container.id": "host",
                        "proc.name": "touch",
                        "proc.pid": 9876
                    }
                }
                """;
        when(jdbc.queryForList(anyString(), eq(String.class), eq("prod-worker-99"), eq("prod-worker-99")))
                .thenReturn(List.of("AGT-PROD-99"));

        assertTrue(service.ingestFalcoEvent(falcoJson));

        ArgumentCaptor<String> agentCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<RptSecurityEvent> eventCaptor = ArgumentCaptor.forClass(RptSecurityEvent.class);
        verify(securityEventService, atLeastOnce()).onEvent(agentCaptor.capture(), eventCaptor.capture());

        assertEquals("AGT-PROD-99", agentCaptor.getValue());
        RptSecurityEvent event = eventCaptor.getValue();
        assertTrue(event.getDetail().contains("\"container_status\":\"host\""));
        assertTrue(event.getDetail().contains("\"in_container\":false"));
        assertTrue(event.getDetail().contains("\"host_bound\":true"));
    }

    @Test
    void testElkeidConnectTelemetryFieldPreservation() {
        // R72: 保全 dip/dport/sip/sport/res; R75: 日常网络遥测置为 telemetry_only
        String connectJson = """
                {
                    "data_type": 42,
                    "nodename": "gw-01",
                    "exe": "/usr/bin/curl",
                    "pid": 2048,
                    "sip": "10.0.0.5",
                    "sport": 54321,
                    "dip": "1.1.1.1",
                    "dport": 443,
                    "res": 0
                }
                """;
        when(jdbc.queryForList(anyString(), eq(String.class), eq("gw-01"), eq("gw-01")))
                .thenReturn(List.of("AGT-GW-01"));

        assertTrue(service.ingestElkeidEvent(connectJson));

        ArgumentCaptor<String> agentCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<RptSecurityEvent> eventCaptor = ArgumentCaptor.forClass(RptSecurityEvent.class);
        verify(securityEventService, atLeastOnce()).onEvent(agentCaptor.capture(), eventCaptor.capture());

        RptSecurityEvent event = eventCaptor.getValue();
        assertEquals("network", event.getType());
        assertEquals("telemetry_only", event.getActionTaken());
        assertEquals(1, event.getSeverityValue()); // SEV_INFO
        assertTrue(event.getDetail().contains("\"dip\":\"1.1.1.1\""));
        assertTrue(event.getDetail().contains("\"dport\":443"));
        assertTrue(event.getDetail().contains("\"telemetry_only\":true"));
    }

    @Test
    void testRedactionOfSensitiveTelemetry() {
        String falcoJson = """
                {
                    "output": "Warning Suspicious curl cmdline: curl -u admin:secret https://internal.corp --password=plain_password_123",
                    "priority": "Warning",
                    "rule": "Suspicious curl with creds",
                    "output_fields": {
                        "proc.cmdline": "curl https://internal.corp --password=plain_password_123 --token=super-secret-jwt-token",
                        "proc.name": "curl",
                        "proc.pid": 3344
                    }
                }
                """;
        service.ingestFalcoEvent(falcoJson);
        ArgumentCaptor<RptSecurityEvent> eventCaptor = ArgumentCaptor.forClass(RptSecurityEvent.class);
        verify(securityEventService, atLeastOnce()).onEvent(anyString(), eventCaptor.capture());
        RptSecurityEvent event = eventCaptor.getValue();
        assertFalse(event.getDetail().contains("plain_password_123"));
        assertFalse(event.getDetail().contains("super-secret-jwt-token"));
        assertTrue(event.getDetail().contains("--password=***"));
        assertTrue(event.getDetail().contains("--token=***"));
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
