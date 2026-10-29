package com.alinksec.bootstrap;

import com.alinksec.proto.*;
import com.alinksec.service.alert.SecurityEventService;
import com.alinksec.service.command.CommandLifecycleListener;
import com.alinksec.service.response.ResponseAutomationService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

public class ResponseAutomationIntegrationTest {

    private IntegrationTestFixture fixture;
    private JdbcTemplate jdbc;
    private ResponseAutomationService responseService;
    private SecurityEventService eventService;

    @BeforeEach
    void setUp() {
        fixture = IntegrationTestFixture.create();
        jdbc = fixture.jdbc;
        responseService = fixture.context.getBean(ResponseAutomationService.class);
        eventService = fixture.context.getBean(SecurityEventService.class);

        // 创建测试 Agent
        jdbc.update("""
            INSERT INTO t_agent (agent_id, hostname, ip, os_type, status, isolation_contract, tags)
            VALUES ('agent-auto-01', 'auto-host', '192.168.10.20', 1, 1, 1, '["web","dmz"]')
            ON CONFLICT (agent_id) DO NOTHING
            """);
    }

    @AfterEach
    void tearDown() {
        if (fixture != null) {
            fixture.close();
        }
    }

    @Test
    void testResponseRuleCrudAndPermissions() {
        // 1. Viewer 无权创建
        assertThrows(IllegalArgumentException.class, () ->
            responseService.createRule(Map.of(
                "name", "SSH爆破自动封禁",
                "alertType", "login_crack",
                "action", "block_ip"
            ), 1L, "viewer")
        );

        // 2. Operator 创建合规规则
        var result = responseService.createRule(Map.of(
            "name", "SSH爆破自动封禁",
            "alertType", "login_crack",
            "minSeverity", 3,
            "action", "block_ip",
            "timeoutSec", 600,
            "hostTag", "web"
        ), 2L, "operator");

        long ruleId = ((Number) result.get("id")).longValue();
        assertTrue(ruleId > 0);

        // 3. 进程查杀未经管理员授权时被拒绝
        assertThrows(IllegalArgumentException.class, () ->
            responseService.createRule(Map.of(
                "name", "异常进程查杀",
                "alertType", "process",
                "action", "kill_process",
                "requireAdminAuth", false
            ), 2L, "operator")
        );

        // 4. Admin 创建进程查杀规则成功
        var adminResult = responseService.createRule(Map.of(
            "name", "恶意反弹Shell查杀",
            "alertType", "process",
            "action", "kill_process",
            "requireAdminAuth", true
        ), 1L, "admin");
        assertTrue(((Number) adminResult.get("id")).longValue() > 0);

        // 5. 规则列表查询
        List<Map<String, Object>> rules = responseService.listRules();
        assertFalse(rules.isEmpty());

        // 6. Viewer/Operator 无权删除规则，仅 Admin 可删除
        assertThrows(IllegalArgumentException.class, () -> responseService.deleteRule(ruleId, "operator"));
        responseService.deleteRule(ruleId, "admin");
    }

    @Test
    void testSecurityEventTriggersAutoResponseAndAuditChain() {
        // 1. 创建触发规则：login_crack -> block_ip (带 300 秒超时撤销)
        responseService.createRule(Map.of(
            "name", "自动封禁爆破IP",
            "alertType", "login_crack",
            "minSeverity", 3,
            "action", "block_ip",
            "timeoutSec", 300
        ), 1L, "admin");

        // 2. 模拟上报登录爆破事件（来源 IP: 203.0.113.55）
        String detail = """
            {"source_ip":"203.0.113.55","account":"root","ssh_ports":[22],"trigger":"ssh_bruteforce"}
            """;
        eventService.onEvent("agent-auto-01", RptSecurityEvent.newBuilder()
            .setRuleId("PR-0003")
            .setRuleName("SSH 登录防护")
            .setType("login_crack")
            .setSeverity(Severity.SEV_HIGH)
            .setActionTaken("alert_only")
            .setDetail(detail)
            .setEventTs(System.currentTimeMillis())
            .build());

        // 3. 验证告警已生成
        Long alertId = jdbc.queryForObject("SELECT id FROM t_alert WHERE agent_id='agent-auto-01' AND event_type='login_crack'", Long.class);
        assertNotNull(alertId);

        // 4. 验证响应执行记录已生成 (t_response_execution)
        var executions = jdbc.queryForList("SELECT * FROM t_response_execution WHERE alert_id=?", alertId);
        assertEquals(1, executions.size());
        var exec = executions.getFirst();
        assertEquals("block_ip", exec.get("action"));
        assertEquals("203.0.113.55", exec.get("target"));
        assertEquals("dispatched", exec.get("status"));
        assertNotNull(exec.get("reversal_scheduled_at"));

        String cmdId = (String) exec.get("command_id");

        // 5. 模拟终端 ACK 收到 (onTerminal DONE)
        responseService.onTerminal("agent-auto-01", cmdId, CommandLifecycleListener.TerminalState.DONE, "iptables rule added");

        // 验证执行状态更新为 completed
        String status = jdbc.queryForObject("SELECT status FROM t_response_execution WHERE command_id=?", String.class, cmdId);
        assertEquals("completed", status);

        // 6. 验证审计日志链式记录 (t_audit_log)
        int auditCount = jdbc.queryForObject("SELECT count(*) FROM t_audit_log WHERE path LIKE ?", Integer.class, "%" + cmdId + "%");
        assertTrue(auditCount >= 2, "应记录 AUTO_DISPATCH 与 TERMINAL_ACK 审计事件");

        // 7. 模拟超时撤销执行
        // 将 reversal_scheduled_at 改为过去时间触发定时撤销
        jdbc.update("UPDATE t_response_execution SET reversal_scheduled_at = datetime('now', '-10 seconds') WHERE command_id=?", cmdId);
        responseService.processScheduledReversals();

        // 验证已派发撤销指令
        String revCmd = jdbc.queryForObject("SELECT reversal_command_id FROM t_response_execution WHERE command_id=?", String.class, cmdId);
        assertNotNull(revCmd);
        assertFalse(revCmd.isBlank());
    }

    @Test
    void testProtectedManagementIpNeverBlocked() {
        // 创建规则
        responseService.createRule(Map.of(
            "name", "管理IP保护测试",
            "alertType", "login_crack",
            "action", "block_ip"
        ), 1L, "admin");

        // 模拟上报 Loopback IP 告警
        eventService.onEvent("agent-auto-01", RptSecurityEvent.newBuilder()
            .setRuleId("PR-0003")
            .setType("login_crack")
            .setSeverity(Severity.SEV_HIGH)
            .setDetail("{\"source_ip\":\"127.0.0.1\"}")
            .build());

        // 确认不会为 127.0.0.1 派发 block_ip 响应
        int execCount = jdbc.queryForObject("SELECT count(*) FROM t_response_execution WHERE target='127.0.0.1'", Integer.class);
        assertEquals(0, execCount, "Loopback 管理 IP 绝对禁止自动封禁");
    }
}
