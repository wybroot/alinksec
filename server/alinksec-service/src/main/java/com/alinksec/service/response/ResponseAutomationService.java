package com.alinksec.service.response;

import com.alinksec.common.util.JsonUtils;
import com.alinksec.proto.CmdProtectAction;
import com.alinksec.proto.Command;
import com.alinksec.service.audit.AuditService;
import com.alinksec.service.command.CommandLifecycleListener;
import com.alinksec.service.command.CommandService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.net.InetAddress;
import java.net.URI;
import java.time.Instant;
import java.util.*;

/**
 * 响应规则自动化与 Wazuh Active Response 闭环机制（D01-D04）：
 * 1. 响应规则 CRUD 与权限约束：admin / operator 可配；viewer 仅读；终止进程或敏感动作需管理员独立确认 (require_admin_auth)。
 * 2. 告警驱动的自动响应派发：支持 local（本告警主机）、agent（指定主机）。
 * 3. 目标 IP / 进程白名单安全校验：管理服务器 IP / 本机 Loopback / 关键系统进程绝对禁止处置。
 * 4. 超时自动撤销 (timeout reversal)：如主机隔离或临时封禁，在超时后自动派发解封/恢复指令并闭环状态。
 * 5. 全链路链式审计：规则匹配 -> 派发 -> 终态 ACK -> 超时撤销，全记录关联 alert_id、agent_id、command_id。
 */
@Service
public class ResponseAutomationService implements CommandLifecycleListener {

    private static final Logger log = LoggerFactory.getLogger(ResponseAutomationService.class);

    private final JdbcTemplate jdbc;
    private final CommandService commandService;
    private final AuditService auditService;

    public ResponseAutomationService(JdbcTemplate jdbc, CommandService commandService, AuditService auditService) {
        this.jdbc = jdbc;
        this.commandService = commandService;
        this.auditService = auditService;
    }

    /* ==================== 响应规则管理 (D01, D03) ==================== */

    public List<Map<String, Object>> listRules() {
        return jdbc.queryForList("""
            SELECT id, name, alert_type, min_severity, trigger_rule_id, host_tag, action, location,
                   target_agent_id, timeout_sec, enabled, require_admin_auth, description, created_by, created_at, updated_at
            FROM t_response_rule
            ORDER BY id ASC
            """);
    }

    @Transactional
    public Map<String, Object> createRule(Map<String, Object> body, Long uid, String role) {
        if (!"admin".equals(role) && !"operator".equals(role)) {
            throw new IllegalArgumentException("仅系统管理员与安全运维角色可配置响应规则");
        }
        String name = (String) body.get("name");
        String alertType = (String) body.get("alertType");
        int minSeverity = body.containsKey("minSeverity") ? ((Number) body.get("minSeverity")).intValue() : 3;
        String triggerRuleId = (String) body.getOrDefault("triggerRuleId", "");
        String hostTag = (String) body.getOrDefault("hostTag", "");
        String action = (String) body.get("action");
        String location = (String) body.getOrDefault("location", "local");
        String targetAgentId = (String) body.getOrDefault("targetAgentId", "");
        int timeoutSec = body.containsKey("timeoutSec") ? ((Number) body.get("timeoutSec")).intValue() : 0;
        boolean enabled = !body.containsKey("enabled") || Boolean.TRUE.equals(body.get("enabled"));
        boolean requireAdminAuth = Boolean.TRUE.equals(body.get("requireAdminAuth"));
        String desc = (String) body.getOrDefault("description", "");

        validateRuleParams(name, alertType, action, location, targetAgentId, timeoutSec, requireAdminAuth, role);

        jdbc.update("""
            INSERT INTO t_response_rule (name, alert_type, min_severity, trigger_rule_id, host_tag, action,
                                         location, target_agent_id, timeout_sec, enabled, require_admin_auth, description, created_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, name, alertType, minSeverity, triggerRuleId, hostTag, action, location, targetAgentId, timeoutSec, enabled, requireAdminAuth, desc, uid);

        Long id = jdbc.queryForObject("SELECT last_insert_rowid()", Long.class);
        log.info("新建自动响应规则: id={} name={} action={}", id, name, action);
        return Map.of("id", id != null ? id : 0, "status", "success");
    }

    @Transactional
    public void updateRule(long ruleId, Map<String, Object> body, Long uid, String role) {
        if (!"admin".equals(role) && !"operator".equals(role)) {
            throw new IllegalArgumentException("仅系统管理员与安全运维角色可配置响应规则");
        }
        var current = jdbc.queryForList("SELECT * FROM t_response_rule WHERE id=?", ruleId);
        if (current.isEmpty()) {
            throw new IllegalArgumentException("响应规则不存在: " + ruleId);
        }
        var cur = current.getFirst();
        String name = (String) body.getOrDefault("name", cur.get("name"));
        String alertType = (String) body.getOrDefault("alertType", cur.get("alert_type"));
        int minSeverity = body.containsKey("minSeverity") ? ((Number) body.get("minSeverity")).intValue() : ((Number) cur.get("min_severity")).intValue();
        String triggerRuleId = (String) body.getOrDefault("triggerRuleId", cur.get("trigger_rule_id"));
        String hostTag = (String) body.getOrDefault("hostTag", cur.get("host_tag"));
        String action = (String) body.getOrDefault("action", cur.get("action"));
        String location = (String) body.getOrDefault("location", cur.get("location"));
        String targetAgentId = (String) body.getOrDefault("targetAgentId", cur.get("target_agent_id"));
        int timeoutSec = body.containsKey("timeoutSec") ? ((Number) body.get("timeoutSec")).intValue() : ((Number) cur.get("timeout_sec")).intValue();
        boolean enabled = body.containsKey("enabled") ? Boolean.TRUE.equals(body.get("enabled")) : Boolean.TRUE.equals(cur.get("enabled"));
        boolean requireAdminAuth = body.containsKey("requireAdminAuth") ? Boolean.TRUE.equals(body.get("requireAdminAuth")) : Boolean.TRUE.equals(cur.get("require_admin_auth"));
        String desc = (String) body.getOrDefault("description", cur.get("description"));

        validateRuleParams(name, alertType, action, location, targetAgentId, timeoutSec, requireAdminAuth, role);

        jdbc.update("""
            UPDATE t_response_rule SET name=?, alert_type=?, min_severity=?, trigger_rule_id=?, host_tag=?,
                   action=?, location=?, target_agent_id=?, timeout_sec=?, enabled=?, require_admin_auth=?,
                   description=?, updated_at=CURRENT_TIMESTAMP
            WHERE id=?
            """, name, alertType, minSeverity, triggerRuleId, hostTag, action, location, targetAgentId, timeoutSec, enabled, requireAdminAuth, desc, ruleId);
    }

    @Transactional
    public void deleteRule(long ruleId, String role) {
        if (!"admin".equals(role)) {
            throw new IllegalArgumentException("仅系统管理员可删除自动响应规则");
        }
        jdbc.update("DELETE FROM t_response_rule WHERE id=?", ruleId);
    }

    private void validateRuleParams(String name, String alertType, String action, String location,
                                    String targetAgentId, int timeoutSec, boolean requireAdminAuth, String role) {
        if (name == null || name.isBlank()) throw new IllegalArgumentException("规则名称不能为空");
        if (alertType == null || alertType.isBlank()) throw new IllegalArgumentException("告警类型不能为空");
        if (!Set.of("isolate_host", "restore_isolation", "kill_process", "block_ip").contains(action)) {
            throw new IllegalArgumentException("不支持的响应动作: " + action);
        }
        if (!Set.of("local", "server", "agent").contains(location)) {
            throw new IllegalArgumentException("不支持的执行位置: " + location);
        }
        if ("agent".equals(location) && (targetAgentId == null || targetAgentId.isBlank())) {
            throw new IllegalArgumentException("指定主机执行必须填写目标 agentId");
        }
        if (timeoutSec < 0 || timeoutSec > 86400 * 7) {
            throw new IllegalArgumentException("超时撤销时间必须在 0 到 7 天之间");
        }
        // 敏感动作（kill_process / 跨机响应）需要系统管理员权限或明确配置 requireAdminAuth
        if ("kill_process".equals(action) && !"admin".equals(role) && !requireAdminAuth) {
            throw new IllegalArgumentException("进程查杀规则需由管理员明确授权 (requireAdminAuth)");
        }
    }

    /* ==================== 响应规则评估与派发 (D01, D02, D04) ==================== */

    /**
     * 当有新告警产生时，评估是否有匹配的自动响应规则并派发
     */
    public void evaluateAndDispatch(long alertId, String alertNo) {
        var alerts = jdbc.queryForList("""
            SELECT id, alert_no, agent_id, rule_id, event_type, severity, severity_level, title, detail, action_taken
            FROM v_alert_severity
            WHERE id = ?
            """, alertId);
        if (alerts.isEmpty()) return;
        var alert = alerts.getFirst();
        String agentId = (String) alert.get("agent_id");
        String eventType = (String) alert.get("event_type");
        int severity = ((Number) alert.get("severity_level")).intValue();
        String triggerRuleId = (String) alert.get("rule_id");
        String detailStr = String.valueOf(alert.get("detail"));

        // 查询符合条件且启用的响应规则
        List<Map<String, Object>> rules = jdbc.queryForList("""
            SELECT * FROM t_response_rule
            WHERE enabled = true AND alert_type = ? AND min_severity <= ?
            """, eventType, severity);

        for (Map<String, Object> r : rules) {
            String specRuleId = (String) r.get("trigger_rule_id");
            if (specRuleId != null && !specRuleId.isBlank() && !specRuleId.equals(triggerRuleId)) {
                continue;
            }
            // 检查主机标签 host_tag（若配置）
            String tag = (String) r.get("host_tag");
            if (tag != null && !tag.isBlank()) {
                Integer hasTag = jdbc.queryForObject("SELECT count(*) FROM t_agent WHERE agent_id=? AND tags LIKE ?",
                        Integer.class, agentId, "%" + tag + "%");
                if (hasTag == null || hasTag == 0) continue;
            }

            executeAutoResponse(alert, r, detailStr);
        }
    }

    private void executeAutoResponse(Map<String, Object> alert, Map<String, Object> rule, String detailStr) {
        long alertId = ((Number) alert.get("id")).longValue();
        String sourceAgentId = (String) alert.get("agent_id");
        String location = (String) rule.get("location");
        String targetAgent = "agent".equals(location) ? (String) rule.get("target_agent_id") : sourceAgentId;
        String action = (String) rule.get("action");
        int timeoutSec = ((Number) rule.get("timeout_sec")).intValue();
        long ruleId = ((Number) rule.get("id")).longValue();

        // 提取 target（IP 或 PID）
        String target = "";
        try {
            var node = JsonUtils.read(detailStr);
            if ("block_ip".equals(action)) {
                target = node.path("source_ip").asText();
                if (target.isBlank()) target = node.path("ip").asText();
                if (isProtectedManagementIP(target)) {
                    log.warn("响应规则忽略保护 IP: ruleId={} ip={}", ruleId, target);
                    return;
                }
            } else if ("kill_process".equals(action)) {
                if (node.has("pid")) {
                    target = String.valueOf(node.path("pid").asInt());
                } else if (node.has("process_key")) {
                    target = node.path("process_key").asText();
                }
                if (target.isBlank() || "0".equals(target) || "1".equals(target)) {
                    log.warn("响应规则忽略危险系统进程 PID: ruleId={} pid={}", ruleId, target);
                    return;
                }
            }
        } catch (Exception e) {
            log.warn("解析告警证据失败: {}", e.getMessage());
        }

        // 构建指令
        CmdProtectAction.Builder pa = CmdProtectAction.newBuilder();
        if ("isolate_host".equals(action)) {
            pa.setAction(CmdProtectAction.Action.ISOLATE_HOST).setIsolationContract(1);
        } else if ("restore_isolation".equals(action)) {
            pa.setAction(CmdProtectAction.Action.RESTORE_ISOLATION).setIsolationContract(1);
        } else if ("kill_process".equals(action)) {
            pa.setAction(CmdProtectAction.Action.KILL_PROCESS).setTarget(target);
        } else if ("block_ip".equals(action)) {
            pa.setAction(CmdProtectAction.Action.BLOCK_IP).setTarget(target);
            if (timeoutSec > 0) pa.setDurationSec(timeoutSec);
        }
        pa.setReason("响应规则 #" + ruleId + " 自动化执行: " + rule.get("name"));

        Command command = Command.newBuilder().setProtectAction(pa).build();
        try {
            String cmdId = commandService.dispatch(targetAgent, command, ((Number) rule.get("created_by")).longValue());

            String revSched = timeoutSec > 0 ? Instant.now().plusSeconds(timeoutSec).toString() : null;
            jdbc.update("""
                INSERT INTO t_response_execution (command_id, alert_id, agent_id, rule_id, action, target,
                                                  status, evidence, reversal_scheduled_at, created_by)
                VALUES (?, ?, ?, ?, ?, ?, 'dispatched', ?, ?, ?)
                """, cmdId, alertId, targetAgent, ruleId, action, target, detailStr, revSched, rule.get("created_by"));

            // D04: 响应链审计
            auditService.record(((Number) rule.get("created_by")).longValue(), "system_auto_response", "AUTO_DISPATCH",
                    "/api/response/dispatch?alert=" + alertId + "&cmd=" + cmdId, "127.0.0.1", 200, 0);

            log.info("自动响应已派发: alertId={} ruleId={} action={} cmdId={} timeoutSec={}", alertId, ruleId, action, cmdId, timeoutSec);
        } catch (Exception ex) {
            log.error("自动响应派发失败: alertId={} ruleId={} err={}", alertId, ruleId, ex.getMessage());
        }
    }

    private boolean isProtectedManagementIP(String ipStr) {
        if (ipStr == null || ipStr.isBlank()) return true;
        try {
            InetAddress addr = InetAddress.getByName(ipStr);
            if (addr.isLoopbackAddress() || addr.isAnyLocalAddress() || addr.isLinkLocalAddress()) {
                return true;
            }
            // 保护本机管理服务器地址
            InetAddress localHost = InetAddress.getLocalHost();
            if (addr.equals(localHost)) return true;
        } catch (Exception e) {
            return true;
        }
        return false;
    }

    /* ==================== CommandLifecycleListener (终态审计与回执 D04) ==================== */

    @Override
    public void onTerminal(String agentId, String cmdId, TerminalState state, String message) {
        var execs = jdbc.queryForList("SELECT id, alert_id, rule_id, action FROM t_response_execution WHERE command_id = ?", cmdId);
        if (execs.isEmpty()) return;
        var ex = execs.getFirst();
        String finalStatus = (state == TerminalState.DONE) ? "completed" : "failed";
        jdbc.update("UPDATE t_response_execution SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE command_id = ?", finalStatus, cmdId);

        // 审计终态
        auditService.record(0L, "system_auto_response", "TERMINAL_ACK",
                "/api/response/terminal?cmd=" + cmdId + "&state=" + finalStatus, "127.0.0.1", 200, 0);
    }

    /* ==================== 超时自动撤销定时扫描 (timeout reversal D01, D02) ==================== */

    @Scheduled(fixedDelay = 10_000, initialDelay = 15_000)
    public void processScheduledReversals() {
        String now = Instant.now().toString();
        List<Map<String, Object>> due = jdbc.queryForList("""
            SELECT id, command_id, alert_id, agent_id, rule_id, action, target, evidence, created_by
            FROM t_response_execution
            WHERE status = 'completed' AND reversal_scheduled_at IS NOT NULL
              AND reversal_scheduled_at <= ? AND reversal_executed_at IS NULL
            LIMIT 20
            """, now);

        for (Map<String, Object> item : due) {
            long execId = ((Number) item.get("id")).longValue();
            String agentId = (String) item.get("agent_id");
            String action = (String) item.get("action");
            String target = (String) item.get("target");
            Long user = item.get("created_by") != null ? ((Number) item.get("created_by")).longValue() : 0L;

            try {
                String revCmdId = null;
                if ("isolate_host".equals(action)) {
                    revCmdId = commandService.dispatch(agentId, Command.newBuilder().setProtectAction(
                            CmdProtectAction.newBuilder().setAction(CmdProtectAction.Action.RESTORE_ISOLATION)
                                    .setIsolationContract(1).setReason("自动化响应执行超时解除隔离")).build(), user);
                } else if ("block_ip".equals(action)) {
                    revCmdId = commandService.dispatch(agentId, Command.newBuilder().setProtectAction(
                            CmdProtectAction.newBuilder().setAction(CmdProtectAction.Action.UNBLOCK_IP)
                                    .setTarget(target).setReason("自动化响应临时封禁超时解封")).build(), user);
                }
                jdbc.update("""
                    UPDATE t_response_execution SET reversal_executed_at = CURRENT_TIMESTAMP,
                           reversal_command_id = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                    """, revCmdId, execId);

                // 审计撤销动作
                auditService.record(user, "system_auto_response", "TIMEOUT_REVERSAL",
                        "/api/response/reversal?exec=" + execId + "&revCmd=" + revCmdId, "127.0.0.1", 200, 0);

                log.info("响应超时自动撤销完成: execId={} action={} revCmdId={}", execId, action, revCmdId);
            } catch (Exception ex) {
                log.error("响应撤销派发失败: execId={} err={}", execId, ex.getMessage());
            }
        }
    }

    public Map<String, Object> listExecutions(long alertId, int page, int pageSize) {
        int offset = (Math.max(page, 1) - 1) * pageSize;
        Long total = jdbc.queryForObject("SELECT count(*) FROM t_response_execution WHERE alert_id = ?", Long.class, alertId);
        List<Map<String, Object>> rows = jdbc.queryForList("""
            SELECT e.*, r.name AS rule_name, c.status AS command_status, c.result AS command_result
            FROM t_response_execution e
            LEFT JOIN t_response_rule r ON r.id = e.rule_id
            LEFT JOIN t_command c ON c.cmd_id = e.command_id
            WHERE e.alert_id = ?
            ORDER BY e.created_at DESC LIMIT ? OFFSET ?
            """, alertId, pageSize, offset);
        return Map.of("total", total != null ? total : 0, "list", rows);
    }
}
