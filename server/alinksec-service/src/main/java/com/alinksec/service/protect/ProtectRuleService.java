package com.alinksec.service.protect;

import com.alinksec.proto.CmdProtectAction;
import com.alinksec.proto.Command;
import com.alinksec.service.command.CommandService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

/**
 * 防护策略与安全处置（docs/05 §2）：
 * - t_protect_rule 规则源管理（诱饵/加密行为等内置规则的平台侧编辑）
 * - CmdProtectAction 下发：kill / isolate / restore
 */
@Service
public class ProtectRuleService {

    private static final Logger log = LoggerFactory.getLogger(ProtectRuleService.class);

    private final JdbcTemplate jdbc;
    private final CommandService commandService;
    private final PolicyStoreService policyStore;

    public ProtectRuleService(JdbcTemplate jdbc, CommandService commandService, PolicyStoreService policyStore) {
        this.jdbc = jdbc;
        this.commandService = commandService;
        this.policyStore = policyStore;
    }

    /** 规则清单（按类型分组展示：诱饵/加密行为在前） */
    public List<Map<String, Object>> listRules() {
        return jdbc.queryForList("""
                SELECT id, rule_id, name, type, match, actions, severity, enabled, built_in, version, updated_at
                FROM t_protect_rule
                ORDER BY (type = 'decoy') DESC, (type = 'ransom_behavior') DESC, rule_id
                """);
    }

    /** 编辑规则（match/actions/enabled；内置规则不可删只可调），version 递增 */
    public void updateRule(String ruleId, Map<String, Object> body) {
        StringBuilder sql = new StringBuilder("UPDATE t_protect_rule SET updated_at = now(), version = version + 1");
        Object[] args = new Object[4];
        int n = 0;
        if (body.containsKey("match")) {
            sql.append(", match = ?::jsonb");
            args[n++] = com.alinksec.common.util.JsonUtils.write(body.get("match"));
        }
        if (body.containsKey("actions")) {
            sql.append(", actions = ?::jsonb");
            args[n++] = com.alinksec.common.util.JsonUtils.write(body.get("actions"));
        }
        if (body.containsKey("enabled")) {
            sql.append(", enabled = ?");
            args[n++] = Boolean.TRUE.equals(body.get("enabled"));
        }
        sql.append(" WHERE rule_id = ?");
        args[n++] = ruleId;
        int rows = jdbc.update(sql.toString(), java.util.Arrays.copyOf(args, n));
        if (rows == 0) {
            throw new IllegalArgumentException("规则不存在: " + ruleId);
        }
        // 规则变更 → 重建策略快照（版本递增 + 在线 Agent 即时热下发，离线 Agent 上线心跳补同步）
        policyStore.rebuild();
    }

    /** 拦截记录：诱饵/加密行为事件（t_alert，含处置动作） */
    public List<Map<String, Object>> listBlocks(int limit) {
        return jdbc.queryForList("""
                SELECT t.id, t.alert_no, t.agent_id, a.hostname, t.rule_id, t.event_type, t.severity,
                       t.title, t.detail, t.action_taken, t.first_time, t.last_time, t.count
                FROM t_alert t LEFT JOIN t_agent a ON a.agent_id = t.agent_id
                WHERE t.event_type IN ('decoy_tamper', 'ransom_behavior')
                ORDER BY t.last_time DESC LIMIT ?
                """, limit);
    }

    /** 下发安全处置指令 */
    public void dispatchAction(String agentId, String action, String target, String reason, Long issuedBy) {
        CmdProtectAction.Action act = switch (action) {
            case "kill" -> CmdProtectAction.Action.KILL_PROCESS;
            case "isolate" -> CmdProtectAction.Action.ISOLATE_HOST;
            case "restore" -> CmdProtectAction.Action.RESTORE_ISOLATION;
            default -> throw new IllegalArgumentException("不支持的动作: " + action);
        };
        commandService.dispatch(agentId, Command.newBuilder()
                .setProtectAction(CmdProtectAction.newBuilder()
                        .setAction(act)
                        .setTarget(target == null ? "" : target)
                        .setReason(reason == null ? "" : reason)),
                issuedBy);
        log.info("安全处置已下发: agent={} action={} target={}", agentId, action, target);
    }
}
