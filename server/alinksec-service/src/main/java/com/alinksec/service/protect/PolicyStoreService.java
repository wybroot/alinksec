package com.alinksec.service.protect;

import com.alinksec.common.util.JsonUtils;
import com.alinksec.service.command.CommandService;
import com.alinksec.service.config.DatabaseDialect;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

/**
 * 策略存储与热下发（docs/04 §策略同步）：
 * - t_policy_state 单行表：version 递增 + 全量策略快照 content；
 * - 快照由 t_protect_rule 聚合生成（PR-0010 诱饵 + PR-0011 加密行为 → policy_json.decoy 段）；
 * - 规则编辑 → rebuild：bump 版本并即时推送在线 Agent；离线 Agent 上线后心跳版本落后自动补同步。
 */
@Service
public class PolicyStoreService {

    private static final Logger log = LoggerFactory.getLogger(PolicyStoreService.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final JdbcTemplate jdbc;
    private final CommandService commandService;

    public PolicyStoreService(JdbcTemplate jdbc, CommandService commandService) {
        this.jdbc = jdbc;
        this.commandService = commandService;
    }

    /** 启动时确保策略行存在并完成首次聚合 */
    @PostConstruct
    public void init() {
        Integer rows = jdbc.queryForObject("SELECT count(*) FROM t_policy_state WHERE id = 1", Integer.class);
        if (rows == null || rows == 0) {
            jdbc.update("INSERT INTO t_policy_state (id, version, content) VALUES (1, 1, '{}')");
        }
        String stored = contentJson();
        if (stored == null || stored.isBlank()
                || !JsonUtils.read(stored).equals(JsonUtils.read(buildFromRules()))) {
            rebuild();
        }
    }

    /** 当前策略版本（"vN"；t_protect_rule 变更 → rebuild 递增） */
    public String currentVersion() {
        return "v" + jdbc.queryForObject("SELECT version FROM t_policy_state WHERE id = 1", Long.class);
    }

    /** 当前全量策略快照（policy_json；Agent 端解析 decoy 段热更新 guard） */
    public String contentJson() {
        return jdbc.queryForObject("SELECT CAST(content AS TEXT) FROM t_policy_state WHERE id = 1", String.class);
    }

    /**
     * 重建快照并递增版本，随后即时推送在线 Agent（离线 Agent 由心跳版本比对补同步）。
     *
     * @return 新版本号
     */
    public synchronized String rebuild() {
        String content = buildFromRules();
        Long version = jdbc.queryForObject(
                "UPDATE t_policy_state SET version = version + 1, content = ?, updated_at = CURRENT_TIMESTAMP " +
                        "WHERE id = 1 RETURNING version", Long.class, content);
        log.info("策略快照已重建: version={} content_bytes={}", version, content.length());
        pushToOnlineAgents();
        return "v" + version;
    }

    /** 聚合 t_protect_rule → policy_json（诱饵配置 + EDR 进程规则）。 */
    private String buildFromRules() {
        ObjectNode root = MAPPER.createObjectNode();
        List<Map<String, Object>> rules = jdbc.queryForList(
                "SELECT rule_id, CAST(match AS TEXT) AS match, CAST(actions AS TEXT) AS actions, enabled FROM t_protect_rule " +
                        "WHERE rule_id IN ('PR-0010', 'PR-0011')");
        Map<String, Map<String, Object>> byId = new java.util.HashMap<>();
        for (Map<String, Object> r : rules) {
            byId.put((String) r.get("rule_id"), r);
        }
        Map<String, Object> decoyRule = byId.get("PR-0010");
        Map<String, Object> rateRule = byId.get("PR-0011");
        List<Map<String, Object>> processRules = jdbc.queryForList(
                "SELECT rule_id, name, CAST(match AS TEXT) AS match, CAST(actions AS TEXT) AS actions, severity, enabled " +
                        "FROM t_protect_rule WHERE type = 'process' ORDER BY rule_id");
        if (decoyRule == null && rateRule == null && processRules.isEmpty()) {
            return "{}";
        }

        ObjectNode decoy = MAPPER.createObjectNode();
        boolean enabled = decoyRule == null || DatabaseDialect.readBoolean(decoyRule.get("enabled"));
        decoy.put("enabled", enabled);
        try {
            if (decoyRule != null) {
                JsonNode match = MAPPER.readTree((String) decoyRule.get("match"));
                copyTextArray(match, "dirs", decoy.putArray("dirs"));
                if (match.hasNonNull("count_per_dir")) decoy.put("count_per_dir", match.get("count_per_dir").asInt());
                copyTextArray(match, "exclude_exes", decoy.putArray("exclude_exes"));
                decoy.put("response", responseOf((String) decoyRule.get("actions")));
            }
            if (rateRule != null && DatabaseDialect.readBoolean(rateRule.get("enabled"))) {
                JsonNode match = MAPPER.readTree((String) rateRule.get("match"));
                if (match.hasNonNull("rate_window_sec")) decoy.put("rate_window_sec", match.get("rate_window_sec").asInt());
                if (match.hasNonNull("rate_threshold")) decoy.put("rate_threshold", match.get("rate_threshold").asInt());
                if (match.hasNonNull("ext_change_ratio")) decoy.put("ext_change_ratio", match.get("ext_change_ratio").asDouble());
            }
        } catch (Exception e) {
            log.warn("策略快照聚合失败，使用空快照", e);
            return "{}";
        }
        root.set("decoy", decoy);
        ArrayNode process = root.putArray("process_rules");
        for (Map<String, Object> rule : processRules) {
            try {
                ObjectNode out = process.addObject();
                out.put("id", (String) rule.get("rule_id"));
                out.put("name", (String) rule.get("name"));
                out.put("severity", ((Number) rule.get("severity")).intValue());
                out.put("enabled", DatabaseDialect.readBoolean(rule.get("enabled")));
                out.set("match", MAPPER.readTree((String) rule.get("match")));
                out.set("actions", MAPPER.readTree((String) rule.get("actions")));
            } catch (Exception e) {
                log.warn("跳过无效 EDR 进程规则: rule={}", rule.get("rule_id"), e);
            }
        }
        return JsonUtils.write(root);
    }

    /** actions（JSONB 数组）→ 响应级别（与 Web levelActions 映射互逆） */
    private String responseOf(String actionsJson) {
        try {
            JsonNode arr = MAPPER.readTree(actionsJson);
            boolean isolate = false, kill = false;
            for (JsonNode a : arr) {
                if ("isolate_host".equals(a.asText())) isolate = true;
                if ("kill".equals(a.asText())) kill = true;
            }
            if (isolate) return "kill_and_isolate";
            if (kill) return "kill";
        } catch (Exception ignored) {
        }
        return "alert_only";
    }

    private void copyTextArray(JsonNode from, String field, ArrayNode to) {
        if (from.has(field) && from.get(field).isArray()) {
            from.get(field).forEach(n -> to.add(n.asText()));
        }
    }

    /** 即时推送在线 Agent（status=1 在线；PENDING 兜底：上线心跳版本落后自动触发） */
    private void pushToOnlineAgents() {
        String version = currentVersion();
        String content = contentJson();
        List<String> online = jdbc.queryForList(
                "SELECT agent_id FROM t_agent WHERE status = 1", String.class);
        for (String agentId : online) {
            commandService.dispatchPolicySync(agentId, version, content);
        }
        log.info("策略热下发: version={} 在线推送 {} 台", version, online.size());
    }
}
