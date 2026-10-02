package com.alinksec.gateway.rest;

import com.alinksec.common.web.ApiResult;
import com.alinksec.service.protect.ProtectRuleService;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * 实时防护：引擎清单 / 主机防护状态 / 防护规则（诱饵/加密行为）/ 安全处置下发。
 * 诱饵参数由 Agent 本地 agent.yml 执行（本地秒级响应），平台侧为规则源与展示。
 */
@RestController
@RequestMapping("/api/protect")
public class ProtectController {

    private final JdbcTemplate jdbc;
    private final ProtectRuleService protectRuleService;

    public ProtectController(JdbcTemplate jdbc, ProtectRuleService protectRuleService) {
        this.jdbc = jdbc;
        this.protectRuleService = protectRuleService;
    }

    /** 内置防护引擎清单（M2 固化：进程/文件/登录/诱饵） */
    @GetMapping("/engines")
    public ApiResult<List<Map<String, Object>>> engines() {
        return ApiResult.ok(List.of(
                Map.of("key", "process", "name", "恶意进程防护", "desc",
                        "EDR 进程行为规则匹配与父链取证，可按规则结束进程树", "builtin", true),
                Map.of("key", "file_tamper", "name", "关键文件防篡改", "desc",
                        "Linux 关键文件内容与权限监控，可按规则自动恢复", "builtin", true),
                Map.of("key", "login", "name", "登录防护", "desc",
                        "Linux SSH 爆破与异常时段登录检测，可按规则限时封禁来源", "builtin", true),
                Map.of("key", "decoy", "name", "勒索诱饵防护", "desc",
                        "诱饵文件触碰即阻断加密进程（本地响应）", "builtin", true)));
    }

    /** 各主机防护开关状态 */
    @GetMapping("/status")
    public ApiResult<List<Map<String, Object>>> status() {
        return ApiResult.ok(jdbc.queryForList("""
                SELECT agent_id, hostname, ip, status, protect_enabled, last_heartbeat
                FROM t_agent WHERE status <> 4
                ORDER BY protect_enabled DESC, hostname
                """));
    }

    /** 防护规则清单（docs/03 t_protect_rule：诱饵 PR-0010 / 加密行为 PR-0011 内置） */
    @GetMapping("/rules")
    public ApiResult<List<Map<String, Object>>> rules() {
        return ApiResult.ok(protectRuleService.listRules());
    }

    /** 编辑规则（match/actions/enabled；内置规则可调不可删） */
    @PutMapping("/rules/{ruleId}")
    public ApiResult<Void> updateRule(@PathVariable String ruleId, @RequestBody Map<String, Object> body) {
        protectRuleService.updateRule(ruleId, body);
        return ApiResult.ok(null);
    }

    /** 勒索拦截记录（decoy_tamper / ransom_behavior 事件流） */
    @GetMapping("/blocks")
    public ApiResult<List<Map<String, Object>>> blocks(@RequestParam(defaultValue = "50") int limit) {
        return ApiResult.ok(protectRuleService.listBlocks(Math.min(limit, 200)));
    }

    /**
     * 安全处置下发：action = kill(target=PID/进程路径) / isolate / restore。
     * Agent 端 executeProtectAction 执行并回 ACK（docs/05 §2.3 处置链）。
     */
    @PostMapping("/actions")
    public ApiResult<Void> actions(@RequestBody Map<String, Object> body) {
        String agentId = (String) body.get("agentId");
        String action = (String) body.get("action");
        if (agentId == null || agentId.isBlank() || action == null || action.isBlank()) {
            throw new IllegalArgumentException("agentId 与 action 必填");
        }
        protectRuleService.dispatchAction(agentId, action,
                (String) body.getOrDefault("target", ""),
                (String) body.getOrDefault("reason", ""), null);
        return ApiResult.ok(null);
    }
}
