package com.alinksec.gateway.rest;

import com.alinksec.common.web.ApiResult;
import com.alinksec.proto.CmdAgentControl;
import com.alinksec.proto.CmdCollectNow;
import com.alinksec.proto.Command;
import com.alinksec.service.command.CommandService;
import com.alinksec.service.enroll.EnrollTokenService;
import com.alinksec.service.protect.ProtectRuleService;
import com.alinksec.service.query.HostQueryService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

/**
 * 主机与资产管理。
 */
@RestController
@RequestMapping("/api/hosts")
public class HostsController {

    private static final SecureRandom RNG = new SecureRandom();

    private final HostQueryService query;
    private final CommandService commandService;
    private final ProtectRuleService protectRuleService;
    private final EnrollTokenService enrollTokenService;

    public HostsController(HostQueryService query, CommandService commandService,
                           ProtectRuleService protectRuleService, EnrollTokenService enrollTokenService) {
        this.query = query;
        this.commandService = commandService;
        this.protectRuleService = protectRuleService;
        this.enrollTokenService = enrollTokenService;
    }

    @GetMapping
    public ApiResult<Map<String, Object>> list(@RequestParam(required = false) String keyword,
                                               @RequestParam(required = false) Integer status,
                                               @RequestParam(defaultValue = "1") int page,
                                               @RequestParam(defaultValue = "20") int size) {
        return ApiResult.ok(query.list(keyword, status, page, Math.min(size, 100)));
    }

    @GetMapping("/groups")
    public ApiResult<List<Map<String, Object>>> groups() {
        return ApiResult.ok(query.groups());
    }

    @GetMapping("/{agentId}")
    public ApiResult<Map<String, Object>> detail(@PathVariable String agentId) {
        Map<String, Object> detail = query.detail(agentId);
        if (detail == null) {
            return ApiResult.error(20007, "Agent 不存在");
        }
        return ApiResult.ok(detail);
    }

    @GetMapping("/{agentId}/software")
    public ApiResult<List<Map<String, Object>>> software(@PathVariable String agentId,
                                                         @RequestParam(required = false) String keyword,
                                                         @RequestParam(defaultValue = "1") int page,
                                                         @RequestParam(defaultValue = "50") int size) {
        return ApiResult.ok(query.software(agentId, keyword, page, Math.min(size, 500)));
    }

    @GetMapping("/{agentId}/ports")
    public ApiResult<List<Map<String, Object>>> ports(@PathVariable String agentId) {
        return ApiResult.ok(query.ports(agentId));
    }

    @GetMapping("/{agentId}/accounts")
    public ApiResult<List<Map<String, Object>>> accounts(@PathVariable String agentId) {
        return ApiResult.ok(query.accounts(agentId));
    }

    /**
     * 申请卸载口令（docs/01 §6.1 防恶意卸载）：
     * 生成 16 位随机口令经 CmdAgentControl.ARM_UNINSTALL 布防到 Agent，
     * 15 分钟内由运维在目标主机执行 alinksec-agent uninstall --token=xxx 完成卸载（一次性）。
     */
    @PostMapping("/{agentId}/uninstall-token")
    public ApiResult<Map<String, Object>> armUninstall(@PathVariable String agentId,
                                                       jakarta.servlet.http.HttpServletRequest request) {
        Long uid = request.getAttribute("uid") instanceof Number n ? n.longValue() : null;
        if (query.detail(agentId) == null) {
            return ApiResult.error(20007, "Agent 不存在");
        }
        byte[] buf = new byte[8];
        RNG.nextBytes(buf);
        String token = HexFormat.of().formatHex(buf);
        CmdAgentControl cmd = CmdAgentControl.newBuilder()
                .setAction(CmdAgentControl.Action.ARM_UNINSTALL)
                .setUninstallToken(token)
                .build();
        commandService.dispatch(agentId, Command.newBuilder().setAgentControl(cmd), uid);
        return ApiResult.ok(Map.of(
                "token", token,
                "validForSec", 900,
                "usage", "alinksec-agent uninstall --token=" + token));
    }

    /**
     * 生成 Agent 安装注册码（一次性，默认 10 次/7 天）。
     * 返回 token + 目标主机可用的安装命令模板。
     */
    @PostMapping("/enroll-token")
    public ApiResult<Map<String, Object>> createEnrollToken(@RequestParam(defaultValue = "10") int maxUses,
                                                            @RequestParam(defaultValue = "7") int validDays,
                                                            jakarta.servlet.http.HttpServletRequest request) {
        Long uid = request.getAttribute("uid") instanceof Number n ? n.longValue() : null;
        String token = enrollTokenService.create(uid, maxUses, validDays);
        return ApiResult.ok(Map.of(
                "token", token,
                "maxUses", maxUses,
                "validDays", validDays,
                "usage", "alinksec-agent install --server <服务端地址> --token " + token));
    }

    /** 立即采集：CmdCollectNow（Agent 端即时全量/指定采集器） */
    @PostMapping("/{agentId}/collect")
    public ApiResult<Map<String, Object>> collectNow(@PathVariable String agentId,
                                                     jakarta.servlet.http.HttpServletRequest request) {
        Long uid = request.getAttribute("uid") instanceof Number n ? n.longValue() : null;
        if (query.detail(agentId) == null) {
            return ApiResult.error(20007, "Agent 不存在");
        }
        commandService.dispatch(agentId,
                Command.newBuilder().setCollectNow(CmdCollectNow.getDefaultInstance()), uid);
        return ApiResult.ok(Map.of("dispatched", true));
    }

    /** 隔离主机：CmdProtectAction.ISOLATE_HOST（Agent 端断网保管理口语义） */
    @PostMapping("/{agentId}/isolate")
    public ApiResult<Map<String, Object>> isolate(@PathVariable String agentId,
                                                  jakarta.servlet.http.HttpServletRequest request) {
        Long uid = request.getAttribute("uid") instanceof Number n ? n.longValue() : null;
        protectRuleService.dispatchAction(agentId, "isolate", "", "控制台手动隔离", uid);
        return ApiResult.ok(Map.of("dispatched", true));
    }

    /** 解除隔离：CmdProtectAction.RESTORE_ISOLATION */
    @PostMapping("/{agentId}/unisolate")
    public ApiResult<Map<String, Object>> unisolate(@PathVariable String agentId,
                                                    jakarta.servlet.http.HttpServletRequest request) {
        Long uid = request.getAttribute("uid") instanceof Number n ? n.longValue() : null;
        protectRuleService.dispatchAction(agentId, "restore", "", "控制台手动解除隔离", uid);
        return ApiResult.ok(Map.of("dispatched", true));
    }
}
