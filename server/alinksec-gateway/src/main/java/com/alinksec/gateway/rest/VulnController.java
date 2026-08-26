package com.alinksec.gateway.rest;

import com.alinksec.common.web.ApiResult;
import com.alinksec.service.query.VulnQueryService;
import com.alinksec.service.scan.ScanTaskService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * 漏洞与弱口令：发现查询 + 扫描任务创建下发 + 端口服务发现。
 */
@RestController
@RequestMapping("/api/vuln")
public class VulnController {

    private final VulnQueryService query;
    private final ScanTaskService scanTaskService;

    public VulnController(VulnQueryService query, ScanTaskService scanTaskService) {
        this.query = query;
        this.scanTaskService = scanTaskService;
    }

    /** 创建安全扫描任务：漏洞比对（服务端）+ 弱口令/端口服务（Agent 执行） */
    @PostMapping("/tasks")
    public ApiResult<Map<String, Object>> createTask(@RequestBody Map<String, Object> body,
                                                     HttpServletRequest request) {
        Object uidAttr = request.getAttribute("uid");
        Long createdBy = uidAttr instanceof Number n ? n.longValue() : null;
        @SuppressWarnings("unchecked")
        List<String> agentIds = (List<String>) body.getOrDefault("agentIds", List.of());
        String name = (String) body.get("name");
        boolean includeVuln = Boolean.TRUE.equals(body.get("includeVuln"));
        boolean includeWeakPassword = Boolean.TRUE.equals(body.get("includeWeakPassword"));
        boolean includePortService = Boolean.TRUE.equals(body.get("includePortService"));
        long taskId = scanTaskService.createTask(name, agentIds,
                includeWeakPassword, includePortService, includeVuln, createdBy);
        return ApiResult.ok(Map.of("taskId", taskId));
    }

    @GetMapping("/tasks")
    public ApiResult<Map<String, Object>> tasks(@RequestParam(defaultValue = "1") int page,
                                                @RequestParam(defaultValue = "20") int size) {
        return ApiResult.ok(query.tasks(page, Math.min(size, 100)));
    }

    @GetMapping("/ports")
    public ApiResult<Map<String, Object>> ports(@RequestParam(required = false) Boolean risky,
                                                @RequestParam(required = false) String agentId,
                                                @RequestParam(required = false) String keyword,
                                                @RequestParam(defaultValue = "1") int page,
                                                @RequestParam(defaultValue = "20") int size) {
        return ApiResult.ok(query.portFindings(risky, agentId, keyword, page, Math.min(size, 100)));
    }

    @GetMapping("/findings")
    public ApiResult<Map<String, Object>> findings(@RequestParam(required = false) Integer status,
                                                   @RequestParam(required = false) Integer severity,
                                                   @RequestParam(required = false) String agentId,
                                                   @RequestParam(required = false) String keyword,
                                                   @RequestParam(defaultValue = "1") int page,
                                                   @RequestParam(defaultValue = "20") int size) {
        return ApiResult.ok(query.findings(status, severity, agentId, keyword, page, Math.min(size, 100)));
    }

    @GetMapping("/weakpwds")
    public ApiResult<Map<String, Object>> weakpwds(@RequestParam(defaultValue = "1") int page,
                                                   @RequestParam(defaultValue = "20") int size) {
        return ApiResult.ok(query.weakpwdFindings(page, Math.min(size, 100)));
    }

    @GetMapping("/stats")
    public ApiResult<Map<String, Object>> stats() {
        return ApiResult.ok(query.stats());
    }
}
