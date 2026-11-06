package com.alinksec.gateway.rest;

import com.alinksec.common.web.ApiResult;
import com.alinksec.service.response.ResponseAutomationService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * 响应规则自动化管理接口（D01-D04）
 */
@RestController
@RequestMapping("/api/protect/response-rules")
public class ResponseRulesController {

    private final ResponseAutomationService responseService;

    public ResponseRulesController(ResponseAutomationService responseService) {
        this.responseService = responseService;
    }

    @GetMapping
    public ApiResult<List<Map<String, Object>>> list() {
        return ApiResult.ok(responseService.listRules());
    }

    @PostMapping
    public ApiResult<Map<String, Object>> create(@RequestBody Map<String, Object> body, HttpServletRequest request) {
        Long uid = ((Number) request.getAttribute("uid")).longValue();
        String role = (String) request.getAttribute("role");
        return ApiResult.ok(responseService.createRule(body, uid, role));
    }

    @PutMapping("/{id}")
    public ApiResult<Void> update(@PathVariable long id, @RequestBody Map<String, Object> body, HttpServletRequest request) {
        Long uid = ((Number) request.getAttribute("uid")).longValue();
        String role = (String) request.getAttribute("role");
        responseService.updateRule(id, body, uid, role);
        return ApiResult.ok(null);
    }

    @DeleteMapping("/{id}")
    public ApiResult<Void> delete(@PathVariable long id, HttpServletRequest request) {
        String role = (String) request.getAttribute("role");
        responseService.deleteRule(id, role);
        return ApiResult.ok(null);
    }

    @PostMapping("/{id}/approve")
    public ApiResult<Void> approve(@PathVariable long id, HttpServletRequest request) {
        Long uid = ((Number) request.getAttribute("uid")).longValue();
        String role = (String) request.getAttribute("role");
        responseService.approveRule(id, uid, role);
        return ApiResult.ok(null);
    }

    @GetMapping("/executions")
    public ApiResult<Map<String, Object>> executions(@RequestParam long alertId,
                                                     @RequestParam(defaultValue = "1") int page,
                                                     @RequestParam(defaultValue = "20") int pageSize) {
        return ApiResult.ok(responseService.listExecutions(alertId, page, pageSize));
    }
}
