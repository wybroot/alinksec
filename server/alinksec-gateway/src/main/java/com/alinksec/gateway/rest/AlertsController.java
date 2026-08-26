package com.alinksec.gateway.rest;

import com.alinksec.common.web.ApiResult;
import com.alinksec.service.query.AlertQueryService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * 告警中心。
 */
@RestController
@RequestMapping("/api/alerts")
public class AlertsController {

    private final AlertQueryService query;

    public AlertsController(AlertQueryService query) {
        this.query = query;
    }

    @GetMapping
    public ApiResult<Map<String, Object>> list(@RequestParam(required = false) Integer status,
                                               @RequestParam(required = false) Integer severity,
                                               @RequestParam(required = false) String agentId,
                                               @RequestParam(required = false) String eventType,
                                               @RequestParam(defaultValue = "1") int page,
                                               @RequestParam(defaultValue = "20") int size) {
        return ApiResult.ok(query.list(status, severity, agentId, eventType, page, Math.min(size, 100)));
    }

    @GetMapping("/severity-distribution")
    public ApiResult<?> severityDistribution() {
        return ApiResult.ok(query.severityDistribution());
    }

    @PostMapping("/{id}/handle")
    public ApiResult<Void> handle(@PathVariable long id, @RequestBody Map<String, String> body,
                                  HttpServletRequest request) {
        long uid = ((Number) request.getAttribute("uid")).longValue();
        boolean ok = query.handle(id, uid, body.getOrDefault("remark", ""));
        return ok ? ApiResult.ok() : ApiResult.error(30001, "告警不存在或已处置");
    }
}
