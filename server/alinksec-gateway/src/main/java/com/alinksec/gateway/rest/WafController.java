package com.alinksec.gateway.rest;

import com.alinksec.common.web.ApiResult;
import com.alinksec.service.waf.WafEngineService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * WAF 引擎状态与运行模式管理接口（E02, E04）
 */
@RestController
@RequestMapping("/api/system/waf")
public class WafController {

    private final WafEngineService wafService;

    public WafController(WafEngineService wafService) {
        this.wafService = wafService;
    }

    @GetMapping("/status")
    public ApiResult<Map<String, Object>> getStatus() {
        return ApiResult.ok(wafService.getStatus());
    }

    @PostMapping("/config")
    public ApiResult<Void> updateConfig(@RequestBody Map<String, Object> body, HttpServletRequest request) {
        String role = (String) request.getAttribute("role");
        if (!"admin".equals(role)) {
            throw new IllegalArgumentException("仅系统管理员可调整 WAF 防护模式");
        }
        boolean enabled = !body.containsKey("enabled") || Boolean.TRUE.equals(body.get("enabled"));
        String mode = (String) body.getOrDefault("mode", "DetectionOnly");
        int threshold = body.containsKey("threshold") ? ((Number) body.get("threshold")).intValue() : 5;
        int pl = body.containsKey("paranoiaLevel") ? ((Number) body.get("paranoiaLevel")).intValue() : 1;

        wafService.updateConfig(enabled, mode, threshold, pl);
        return ApiResult.ok(null);
    }
}
