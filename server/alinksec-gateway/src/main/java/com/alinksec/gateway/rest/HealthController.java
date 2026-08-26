package com.alinksec.gateway.rest;

import com.alinksec.common.web.ApiResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 存活探针（容器 healthcheck / nginx upstream 检查用，免鉴权）。
 */
@RestController
public class HealthController {

    @GetMapping("/api/health")
    public ApiResult<Void> health() {
        return ApiResult.ok();
    }
}
