package com.alinksec.gateway.rest;

import com.alinksec.common.web.ApiResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 存活探针（容器 healthcheck / nginx upstream 检查用，免鉴权）。
 */
@RestController
public class HealthController {
    private final com.alinksec.service.cluster.ClusterRuntime cluster;
    public HealthController(com.alinksec.service.cluster.ClusterRuntime cluster) {this.cluster=cluster;}
    @GetMapping("/api/ready")
    public org.springframework.http.ResponseEntity<?> ready() {
        boolean ready=cluster.ready();
        return org.springframework.http.ResponseEntity.status(ready?200:503)
                .header("Cache-Control","no-store").body(java.util.Map.of("ready",ready));
    }

    @GetMapping("/api/health")
    public ApiResult<Void> health() {
        return ApiResult.ok();
    }
}
