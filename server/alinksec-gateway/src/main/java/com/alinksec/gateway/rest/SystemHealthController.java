package com.alinksec.gateway.rest;

import com.alinksec.common.web.ApiResult;
import com.alinksec.gateway.server.ComponentHealthService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import java.util.Map;

/** Detailed diagnostics require administrator authentication; public probes stay minimal. */
@RestController
public class SystemHealthController {
    private final ComponentHealthService health;
    public SystemHealthController(ComponentHealthService health) { this.health=health; }
    @GetMapping("/api/system/health")
    public ResponseEntity<ApiResult<Map<String,Object>>> health() {
        return ResponseEntity.ok().header("Cache-Control","no-store").body(ApiResult.ok(health.snapshot()));
    }
}
