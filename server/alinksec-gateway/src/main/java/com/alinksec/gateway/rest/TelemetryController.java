package com.alinksec.gateway.rest;

import com.alinksec.common.web.ApiResult;
import com.alinksec.service.config.AlinkSecProperties;
import com.alinksec.service.telemetry.KernelTelemetryService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * 内核与 eBPF 遥测接收及状态端点（docs/84 第六批 F01-kernel ~ F04-kernel）。
 * 1. POST /api/telemetry/falco/events: 接收 Falco HTTP webhook 告警
 * 2. POST /api/telemetry/elkeid/events: 接收 Elkeid Driver/Agent 遥测事件
 * 3. GET  /api/telemetry/status: 获取内核探针状态与心跳
 */
@RestController
@RequestMapping("/api/telemetry")
public class TelemetryController {

    private final KernelTelemetryService telemetryService;
    private final AlinkSecProperties properties;

    public TelemetryController(KernelTelemetryService telemetryService, AlinkSecProperties properties) {
        this.telemetryService = telemetryService;
        this.properties = properties;
    }

    /**
     * 接收 Falco 告警 (F01-kernel)。
     * 支持通过 X-Falco-Token 或 Authorization 验证配置的 Falco 共享密钥。
     */
    @PostMapping("/falco/events")
    public ResponseEntity<ApiResult<Map<String, Object>>> ingestFalco(
            @RequestBody String payload,
            HttpServletRequest request) {

        String secret = properties.getTelemetry().getFalcoSecret();
        if (secret != null && !secret.isBlank()) {
            String token = request.getHeader("X-Falco-Token");
            if (token == null || !token.equals(secret)) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(ApiResult.error(401, "Falco 鉴权密钥无效"));
            }
        }

        boolean ok = telemetryService.ingestFalcoEvent(payload);
        if (!ok) {
            return ResponseEntity.badRequest().body(ApiResult.error(400, "Falco 数据格式解析失败"));
        }
        return ResponseEntity.ok(ApiResult.ok(Map.of("received", true)));
    }

    /**
     * 接收 Elkeid Driver 事件 (F02-kernel)。
     */
    @PostMapping("/elkeid/events")
    public ResponseEntity<ApiResult<Map<String, Object>>> ingestElkeid(
            @RequestBody String payload) {

        boolean ok = telemetryService.ingestElkeidEvent(payload);
        if (!ok) {
            return ResponseEntity.badRequest().body(ApiResult.error(400, "Elkeid 数据格式解析失败"));
        }
        return ResponseEntity.ok(ApiResult.ok(Map.of("received", true)));
    }

    /**
     * 遥测探针健康与心跳状态 (F04-kernel)。
     */
    @GetMapping("/status")
    public ApiResult<Map<String, Object>> status() {
        return ApiResult.ok(telemetryService.getTelemetryHealth());
    }
}
