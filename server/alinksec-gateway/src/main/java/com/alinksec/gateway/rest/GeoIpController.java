package com.alinksec.gateway.rest;

import com.alinksec.common.web.ApiResult;
import com.alinksec.service.geo.GeoIpService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RequestParam;

/** /api/system is administrator-only in JwtAuthInterceptor; requests cannot choose a file or URL. */
@RestController
public class GeoIpController {
    private final GeoIpService geo;
    public GeoIpController(GeoIpService geo) { this.geo = geo; }
    @GetMapping("/api/system/geoip") public ApiResult<?> status() { return ApiResult.ok(geo.metadata()); }
    @GetMapping("/api/system/geoip/lookup") public ApiResult<?> lookup(@RequestParam String ip) { return ApiResult.ok(geo.locate(ip)); }
    @PostMapping("/api/system/geoip/reload") public ApiResult<?> reload() { return ApiResult.ok(geo.reload()); }
}
