package com.alinksec.gateway.rest;

import com.alinksec.common.web.ApiResult;
import com.alinksec.service.geo.ScreenSituationService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ScreenSituationController {
    private final ScreenSituationService service;
    public ScreenSituationController(ScreenSituationService service) { this.service = service; }
    @GetMapping("/api/dashboard/screen-situation")
    public ApiResult<?> snapshot() { return ApiResult.ok(service.snapshot()); }
}
