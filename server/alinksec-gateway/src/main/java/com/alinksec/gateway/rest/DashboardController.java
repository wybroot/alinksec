package com.alinksec.gateway.rest;

import com.alinksec.common.web.ApiResult;
import com.alinksec.service.query.DashboardQueryService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * 安全总览（首页 Dashboard）。
 */
@RestController
@RequestMapping("/api/dashboard")
public class DashboardController {

    private final DashboardQueryService query;

    public DashboardController(DashboardQueryService query) {
        this.query = query;
    }

    @GetMapping("/summary")
    public ApiResult<Map<String, Object>> summary() {
        return ApiResult.ok(query.summary());
    }

    @GetMapping("/alert-trend")
    public ApiResult<?> alertTrend(@RequestParam(defaultValue = "7") int days) {
        return ApiResult.ok(query.alertTrend(Math.min(Math.max(days, 1), 30)));
    }

    @GetMapping("/event-distribution")
    public ApiResult<?> eventDistribution() {
        return ApiResult.ok(query.eventTypeDistribution());
    }

    @GetMapping("/top-hosts")
    public ApiResult<?> topHosts(@RequestParam(defaultValue = "5") int limit) {
        return ApiResult.ok(query.topRiskHosts(Math.min(Math.max(limit, 1), 20)));
    }

    /** 大屏专用：病毒告警/防护拦截双趋势 */
    @GetMapping("/screen-trend")
    public ApiResult<?> screenTrend(@RequestParam(defaultValue = "7") int days) {
        return ApiResult.ok(query.screenTrend(Math.min(Math.max(days, 1), 30)));
    }

    /** 大屏专用：最近一次基线任务各维度通过率 */
    @GetMapping("/baseline-categories")
    public ApiResult<?> baselineCategories() {
        return ApiResult.ok(query.baselineCategories());
    }
}
