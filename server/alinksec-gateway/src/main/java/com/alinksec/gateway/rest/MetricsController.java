package com.alinksec.gateway.rest;

import com.alinksec.common.web.ApiResult;
import com.alinksec.service.config.AlinkSecProperties;
import com.alinksec.service.metrics.VmQueryClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * 指标查询（docs/03 §3.2）：MetricsQL/PromQL 透传 VictoriaMetrics。
 * 即时 /api/metrics/query；区间 /api/metrics/query_range（大盘趋势图）。
 */
@RestController
@RequestMapping("/api/metrics")
public class MetricsController {

    private final VmQueryClient vm;
    private final AlinkSecProperties props;

    public MetricsController(VmQueryClient vm, AlinkSecProperties props) {
        this.vm = vm;
        this.props = props;
    }

    /** 即时查询：query 例 alinksec_cpu_usage{agent_id="xxx"} */
    @GetMapping("/query")
    public ApiResult<Object> query(@RequestParam String query,
                                   @RequestParam(required = false) String time) {
        if (!props.getMetrics().isEnabled()) {
            return ApiResult.ok(Map.of("status", "disabled", "data", java.util.List.of()));
        }
        return ApiResult.ok(vm.query(query, time));
    }

    /** 区间查询：start/end 为秒级时间戳或 RFC3339；step 例 60s */
    @GetMapping("/query_range")
    public ApiResult<Object> queryRange(@RequestParam String query,
                                        @RequestParam String start,
                                        @RequestParam String end,
                                        @RequestParam(defaultValue = "60s") String step) {
        if (!props.getMetrics().isEnabled()) {
            return ApiResult.ok(Map.of("status", "disabled", "data", java.util.List.of()));
        }
        return ApiResult.ok(vm.queryRange(query, start, end, step));
    }
}
