package com.alinksec.gateway.rest;

import com.alinksec.common.web.ApiResult;
import com.alinksec.service.alert.AlertResponseService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/alerts/{id}/responses")
public class AlertResponsesController {
    private final AlertResponseService responses;
    public AlertResponsesController(AlertResponseService responses) { this.responses=responses; }
    public record Input(String action) {}
    @GetMapping public ApiResult<?> list(@PathVariable long id,@RequestParam(defaultValue="1") int page) { return ApiResult.ok(responses.list(id,page)); }
    @PostMapping public ApiResult<?> dispatch(@PathVariable long id,@RequestBody Input input,HttpServletRequest request) {
        return ApiResult.ok(responses.dispatch(id,input.action(),((Number)request.getAttribute("uid")).longValue()));
    }
}
