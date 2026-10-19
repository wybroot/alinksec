package com.alinksec.gateway.rest;

import com.alinksec.common.web.ApiResult;
import com.alinksec.service.fix.WindowsUpdateService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.*;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/fix/windows")
public class WindowsUpdateController {
    private final WindowsUpdateService updates;
    public WindowsUpdateController(WindowsUpdateService updates) { this.updates=updates; }
    @GetMapping("/hosts")
    public ApiResult<Map<String,Object>> hosts(@RequestParam(defaultValue="1") int page,@RequestParam(defaultValue="20") int size) { return ApiResult.ok(updates.hosts(Math.max(1,page),Math.max(1,Math.min(100,size)))); }
    @GetMapping("/candidates")
    public ApiResult<List<Map<String,Object>>> candidates(@RequestParam String agentId) { return ApiResult.ok(updates.candidates(agentId)); }
    @PostMapping("/scans")
    public ApiResult<Map<String,Object>> scan(@RequestBody Scan body,HttpServletRequest request) { return ApiResult.ok(updates.scan(body.agentIds(),uid(request))); }
    @PostMapping("/tasks")
    public ApiResult<Map<String,Object>> task(@RequestBody Task body,HttpServletRequest request) { return ApiResult.ok(updates.createTask(body.items(),body.approver(),body.windowStart(),body.windowEnd(),uid(request))); }
    public record Scan(List<String> agentIds) { }
    public record Task(List<Map<String,Object>> items,String approver,String windowStart,String windowEnd) { }
    private static Long uid(HttpServletRequest r) { return r.getAttribute("uid") instanceof Number n?n.longValue():null; }
}
