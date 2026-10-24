package com.alinksec.gateway.rest;

import com.alinksec.common.web.ApiResult;
import com.alinksec.service.cluster.ClusterConsoleService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/cluster")
public class ClusterController {
    private final ClusterConsoleService console;
    public ClusterController(ClusterConsoleService console) {this.console=console;}
    @ModelAttribute public void privateResponse(jakarta.servlet.http.HttpServletResponse response) {
        response.setHeader("Cache-Control","no-store");response.setHeader("X-Content-Type-Options","nosniff");
    }
    private static Long actor(HttpServletRequest request) {
        if(!(request.getAttribute("uid") instanceof Number id))throw new IllegalArgumentException("需要已登录账号");return id.longValue();
    }
    @GetMapping public ApiResult<?> status(HttpServletRequest request) {return ApiResult.ok(console.status(actor(request)));}
    @PostMapping("/reports/{id}/retry") public ApiResult<?> retry(@PathVariable String id,@RequestBody ClusterConsoleService.Retry change,HttpServletRequest request) {
        console.retry(id,change,actor(request));return ApiResult.ok();
    }
}
