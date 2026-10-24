package com.alinksec.gateway.rest;

import com.alinksec.common.web.ApiResult;
import com.alinksec.service.log.LogSearchService;
import jakarta.servlet.http.*;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/logs")
public class LogController {
    private final LogSearchService logs;
    public LogController(LogSearchService logs){this.logs=logs;}
    @ModelAttribute public void privateResponse(HttpServletResponse response) {
        response.setHeader("Cache-Control","no-store");response.setHeader("X-Content-Type-Options","nosniff");
    }
    private static Long actor(HttpServletRequest request) {
        if(!(request.getAttribute("uid") instanceof Number id))throw new IllegalArgumentException("需要已登录账号");return id.longValue();
    }
    @GetMapping public ApiResult<?> search(@RequestParam long from,@RequestParam long to,
            @RequestParam(required=false) String agent,@RequestParam(required=false) String source,
            @RequestParam(required=false) String keyword,@RequestParam(required=false) String cursor,HttpServletRequest request) {
        return ApiResult.ok(logs.search(new LogSearchService.Query(from,to,agent,source,keyword,cursor),actor(request)));
    }
    @GetMapping("/{id}") public ApiResult<?> detail(@PathVariable String id,HttpServletRequest request) {return ApiResult.ok(logs.detail(id,actor(request)));}
    @PostMapping("/export") public ResponseEntity<byte[]> export(@RequestBody LogSearchService.Export body,HttpServletRequest request) {
        var file=logs.export(body,actor(request));
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_OCTET_STREAM)
                .header(HttpHeaders.CONTENT_DISPOSITION,"attachment; filename=\""+file.filename()+"\"")
                .header(HttpHeaders.CACHE_CONTROL,"no-store").header("X-Content-Type-Options","nosniff")
                .header("Content-Security-Policy","sandbox; default-src 'none'").header("X-Content-SHA256",file.sha256()).body(file.bytes());
    }
}
