package com.alinksec.gateway.rest;

import com.alinksec.common.web.ApiResult;
import com.alinksec.service.evidence.EvidenceService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/evidence")
public class EvidenceController {
    private final EvidenceService evidence;
    public EvidenceController(EvidenceService evidence){this.evidence=evidence;}
    @ModelAttribute public void privateResponse(jakarta.servlet.http.HttpServletResponse response) {
        response.setHeader("Cache-Control","no-store");response.setHeader("X-Content-Type-Options","nosniff");
    }
    private static Long actor(HttpServletRequest request) {
        if(!(request.getAttribute("uid") instanceof Number id))throw new IllegalArgumentException("需要已登录账号");return id.longValue();
    }
    @GetMapping public ApiResult<?> history(HttpServletRequest request){return ApiResult.ok(evidence.history(actor(request)));}
    @GetMapping("/targets") public ApiResult<?> targets(HttpServletRequest request){return ApiResult.ok(evidence.targets(actor(request)));}
    @GetMapping("/targets/{agent}/samples") public ApiResult<?> samples(@PathVariable String agent,HttpServletRequest request){return ApiResult.ok(evidence.samples(agent,actor(request)));}
    @PostMapping public ApiResult<?> create(@RequestBody EvidenceService.Request body,HttpServletRequest request){return ApiResult.ok(evidence.create(body,actor(request)));}
    @DeleteMapping("/{id}") public ApiResult<?> delete(@PathVariable String id,HttpServletRequest request){evidence.delete(id,actor(request));return ApiResult.ok(null);}
    @GetMapping("/{id}/download") public ResponseEntity<byte[]> download(@PathVariable String id,HttpServletRequest request) {
        var file=evidence.download(id,actor(request));
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_OCTET_STREAM)
                .header(HttpHeaders.CONTENT_DISPOSITION,"attachment; filename=\""+file.filename()+"\"")
                .header(HttpHeaders.CACHE_CONTROL,"no-store").header("X-Content-Type-Options","nosniff")
                .header("Content-Security-Policy","sandbox; default-src 'none'")
                .header("X-Content-SHA256",file.sha256()).body(file.bytes());
    }
}
