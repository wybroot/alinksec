package com.alinksec.gateway.rest;

import com.alinksec.common.web.ApiResult;
import com.alinksec.service.baseline.BaselineUpstreamService;
import com.alinksec.service.baseline.ScapPackage;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.util.*;

@RestController
@RequestMapping("/api/baseline/upstreams")
public class BaselineUpstreamController {
    private final BaselineUpstreamService service;
    public BaselineUpstreamController(BaselineUpstreamService service){this.service=service;}
    @GetMapping public ApiResult<List<Map<String,Object>>> list(){return ApiResult.ok(service.list());}
    @GetMapping("/{id}") public ApiResult<Map<String,Object>> detail(@PathVariable String id){return ApiResult.ok(service.detail(id));}
    @PutMapping("/{id}/schedule") public ApiResult<Map<String,Object>> schedule(@PathVariable String id,@RequestBody BaselineUpstreamService.Schedule body,HttpServletRequest request){return ApiResult.ok(service.schedule(id,body,actor(request)));}
    @PostMapping("/{id}/sync") public ApiResult<Map<String,String>> sync(@PathVariable String id,HttpServletRequest request){return ApiResult.ok(service.trigger(id,actor(request)));}
    @PostMapping("/{id}/releases/{release}/retry") public ApiResult<Map<String,Object>> retry(@PathVariable String id,@PathVariable String release,HttpServletRequest request){return ApiResult.ok(service.retry(id,release,actor(request)));}
    @GetMapping("/{id}/receipts/{receipt}") public ResponseEntity<byte[]> receipt(@PathVariable String id,@PathVariable String receipt){return attachment(service.receipt(id,receipt),"application/json","signed-index.json");}
    @GetMapping("/{id}/releases/{release}/artifact") public ResponseEntity<byte[]> artifact(@PathVariable String id,@PathVariable String release){return attachment(service.artifact(id,release),"application/octet-stream","upstream-original.bin");}
    private static Long actor(HttpServletRequest request){return request.getAttribute("uid") instanceof Number n?n.longValue():null;}
    private static ResponseEntity<byte[]> attachment(byte[] data,String type,String filename){return ResponseEntity.ok().header("Content-Type",type).header("Content-Disposition","attachment; filename=\""+filename+"\"").header("Cache-Control","no-store").header("X-Content-Type-Options","nosniff").header("X-Content-SHA256",ScapPackage.digest(data)).body(data);}
}
