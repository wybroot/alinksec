package com.alinksec.gateway.rest;

import com.alinksec.common.web.ApiResult;
import com.alinksec.service.virus.ClamavService;
import org.springframework.web.bind.annotation.*;
import java.util.Map;

@RestController
@RequestMapping("/api/virus")
public class ClamavController {
    private final ClamavService service;
    public ClamavController(ClamavService service){this.service=service;}
    @GetMapping("/clamav-status")
    public ApiResult<Map<String,Object>> status(@RequestParam(defaultValue="1") int page,@RequestParam(defaultValue="20") int size) {
        return ApiResult.ok(service.status(page,size));
    }
}
