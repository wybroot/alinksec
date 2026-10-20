package com.alinksec.gateway.rest;

import com.alinksec.common.web.ApiResult;
import com.alinksec.service.virus.YaraService;
import org.springframework.web.bind.annotation.*;
import java.util.Map;

@RestController
@RequestMapping("/api/virus")
public class YaraController {
    private final YaraService service;
    public YaraController(YaraService service){this.service=service;}
    @GetMapping("/yara-status")
    public ApiResult<Map<String,Object>> status(@RequestParam(defaultValue="1") int page,@RequestParam(defaultValue="20") int size) {
        return ApiResult.ok(service.status(page,size));
    }
}
