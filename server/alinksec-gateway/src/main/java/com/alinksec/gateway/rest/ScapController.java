package com.alinksec.gateway.rest;

import com.alinksec.common.web.ApiResult;
import com.alinksec.service.baseline.ScapPackage;
import com.alinksec.service.baseline.ScapPackageService;
import com.alinksec.service.baseline.ScapReadiness;
import com.alinksec.service.baseline.ScapResults;
import com.alinksec.service.baseline.ScapTaskService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/baseline/scap")
public class ScapController {
    private final ScapPackageService packages;
    private final ScapTaskService tasks;
    private final JdbcTemplate jdbc;
    public ScapController(ScapPackageService packages,ScapTaskService tasks,JdbcTemplate jdbc) {this.packages=packages;this.tasks=tasks;this.jdbc=jdbc;}
    public record Selection(String packageId,List<String> agentIds,String name) {}
    @GetMapping("/packages") public ApiResult<List<Map<String,Object>>> packages() {return ApiResult.ok(packages.list());}
    @GetMapping("/packages/{id}") public ApiResult<Map<String,Object>> content(@PathVariable String id) {return ApiResult.ok(packages.detail(id));}
    @PostMapping("/packages/import") public ApiResult<Map<String,Object>> importContent(@RequestParam("file") MultipartFile file,HttpServletRequest request) throws java.io.IOException {
        if (file.getSize()>ScapPackage.MAX_ARCHIVE) throw new IllegalArgumentException("SCAP ZIP 最多 2 MiB");
        try (var input=file.getInputStream()) {return ApiResult.ok(packages.importContent(input.readNBytes(ScapPackage.MAX_ARCHIVE+1),actor(request)));}
    }
    @PostMapping("/packages/{id}/decision") public ApiResult<Map<String,Object>> decide(@PathVariable String id,@RequestBody ScapPackageService.Decision decision,HttpServletRequest request) {
        return ApiResult.ok(packages.decide(id,decision,actor(request)));
    }
    @GetMapping("/packages/{id}/content") public ResponseEntity<byte[]> downloadContent(@PathVariable String id) {return attachment(packages.content(id),"application/zip","scap-content.zip");}
    @GetMapping("/packages/{id}/source") public ResponseEntity<byte[]> downloadSource(@PathVariable String id) {return attachment(packages.source(id),"application/zip","scap-original.zip");}
    @GetMapping("/targets") public ApiResult<List<Map<String,Object>>> targets() {return ApiResult.ok(ScapReadiness.targets(jdbc));}
    @PostMapping("/tasks") public ApiResult<Map<String,String>> create(@RequestBody Selection selection,HttpServletRequest request) {
        return ApiResult.ok(Map.of("taskId",tasks.create(selection.packageId(),selection.agentIds(),selection.name(),actor(request),false)));
    }
    @GetMapping("/tasks") public ApiResult<Map<String,Object>> tasks(@RequestParam(defaultValue="1") int page,@RequestParam(defaultValue="20") int size) {return ApiResult.ok(tasks.list(page,size));}
    @GetMapping("/tasks/{id}") public ApiResult<Map<String,Object>> task(@PathVariable String id) {return ApiResult.ok(tasks.detail(id));}
    @GetMapping("/tasks/{id}/content") public ResponseEntity<byte[]> taskContent(@PathVariable String id) {return attachment(tasks.content(id),"application/zip","scap-task-content.zip");}
    @GetMapping("/tasks/{id}/agents/{agent}/evidence") public ResponseEntity<byte[]> evidence(@PathVariable String id,@PathVariable String agent) {
        return attachment(ScapResults.export(jdbc,id,agent),"application/json","scap-evidence.json");
    }
    private static Long actor(HttpServletRequest request) {return request.getAttribute("uid") instanceof Number n?n.longValue():null;}
    private static ResponseEntity<byte[]> attachment(byte[] data,String type,String filename) {
        return ResponseEntity.ok().header("Content-Type",type).header("Content-Disposition","attachment; filename=\""+filename+"\"")
                .header("Cache-Control","no-store").header("X-Content-Type-Options","nosniff").header("X-Content-SHA256",ScapPackage.digest(data)).body(data);
    }
}
