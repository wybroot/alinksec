package com.alinksec.gateway.rest;

import com.alinksec.common.web.ApiResult;
import com.alinksec.service.query.VirusQueryService;
import com.alinksec.service.virus.VirusActionService;
import com.alinksec.service.virus.VirusDbService;
import com.alinksec.service.virus.VirusTaskService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.core.io.FileSystemResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

/**
 * 病毒查杀：扫描任务 / 检出处置 / 特征库管理 / 白名单。
 * 下载端点（/api/virus/db/download）供 Agent 拉取特征包（无 JWT，package_key 不可猜测）。
 */
@RestController
@RequestMapping("/api/virus")
public class VirusController {

    private final VirusQueryService query;
    private final VirusTaskService taskService;
    private final VirusActionService actionService;
    private final VirusDbService dbService;

    public VirusController(VirusQueryService query, VirusTaskService taskService,
                           VirusActionService actionService, VirusDbService dbService) {
        this.query = query;
        this.taskService = taskService;
        this.actionService = actionService;
        this.dbService = dbService;
    }

    /** 创建病毒扫描任务：mode 1快速 2全盘 3自定义（paths） */
    @PostMapping("/tasks")
    public ApiResult<Map<String, Object>> createTask(@RequestBody Map<String, Object> body,
                                                     HttpServletRequest request) {
        Long uid = request.getAttribute("uid") instanceof Number n ? n.longValue() : null;
        @SuppressWarnings("unchecked")
        List<String> agentIds = (List<String>) body.getOrDefault("agentIds", List.of());
        int mode = body.get("mode") instanceof Number m ? m.intValue() : VirusTaskService.MODE_QUICK;
        @SuppressWarnings("unchecked")
        List<String> paths = (List<String>) body.getOrDefault("paths", List.of());
        String name = (String) body.get("name");
        long taskId = taskService.createTask(name, agentIds, mode, paths, uid);
        return ApiResult.ok(Map.of("taskId", taskId));
    }

    /** 检出处置：action = quarantine / delete / restore / whitelist */
    @PostMapping("/findings/actions")
    public ApiResult<Map<String, Object>> act(@RequestBody Map<String, Object> body,
                                              HttpServletRequest request) {
        Long uid = request.getAttribute("uid") instanceof Number n ? n.longValue() : null;
        @SuppressWarnings("unchecked")
        List<Number> ids = (List<Number>) body.getOrDefault("findingIds", List.of());
        String action = String.valueOf(body.get("action"));
        List<Long> findingIds = ids.stream().map(Number::longValue).toList();
        return ApiResult.ok(actionService.act(findingIds, action, uid));
    }

    /** 导入特征库包（zip：manifest.json + hashes.txt），成功后自动推送全部 Agent */
    @PostMapping("/db/import")
    public ApiResult<Map<String, Object>> importDb(@RequestParam("file") MultipartFile file,
                                                   HttpServletRequest request) throws Exception {
        Long uid = request.getAttribute("uid") instanceof Number n ? n.longValue() : null;
        return ApiResult.ok(dbService.importPackage(file.getInputStream(), uid));
    }

    /** 手动触发特征库推送（新装 Agent 补拉场景） */
    @PostMapping("/db/push")
    public ApiResult<Map<String, Object>> pushDb() {
        dbService.pushToAllAgents();
        return ApiResult.ok(Map.of("pushed", true));
    }

    /** 特征包下载（Agent 拉取端点，无 JWT：package_key 为版本号文件名 + 内网部署） */
    @GetMapping("/db/download")
    public ResponseEntity<FileSystemResource> download(@RequestParam String packageKey) {
        Path path = dbService.packagePath(packageKey);
        if (!Files.isRegularFile(path)) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + path.getFileName() + "\"")
                .body(new FileSystemResource(path));
    }

    /** 新增白名单（type = hash / path） */
    @PostMapping("/whitelist")
    public ApiResult<Void> addWhitelist(@RequestBody Map<String, Object> body,
                                        HttpServletRequest request) {
        Long uid = request.getAttribute("uid") instanceof Number n ? n.longValue() : null;
        actionService.addWhitelistEntry(String.valueOf(body.get("type")),
                String.valueOf(body.get("value")), (String) body.get("remark"), uid);
        return ApiResult.ok(null);
    }

    @DeleteMapping("/whitelist/{id}")
    public ApiResult<Void> removeWhitelist(@PathVariable long id) {
        actionService.removeWhitelist(id);
        return ApiResult.ok(null);
    }

    /* ---------- 查询 ---------- */

    @GetMapping("/tasks")
    public ApiResult<Map<String, Object>> tasks(@RequestParam(defaultValue = "1") int page,
                                                @RequestParam(defaultValue = "20") int size) {
        return ApiResult.ok(query.tasks(page, Math.min(size, 100)));
    }

    @GetMapping("/findings")
    public ApiResult<Map<String, Object>> findings(@RequestParam(required = false) Integer status,
                                                   @RequestParam(required = false) String agentId,
                                                   @RequestParam(defaultValue = "1") int page,
                                                   @RequestParam(defaultValue = "20") int size) {
        return ApiResult.ok(query.findings(status, agentId, page, Math.min(size, 100)));
    }

    @GetMapping("/db")
    public ApiResult<List<Map<String, Object>>> dbVersions() {
        return ApiResult.ok(query.dbVersions());
    }

    @GetMapping("/whitelist")
    public ApiResult<List<Map<String, Object>>> whitelist() {
        return ApiResult.ok(query.whitelist());
    }

    @GetMapping("/stats")
    public ApiResult<Map<String, Object>> stats() {
        return ApiResult.ok(query.stats());
    }
}
