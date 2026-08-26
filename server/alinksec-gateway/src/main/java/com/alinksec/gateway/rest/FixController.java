package com.alinksec.gateway.rest;

import com.alinksec.common.web.ApiResult;
import com.alinksec.service.fix.FixTaskService;
import com.alinksec.service.fix.PatchRepoService;
import com.alinksec.service.query.FixQueryService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.core.io.FileSystemResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

/**
 * 一键修复：配置类 / 软件包类任务（审批+维护窗口）/ 补丁仓库管理。
 */
@RestController
@RequestMapping("/api/fix")
public class FixController {

    private final FixTaskService taskService;
    private final FixQueryService query;
    private final PatchRepoService patchRepo;

    public FixController(FixTaskService taskService, FixQueryService query, PatchRepoService patchRepo) {
        this.taskService = taskService;
        this.query = query;
        this.patchRepo = patchRepo;
    }

    /**
     * 创建修复任务：items = [{agentId, itemId}]（基线核查失败项，fixable=true 的才允许）。
     * Agent 执行：备份 → 执行 → 复核 → 失败回滚。
     */
    @PostMapping("/tasks")
    public ApiResult<Map<String, Object>> createTask(@RequestBody Map<String, Object> body,
                                                     HttpServletRequest request) {
        Long uid = request.getAttribute("uid") instanceof Number n ? n.longValue() : null;
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> items = (List<Map<String, Object>>) body.getOrDefault("items", List.of());
        String name = (String) body.get("name");
        long taskId = taskService.createTask(name, items, uid);
        return ApiResult.ok(Map.of("taskId", taskId));
    }

    @GetMapping("/tasks")
    public ApiResult<Map<String, Object>> tasks(@RequestParam(defaultValue = "1") int page,
                                                @RequestParam(defaultValue = "20") int size) {
        return ApiResult.ok(query.tasks(page, Math.min(size, 100)));
    }

    @GetMapping("/tasks/{id}/records")
    public ApiResult<Map<String, Object>> records(@PathVariable long id) {
        return ApiResult.ok(query.taskRecords(id));
    }
}
