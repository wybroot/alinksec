package com.alinksec.gateway.rest;

import com.alinksec.common.web.ApiResult;
import com.alinksec.service.baseline.BaselineTaskService;
import com.alinksec.service.baseline.BaselinePackageService;
import com.alinksec.service.query.BaselineQueryService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;
import java.util.Map;

/**
 * 基线核查：模板/任务查询 + 任务创建下发。
 */
@RestController
@RequestMapping("/api/baseline")
public class BaselineController {

    private final BaselineQueryService query;
    private final BaselineTaskService taskService;
    private final BaselinePackageService packages;

    public BaselineController(BaselineQueryService query, BaselineTaskService taskService, BaselinePackageService packages) {
        this.query = query;
        this.taskService = taskService;
        this.packages = packages;
    }

    public record Selection(List<String> agentIds, List<Long> templateIds, String name) {}
    public record Decision(Boolean approved, String note) {}
    @PostMapping("/coverage")
    public ApiResult<List<Map<String, Object>>> coverage(@RequestBody Selection body) {
        return ApiResult.ok(taskService.coverage(body.agentIds(), body.templateIds()));
    }
    @GetMapping("/packages")
    public ApiResult<List<Map<String, Object>>> packages() { return ApiResult.ok(packages.list()); }
    @GetMapping("/packages/{id}")
    public ApiResult<Map<String, Object>> packageDetail(@PathVariable String id) { return ApiResult.ok(packages.detail(id)); }
    @PostMapping("/packages/import")
    public ApiResult<Map<String, Object>> importPackage(@RequestParam("file") MultipartFile file, HttpServletRequest request) throws java.io.IOException {
        if (file.getSize() > com.alinksec.service.baseline.BaselinePackageFormat.MAX_BYTES) throw new IllegalArgumentException("模板包最多 2 MiB");
        try (var stream = file.getInputStream()) { return ApiResult.ok(packages.importPackage(stream, user(request))); }
    }
    @PostMapping("/packages/{id}/review")
    public ApiResult<Map<String, Object>> review(@PathVariable String id, @RequestBody Decision decision, HttpServletRequest request) {
        if (decision.approved() == null) throw new IllegalArgumentException("请明确审核通过或拒绝");
        return ApiResult.ok(packages.review(id, decision.approved(), decision.note(), user(request)));
    }
    @PostMapping("/packages/{id}/test")
    public ApiResult<Map<String, Object>> test(@PathVariable String id, @RequestBody Selection selection, HttpServletRequest request) {
        return ApiResult.ok(packages.test(id, selection.agentIds(), user(request)));
    }
    @PostMapping("/packages/{id}/publish")
    public ApiResult<Map<String, Object>> publish(@PathVariable String id, @RequestBody Decision decision, HttpServletRequest request) {
        return ApiResult.ok(packages.publish(id, decision.note(), user(request)));
    }
    @PostMapping("/packages/{id}/withdraw")
    public ApiResult<Map<String, Object>> withdraw(@PathVariable String id, @RequestBody Decision decision) {
        return ApiResult.ok(packages.withdraw(id, decision.note()));
    }
    private static Long user(HttpServletRequest request) {
        return request.getAttribute("uid") instanceof Number number ? number.longValue() : null;
    }

    @PostMapping("/tasks")
    public ApiResult<Map<String, Object>> createTask(@RequestBody Selection body,
                                                     HttpServletRequest request) {
        Object uidAttr = request.getAttribute("uid");
        Long createdBy = uidAttr instanceof Number n ? n.longValue() : null;
        long taskId = taskService.createTask(body.name(), body.agentIds(), body.templateIds(), createdBy);
        return ApiResult.ok(Map.of("taskId", taskId));
    }

    @GetMapping("/templates")
    public ApiResult<List<Map<String, Object>>> templates() {
        return ApiResult.ok(query.templates());
    }

    @GetMapping("/templates/{id}/items")
    public ApiResult<Map<String, Object>> templateItems(@PathVariable long id,
                                                        @RequestParam(required = false) String category,
                                                        @RequestParam(required = false) Integer severity) {
        return ApiResult.ok(query.templateItems(id, category, severity));
    }

    @GetMapping("/tasks")
    public ApiResult<Map<String, Object>> tasks(@RequestParam(defaultValue = "1") int page,
                                                @RequestParam(defaultValue = "20") int size) {
        return ApiResult.ok(query.tasks(page, Math.min(size, 100)));
    }

    @GetMapping("/tasks/{id}")
    public ApiResult<Map<String, Object>> taskDetail(@PathVariable long id) {
        Map<String, Object> detail = query.taskDetail(id);
        if (detail == null) {
            return ApiResult.error(30002, "任务不存在");
        }
        return ApiResult.ok(detail);
    }

    @GetMapping("/tasks/{id}/agents/{agentId}/items")
    public ApiResult<List<Map<String, Object>>> taskAgentItems(
            @PathVariable long id, @PathVariable String agentId,
            @RequestParam(required = false) Boolean passed) {
        return ApiResult.ok(query.taskAgentItems(id, agentId, passed));
    }

    @GetMapping("/tasks/{id}/category-stats")
    public ApiResult<List<Map<String, Object>>> taskCategoryStats(@PathVariable long id) {
        return ApiResult.ok(query.taskCategoryStats(id));
    }

    @GetMapping("/latest")
    public ApiResult<Map<String, Object>> latest() {
        return ApiResult.ok(query.latestTaskRows());
    }
}
