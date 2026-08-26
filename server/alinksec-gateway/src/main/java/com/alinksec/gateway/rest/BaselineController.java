package com.alinksec.gateway.rest;

import com.alinksec.common.web.ApiResult;
import com.alinksec.service.baseline.BaselineTaskService;
import com.alinksec.service.query.BaselineQueryService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

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

    public BaselineController(BaselineQueryService query, BaselineTaskService taskService) {
        this.query = query;
        this.taskService = taskService;
    }

    @PostMapping("/tasks")
    public ApiResult<Map<String, Object>> createTask(@RequestBody Map<String, Object> body,
                                                     HttpServletRequest request) {
        Object uidAttr = request.getAttribute("uid");
        Long createdBy = uidAttr instanceof Number n ? n.longValue() : null;
        @SuppressWarnings("unchecked")
        List<String> agentIds = (List<String>) body.getOrDefault("agentIds", List.of());
        @SuppressWarnings("unchecked")
        List<Number> templateIdNums = (List<Number>) body.getOrDefault("templateIds", List.of());
        List<Long> templateIds = templateIdNums.stream().map(Number::longValue).toList();
        String name = (String) body.get("name");
        long taskId = taskService.createTask(name, agentIds, templateIds, createdBy);
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
