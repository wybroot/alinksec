package com.alinksec.gateway.rest;

import com.alinksec.common.web.ApiResult;
import com.alinksec.service.query.VirusQueryService;
import com.alinksec.service.virus.VirusActionService;
import com.alinksec.service.virus.VirusDbService;
import com.alinksec.service.virus.VirusTaskService;
import com.alinksec.service.download.AgentDownloadTokenService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.core.io.Resource;
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

import java.util.List;
import java.util.Map;

/**
 * 病毒查杀：扫描任务 / 检出处置 / 特征库管理 / 白名单。
 * 下载端点（/api/virus/db/download）供 Agent 拉取特征包（无 JWT，package_key 不可猜测）。
 */
@RestController
@RequestMapping("/api/virus")
public class VirusController {
    public record WhitelistRequest(String type,String value,String remark) {}
    public record RealtimeRequest(Boolean enabled,String action) {}
    private static String text(com.fasterxml.jackson.databind.JsonNode body,String field,boolean optional) {
        var value=body.get(field);
        if(optional && (value==null || value.isNull())) return null;
        if(value==null || !value.isTextual()) throw new IllegalArgumentException(field+" 必须为文本");
        return value.textValue();
    }
    private static List<String> texts(com.fasterxml.jackson.databind.JsonNode body,String field,boolean optional) {
        var values=body.get(field);
        if(optional && (values==null || values.isNull())) return List.of();
        if(values==null || !values.isArray() || values.size()>500) throw new IllegalArgumentException(field+" 必须为有界数组");
        var list=new java.util.ArrayList<String>();
        for(var value:values) { if(!value.isTextual()) throw new IllegalArgumentException(field+" 成员必须为文本"); list.add(value.textValue()); }
        return list;
    }
    private static Long actor(HttpServletRequest request) {
        if(!(request.getAttribute("uid") instanceof Number n)) throw new IllegalArgumentException("检测操作需要登录账号");
        return n.longValue();
    }

    private final VirusQueryService query;
    private final VirusTaskService taskService;
    private final VirusActionService actionService;
    private final VirusDbService dbService;
    private final AgentDownloadTokenService downloadTokens;

    public VirusController(VirusQueryService query, VirusTaskService taskService,
                           VirusActionService actionService, VirusDbService dbService,
                           AgentDownloadTokenService downloadTokens) {
        this.query = query;
        this.taskService = taskService;
        this.actionService = actionService;
        this.dbService = dbService;
        this.downloadTokens = downloadTokens;
    }

    /** 创建病毒扫描任务：mode 1快速 2全盘 3自定义（paths） */
    @PostMapping("/tasks")
    public ApiResult<Map<String, Object>> createTask(@RequestBody com.fasterxml.jackson.databind.JsonNode body,
                                                     HttpServletRequest request) {
        var mode=body.get("mode");
        if(mode!=null && (!mode.isIntegralNumber() || !mode.canConvertToInt())) throw new IllegalArgumentException("mode 必须为整数");
        long taskId = taskService.createTask(text(body,"name",true),texts(body,"agentIds",false),mode==null?1:mode.intValue(),texts(body,"paths",true),actor(request),text(body,"engine",true));
        return ApiResult.ok(Map.of("taskId", taskId));
    }

    /** 检出处置：action = quarantine / delete / restore / whitelist */
    @PostMapping("/findings/actions")
    public ApiResult<Map<String, Object>> act(@RequestBody com.fasterxml.jackson.databind.JsonNode body,
                                              HttpServletRequest request) {
        var values=body.path("findingIds");
        if(!values.isArray() || values.isEmpty() || values.size()>32) throw new IllegalArgumentException("findingIds 需要1至32个整数");
        var ids=new java.util.ArrayList<Long>();
        for(var value:values) { if(!value.isIntegralNumber() || !value.canConvertToLong()) throw new IllegalArgumentException("检出编号必须为整数"); ids.add(value.longValue()); }
        return ApiResult.ok(actionService.act(ids,text(body,"action",false),actor(request)));
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
    public ResponseEntity<Resource> download(@RequestParam String packageKey, @RequestParam String token) throws java.io.IOException {
        if (!downloadTokens.isAuthorized(token, "virus-db", packageKey)) {
            return ResponseEntity.notFound().build();
        }
        var artifact = dbService.downloadPackage(packageKey);
        if (artifact == null) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + packageKey + "\"")
                .contentLength(artifact.size())
                .body(artifact.resource());
    }

    /** 新增白名单（type = hash / path） */
    @PostMapping("/whitelist")
    public ApiResult<Void> addWhitelist(@RequestBody WhitelistRequest body,
                                        HttpServletRequest request) {
        actionService.addWhitelistEntry(body.type(),body.value(),body.remark(),actor(request));
        return ApiResult.ok(null);
    }

    @DeleteMapping("/whitelist/{id}")
    public ApiResult<Void> removeWhitelist(@PathVariable long id,HttpServletRequest request) {
        actionService.removeWhitelist(id,actor(request));
        return ApiResult.ok(null);
    }

    /* ---------- 查询 ---------- */

    @PostMapping("/realtime")
    public ApiResult<Map<String,Object>> realtime(@RequestBody com.fasterxml.jackson.databind.JsonNode body,HttpServletRequest request) {
        if(!body.path("enabled").isBoolean()) throw new IllegalArgumentException("周期防护开关必须为布尔值");
        return ApiResult.ok(actionService.updateRealtime(body.path("enabled").booleanValue(),text(body,"action",false),actor(request)));
    }
    @GetMapping("/tasks/{id}/evidence")
    public ApiResult<List<Map<String,Object>>> taskEvidence(@PathVariable long id) { return ApiResult.ok(query.taskEvidence(id)); }
    @GetMapping("/findings/{id}/history")
    public ApiResult<List<Map<String,Object>>> history(@PathVariable long id) { return ApiResult.ok(query.actionHistory(id)); }

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
