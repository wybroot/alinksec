package com.alinksec.gateway.rest;

import com.alinksec.common.web.ApiResult;
import com.alinksec.service.upgrade.UpgradeService;
import com.alinksec.service.download.AgentDownloadTokenService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.core.io.FileSystemResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
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
 * Agent 灰度升级（docs/01 §6.4）：升级包上传 / 列表 / 版本分布 / 灰度下发。
 * 下载端点无 JWT（package_key 含版本与平台，内网部署）。
 */
@RestController
@RequestMapping("/api/upgrade")
public class UpgradeController {

    private final UpgradeService upgradeService;
    private final AgentDownloadTokenService downloadTokens;

    public UpgradeController(UpgradeService upgradeService, AgentDownloadTokenService downloadTokens) {
        this.upgradeService = upgradeService;
        this.downloadTokens = downloadTokens;
    }

    /** 上传升级包（multipart：file + version + platform + notes） */
    @PostMapping("/packages")
    public ApiResult<Map<String, Object>> upload(@RequestParam("file") MultipartFile file,
                                                 @RequestParam String version,
                                                 @RequestParam String platform,
                                                 @RequestParam(required = false) String notes,
                                                 HttpServletRequest request) throws Exception {
        Long uid = request.getAttribute("uid") instanceof Number n ? n.longValue() : null;
        return ApiResult.ok(upgradeService.upload(file.getInputStream(), version, platform, notes, uid));
    }

    /** 灰度下发：body = {packageId, agentIds:[]} */
    @PostMapping("/dispatch")
    public ApiResult<Map<String, Object>> dispatch(@RequestBody Map<String, Object> body,
                                                   HttpServletRequest request) {
        Long uid = request.getAttribute("uid") instanceof Number n ? n.longValue() : null;
        long packageId = ((Number) body.get("packageId")).longValue();
        @SuppressWarnings("unchecked")
        List<String> agentIds = (List<String>) body.getOrDefault("agentIds", List.of());
        return ApiResult.ok(upgradeService.dispatch(packageId, agentIds, uid));
    }

    @GetMapping("/packages")
    public ApiResult<List<Map<String, Object>>> packages() {
        return ApiResult.ok(upgradeService.packages());
    }

    @GetMapping("/versions")
    public ApiResult<List<Map<String, Object>>> versions() {
        return ApiResult.ok(upgradeService.versionDistribution());
    }

    /** 升级包下载（Agent 拉取端点，无 JWT） */
    @GetMapping("/download")
    public ResponseEntity<FileSystemResource> download(@RequestParam String packageKey, @RequestParam String token) {
        if (!downloadTokens.isAuthorized(token, "agent-upgrade", packageKey)) {
            return ResponseEntity.notFound().build();
        }
        Path path = upgradeService.packagePath(packageKey);
        if (!Files.isRegularFile(path)) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + path.getFileName() + "\"")
                .body(new FileSystemResource(path));
    }
}
