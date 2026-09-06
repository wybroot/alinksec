package com.alinksec.service.upgrade;

import com.alinksec.service.command.CommandService;
import com.alinksec.service.config.AlinkSecProperties;
import com.alinksec.service.download.AgentDownloadTokenService;
import com.alinksec.proto.CmdAgentUpgrade;
import com.alinksec.proto.Command;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Agent 灰度升级（docs/01 §6.4）：
 * 上传升级包（sha256 服务端核算）→ 选定主机下发 CmdAgentUpgrade
 * → Agent 限速下载校验替换 → 退出由 systemd/SCM 拉起新版本 → 心跳上报新版本。
 * 旧版本 Agent 侧保留 .old，可人工回滚。
 */
@Service
public class UpgradeService {

    private static final Logger log = LoggerFactory.getLogger(UpgradeService.class);

    private final JdbcTemplate jdbc;
    private final CommandService commandService;
    private final AlinkSecProperties props;
    private final AgentDownloadTokenService downloadTokens;

    public UpgradeService(JdbcTemplate jdbc, CommandService commandService, AlinkSecProperties props,
                          AgentDownloadTokenService downloadTokens) {
        this.jdbc = jdbc;
        this.commandService = commandService;
        this.props = props;
        this.downloadTokens = downloadTokens;
    }

    /** 上传升级包：{version, platform} 由前端指定，落盘 + 记录。 */
    public Map<String, Object> upload(InputStream in, String version, String platform,
                                      String notes, Long uploadedBy) throws IOException {
        if (version == null || version.isBlank() || platform == null || platform.isBlank()) {
            throw new IllegalArgumentException("version 与 platform 必填（如 1.2.0 / linux-amd64）");
        }
        Path dir = Path.of(props.getUpgrade().getStorageDir());
        Files.createDirectories(dir);
        Path tmp = dir.resolve("upload-" + UUID.randomUUID() + ".pkg");
        Files.copy(in, tmp, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        try {
            Integer exists = jdbc.queryForObject(
                    "SELECT count(*) FROM t_agent_upgrade_package WHERE version = ? AND platform = ?",
                    Integer.class, version, platform);
            if (exists != null && exists > 0) {
                throw new IllegalArgumentException("该版本已存在: " + version + "/" + platform);
            }
            String sha256 = sha256(tmp);
            String packageKey = version + "-" + platform + ".bin";
            Files.move(tmp, dir.resolve(packageKey), java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            jdbc.update("""
                    INSERT INTO t_agent_upgrade_package (version, platform, package_key, sha256, size, notes, uploaded_by)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, version, platform, packageKey, sha256, Files.size(dir.resolve(packageKey)),
                    notes, uploadedBy);
            log.info("升级包已上传: version={} platform={} sha256={}", version, platform, sha256);
            return Map.of("version", version, "platform", platform, "sha256", sha256);
        } finally {
            Files.deleteIfExists(tmp);
        }
    }

    /** 灰度下发：按 agent 列表（前端选分组/多选），逐台下发指令。 */
    public Map<String, Object> dispatch(long packageId, List<String> agentIds, Long operatedBy) {
        Map<String, Object> pkg = jdbc.queryForMap(
                "SELECT version, platform, package_key, sha256 FROM t_agent_upgrade_package WHERE id = ?",
                packageId);
        agentIds = agentIds == null ? List.of() : agentIds.stream().filter(a -> !a.isBlank()).toList();
        if (agentIds.isEmpty()) {
            throw new IllegalArgumentException("请选择升级目标主机");
        }
        for (String agentId : agentIds) {
            CmdAgentUpgrade cmd = CmdAgentUpgrade.newBuilder()
                    .setVersion((String) pkg.get("version"))
                    .setDownloadUrl(downloadUrl(agentId, (String) pkg.get("package_key")))
                    .setSha256((String) pkg.get("sha256"))
                    .build();
            commandService.dispatch(agentId, Command.newBuilder().setAgentUpgrade(cmd), operatedBy);
        }
        log.info("升级指令已下发: version={} agents={}", pkg.get("version"), agentIds.size());
        return Map.of("dispatched", agentIds.size(), "version", pkg.get("version"));
    }

    public List<Map<String, Object>> packages() {
        return jdbc.queryForList(
                "SELECT id, version, platform, sha256, size, notes, created_at "
                        + "FROM t_agent_upgrade_package ORDER BY created_at DESC");
    }

    /** 当前各版本 Agent 分布（心跳刷新的 agent_version） */
    public List<Map<String, Object>> versionDistribution() {
        return jdbc.queryForList("""
                SELECT agent_version AS version, count(*) AS count,
                        bool_and(status = 1) FILTER (WHERE status = 1) AS all_online
                FROM t_agent WHERE deleted = false
                GROUP BY agent_version ORDER BY count DESC
                """);
    }

    public Path packagePath(String packageKey) {
        String name = Path.of(packageKey).getFileName().toString();
        return Path.of(props.getUpgrade().getStorageDir()).resolve(name);
    }

    private String downloadUrl(String agentId, String packageKey) {
        String base = props.getUpgrade().getDownloadBaseUrl().replaceAll("/+$", "");
        return base + "/api/upgrade/download?packageKey=" + packageKey
                + "&token=" + downloadTokens.issue(agentId, "agent-upgrade", packageKey);
    }

    private static String sha256(Path file) throws IOException {
        try (InputStream in = Files.newInputStream(file)) {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) > 0) {
                md.update(buf, 0, n);
            }
            return HexFormat.of().formatHex(md.digest());
        } catch (Exception e) {
            throw new IOException("sha256 计算失败", e);
        }
    }
}
