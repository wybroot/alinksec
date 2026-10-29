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
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.io.InputStream;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Agent 灰度升级（docs/01 §6.4）：
 * 上传升级包（sha256 服务端核算）→ 选定主机下发 CmdAgentUpgrade
 * → Agent 限速下载校验替换 → 退出由 systemd/SCM 拉起新版本 → 心跳上报新版本。
 * 独立看护确认新进程健康，失败自动恢复旧版本；仅支持声明升级契约 1 的原生服务。
 */
@Service
public class UpgradeService {

    private static final Logger log = LoggerFactory.getLogger(UpgradeService.class);
    private static final Set<String> PLATFORMS = Set.of("linux-amd64", "linux-arm64", "windows-amd64");

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
        requirePlatform(platform);
        if (!version.matches("[A-Za-z0-9][A-Za-z0-9._+\\-]{0,127}")) {
            throw new IllegalArgumentException("version 必须是最多128字符的安全版本标识");
        }
        Path dir = Path.of(props.getUpgrade().getStorageDir());
        Files.createDirectories(dir);
        Path tmp = Files.createTempFile(dir,"upload-",".pkg");
        Path destination=dir.resolve(version+"-"+platform+".bin");
        boolean moved=false, saved=false;
        try {
            try(var output=Files.newOutputStream(tmp)) {
                byte[] buffer=new byte[8192];long total=0;int count;
                while((count=in.read(buffer))!=-1) {
                    total+=count;if(total>128L*1024*1024) throw new IllegalArgumentException("Agent升级包不能超过128MiB");
                    output.write(buffer,0,count);
                }
            }
            Integer exists = jdbc.queryForObject(
                    "SELECT count(*) FROM t_agent_upgrade_package WHERE version = ? AND platform = ?",
                    Integer.class, version, platform);
            if (exists != null && exists > 0) {
                throw new IllegalArgumentException("该版本已存在: " + version + "/" + platform);
            }
            String sha256 = sha256(tmp);
            String packageKey = version + "-" + platform + ".bin";
            // CREATE_NEW performs the existence check and creation atomically;
            // a plain move can race another publisher's destination check.
            try(var output=Files.newOutputStream(destination,java.nio.file.StandardOpenOption.CREATE_NEW,
                    java.nio.file.StandardOpenOption.WRITE)) {
                moved=true;
                Files.copy(tmp,output);
            }
            jdbc.update("""
                    INSERT INTO t_agent_upgrade_package (version, platform, package_key, sha256, size, notes, uploaded_by)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, version, platform, packageKey, sha256, Files.size(dir.resolve(packageKey)),
                    notes, uploadedBy);
            saved=true;
            log.info("升级包已上传: version={} platform={} sha256={}", version, platform, sha256);
            return Map.of("version", version, "platform", platform, "sha256", sha256);
        } finally {
            try { Files.deleteIfExists(tmp); }
            finally { if(moved && !saved) Files.deleteIfExists(destination); }
        }
    }

    /** 灰度下发：按 agent 列表（前端选分组/多选），逐台下发指令。 */
    @Transactional
    public Map<String, Object> dispatch(long packageId, List<String> agentIds, Long operatedBy) {
        Map<String, Object> pkg = jdbc.queryForMap(
                "SELECT version, platform, package_key, sha256 FROM t_agent_upgrade_package WHERE id = ?",
                packageId);
        String platform = (String) pkg.get("platform");
        requirePlatform(platform);
        agentIds = agentIds == null ? List.of() : agentIds.stream()
                .filter(a -> a != null && !a.isBlank()).distinct().toList();
        if (agentIds.isEmpty() || agentIds.size() > 500) {
            throw new IllegalArgumentException("请选择 1 至 500 台升级目标主机");
        }
        // Validate every target before creating any command in a mixed-architecture batch.
        for (String agentId : agentIds) {
            List<Map<String, Object>> hosts = jdbc.queryForList(
                    "SELECT os_type, arch, upgrade_contract FROM t_agent WHERE agent_id = ? AND status <> 4 AND deleted=false", agentId);
            if (hosts.isEmpty()) {
                throw new IllegalArgumentException("升级目标主机不存在: " + agentId);
            }
            Map<String, Object> host = hosts.get(0);
            if (!(host.get("upgrade_contract") instanceof Number capability) || capability.intValue()!=1) {
                throw new IllegalArgumentException("主机未声明原生升级看护能力，请先人工更新 Agent 并作为 systemd/SCM 服务启动: " + agentId);
            }
            String target = hostPlatform(((Number) host.get("os_type")).intValue(), (String) host.get("arch"));
            if (!platform.equals(target)) {
                throw new IllegalArgumentException("升级包平台 " + platform + " 与主机 " + agentId
                        + " 的平台 " + target + " 不匹配");
            }
        }
        String batchId = java.util.UUID.randomUUID().toString();
        jdbc.update("INSERT INTO t_upgrade_batch(id,package_id,created_by) VALUES(?,?,?)", batchId, packageId, operatedBy);
        for (String agentId : agentIds) {
            CmdAgentUpgrade cmd = CmdAgentUpgrade.newBuilder()
                    .setVersion((String) pkg.get("version"))
                    .setDownloadUrl(downloadUrl(agentId, (String) pkg.get("package_key")))
                    .setSha256((String) pkg.get("sha256"))
                    .setExecutionContract(1)
                    .build();
            String commandId = commandService.dispatchAfterCommit(agentId, Command.newBuilder().setAgentUpgrade(cmd), operatedBy);
            jdbc.update("INSERT INTO t_upgrade_target(batch_id,agent_id,command_id) VALUES(?,?,?)", batchId, agentId, commandId);
        }
        log.info("升级指令已下发: version={} agents={}", pkg.get("version"), agentIds.size());
        return Map.of("batchId", batchId, "dispatched", agentIds.size(), "version", pkg.get("version"));
    }

    public Map<String,Object> targets(long packageId, int page) {
        String platform = jdbc.queryForObject("SELECT platform FROM t_agent_upgrade_package WHERE id=?", String.class, packageId);
        requirePlatform(platform);
        String[] parts = platform.split("-");
        int os = parts[0].equals("linux") ? 1 : 2;
        String[] arches = parts[1].equals("amd64") ? new String[]{"amd64", "x86_64", "x64"} : new String[]{"arm64", "aarch64", "arm64"};
        String condition = " FROM t_agent WHERE status<>4 AND deleted=false AND upgrade_contract=1 AND os_type=? AND LOWER(arch) IN (?,?,?)";
        return Map.of("total", jdbc.queryForObject("SELECT count(*)" + condition, Long.class, os, arches[0], arches[1], arches[2]),
            "list", jdbc.queryForList("SELECT agent_id,hostname,ip,agent_version,status" + condition + " ORDER BY hostname,agent_id LIMIT 20 OFFSET ?",
                os, arches[0], arches[1], arches[2], (Math.max(1,page)-1)*20));
    }

    public Map<String,Object> batches(int page) {
        return Map.of("total", jdbc.queryForObject("SELECT count(*) FROM t_upgrade_batch", Long.class),
            "list", jdbc.queryForList("""
                SELECT b.id,b.created_at,p.version,p.platform,p.sha256,
                  (SELECT count(*) FROM t_upgrade_target t WHERE t.batch_id=b.id) AS target_count
                FROM t_upgrade_batch b JOIN t_agent_upgrade_package p ON p.id=b.package_id
                ORDER BY b.created_at DESC,b.id DESC LIMIT 20 OFFSET ?
                """, (Math.max(1,page)-1)*20));
    }

    public Map<String,Object> batchTargets(String batchId, int page) {
        var rows = jdbc.queryForList("""
            SELECT t.agent_id,a.hostname,a.agent_version,a.status AS host_status,t.command_id,
                c.status,c.result,c.created_at,c.acked_at,c.finished_at,p.version AS expected_version,p.sha256 AS expected_sha256
            FROM t_upgrade_target t JOIN t_upgrade_batch b ON b.id=t.batch_id
            JOIN t_agent_upgrade_package p ON p.id=b.package_id
            LEFT JOIN t_agent a ON a.agent_id=t.agent_id LEFT JOIN t_command c ON c.cmd_id=t.command_id
            WHERE t.batch_id=? ORDER BY t.agent_id LIMIT 20 OFFSET ?
            """, batchId, (Math.max(1,page)-1)*20);
        for (var row : rows) {
            var result = com.alinksec.common.util.JsonUtils.read(String.valueOf(row.getOrDefault("result", "null")));
            String message = result == null ? "" : result.path("message").asText("");
            row.put("result_message", message);
            // A legacy plain-text acknowledgement is not a digest confirmation.
            row.put("confirmation", "unverified");
            try {
                var evidence = com.alinksec.common.util.JsonUtils.read(message);
                if (evidence != null && evidence.isObject()) {
                    row.put("result_message", evidence.path("message").asText(message));
                    row.put("rolled_back", evidence.path("rolled_back").asBoolean(false));
                    row.put("receipt", evidence);
                    if (((Number)row.get("status")).intValue()==4 && evidence.path("success").asBoolean()
                        && evidence.path("complete").asBoolean() && row.get("expected_version").equals(evidence.path("version").asText())
                        && row.get("expected_sha256").equals(evidence.path("sha256").asText())) row.put("confirmation", "verified");
                }
            } catch (RuntimeException ignored) { /* Legacy acknowledgement: show message and unknown confirmation. */ }
        }
        return Map.of("total", jdbc.queryForObject("SELECT count(*) FROM t_upgrade_target WHERE batch_id=?", Long.class, batchId), "list", rows);
    }

    private static void requirePlatform(String platform) {
        if (platform == null || !PLATFORMS.contains(platform)) {
            throw new IllegalArgumentException("不支持的 Agent 平台: " + platform);
        }
    }

    private static String hostPlatform(int osType, String arch) {
        String os = switch (osType) {
            case 1 -> "linux";
            case 2 -> "windows";
            default -> "unknown";
        };
        // Older Agents reported kernel names from gopsutil instead of Go architecture names.
        String normalized = switch (arch == null ? "" : arch.toLowerCase(Locale.ROOT)) {
            case "amd64", "x86_64", "x64" -> "amd64";
            case "arm64", "aarch64" -> "arm64";
            default -> "unknown";
        };
        return os + "-" + normalized;
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
                        CASE WHEN SUM(CASE WHEN status <> 1 THEN 1 ELSE 0 END) = 0 THEN true ELSE false END AS all_online
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
        return base + "/api/upgrade/download?packageKey=" + URLEncoder.encode(packageKey, StandardCharsets.UTF_8)
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
