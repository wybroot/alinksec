package com.alinksec.service.virus;

import com.alinksec.common.util.JsonUtils;
import com.alinksec.service.config.AlinkSecProperties;
import com.alinksec.service.download.AgentDownloadTokenService;
import com.alinksec.proto.CmdSignatureUpdate;
import com.alinksec.proto.Command;
import com.alinksec.service.command.CommandService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * 病毒特征库管理（docs/05 §1.2）：
 * 导入（zip：manifest.json + hashes.txt）→ 本地磁盘存储 → t_virus_db 版本记录 → 推送 CmdSignatureUpdate。
 *
 * 版本比对：Agent 心跳携带 db_version（proto v8），落后于平台当前版本即按需下发
 * CmdSignatureUpdate；另有「导入后立即推送 + 定时兜底推送」，Agent 端幂等（版本一致直接 ACK DONE）。
 */
@Service
public class VirusDbService {

    private static final Logger log = LoggerFactory.getLogger(VirusDbService.class);

    private final JdbcTemplate jdbc;
    private final CommandService commandService;
    private final AlinkSecProperties props;
    private final AgentDownloadTokenService downloadTokens;

    public VirusDbService(JdbcTemplate jdbc, CommandService commandService, AlinkSecProperties props,
                          AgentDownloadTokenService downloadTokens) {
        this.jdbc = jdbc;
        this.commandService = commandService;
        this.props = props;
        this.downloadTokens = downloadTokens;
    }

    /**
     * 导入特征库包：解析校验 zip 结构 → 落盘 → 记录版本 → 推送全部 Agent。
     * 返回 {dbVersion, hashCount, ruleCount}。
     */
    public Map<String, Object> importPackage(InputStream in, Long importedBy) throws IOException {
        Path dir = Path.of(props.getSignature().getStorageDir());
        Files.createDirectories(dir);
        Path tmp = dir.resolve("import-" + UUID.randomUUID() + ".zip");
        Files.copy(in, tmp, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        try {
            Parsed pkg = parseZip(tmp);
            String sha256 = sha256(tmp);
            if (!sha256.equalsIgnoreCase(pkg.manifestSha256()) && !pkg.manifestSha256().isBlank()) {
                throw new IllegalArgumentException("manifest 声明的 sha256 与包实际值不一致");
            }
            // 版本号唯一：重复导入同版本报错
            Integer exists = jdbc.queryForObject(
                    "SELECT count(*) FROM t_virus_db WHERE db_version = ?", Integer.class, pkg.version());
            if (exists != null && exists > 0) {
                throw new IllegalArgumentException("特征库版本已存在: " + pkg.version());
            }
            // 固化存储：{db_version}.zip
            Path stored = dir.resolve(pkg.version() + ".zip");
            Files.move(tmp, stored, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            String packageKey = pkg.version() + ".zip";
            jdbc.update("""
                    INSERT INTO t_virus_db (db_version, package_key, sha256, size, hash_count, rule_count, imported_by)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, pkg.version(), packageKey, sha256, Files.size(stored),
                    pkg.hashCount(), pkg.ruleCount(), importedBy);
            log.info("特征库导入成功: version={} sha256={} hash={} rule={}",
                    pkg.version(), sha256, pkg.hashCount(), pkg.ruleCount());
            pushToAllAgents();
            return Map.of("dbVersion", pkg.version(), "hashCount", pkg.hashCount(),
                    "ruleCount", pkg.ruleCount());
        } finally {
            Files.deleteIfExists(tmp);
        }
    }

    /** 存储路径（下载端点用） */
    public Path packagePath(String packageKey) {
        // 防路径穿越：仅取文件名部分
        String name = Path.of(packageKey).getFileName().toString();
        return Path.of(props.getSignature().getStorageDir()).resolve(name);
    }

    /** Agent 下载 URL（package_key 为版本号文件名，不可猜测性由版本号语义承担 + 内网部署） */
    public String downloadUrl(String agentId, String packageKey) {
        String base = props.getSignature().getDownloadBaseUrl().replaceAll("/+$", "");
        return base + "/api/virus/db/download?packageKey=" + packageKey
                + "&token=" + downloadTokens.issue(agentId, "virus-db", packageKey);
    }

    /** 推送最新特征库给全部 Agent（在线即达，离线指令挂起） */
    public void pushToAllAgents() {
        Map<String, Object> latest = latestDb();
        if (latest == null) {
            return;
        }
        List<String> agents = jdbc.queryForList(
                "SELECT agent_id FROM t_agent WHERE deleted = false", String.class);
        for (String agentId : agents) {
            dispatchUpdate(agentId, latest);
        }
        log.info("特征库更新指令已下发: version={} agents={}", latest.get("db_version"), agents.size());
    }

    /** 定时兜底推送（新装 Agent 上线后最长 interval 内拿到最新库；Agent 幂等跳过已装版本） */
    @Scheduled(fixedDelayString = "${alinksec.signature.push-interval-ms:3600000}",
            initialDelayString = "${alinksec.signature.push-interval-ms:3600000}")
    public void scheduledPush() {
        Map<String, Object> latest = latestDb();
        if (latest != null) {
            pushToAllAgents();
        }
    }

    /**
     * 心跳版本比对触发更新（docs/05 §1.2）：Agent db_version 落后/未装时下发更新指令。
     * Agent 幂等（版本一致 ACK DONE），故重复下发无害。
     */
    public void pushIfOutdated(String agentId, String agentDbVersion) {
        Map<String, Object> latest = latestDb();
        if (latest == null) {
            return;
        }
        String latestVersion = (String) latest.get("db_version");
        if (!latestVersion.equals(agentDbVersion == null ? "" : agentDbVersion)) {
            log.info("特征库版本落后，下发更新: agent={} agent_db={} latest={}",
                    agentId, agentDbVersion, latestVersion);
            dispatchUpdate(agentId, latest);
        }
    }

    private void dispatchUpdate(String agentId, Map<String, Object> db) {
        commandService.dispatch(agentId, Command.newBuilder()
                .setSignatureUpdate(CmdSignatureUpdate.newBuilder()
                        .setDbVersion((String) db.get("db_version"))
                        .setDownloadUrl(downloadUrl(agentId, (String) db.get("package_key")))
                        .setSha256((String) db.get("sha256"))),
                null);
    }

    private Map<String, Object> latestDb() {
        List<Map<String, Object>> rows = jdbc.queryForList("""
                SELECT db_version, package_key, sha256 FROM t_virus_db ORDER BY id DESC LIMIT 1
                """);
        return rows.isEmpty() ? null : rows.get(0);
    }

    /* ==================== zip 解析 ==================== */

    private record Parsed(String version, int hashCount, int ruleCount, String manifestSha256) {}

    /**
     * 解析 zip：manifest.json（必需，校验版本/计数）+ hashes.txt（行数复核）。
     * 结构非法直接抛异常（导入失败不影响存量库）。
     */
    private Parsed parseZip(Path zip) throws IOException {
        String manifest = null;
        int hashLines = 0;
        try (ZipInputStream zis = new ZipInputStream(Files.newInputStream(zip))) {
            ZipEntry e;
            while ((e = zis.getNextEntry()) != null) {
                if (e.isDirectory()) {
                    continue;
                }
                String name = Path.of(e.getName()).getFileName().toString();
                if ("manifest.json".equals(name)) {
                    manifest = new String(zis.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
                } else if ("hashes.txt".equals(name)) {
                    hashLines = countLines(zis);
                }
            }
        }
        if (manifest == null) {
            throw new IllegalArgumentException("特征包缺少 manifest.json");
        }
        var m = JsonUtils.read(manifest);
        String version = m.path("db_version").asText("");
        if (version.isBlank() || !version.matches("[A-Za-z0-9._-]{1,32}")) {
            throw new IllegalArgumentException("manifest.db_version 非法（1-32 位字母数字._-）: " + version);
        }
        int hashCount = m.path("hash_count").asInt(0);
        int ruleCount = m.path("rule_count").asInt(0);
        if (hashCount > 0 && hashCount != hashLines) {
            throw new IllegalArgumentException(
                    "hash_count 声明 " + hashCount + " 与 hashes.txt 实际 " + hashLines + " 不一致");
        }
        return new Parsed(version, hashLines, ruleCount, m.path("sha256").asText(""));
    }

    private static int countLines(InputStream in) throws IOException {
        int lines = 0;
        byte[] buf = new byte[8192];
        int n;
        boolean lastWasNewline = true;
        while ((n = in.read(buf)) > 0) {
            for (int i = 0; i < n; i++) {
                if (buf[i] == '\n') {
                    lines++;
                    lastWasNewline = true;
                } else {
                    lastWasNewline = false;
                }
            }
        }
        if (!lastWasNewline) {
            lines++; // 末行无换行符
        }
        return lines;
    }

    private static String sha256(Path file) throws IOException {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            try (InputStream in = Files.newInputStream(file)) {
                byte[] buf = new byte[1 << 16];
                int n;
                while ((n = in.read(buf)) > 0) {
                    md.update(buf, 0, n);
                }
            }
            return HexFormat.of().formatHex(md.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
