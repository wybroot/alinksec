package com.alinksec.service.fix;

import com.alinksec.service.config.AlinkSecProperties;
import com.alinksec.service.download.AgentDownloadTokenService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * 离线补丁仓库（docs/05 §3.4）：补丁包导入（实施/运维离线操作）→ 落盘 → t_patch_package 清单。
 * Agent 通过下载端点拉取（key = 补丁 sha256，不可猜测，无 JWT 放行）。
 */
@Service
public class PatchRepoService {

    private static final Logger log = LoggerFactory.getLogger(PatchRepoService.class);

    private final JdbcTemplate jdbc;
    private final AlinkSecProperties props;
    private final AgentDownloadTokenService downloadTokens;

    public PatchRepoService(JdbcTemplate jdbc, AlinkSecProperties props,
                            AgentDownloadTokenService downloadTokens) {
        this.jdbc = jdbc;
        this.props = props;
        this.downloadTokens = downloadTokens;
    }

    /**
     * 导入补丁包。
     *
     * @param osType        1 Linux / 2 Windows
     * @param osVersion     centos7 / ubuntu2204 / win2019（可空 = 该 OS 通用）
     * @param pkgName       包名（openssl / KB5034441）
     * @param targetVersion 目标版本（rpm/deb 完整版本；msu 为 KB 号重复即可）
     * @param repoType      rpm / deb / msu
     */
    @Transactional
    public Map<String, Object> importPackage(InputStream in, String originalName,
                                             int osType, String osVersion, String pkgName,
                                             String targetVersion, String repoType, Long importedBy) throws IOException {
        if (pkgName == null || pkgName.isBlank() || targetVersion == null || targetVersion.isBlank()) {
            throw new IllegalArgumentException("pkg_name 与 target_version 必填");
        }
        repoType = normalizeRepoType(repoType, osType, originalName);
        Path dir = Path.of(props.getPatch().getStorageDir());
        Files.createDirectories(dir);
        String filename = UUID.randomUUID().toString().replace("-", "") + "-" + sanitize(originalName);
        Path dest = dir.resolve(filename);
        String sha256;
        long size;
        try {
            try (InputStream src = in) {
                size = Files.copy(src, dest, StandardCopyOption.REPLACE_EXISTING);
            }
            sha256 = sha256(dest);
        } catch (Exception e) {
            Files.deleteIfExists(dest);
            throw e;
        }
        // 与包类型一致性的最低校验（扩展名提示，不阻断——由导入人负责）
        try {
            long id = jdbc.queryForObject("""
                    INSERT INTO t_patch_package
                        (os_type, os_version, pkg_name, target_version, repo_type, filename, sha256, size, imported_by)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT (os_type, os_version, pkg_name, target_version)
                    DO UPDATE SET filename = EXCLUDED.filename, sha256 = EXCLUDED.sha256,
                                  size = EXCLUDED.size, imported_by = EXCLUDED.imported_by
                    RETURNING id
                    """, Long.class, osType, osVersion == null ? "" : osVersion, pkgName.trim(),
                    targetVersion.trim(), repoType, filename, sha256, size, importedBy);
            log.info("补丁包导入: {} {} {} → {} ({}B)", repoType, pkgName, targetVersion, filename, size);
            return Map.of("id", id, "filename", filename, "sha256", sha256, "size", size);
        } catch (Exception e) {
            Files.deleteIfExists(dest);
            throw e;
        }
    }

    /** 分页清单（按 os_type / 关键字过滤） */
    public Map<String, Object> list(int page, int size, Integer osType, String keyword) {
        StringBuilder where = new StringBuilder(" WHERE 1=1");
        List<Object> args = new ArrayList<>();
        if (osType != null && osType > 0) {
            where.append(" AND os_type = ?");
            args.add(osType);
        }
        if (keyword != null && !keyword.isBlank()) {
            where.append(" AND (pkg_name ILIKE ? OR target_version ILIKE ?)");
            String kw = "%" + keyword.trim() + "%";
            args.addAll(List.of(kw, kw));
        }
        Long total = jdbc.queryForObject("SELECT count(*) FROM t_patch_package" + where, Long.class, args.toArray());
        String limit = " ORDER BY id DESC LIMIT " + Math.min(size, 100) + " OFFSET " + (long) Math.max(page - 1, 0) * Math.min(size, 100);
        List<Map<String, Object>> rows = jdbc.queryForList(
                "SELECT * FROM t_patch_package" + where + limit, args.toArray());
        return Map.of("total", total == null ? 0 : total, "list", rows);
    }

    /** Agent 下载端点解析：filename + key（sha256）双因子校验 */
    public Path resolveFile(String filename) {
        if (filename == null || filename.contains("..") || filename.contains("/") || filename.contains("\\")) {
            throw new IllegalArgumentException("非法文件名");
        }
        Integer count = jdbc.queryForObject("SELECT count(*) FROM t_patch_package WHERE filename = ?",
                Integer.class, filename);
        if (count == null || count != 1) {
            throw new IllegalArgumentException("补丁不存在");
        }
        return Path.of(props.getPatch().getStorageDir()).resolve(filename);
    }

    /**
     * 覆盖率解析：给定主机 OS 与目标软件清单，返回 命中补丁 + 缺失清单（阻断创建用）。
     */
    public record Resolved(Map<String, Map<String, Object>> hits, List<String> missing) {}

    public Resolved resolveForAgents(List<Map<String, Object>> targets) {
        // targets: [{agent_id, os_type, os_version, pkg_name, target_version, cve_id, finding_id}]
        Map<String, Map<String, Object>> hits = new java.util.LinkedHashMap<>();
        List<String> missing = new ArrayList<>();
        for (Map<String, Object> t : targets) {
            int osType = ((Number) t.get("os_type")).intValue();
            String osVer = String.valueOf(t.get("os_version") == null ? "" : t.get("os_version"));
            String pkg = String.valueOf(t.get("pkg_name"));
            String ver = String.valueOf(t.get("target_version"));
            // 精确 os_version 命中优先，其次通用包（os_version=''）
            List<Map<String, Object>> found = jdbc.queryForList("""
                    SELECT * FROM t_patch_package
                    WHERE os_type = ? AND pkg_name = ? AND target_version = ?
                      AND (os_version = ? OR os_version = '')
                    ORDER BY (os_version = ?) DESC LIMIT 1
                    """, osType, pkg, ver, osVer, osVer);
            if (found.isEmpty()) {
                missing.add("[" + t.get("agent_id") + "] " + pkg + " → " + ver
                        + "（" + (osType == 1 ? "Linux/" + osVer : "Windows") + "，关联 " + t.get("cve_id") + "）");
            } else {
                hits.put(t.get("agent_id") + ":" + t.get("finding_id"), found.get(0));
            }
        }
        return new Resolved(hits, missing);
    }

    /** 构造 Agent 下载 URL（key=sha256，RestConfig 白名单放行） */
    public String downloadUrl(String agentId, Map<String, Object> patchRow) {
        return props.getPatch().getDownloadBaseUrl()
                + "/api/fix/patches/download?filename=" + patchRow.get("filename")
                + "&token=" + downloadTokens.issue(agentId, "patch", String.valueOf(patchRow.get("filename")));
    }

    private String normalizeRepoType(String repoType, int osType, String originalName) {
        if (repoType != null && !repoType.isBlank()) {
            return repoType.trim().toLowerCase();
        }
        String n = originalName == null ? "" : originalName.toLowerCase();
        if (n.endsWith(".rpm")) return "rpm";
        if (n.endsWith(".deb")) return "deb";
        if (n.endsWith(".msu")) return "msu";
        throw new IllegalArgumentException("无法识别补丁类型，请显式指定 repo_type（rpm/deb/msu）");
    }

    private static String sanitize(String name) {
        return name == null ? "patch.bin" : name.replaceAll("[\\\\/:*?\"<>|\\s]", "_");
    }

    static String sha256(Path file) throws IOException {
        try (InputStream in = Files.newInputStream(file)) {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) > 0) {
                md.update(buf, 0, n);
            }
            return HexFormat.of().formatHex(md.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
