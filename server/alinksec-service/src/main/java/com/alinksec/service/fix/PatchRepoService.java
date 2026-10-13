package com.alinksec.service.fix;

import com.alinksec.common.util.JsonUtils;
import com.alinksec.service.config.AlinkSecProperties;
import com.alinksec.service.library.LibraryFiles;
import com.alinksec.service.download.AgentDownloadTokenService;
import com.alinksec.service.scan.PackageVersions;
import com.alinksec.service.scan.VulnerabilityEvidence;
import com.alinksec.service.scan.VulnerabilityScope;
import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/** Immutable binary artifacts and explicit manual confirmation of distribution/CVE applicability. */
@Service
public class PatchRepoService {
    public static final long MAX_PACKAGE_BYTES = 128L * 1024 * 1024;
    private final JdbcTemplate jdbc;
    private final AlinkSecProperties props;
    private final AgentDownloadTokenService downloadTokens;
    private final LibraryFiles files;
    private final PackageMetadataReader reader;

    @Autowired
    public PatchRepoService(JdbcTemplate jdbc, AlinkSecProperties props, AgentDownloadTokenService downloadTokens,
                            LibraryFiles files, PackageMetadataReader reader) {
        this.jdbc = jdbc; this.props = props; this.downloadTokens = downloadTokens; this.files = files; this.reader = reader;
    }
    public PatchRepoService(JdbcTemplate jdbc, AlinkSecProperties props, AgentDownloadTokenService downloadTokens, LibraryFiles files) {
        this(jdbc, props, downloadTokens, files, new PackageMetadataReader());
    }

    /** Old callers cannot silently turn an OS display label into a native distribution declaration. */
    public Map<String, Object> importPackage(InputStream in, String originalName, int osType, String osVersion,
                                             String pkgName, String targetVersion, String repoType, Long importedBy) throws IOException {
        try (in) { throw new IllegalArgumentException("补丁导入必须声明明确的发行版、发行版版本及二进制包架构"); }
    }

    @Transactional
    public Map<String, Object> importPackage(InputStream in, String originalName, int osType, String osVersion,
                                             String pkgName, String targetVersion, String repoType,
                                             String distroId, String distroVersion, String architecture, Long importedBy) throws IOException {
        Path temp = null;
        String filename = null;
        boolean published = false;
        try (in) {
            if (osType != 1 || importedBy == null || importedBy <= 0) throw new IllegalArgumentException("仅支持已登录用户导入 Linux 二进制补丁，Windows 补丁请人工处理");
            repoType = normalizeRepoType(repoType, originalName);
            String source = "deb".equals(repoType) ? "dpkg" : "rpm";
            if (pkgName == null || !pkgName.matches("[A-Za-z0-9][A-Za-z0-9+_.-]{0,254}")
                    || distroId == null || !VulnerabilityScope.distributionId(distroId)
                    || distroVersion == null || !VulnerabilityScope.distributionVersion(distroVersion)
                    || architecture == null || !VulnerabilityScope.architecture(architecture) || List.of("src", "nosrc").contains(architecture))
                throw new IllegalArgumentException("补丁必须声明有效包名及精确发行版、版本和二进制包架构，不能使用通配范围");
            String version = PackageMetadataReader.versionIdentity(source, targetVersion);
            if (osVersion != null && osVersion.length() > 64) throw new IllegalArgumentException("系统显示版本过长");
            temp = files.temporary("." + repoType);
            long size = copyBounded(in, temp);
            if (size == 0) throw new IllegalArgumentException("补丁文件为空");
            PackageMetadataReader.Metadata metadata;
            try { metadata = reader.inspect(repoType, temp); }
            catch (IOException error) { throw new IllegalArgumentException("无法在权限、时间或资源限制内读取补丁包头，请检查原生工具或人工处理", error); }
            if (!pkgName.equals(metadata.name()) || !architecture.equals(metadata.architecture())
                    || !source.equals(metadata.source()) || !PackageMetadataReader.sameVersion(source, targetVersion, metadata.version()))
                throw new IllegalArgumentException("声明的包名、完整版本或包架构与实际二进制包头不一致");
            String sha256 = sha256(temp);
            String evidence = JsonUtils.write(Map.of("verification", "package_header", "name", metadata.name(), "version", metadata.version(),
                    "architecture", metadata.architecture(), "source", metadata.source(), "parser", "deb".equals(repoType) ? "dpkg-deb" : "rpm", "validated_at", Instant.now().toString()));
            filename = UUID.randomUUID().toString().replace("-", "") + "-" + sanitize(originalName);
            files.put("patch", filename, temp); published = true;
            if (org.springframework.transaction.support.TransactionSynchronizationManager.isSynchronizationActive()) {
                String object = filename;
                org.springframework.transaction.support.TransactionSynchronizationManager.registerSynchronization(
                        new org.springframework.transaction.support.TransactionSynchronization() {
                            @Override public void afterCompletion(int status) {
                                if (status == STATUS_COMMITTED) return;
                                try { files.delete("patch", object); }
                                catch (IOException error) { org.slf4j.LoggerFactory.getLogger(PatchRepoService.class).warn("Rolled-back patch cleanup failed: {}", object, error); }
                            }
                        });
            }
            long id = jdbc.queryForObject("""
                    INSERT INTO t_patch_package(os_type,os_version,pkg_name,target_version,repo_type,filename,sha256,size,imported_by,
                        source,distro_id,distro_version,architecture,version_identity,metadata_status,metadata)
                    VALUES (1,?,?,?,?,?,?,?,?,?,?,?,?,?,'validated',?) RETURNING id
                    """, Long.class, osVersion == null ? "" : osVersion, pkgName, targetVersion, repoType, filename, sha256, size, importedBy,
                    source, distroId, distroVersion, architecture, version, evidence);
            return packageRow(id);
        } catch (Exception error) {
            if (published) try { files.delete("patch", filename); } catch (IOException cleanup) { error.addSuppressed(cleanup); }
            throw error;
        } finally { if (temp != null) Files.deleteIfExists(temp); }
    }

    private static long copyBounded(InputStream input, Path target) throws IOException {
        long size = 0;
        try (var output = Files.newOutputStream(target)) {
            byte[] buffer = new byte[32 * 1024]; int count;
            while ((count = input.read(buffer)) != -1) {
                size += count;
                if (size > MAX_PACKAGE_BYTES) throw new IllegalArgumentException("补丁文件超过 128 MiB 限制，请人工处理");
                output.write(buffer, 0, count);
            }
        }
        return size;
    }

    public Map<String, Object> reviewContext(long patchId, String cveId) {
        var patch = packageRow(patchId);
        var rule = reviewRule(patch, cveId);
        return Map.of("patch", patch, "patchDigest", patchDigest(patch), "cve", rule,
                "reviewBasis", "manual_confirmation", "vendorVerification", "not_verified");
    }

    @Transactional
    public Map<String, Object> review(long patchId, String cveId, String ruleDigest, String expectedPatchDigest,
                                       String notes, boolean acknowledged, Long reviewer) throws IOException {
        if (reviewer == null || reviewer <= 0 || !acknowledged || notes == null || notes.trim().length() < 10 || notes.length() > 2048)
            throw new IllegalArgumentException("请明确确认发行版适用性及 CVE 修复目标，并填写 10–2048 字的复核依据");
        var patch = packageRow(patchId);
        var rule = reviewRule(patch, cveId);
        String binding = patchDigest(patch);
        if (!binding.equals(expectedPatchDigest) || !rule.get("rule_digest").equals(ruleDigest))
            throw new IllegalArgumentException("补丁范围、二进制元数据或漏洞规则已变化，请重新查看并复核");
        verifyBytes(patch);
        String id = UUID.randomUUID().toString();
        String when = Instant.now().toString();
        jdbc.update("""
                INSERT INTO t_patch_review(id,patch_id,patch_sha256,patch_digest,cve_id,rule_source_id,rule_digest,reviewed_by,reviewed_at,notes)
                VALUES (?,?,?,?,?,?,?,?,?,?)
                """, id, patchId, patch.get("sha256"), binding, cveId, rule.get("rule_source_id"), ruleDigest, reviewer, when, notes.trim());
        return Map.of("id", id, "reviewed_by", reviewer, "reviewed_at", when, "basis", "manual_confirmation", "vendor_verification", "not_verified");
    }

    @Transactional
    public void revoke(long patchId, String reviewId, Long reviewer, String note) {
        if (reviewer == null || reviewer <= 0 || note == null || note.trim().isEmpty() || note.length() > 2048)
            throw new IllegalArgumentException("撤销复核需已登录用户及原因");
        int count = jdbc.update("""
                UPDATE t_patch_review SET revoked_by=?,revoked_at=?,revocation_note=?
                WHERE id=? AND patch_id=? AND revoked_at IS NULL
                """, reviewer, Instant.now().toString(), note.trim(), reviewId, patchId);
        if (count != 1) throw new IllegalArgumentException("复核不存在或已撤销");
    }

    private Map<String, Object> reviewRule(Map<String, Object> patch, String cveId) {
        if (cveId == null || !cveId.matches("CVE-[0-9]{4}-[0-9]{4,}")) throw new IllegalArgumentException("CVE 编号非法");
        patchDigest(patch); // Rejects historical/unparsed objects.
        var rows = jdbc.queryForList("SELECT cve_id,rule_source_id,rule_digest,CAST(affected AS TEXT) AS affected,provenance FROM t_cve_db WHERE cve_id=?", cveId);
        if (rows.size() != 1) throw new IllegalArgumentException("当前有效漏洞规则不存在");
        var current = rows.get(0); JsonNode rules = JsonUtils.read(String.valueOf(current.get("affected")));
        String origin = String.valueOf(current.get("rule_source_id")), digest = String.valueOf(current.get("rule_digest"));
        if (origin.isBlank() || !digest.equals(VulnerabilityEvidence.ruleDigest(origin, cveId, rules)))
            throw new IllegalArgumentException("漏洞规则来源或指纹不完整，请重新导入核对");
        boolean targetDeclared = false;
        for (JsonNode rule : rules) {
            if (!scopeMatches(rule, patch)) continue;
            if (!VulnerabilityEvidence.comparable(rule)) throw new IllegalArgumentException("该包范围存在未知或不可评估声明，请人工处理");
            String assessment = rule.path("evidence").path("assessment").asText();
            if ("affected".equals(assessment)) {
                if (targetInRange(rule, String.valueOf(patch.get("source")), String.valueOf(patch.get("target_version"))))
                    throw new IllegalArgumentException("目标完整版本仍命中受影响声明，不能确认自动修复");
                targetDeclared |= PackageMetadataReader.sameVersion(String.valueOf(patch.get("source")), rule.path("fixed_version").asText(), String.valueOf(patch.get("target_version")));
            }
        }
        if (!targetDeclared) throw new IllegalArgumentException("补丁包范围或完整目标版本不对应当前二进制修复声明");
        return current;
    }

    private static boolean scopeMatches(JsonNode rule, Map<String, Object> patch) {
        return VulnerabilityScope.nativeRule(rule) && rule.path("name").asText().equals(patch.get("pkg_name"))
                && rule.path("source").asText().equals(patch.get("source")) && rule.path("distro_id").asText().equals(patch.get("distro_id"))
                && rule.path("distro_version").asText().equals(patch.get("distro_version"))
                && ("*".equals(rule.path("architecture").asText()) || rule.path("architecture").asText().equals(patch.get("architecture")));
    }
    private static boolean targetInRange(JsonNode rule, String source, String version) {
        if (rule.has("ranges")) {
            if (rule.path("ranges").isEmpty()) throw new IllegalArgumentException("目标范围缺失");
            for (JsonNode range : rule.path("ranges")) if (!PackageVersions.inRange(source, version, range.asText())) return false;
            return true;
        }
        return PackageVersions.inRange(source, version, rule.path("vrange").asText("*"));
    }

    public record Resolved(Map<String, Map<String, Object>> hits, List<String> missing) {}
    public Resolved resolveForAgents(List<Map<String, Object>> targets) {
        Map<String, Map<String, Object>> hits = new LinkedHashMap<>(); var missing = new ArrayList<String>();
        for (var target : targets) {
            var patch = reviewedPatch(jdbc, target);
            if (patch == null) missing.add("[" + target.get("agent_id") + "] " + target.get("pkg_name") + " → " + target.get("target_version") + "：缺少同一发行版、包架构、来源及当前规则下的补丁人工复核");
            else hits.put(target.get("agent_id") + ":" + target.get("finding_id"), patch);
        }
        return new Resolved(hits, missing);
    }

    /** Pure lookup for finding display and task creation; content is checked again before use. */
    public static Map<String, Object> reviewedPatch(JdbcTemplate jdbc, Map<String, Object> target) {
        Map<?, ?> identity = target.get("inventory") instanceof Map<?, ?> map ? map : target;
        String source = String.valueOf(identity.get("source")); String version;
        try { version = PackageMetadataReader.versionIdentity(source, String.valueOf(target.get("target_version"))); }
        catch (IllegalArgumentException error) { return null; }
        var candidates = jdbc.queryForList("""
                SELECT p.*,r.id AS review_id,r.patch_digest AS review_patch_digest,r.patch_sha256 AS review_patch_sha256,
                    r.reviewed_by,r.reviewed_at,r.notes AS review_notes
                FROM t_patch_package p JOIN t_patch_review r ON r.patch_id=p.id
                WHERE p.os_type=1 AND p.metadata_status='validated' AND p.pkg_name=? AND p.version_identity=?
                  AND p.source=? AND p.distro_id=? AND p.distro_version=? AND p.architecture=?
                  AND r.cve_id=? AND r.rule_source_id=? AND r.rule_digest=? AND r.revoked_at IS NULL
                ORDER BY p.id DESC,r.reviewed_at DESC,r.id DESC LIMIT 20
                """, target.get("pkg_name"), version, source, identity.get("distro_id"), identity.get("distro_version"), identity.get("architecture"),
                target.get("cve_id"), target.get("rule_source_id"), target.get("rule_digest"));
        for (var patch : candidates) {
            try {
                if (patch.get("sha256").equals(patch.get("review_patch_sha256")) && patchDigest(patch).equals(patch.get("review_patch_digest"))) return patch;
            } catch (IllegalArgumentException ignored) { /* A changed object cannot reuse a historical review. */ }
        }
        return null;
    }

    public Map<String, Object> pin(Map<String, Object> patch, Map<String, Object> target) {
        var pin = Map.<String, Object>of("patch_id", String.valueOf(patch.get("id")), "review_id", patch.get("review_id"), "patch_digest", patchDigest(patch), "sha256", patch.get("sha256"),
                "reviewed_by", patch.get("reviewed_by"), "reviewed_at", patch.get("reviewed_at"), "basis", "manual_confirmation");
        verifyPin(pin, target);
        return pin;
    }

    public Map<String, Object> verifyPin(Map<?, ?> pin, Map<String, Object> target) {
        if (pin == null || !String.valueOf(pin.get("patch_id")).matches("[1-9][0-9]*")) throw new IllegalArgumentException("旧修复任务缺少固定补丁与人工复核，请重新创建");
        var patch = packageRow(Long.parseLong(String.valueOf(pin.get("patch_id"))));
        String binding = patchDigest(patch);
        var reviews = jdbc.queryForList("""
                SELECT id,patch_sha256,patch_digest,reviewed_by,reviewed_at FROM t_patch_review
                WHERE id=? AND patch_id=? AND cve_id=? AND rule_source_id=? AND rule_digest=? AND revoked_at IS NULL
                """, pin.get("review_id"), patch.get("id"), target.get("cve_id"), target.get("rule_source_id"), target.get("rule_digest"));
        if (reviews.size() != 1 || !binding.equals(pin.get("patch_digest")) || !binding.equals(reviews.get(0).get("patch_digest"))
                || !patch.get("sha256").equals(pin.get("sha256")) || !patch.get("sha256").equals(reviews.get(0).get("patch_sha256"))
                || !String.valueOf(pin.get("reviewed_by")).equals(String.valueOf(reviews.get(0).get("reviewed_by")))
                || !java.util.Objects.equals(pin.get("reviewed_at"), reviews.get(0).get("reviewed_at")))
            throw new IllegalArgumentException("审批所依据的补丁或人工复核已变化或被撤销，请重新创建");
        Map<?, ?> identity = target.get("inventory") instanceof Map<?, ?> map ? map : target;
        for (String field : List.of("source", "distro_id", "distro_version", "architecture"))
            if (!patch.get(field).equals(identity.get(field))) throw new IllegalArgumentException("固定补丁范围与当前安装不对应");
        if (!patch.get("pkg_name").equals(target.get("pkg_name")) || !PackageMetadataReader.sameVersion(String.valueOf(patch.get("source")), String.valueOf(patch.get("target_version")), String.valueOf(target.get("target_version"))))
            throw new IllegalArgumentException("固定补丁与修复目标不对应");
        var current = reviewRule(patch, String.valueOf(target.get("cve_id")));
        if (!java.util.Objects.equals(current.get("rule_source_id"), target.get("rule_source_id"))
                || !java.util.Objects.equals(current.get("rule_digest"), target.get("rule_digest")))
            throw new IllegalArgumentException("固定补丁人工复核引用的漏洞规则已变化，请重新扫描复核");
        try { verifyBytes(patch); }
        catch (IOException error) { throw new IllegalArgumentException("固定补丁无法读取，请重新导入复核", error); }
        return patch;
    }

    private void verifyBytes(Map<String, Object> patch) throws IOException {
        var artifact = files.download("patch", String.valueOf(patch.get("filename")));
        if (artifact == null || artifact.size() <= 0 || artifact.size() > MAX_PACKAGE_BYTES || artifact.size() != ((Number) patch.get("size")).longValue())
            throw new IllegalArgumentException("固定补丁文件缺失或大小已变化，请重新导入复核");
        try (InputStream in = artifact.resource().getInputStream()) {
            var digest = newDigest(); byte[] buffer = new byte[32 * 1024]; long total = 0; int count;
            while ((count = in.read(buffer)) != -1) {
                total += count;
                if (total > artifact.size()) throw new IllegalArgumentException("固定补丁文件大小已变化");
                digest.update(buffer, 0, count);
            }
            if (total != artifact.size() || !HexFormat.of().formatHex(digest.digest()).equals(patch.get("sha256")))
                throw new IllegalArgumentException("固定补丁字节摘要已变化，旧人工复核不能继续使用");
        }
    }

    public static String patchDigest(Map<String, Object> patch) {
        if (!"validated".equals(patch.get("metadata_status")) || !String.valueOf(patch.get("sha256")).matches("[a-f0-9]{64}"))
            throw new IllegalArgumentException("历史补丁包没有实际包头验证及发行版适用性复核，请重新导入");
        var values = new LinkedHashMap<String, Object>();
        for (String field : List.of("id", "pkg_name", "target_version", "repo_type", "filename", "sha256", "size", "source", "distro_id", "distro_version", "architecture", "version_identity", "metadata_status")) values.put(field, String.valueOf(patch.get(field)));
        values.put("metadata", JsonUtils.read(String.valueOf(patch.get("metadata"))));
        return VulnerabilityEvidence.sha256(VulnerabilityEvidence.canonicalJson(JsonUtils.read(JsonUtils.write(values))));
    }

    private Map<String, Object> packageRow(long id) {
        var rows = jdbc.queryForList("SELECT * FROM t_patch_package WHERE id=?", id);
        if (rows.size() != 1) throw new IllegalArgumentException("补丁包不存在");
        return rows.get(0);
    }
    public Map<String, Object> list(int page, int size, Integer osType, String keyword) {
        StringBuilder where = new StringBuilder(" WHERE 1=1"); var args = new ArrayList<Object>();
        if (osType != null && osType > 0) { where.append(" AND os_type=?"); args.add(osType); }
        if (keyword != null && !keyword.isBlank()) { where.append(" AND (LOWER(pkg_name) LIKE LOWER(?) OR LOWER(target_version) LIKE LOWER(?))"); args.add("%" + keyword.trim() + "%"); args.add("%" + keyword.trim() + "%"); }
        Long total = jdbc.queryForObject("SELECT count(*) FROM t_patch_package" + where, Long.class, args.toArray());
        var rows = jdbc.queryForList("SELECT * FROM t_patch_package" + where + " ORDER BY id DESC LIMIT " + Math.min(size, 100) + " OFFSET " + (long) Math.max(page - 1, 0) * Math.min(size, 100), args.toArray());
        for (var row : rows) row.put("reviews", jdbc.queryForList("SELECT id,cve_id,rule_source_id,rule_digest,patch_digest,reviewed_by,reviewed_at,notes,revoked_by,revoked_at,revocation_note FROM t_patch_review WHERE patch_id=? ORDER BY reviewed_at DESC,id DESC", row.get("id")));
        return Map.of("total", total == null ? 0 : total, "list", rows);
    }
    public LibraryFiles.Download downloadPackage(String filename) throws IOException { resolveFile(filename); return files.download("patch", filename); }
    public Path resolveFile(String filename) {
        LibraryFiles.validateKey(filename);
        if (jdbc.queryForObject("SELECT count(*) FROM t_patch_package WHERE filename=?", Integer.class, filename) != 1) throw new IllegalArgumentException("补丁不存在");
        return Path.of(props.getPatch().getStorageDir()).resolve(filename);
    }
    public String downloadUrl(String agentId, Map<String, Object> patchRow) {
        return props.getPatch().getDownloadBaseUrl() + "/api/fix/patches/download?filename=" + java.net.URLEncoder.encode(String.valueOf(patchRow.get("filename")), StandardCharsets.UTF_8)
                + "&token=" + downloadTokens.issue(agentId, "patch", String.valueOf(patchRow.get("filename")));
    }
    private static String normalizeRepoType(String type, String original) {
        String actual = type == null || type.isBlank() ? (original != null && original.toLowerCase().endsWith(".deb") ? "deb" : original != null && original.toLowerCase().endsWith(".rpm") ? "rpm" : "") : type.trim().toLowerCase();
        if (!List.of("deb", "rpm").contains(actual)) throw new IllegalArgumentException("仅支持 Linux 二进制 DEB/RPM，其他补丁请人工处理");
        return actual;
    }
    private static String sanitize(String name) {
        String value = name == null ? "patch.bin" : name.replaceAll("[^\\p{L}\\p{N}._~+()@\\[\\]%-]", "_").replace("..", "__");
        return value.substring(0, Math.min(value.length(), 200));
    }
    static String sha256(Path file) throws IOException {
        try (InputStream in = Files.newInputStream(file)) { var digest = newDigest(); byte[] buffer = new byte[32 * 1024]; int count; while ((count = in.read(buffer)) != -1) digest.update(buffer, 0, count); return HexFormat.of().formatHex(digest.digest()); }
    }
    private static MessageDigest newDigest() { try { return MessageDigest.getInstance("SHA-256"); } catch (NoSuchAlgorithmException error) { throw new IllegalStateException(error); } }
}
