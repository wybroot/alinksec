package com.alinksec.service.library;

import com.alinksec.common.util.JsonUtils;
import com.alinksec.service.config.DatabaseDialect;
import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.Instant;
import java.util.*;
import java.util.zip.*;

/** Source rows and the published version commit together; failed candidates keep the last good release. */
@Service
public class LibraryCatalog {
    private final JdbcTemplate jdbc;
    private final LibraryProperties props;
    private final LibraryFiles files;
    private final DatabaseDialect database;
    private final TransactionTemplate transaction;
    public LibraryCatalog(JdbcTemplate jdbc, LibraryProperties props, LibraryFiles files,
                          DatabaseDialect database, PlatformTransactionManager manager) {
        this.jdbc = jdbc; this.props = props; this.files = files; this.database = database;
        transaction = new TransactionTemplate(manager);
    }
    public synchronized Map<String, Object> signatures(String source, SignaturePackage pkg, boolean replace, Long actor) throws IOException {
        try {
            return transaction.execute(status -> {
                try {
                    adoptLegacySignature("manual".equals(source) && replace);
                    if (replace) {
                        jdbc.update("DELETE FROM t_security_hash WHERE source_id = ?", source);
                        jdbc.update("DELETE FROM t_security_rule WHERE source_id = ?", source);
                    }
                    jdbc.batchUpdate("""
                            INSERT INTO t_security_hash(source_id,sha256,name,severity) VALUES (?,?,?,?)
                            ON CONFLICT(source_id,sha256) DO UPDATE SET name=EXCLUDED.name,severity=EXCLUDED.severity
                            """, pkg.hashes().values(), 500, (stmt, hash) -> {
                        stmt.setString(1, source); stmt.setString(2, hash.sha256()); stmt.setString(3, hash.name()); stmt.setInt(4, hash.severity());
                    });
                    for (JsonNode rule : pkg.rules()) jdbc.update("""
                            INSERT INTO t_security_rule(source_id,name,document) VALUES (?,?,?)
                            ON CONFLICT(source_id,name) DO UPDATE SET document=EXCLUDED.document
                            """, source, rule.path("name").asText(), JsonUtils.write(rule));
                    int count = jdbc.queryForObject("SELECT count(DISTINCT sha256) FROM t_security_hash", Integer.class);
                    if (count > props.getMaxHashes()) throw new IllegalArgumentException("合并哈希库超过容量上限，已有库保留");
                    return publishSignatures(actor, "manual".equals(source) ? pkg.version() : "");
                } catch (IOException e) { throw new UncheckedIOException(e); }
            });
        } catch (UncheckedIOException e) { throw e.getCause(); }
    }
    private void adoptLegacySignature(boolean replacingManual) throws IOException {
        if (jdbc.queryForObject("SELECT count(*) FROM t_security_feed_state WHERE source_id = '_legacy-signature'", Integer.class) > 0) return;
        var latest = jdbc.queryForList("SELECT package_key FROM t_virus_db ORDER BY id DESC LIMIT 1");
        if (!replacingManual && !latest.isEmpty()) {
            Path tmp = files.temporary(".zip");
            try {
                files.copyTo("signature", (String) latest.get(0).get("package_key"), tmp);
                SignaturePackage old = SignaturePackage.read(tmp, props);
                // Existing imported data becomes the manual source, so remote updates cannot erase it.
                jdbc.batchUpdate("INSERT INTO t_security_hash(source_id,sha256,name,severity) VALUES ('manual',?,?,?) ON CONFLICT DO NOTHING",
                        old.hashes().values(), 500, (stmt, hash) -> { stmt.setString(1, hash.sha256()); stmt.setString(2, hash.name()); stmt.setInt(3, hash.severity()); });
                for (JsonNode rule : old.rules()) jdbc.update("INSERT INTO t_security_rule(source_id,name,document) VALUES ('manual',?,?) ON CONFLICT DO NOTHING", rule.path("name").asText(), JsonUtils.write(rule));
            } finally { Files.deleteIfExists(tmp); }
        }
        jdbc.update("INSERT INTO t_security_feed_state(source_id,kind,status) VALUES ('_legacy-signature','internal','success')");
    }
    private Map<String, Object> publishSignatures(Long actor, String proposedVersion) throws IOException {
        Path hashes = files.temporary(".txt"), rules = files.temporary(".json"), zip = files.temporary(".zip");
        try {
            int hashCount = jdbc.queryForObject("SELECT count(DISTINCT sha256) FROM t_security_hash", Integer.class);
            try (BufferedWriter writer = Files.newBufferedWriter(hashes, StandardCharsets.UTF_8)) {
                jdbc.query("""
                        SELECT sha256,name,severity FROM (
                          SELECT sha256,name,severity,ROW_NUMBER() OVER(PARTITION BY sha256
                          ORDER BY CASE WHEN source_id='manual' THEN 0 ELSE 1 END,source_id) AS priority
                          FROM t_security_hash
                        ) h WHERE priority=1 ORDER BY sha256
                        """, (org.springframework.jdbc.core.RowCallbackHandler) rs -> {
                    try { writer.write(rs.getString(1) + " " + rs.getString(2) + " " + rs.getInt(3) + "\n"); }
                    catch (IOException e) { throw new UncheckedIOException(e); }
                });
            }
            var ruleRows = jdbc.queryForList("""
                    SELECT document FROM (
                      SELECT document,name,ROW_NUMBER() OVER(PARTITION BY name
                      ORDER BY CASE WHEN source_id='manual' THEN 0 ELSE 1 END,source_id) AS priority
                      FROM t_security_rule
                    ) r WHERE priority=1 ORDER BY name
                    """);
            if (ruleRows.size() > 2000) throw new IllegalArgumentException("合并规则数量超过上限");
            Files.writeString(rules, JsonUtils.write(Map.of("rules", ruleRows.stream().map(r -> JsonUtils.read((String) r.get("document"))).toList())));
            if (hashCount == 0 && ruleRows.isEmpty()) throw new IllegalArgumentException("拒绝发布空特征库");
            String fingerprint = SignaturePackage.sha256(hashes) + SignaturePackage.sha256(rules);
            var state = jdbc.queryForList("SELECT cursor,version FROM t_security_feed_state WHERE source_id = '_signature-release'");
            if (!state.isEmpty() && fingerprint.equals(state.get(0).get("cursor"))) {
                return Map.of("dbVersion", state.get(0).get("version"), "hashCount", hashCount, "ruleCount", ruleRows.size(), "changed", false);
            }
            String version = proposedVersion;
            if (version.isBlank() || jdbc.queryForObject("SELECT count(*) FROM t_virus_db WHERE db_version=?", Integer.class, version) > 0) {
                version = "lib-" + Long.toString(System.currentTimeMillis(), 36) + "-" + UUID.randomUUID().toString().substring(0, 8);
            }
            try (ZipOutputStream out = new ZipOutputStream(Files.newOutputStream(zip))) {
                out.putNextEntry(new ZipEntry("manifest.json"));
                out.write(JsonUtils.write(Map.of("db_version", version, "hash_count", hashCount, "rule_count", ruleRows.size())).getBytes(StandardCharsets.UTF_8));
                out.closeEntry();
                for (var entry : Map.of("hashes.txt", hashes, "rules.json", rules).entrySet()) {
                    out.putNextEntry(new ZipEntry(entry.getKey())); Files.copy(entry.getValue(), out); out.closeEntry();
                }
            }
            String key = version + ".zip";
            files.put("signature", key, zip);
            jdbc.update("""
                    INSERT INTO t_virus_db(db_version,package_key,sha256,size,hash_count,rule_count,imported_by)
                    VALUES (?,?,?,?,?,?,?)
                    """, version, key, SignaturePackage.sha256(zip), Files.size(zip), hashCount, ruleRows.size(), actor);
            jdbc.update("""
                    INSERT INTO t_security_feed_state(source_id,kind,status,cursor,version,entry_count,success_at)
                    VALUES ('_signature-release','internal','success',?,?,?,?)
                    ON CONFLICT(source_id) DO UPDATE SET cursor=EXCLUDED.cursor,version=EXCLUDED.version,
                    entry_count=EXCLUDED.entry_count,success_at=EXCLUDED.success_at
                    """, fingerprint, version, hashCount, Instant.now().toString());
            return Map.of("dbVersion", version, "hashCount", hashCount, "ruleCount", ruleRows.size(), "changed", true);
        } finally { Files.deleteIfExists(hashes); Files.deleteIfExists(rules); Files.deleteIfExists(zip); }
    }
    public synchronized int cves(String source, List<JsonNode> documents) {
        if (documents.size() > props.getMaxCvesPerImport()) throw new IllegalArgumentException("漏洞数据超过单次导入上限");
        for (JsonNode document : documents) validateCve(document);
        return transaction.execute(status -> {
            for (JsonNode document : documents) {
                String id = document.path("cve_id").asText();
                for (JsonNode rule : document.path("affected")) {
                    if (!rule.has("match")) ((com.fasterxml.jackson.databind.node.ObjectNode) rule).put("match", "exact");
                }
                jdbc.update("""
                        INSERT INTO t_security_cve(source_id,cve_id,document,matchable) VALUES (?,?,?,?)
                        ON CONFLICT(source_id,cve_id) DO UPDATE SET document=EXCLUDED.document,matchable=EXCLUDED.matchable
                        """, source, id, JsonUtils.write(document), document.path("affected").isEmpty() ? 0 : 1);
                // Manual corrections win over remotely supplied rules/metadata.
                String effective = jdbc.queryForObject("""
                        SELECT document FROM t_security_cve WHERE cve_id=?
                        ORDER BY CASE WHEN source_id='manual' THEN 0 ELSE 1 END,source_id LIMIT 1
                        """, String.class, id);
                JsonNode cve = JsonUtils.read(effective);
                jdbc.update("""
                        INSERT INTO t_cve_db(cve_id,title,severity,cvss,affected,description,published_at)
                        VALUES (?,?,?,?,?,?,?) ON CONFLICT(cve_id) DO UPDATE SET title=EXCLUDED.title,
                        severity=EXCLUDED.severity,cvss=EXCLUDED.cvss,affected=EXCLUDED.affected,
                        description=EXCLUDED.description,published_at=EXCLUDED.published_at,imported_at=CURRENT_TIMESTAMP
                        """, id, cve.path("title").asText(id), cve.path("severity").asInt(),
                        cve.hasNonNull("cvss") ? cve.path("cvss").asDouble() : null,
                        JsonUtils.write(cve.path("affected")), cve.path("description").asText(""),
                        cve.hasNonNull("published_at") ? database.timestamp(Instant.parse(cve.path("published_at").asText())) : null);
            }
            return documents.size();
        });
    }
    /** Retain current/recent releases and every artifact referenced by pending delivery or valid tokens. */
    public synchronized int pruneSignatures() throws IOException {
        if (props.getRetainVersions() < 2 || props.getRetainDays() < 1) throw new IllegalArgumentException("至少保留两个版本和一天历史");
        // A queued command can still contain an old package URL. Conservatively defer cleanup.
        if (jdbc.queryForObject("SELECT count(*) FROM t_command WHERE type='signature_update' AND status IN (0,1,2,3)", Integer.class) > 0) return 0;
        var protectedIds = jdbc.queryForList("SELECT id FROM t_virus_db ORDER BY id DESC LIMIT ?", Long.class, props.getRetainVersions());
        if (protectedIds.isEmpty()) return 0;
        var candidates = jdbc.queryForList("""
                SELECT id,package_key FROM t_virus_db WHERE id < ? AND imported_at < ?
                  AND NOT EXISTS (SELECT 1 FROM t_agent_download_token t
                    WHERE t.resource_type='virus-db' AND t.resource_key=t_virus_db.package_key AND t.expire_at > ?)
                ORDER BY id LIMIT 100
                """, protectedIds.get(protectedIds.size() - 1), database.timestampBefore(java.time.Duration.ofDays(props.getRetainDays())), database.timestamp(Instant.now()));
        int removed = 0;
        for (var row : candidates) {
            files.delete("signature", (String) row.get("package_key"));
            removed += jdbc.update("DELETE FROM t_virus_db WHERE id=?", row.get("id"));
        }
        return removed;
    }
    public static void validateCve(JsonNode document) {
        String id = document.path("cve_id").asText("");
        int severity = document.path("severity").asInt(0);
        if (!document.isObject() || !document.path("cve_id").isTextual() || !document.path("severity").isIntegralNumber()
                || !id.matches("CVE-[0-9]{4}-[0-9]{4,19}") || severity < 1 || severity > 4 || !document.path("affected").isArray()
                || document.path("affected").size() > 200 || document.path("title").asText("").length() > 512
                || (document.has("title") && !document.path("title").isTextual())
                || (document.has("description") && !document.path("description").isTextual())
                || (document.hasNonNull("cvss") && (!document.path("cvss").isNumber() || document.path("cvss").asDouble(-1) < 0 || document.path("cvss").asDouble() > 10))) throw new IllegalArgumentException("漏洞数据格式非法");
        if (document.hasNonNull("published_at")) {
            if (!document.path("published_at").isTextual()) throw new IllegalArgumentException("漏洞发布时间格式非法");
            try { Instant.parse(document.path("published_at").asText()); }
            catch (java.time.DateTimeException e) { throw new IllegalArgumentException("漏洞发布时间必须是带时区的 ISO 日期"); }
        }
        for (JsonNode rule : document.path("affected")) {
            String name = rule.path("name").asText("");
            if (!rule.isObject() || !rule.path("name").isTextual() || name.isBlank() || name.length() > 255
                    || rule.has("vrange") == rule.has("ranges")) throw new IllegalArgumentException("漏洞缺少软件及唯一版本条件");
            for (String field : List.of("os", "source", "fixed_version", "match")) {
                if (rule.has(field) && (!rule.path(field).isTextual() || rule.path(field).asText().length() > 255)) throw new IllegalArgumentException("漏洞规则字段类型非法");
            }
            if (rule.has("match") && !Set.of("exact", "contains").contains(rule.path("match").asText())) throw new IllegalArgumentException("软件名匹配方式非法");
            if (rule.has("vrange") && (!rule.path("vrange").isTextual()
                    || !rule.path("vrange").asText().matches("(?:\\*|(?:>=|<=|>|<|=)?[A-Za-z0-9][A-Za-z0-9._:+~%-]{0,254})"))) throw new IllegalArgumentException("漏洞版本条件非法");
            if (rule.has("ranges") && (!rule.path("ranges").isArray() || rule.path("ranges").isEmpty() || rule.path("ranges").size() > 8)) throw new IllegalArgumentException("漏洞版本范围非法");
            if (rule.has("ranges")) for (JsonNode range : rule.path("ranges")) {
                if (!range.isTextual() || !range.asText().matches("(?:>=|<=|>|<|=)[A-Za-z0-9][A-Za-z0-9._:+~%-]{0,254}")) throw new IllegalArgumentException("漏洞版本范围非法");
            }
        }
    }
}
