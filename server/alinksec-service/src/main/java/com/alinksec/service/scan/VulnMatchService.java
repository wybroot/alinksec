package com.alinksec.service.scan;

import com.alinksec.common.util.JsonUtils;
import com.fasterxml.jackson.databind.JsonNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;
import java.util.LinkedHashMap;
import java.util.Objects;
import java.util.Set;

/**
 * 漏洞比对引擎（docs/04 §4.4）：t_cve_db.affected(JSONB) × t_asset_software 快照 → t_vuln_finding。
 *
 * 触发点：
 *   1. Agent 资产快照落库后自动比对（task_id=0，快照触发）
 *   2. 漏洞扫描任务创建时比对（task_id=任务 id）
 *
 * 保留原始依据及修复引用。已修复决定只等待新的资产采集，不永久抑制重新安装。
 */
@Service
public class VulnMatchService {

    private static final Logger log = LoggerFactory.getLogger(VulnMatchService.class);

    private final JdbcTemplate jdbc;
    private final org.springframework.transaction.support.TransactionTemplate transaction;

    public VulnMatchService(JdbcTemplate jdbc, org.springframework.transaction.PlatformTransactionManager transactionManager) {
        this.jdbc = jdbc;
        this.transaction = new org.springframework.transaction.support.TransactionTemplate(transactionManager);
    }

    /** 单机比对。taskId=0 表示资产快照触发的自动比对。 */
    @Transactional
    public void matchAgent(String agentId, long taskId) {
        transaction.executeWithoutResult(status -> matchSnapshot(agentId,taskId));
    }

    private void matchSnapshot(String agentId, long taskId) {
        // Serialize scans/results with inventory replacement for this host. This
        // also makes a fixed finding's inventory revision a durable boundary.
        jdbc.update("UPDATE t_agent SET software_revision=software_revision WHERE agent_id=? AND deleted=false", agentId);
        var hosts = jdbc.queryForList("""
                SELECT os_type,os_version,distro_id,distro_version,software_collection_status,software_identity_error,software_revision
                FROM t_agent WHERE agent_id=? AND deleted=false
                """, agentId);
        if (hosts.size() != 1) return;
        var host = hosts.get(0);
        long inventoryRevision = ((Number)host.get("software_revision")).longValue();
        long ruleRevision = jdbc.queryForObject("SELECT revision FROM t_vuln_rule_state WHERE id=1", Long.class);
        jdbc.update("UPDATE t_vuln_finding SET current_match=false WHERE agent_id=?", agentId);
        List<Map<String, Object>> software = jdbc.queryForList(
                "SELECT name,version,source,architecture FROM t_asset_software WHERE agent_id = ? ORDER BY name,source,architecture,version", agentId);
        var coverage = new VulnerabilityCoverage(host, software, ruleRevision);
        if (Set.of("failed", "unsupported").contains(text(host, "software_collection_status"))) {
            coverage.persist(jdbc, agentId, taskId);
            log.info("跳过不完整的软件资产比对: agent={}", agentId);
            return;
        }

        String pendingRepair = """
                EXISTS (SELECT 1 FROM t_fix_record r JOIN t_fix_task t ON t.id = r.task_id
                        WHERE r.agent_id = f.agent_id AND r.ref_id = CAST(f.id AS TEXT)
                          AND r.ref_type = 'vuln_finding' AND r.status = 0 AND t.status IN (0, 1))
                """;
        // 保留修复引用的 finding ID，重连时的资产扫描不能让结果失去回写目标。
        Map<String, Long> dismissed = new LinkedHashMap<>();
        jdbc.query("""
                         SELECT cve_id,software,installed_version,source,architecture,distro_id,distro_version,os_type,os_version,identity_status,rule_source_id,rule_digest,evidence_status,id FROM t_vuln_finding f
                        WHERE agent_id = ? AND (status=2 OR (status=3 AND resolved_inventory_revision>=?) OR %s)
                          """.formatted(pendingRepair), (rs, i) -> dismissed.put(decisionKey(findingKey(rs.getString(1), rs.getString(2), rs.getString(3),
                          rs.getString(4), rs.getString(5), rs.getString(6), rs.getString(7), rs.getInt(8), rs.getString(9), rs.getString(10)),
                          rs.getString(11), rs.getString(12), rs.getString(13)), rs.getLong(14)),
                agentId, inventoryRevision);

        Map<String, Long> open = new LinkedHashMap<>();
        jdbc.query("""
                SELECT cve_id,software,installed_version,source,architecture,distro_id,distro_version,os_type,os_version,
                  identity_status,rule_source_id,rule_digest,evidence_status,id FROM t_vuln_finding
                WHERE agent_id=? AND status IN (0,1) ORDER BY id DESC
                """, (rs,i) -> open.putIfAbsent(decisionKey(findingKey(rs.getString(1),rs.getString(2),rs.getString(3),
                rs.getString(4),rs.getString(5),rs.getString(6),rs.getString(7),rs.getInt(8),rs.getString(9),rs.getString(10)),
                rs.getString(11),rs.getString(12),rs.getString(13)),rs.getLong(14)),agentId);
        Map<String,List<Map<String,Object>>> named = new LinkedHashMap<>();
        List<Map<String,Object>> registry = new java.util.ArrayList<>();
        for (var sw : software) {
            named.computeIfAbsent(text(sw,"name"), ignored -> new java.util.ArrayList<>()).add(sw);
            if (!VulnerabilityScope.nativeSource(text(sw,"source"))) registry.add(sw);
        }

        String os = text(host, "os_version"), distroId = text(host, "distro_id"), distroVersion = text(host, "distro_version");
        int osType = ((Number) host.get("os_type")).intValue();
        boolean complete = "complete".equals(text(host, "software_collection_status"));
        boolean nativeIdentity = complete && osType == 1 && text(host, "software_identity_error").isEmpty()
                && VulnerabilityScope.distributionId(distroId) && VulnerabilityScope.distributionVersion(distroVersion);
        int[] inserted = {0};
        // Metadata-only declarations contribute to coverage without generating findings.
        jdbc.query("SELECT cve_id,severity,cvss,CAST(affected AS TEXT) AS affected,rule_source_id,rule_digest,provenance FROM t_cve_db ORDER BY cve_id",
                (org.springframework.jdbc.core.RowCallbackHandler) cve -> {
            String cveId = cve.getString("cve_id");
            int severity = cve.getInt("severity");
            Object cvss = cve.getObject("cvss");
            JsonNode rules = JsonUtils.read(cve.getString("affected"));
            String ruleSource = cve.getString("rule_source_id"), ruleDigest = cve.getString("rule_digest");
            boolean recorded = !ruleSource.isEmpty() && ruleDigest.equals(VulnerabilityEvidence.ruleDigest(ruleSource, cveId, rules));
            var selection=JsonUtils.read(cve.getString("provenance")).path("selection");
            if(selection.isObject() ? !selection.path("effective").asBoolean() :
                    recorded && !new com.alinksec.service.library.LibrarySelection(jdbc).allowsCve(cveId,ruleSource,ruleDigest)) {
                coverage.selectionHeld(); return;
            }
            coverage.assess(cveId,rules,ruleSource,ruleDigest,recorded);
            Map<String, Candidate> candidates = new LinkedHashMap<>();
            for (JsonNode rule : rules) {
                String cveName = rule.path("name").asText("");
                String vrange = rule.path("vrange").asText("*");
                if (cveName.isEmpty()) {
                    continue;
                }
                var applicableSoftware = new java.util.ArrayList<>(named.getOrDefault(cveName,List.of()));
                for (var sw : registry) if (!applicableSoftware.contains(sw)) applicableSoftware.add(sw);
                for (Map<String, Object> sw : applicableSoftware) {
                    String swName = String.valueOf(sw.get("name"));
                    String swVersion = String.valueOf(sw.get("version") == null ? "" : sw.get("version"));
                    String source = text(sw, "source"), architecture = text(sw, "architecture");
                    if (VulnerabilityScope.nativeSource(source) && !recorded) continue;
                    boolean identityKnown = VulnerabilityScope.nativeSource(source) ? nativeIdentity : complete;
                    if (!ruleMatches(rule, swName, swVersion, os, source, distroId, distroVersion, architecture, identityKnown)) continue;
                    String fixed = rule.has("fixed_version") ? rule.path("fixed_version").asText("") : rangeFixedVersion(vrange);
                    String identityStatus = identityKnown ? "complete" : "legacy";
                    String key = findingKey(cveId, swName, swVersion, source, architecture, distroId, distroVersion, osType, os, identityStatus);
                    boolean excluded = "not_affected".equals(rule.path("evidence").path("assessment").asText());
                    candidates.merge(key, new Candidate(swName, swVersion, source, architecture, identityStatus, fixed,
                            !excluded, excluded, false, List.of(rule)), VulnMatchService::merge);
                }
            }
            for (Candidate candidate : candidates.values()) {
                if (!candidate.affected()) continue;
                boolean indeterminate = coverage.indeterminate(candidate.name(),candidate.version(),candidate.source(),candidate.architecture());
                String evidenceStatus = candidate.excluded() || candidate.fixConflict() || indeterminate ? "conflicting" : recorded
                        && candidate.rules().stream().allMatch(r -> r.path("evidence").isObject()) ? "declared" : "legacy";
                String key = findingKey(cveId, candidate.name(), candidate.version(), candidate.source(), candidate.architecture(),
                        distroId, distroVersion, osType, os, candidate.status());
                String decision = decisionKey(key,ruleSource,ruleDigest,evidenceStatus);
                Long retained = dismissed.get(decision);
                if (retained == null) retained = open.get(decision);
                if (retained != null) {
                    jdbc.update("UPDATE t_vuln_finding SET current_match=true,observed_at=CURRENT_TIMESTAMP,inventory_revision=? WHERE id=?",inventoryRevision,retained);
                    continue;
                }
                String snapshot = JsonUtils.write(Map.of("import", JsonUtils.read(cve.getString("provenance")), "rules", candidate.rules()));
                jdbc.update("""
                            INSERT INTO t_vuln_finding
                               (task_id,agent_id,cve_id,software,installed_version,fixed_version,severity,cvss,
                                 source,architecture,distro_id,distro_version,os_type,os_version,identity_status,
                                 rule_source_id,rule_digest,rule_evidence,evidence_status,current_match,inventory_revision,observed_at)
                              VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,true,?,CURRENT_TIMESTAMP)
                              """, taskId, agentId, cveId, candidate.name(), candidate.version(), candidate.excluded() || candidate.fixConflict() || indeterminate ? null : candidate.fixed(), severity, cvss,
                              candidate.source(), candidate.architecture(), distroId, distroVersion, osType, os, candidate.status(),
                              ruleSource, ruleDigest, snapshot, evidenceStatus,inventoryRevision);
                inserted[0]++;
            }
        });
        // Keep historical rows and any fix-record references; only their current
        // assessment ends. Pending task IDs remain available for authenticated results.
        jdbc.update("UPDATE t_vuln_finding AS f SET status=4 WHERE agent_id=? AND status IN (0,1) AND current_match=false AND NOT " + pendingRepair,agentId);
        coverage.persist(jdbc,agentId,taskId);
        if(ruleRevision!=jdbc.queryForObject("SELECT revision FROM t_vuln_rule_state WHERE id=1",Long.class))
            throw new IllegalStateException("漏洞来源依据在比对过程中已变化，请重试");
        log.info("漏洞比对完成: agent={} task={} software={} findings={}", agentId, taskId, software.size(), inserted[0]);
    }

    /** 全量比对（CVE 库导入后手动刷新）。返回比对主机数。 */
    public int matchAll(long taskId) {
        List<String> agents = jdbc.queryForList(
                "SELECT agent_id FROM t_agent WHERE deleted=false ORDER BY agent_id", String.class);
        for (String agentId : agents) {
            try {
                matchAgent(agentId, taskId);
            } catch (Exception e) {
                log.warn("漏洞比对失败: agent={} err={}", agentId, e.getMessage());
            }
        }
        return agents.size();
    }
    /** Governance delivery stays pending if even one host transaction fails. */
    public void matchAllForSelection() {
        for(String id:jdbc.queryForList("SELECT agent_id FROM t_agent WHERE deleted=false ORDER BY agent_id",String.class))
            matchAgent(id,0);
    }

    /* ==================== 来源对应的完整软件包版本与旧上游规则 ==================== */

    static boolean versionInRange(String version, String vrange, String source) {
        if (!Set.of("rpm", "dpkg").contains(source)) return versionInRange(version, vrange);
        try {
            return PackageVersions.inRange(source, version, vrange);
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    /**
     * 判断版本是否落在 vrange 内。支持：*（全匹配）、<x、<=x、>x、>=x、=x、x。
     * 空版本（采集缺失）按不匹配处理（避免误报）。
     */
    static boolean versionInRange(String version, String vrange) {
        if (version == null || version.isBlank()) {
            return false;
        }
        String range = vrange == null ? "*" : vrange.trim();
        if (range.isEmpty() || "*".equals(range)) {
            return true;
        }
        String op = range.startsWith(">=") ? ">=" : range.startsWith("<=") ? "<="
                : range.startsWith("<") ? "<" : range.startsWith(">") ? ">"
                : range.startsWith("=") ? "=" : "";
        String bound = range.substring(op.length()).trim();
        if (bound.isEmpty()) {
            return false;
        }
        int cmp = compareVersions(version, bound);
        return switch (op) {
            case "<" -> cmp < 0;
            case "<=" -> cmp <= 0;
            case ">" -> cmp > 0;
            case ">=" -> cmp >= 0;
            default -> cmp == 0;
        };
    }

    static boolean ruleMatches(JsonNode rule, String name, String version, String os, String source) {
        return ruleMatches(rule, name, version, os, source, "", "", "", false);
    }

    static boolean ruleMatches(JsonNode rule, String name, String version, String os, String source,
                               String distroId, String distroVersion, String architecture, boolean identityKnown) {
        String expected = rule.path("name").asText("");
        if (expected.isBlank() || !VulnerabilityEvidence.comparable(rule)) return false;
        if (VulnerabilityScope.nativeSource(source)) {
            if (!identityKnown || !VulnerabilityScope.nativeRule(rule) || !name.equals(expected)
                    || !VulnerabilityScope.distributionId(distroId) || !VulnerabilityScope.distributionVersion(distroVersion)
                    || !VulnerabilityScope.architecture(architecture)) return false;
        }
        for (var field : Map.of("distro_id", distroId, "distro_version", distroVersion, "architecture", architecture).entrySet()) {
            if (!rule.has(field.getKey())) continue;
            String constraint = rule.path(field.getKey()).asText("");
            if (!identityKnown || field.getValue().isEmpty() || ("*".equals(constraint)
                    ? !"architecture".equals(field.getKey()) : !constraint.equals(field.getValue()))) return false;
        }
        boolean exact = "exact".equals(rule.path("match").asText("legacy"));
        if (exact ? !name.equalsIgnoreCase(expected) : !name.toLowerCase(java.util.Locale.ROOT).contains(expected.toLowerCase(java.util.Locale.ROOT))) return false;
        String expectedOs = rule.path("os").asText("");
        if (!expectedOs.isBlank() && !"*".equals(expectedOs) && !expectedOs.equalsIgnoreCase(os)) return false;
        String expectedSource = rule.path("source").asText("");
        if (!expectedSource.isBlank() && !expectedSource.equals(source)) return false;
        String scheme = rule.path("version_scheme").asText("");
        if (!scheme.isEmpty()) {
            if (!Set.of("rpm", "dpkg", "upstream").contains(scheme)) return false;
            if ("upstream".equals(scheme) ? Set.of("rpm", "dpkg").contains(source) : !scheme.equals(source)) return false;
        }
        if (rule.has("ranges")) {
            for (JsonNode range : rule.path("ranges")) if (!versionInRange(version, range.asText(), source)) return false;
            return !rule.path("ranges").isEmpty();
        }
        return versionInRange(version, rule.path("vrange").asText("*"), source);
    }

    private static String text(Map<String, Object> row, String field) {
        return row.get(field) == null ? "" : String.valueOf(row.get(field));
    }

    private record Candidate(String name, String version, String source, String architecture, String status, String fixed,
                             boolean affected, boolean excluded, boolean fixConflict, List<JsonNode> rules) {}

    private static Candidate merge(Candidate left, Candidate right) {
        var rules = new java.util.ArrayList<>(left.rules()); rules.addAll(right.rules());
        String fixed = !left.affected() ? right.fixed() : !right.affected() ? left.fixed()
                : Objects.equals(left.fixed(), right.fixed()) ? left.fixed() : null;
        return new Candidate(left.name(), left.version(), left.source(), left.architecture(), left.status(), fixed,
                left.affected() || right.affected(), left.excluded() || right.excluded(), left.fixConflict() || right.fixConflict()
                || rules.stream().filter(r -> !"not_affected".equals(r.path("evidence").path("assessment").asText()))
                .map(r -> r.path("fixed_version").asText("")).filter(v -> !v.isBlank()).distinct().limit(2).count() > 1,
                List.copyOf(rules));
    }

    private static String decisionKey(String identity, String source, String digest, String evidenceStatus) {
        return JsonUtils.write(List.of(identity, source, digest, evidenceStatus));
    }

    private static String findingKey(String cve, String name, String version, String source, String architecture,
                                     String distroId, String distroVersion, int osType, String osVersion, String status) {
        return JsonUtils.write(java.util.Arrays.asList(cve, name, version, source, architecture, distroId, distroVersion, osType, osVersion, status));
    }

    /** A vulnerable-range boundary does not establish a vendor-confirmed fixed package. */
    static String rangeFixedVersion(String vrange) {
        return null;
    }

    /**
     * 宽松版本比较（rpm/semver 混合常见格式）：
     *   - 按 . _ - 分段；段内前导数字为数值，余下字母串
     *   - 纯数字段按数值比；数字段 < 字母段（openssl 序：1.1.1 < 1.1.1a < 1.1.1z）
     *   - 段数不足按空段（=0）补齐：9.8 < 9.8p1
     *   - 字母段按字典序：1.9.5p2 中 p2 与 p10 按字符串比（主流发行版足够）
     * 返回：负数 a<b、0 相等、正数 a>b
     */
    static int compareVersions(String a, String b) {
        String[] sa = a.trim().split("[._\\-]+");
        String[] sb = b.trim().split("[._\\-]+");
        int n = Math.max(sa.length, sb.length);
        for (int i = 0; i < n; i++) {
            String ta = i < sa.length ? sa[i] : "";
            String tb = i < sb.length ? sb[i] : "";
            int cmp = compareToken(ta, tb);
            if (cmp != 0) {
                return cmp;
            }
        }
        return 0;
    }

    private static int compareToken(String ta, String tb) {
        // 提取段内数字前缀与字母余部："10p2" → num=10, alpha="p2"
        String na = leadingDigits(ta), nb = leadingDigits(tb);
        String aa = ta.substring(na.length()), ab = tb.substring(nb.length());
        if (na.isEmpty() && nb.isEmpty()) {
            return aa.compareTo(ab);               // 纯字母段：字典序（空 "" 最小）
        }
        if (na.isEmpty()) {
            return 1;                              // 字母段 > 数字段（rpm 语义）
        }
        if (nb.isEmpty()) {
            return -1;                             // 数字段 < 字母段
        }
        int numeric = new java.math.BigInteger(na).compareTo(new java.math.BigInteger(nb));
        if (numeric != 0) return numeric;
        // 数值相等：余部短的更小（"1" < "1p1"）；再按字典序（"p1" < "p2"）
        if (aa.isEmpty() && ab.isEmpty()) {
            return 0;
        }
        if (aa.isEmpty()) {
            return -1;
        }
        if (ab.isEmpty()) {
            return 1;
        }
        return aa.compareTo(ab);
    }

    private static String leadingDigits(String s) {
        int i = 0;
        while (i < s.length() && Character.isDigit(s.charAt(i))) {
            i++;
        }
        return s.substring(0, i);
    }
}
