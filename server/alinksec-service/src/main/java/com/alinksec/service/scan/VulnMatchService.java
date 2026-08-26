package com.alinksec.service.scan;

import com.alinksec.common.util.JsonUtils;
import com.fasterxml.jackson.databind.JsonNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 漏洞比对引擎（docs/04 §4.4）：t_cve_db.affected(JSONB) × t_asset_software 快照 → t_vuln_finding。
 *
 * 触发点：
 *   1. Agent 资产快照落库后自动比对（task_id=0，快照触发）
 *   2. 漏洞扫描任务创建时比对（task_id=任务 id）
 *
 * 状态保留：已忽略(2)/已修复(3) 的 (agent,cve,software) 组合不重复插入；
 * 新一轮比对前清除该 agent 未处置(0/1)记录后重插。
 */
@Service
public class VulnMatchService {

    private static final Logger log = LoggerFactory.getLogger(VulnMatchService.class);

    private final JdbcTemplate jdbc;

    public VulnMatchService(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    /** 单机比对。taskId=0 表示资产快照触发的自动比对。 */
    @Transactional
    public void matchAgent(String agentId, long taskId) {
        List<Map<String, Object>> cves = jdbc.queryForList(
                "SELECT cve_id, severity, cvss, affected::text AS affected FROM t_cve_db");
        if (cves.isEmpty()) {
            return;
        }
        List<Map<String, Object>> software = jdbc.queryForList(
                "SELECT name, version FROM t_asset_software WHERE agent_id = ?", agentId);
        if (software.isEmpty()) {
            return;
        }

        // 已忽略/已修复组合：新一轮不再重复报
        Set<String> dismissed = new HashSet<>();
        jdbc.query("""
                        SELECT cve_id, software FROM t_vuln_finding
                        WHERE agent_id = ? AND status IN (2, 3)
                        """, (rs, i) -> dismissed.add(rs.getString(1) + "|" + rs.getString(2)),
                agentId);

        // 未处置记录先清后插（快照全量替换语义）
        jdbc.update("DELETE FROM t_vuln_finding WHERE agent_id = ? AND status IN (0, 1)", agentId);

        int inserted = 0;
        for (Map<String, Object> cve : cves) {
            String cveId = (String) cve.get("cve_id");
            int severity = ((Number) cve.get("severity")).intValue();
            Object cvss = cve.get("cvss");
            for (JsonNode rule : JsonUtils.read((String) cve.get("affected"))) {
                String cveName = rule.path("name").asText("");
                String vrange = rule.path("vrange").asText("*");
                if (cveName.isEmpty()) {
                    continue;
                }
                for (Map<String, Object> sw : software) {
                    String swName = String.valueOf(sw.get("name"));
                    String swVersion = String.valueOf(sw.get("version") == null ? "" : sw.get("version"));
                    // 名称宽松匹配：CVE 侧名称为资产软件名子串（如 openssl 命中 openssl-libs）
                    if (!swName.toLowerCase().contains(cveName.toLowerCase())) {
                        continue;
                    }
                    String fixed = rangeFixedVersion(vrange);
                    if (!versionInRange(swVersion, vrange)) {
                        continue;
                    }
                    if (dismissed.contains(cveId + "|" + swName)) {
                        continue;
                    }
                    jdbc.update("""
                            INSERT INTO t_vuln_finding
                              (task_id, agent_id, cve_id, software, installed_version, fixed_version, severity, cvss)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                            """, taskId, agentId, cveId, swName, swVersion, fixed, severity, cvss);
                    inserted++;
                }
            }
        }
        log.info("漏洞比对完成: agent={} task={} cve_db={} software={} findings={}",
                agentId, taskId, cves.size(), software.size(), inserted);
    }

    /** 全量比对（CVE 库导入后手动刷新）。返回比对主机数。 */
    public int matchAll(long taskId) {
        List<String> agents = jdbc.queryForList(
                "SELECT agent_id FROM t_asset_software GROUP BY agent_id", String.class);
        for (String agentId : agents) {
            try {
                matchAgent(agentId, taskId);
            } catch (Exception e) {
                log.warn("漏洞比对失败: agent={} err={}", agentId, e.getMessage());
            }
        }
        return agents.size();
    }

    /* ==================== 版本比较器（rpm 宽松风格） ==================== */

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
                : range.startsWith("=") ? "=" : "=";
        String bound = range.substring(op.length()).trim();
        if (bound.isEmpty()) {
            return true;
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

    /** 从 vrange 提取修复版本（边界值），如 "<1.1.1n" → "1.1.1n" */
    static String rangeFixedVersion(String vrange) {
        String range = vrange == null ? "" : vrange.trim();
        if (range.startsWith("<=")) {
            return range.substring(2).trim();
        }
        if (range.startsWith("<")) {
            return range.substring(1).trim();
        }
        if (range.startsWith(">=")) {
            return range.substring(2).trim();
        }
        if (range.startsWith(">")) {
            return range.substring(1).trim();
        }
        if (range.startsWith("=")) {
            return range.substring(1).trim();
        }
        return range.isEmpty() || "*".equals(range) ? null : range;
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
        long va = Long.parseLong(na), vb = Long.parseLong(nb);
        if (va != vb) {
            return Long.compare(va, vb);
        }
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
