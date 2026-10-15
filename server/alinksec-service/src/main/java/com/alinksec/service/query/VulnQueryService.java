package com.alinksec.service.query;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * 漏洞与弱口令查询。
 */
@Service
public class VulnQueryService {

    private final JdbcTemplate jdbc;

    public VulnQueryService(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public Map<String, Object> findings(Integer status, Integer severity, String agentId,
                                        String keyword, int page, int size) {
        StringBuilder where = new StringBuilder(" WHERE 1=1");
        List<Object> args = new ArrayList<>();
        if (status != null) {
            where.append(" AND f.status = ?");
            args.add(status);
        } else {
            where.append(" AND f.status IN (0,1)");
        }
        if (severity != null) {
            where.append(" AND f.severity >= ?");
            args.add(severity);
        }
        if (agentId != null && !agentId.isBlank()) {
            where.append(" AND f.agent_id = ?");
            args.add(agentId.trim());
        }
        if (keyword != null && !keyword.isBlank()) {
            where.append(" AND (LOWER(f.cve_id) LIKE LOWER(?) OR LOWER(f.software) LIKE LOWER(?))");
            String pattern = "%" + keyword.trim() + "%";
            args.add(pattern);
            args.add(pattern);
        }
        String cond = where.toString();

        Long total = jdbc.queryForObject(
                "SELECT count(*) FROM t_vuln_finding f" + cond, Long.class, args.toArray());
        List<Object> pageArgs = new ArrayList<>(args);
        pageArgs.add(size);
        pageArgs.add((page - 1) * size);
        List<Map<String, Object>> list = jdbc.queryForList("""
                SELECT f.id, f.task_id, f.agent_id, a.hostname, f.cve_id, c.title, f.software,
                       f.installed_version, f.fixed_version, f.severity, f.cvss,
                       f.status,f.created_at,f.current_match,f.observed_at,f.source,f.architecture,f.distro_id,f.distro_version,
                        f.os_type,f.os_version,f.identity_status,a.software_collection_status,
                        f.rule_source_id,f.rule_digest,f.rule_evidence,f.evidence_status,
                        CASE WHEN a.os_type=1 AND a.package_repair_contract=2 THEN 1 ELSE 0 END AS execution_supported,
                        CASE WHEN f.evidence_status='declared' AND f.rule_digest<>''
                          AND f.rule_digest=c.rule_digest AND f.rule_source_id=c.rule_source_id THEN 1 ELSE 0 END AS rule_current,
                       CASE WHEN f.current_match=true AND f.identity_status='complete' AND a.deleted=false
                         AND a.software_collection_status='complete' AND a.os_type=f.os_type
                         AND COALESCE(a.os_version,'')=f.os_version AND a.distro_id=f.distro_id AND a.distro_version=f.distro_version
                         AND (f.source='registry' OR a.software_identity_error='')
                         AND (SELECT count(*) FROM t_asset_software s WHERE s.agent_id=f.agent_id AND s.name=f.software)=1
                         AND EXISTS (SELECT 1 FROM t_asset_software s WHERE s.agent_id=f.agent_id AND s.name=f.software
                           AND s.version=f.installed_version AND s.source=f.source AND s.architecture=f.architecture)
                         THEN 1 ELSE 0 END AS identity_current
                FROM t_vuln_finding f
                LEFT JOIN t_agent a ON a.agent_id = f.agent_id
                LEFT JOIN t_cve_db c ON c.cve_id = f.cve_id""" + cond
                 + " ORDER BY f.severity DESC, f.created_at DESC, f.id DESC LIMIT ? OFFSET ?",
                pageArgs.toArray());

        for (var row : list) {
            var target = new HashMap<>(row);
            target.put("pkg_name", row.get("software"));
            target.put("target_version", row.get("fixed_version"));
            row.put("repair_reviewed", com.alinksec.service.fix.PatchRepoService.reviewedPatch(jdbc, target) == null ? 0 : 1);
        }
        Map<String, Object> result = new HashMap<>();
        result.put("list", list);
        result.put("total", total == null ? 0 : total);
        return result;
    }

    public Map<String, Object> weakpwdFindings(int page, int size) {
        Long total = jdbc.queryForObject(
                "SELECT count(*) FROM t_weakpwd_finding WHERE status IN (0,1)", Long.class);
        List<Map<String, Object>> list = jdbc.queryForList("""
                SELECT w.id, w.task_id, w.agent_id, a.hostname, w.account, w.type, w.remark,
                       w.status, w.created_at
                FROM t_weakpwd_finding w LEFT JOIN t_agent a ON a.agent_id = w.agent_id
                WHERE w.status IN (0,1)
                ORDER BY w.created_at DESC LIMIT ? OFFSET ?
                """, size, (page - 1) * size);
        Map<String, Object> result = new HashMap<>();
        result.put("list", list);
        result.put("total", total == null ? 0 : total);
        return result;
    }

    /** 端口服务发现（含高危标记） */
    public Map<String, Object> portFindings(Boolean risky, String agentId,
                                            String keyword, int page, int size) {
        StringBuilder where = new StringBuilder(" WHERE 1=1");
        List<Object> args = new ArrayList<>();
        if (Boolean.TRUE.equals(risky)) {
            where.append(" AND p.risky");
        }
        if (agentId != null && !agentId.isBlank()) {
            where.append(" AND p.agent_id = ?");
            args.add(agentId.trim());
        }
        if (keyword != null && !keyword.isBlank()) {
            where.append(" AND (LOWER(p.service) LIKE LOWER(?) OR LOWER(p.process) LIKE LOWER(?) OR CAST(p.port AS TEXT) LIKE ?)");
            String pattern = "%" + keyword.trim() + "%";
            args.add(pattern);
            args.add(pattern);
            args.add(pattern);
        }
        String cond = where.toString();
        Long total = jdbc.queryForObject(
                "SELECT count(*) FROM t_port_finding p" + cond, Long.class, args.toArray());
        List<Object> pageArgs = new ArrayList<>(args);
        pageArgs.add(size);
        pageArgs.add((page - 1) * size);
        List<Map<String, Object>> list = jdbc.queryForList("""
                SELECT p.id, p.task_id, p.agent_id, a.hostname, p.port, p.protocol, p.process,
                       p.service, p.risky, p.risky_reason, p.created_at
                FROM t_port_finding p LEFT JOIN t_agent a ON a.agent_id = p.agent_id
                """ + cond + " ORDER BY p.risky DESC, p.port LIMIT ? OFFSET ?",
                pageArgs.toArray());
        Map<String, Object> result = new HashMap<>();
        result.put("list", list);
        result.put("total", total == null ? 0 : total);
        return result;
    }

    /** 扫描任务分页 */
    public Map<String, Object> tasks(int page, int size) {
        Long total = jdbc.queryForObject("SELECT count(*) FROM t_scan_task", Long.class);
        List<Map<String, Object>> list = jdbc.queryForList("""
                SELECT id, task_no, name, type, CAST(scope AS TEXT) AS scope, status, progress,
                       started_at, finished_at, created_at
                FROM t_scan_task ORDER BY created_at DESC LIMIT ? OFFSET ?
                """, size, (page - 1) * size);
        Map<String, Object> result = new HashMap<>();
        result.put("list", list);
        result.put("total", total == null ? 0 : total);
        return result;
    }

    public Map<String, Object> stats() {
        Map<String, Object> result = new HashMap<>();
        result.putAll(jdbc.queryForMap("""
                SELECT SUM(CASE WHEN status IN (0,1) THEN 1 ELSE 0 END) AS pending,
                       SUM(CASE WHEN status = 3 THEN 1 ELSE 0 END) AS fixed,
                       SUM(CASE WHEN status IN (0,1,3) THEN 1 ELSE 0 END) AS total
                FROM t_vuln_finding
                """));
        result.put("bySeverity", jdbc.queryForList("""
                SELECT severity, count(*) AS count
                FROM t_vuln_finding WHERE status IN (0,1)
                GROUP BY severity ORDER BY severity
                """));
        result.put("topSoftware", jdbc.queryForList("""
                SELECT software,source,architecture,distro_id,distro_version,os_type,os_version,
                       count(DISTINCT agent_id) AS hosts, count(*) AS findings
                FROM t_vuln_finding WHERE status IN (0,1)
                GROUP BY software,source,architecture,distro_id,distro_version,os_type,os_version ORDER BY findings DESC LIMIT 10
                """));
        result.put("weakpwd", jdbc.queryForObject(
                "SELECT count(*) FROM t_weakpwd_finding WHERE status IN (0,1)", Long.class));
        result.put("cveDbCount", jdbc.queryForObject(
                "SELECT count(*) FROM t_cve_db", Long.class));
        result.put("coverage", jdbc.queryForList("""
                SELECT %s AS status,count(*) AS hosts FROM t_agent a
                LEFT JOIN t_vuln_coverage v ON v.agent_id=a.agent_id
                WHERE a.deleted=false GROUP BY %s
                """.formatted(coverageStatus(),coverageStatus())));
        return result;
    }

    private static String coverageStatus() {
        return """
                CASE WHEN a.software_collection_status<>'complete' THEN a.software_collection_status
                  WHEN v.agent_id IS NULL THEN 'not_scanned'
                  WHEN v.inventory_revision<>a.software_revision THEN 'stale_inventory'
                  WHEN v.rule_revision<>(SELECT revision FROM t_vuln_rule_state WHERE id=1) THEN 'stale_rules'
                  ELSE v.status END
                """;
    }

    public Map<String,Object> coverage(String agentId, int page, int size) {
        String condition = " WHERE a.deleted=false";
        var args = new ArrayList<Object>();
        if (agentId != null && !agentId.isBlank()) { condition += " AND a.agent_id=?"; args.add(agentId.trim()); }
        Long total = jdbc.queryForObject("SELECT count(*) FROM t_agent a" + condition,Long.class,args.toArray());
        args.add(size); args.add((page-1)*size);
        var rows = jdbc.queryForList("""
                SELECT a.agent_id,a.hostname,a.distro_id,a.distro_version,a.os_type,a.os_version,
                  a.software_collection_status,a.software_collection_error,a.software_identity_error,
                  a.software_succeeded_at,a.software_attempted_at,%s AS status,
                  v.task_id,v.assessed_at,v.inventory_revision,v.rule_revision,
                  COALESCE(v.software_count,(SELECT count(*) FROM t_asset_software s WHERE s.agent_id=a.agent_id)) AS software_count,
                  v.affected_packages,v.evaluated_packages,v.unknown_packages,v.no_rule_packages,v.assessment
                FROM t_agent a LEFT JOIN t_vuln_coverage v ON v.agent_id=a.agent_id
                """.formatted(coverageStatus()) + condition + " ORDER BY a.hostname,a.agent_id LIMIT ? OFFSET ?",args.toArray());
        return Map.of("list",rows,"total",total == null ? 0 : total,
                "limitation","只比对当前选中的已导入声明；没有漏洞结果、没有适用规则或空清单都不能证明安全。当前来源按整条 CVE 选择：人工来源优先，其余按来源标识排序，不合并其他来源的系统范围。");
    }

    public Map<String,Object> packageAssessments(String agentId, String keyword, int page, int size) {
        var host = coverage(agentId,1,1);
        @SuppressWarnings("unchecked") var hosts = (List<Map<String,Object>>)host.get("list");
        if (hosts.size()!=1 || !agentId.equals(hosts.get(0).get("agent_id"))) throw new IllegalArgumentException("主机不存在或已删除");
        String condition = " WHERE agent_id=?";
        var args = new ArrayList<Object>(); args.add(agentId);
        if (keyword != null && !keyword.isBlank()) { condition += " AND LOWER(software) LIKE LOWER(?)"; args.add("%"+keyword.trim()+"%"); }
        Long total = jdbc.queryForObject("SELECT count(*) FROM t_vuln_package_assessment"+condition,Long.class,args.toArray());
        args.add(size); args.add((page-1)*size);
        var rows = jdbc.queryForList("SELECT software,installed_version,source,architecture,status,affected_cves,not_affected_cves,unknown_cves,evidence FROM t_vuln_package_assessment"
                +condition+" ORDER BY software,source,architecture,installed_version LIMIT ? OFFSET ?",args.toArray());
        return Map.of("host",hosts.get(0),"list",rows,"total",total == null ? 0 : total,"limitation",host.get("limitation"));
    }
}
