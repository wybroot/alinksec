package com.alinksec.service.query;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import java.util.HashMap;
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
        if (status != null) {
            where.append(" AND f.status = ").append(status);
        } else {
            where.append(" AND f.status IN (0,1)");
        }
        if (severity != null) {
            where.append(" AND f.severity >= ").append(severity);
        }
        if (agentId != null && !agentId.isBlank()) {
            where.append(" AND f.agent_id = '").append(agentId.replace("'", "''")).append("'");
        }
        String kw = keyword == null || keyword.isBlank() ? null : "%" + keyword.trim() + "%";
        if (kw != null) {
            where.append(" AND (f.cve_id ILIKE ? OR f.software ILIKE ?)");
        }
        String cond = where.toString();

        Long total = jdbc.queryForObject(
                "SELECT count(*) FROM t_vuln_finding f" + cond, Long.class, kw, kw);
        List<Map<String, Object>> list = jdbc.queryForList("""
                SELECT f.id, f.task_id, f.agent_id, a.hostname, f.cve_id, c.title, f.software,
                       f.installed_version, f.fixed_version, f.severity, c.cvss,
                       f.status, f.created_at
                FROM t_vuln_finding f
                LEFT JOIN t_agent a ON a.agent_id = f.agent_id
                LEFT JOIN t_cve_db c ON c.cve_id = f.cve_id""" + cond + """
                ORDER BY f.severity DESC, f.created_at DESC LIMIT ? OFFSET ?
                """, kw, kw, size, (page - 1) * size);

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
        if (Boolean.TRUE.equals(risky)) {
            where.append(" AND p.risky");
        }
        if (agentId != null && !agentId.isBlank()) {
            where.append(" AND p.agent_id = '").append(agentId.replace("'", "''")).append("'");
        }
        String kw = keyword == null || keyword.isBlank() ? null : "%" + keyword.trim() + "%";
        if (kw != null) {
            where.append(" AND (p.service ILIKE ? OR p.process ILIKE ? OR CAST(p.port AS TEXT) LIKE ?)");
        }
        String cond = where.toString();
        Long total = jdbc.queryForObject(
                "SELECT count(*) FROM t_port_finding p" + cond, Long.class, kw, kw, kw);
        List<Map<String, Object>> list = jdbc.queryForList("""
                SELECT p.id, p.task_id, p.agent_id, a.hostname, p.port, p.protocol, p.process,
                       p.service, p.risky, p.risky_reason, p.created_at
                FROM t_port_finding p LEFT JOIN t_agent a ON a.agent_id = p.agent_id
                """ + cond + " ORDER BY p.risky DESC, p.port LIMIT ? OFFSET ?",
                kw, kw, kw, size, (page - 1) * size);
        Map<String, Object> result = new HashMap<>();
        result.put("list", list);
        result.put("total", total == null ? 0 : total);
        return result;
    }

    /** 扫描任务分页 */
    public Map<String, Object> tasks(int page, int size) {
        Long total = jdbc.queryForObject("SELECT count(*) FROM t_scan_task", Long.class);
        List<Map<String, Object>> list = jdbc.queryForList("""
                SELECT id, task_no, name, type, scope::text AS scope, status, progress,
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
        result.put("bySeverity", jdbc.queryForList("""
                SELECT severity, count(*) AS count
                FROM t_vuln_finding WHERE status IN (0,1)
                GROUP BY severity ORDER BY severity
                """));
        result.put("topSoftware", jdbc.queryForList("""
                SELECT software, count(DISTINCT agent_id) AS hosts, count(*) AS findings
                FROM t_vuln_finding WHERE status IN (0,1)
                GROUP BY software ORDER BY findings DESC LIMIT 10
                """));
        result.put("weakpwd", jdbc.queryForObject(
                "SELECT count(*) FROM t_weakpwd_finding WHERE status IN (0,1)", Long.class));
        result.put("cveDbCount", jdbc.queryForObject(
                "SELECT count(*) FROM t_cve_db", Long.class));
        return result;
    }
}
