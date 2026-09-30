package com.alinksec.service.query;

import com.alinksec.service.config.DatabaseDialect;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 病毒查杀查询：任务 / 检出 / 特征库 / 白名单。
 */
@Service
public class VirusQueryService {

    private final JdbcTemplate jdbc;
    private final DatabaseDialect database;

    public VirusQueryService(JdbcTemplate jdbc, DatabaseDialect database) {
        this.jdbc = jdbc;
        this.database = database;
    }

    public Map<String, Object> tasks(int page, int size) {
        Long total = jdbc.queryForObject("SELECT count(*) FROM t_virus_scan_task", Long.class);
        List<Map<String, Object>> list = jdbc.queryForList("""
                SELECT t.id, t.task_no, t.name, t.mode, CAST(t.scope AS TEXT) AS scope, t.status, t.progress,
                       (SELECT count(*) FROM t_virus_finding f WHERE f.task_id = t.id) AS findings,
                       t.created_at, t.started_at, t.finished_at
                FROM t_virus_scan_task t ORDER BY t.id DESC LIMIT ? OFFSET ?
                """, size, (page - 1) * size);
        Map<String, Object> result = new HashMap<>();
        result.put("list", list);
        result.put("total", total == null ? 0 : total);
        return result;
    }

    public Map<String, Object> findings(Integer status, String agentId, int page, int size) {
        StringBuilder where = new StringBuilder(" WHERE 1=1");
        if (status != null) {
            where.append(" AND f.status = ").append(status);
        } else {
            where.append(" AND f.status <> 4");
        }
        if (agentId != null && !agentId.isBlank()) {
            where.append(" AND f.agent_id = '").append(agentId.replace("'", "''")).append("'");
        }
        String cond = where.toString();

        Long total = jdbc.queryForObject(
                "SELECT count(*) FROM t_virus_finding f" + cond, Long.class);
        List<Map<String, Object>> list = jdbc.queryForList("""
                SELECT f.id, f.task_id, f.agent_id, a.hostname, f.path, f.name, f.sha256, f.size,
                       f.engine, f.severity, f.action_taken, f.status, f.created_at
                FROM t_virus_finding f LEFT JOIN t_agent a ON a.agent_id = f.agent_id""" + cond
                + " ORDER BY f.created_at DESC LIMIT ? OFFSET ?", size, (page - 1) * size);
        Map<String, Object> result = new HashMap<>();
        result.put("list", list);
        result.put("total", total == null ? 0 : total);
        return result;
    }

    public List<Map<String, Object>> dbVersions() {
        return jdbc.queryForList("""
                SELECT id, db_version, sha256, size, hash_count, rule_count, imported_at
                FROM t_virus_db ORDER BY id DESC
                """);
    }

    public List<Map<String, Object>> whitelist() {
        return jdbc.queryForList("""
                SELECT id, type, value, remark, created_at
                FROM t_virus_whitelist ORDER BY id DESC
                """);
    }

    public Map<String, Object> stats() {
        Map<String, Object> result = new HashMap<>();
        result.put("findings30d", jdbc.queryForObject(
                "SELECT count(*) FROM t_virus_finding WHERE created_at >= ?",
                Long.class, database.startOfDayDaysAgo(30)));
        result.put("quarantined", jdbc.queryForObject(
                "SELECT count(*) FROM t_virus_finding WHERE status IN (1,2)", Long.class));
        result.put("latestDb", jdbc.queryForList("""
                SELECT db_version, hash_count, rule_count, imported_at
                FROM t_virus_db ORDER BY id DESC LIMIT 1
                """));
        return result;
    }
}
