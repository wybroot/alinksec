package com.alinksec.service.query;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 配置修复查询：任务列表 / 明细。
 */
@Service
public class FixQueryService {

    private final JdbcTemplate jdbc;

    public FixQueryService(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public Map<String, Object> tasks(int page, int size) {
        Long total = jdbc.queryForObject("SELECT count(*) FROM t_fix_task", Long.class);
        List<Map<String, Object>> list = jdbc.queryForList("""
                SELECT t.id, t.task_no, t.name, t.type, t.status, t.created_at, t.started_at, t.finished_at,
                       (SELECT count(*) FROM t_fix_record r WHERE r.task_id = t.id) AS total_records,
                       (SELECT count(*) FROM t_fix_record r WHERE r.task_id = t.id AND r.status = 1) AS ok_records,
                       (SELECT count(*) FROM t_fix_record r WHERE r.task_id = t.id AND r.status IN (2,3,5)) AS failed_records
                FROM t_fix_task t ORDER BY t.id DESC LIMIT ? OFFSET ?
                """, size, (page - 1) * size);
        Map<String, Object> result = new HashMap<>();
        result.put("list", list);
        result.put("total", total == null ? 0 : total);
        return result;
    }

    /** 任务明细：join 主机与基线项/漏洞信息（ref_type 区分） */
    public Map<String, Object> taskRecords(long taskId) {
        List<Map<String, Object>> list = jdbc.queryForList("""
                SELECT r.id, r.agent_id, a.hostname, r.ref_id, r.ref_type,
                       COALESCE(i.code, v.cve_id)  AS code,
                       COALESCE(i.name, v.software || ' ' || COALESCE(v.installed_version,'') || ' → '
                                || COALESCE(v.fixed_version,'')) AS name,
                       COALESCE(i.category, '漏洞修复') AS category,
                       r.status, r.log, r.finished_at, r.created_at
                FROM t_fix_record r
                LEFT JOIN t_agent a ON a.agent_id = r.agent_id
                LEFT JOIN t_baseline_item i ON (r.ref_type = 'baseline_item' AND i.id = CAST(r.ref_id AS BIGINT))
                LEFT JOIN t_vuln_finding v ON (r.ref_type = 'vuln_finding' AND v.id = CAST(r.ref_id AS BIGINT))
                WHERE r.task_id = ? ORDER BY a.hostname NULLS LAST, code
                """, taskId);
        Map<String, Object> task = jdbc.queryForMap(
                "SELECT id, task_no, name, type, status, approver, approved, approved_at, "
                        + "window_start, window_end, dispatched_at, created_at, started_at, finished_at "
                        + "FROM t_fix_task WHERE id = ?",
                taskId);
        Map<String, Object> result = new HashMap<>();
        result.put("task", task);
        result.put("list", list);
        return result;
    }
}
