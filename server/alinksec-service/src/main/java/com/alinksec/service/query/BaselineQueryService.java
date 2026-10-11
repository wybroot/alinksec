package com.alinksec.service.query;

import com.alinksec.service.config.DatabaseDialect;
import com.alinksec.common.util.JsonUtils;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 基线核查查询：模板 / 任务 / 结果明细。
 */
@Service
public class BaselineQueryService {

    private final JdbcTemplate jdbc;
    private final DatabaseDialect database;

    public BaselineQueryService(JdbcTemplate jdbc, DatabaseDialect database) {
        this.jdbc = jdbc;
        this.database = database;
    }

    public List<Map<String, Object>> templates() {
        return jdbc.queryForList("""
                SELECT id, code, name, standard, os_type, version, item_count, enabled, package_id, os_version_pattern
                FROM t_baseline_template ORDER BY id
                """);
    }

    public Map<String, Object> templateItems(long templateId, String category, Integer severity) {
        StringBuilder where = new StringBuilder(" WHERE template_id = ").append(templateId);
        if (category != null && !category.isBlank()) {
            where.append(" AND category = '").append(category.replace("'", "''")).append("'");
        }
        if (severity != null) {
            where.append(" AND severity >= ").append(severity);
        }
        Long total = jdbc.queryForObject(
                "SELECT count(*) FROM t_baseline_item" + where, Long.class);
        List<Map<String, Object>> items = jdbc.queryForList("""
                SELECT id, code, name, category, severity, CAST("check" AS TEXT) AS "check",
                       remediation, CAST(fix_spec AS TEXT) AS fix_spec, enabled
                FROM t_baseline_item""" + where + " ORDER BY code");
        Map<String, Object> result = new HashMap<>();
        result.put("list", items);
        result.put("total", total == null ? 0 : total);
        return result;
    }

    public Map<String, Object> tasks(int page, int size) {
        Long total = jdbc.queryForObject("SELECT count(*) FROM t_baseline_task", Long.class);
        List<Map<String, Object>> list = jdbc.queryForList("""
                SELECT t.id, t.task_no, t.name, CAST(t.template_ids AS TEXT) AS template_ids, t.status, t.progress,
                       (SELECT count(*) FROM t_baseline_summary s WHERE s.task_id = t.id) AS agent_count,
                       (SELECT ROUND(AVG(s.score), 2) FROM t_baseline_summary s WHERE s.task_id = t.id) AS avg_score,
                       t.created_at, t.started_at, t.finished_at
                FROM t_baseline_task t ORDER BY t.id DESC LIMIT ? OFFSET ?
                """, size, (page - 1) * size);
        list.forEach(this::normalizeTemplateIds);
        Map<String, Object> result = new HashMap<>();
        result.put("list", list);
        result.put("total", total == null ? 0 : total);
        return result;
    }

    /** 任务详情：按主机汇总 */
    public Map<String, Object> taskDetail(long taskId) {
        List<Map<String, Object>> task = jdbc.queryForList("""
                SELECT t.id, t.task_no, t.name, CAST(t.template_ids AS TEXT) AS template_ids, t.status, t.progress,
                       CAST(t.scope AS TEXT) AS scope, t.created_at, t.started_at, t.finished_at
                FROM t_baseline_task t WHERE t.id = ?
                """, taskId);
        if (task.isEmpty()) {
            return null;
        }
        normalizeTemplateIds(task.get(0));
        List<Map<String, Object>> hosts = jdbc.queryForList("""
                SELECT s.agent_id, a.hostname, a.ip, s.total, s.passed_count, s.failed_count, s.error_count, s.legacy_count,
                       s.score, s.checked_at
                FROM t_baseline_summary s
                LEFT JOIN t_agent a ON a.agent_id = s.agent_id
                WHERE s.task_id = ?
                ORDER BY s.score ASC
                """, taskId);
        Map<String, Object> result = new HashMap<>();
        result.put("task", task.get(0));
        result.put("hosts", hosts);
        result.put("templates", jdbc.queryForList("SELECT * FROM t_baseline_task_template WHERE task_id=? ORDER BY template_id", taskId));
        return result;
    }

    /** Return plain IDs, never a PostgreSQL JDBC array and its connection internals. */
    private void normalizeTemplateIds(Map<String, Object> task) {
        String encoded = String.valueOf(task.get("template_ids"));
        var values = JsonUtils.read(database.isSqlite() ? encoded : encoded.replace('{', '[').replace('}', ']'));
        List<Long> ids = new java.util.ArrayList<>();
        values.forEach(value -> ids.add(value.longValue()));
        task.put("template_ids", ids);
    }

    /** 单机核查明细（含模板项信息；fixable = fix_spec 非空且 risk=auto，一键修复入口用） */
    public List<Map<String, Object>> taskAgentItems(long taskId, String agentId, Boolean passed) {
        StringBuilder where = new StringBuilder(
                " WHERE r.task_id = " + taskId + " AND r.agent_id = '" + agentId.replace("'", "''") + "'");
        if (passed != null) {
            where.append(" AND r.passed = ").append(passed);
        }
        String sql = ("""
                SELECT i.id AS item_id, i.code, i.name, i.category, i.severity, r.passed, r.actual, r.message,r.execution_status,r.duration_ms,
                       r.checked_at, i.rule_id, i.template_version, i.package_id, i.content_sha256, CAST(i.fix_spec AS TEXT) AS fix_spec,
                       (NOT r.passed AND r.execution_status <> 'error' AND i.fix_current AND i.fix_spec IS NOT NULL
                        AND CAST(i.fix_spec AS TEXT) NOT IN ('null', '')
                        AND COALESCE(%s, 'auto') <> 'manual') AS fixable
                FROM t_baseline_result r
                JOIN v_baseline_result_definition i ON i.result_id = r.id""" + where
                + " ORDER BY i.severity DESC, i.code")
                .formatted(database.isSqlite() ? "json_extract(i.fix_spec, '$.risk')" : "CAST(i.fix_spec AS JSONB)->>'risk'");
        return jdbc.queryForList(sql);
    }

    /** 类别维度失败统计（雷达图/柱状图） */
    public List<Map<String, Object>> taskCategoryStats(long taskId) {
        return jdbc.queryForList("""
                SELECT i.category, count(*) AS total,
                       SUM(CASE WHEN r.execution_status='pass' THEN 1 ELSE 0 END) AS passed,
                       SUM(CASE WHEN r.execution_status='fail' THEN 1 ELSE 0 END) AS failed,
                       SUM(CASE WHEN r.execution_status='error' THEN 1 ELSE 0 END) AS errors,
                       SUM(CASE WHEN r.execution_status='legacy' THEN 1 ELSE 0 END) AS legacy
                FROM t_baseline_result r JOIN v_baseline_result_definition i ON i.result_id = r.id
                WHERE r.task_id = ?
                GROUP BY i.category ORDER BY i.category
                """, taskId);
    }

    /** 最新任务按主机汇总（含严重度分布），供基线页首屏 */
    public Map<String, Object> latestTaskRows() {
        List<Map<String, Object>> tasks = jdbc.queryForList(
                "SELECT id, task_no, name, template_ids FROM t_baseline_task ORDER BY id DESC LIMIT 1");
        if (tasks.isEmpty()) {
            return Map.of("list", List.of(), "total", 0);
        }
        long taskId = ((Number) tasks.get(0).get("id")).longValue();
        List<Map<String, Object>> rows = jdbc.queryForList("""
                SELECT s.agent_id, a.hostname, t.name AS tpl, s.total, s.passed_count, s.failed_count,s.error_count,s.legacy_count,
                       s.score, s.checked_at,
                       SUM(CASE WHEN r.execution_status='fail' AND i.severity = 4 THEN 1 ELSE 0 END) AS c,
                       SUM(CASE WHEN r.execution_status='fail' AND i.severity = 3 THEN 1 ELSE 0 END) AS h,
                       SUM(CASE WHEN r.execution_status='fail' AND i.severity = 2 THEN 1 ELSE 0 END) AS m,
                       SUM(CASE WHEN r.execution_status='fail' AND i.severity = 1 THEN 1 ELSE 0 END) AS l
                FROM t_baseline_summary s
                JOIN t_agent a ON a.agent_id = s.agent_id
                JOIN t_baseline_task t ON t.id = s.task_id
                LEFT JOIN t_baseline_result r ON r.task_id = s.task_id AND r.agent_id = s.agent_id
                LEFT JOIN v_baseline_result_definition i ON i.result_id = r.id
                WHERE s.task_id = ?
                GROUP BY s.agent_id, a.hostname, t.name, s.total, s.passed_count, s.failed_count,s.error_count,s.legacy_count,
                         s.score, s.checked_at
                ORDER BY s.score ASC
                """, taskId);
        Map<String, Object> result = new HashMap<>();
        result.put("taskId", taskId);
        result.put("list", rows);
        result.put("total", rows.size());
        return result;
    }
}
