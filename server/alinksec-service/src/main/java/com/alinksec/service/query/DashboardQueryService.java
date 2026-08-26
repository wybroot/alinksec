package com.alinksec.service.query;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 安全总览查询（Dashboard / 大屏共用，数据全部来自真实落库表）。
 */
@Service
public class DashboardQueryService {

    private final JdbcTemplate jdbc;

    public DashboardQueryService(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public Map<String, Object> summary() {
        Map<String, Object> result = new HashMap<>();

        // 主机状态（0待激活 1在线 2离线）
        List<Map<String, Object>> hostRows = jdbc.queryForList("""
                SELECT status, count(*) AS cnt FROM t_agent
                WHERE status <> 4 GROUP BY status
                """);
        long total = 0, online = 0, offline = 0;
        for (var row : hostRows) {
            long cnt = ((Number) row.get("cnt")).longValue();
            total += cnt;
            switch (((Number) row.get("status")).intValue()) {
                case 1 -> online += cnt;
                case 2, 3 -> offline += cnt;
            }
        }
        Map<String, Object> hosts = new HashMap<>();
        hosts.put("total", total);
        hosts.put("online", online);
        hosts.put("offline", offline);
        hosts.put("weekNew", jdbc.queryForObject(
                "SELECT count(*) FROM t_agent WHERE status <> 4 AND created_at >= now() - interval '7 day'",
                Long.class));
        hosts.put("protectOn", jdbc.queryForObject(
                "SELECT count(*) FROM t_agent WHERE status <> 4 AND protect_enabled", Long.class));
        result.put("hosts", hosts);

        // 告警
        Map<String, Object> alerts = new HashMap<>();
        alerts.put("open", jdbc.queryForObject(
                "SELECT count(*) FROM t_alert WHERE status IN (0,1)", Long.class));
        alerts.put("criticalOpen", jdbc.queryForObject(
                "SELECT count(*) FROM t_alert WHERE status IN (0,1) AND severity >= 4", Long.class));
        alerts.put("today", jdbc.queryForObject(
                "SELECT count(*) FROM t_alert WHERE first_time >= current_date", Long.class));
        alerts.put("bySeverity", jdbc.queryForList("""
                SELECT severity, count(*) AS count
                FROM t_alert WHERE status IN (0,1) GROUP BY severity ORDER BY severity
                """));
        result.put("alerts", alerts);

        // 病毒 / 漏洞
        Map<String, Object> virus = new HashMap<>();
        virus.put("findings30d", jdbc.queryForObject(
                "SELECT count(*) FROM t_virus_finding WHERE created_at >= now() - interval '30 day'", Long.class));
        virus.put("quarantined", jdbc.queryForObject(
                "SELECT count(*) FROM t_virus_finding WHERE status IN (1,2)", Long.class));
        virus.put("todo", jdbc.queryForObject(
                "SELECT count(*) FROM t_virus_finding WHERE status = 0", Long.class));
        result.put("virus", virus);

        Map<String, Object> vuln = new HashMap<>();
        vuln.put("open", jdbc.queryForObject(
                "SELECT count(*) FROM t_vuln_finding WHERE status IN (0,1)", Long.class));
        vuln.put("highOpen", jdbc.queryForObject(
                "SELECT count(*) FROM t_vuln_finding WHERE status IN (0,1) AND severity >= 3", Long.class));
        result.put("vuln", vuln);

        // 基线最近一次任务
        Map<String, Object> baseline = new HashMap<>();
        List<Map<String, Object>> blRows = jdbc.queryForList("""
                SELECT avg(score)::numeric(5,2) AS avg_score, count(*) AS agents
                FROM t_baseline_summary
                WHERE (task_id, checked_at) IN (
                    SELECT task_id, max(checked_at) FROM t_baseline_summary GROUP BY task_id
                ) AND task_id = (SELECT max(id) FROM t_baseline_task)
                """);
        if (!blRows.isEmpty() && blRows.get(0).get("avg_score") != null) {
            baseline.put("avgScore", ((Number) blRows.get(0).get("avg_score")).doubleValue());
            baseline.put("hostsChecked", ((Number) blRows.get(0).get("agents")).longValue());
        }
        result.put("baseline", baseline);

        return result;
    }

    /** 近 N 天每日新增告警（趋势图） */
    public List<Map<String, Object>> alertTrend(int days) {
        return jdbc.queryForList("""
                SELECT to_char(d.day, 'MM-DD') AS date,
                       coalesce(a.cnt, 0) AS count,
                       coalesce(a.done, 0) AS handled
                FROM generate_series(current_date - (?::int - 1), current_date, interval '1 day') AS d(day)
                LEFT JOIN (
                    SELECT first_time::date AS day, count(*) AS cnt,
                           count(*) FILTER (WHERE status = 2) AS done
                    FROM t_alert GROUP BY first_time::date
                ) a ON a.day = d.day::date
                ORDER BY d.day
                """, days);
    }

    /** 告警事件类型分布 */
    public List<Map<String, Object>> eventTypeDistribution() {
        return jdbc.queryForList("""
                SELECT event_type AS type, count(*) AS count
                FROM t_alert WHERE status IN (0,1)
                GROUP BY event_type ORDER BY count DESC
                """);
    }

    /** 大屏趋势：近 N 天病毒类告警数 与 已拦截（action_taken 非空）事件数 */
    public List<Map<String, Object>> screenTrend(int days) {
        return jdbc.queryForList("""
                SELECT to_char(d.day, 'MM-DD') AS date,
                       coalesce(v.cnt, 0) AS virus,
                       coalesce(b.cnt, 0) AS blocked
                FROM generate_series(current_date - (?::int - 1), current_date, interval '1 day') AS d(day)
                LEFT JOIN (
                    SELECT first_time::date AS day, count(*) AS cnt
                    FROM t_alert WHERE event_type = 'virus'
                    GROUP BY first_time::date
                ) v ON v.day = d.day::date
                LEFT JOIN (
                    SELECT first_time::date AS day, count(*) AS cnt
                    FROM t_alert WHERE action_taken IS NOT NULL AND action_taken <> ''
                    GROUP BY first_time::date
                ) b ON b.day = d.day::date
                ORDER BY d.day
                """, days);
    }

    /** 大屏雷达：最近一次基线任务的等保维度通过率（category -> 0~100） */
    public List<Map<String, Object>> baselineCategories() {
        return jdbc.queryForList("""
                SELECT i.category,
                       round(100.0 * sum(CASE WHEN r.passed THEN 1 ELSE 0 END) / count(*)) AS pass_rate
                FROM t_baseline_result r
                JOIN t_baseline_item i ON i.id = r.item_id
                WHERE r.task_id = (SELECT max(id) FROM t_baseline_task WHERE status IN (2, 3))
                GROUP BY i.category
                ORDER BY i.category
                """);
    }

    /** 告警最多的主机 TOP N */
    public List<Map<String, Object>> topRiskHosts(int limit) {
        return jdbc.queryForList("""
                SELECT a.agent_id, a.hostname, count(*) AS alert_count
                FROM t_alert t JOIN t_agent a ON a.agent_id = t.agent_id
                WHERE t.status IN (0,1)
                GROUP BY a.agent_id, a.hostname
                ORDER BY alert_count DESC LIMIT ?
                """, limit);
    }
}
