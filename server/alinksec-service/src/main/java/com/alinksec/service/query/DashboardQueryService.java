package com.alinksec.service.query;

import com.alinksec.service.config.DatabaseDialect;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.List;
import java.util.Map;

/**
 * 安全总览查询（Dashboard / 大屏共用，数据全部来自真实落库表）。
 */
@Service
public class DashboardQueryService {

    private final JdbcTemplate jdbc;
    private final DatabaseDialect database;

    public DashboardQueryService(JdbcTemplate jdbc, DatabaseDialect database) {
        this.jdbc = jdbc;
        this.database = database;
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
                "SELECT count(*) FROM t_agent WHERE status <> 4 AND created_at >= ?",
                Long.class, database.startOfDayDaysAgo(7)));
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
                "SELECT count(*) FROM t_alert WHERE first_time >= ?", Long.class, database.startOfToday()));
        alerts.put("bySeverity", jdbc.queryForList("""
                SELECT severity, count(*) AS count
                FROM t_alert WHERE status IN (0,1) GROUP BY severity ORDER BY severity
                """));
        result.put("alerts", alerts);

        // 病毒 / 漏洞
        Map<String, Object> virus = new HashMap<>();
        virus.put("findings30d", jdbc.queryForObject(
                "SELECT count(*) FROM t_virus_finding WHERE created_at >= ?", Long.class,
                database.startOfDayDaysAgo(30)));
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
                SELECT ROUND(AVG(score), 2) AS avg_score, count(*) AS agents
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
        String bucket = database.dayBucket("first_time");
        List<Map<String, Object>> rows = jdbc.queryForList("""
                SELECT %s AS day, count(*) AS count,
                       SUM(CASE WHEN status = 2 THEN 1 ELSE 0 END) AS handled
                FROM t_alert WHERE first_time >= ?
                GROUP BY %s ORDER BY day
                """.formatted(bucket, bucket), database.startOfDayDaysAgo(days - 1));
        return fillTrend(days, rows, "count", "handled");
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
        String bucket = database.dayBucket("first_time");
        List<Map<String, Object>> rows = jdbc.queryForList("""
                SELECT %s AS day,
                       SUM(CASE WHEN event_type = 'virus' THEN 1 ELSE 0 END) AS virus,
                       SUM(CASE WHEN action_taken IS NOT NULL AND action_taken <> '' THEN 1 ELSE 0 END) AS blocked
                FROM t_alert WHERE first_time >= ?
                GROUP BY %s ORDER BY day
                """.formatted(bucket, bucket), database.startOfDayDaysAgo(days - 1));
        return fillTrend(days, rows, "virus", "blocked");
    }

    /** 大屏雷达：最近一次基线任务的等保维度通过率（category -> 0~100） */
    public List<Map<String, Object>> baselineCategories() {
        return jdbc.queryForList("""
                SELECT i.category,
                       round(100.0 * sum(CASE WHEN r.passed THEN 1 ELSE 0 END) / count(*)) AS pass_rate
                FROM t_baseline_result r
                JOIN v_baseline_result_definition i ON i.result_id = r.id
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

    private List<Map<String, Object>> fillTrend(int days, List<Map<String, Object>> rows,
                                                String firstMetric, String secondMetric) {
        Map<String, Map<String, Object>> byDay = new HashMap<>();
        for (Map<String, Object> row : rows) {
            byDay.put(String.valueOf(row.get("day")), row);
        }
        LocalDate today = LocalDate.now(ZoneId.of("Asia/Shanghai"));
        List<Map<String, Object>> result = new java.util.ArrayList<>(days);
        for (int offset = days - 1; offset >= 0; offset--) {
            LocalDate day = today.minusDays(offset);
            Map<String, Object> source = byDay.get(day.toString());
            Map<String, Object> point = new LinkedHashMap<>();
            point.put("date", day.format(java.time.format.DateTimeFormatter.ofPattern("MM-dd")));
            point.put(firstMetric, source == null ? 0L : number(source.get(firstMetric)));
            point.put(secondMetric, source == null ? 0L : number(source.get(secondMetric)));
            result.add(point);
        }
        return result;
    }

    private static long number(Object value) {
        return value instanceof Number number ? number.longValue() : 0L;
    }
}
