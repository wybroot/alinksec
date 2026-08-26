package com.alinksec.service.report;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

/**
 * 合规报表（M4）：按时间段聚合主机资产/基线合规率/漏洞分布/告警处置情况 → CSV 导出。
 * 一期 CSV（Excel 直接打开，UTF-8 BOM 防中文乱码）；PDF/定时邮件后续演进。
 */
@Service
public class ComplianceReportService {

    private final JdbcTemplate jdbc;

    public ComplianceReportService(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    /** 生成 CSV 字节（区间默认近 30 天） */
    public byte[] csv(String from, String to) {
        StringBuilder sb = new StringBuilder("\uFEFF"); // BOM
        sb.append("ALinkSec 合规报表,").append(from).append(" ~ ").append(to).append("\n\n");

        // 1. 主机资产概览
        sb.append("[主机资产]\n主机总数,在线,离线,在线率\n");
        Map<String, Object> hosts = jdbc.queryForMap("""
                SELECT count(*) AS total,
                       count(*) FILTER (WHERE status = 1) AS online,
                       count(*) FILTER (WHERE status = 2) AS offline
                FROM t_agent WHERE deleted = false
                """);
        long total = ((Number) hosts.get("total")).longValue();
        long online = ((Number) hosts.get("online")).longValue();
        sb.append(total).append(',').append(online).append(',').append(((Number) hosts.get("offline")).longValue())
                .append(',').append(total == 0 ? "0%" : String.format("%.1f%%", online * 100.0 / total)).append('\n');

        // 2. 基线核查合规率（每主机最近一轮汇总）
        sb.append("\n[基线核查（每主机最近一轮）]\n主机,任务,检查项,通过,不通过,得分\n");
        List<Map<String, Object>> baselines = jdbc.queryForList("""
                SELECT DISTINCT ON (s.agent_id) a.hostname, t.name AS task_name,
                       s.total, s.passed_count, s.score
                FROM t_baseline_summary s
                JOIN t_agent a ON a.agent_id = s.agent_id
                JOIN t_baseline_task t ON t.id = s.task_id
                ORDER BY s.agent_id, s.checked_at DESC
                """);
        for (Map<String, Object> r : baselines) {
            sb.append(r.get("hostname")).append(',').append(r.get("task_name"))
                    .append(',').append(r.get("total")).append(',').append(r.get("passed_count"))
                    .append(',').append(r.get("failed_count")).append(',').append(r.get("score")).append('\n');
        }

        // 3. 漏洞分布（t_vuln_finding）
        sb.append("\n[漏洞分布（区间内）]\n等级,数量\n");
        List<Map<String, Object>> vulns = jdbc.queryForList("""
                SELECT severity, count(*) AS c FROM t_vuln_finding
                WHERE created_at BETWEEN ?::timestamptz AND ?::timestamptz
                GROUP BY severity ORDER BY severity DESC
                """, from, to);
        for (Map<String, Object> r : vulns) {
            sb.append(sevName(((Number) r.get("severity")).intValue())).append(',')
                    .append(((Number) r.get("c")).longValue()).append('\n');
        }

        // 4. 告警处置
        sb.append("\n[告警处置（区间内）]\n级别,新增,已处置,处置率\n");
        List<Map<String, Object>> alerts = jdbc.queryForList("""
                SELECT severity, count(*) AS c,
                       count(*) FILTER (WHERE status = 2) AS done
                FROM t_alert WHERE first_time BETWEEN ?::timestamptz AND ?::timestamptz
                GROUP BY severity ORDER BY severity DESC
                """, from, to);
        for (Map<String, Object> r : alerts) {
            long c = ((Number) r.get("c")).longValue();
            long done = ((Number) r.get("done")).longValue();
            sb.append(sevName(((Number) r.get("severity")).intValue())).append(',').append(c)
                    .append(',').append(done).append(',')
                    .append(c == 0 ? "0%" : String.format("%.1f%%", done * 100.0 / c)).append('\n');
        }
        return sb.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }

    private static String sevName(int s) {
        return switch (s) {
            case 4 -> "严重";
            case 3 -> "高危";
            case 2 -> "中危";
            default -> "低危";
        };
    }
}
