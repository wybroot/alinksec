package com.alinksec.service.query;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 告警中心查询与处置。
 */
@Service
public class AlertQueryService {

    private final JdbcTemplate jdbc;

    public AlertQueryService(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public Map<String, Object> list(Integer status, Integer severity, String agentId,
                                    String eventType, int page, int size) {
        return list(status, severity, agentId, eventType, page, size, false);
    }

    public Map<String, Object> list(Integer status, Integer severity, String agentId,
                                    String eventType, int page, int size, boolean exactSeverity) {
        page = Math.max(1, page);
        size = Math.max(1, Math.min(size, 100));
        StringBuilder where = new StringBuilder(" WHERE 1=1");
        if (status != null && status == -1) {
            where.append(" AND t.status IN (0,1)");
        } else if (status != null) {
            where.append(" AND t.status = ").append(status);
        } else {
            where.append(" AND t.status <> 9"); // 默认排除已删除（如有）
        }
        if (severity != null) {
            where.append(exactSeverity ? " AND t.severity_level = " : " AND t.severity_level >= ").append(severity);
        }
        if (agentId != null && !agentId.isBlank()) {
            where.append(" AND t.agent_id = '").append(agentId.replace("'", "''")).append("'");
        }
        if (eventType != null && !eventType.isBlank()) {
            where.append(" AND t.event_type = '").append(eventType.replace("'", "''")).append("'");
        }
        String cond = where.toString();

        Long total = jdbc.queryForObject(
                "SELECT count(*) FROM v_alert_severity t" + cond, Long.class);
        List<Map<String, Object>> list = jdbc.queryForList("""
                SELECT t.id, t.alert_no, t.agent_id, a.hostname, a.ip AS host_ip, t.event_type, t.severity, t.severity_source, t.severity_level, t.title,
                       CAST(t.detail AS TEXT) AS detail, t.action_taken, t.status, t.count,
                       t.first_time, t.last_time, t.handle_remark, t.handled_at
                FROM v_alert_severity t LEFT JOIN t_agent a ON a.agent_id = t.agent_id""" + cond
                + " ORDER BY t.last_time DESC, t.id DESC LIMIT ? OFFSET ?", size, (page - 1) * size);

        Map<String, Object> result = new HashMap<>();
        result.put("list", list);
        result.put("total", total == null ? 0 : total);
        return result;
    }

    public List<Map<String, Object>> severityDistribution() {
        return jdbc.queryForList("""
                SELECT severity_level AS severity, count(*) AS count,
                       SUM(CASE WHEN severity_source='legacy_unclassified' THEN 1 ELSE 0 END) AS legacy_count
                FROM v_alert_severity WHERE status IN (0,1)
                GROUP BY severity_level ORDER BY severity_level
                """);
    }

    /** 关闭告警记录，不执行主机安全动作。2=已确认，3=已忽略。 */
    public boolean handle(long id, long userId, String remark) {
        return close(id, userId, remark, "acknowledge");
    }

    public boolean close(long id, long userId, String remark, String resolution) {
        if (!"acknowledge".equals(resolution) && !"ignore".equals(resolution)) {
            throw new IllegalArgumentException("不支持的告警记录操作");
        }
        boolean updated = jdbc.update("""
                UPDATE t_alert
                SET status = ?, handle_remark = ?, handled_by = ?, handled_at = CURRENT_TIMESTAMP
                WHERE id = ? AND status IN (0,1)
                """, "ignore".equals(resolution) ? 3 : 2, remark, userId, id) > 0;
        if (updated) {
            jdbc.update("""
                    UPDATE t_alert_notify_delivery
                    SET last_error = 'alert_closed_before_delivery', lease_until = 0, next_attempt_at = 9999999999999
                    WHERE alert_no = (SELECT alert_no FROM t_alert WHERE id = ?) AND delivered_at IS NULL
                    """, id);
        }
        return updated;
    }
}
