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
        StringBuilder where = new StringBuilder(" WHERE 1=1");
        if (status != null) {
            where.append(" AND t.status = ").append(status);
        } else {
            where.append(" AND t.status <> 9"); // 默认排除已删除（如有）
        }
        if (severity != null) {
            where.append(" AND t.severity >= ").append(severity);
        }
        if (agentId != null && !agentId.isBlank()) {
            where.append(" AND t.agent_id = '").append(agentId.replace("'", "''")).append("'");
        }
        if (eventType != null && !eventType.isBlank()) {
            where.append(" AND t.event_type = '").append(eventType.replace("'", "''")).append("'");
        }
        String cond = where.toString();

        Long total = jdbc.queryForObject(
                "SELECT count(*) FROM t_alert t" + cond, Long.class);
        List<Map<String, Object>> list = jdbc.queryForList("""
                SELECT t.id, t.alert_no, t.agent_id, a.hostname, t.event_type, t.severity, t.title,
                       CAST(t.detail AS TEXT) AS detail, t.action_taken, t.status, t.count,
                       t.first_time, t.last_time, t.handle_remark, t.handled_at
                FROM t_alert t LEFT JOIN t_agent a ON a.agent_id = t.agent_id""" + cond
                + " ORDER BY t.last_time DESC LIMIT ? OFFSET ?", size, (page - 1) * size);

        Map<String, Object> result = new HashMap<>();
        result.put("list", list);
        result.put("total", total == null ? 0 : total);
        return result;
    }

    public List<Map<String, Object>> severityDistribution() {
        return jdbc.queryForList("""
                SELECT severity, count(*) AS count
                FROM t_alert WHERE status IN (0,1)
                GROUP BY severity ORDER BY severity
                """);
    }

    /** 处置告警：status 2=已处理 */
    public boolean handle(long id, long userId, String remark) {
        return jdbc.update("""
                UPDATE t_alert
                SET status = 2, handle_remark = ?, handled_by = ?, handled_at = CURRENT_TIMESTAMP
                WHERE id = ? AND status IN (0,1)
                """, remark, userId, id) > 0;
    }
}
