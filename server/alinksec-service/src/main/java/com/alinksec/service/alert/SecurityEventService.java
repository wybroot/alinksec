package com.alinksec.service.alert;

import com.alinksec.common.util.JsonUtils;
import com.alinksec.proto.RptSecurityEvent;
import com.alinksec.service.notify.NotifyService;
import com.alinksec.service.config.DatabaseDialect;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

/**
 * 安全事件入库与告警聚合（数据库设计 §2.5）：
 * 同源事件（agent+rule+fingerprint）5min 窗口内累加 count，不重复建告警。
 * fingerprint = type + detail 关键字段摘要。EDR 进程事件使用 PID + 创建时间，
 * 避免同一规则命中不同进程实例时错误合并。
 * 新告警触发 webhook 通知（M4，尽力而为不阻塞主流程）。
 */
@Service
public class SecurityEventService {

    private static final Logger log = LoggerFactory.getLogger(SecurityEventService.class);

    private final JdbcTemplate jdbc;
    private final NotifyService notifyService;
    private final DatabaseDialect database;

    public SecurityEventService(JdbcTemplate jdbc, NotifyService notifyService, DatabaseDialect database) {
        this.jdbc = jdbc;
        this.notifyService = notifyService;
        this.database = database;
    }

    public void onEvent(String agentId, RptSecurityEvent event) {
        String detailJson = event.getDetail().isBlank() ? "{}" : event.getDetail();
        String fingerprint = fingerprint(event, detailJson);

        // 聚合：未关闭的同源告警 count+1（uq_alert_dedup 兜底并发重复）
        String mergeSql = """
                UPDATE t_alert
                SET count = count + 1, last_time = CURRENT_TIMESTAMP,
                    detail = ?
                WHERE agent_id = ? AND rule_id = ?
                  AND (%s) = ?
                  AND status IN (0, 1)
                """.formatted(database.jsonTextValue("detail", "fingerprint"));
        int merged = jdbc.update(mergeSql, detailJson, agentId, event.getRuleId(), fingerprint);
        if (merged > 0) {
            log.debug("告警聚合: agent={} rule={} type={}", agentId, event.getRuleId(), event.getType());
            return;
        }

        String alertNo = "ALT-" + System.currentTimeMillis() + "-"
                + Integer.toHexString(fingerprint.hashCode() & 0xffffff);
        jdbc.update("""
                INSERT INTO t_alert (alert_no, agent_id, rule_id, event_type, severity, title, detail, action_taken)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT DO NOTHING
                """,
                alertNo, agentId, event.getRuleId(), event.getType(),
                event.getSeverity().getNumber(),
                buildTitle(event), withFingerprint(detailJson, fingerprint),
                event.getActionTaken());
        log.info("新告警: agent={} type={} severity={} rule={}",
                agentId, event.getType(), event.getSeverity(), event.getRuleId());
        notifyService.onAlert(alertNo, agentId, event.getType(),
                event.getSeverity().getNumber(), buildTitle(event), event.getActionTaken());
    }

    private String buildTitle(RptSecurityEvent e) {
        String type = switch (e.getType()) {
            case "process" -> "可疑进程";
            case "file_tamper" -> "文件篡改";
            case "login_crack" -> "登录暴力破解";
            case "self_defense" -> "Agent 自保护触发";
            case "virus" -> "恶意文件检出";
            case "decoy_tamper" -> "勒索诱饵被触碰";
            case "ransom_behavior" -> "勒索加密行为";
            default -> "安全事件";
        };
        return "[" + type + "] " + (e.getRuleName().isBlank() ? e.getRuleId() : e.getRuleName());
    }

    private String fingerprint(RptSecurityEvent event, String detailJson) {
        String base = event.getType() + ":" + event.getRuleId();
        if (!"process".equals(event.getType())) {
            return base;
        }
        try {
            String processKey = JsonUtils.read(detailJson).path("process_key").asText();
            return processKey.isBlank() ? base : base + ":" + processKey;
        } catch (IllegalArgumentException e) {
            return base;
        }
    }

    private String withFingerprint(String detailJson, String fingerprint) {
        var node = JsonUtils.read(detailJson);
        if (!node.isObject()) {
            return JsonUtils.write(java.util.Map.of("fingerprint", fingerprint, "raw", detailJson));
        }
        var obj = (com.fasterxml.jackson.databind.node.ObjectNode) node;
        obj.put("fingerprint", fingerprint);
        return obj.toString();
    }

}
