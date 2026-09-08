package com.alinksec.service.notify;

import com.alinksec.common.util.JsonUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 告警通知（M4：通知渠道）：
 * 新增高危/严重告警时向启用的 webhook 渠道推送 JSON（钉钉/企微/飞书群机器人通用格式兼容）；
 * 失败落 t_notify_channel 重试标记由定时任务兜底重发（简化：内存重试队列 + 定时扫表）。
 * 通知为尽力而为，失败不影响告警主流程。
 */
@Service
public class NotifyService {

    private static final Logger log = LoggerFactory.getLogger(NotifyService.class);

    private final JdbcTemplate jdbc;
    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(3)).build();

    public NotifyService(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    /** 新告警异步通知（severity: 2=medium 3=high 4=critical） */
    @Async
    public void onAlert(String alertNo, String agentId, String eventType,
                        int severity, String title, String actionTaken) {
        // Snapshot eligible channels before delivery. A later channel change only
        // affects future alerts, rather than unexpectedly replaying old alerts.
        jdbc.update("""
                INSERT INTO t_alert_notify_delivery (alert_no, channel_id)
                SELECT ?, id FROM t_notify_channel
                WHERE enabled = true AND type = 'webhook' AND min_severity <= ?
                  AND NOT EXISTS (
                      SELECT 1 FROM t_alert_notify_delivery WHERE alert_no = ?
                  )
                ON CONFLICT (alert_no, channel_id) DO NOTHING
                """, alertNo, severity, alertNo);

        Map<String, Object> details = new HashMap<>();
        details.put("alertNo", alertNo);
        details.put("agentId", agentId);
        details.put("eventType", eventType);
        details.put("severity", severity);
        details.put("actionTaken", actionTaken == null ? "" : actionTaken);
        String payload = JsonUtils.write(Map.of(
                "msgtype", "text",
                "text", Map.of("content", "[ALinkSec 告警] " + title),
                "alinksec", details));

        List<Map<String, Object>> channels = jdbc.queryForList("""
                SELECT d.channel_id, c.name, c.webhook_url
                FROM t_alert_notify_delivery d
                JOIN t_notify_channel c ON c.id = d.channel_id
                WHERE d.alert_no = ? AND d.delivered_at IS NULL AND c.enabled = true
                """, alertNo);
        for (Map<String, Object> ch : channels) {
            long channelId = ((Number) ch.get("channel_id")).longValue();
            String error = send((String) ch.get("webhook_url"), payload, (String) ch.get("name"));
            if (error == null) {
                jdbc.update("""
                        UPDATE t_alert_notify_delivery
                        SET attempts = attempts + 1, attempted_at = now(), delivered_at = now(), last_error = NULL
                        WHERE alert_no = ? AND channel_id = ?
                        """, alertNo, channelId);
            } else {
                jdbc.update("""
                        UPDATE t_alert_notify_delivery
                        SET attempts = attempts + 1, attempted_at = now(), last_error = ?
                        WHERE alert_no = ? AND channel_id = ?
                        """, error, alertNo, channelId);
            }
        }
        markCompleteIfDelivered(alertNo);
    }

    /** 兜底重试：每 5 分钟重发未确认的高危告警（含首次通知失败的） */
    @Scheduled(fixedDelay = 300_000, initialDelay = 300_000)
    public void retryRecent() {
        List<Map<String, Object>> missed = jdbc.queryForList("""
                SELECT alert_no, agent_id, event_type, severity, title, action_taken
                FROM t_alert WHERE severity >= 3 AND status IN (0, 1) AND notified = false
                LIMIT 20
                """);
        for (Map<String, Object> a : missed) {
            onAlert((String) a.get("alert_no"), (String) a.get("agent_id"),
                    (String) a.get("event_type"), ((Number) a.get("severity")).intValue(),
                    (String) a.get("title"), String.valueOf(a.get("action_taken")));
        }
    }

    private void markCompleteIfDelivered(String alertNo) {
        jdbc.update("""
                UPDATE t_alert SET notified = NOT EXISTS (
                    SELECT 1 FROM t_alert_notify_delivery d
                    JOIN t_notify_channel c ON c.id = d.channel_id
                    WHERE d.alert_no = ? AND c.enabled = true AND d.delivered_at IS NULL
                ) WHERE alert_no = ?
                """, alertNo, alertNo);
    }

    /** @return null when the remote endpoint accepted the delivery. */
    private String send(String url, String payload, String name) {
        try {
            HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                    .timeout(Duration.ofSeconds(5))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(payload))
                    .build();
            HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() / 100 != 2) {
                log.warn("通知发送非 2xx: channel={} status={}", name, resp.statusCode());
                return "HTTP " + resp.statusCode();
            }
            return null;
        } catch (Exception e) {
            log.warn("通知发送失败（不阻塞主流程）: channel={} err={}", name, e.getMessage());
            return e.getClass().getSimpleName() + ": " + String.valueOf(e.getMessage());
        }
    }
}
