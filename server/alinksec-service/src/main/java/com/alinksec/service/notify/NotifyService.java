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
 * 数据库令牌领取防止副本并发发送，最多尝试五次；远端确认丢失可再次投递相同 Idempotency-Key。
 * 通知为尽力而为，失败不影响告警主流程。
 */
@Service
public class NotifyService {

    private static final Logger log = LoggerFactory.getLogger(NotifyService.class);

    private final JdbcTemplate jdbc;
    @org.springframework.beans.factory.annotation.Autowired
    private com.alinksec.service.cluster.ClusterProperties clusterProperties;
    private long clock() {
        return clusterProperties!=null && clusterProperties.isEnabled()
                ? com.alinksec.service.cluster.ClusterRuntime.databaseTime(jdbc) : System.currentTimeMillis();
    }
    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(3)).build();

    public NotifyService(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    /** Eligibility and payload come from the committed source-aware alert. */
    @Async
    public void onAlert(String alertNo) {
        var alerts = jdbc.queryForList("SELECT * FROM v_alert_severity WHERE alert_no=?", alertNo);
        if (alerts.isEmpty()) return;
        var alert = alerts.getFirst();
        int severity = ((Number) alert.get("severity_level")).intValue();
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
        details.put("agentId", alert.get("agent_id"));
        details.put("eventType", alert.get("event_type"));
        details.put("severity", alert.get("severity"));
        details.put("severityLevel", severity);
        details.put("severitySource", alert.get("severity_source"));
        details.put("severityLabel", com.alinksec.service.alert.AlertSeverity.label(alert));
        details.put("actionTaken", alert.get("action_taken") == null ? "" : alert.get("action_taken"));
        String payload = JsonUtils.write(Map.of(
                "msgtype", "text",
                "text", Map.of("content", "[ALinkSec 告警] " + alert.get("title")),
                "alinksec", details));

        List<Map<String, Object>> channels = jdbc.queryForList("""
                SELECT d.channel_id, c.name, c.webhook_url
                FROM t_alert_notify_delivery d
                JOIN t_notify_channel c ON c.id = d.channel_id
                WHERE d.alert_no = ? AND d.delivered_at IS NULL AND c.enabled = true
                """, alertNo);
        for (Map<String, Object> ch : channels) {
            long channelId = ((Number) ch.get("channel_id")).longValue();
            String claim=java.util.UUID.randomUUID().toString();
            long now=clock();
            if(jdbc.update("""
                    UPDATE t_alert_notify_delivery SET claim_token=?,lease_until=?,attempts=attempts+1,
                      attempted_at=CURRENT_TIMESTAMP
                    WHERE alert_no=? AND channel_id=? AND delivered_at IS NULL AND attempts<5
                      AND lease_until<=? AND next_attempt_at<=?
                    """,claim,now+30_000,alertNo,channelId,now,now)!=1)continue;
            String idempotency=java.util.UUID.nameUUIDFromBytes((alertNo+"\0"+channelId).getBytes(java.nio.charset.StandardCharsets.UTF_8)).toString();
            String error=send((String)ch.get("webhook_url"),payload,(String)ch.get("name"),idempotency);
            jdbc.update("""
                    UPDATE t_alert_notify_delivery SET delivered_at=CASE WHEN ?=1 THEN CURRENT_TIMESTAMP ELSE delivered_at END,
                      last_error=?,lease_until=0,next_attempt_at=?
                    WHERE alert_no=? AND channel_id=? AND claim_token=? AND delivered_at IS NULL
                    """,error==null?1:0,error,clock()+60_000,alertNo,channelId,claim);
        }
        markCompleteIfDelivered(alertNo);
    }

    /** 兜底重试：每 5 分钟重发未确认的高危告警（含首次通知失败的） */
    @Scheduled(fixedDelay = 300_000, initialDelay = 300_000)
    public void retryRecent() {
        List<Map<String, Object>> missed = jdbc.queryForList("""
                SELECT alert_no
                FROM v_alert_severity a WHERE severity_level >= 1 AND status IN (0, 1) AND notified = false
                  AND (NOT EXISTS(SELECT 1 FROM t_alert_notify_delivery d WHERE d.alert_no=a.alert_no)
                    OR EXISTS(SELECT 1 FROM t_alert_notify_delivery d JOIN t_notify_channel c ON c.id=d.channel_id
                      WHERE d.alert_no=a.alert_no AND d.delivered_at IS NULL AND d.attempts<5 AND c.enabled=true))
                ORDER BY first_time LIMIT 20
                """);
        for (Map<String, Object> a : missed) {
            onAlert((String) a.get("alert_no"));
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
    private String send(String url, String payload, String name,String idempotency) {
        try {
            HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                    .timeout(Duration.ofSeconds(5))
                    .header("Content-Type", "application/json")
                    .header("Idempotency-Key",idempotency)
                    .POST(HttpRequest.BodyPublishers.ofString(payload))
                    .build();
            HttpResponse<Void> resp = http.send(req, HttpResponse.BodyHandlers.discarding());
            if (resp.statusCode() / 100 != 2) {
                log.warn("通知发送非 2xx: channel={} status={}", name, resp.statusCode());
                return "HTTP " + resp.statusCode();
            }
            return null;
        } catch (Exception e) {
            if(e instanceof InterruptedException)Thread.currentThread().interrupt();
            log.warn("通知发送失败: channel={} type={}", name, e.getClass().getSimpleName());
            return e instanceof java.net.http.HttpTimeoutException ? "webhook_timeout" : "webhook_unavailable";
        }
    }
}
