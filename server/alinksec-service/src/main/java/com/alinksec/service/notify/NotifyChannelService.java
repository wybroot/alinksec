package com.alinksec.service.notify;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.util.List;
import java.util.Map;

@Service
public class NotifyChannelService {

    private final JdbcTemplate jdbc;

    public NotifyChannelService(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public List<Map<String, Object>> list() {
        return jdbc.queryForList("""
                SELECT id, name, type, webhook_url, min_severity, enabled, created_at
                FROM t_notify_channel ORDER BY id DESC
                """);
    }

    public Map<String, Object> create(Map<String, Object> body) {
        Channel channel = validate(body);
        Long id = jdbc.queryForObject("""
                INSERT INTO t_notify_channel (name, type, webhook_url, min_severity, enabled)
                VALUES (?, 'webhook', ?, ?, ?) RETURNING id
                """, Long.class, channel.name(), channel.webhookUrl(), channel.minSeverity(), channel.enabled());
        return jdbc.queryForMap("""
                SELECT id, name, type, webhook_url, min_severity, enabled, created_at
                FROM t_notify_channel WHERE id = ?
                """, id);
    }

    public Map<String, Object> update(long id, Map<String, Object> body) {
        Channel channel = validate(body);
        int changed = jdbc.update("""
                UPDATE t_notify_channel SET name = ?, webhook_url = ?, min_severity = ?, enabled = ?
                WHERE id = ?
                """, channel.name(), channel.webhookUrl(), channel.minSeverity(), channel.enabled(), id);
        if (changed == 0) {
            throw new IllegalArgumentException("通知通道不存在");
        }
        return jdbc.queryForMap("""
                SELECT id, name, type, webhook_url, min_severity, enabled, created_at
                FROM t_notify_channel WHERE id = ?
                """, id);
    }

    public void delete(long id) {
        if (jdbc.update("DELETE FROM t_notify_channel WHERE id = ?", id) == 0) {
            throw new IllegalArgumentException("通知通道不存在");
        }
    }

    private Channel validate(Map<String, Object> body) {
        String name = string(body, "name");
        String webhookUrl = string(body, "webhookUrl");
        if (name.isBlank() || name.length() > 64) {
            throw new IllegalArgumentException("通道名称长度必须为 1 到 64 个字符");
        }
        URI uri;
        try {
            uri = URI.create(webhookUrl);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Webhook URL 格式无效");
        }
        if (!"http".equalsIgnoreCase(uri.getScheme()) && !"https".equalsIgnoreCase(uri.getScheme())
                || uri.getHost() == null || uri.getUserInfo() != null) {
            throw new IllegalArgumentException("Webhook URL 必须是无内嵌凭据的 HTTP(S) 地址");
        }
        int minSeverity = number(body.get("minSeverity"), 3);
        if (minSeverity < 1 || minSeverity > 4) {
            throw new IllegalArgumentException("最低告警级别必须在 1 到 4 之间");
        }
        Object enabledValue = body.get("enabled");
        boolean enabled = enabledValue == null || Boolean.parseBoolean(String.valueOf(enabledValue));
        return new Channel(name, webhookUrl, minSeverity, enabled);
    }

    private String string(Map<String, Object> body, String field) {
        Object value = body.get(field);
        return value == null ? "" : String.valueOf(value).trim();
    }

    private int number(Object value, int fallback) {
        if (value == null) return fallback;
        if (value instanceof Number number) return number.intValue();
        try {
            return Integer.parseInt(String.valueOf(value));
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("最低告警级别格式无效");
        }
    }

    private record Channel(String name, String webhookUrl, int minSeverity, boolean enabled) { }
}
