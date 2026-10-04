package com.alinksec.service.library;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import java.time.Instant;
import java.util.Map;

/** Console overrides contain scheduling only; endpoints and credentials remain deployment settings. */
@Service
public class LibrarySchedule {
    public static final long MAX_INTERVAL_MS = 7L * 24 * 60 * 60 * 1000;
    private final LibraryProperties props;
    private final JdbcTemplate jdbc;
    public LibrarySchedule(LibraryProperties props, JdbcTemplate jdbc) {
        this.props = props; this.jdbc = jdbc;
    }
    public record Plan(boolean enabled, long intervalMs, boolean overridden) {}
    public LibraryProperties.Source source(String id) {
        return props.getSources().stream().filter(s -> s.getId().equals(id)).findFirst()
                .orElseThrow(() -> new IllegalArgumentException("数据源不存在"));
    }
    public static long minimumInterval(String type) { return "nvd".equals(type) ? 7_200_000 : 300_000; }
    public static void validateInterval(String type, long interval) {
        if (interval < minimumInterval(type) || interval > MAX_INTERVAL_MS)
            throw new IllegalArgumentException("同步间隔须在 5 分钟至 7 天内，NVD 最少两小时");
    }
    public Plan effective(LibraryProperties.Source source) {
        var overrides = jdbc.queryForList("SELECT enabled,interval_ms FROM t_security_feed_schedule WHERE source_id=?", source.getId());
        if (overrides.isEmpty()) return new Plan(source.isEnabled(), source.getIntervalMs(), false);
        var row = overrides.get(0);
        long interval = ((Number) row.get("interval_ms")).longValue();
        // A changed deployment type must never inherit an interval below its provider limit.
        interval = Math.max(minimumInterval(source.getType()), Math.min(MAX_INTERVAL_MS, interval));
        return new Plan(((Number) row.get("enabled")).intValue() == 1, interval, true);
    }
    public Plan update(String id, Boolean enabled, Long intervalMs) {
        var source = source(id);
        if (enabled == null || intervalMs == null) throw new IllegalArgumentException("须指定启停状态和同步间隔");
        validateInterval(source.getType(), intervalMs);
        if (enabled && !configurationIssue(source).isEmpty()) throw new IllegalArgumentException(configurationIssue(source));
        jdbc.update("""
                INSERT INTO t_security_feed_schedule(source_id,enabled,interval_ms,updated_at) VALUES (?,?,?,?)
                ON CONFLICT(source_id) DO UPDATE SET enabled=EXCLUDED.enabled,interval_ms=EXCLUDED.interval_ms,updated_at=EXCLUDED.updated_at
                """, id, enabled ? 1 : 0, intervalMs, Instant.now().toString());
        return effective(source);
    }
    public Plan reset(String id) {
        var source = source(id);
        jdbc.update("DELETE FROM t_security_feed_schedule WHERE source_id=?", id);
        return effective(source);
    }
    public static String configurationIssue(LibraryProperties.Source source) {
        if (("misp".equals(source.getType()) || "malwarebazaar".equals(source.getType())) && source.getApiKey().isBlank())
            return "请在部署配置中设置该平台的只读认证密钥";
        if ("misp".equals(source.getType()) && !source.getMispTag().matches("[A-Za-z0-9][A-Za-z0-9:._=-]{0,127}"))
            return "请在部署配置中设置明确的 MISP 审核标签";
        if (source.getUrl().isBlank()) {
            return java.util.Set.of("nvd", "malwarebazaar").contains(source.getType()) ? "" : "请在部署配置中设置数据源地址";
        }
        try { FeedDownload.validateAddress(source.getUrl()); }
        catch (IllegalArgumentException e) { return "请在部署配置中设置有效的 HTTPS 数据源地址"; }
        return "";
    }
    public static long delay(Plan plan, int failures) {
        long maximum = Math.max(plan.intervalMs(), 86_400_000L);
        return Math.min(maximum, plan.intervalMs() * (1L << Math.min(5, Math.max(0, failures - 1))));
    }
    public static Instant nextCheck(Plan plan, Map<String, Object> state) {
        Object checked = state.get("checked_at");
        int failures = state.get("failure_count") instanceof Number count ? count.intValue() : 0;
        return checked == null ? Instant.EPOCH : Instant.parse(checked.toString()).plusMillis(delay(plan, failures));
    }
}
