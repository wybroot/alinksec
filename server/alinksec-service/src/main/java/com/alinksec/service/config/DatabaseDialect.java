package com.alinksec.service.config;

import org.springframework.stereotype.Component;

import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/** Small, explicit boundary for the SQL fragments and values that cannot be portable. */
@Component
public class DatabaseDialect {

    private static final ZoneId PLATFORM_ZONE = ZoneId.of("Asia/Shanghai");
    private static final DateTimeFormatter SQLITE_TIME =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS").withZone(ZoneOffset.UTC);

    private final boolean sqlite;

    public DatabaseDialect(AlinkSecProperties properties) {
        this.sqlite = "sqlite".equalsIgnoreCase(properties.getDatabase().getType());
    }

    public boolean isSqlite() {
        return sqlite;
    }

    public static boolean readBoolean(Object value) {
        return Boolean.TRUE.equals(value) || value instanceof Number number && number.intValue() != 0;
    }

    public String jsonTextValue(String column, String key) {
        if (!column.matches("[A-Za-z0-9_.]+") || !key.matches("[A-Za-z0-9_]+")) {
            throw new IllegalArgumentException("Unsafe JSON SQL identifier");
        }
        return sqlite
                ? "json_extract(" + column + ", '$." + key + "')"
                : column + "->>'" + key + "'";
    }

    public String dayBucket(String column) {
        if (!column.matches("[A-Za-z0-9_.]+")) {
            throw new IllegalArgumentException("Unsafe date SQL identifier");
        }
        return sqlite
                ? "strftime('%Y-%m-%d', " + column + ", '+8 hours')"
                : "to_char(" + column + ", 'YYYY-MM-DD')";
    }

    public Object timestamp(Instant instant) {
        return sqlite ? SQLITE_TIME.format(instant) : Timestamp.from(instant);
    }

    public Object timestampAfter(Duration duration) {
        return timestamp(Instant.now().plus(duration));
    }

    public Object timestampBefore(Duration duration) {
        return timestamp(Instant.now().minus(duration));
    }

    public Object startOfToday() {
        return timestamp(LocalDate.now(PLATFORM_ZONE).atStartOfDay(PLATFORM_ZONE).toInstant());
    }

    public Object startOfDayDaysAgo(int daysAgo) {
        return timestamp(LocalDate.now(PLATFORM_ZONE).minusDays(daysAgo)
                .atStartOfDay(PLATFORM_ZONE).toInstant());
    }

    public Object timestamp(OffsetDateTime value) {
        return value == null ? null : timestamp(value.toInstant());
    }

    public OffsetDateTime readOffsetDateTime(Object value) {
        if (value == null) {
            return null;
        }
        if (value instanceof OffsetDateTime offsetDateTime) {
            return offsetDateTime;
        }
        if (value instanceof Timestamp timestamp) {
            return timestamp.toInstant().atZone(PLATFORM_ZONE).toOffsetDateTime();
        }
        String text = String.valueOf(value).trim();
        try {
            return OffsetDateTime.parse(text);
        } catch (RuntimeException ignored) {
            LocalDateTime local = LocalDateTime.parse(text, DateTimeFormatter.ofPattern(
                    text.contains(".") ? "yyyy-MM-dd HH:mm:ss.SSS" : "yyyy-MM-dd HH:mm:ss",
                    Locale.ROOT));
            return local.atOffset(ZoneOffset.UTC).atZoneSameInstant(PLATFORM_ZONE).toOffsetDateTime();
        }
    }

    /** t_baseline_task.template_ids is BIGINT[] in PostgreSQL and JSON text in SQLite. */
    public String encodeLongList(List<Long> values) {
        String joined = String.join(",", values.stream().map(String::valueOf).toList());
        return sqlite ? "[" + joined + "]" : "{" + joined + "}";
    }

    public static String placeholders(int size) {
        if (size < 1) {
            throw new IllegalArgumentException("At least one SQL placeholder is required");
        }
        return String.join(",", Collections.nCopies(size, "?"));
    }
}
