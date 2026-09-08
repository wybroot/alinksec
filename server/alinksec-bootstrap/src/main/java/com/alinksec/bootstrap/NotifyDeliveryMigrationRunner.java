package com.alinksec.bootstrap;

import org.springframework.boot.CommandLineRunner;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

/** Creates the M5 delivery table for deployments whose PostgreSQL volume predates this release. */
@Component
public class NotifyDeliveryMigrationRunner implements CommandLineRunner {

    private final JdbcTemplate jdbc;

    public NotifyDeliveryMigrationRunner(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @Override
    public void run(String... args) {
        jdbc.execute("""
                CREATE TABLE IF NOT EXISTS t_alert_notify_delivery (
                    id BIGSERIAL PRIMARY KEY,
                    alert_no VARCHAR(64) NOT NULL,
                    channel_id BIGINT NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    attempted_at TIMESTAMPTZ,
                    delivered_at TIMESTAMPTZ,
                    last_error TEXT,
                    UNIQUE (alert_no, channel_id)
                )
                """);
        jdbc.execute("""
                CREATE INDEX IF NOT EXISTS idx_alert_notify_pending
                ON t_alert_notify_delivery (delivered_at, attempted_at)
                """);
    }
}
