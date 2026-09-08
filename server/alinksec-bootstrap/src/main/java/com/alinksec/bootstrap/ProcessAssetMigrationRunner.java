package com.alinksec.bootstrap;
import org.springframework.boot.CommandLineRunner;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
@Component
public class ProcessAssetMigrationRunner implements CommandLineRunner {
    private final JdbcTemplate jdbc;
    public ProcessAssetMigrationRunner(JdbcTemplate jdbc) { this.jdbc = jdbc; }
    @Override public void run(String... args) {
        jdbc.execute("CREATE TABLE IF NOT EXISTS t_asset_process (id BIGSERIAL PRIMARY KEY, agent_id VARCHAR(64) NOT NULL, pid INTEGER NOT NULL, name VARCHAR(255), exe TEXT, cmdline TEXT, username VARCHAR(255), rss_bytes BIGINT NOT NULL DEFAULT 0, updated_at TIMESTAMPTZ NOT NULL DEFAULT now(), UNIQUE(agent_id, pid))");
        jdbc.execute("CREATE INDEX IF NOT EXISTS idx_process_agent_rss ON t_asset_process(agent_id, rss_bytes DESC)");
    }
}
