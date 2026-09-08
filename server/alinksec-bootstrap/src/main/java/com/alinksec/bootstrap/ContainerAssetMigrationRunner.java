package com.alinksec.bootstrap;

import org.springframework.boot.CommandLineRunner;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

@Component
public class ContainerAssetMigrationRunner implements CommandLineRunner {
    private final JdbcTemplate jdbc;

    public ContainerAssetMigrationRunner(JdbcTemplate jdbc) { this.jdbc = jdbc; }

    @Override
    public void run(String... args) {
        jdbc.execute("""
                CREATE TABLE IF NOT EXISTS t_asset_container (
                  id BIGSERIAL PRIMARY KEY, agent_id VARCHAR(64) NOT NULL, container_id VARCHAR(128) NOT NULL,
                  name VARCHAR(255), image VARCHAR(512), image_id VARCHAR(128), status VARCHAR(255),
                  created_at TIMESTAMPTZ, started_at TIMESTAMPTZ, ports JSONB NOT NULL DEFAULT '[]',
                  labels JSONB NOT NULL DEFAULT '{}', updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                  UNIQUE(agent_id, container_id))
                """);
        jdbc.execute("CREATE INDEX IF NOT EXISTS idx_container_agent ON t_asset_container(agent_id)");
    }
}
