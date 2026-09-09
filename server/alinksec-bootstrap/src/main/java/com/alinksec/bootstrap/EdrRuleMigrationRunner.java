package com.alinksec.bootstrap;

import org.springframework.boot.CommandLineRunner;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import com.alinksec.service.protect.PolicyStoreService;

/** Seeds the built-in EDR process rule for PostgreSQL volumes created before EDR. */
@Component
public class EdrRuleMigrationRunner implements CommandLineRunner {
    private final JdbcTemplate jdbc;
    private final PolicyStoreService policyStore;

    public EdrRuleMigrationRunner(JdbcTemplate jdbc, PolicyStoreService policyStore) {
        this.jdbc = jdbc;
        this.policyStore = policyStore;
    }

    @Override
    public void run(String... args) {
        int inserted = jdbc.update("""
                INSERT INTO t_protect_rule (rule_id, name, type, match, actions, severity, enabled, built_in)
                VALUES ('PR-0001', 'EDR miner process block', 'process',
                        ?::jsonb, ?::jsonb, 4, TRUE, TRUE)
                ON CONFLICT (rule_id) DO NOTHING
                """, "{\"exe_regex\":\"(?i)(^|/)(xmrig|minerd|kdevtmpfsi|kinsing)$\"}", "[\"kill\",\"alert\"]");
        if (inserted > 0) {
            policyStore.rebuild();
        }
    }
}
