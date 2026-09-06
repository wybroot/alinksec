package com.alinksec.bootstrap;

import com.alinksec.service.enroll.EnrollTokenService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * 开发期种子：
 * 在显式提供的环境变量满足条件时创建初始管理员和注册码；敏感值不写入日志。
 */
@Component
public class DevSeedRunner implements CommandLineRunner {

    private static final Logger log = LoggerFactory.getLogger(DevSeedRunner.class);

    private final EnrollTokenService enrollTokenService;
    private final JdbcTemplate jdbc;

    @Value("${ALINKSEC_BOOTSTRAP_ADMIN_PASSWORD:}")
    private String bootstrapAdminPassword;

    @Value("${ALINKSEC_BOOTSTRAP_ENROLL_TOKEN:}")
    private String bootstrapEnrollToken;

    public DevSeedRunner(EnrollTokenService enrollTokenService, JdbcTemplate jdbc) {
        this.enrollTokenService = enrollTokenService;
        this.jdbc = jdbc;
    }

    @Override
    public void run(String... args) {
        seedAdmin();
        seedEnrollToken();
    }

    private void seedAdmin() {
        Integer count = jdbc.queryForObject("SELECT count(*) FROM t_user", Integer.class);
        if (count != null && count > 0) {
            return;
        }
        if (bootstrapAdminPassword == null || bootstrapAdminPassword.length() < 12) {
            log.warn("No bootstrap administrator created: set ALINKSEC_BOOTSTRAP_ADMIN_PASSWORD to at least 12 characters");
            return;
        }
        String hash = new BCryptPasswordEncoder().encode(bootstrapAdminPassword);
        jdbc.update("""
                INSERT INTO t_user (username, password_hash, real_name, role_id, status)
                SELECT 'admin', ?, '系统管理员', 1, 1
                WHERE EXISTS (SELECT 1 FROM t_role WHERE id = 1)
                """, hash);
        log.info("Bootstrap administrator created: admin");
    }

    private void seedEnrollToken() {
        if (enrollTokenService.anyExists()) {
            return;
        }
        if (bootstrapEnrollToken == null || bootstrapEnrollToken.isBlank()) {
            log.warn("No bootstrap enrollment token created: set ALINKSEC_BOOTSTRAP_ENROLL_TOKEN or create one after login");
            return;
        }
        jdbc.update("""
                INSERT INTO t_enroll_token (token, max_uses, expire_at, created_by, status)
                VALUES (?, 100, now() + interval '30 day', NULL, 1)
                """, bootstrapEnrollToken.trim());
        log.info("Bootstrap enrollment token created");
    }
}
