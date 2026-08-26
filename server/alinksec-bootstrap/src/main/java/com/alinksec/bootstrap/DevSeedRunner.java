package com.alinksec.bootstrap;

import com.alinksec.service.enroll.EnrollTokenService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * 开发期种子：
 * 1) 无有效注册码时生成一个（30 天 / 100 次），打印到日志供 Agent 安装使用；
 * 2) 无管理账号时创建 admin / admin@123（首次登录后请修改）。
 */
@Component
public class DevSeedRunner implements CommandLineRunner {

    private static final Logger log = LoggerFactory.getLogger(DevSeedRunner.class);

    private final EnrollTokenService enrollTokenService;
    private final JdbcTemplate jdbc;

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
        String hash = new BCryptPasswordEncoder().encode("admin@123");
        jdbc.update("""
                INSERT INTO t_user (username, password_hash, real_name, role_id, status)
                SELECT 'admin', ?, '系统管理员', 1, 1
                WHERE EXISTS (SELECT 1 FROM t_role WHERE id = 1)
                """, hash);
        log.info("==================================================");
        log.info("已创建默认管理员: admin / admin@123（首次登录后请修改密码）");
        log.info("==================================================");
    }

    private void seedEnrollToken() {
        if (enrollTokenService.anyExists()) {
            return;
        }
        String token = enrollTokenService.create(null, 100, 30);
        log.info("==================================================");
        log.info("已生成开发注册码（30 天 / 100 次）: {}", token);
        log.info("Agent 安装: alinksec-agent install --server <host:9443> --token {}", token);
        log.info("==================================================");
    }
}
