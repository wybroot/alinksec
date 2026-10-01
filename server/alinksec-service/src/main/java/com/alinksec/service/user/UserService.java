package com.alinksec.service.user;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * 管理端用户（t_user / t_role）：登录校验 + 登录审计。
 * 初始账号由 bootstrap DevSeedRunner 根据环境变量创建。
 */
@Service
public class UserService {

    private final JdbcTemplate jdbc;
    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

    public UserService(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    /** 账号不存在与密码错误统一返回 empty，避免用户名枚举 */
    public Optional<UserProfile> login(String username, String rawPassword, String sourceIp) {
        List<Map<String, Object>> rows = jdbc.queryForList("""
                SELECT u.id, u.username, u.real_name, u.password_hash, u.status,
                       u.role_id, r.name AS role_name, CAST(r.permissions AS TEXT) AS permissions
                FROM t_user u JOIN t_role r ON r.id = u.role_id
                WHERE u.username = ?
                """, username);
        if (rows.isEmpty()) {
            audit(null, username, "login_failed", sourceIp);
            return Optional.empty();
        }
        var row = rows.get(0);
        boolean ok = encoder.matches(rawPassword, (String) row.get("password_hash"));
        boolean enabled = ((Number) row.get("status")).intValue() == 1;
        if (!ok || !enabled) {
            audit(((Number) row.get("id")).longValue(), username, "login_failed", sourceIp);
            return Optional.empty();
        }
        long uid = ((Number) row.get("id")).longValue();
        jdbc.update("UPDATE t_user SET last_login_at = CURRENT_TIMESTAMP, last_login_ip = ? WHERE id = ?", sourceIp, uid);
        audit(uid, username, "login", sourceIp);
        return Optional.of(new UserProfile(
                uid, username, (String) row.get("real_name"), (String) row.get("role_name"),
                (String) row.get("permissions")));
    }

    public void audit(Long userId, String username, String action, String sourceIp) {
        try {
            jdbc.update("""
                    INSERT INTO t_audit_log (uid, username, method, path, source_ip, status, cost_ms)
                    VALUES (?, ?, ?, '/api/auth/login', ?, ?, 0)
                    """, userId, username, action, sourceIp,
                    "login_failed".equals(action) ? 401 : 200);
        } catch (Exception ignored) {
            // 审计失败不阻断登录主链路
        }
    }

    public record UserProfile(long id, String username, String realName, String roleName, String permissionsJson) {}
}
