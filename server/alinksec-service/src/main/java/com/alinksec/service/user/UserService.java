package com.alinksec.service.user;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * 管理端用户（t_user / t_role）：登录校验 + 用户生命周期治理 + 会话撤销与安全恢复 (G10/R16)。
 */
@Service
public class UserService {

    private final JdbcTemplate jdbc;
    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
    private final TokenRevocationService tokenRevocationService;

    public UserService(JdbcTemplate jdbc) {
        this(jdbc, null);
    }

    @Autowired
    public UserService(JdbcTemplate jdbc, @Autowired(required = false) TokenRevocationService tokenRevocationService) {
        this.jdbc = jdbc;
        this.tokenRevocationService = tokenRevocationService;
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
        audit(userId, username, action, "/api/auth/login", sourceIp);
    }

    public void audit(Long userId, String username, String action, String path, String sourceIp) {
        try {
            jdbc.update("""
                    INSERT INTO t_audit_log (uid, username, method, path, source_ip, status, cost_ms)
                    VALUES (?, ?, ?, ?, ?, ?, 0)
                    """, userId, username, action, path, sourceIp,
                    "login_failed".equals(action) ? 401 : 200);
        } catch (Exception ignored) {
            // 审计失败不阻断主链路
        }
    }

    /** G10: 用户列表查询（脱敏去除 password_hash） */
    public List<Map<String, Object>> listUsers() {
        return jdbc.queryForList("""
                SELECT u.id, u.username, u.real_name, u.role_id, r.name AS role_name,
                       u.status, u.last_login_at, u.last_login_ip, u.created_at
                FROM t_user u JOIN t_role r ON r.id = u.role_id
                ORDER BY u.id ASC
                """);
    }

    /** G10: 角色列表查询 */
    public List<Map<String, Object>> listRoles() {
        return jdbc.queryForList("SELECT id, name, permissions, created_at FROM t_role ORDER BY id ASC");
    }

    /** G10: 创建新用户 */
    public Map<String, Object> createUser(String username, String rawPassword, String realName, String roleName, Long operatorUid) {
        if (username == null || !username.matches("^[a-zA-Z0-9_-]{3,32}$")) {
            throw new IllegalArgumentException("用户名需由 3-32 位字母、数字、下划线或连字符组成");
        }
        if (rawPassword == null || rawPassword.length() < 8) {
            throw new IllegalArgumentException("密码长度不能少于 8 位");
        }
        Integer count = jdbc.queryForObject("SELECT count(*) FROM t_user WHERE username = ?", Integer.class, username);
        if (count != null && count > 0) {
            throw new IllegalArgumentException("用户名已存在: " + username);
        }
        List<Map<String, Object>> roles = jdbc.queryForList("SELECT id FROM t_role WHERE name = ?", roleName);
        if (roles.isEmpty()) {
            throw new IllegalArgumentException("指定角色不存在: " + roleName);
        }
        long roleId = ((Number) roles.get(0).get("id")).longValue();
        String hash = encoder.encode(rawPassword);
        jdbc.update("INSERT INTO t_user (username, password_hash, real_name, role_id, status) VALUES (?, ?, ?, ?, 1)",
                username, hash, realName != null && !realName.isBlank() ? realName : username, roleId);
        audit(operatorUid, username, "create_user", "/api/users", null);
        var created = jdbc.queryForList("SELECT id, username, real_name, role_id, status, created_at FROM t_user WHERE username = ?", username);
        return created.isEmpty() ? Map.of("username", username) : created.get(0);
    }

    /** G10: 编辑用户信息与状态（具备自锁保护与会话即时撤销） */
    public void updateUser(long uid, String realName, String roleName, Boolean enabled, Long operatorUid) {
        List<Map<String, Object>> users = jdbc.queryForList("SELECT u.*, r.name AS role_name FROM t_user u JOIN t_role r ON r.id = u.role_id WHERE u.id = ?", uid);
        if (users.isEmpty()) {
            throw new IllegalArgumentException("用户不存在: " + uid);
        }
        var current = users.get(0);
        String currentRole = (String) current.get("role_name");
        boolean currentEnabled = ((Number) current.get("status")).intValue() == 1;

        boolean newEnabled = enabled != null ? enabled : currentEnabled;
        String targetRole = roleName != null && !roleName.isBlank() ? roleName : currentRole;

        // 保障安全恢复约束：系统必须保留至少 1 个启用的 admin 账号，避免自我锁定
        if (currentEnabled && "admin".equals(currentRole)) {
            if (!newEnabled || !"admin".equals(targetRole)) {
                Integer activeAdmins = jdbc.queryForObject("""
                        SELECT count(*) FROM t_user u JOIN t_role r ON r.id = u.role_id
                        WHERE u.status = 1 AND r.name = 'admin'
                        """, Integer.class);
                if (activeAdmins != null && activeAdmins <= 1) {
                    throw new IllegalArgumentException("操作拒绝：系统必须保留至少一个启用的管理员账号，禁止停用或降权最后一位管理员");
                }
            }
        }

        List<Map<String, Object>> roles = jdbc.queryForList("SELECT id FROM t_role WHERE name = ?", targetRole);
        if (roles.isEmpty()) {
            throw new IllegalArgumentException("指定角色不存在: " + targetRole);
        }
        long roleId = ((Number) roles.get(0).get("id")).longValue();
        String targetRealName = realName != null ? realName : (String) current.get("real_name");

        jdbc.update("UPDATE t_user SET real_name = ?, role_id = ?, status = ? WHERE id = ?",
                targetRealName, roleId, newEnabled ? 1 : 0, uid);

        // 如果用户被禁用或角色发生变更，立即撤销既有会话
        if (!newEnabled || !targetRole.equals(currentRole)) {
            if (tokenRevocationService != null) {
                tokenRevocationService.revokeUser(uid);
            }
        }
        audit(operatorUid, (String) current.get("username"), "update_user", "/api/users", null);
    }

    /** G10: 用户自助修改密码 */
    public void changePassword(long uid, String oldPassword, String newPassword) {
        if (newPassword == null || newPassword.length() < 8) {
            throw new IllegalArgumentException("新密码长度不能少于 8 位");
        }
        if (newPassword.equals(oldPassword)) {
            throw new IllegalArgumentException("新密码不能与原密码相同");
        }
        List<Map<String, Object>> users = jdbc.queryForList("SELECT * FROM t_user WHERE id = ?", uid);
        if (users.isEmpty()) {
            throw new IllegalArgumentException("用户不存在: " + uid);
        }
        var user = users.get(0);
        String currentHash = (String) user.get("password_hash");
        if (!encoder.matches(oldPassword, currentHash)) {
            throw new IllegalArgumentException("原密码不正确");
        }
        String newHash = encoder.encode(newPassword);
        jdbc.update("UPDATE t_user SET password_hash = ? WHERE id = ?", newHash, uid);
        if (tokenRevocationService != null) {
            tokenRevocationService.revokeUser(uid);
        }
        audit(uid, (String) user.get("username"), "change_password", "/api/auth/change-password", null);
    }

    /** G10: 管理员重置用户密码 */
    public void resetPassword(long uid, String newPassword, Long adminUid) {
        if (newPassword == null || newPassword.length() < 8) {
            throw new IllegalArgumentException("新密码长度不能少于 8 位");
        }
        List<Map<String, Object>> users = jdbc.queryForList("SELECT * FROM t_user WHERE id = ?", uid);
        if (users.isEmpty()) {
            throw new IllegalArgumentException("用户不存在: " + uid);
        }
        var user = users.get(0);
        String newHash = encoder.encode(newPassword);
        jdbc.update("UPDATE t_user SET password_hash = ? WHERE id = ?", newHash, uid);
        if (tokenRevocationService != null) {
            tokenRevocationService.revokeUser(uid);
        }
        audit(adminUid, (String) user.get("username"), "reset_password", "/api/users", null);
    }

    public record UserState(boolean exists, boolean enabled, String roleName) {}

    /** R16: 查询用户最新启用状态与有效角色，用于会话时效校验与降权生效 */
    public Optional<UserState> getUserState(long uid) {
        List<Map<String, Object>> rows = jdbc.queryForList("""
                SELECT u.status, r.name AS role_name
                FROM t_user u JOIN t_role r ON r.id = u.role_id
                WHERE u.id = ?
                """, uid);
        if (rows.isEmpty()) {
            return Optional.empty();
        }
        var row = rows.get(0);
        boolean enabled = ((Number) row.get("status")).intValue() == 1;
        String roleName = (String) row.get("role_name");
        return Optional.of(new UserState(true, enabled, roleName));
    }

    public record UserProfile(long id, String username, String realName, String roleName, String permissionsJson) {}
}
