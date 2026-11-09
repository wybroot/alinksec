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
                       u.auth_version, u.role_id, r.name AS role_name, CAST(r.permissions AS TEXT) AS permissions
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
                (String) row.get("permissions"), ((Number)row.get("auth_version")).longValue()));
    }

    @org.springframework.transaction.annotation.Transactional
    public String createSession(UserProfile profile,long ttlSeconds) {
        jdbc.update("UPDATE t_user SET auth_version=auth_version WHERE id=?",profile.id());
        String sid=java.util.UUID.randomUUID().toString();
        jdbc.update("DELETE FROM t_user_session WHERE expires_at<=?",System.currentTimeMillis()/1000);
        while(jdbc.queryForObject("SELECT count(*) FROM t_user_session WHERE user_id=?",Long.class,profile.id())>=16)
            jdbc.update("DELETE FROM t_user_session WHERE session_id IN (SELECT session_id FROM t_user_session WHERE user_id=? ORDER BY expires_at LIMIT 1)",profile.id());
        if(jdbc.update("INSERT INTO t_user_session(session_id,user_id,auth_version,role_name,expires_at) SELECT ?,id,auth_version,?,? FROM t_user WHERE id=? AND auth_version=? AND status=1 AND role_id=(SELECT id FROM t_role WHERE name=?)",sid,profile.roleName(),System.currentTimeMillis()/1000+ttlSeconds,profile.id(),profile.authVersion(),profile.roleName())!=1)
            throw new IllegalArgumentException("账号已变化，请重新登录");
        return sid;
    }
    public UserProfile authenticate(long uid,String sid) {
        var rows=jdbc.queryForList("SELECT u.id,u.username,u.real_name,u.auth_version,r.name AS role_name FROM t_user u JOIN t_role r ON r.id=u.role_id JOIN t_user_session s ON s.user_id=u.id WHERE u.id=? AND u.status=1 AND s.session_id=? AND s.expires_at>? AND s.auth_version=u.auth_version AND s.role_name=r.name",uid,sid,System.currentTimeMillis()/1000);
        if(rows.isEmpty())throw new IllegalArgumentException("会话已失效，请重新登录");
        var r=rows.get(0);return new UserProfile(uid,(String)r.get("username"),(String)r.get("real_name"),(String)r.get("role_name"),"",((Number)r.get("auth_version")).longValue());
    }
    public void logout(String sid,long uid){jdbc.update("DELETE FROM t_user_session WHERE session_id=? AND user_id=?",sid,uid);}
    @org.springframework.transaction.annotation.Transactional
    public void changePassword(long uid,String oldPassword,String password) {
        requirePassword(password);
        var rows=jdbc.queryForList("SELECT password_hash,auth_version FROM t_user WHERE id=? AND status=1",uid);
        if(rows.isEmpty() || oldPassword==null || oldPassword.getBytes(java.nio.charset.StandardCharsets.UTF_8).length>72 || !encoder.matches(oldPassword,(String)rows.get(0).get("password_hash")))throw new IllegalArgumentException("原密码不正确");
        if(jdbc.update("UPDATE t_user SET password_hash=?,auth_version=auth_version+1 WHERE id=? AND auth_version=?",encoder.encode(password),uid,rows.get(0).get("auth_version"))!=1)throw new IllegalArgumentException("账号已变化，请重试");
        jdbc.update("DELETE FROM t_user_session WHERE user_id=?",uid);
        audit(uid,"","password_changed","");
    }
    public Map<String,Object> users(int page,int size){size=Math.min(size,100);com.alinksec.common.web.PageBounds.offset(page,size);return Map.of("total",jdbc.queryForObject("SELECT count(*) FROM t_user",Long.class),"list",jdbc.queryForList("SELECT u.id,u.username,u.real_name,u.status,u.auth_version,r.name AS role FROM t_user u JOIN t_role r ON r.id=u.role_id ORDER BY u.id LIMIT ? OFFSET ?",Math.min(size,100),com.alinksec.common.web.PageBounds.offset(page,size)));}
    @org.springframework.transaction.annotation.Transactional
    public void createUser(String name,String realName,String password,String role,long actor) {
        jdbc.update("UPDATE t_role SET name=name WHERE name='admin'");
        requireAdmin(actor);requirePassword(password);requireRole(role);
        if(name==null || !name.matches("[a-zA-Z0-9_.@-]{1,64}") || realName!=null && realName.length()>64)throw new IllegalArgumentException("用户名或姓名格式不正确");
        if(jdbc.queryForObject("SELECT count(*) FROM t_user WHERE username=?",Long.class,name)>0)throw new IllegalArgumentException("用户名已存在");
        if(jdbc.queryForObject("SELECT count(*) FROM t_user",Long.class)>=10000)throw new IllegalArgumentException("用户数量已达上限");
        jdbc.update("INSERT INTO t_user(username,real_name,password_hash,role_id,status) VALUES(?,?,?,(SELECT id FROM t_role WHERE name=?),1)",name,realName,encoder.encode(password),role);
        audit(actor,"","user_created","");
    }
    @org.springframework.transaction.annotation.Transactional
    public void updateUser(long id,String role,int status,String password,long actor) {updateUser(id,role,status,password,actor,null);}
    @org.springframework.transaction.annotation.Transactional
    public void updateUser(long id,String role,int status,String password,long actor,Long expectedVersion) {
        jdbc.update("UPDATE t_role SET name=name WHERE name='admin'");
        requireAdmin(actor);requireRole(role);if(status!=0 && status!=1)throw new IllegalArgumentException("无效账号状态");
        if(id==actor && (status!=1 || !role.equals("admin")))throw new IllegalArgumentException("不能禁用自己或撤销自己的管理员角色");
        if(password!=null)requirePassword(password);
        var versions=jdbc.queryForList("SELECT auth_version FROM t_user WHERE id=?",Long.class,id);
        if(versions.isEmpty())throw new IllegalArgumentException("用户不存在");
        long version=versions.get(0);
        if(expectedVersion!=null && expectedVersion!=version)throw new IllegalArgumentException("账号已变化，请刷新后重试");
        int changed=password==null?jdbc.update("UPDATE t_user SET role_id=(SELECT id FROM t_role WHERE name=?),status=?,auth_version=auth_version+1 WHERE id=? AND auth_version=?",role,status,id,version):jdbc.update("UPDATE t_user SET role_id=(SELECT id FROM t_role WHERE name=?),status=?,password_hash=?,auth_version=auth_version+1 WHERE id=? AND auth_version=?",role,status,encoder.encode(password),id,version);
        if(changed!=1)throw new IllegalArgumentException("用户不存在");
        jdbc.update("DELETE FROM t_user_session WHERE user_id=?",id);
        audit(actor,"","user_updated","");
    }
    private void requireAdmin(long uid){if(jdbc.queryForObject("SELECT count(*) FROM t_user u JOIN t_role r ON r.id=u.role_id WHERE u.id=? AND u.status=1 AND r.name='admin'",Long.class,uid)!=1)throw new IllegalArgumentException("需要有效管理员账号");}
    private static void requireRole(String role){if(role==null || !java.util.Set.of("admin","operator","viewer").contains(role))throw new IllegalArgumentException("无效角色");}
    private static void requirePassword(String password){if(password==null || password.codePointCount(0,password.length())<12 || password.getBytes(java.nio.charset.StandardCharsets.UTF_8).length>72)throw new IllegalArgumentException("密码至少12字符且不超过72个UTF-8字节");}

    public void audit(Long userId, String username, String action, String sourceIp) {
        try {
            jdbc.update("""
                    INSERT INTO t_audit_log (uid, username, method, path, source_ip, status, cost_ms)
                    VALUES (?, ?, ?, ?, ?, ?, 0)
                    """, userId, username, action, action.startsWith("login")?"/api/auth/login":action.equals("logout")?"/api/auth/logout":action.equals("password_changed")?"/api/auth/password":"/api/users", sourceIp,
                    "login_failed".equals(action) ? 401 : 200);
        } catch (Exception ignored) {
            // 审计失败不阻断登录主链路
        }
    }

    public record UserProfile(long id, String username, String realName, String roleName, String permissionsJson,long authVersion) {}
}
