package com.alinksec.gateway.rest;

import com.alinksec.common.util.JwtUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * REST 鉴权拦截：Authorization: Bearer <jwt>，校验通过后把 uid/username/role 放入 request attribute。
 * RBAC（docs/01 §6.1 三角色）：
 *   admin    全部权限
 *   operator 安全运维（扫描/修复/处置/灰度下发等写操作），平台管理类写操作除外
 *   viewer   只读审计，一切写操作 403
 */
@Component
public class JwtAuthInterceptor implements HandlerInterceptor {

    /** 写方法集合 */
    private static final Set<String> WRITE_METHODS = Set.of("POST", "PUT", "DELETE", "PATCH");

    /** 平台管理类写前缀：仅 admin（升级包上传 / 注册码生成） */
    private static final List<String> ADMIN_WRITE_PREFIXES = List.of(
            "/api/upgrade/packages", "/api/hosts/enroll-token", "/api/notify");

    /** Sensitive configuration, including webhook URLs that may carry bot tokens. */
    private static final List<String> ADMIN_ONLY_PREFIXES = List.of("/api/notify", "/api/audit");

    /** 自服务写操作：任何已认证角色可执行（登出需落审计，不应被写拦截误伤） */
    private static final Set<String> SELF_WRITE_URIS = Set.of("/api/auth/logout");

    /** 平台管理类写后缀：仅 admin（卸载口令布防） */
    private static final List<String> ADMIN_WRITE_SUFFIXES = List.of("/uninstall-token");

    private final JwtSecretHolder secretHolder;

    public JwtAuthInterceptor(JwtSecretHolder secretHolder) {
        this.secretHolder = secretHolder;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
            throws Exception {
        if ("OPTIONS".equalsIgnoreCase(request.getMethod())) {
            return true; // 预检放行（dev 跨域场景）
        }
        String auth = request.getHeader("Authorization");
        if (auth == null || !auth.startsWith("Bearer ")) {
            reject(response, HttpStatus.UNAUTHORIZED, 40100, "未登录");
            return false;
        }
        try {
            Map<String, Object> claims = JwtUtil.verify(secretHolder.secret(), auth.substring(7));
            String role = String.valueOf(claims.get("role"));
            request.setAttribute("uid", ((Number) claims.get("uid")).longValue());
            request.setAttribute("username", claims.get("username"));
            request.setAttribute("role", role);
            if (ADMIN_ONLY_PREFIXES.stream().anyMatch(request.getRequestURI()::startsWith)
                    && !"admin".equals(role)) {
                reject(response, HttpStatus.FORBIDDEN, 40301, "Administrator access is required");
                return false;
            }
            // 写操作角色校验（读操作三角色均放行；自服务写操作如登出对所有角色放行）
            if (WRITE_METHODS.contains(request.getMethod().toUpperCase())
                    && !SELF_WRITE_URIS.contains(request.getRequestURI())
                    && !canWrite(role, request.getRequestURI())) {
                reject(response, HttpStatus.FORBIDDEN, 40301,
                        "viewer".equals(role) ? "只读角色无写权限" : "该操作需要管理员权限");
                return false;
            }
            return true;
        } catch (IllegalArgumentException e) {
            reject(response, HttpStatus.UNAUTHORIZED, 40100, e.getMessage());
            return false;
        }
    }

    /** 写权限矩阵：admin 全通过；operator 排除平台管理前缀/后缀（安全处置类放行）；其余（viewer）全拒 */
    private boolean canWrite(String role, String uri) {
        if ("admin".equals(role)) {
            return true;
        }
        if ("operator".equals(role)) {
            return ADMIN_WRITE_PREFIXES.stream().noneMatch(uri::startsWith)
                    && ADMIN_WRITE_SUFFIXES.stream().noneMatch(uri::endsWith);
        }
        return false;
    }

    private void reject(HttpServletResponse response, HttpStatus status, int code, String msg) throws Exception {
        response.setStatus(status.value());
        response.setContentType("application/json;charset=UTF-8");
        response.getWriter().write("{\"code\":" + code + ",\"msg\":\"" + msg + "\",\"data\":null}");
    }
}
