package com.alinksec.gateway;

import com.alinksec.service.audit.AuditService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * REST 写操作审计入口（docs/01 §6.1）：
 * 拦截 /api/** 的 POST/PUT/DELETE，落 t_audit_log（操作人/来源 IP/耗时/响应码）。
 * 操作人取 JwtAuthInterceptor 写入的 request attribute（拦截器先于本 Filter 的 finally 执行）。
 */
@Component
public class AuditFilter extends OncePerRequestFilter {

    private final AuditService auditService;

    public AuditFilter(AuditService auditService) {
        this.auditService = auditService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        boolean write = "POST".equalsIgnoreCase(request.getMethod())
                || "PUT".equalsIgnoreCase(request.getMethod())
                || "DELETE".equalsIgnoreCase(request.getMethod())
                || "PATCH".equalsIgnoreCase(request.getMethod());
        if (!write || !request.getRequestURI().startsWith("/api/")) {
            chain.doFilter(request, response);
            return;
        }
        long start = System.currentTimeMillis();
        try {
            chain.doFilter(request, response);
        } finally {
            Long uid = request.getAttribute("uid") instanceof Number n ? n.longValue() : null;
            String username = request.getAttribute("username") instanceof String s ? s : null;
            auditService.record(uid, username, request.getMethod(), request.getRequestURI(),
                    clientIp(request), response.getStatus(),
                    (int) (System.currentTimeMillis() - start));
        }
    }

    private String clientIp(HttpServletRequest request) {
        String fwd = request.getHeader("X-Forwarded-For");
        return fwd != null && !fwd.isBlank() ? fwd.split(",")[0].trim() : request.getRemoteAddr();
    }
}
