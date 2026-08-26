package com.alinksec.gateway;

import com.alinksec.service.audit.AuditService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.ContentCachingRequestWrapper;

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
        boolean multipart = request.getContentType() != null
                && request.getContentType().startsWith("multipart/");
        ContentCachingRequestWrapper wrapped = multipart ? null : new ContentCachingRequestWrapper(request);
        HttpServletRequest effective = wrapped != null ? wrapped : request;
        long start = System.currentTimeMillis();
        try {
            chain.doFilter(effective, response);
        } finally {
            String digest = bodyDigest(wrapped, request);
            Long uid = request.getAttribute("uid") instanceof Number n ? n.longValue() : null;
            String username = request.getAttribute("username") instanceof String s ? s : null;
            auditService.record(uid, username, request.getMethod(), request.getRequestURI(),
                    digest, clientIp(request), response.getStatus(),
                    (int) (System.currentTimeMillis() - start));
        }
    }

    /** 请求体摘要：multipart 不缓存；登录/改密等敏感路径脱敏；其余截断 500 字符 */
    private String bodyDigest(ContentCachingRequestWrapper wrapped, HttpServletRequest request) {
        if (wrapped == null) {
            return "(multipart)";
        }
        if (request.getRequestURI().contains("/auth/")) {
            return "(sensitive)";
        }
        String body = new String(wrapped.getContentAsByteArray(), java.nio.charset.StandardCharsets.UTF_8);
        return body.isEmpty() ? null : (body.length() > 500 ? body.substring(0, 500) + "..." : body);
    }

    private String clientIp(HttpServletRequest request) {
        String fwd = request.getHeader("X-Forwarded-For");
        return fwd != null && !fwd.isBlank() ? fwd.split(",")[0].trim() : request.getRemoteAddr();
    }
}
