package com.alinksec.gateway;

import com.alinksec.common.util.JsonUtils;
import com.alinksec.service.audit.AuditService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.ContentCachingResponseWrapper;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * REST 写操作审计入口（docs/01 §6.1）：
 * 拦截 /api/** 的 POST/PUT/DELETE，落 t_audit_log（操作人/来源 IP/耗时/响应码）。
 * 操作人取 JwtAuthInterceptor 写入的 request attribute（拦截器先于本 Filter 的 finally 执行）。
 * R21: 捕获响应体业务状态码（ApiResult.code != 0），避免业务失败被记为 HTTP 200 假成功。
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
        ContentCachingResponseWrapper responseWrapper = new ContentCachingResponseWrapper(response);
        long start = System.currentTimeMillis();
        try {
            chain.doFilter(request, responseWrapper);
        } finally {
            int status = responseWrapper.getStatus();
            if (status == 200) {
                byte[] content = responseWrapper.getContentAsByteArray();
                if (content.length > 0 && content.length < 8192) {
                    String body = new String(content, StandardCharsets.UTF_8).trim();
                    if (body.startsWith("{") && body.contains("\"code\":")) {
                        try {
                            Map<?, ?> json = JsonUtils.read(body, Map.class);
                            Object codeObj = json.get("code");
                            if (codeObj instanceof Number n && n.intValue() != 0) {
                                status = n.intValue();
                            }
                        } catch (Exception ignored) {
                        }
                    }
                }
            }
            Long uid = request.getAttribute("uid") instanceof Number n ? n.longValue() : null;
            String username = request.getAttribute("username") instanceof String s ? s : null;
            auditService.record(uid, username, request.getMethod(), request.getRequestURI(),
                    clientIp(request), status,
                    (int) (System.currentTimeMillis() - start));
            responseWrapper.copyBodyToResponse();
        }
    }

    private String clientIp(HttpServletRequest request) {
        String fwd = request.getHeader("X-Forwarded-For");
        return fwd != null && !fwd.isBlank() ? fwd.split(",")[0].trim() : request.getRemoteAddr();
    }
}
