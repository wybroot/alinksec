package com.alinksec.gateway;

import com.alinksec.service.waf.WafEngineService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * WAF 检查过滤器（E01 / E04）：
 * 位于网关入口最高优先级，在请求进入 Controller 前执行 OWASP CRS 检查。
 * - DetectionOnly 模式：记录并上报安全事件，正常放行。
 * - On 模式：达到异常阈值时立即返回 HTTP 403 阻断，截断攻击。
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 5)
public class WafFilter extends OncePerRequestFilter {

    private final WafEngineService wafService;

    public WafFilter(WafEngineService wafService) {
        this.wafService = wafService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String uri = request.getRequestURI();
        String query = request.getQueryString();
        String method = request.getMethod();
        String userAgent = request.getHeader("User-Agent");
        String clientIp = clientIp(request);

        // 仅对 /api/** 请求或可疑 URI 路径执行检测
        if (uri.startsWith("/api/")) {
            // 对常见查询与轻量请求检查
            var result = wafService.inspect(method, uri, query, userAgent, "", clientIp);
            if (result.blocked()) {
                response.setStatus(HttpStatus.FORBIDDEN.value());
                response.setContentType(MediaType.APPLICATION_JSON_VALUE + ";charset=UTF-8");
                response.getWriter().write(String.format(
                        "{\"code\":40300,\"msg\":\"请求被 Web 应用防火墙 (OWASP CRS) 拦截: %s\",\"data\":null}",
                        result.matchedCategory()
                ));
                return;
            }
        }

        filterChain.doFilter(request, response);
    }

    private String clientIp(HttpServletRequest request) {
        String fwd = request.getHeader("X-Forwarded-For");
        return fwd != null && !fwd.isBlank() ? fwd.split(",")[0].trim() : request.getRemoteAddr();
    }
}
