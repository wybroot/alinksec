package com.alinksec.gateway;

import com.alinksec.service.waf.WafEngineService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

/**
 * WAF 检查过滤器（E01 / E04 / R60）：
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
        HttpServletRequest requestToUse = request;

        // 仅对 /api/** 请求执行检测
        if (uri.startsWith("/api/")) {
            String bodySnippet = "";
            String contentType = request.getContentType();
            boolean isEligibleBody = ("POST".equalsIgnoreCase(method) || "PUT".equalsIgnoreCase(method) || "PATCH".equalsIgnoreCase(method))
                    && contentType != null && !contentType.startsWith("multipart/") && !contentType.startsWith("application/octet-stream");

            if (isEligibleBody) {
                CachedBodyHttpServletRequest wrappedRequest = new CachedBodyHttpServletRequest(request);
                bodySnippet = new String(wrappedRequest.getBody(), StandardCharsets.UTF_8);
                requestToUse = wrappedRequest;
            }

            Map<String, String> headers = new HashMap<>();
            var headerNames = request.getHeaderNames();
            if (headerNames != null) {
                while (headerNames.hasMoreElements()) {
                    String hName = headerNames.nextElement();
                    if (!"User-Agent".equalsIgnoreCase(hName) && !"Authorization".equalsIgnoreCase(hName)) {
                        headers.put(hName, request.getHeader(hName));
                    }
                }
            }
            Map<String, String> cookies = new HashMap<>();
            if (request.getCookies() != null) {
                for (var c : request.getCookies()) {
                    if (c.getName() != null && c.getValue() != null) {
                        cookies.put(c.getName(), c.getValue());
                    }
                }
            }

            var result = wafService.inspect(method, uri, query, userAgent, bodySnippet, clientIp, headers, cookies);
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

        filterChain.doFilter(requestToUse, response);
    }

    private String clientIp(HttpServletRequest request) {
        String fwd = request.getHeader("X-Forwarded-For");
        return fwd != null && !fwd.isBlank() ? fwd.split(",")[0].trim() : request.getRemoteAddr();
    }

    private static class CachedBodyHttpServletRequest extends HttpServletRequestWrapper {
        private final byte[] body;

        public CachedBodyHttpServletRequest(HttpServletRequest request) throws IOException {
            super(request);
            InputStream is = request.getInputStream();
            this.body = is != null ? is.readNBytes(16 * 1024) : new byte[0];
        }

        public byte[] getBody() {
            return body;
        }

        @Override
        public ServletInputStream getInputStream() {
            ByteArrayInputStream bais = new ByteArrayInputStream(body);
            return new DelegatingServletInputStream(bais);
        }

        @Override
        public BufferedReader getReader() {
            return new BufferedReader(new InputStreamReader(getInputStream(), StandardCharsets.UTF_8));
        }
    }

    private static class DelegatingServletInputStream extends ServletInputStream {
        private final InputStream sourceStream;

        public DelegatingServletInputStream(InputStream sourceStream) {
            this.sourceStream = sourceStream;
        }

        @Override
        public int read() throws IOException {
            return sourceStream.read();
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            return sourceStream.read(b, off, len);
        }

        @Override
        public boolean isFinished() {
            try {
                return sourceStream.available() == 0;
            } catch (IOException e) {
                return true;
            }
        }

        @Override
        public boolean isReady() {
            return true;
        }

        @Override
        public void setReadListener(ReadListener readListener) {}
    }
}
