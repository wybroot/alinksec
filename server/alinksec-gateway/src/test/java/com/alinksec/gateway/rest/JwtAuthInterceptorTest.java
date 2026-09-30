package com.alinksec.gateway.rest;

import com.alinksec.common.util.JwtUtil;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class JwtAuthInterceptorTest {

    @Test
    void viewerCannotReadAuditLogs() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();

        assertFalse(interceptor().preHandle(request("viewer"), response, new Object()));

        assertEquals(403, response.getStatus());
    }

    @Test
    void administratorCanReadAuditLogs() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();

        assertTrue(interceptor().preHandle(request("admin"), response, new Object()));
    }

    private static JwtAuthInterceptor interceptor() {
        JwtSecretHolder secret = mock(JwtSecretHolder.class);
        when(secret.secret()).thenReturn("test-signing-secret");
        return new JwtAuthInterceptor(secret);
    }

    private static MockHttpServletRequest request(String role) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/audit/logs");
        String token = JwtUtil.sign("test-signing-secret",
                Map.of("uid", 7L, "username", role, "role", role), 3600);
        request.addHeader("Authorization", "Bearer " + token);
        return request;
    }
}
