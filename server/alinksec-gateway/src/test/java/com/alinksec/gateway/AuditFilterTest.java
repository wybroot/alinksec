package com.alinksec.gateway;

import com.alinksec.service.audit.AuditService;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class AuditFilterTest {

    @Test
    void webhookBodyReachesControllerButIsNotRecorded() throws Exception {
        AuditService audit = mock(AuditService.class);
        AuditFilter filter = new AuditFilter(audit);
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/notify/channels");
        String body = "{\"webhookUrl\":\"https://example.test/hook?token=secret\"}";
        request.setContent(body.getBytes(StandardCharsets.UTF_8));
        request.setRemoteAddr("192.0.2.10");
        request.setAttribute("uid", 7L);
        request.setAttribute("username", "admin");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, (req, res) ->
                assertEquals(body, new String(req.getInputStream().readAllBytes(), StandardCharsets.UTF_8)));

        verify(audit).record(eq(7L), eq("admin"), eq("POST"), eq("/api/notify/channels"),
                eq("192.0.2.10"), eq(200), anyInt());
    }
}
