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
    @Test
    void onlyAdministratorsCanTriggerRemoteLibraryAccess() throws Exception {
        for (String role : new String[]{"admin", "operator", "viewer"}) {
            var request = request(role);
            request.setMethod("POST"); request.setRequestURI("/api/libraries/sources/provider/sync");
            assertEquals("admin".equals(role), interceptor().preHandle(request, new MockHttpServletResponse(), new Object()));
        }
    }
    @Test
    void operatorsCanImportButViewersCannotModifyLibraries() throws Exception {
        var operator = request("operator"); operator.setMethod("POST"); operator.setRequestURI("/api/libraries/cves/import");
        assertTrue(interceptor().preHandle(operator, new MockHttpServletResponse(), new Object()));
        var viewer = request("viewer"); viewer.setMethod("POST"); viewer.setRequestURI("/api/libraries/cves/import");
        assertFalse(interceptor().preHandle(viewer, new MockHttpServletResponse(), new Object()));
    }
    @Test
    void onlyAdministratorsChangeSchedulesButAllRolesCanInspectRuns() throws Exception {
        for (String role : new String[]{"admin", "operator", "viewer"}) {
            for (String method : new String[]{"PUT", "DELETE"}) {
                var request = request(role);
                request.setMethod(method); request.setRequestURI("/api/libraries/sources/provider/schedule");
                assertEquals("admin".equals(role), interceptor().preHandle(request, new MockHttpServletResponse(), new Object()));
            }
            var read = request(role); read.setRequestURI("/api/libraries/sources/provider/runs");
            assertTrue(interceptor().preHandle(read, new MockHttpServletResponse(), new Object()));
        }
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
