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
    @Test void sourceGovernanceWritesRequireAdminWhileAuditRemainsReadable() throws Exception {
        for(String role:new String[]{"admin","operator","viewer"}) {
            for(String path:new String[]{"/api/libraries/sources/provider/retire","/api/libraries/sources/provider/cves/CVE-2099-12345/decision"}) {
                var write=request(role); write.setMethod("POST"); write.setRequestURI(path);
                assertEquals("admin".equals(role),interceptor().preHandle(write,new MockHttpServletResponse(),new Object()));
            }
            var read=request(role); read.setRequestURI("/api/libraries/sources/provider/governance");
            assertTrue(interceptor().preHandle(read,new MockHttpServletResponse(),new Object()));
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

    @Test
    void baselinePackageLifecycleIsAdministratorOnlyButOperatorsCanRunCoveredTasks() throws Exception {
        for (String role : new String[]{"admin", "operator", "viewer"}) {
            for (String operation : new String[]{"import", "pkg/review", "pkg/test", "pkg/publish", "pkg/withdraw"}) {
                var request = request(role); request.setMethod("POST"); request.setRequestURI("/api/baseline/packages/" + operation);
                assertEquals("admin".equals(role), interceptor().preHandle(request, new MockHttpServletResponse(), new Object()));
            }
            var read = request(role); read.setRequestURI("/api/baseline/packages/pkg");
            assertTrue(interceptor().preHandle(read, new MockHttpServletResponse(), new Object()));
            var task = request(role); task.setMethod("POST"); task.setRequestURI("/api/baseline/tasks");
            assertEquals(!"viewer".equals(role), interceptor().preHandle(task, new MockHttpServletResponse(), new Object()));
        }
    }

    @Test void patchImportReviewAndRevocationRequireAnAuthenticatedWriter() throws Exception {
        for (String path : new String[]{"/api/fix/tasks/package", "/api/fix/tasks/1/approve", "/api/fix/tasks/1/cancel", "/api/fix/patches", "/api/fix/patches/1/reviews", "/api/fix/patches/1/reviews/review/revoke"}) {
            for (String role : new String[]{"admin", "operator", "viewer"}) {
                var req = request(role); req.setMethod("POST"); req.setRequestURI(path);
                var response = new MockHttpServletResponse();
                assertEquals(!"viewer".equals(role), interceptor().preHandle(req,response,new Object()));
                if ("viewer".equals(role)) assertEquals(403,response.getStatus());
                else assertEquals(7L,req.getAttribute("uid"));
            }
            var anonymous = new MockHttpServletRequest("POST", path); var response = new MockHttpServletResponse();
            assertFalse(interceptor().preHandle(anonymous,response,new Object())); assertEquals(401,response.getStatus());
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
