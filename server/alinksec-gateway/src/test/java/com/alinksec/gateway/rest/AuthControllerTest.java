package com.alinksec.gateway.rest;

import com.alinksec.common.util.JwtUtil;
import com.alinksec.service.user.UserService;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AuthControllerTest {

    @Test
    void successfulLoginReturnsVerifiableToken() {
        UserService users = mock(UserService.class);
        JwtSecretHolder secret = mock(JwtSecretHolder.class);
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getRemoteAddr()).thenReturn("192.0.2.10");
        when(secret.secret()).thenReturn("test-signing-secret");
        when(users.login("admin", "correct", "192.0.2.10"))
                .thenReturn(Optional.of(new UserService.UserProfile(7L, "admin", null, "admin", "{}")));
        AuthController controller = new AuthController(users, secret, new LoginAttemptLimiter());

        var result = controller.login(Map.of("username", "admin", "password", "correct"), request);

        assertEquals(0, result.code());
        String token = (String) result.data().get("token");
        assertNotNull(token);
        Map<String, Object> claims = JwtUtil.verify("test-signing-secret", token);
        assertEquals("admin", claims.get("username"));
        assertEquals("admin", claims.get("role"));
        assertTrue(((Number) claims.get("exp")).longValue() > System.currentTimeMillis() / 1000);
    }

    @Test
    void invalidPasswordStillReturnsBusinessError() {
        UserService users = mock(UserService.class);
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getRemoteAddr()).thenReturn("192.0.2.10");
        when(users.login("admin", "wrong", "192.0.2.10")).thenReturn(Optional.empty());
        AuthController controller = new AuthController(users, mock(JwtSecretHolder.class), new LoginAttemptLimiter());

        var result = controller.login(Map.of("username", "admin", "password", "wrong"), request);

        assertEquals(40101, result.code());
    }
}
