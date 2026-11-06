package com.alinksec.gateway.rest;

import com.alinksec.common.util.JwtUtil;
import com.alinksec.common.web.ApiResult;
import com.alinksec.service.user.TokenRevocationService;
import com.alinksec.service.user.UserService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * 管理端登录（JWT，12h 有效）。
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private static final long TOKEN_TTL_SECONDS = 12 * 3600;

    private final UserService userService;
    private final JwtSecretHolder secretHolder;
    private final LoginAttemptLimiter loginAttempts;
    private final TokenRevocationService tokenRevocationService;

    public AuthController(UserService userService, JwtSecretHolder secretHolder, LoginAttemptLimiter loginAttempts) {
        this(userService, secretHolder, loginAttempts, null);
    }

    @Autowired
    public AuthController(UserService userService, JwtSecretHolder secretHolder, LoginAttemptLimiter loginAttempts,
                          @Autowired(required = false) TokenRevocationService tokenRevocationService) {
        this.userService = userService;
        this.secretHolder = secretHolder;
        this.loginAttempts = loginAttempts;
        this.tokenRevocationService = tokenRevocationService;
    }

    @PostMapping("/login")
    public ApiResult<Map<String, Object>> login(@RequestBody Map<String, String> body,
                                                HttpServletRequest request) {
        String username = body.getOrDefault("username", "");
        String password = body.getOrDefault("password", "");
        if (username.isBlank() || password.isBlank()) {
            return ApiResult.error(10001, "用户名或密码不能为空");
        }
        String sourceIp = clientIp(request);
        if (!loginAttempts.isAllowed(sourceIp, username)) {
            return ApiResult.error(42901, "登录尝试过于频繁，请稍后再试");
        }
        var profile = userService.login(username, password, sourceIp);
        if (profile.isEmpty()) {
            loginAttempts.recordFailure(sourceIp, username);
            return ApiResult.error(40101, "用户名或密码错误");
        }
        loginAttempts.recordSuccess(sourceIp, username);
        var p = profile.get();
        String token = JwtUtil.sign(secretHolder.secret(), Map.of(
                "uid", p.id(), "username", p.username(), "role", p.roleName()),
                TOKEN_TTL_SECONDS);
        return ApiResult.ok(Map.of(
                "token", token,
                "user", Map.of(
                        "id", p.id(),
                        "username", p.username(),
                        "realName", p.realName() == null ? p.username() : p.realName(),
                        "role", p.roleName())));
    }

    @PostMapping("/logout")
    public ApiResult<Void> logout(HttpServletRequest request) {
        String auth = request.getHeader("Authorization");
        if (auth != null && auth.startsWith("Bearer ") && tokenRevocationService != null) {
            String rawToken = auth.substring(7);
            try {
                Map<String, Object> claims = JwtUtil.verify(secretHolder.secret(), rawToken);
                long exp = claims.get("exp") instanceof Number n ? n.longValue() : (System.currentTimeMillis() / 1000 + TOKEN_TTL_SECONDS);
                tokenRevocationService.revokeToken(rawToken, exp);
            } catch (Exception ignored) {
                tokenRevocationService.revokeToken(rawToken, System.currentTimeMillis() / 1000 + TOKEN_TTL_SECONDS);
            }
        }
        userService.audit(null, String.valueOf(request.getAttribute("username")), "logout",
                clientIp(request));
        return ApiResult.ok();
    }

    @PostMapping("/change-password")
    public ApiResult<Void> changePassword(@RequestBody Map<String, String> body, HttpServletRequest request) {
        Object uidObj = request.getAttribute("uid");
        if (uidObj == null) {
            return ApiResult.error(40100, "未认证");
        }
        long uid = ((Number) uidObj).longValue();
        String oldPassword = body.getOrDefault("oldPassword", "");
        String newPassword = body.getOrDefault("newPassword", "");
        if (oldPassword.isBlank() || newPassword.isBlank()) {
            return ApiResult.error(10001, "原密码与新密码均不能为空");
        }
        try {
            userService.changePassword(uid, oldPassword, newPassword);
            return ApiResult.ok();
        } catch (IllegalArgumentException e) {
            return ApiResult.error(40001, e.getMessage());
        }
    }

    private static String clientIp(HttpServletRequest request) {
        String xff = request.getHeader("X-Forwarded-For");
        return xff != null && !xff.isBlank() ? xff.split(",")[0].trim() : request.getRemoteAddr();
    }
}
