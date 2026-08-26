package com.alinksec.gateway.rest;

import com.alinksec.common.util.JwtUtil;
import com.alinksec.common.web.ApiResult;
import com.alinksec.service.user.UserService;
import jakarta.servlet.http.HttpServletRequest;
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

    public AuthController(UserService userService, JwtSecretHolder secretHolder) {
        this.userService = userService;
        this.secretHolder = secretHolder;
    }

    @PostMapping("/login")
    public ApiResult<Map<String, Object>> login(@RequestBody Map<String, String> body,
                                                HttpServletRequest request) {
        String username = body.getOrDefault("username", "");
        String password = body.getOrDefault("password", "");
        if (username.isBlank() || password.isBlank()) {
            return ApiResult.error(10001, "用户名或密码不能为空");
        }
        var profile = userService.login(username, password, clientIp(request));
        if (profile.isEmpty()) {
            return ApiResult.error(40101, "用户名或密码错误");
        }
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
        userService.audit(null, String.valueOf(request.getAttribute("username")), "logout", null,
                clientIp(request));
        return ApiResult.ok();
    }

    private static String clientIp(HttpServletRequest request) {
        String xff = request.getHeader("X-Forwarded-For");
        return xff != null && !xff.isBlank() ? xff.split(",")[0].trim() : request.getRemoteAddr();
    }
}
