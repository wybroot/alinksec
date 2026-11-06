package com.alinksec.gateway.rest;

import com.alinksec.common.web.ApiResult;
import com.alinksec.service.user.UserService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * 管理端账号生命周期管理（G10）：
 * 仅限系统管理员（admin）访问，支持账号列表、新建、编辑角色/状态、重置密码。
 */
@RestController
@RequestMapping("/api/users")
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping
    public ApiResult<List<Map<String, Object>>> listUsers() {
        return ApiResult.ok(userService.listUsers());
    }

    @GetMapping("/roles")
    public ApiResult<List<Map<String, Object>>> listRoles() {
        return ApiResult.ok(userService.listRoles());
    }

    @PostMapping
    public ApiResult<Map<String, Object>> createUser(@RequestBody Map<String, Object> body, HttpServletRequest request) {
        String username = (String) body.getOrDefault("username", "");
        String password = (String) body.getOrDefault("password", "");
        String realName = (String) body.getOrDefault("realName", username);
        String roleName = (String) body.getOrDefault("roleName", body.getOrDefault("role", "viewer"));
        Long operatorUid = request.getAttribute("uid") instanceof Number n ? n.longValue() : null;

        try {
            var created = userService.createUser(username, password, realName, roleName, operatorUid);
            return ApiResult.ok(created);
        } catch (IllegalArgumentException e) {
            return ApiResult.error(40001, e.getMessage());
        }
    }

    @PutMapping("/{uid}")
    public ApiResult<Void> updateUser(@PathVariable long uid, @RequestBody Map<String, Object> body, HttpServletRequest request) {
        String realName = (String) body.get("realName");
        String roleName = (String) body.getOrDefault("roleName", body.get("role"));
        Boolean enabled = body.containsKey("enabled") ? Boolean.valueOf(String.valueOf(body.get("enabled"))) : null;
        Long operatorUid = request.getAttribute("uid") instanceof Number n ? n.longValue() : null;

        try {
            userService.updateUser(uid, realName, roleName, enabled, operatorUid);
            return ApiResult.ok();
        } catch (IllegalArgumentException e) {
            return ApiResult.error(40001, e.getMessage());
        }
    }

    @PostMapping("/{uid}/reset-password")
    public ApiResult<Void> resetPassword(@PathVariable long uid, @RequestBody Map<String, String> body, HttpServletRequest request) {
        String newPassword = body.getOrDefault("password", body.getOrDefault("newPassword", ""));
        if (newPassword.isBlank()) {
            return ApiResult.error(10001, "新密码不能为空");
        }
        Long operatorUid = request.getAttribute("uid") instanceof Number n ? n.longValue() : null;

        try {
            userService.resetPassword(uid, newPassword, operatorUid);
            return ApiResult.ok();
        } catch (IllegalArgumentException e) {
            return ApiResult.error(40001, e.getMessage());
        }
    }
}
