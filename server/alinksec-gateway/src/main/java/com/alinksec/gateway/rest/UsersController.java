package com.alinksec.gateway.rest;
import com.alinksec.common.web.ApiResult;
import com.alinksec.service.user.UserService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.*;
import java.util.Map;

@RestController
@RequestMapping("/api/users")
public class UsersController {
    private final UserService users;
    public UsersController(UserService users){this.users=users;}
    @GetMapping public ApiResult<?> list(@RequestParam(defaultValue="1") int page,@RequestParam(defaultValue="100") int size){return ApiResult.ok(users.users(page,size));}
    @PostMapping public ApiResult<?> create(@RequestBody Map<String,String> body,HttpServletRequest request){users.createUser(body.get("username"),body.get("realName"),body.get("password"),body.get("role"),((Number)request.getAttribute("uid")).longValue());return ApiResult.ok();}
    @PutMapping("/{id}") public ApiResult<?> update(@PathVariable long id,@RequestBody Map<String,String> body,HttpServletRequest request){users.updateUser(id,body.get("role"),Integer.parseInt(body.getOrDefault("status","-1")),body.get("password"),((Number)request.getAttribute("uid")).longValue(),Long.valueOf(body.getOrDefault("version","-1")));return ApiResult.ok();}
}
