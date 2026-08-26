package com.alinksec.gateway.rest;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * REST 层装配：/api/** 统一 JWT 鉴权（放行 /api/auth/login）。
 */
@Configuration
public class RestConfig implements WebMvcConfigurer {

    private final JwtAuthInterceptor jwtAuthInterceptor;

    public RestConfig(JwtAuthInterceptor jwtAuthInterceptor) {
        this.jwtAuthInterceptor = jwtAuthInterceptor;
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(jwtAuthInterceptor)
                .addPathPatterns("/api/**")
                .excludePathPatterns("/api/auth/login", "/api/health",
                        "/api/virus/db/download", // Agent 特征包拉取（无 JWT：package_key 不可猜测）
                        "/api/fix/patches/download"); // Agent 补丁拉取（无 JWT：filename+sha256 双因子）
    }
}
