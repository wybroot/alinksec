package com.alinksec.common.util;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * 轻量 JWT（HS256），零第三方依赖。
 * 载荷字段：uid / username / role / exp（epoch 秒）。
 * 密钥由调用方持久化管理（环境变量或 data 目录随机生成）。
 */
public final class JwtUtil {

    private static final String HEADER = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";

    private JwtUtil() {}

    public static String sign(String secret, Map<String, Object> claims, long ttlSeconds) {
        Map<String, Object> payload = new HashMap<>(claims);
        payload.put("exp", System.currentTimeMillis() / 1000 + ttlSeconds);
        String encodedHeader = b64(HEADER.getBytes(StandardCharsets.UTF_8));
        String encodedPayload = b64(JsonUtils.write(payload).getBytes(StandardCharsets.UTF_8));
        String signingInput = encodedHeader + "." + encodedPayload;
        return signingInput + "." + b64(hmac(secret, signingInput));
    }

    /** 校验签名与有效期，失败抛 IllegalArgumentException */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> verify(String secret, String token) {
        if (token == null) {
            throw new IllegalArgumentException("缺少 token");
        }
        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            throw new IllegalArgumentException("token 格式错误");
        }
        String expected = b64(hmac(secret, parts[0] + "." + parts[1]));
        if (!constantTimeEquals(expected, parts[2])) {
            throw new IllegalArgumentException("token 签名无效");
        }
        Map<String, Object> claims = JsonUtils.read(
                new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8), Map.class);
        Object exp = claims.get("exp");
        if (exp instanceof Number n && n.longValue() < System.currentTimeMillis() / 1000) {
            throw new IllegalArgumentException("token 已过期");
        }
        return claims;
    }

    private static byte[] hmac(String secret, String input) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            return mac.doFinal(input.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new IllegalStateException("JWT 签名失败", e);
        }
    }

    private static String b64(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static boolean constantTimeEquals(String a, String b) {
        if (a.length() != b.length()) {
            return false;
        }
        int r = 0;
        for (int i = 0; i < a.length(); i++) {
            r |= a.charAt(i) ^ b.charAt(i);
        }
        return r == 0;
    }
}
