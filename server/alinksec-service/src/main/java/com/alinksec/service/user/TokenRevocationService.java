package com.alinksec.service.user;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.concurrent.ConcurrentHashMap;

/**
 * R16: 会话撤销与权限时效管理
 * 支持单 Token 撤销（登出）与用户级会话撤销（禁用/改密/降权），内存维护带 TTL 的黑名单。
 */
@Service
public class TokenRevocationService {

    private final ConcurrentHashMap<String, Long> revokedTokens = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<Long, Long> userRevocationTimestamps = new ConcurrentHashMap<>();

    public void revokeToken(String token, long expiryEpochSeconds) {
        if (token == null || token.isBlank()) return;
        revokedTokens.put(hash(token), expiryEpochSeconds);
    }

    public boolean isTokenRevoked(String token) {
        if (token == null || token.isBlank()) return false;
        String h = hash(token);
        Long exp = revokedTokens.get(h);
        if (exp == null) return false;
        if (System.currentTimeMillis() / 1000 > exp) {
            revokedTokens.remove(h);
            return false;
        }
        return true;
    }

    public void revokeUser(long uid) {
        userRevocationTimestamps.put(uid, System.currentTimeMillis() / 1000);
    }

    public boolean isUserRevoked(long uid, long tokenIssuedAtEpochSeconds) {
        Long revokedAt = userRevocationTimestamps.get(uid);
        if (revokedAt == null) return false;
        return tokenIssuedAtEpochSeconds > 0 && tokenIssuedAtEpochSeconds < revokedAt;
    }

    @Scheduled(fixedDelay = 600_000, initialDelay = 600_000)
    public void purgeExpired() {
        long now = System.currentTimeMillis() / 1000;
        revokedTokens.entrySet().removeIf(e -> e.getValue() < now);
    }

    private static String hash(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(md.digest(input.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            return Integer.toHexString(input.hashCode());
        }
    }
}
