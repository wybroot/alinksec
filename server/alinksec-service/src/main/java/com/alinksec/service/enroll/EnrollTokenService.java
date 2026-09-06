package com.alinksec.service.enroll;

import com.alinksec.common.error.ApiException;
import com.alinksec.common.error.ErrorCode;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;

/**
 * 一次性注册码（t_enroll_token）：校验 + 原子核销。
 * 核销使用条件 UPDATE（status=1 且未过期且 used_count<max_uses），失败后回查定位原因。
 */
@Service
public class EnrollTokenService {

    private final JdbcTemplate jdbc;

    public EnrollTokenService(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    /** 校验并核销一次使用名额（幂等性由调用方事务保证：事务回滚则名额不消耗） */
    @Transactional
    public void consume(String token) {
        int updated = jdbc.update("""
                UPDATE t_enroll_token
                SET used_count = used_count + 1
                WHERE token = ? AND status = 1 AND expire_at > now() AND used_count < max_uses
                """, token);
        if (updated == 1) {
            return;
        }
        // 定位失败原因
        List<Map<String, Object>> rows = jdbc.queryForList(
                "SELECT status, expire_at, used_count, max_uses FROM t_enroll_token WHERE token = ?", token);
        if (rows.isEmpty()) {
            throw new ApiException(ErrorCode.ENROLL_TOKEN_INVALID);
        }
        var row = rows.get(0);
        if (((Number) row.get("status")).intValue() != 1
                || ((OffsetDateTime) row.get("expire_at")).isBefore(OffsetDateTime.now())) {
            throw new ApiException(ErrorCode.ENROLL_TOKEN_INVALID);
        }
        throw new ApiException(ErrorCode.ENROLL_TOKEN_EXHAUSTED);
    }

    /** 生成新注册码（REST 端点 POST /api/hosts/enroll-token；启动种子与该端点共用） */
    public String create(Long createdBy, int maxUses, int validDays) {
        if (maxUses < 1 || maxUses > 10_000 || validDays < 1 || validDays > 365) {
            throw new IllegalArgumentException("注册码使用次数或有效期超出允许范围");
        }
        String token = "ENROLL-" + randomToken();
        jdbc.update("""
                INSERT INTO t_enroll_token (token, max_uses, expire_at, created_by, status)
                VALUES (?, ?, now() + ? * interval '1 day', ?, 1)
                """, token, maxUses, validDays, createdBy);
        return token;
    }

    public boolean anyExists() {
        Integer count = jdbc.queryForObject(
                "SELECT COUNT(*) FROM t_enroll_token WHERE status = 1 AND expire_at > now()", Integer.class);
        return count != null && count > 0;
    }

    private static String randomToken() {
        String alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
        SecureRandom rnd = new SecureRandom();
        StringBuilder sb = new StringBuilder(20);
        for (int i = 0; i < 20; i++) {
            sb.append(alphabet.charAt(rnd.nextInt(alphabet.length())));
        }
        return sb.toString();
    }
}
