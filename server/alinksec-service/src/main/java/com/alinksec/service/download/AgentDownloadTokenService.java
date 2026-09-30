package com.alinksec.service.download;

import com.alinksec.service.config.DatabaseDialect;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.util.Base64;
import java.time.Duration;

/** Short-lived, resource-scoped credentials for Agent package downloads. */
@Service
public class AgentDownloadTokenService {

    private static final SecureRandom RANDOM = new SecureRandom();
    private final JdbcTemplate jdbc;
    private final DatabaseDialect database;

    public AgentDownloadTokenService(JdbcTemplate jdbc, DatabaseDialect database) {
        this.jdbc = jdbc;
        this.database = database;
    }

    public String issue(String agentId, String resourceType, String resourceKey) {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        jdbc.update("DELETE FROM t_agent_download_token WHERE expire_at < CURRENT_TIMESTAMP");
        jdbc.update("""
                INSERT INTO t_agent_download_token (token, agent_id, resource_type, resource_key, expire_at)
                VALUES (?, ?, ?, ?, ?)
                """, token, agentId, resourceType, resourceKey,
                database.timestampAfter(Duration.ofMinutes(15)));
        return token;
    }

    public boolean isAuthorized(String token, String resourceType, String resourceKey) {
        if (token == null || token.isBlank()) {
            return false;
        }
        Integer count = jdbc.queryForObject("""
                SELECT count(*) FROM t_agent_download_token
                WHERE token = ? AND resource_type = ? AND resource_key = ? AND expire_at > CURRENT_TIMESTAMP
                """, Integer.class, token, resourceType, resourceKey);
        return count != null && count == 1;
    }
}
