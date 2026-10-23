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
        if ("patch".equals(resourceType)) return authorizedRepair(token,resourceKey);
        if ("virus-db".equals(resourceType)) {
            var keys=jdbc.queryForList("SELECT package_key,delta_key FROM t_virus_db ORDER BY id DESC LIMIT 1");
            if (keys.size()!=1 || !keys.get(0).get("package_key").equals(resourceKey)
                    && (String.valueOf(keys.get(0).get("delta_key")).isEmpty() || !keys.get(0).get("delta_key").equals(resourceKey))) return false;
        }
        Integer count = jdbc.queryForObject("""
                SELECT count(*) FROM t_agent_download_token
                WHERE token = ? AND resource_type = ? AND resource_key = ? AND expire_at > CURRENT_TIMESTAMP
                """, Integer.class, token, resourceType, resourceKey);
        return count != null && count == 1;
    }

    public String issueForRepair(String agentId,String filename,long taskId,String refId,String reviewId,java.time.Instant deadline) {
        java.time.Instant now=java.time.Instant.now(),expiry=now.plus(Duration.ofMinutes(15));
        if (deadline.isBefore(expiry)) expiry=deadline;
        if (!expiry.isAfter(now)) throw new IllegalArgumentException("任务或维护窗口已经过期");
        byte[] bytes=new byte[32]; RANDOM.nextBytes(bytes);
        String token=Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        jdbc.update("""
                INSERT INTO t_agent_download_token(token,agent_id,resource_type,resource_key,expire_at,fix_task_id,fix_ref_id,patch_review_id)
                VALUES (?,?,'patch',?,?,?,?,?)
                """,token,agentId,filename,database.timestamp(expiry),taskId,refId,reviewId);
        return token;
    }

    private boolean authorizedRepair(String token,String filename) {
        var rows=jdbc.queryForList("""
                SELECT p.*,r.patch_digest AS review_digest,c.cve_id,c.rule_source_id,c.rule_digest,CAST(c.affected AS TEXT) AS affected
                FROM t_agent_download_token k JOIN t_fix_task t ON t.id=k.fix_task_id
                JOIN t_fix_record f ON f.task_id=t.id AND f.agent_id=k.agent_id AND f.ref_id=k.fix_ref_id
                  AND f.ref_type='vuln_finding' AND f.status=0
                JOIN t_command command ON command.cmd_id=f.command_id AND command.status IN (0,1,2,3)
                JOIN t_patch_review r ON r.id=k.patch_review_id AND r.revoked_at IS NULL
                JOIN t_patch_package p ON p.id=r.patch_id AND p.filename=k.resource_key AND p.sha256=r.patch_sha256
                JOIN t_cve_db c ON c.cve_id=r.cve_id AND c.rule_source_id=r.rule_source_id AND c.rule_digest=r.rule_digest
                JOIN t_user u ON u.id=t.approved_by AND u.status=1 JOIN t_role role ON role.id=u.role_id AND role.name IN ('admin','operator')
                WHERE k.token=? AND k.resource_type='patch' AND k.resource_key=? AND k.expire_at>?
                  AND t.type=2 AND t.status=1 AND t.approved=true AND t.approver_id=t.approved_by
                  AND (t.window_end IS NULL OR t.window_end>?)
                """,token,filename,database.timestamp(java.time.Instant.now()),database.timestamp(java.time.Instant.now()));
        if (rows.size()!=1) return false;
        var row=rows.get(0);
        try {
            return row.get("review_digest").equals(com.alinksec.service.fix.PatchRepoService.patchDigest(row))
                    && new com.alinksec.service.library.LibrarySelection(jdbc).allowsCve(String.valueOf(row.get("cve_id")),
                        String.valueOf(row.get("rule_source_id")),String.valueOf(row.get("rule_digest")))
                    && row.get("rule_digest").equals(com.alinksec.service.scan.VulnerabilityEvidence.ruleDigest(
                    String.valueOf(row.get("rule_source_id")),String.valueOf(row.get("cve_id")),com.alinksec.common.util.JsonUtils.read(String.valueOf(row.get("affected")))));
        } catch (IllegalArgumentException e) { return false; }
    }
}
