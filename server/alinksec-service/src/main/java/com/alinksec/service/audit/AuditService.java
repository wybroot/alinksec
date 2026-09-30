package com.alinksec.service.audit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

/**
 * 平台操作审计（docs/01 §6.1）：
 * 写入由 gateway 层 AuditFilter 拦截 REST 写操作（POST/PUT/DELETE）调用本服务落 t_audit_log
 * （含操作人/来源 IP/耗时/响应码）；登录/登出等无 uid 请求记录 username=null。
 */
@Service
public class AuditService {

    private static final Logger log = LoggerFactory.getLogger(AuditService.class);

    private final JdbcTemplate jdbc;

    public AuditService(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    /** 落一条审计记录（失败不影响业务） */
    public void record(Long uid, String username, String method, String path,
                       String sourceIp, int status, int costMs) {
        try {
            jdbc.update("""
                    INSERT INTO t_audit_log (uid, username, method, path, source_ip, status, cost_ms)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, uid, username, method, path, sourceIp, status, costMs);
        } catch (Exception e) {
            log.warn("审计记录失败（不影响业务）: {}", e.getMessage());
        }
    }

    /** 审计查询（AuditController 用） */
    public Map<String, Object> query(Long uid, String path, int page, int size) {
        StringBuilder where = new StringBuilder(" WHERE 1=1");
        if (uid != null) {
            where.append(" AND uid = ").append(uid);
        }
        if (path != null && !path.isBlank()) {
            where.append(" AND path LIKE '%").append(path.replace("'", "''")).append("%'");
        }
        Long total = jdbc.queryForObject("SELECT count(*) FROM t_audit_log" + where, Long.class);
        int offset = (page - 1) * size;
        List<Map<String, Object>> list = jdbc.queryForList(
                "SELECT id, uid, username, method, path, source_ip, status, cost_ms, created_at "
                        + "FROM t_audit_log" + where + " ORDER BY id DESC LIMIT " + size + " OFFSET " + offset);
        return Map.of("total", total == null ? 0 : total, "list", list);
    }
}
