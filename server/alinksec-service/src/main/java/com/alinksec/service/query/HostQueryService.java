package com.alinksec.service.query;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * 主机资产查询：t_agent 列表/详情 + t_asset_*（软件/端口/账号）。
 */
@Service
public class HostQueryService {

    private final JdbcTemplate jdbc;

    public HostQueryService(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public Map<String, Object> list(String keyword, Integer status, Integer isolationStatus,
                                    int page, int size) {
        StringBuilder where = new StringBuilder(" WHERE a.status <> 4");
        List<Object> args = new ArrayList<>();
        if (keyword != null && !keyword.isBlank()) {
            where.append(" AND (a.hostname ILIKE ? OR a.ip ILIKE ? OR a.agent_id ILIKE ?)");
            String pattern = "%" + keyword.trim() + "%";
            args.add(pattern);
            args.add(pattern);
            args.add(pattern);
        }
        if (status != null) {
            where.append(" AND a.status = ?");
            args.add(status);
        }
        if (isolationStatus != null) {
            where.append(" AND a.isolation_status = ?");
            args.add(isolationStatus);
        }
        String cond = where.toString();
        Long total = jdbc.queryForObject(
                "SELECT count(*) FROM t_agent a" + cond, Long.class,
                args.toArray());

        List<Object> pageArgs = new ArrayList<>(args);
        pageArgs.add(size);
        pageArgs.add((page - 1) * size);
        List<Map<String, Object>> list = jdbc.queryForList("""
                SELECT a.agent_id, a.hostname, a.ip, a.os_type, a.os_version, a.kernel, a.arch,
                       a.agent_version, a.status, a.protect_enabled, a.last_heartbeat,
                       a.isolation_status, a.isolation_command_id, a.isolation_error, a.isolation_updated_at,
                       (SELECT count(*) FROM t_asset_software s WHERE s.agent_id = a.agent_id) AS software_count,
                       (SELECT count(*) FROM t_asset_port p WHERE p.agent_id = a.agent_id) AS port_count,
                       (SELECT count(*) FROM t_asset_process p WHERE p.agent_id = a.agent_id) AS process_count,
                       (SELECT count(*) FROM t_asset_account c WHERE c.agent_id = a.agent_id) AS account_count,
                       (SELECT count(*) FROM t_asset_account c WHERE c.agent_id = a.agent_id AND c.risky = TRUE) AS risky_account_count,
                       (SELECT count(*) FROM t_asset_container c WHERE c.agent_id = a.agent_id) AS container_count,
                       (SELECT count(*) FROM t_alert ta WHERE ta.agent_id = a.agent_id AND ta.status IN (0,1)) AS alert_count,
                       e.title AS last_event
                FROM t_agent a
                LEFT JOIN LATERAL (
                    SELECT title FROM t_alert t2 WHERE t2.agent_id = a.agent_id
                    ORDER BY t2.last_time DESC LIMIT 1
                ) e ON TRUE""" + cond + """
                ORDER BY a.status, a.hostname
                LIMIT ? OFFSET ?
                """, pageArgs.toArray());

        Map<String, Object> result = new HashMap<>();
        result.put("list", list);
        result.put("total", total == null ? 0 : total);
        return result;
    }

    public Map<String, Object> detail(String agentId) {
        List<Map<String, Object>> rows = jdbc.queryForList("""
                SELECT agent_id, hostname, ip, os_type, os_version, kernel, arch, agent_version,
                       machine_id, status, protect_enabled, policy_version, last_heartbeat, created_at,
                       isolation_status, isolation_command_id, isolation_error, isolation_updated_at
                FROM t_agent WHERE agent_id = ? AND status <> 4
                """, agentId);
        if (rows.isEmpty()) {
            return null;
        }
        return rows.get(0);
    }

    public List<Map<String, Object>> groups() {
        return jdbc.queryForList("""
                SELECT g.id, g.name, count(a.id) AS host_count
                FROM t_host_group g
                LEFT JOIN t_agent a ON a.group_id = g.id AND a.status <> 4
                GROUP BY g.id, g.name ORDER BY g.id
                """);
    }

    public List<Map<String, Object>> software(String agentId, String keyword, int page, int size) {
        return jdbc.queryForList("""
                SELECT name, version, vendor, install_time, source
                FROM t_asset_software WHERE agent_id = ?
                  AND (? IS NULL OR name ILIKE '%' || ? || '%')
                ORDER BY name LIMIT ? OFFSET ?
                """, agentId, blankToNull(keyword), keyword, size, (page - 1) * size);
    }

    public List<Map<String, Object>> ports(String agentId) {
        return jdbc.queryForList("""
                SELECT port, protocol, process, bind_addr
                FROM t_asset_port WHERE agent_id = ?
                ORDER BY port
                """, agentId);
    }

    public List<Map<String, Object>> accounts(String agentId) {
        return jdbc.queryForList("""
                SELECT name, uid, gid, shell, login_enabled, last_login, risky, risky_reason
                FROM t_asset_account WHERE agent_id = ?
                ORDER BY uid
                """, agentId);
    }

    public List<Map<String, Object>> processes(String agentId) {
        return jdbc.queryForList("SELECT pid, name, exe, cmdline, username, rss_bytes, updated_at FROM t_asset_process WHERE agent_id = ? ORDER BY rss_bytes DESC, pid LIMIT 500", agentId);
    }

    public List<Map<String, Object>> containers(String agentId) {
        return jdbc.queryForList("""
                SELECT container_id, name, image, image_id, orchestrator, namespace, status, created_at, started_at, ports, labels, risky, risk_reasons, updated_at
                FROM t_asset_container WHERE agent_id = ? ORDER BY name
                """, agentId);
    }

    private static String blankToNull(String s) {
        return s == null || s.isBlank() ? null : s.trim();
    }
}
