package com.alinksec.service.query;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

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
        return list(keyword, status, isolationStatus, page, size, null);
    }

    public Map<String, Object> list(String keyword, Integer status, Integer isolationStatus,
                                    int page, int size, Long groupId) {
        page = Math.max(1, page); size = Math.max(1, Math.min(100, size));
        StringBuilder where = new StringBuilder(" WHERE a.status <> 4");
        List<Object> args = new ArrayList<>();
        if (keyword != null && !keyword.isBlank()) {
            where.append(" AND (LOWER(a.hostname) LIKE LOWER(?) OR LOWER(a.ip) LIKE LOWER(?) OR LOWER(a.agent_id) LIKE LOWER(?))");
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
        if (groupId != null) {
            if (groupId == 0) where.append(" AND a.group_id IS NULL");
            else { where.append(" AND a.group_id = ?"); args.add(groupId); }
        }
        String cond = where.toString();
        Long total = jdbc.queryForObject(
                "SELECT count(*) FROM t_agent a" + cond, Long.class,
                args.toArray());

        List<Object> pageArgs = new ArrayList<>(args);
        pageArgs.add(size);
        pageArgs.add((page - 1) * size);
        List<Map<String, Object>> list = jdbc.queryForList("""
                SELECT a.group_id, (SELECT name FROM t_host_group g WHERE g.id=a.group_id) AS group_name, a.agent_id, a.hostname, a.ip, a.os_type, a.os_version, a.kernel, a.arch,
                       a.agent_version, a.status, a.protect_enabled, a.last_heartbeat,a.virus_execution_contract,a.virus_db_version,
                       a.isolation_status, a.isolation_command_id, a.isolation_error, a.isolation_updated_at, a.isolation_contract, a.isolation_automatic, a.isolation_lease_deadline,
                       (SELECT count(*) FROM t_asset_software s WHERE s.agent_id = a.agent_id) AS software_count,
                       (SELECT count(*) FROM t_asset_port p WHERE p.agent_id = a.agent_id) AS port_count,
                       (SELECT count(*) FROM t_asset_process p WHERE p.agent_id = a.agent_id) AS process_count,
                       (SELECT count(*) FROM t_asset_account c WHERE c.agent_id = a.agent_id) AS account_count,
                       (SELECT count(*) FROM t_asset_account c WHERE c.agent_id = a.agent_id AND c.risky = TRUE) AS risky_account_count,
                       (SELECT count(*) FROM t_asset_container c WHERE c.agent_id = a.agent_id) AS container_count,
                       (SELECT count(*) FROM t_alert ta WHERE ta.agent_id = a.agent_id AND ta.status IN (0,1)) AS alert_count,
                       (SELECT title FROM t_alert t2 WHERE t2.agent_id = a.agent_id
                        ORDER BY t2.last_time DESC LIMIT 1) AS last_event
                FROM t_agent a
                """ + cond + "\n" + """
                ORDER BY a.status, a.hostname, a.agent_id
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
                       isolation_status, isolation_command_id, isolation_error, isolation_updated_at, isolation_contract, isolation_automatic, isolation_lease_deadline,
                       distro_id, distro_version, software_inventory_source, software_identity_error, package_repair_contract,virus_execution_contract,virus_db_version,
                       software_collection_status, software_collection_error, software_attempted_at, software_succeeded_at
                FROM t_agent WHERE agent_id = ? AND status <> 4
                """, agentId);
        if (rows.isEmpty()) {
            return null;
        }
        var result=rows.get(0);
        result.put("collection_attempts", jdbc.queryForList("SELECT source,status,error,attempted_at,succeeded_at FROM t_asset_collection WHERE agent_id=? ORDER BY source", agentId));
        result.put("disks",jdbc.queryForList("SELECT mount,fs_type,total_bytes,used_bytes,updated_at FROM t_asset_disk WHERE agent_id=? ORDER BY mount",agentId));
        return result;
    }

    public List<Map<String, Object>> groups() {
        return jdbc.queryForList("""
                SELECT g.id, g.name, count(a.id) AS host_count
                FROM t_host_group g
                LEFT JOIN t_agent a ON a.group_id = g.id AND a.status <> 4
                GROUP BY g.id, g.name ORDER BY g.id
                """);
    }

    @Transactional
    public Map<String,Object> saveGroup(Long id, String name) {
        if (name == null || name.isBlank() || name.trim().length() > 128) throw new IllegalArgumentException("分组名称须为 1–128 个字符");
        name = name.trim();
        if (id == null) jdbc.update("INSERT INTO t_host_group(name) VALUES(?)", name);
        else if (jdbc.update("UPDATE t_host_group SET name=? WHERE id=?", name, id) != 1) throw new IllegalArgumentException("分组不存在");
        return jdbc.queryForMap("SELECT id,name FROM t_host_group WHERE name=?", name);
    }

    @Transactional
    public void deleteGroup(long id) {
        jdbc.update("UPDATE t_agent SET group_id=NULL WHERE group_id=?", id);
        if (jdbc.update("DELETE FROM t_host_group WHERE id=?", id) != 1) throw new IllegalArgumentException("分组不存在");
    }

    @Transactional
    public void assignGroup(String agentId, Long groupId) {
        if (groupId != null && groupId != 0 && jdbc.queryForObject("SELECT count(*) FROM t_host_group WHERE id=?", Integer.class, groupId) != 1) throw new IllegalArgumentException("分组不存在");
        if (jdbc.update("UPDATE t_agent SET group_id=? WHERE agent_id=? AND status<>4", groupId == null || groupId == 0 ? null : groupId, agentId) != 1) throw new IllegalArgumentException("主机不存在");
    }

    public Map<String,Object> runtime(String agentId) {
        return new com.alinksec.service.heartbeat.HostRuntimeService(jdbc).snapshot(agentId);
    }

    public List<Map<String, Object>> software(String agentId, String keyword, int page, int size) {
        String normalizedKeyword = blankToNull(keyword);
        return jdbc.queryForList("""
                SELECT name, version, vendor, install_time, source, architecture
                FROM t_asset_software WHERE agent_id = ?
                  AND (CAST(? AS TEXT) IS NULL OR LOWER(name) LIKE LOWER('%' || ? || '%'))
                ORDER BY name, source, architecture, version LIMIT ? OFFSET ?
                """, agentId, normalizedKeyword, normalizedKeyword, size, (page - 1) * size);
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
