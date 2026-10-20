package com.alinksec.service.query;

import com.alinksec.service.config.DatabaseDialect;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 病毒查杀查询：任务 / 检出 / 特征库 / 白名单。
 */
@Service
public class VirusQueryService {

    private final JdbcTemplate jdbc;
    private final DatabaseDialect database;

    public VirusQueryService(JdbcTemplate jdbc, DatabaseDialect database) {
        this.jdbc = jdbc;
        this.database = database;
    }

    public Map<String, Object> tasks(int page, int size) {
        page=Math.max(1,page); size=Math.max(1,Math.min(size,100));
        Long total = jdbc.queryForObject("SELECT count(*) FROM t_virus_scan_task", Long.class);
        List<Map<String, Object>> list = jdbc.queryForList("""
                SELECT t.id, t.task_no, t.name, t.mode, CAST(t.scope AS TEXT) AS scope, t.status, t.progress,
                       (SELECT count(*) FROM t_virus_finding f WHERE f.task_id = t.id) AS findings,
                       t.created_at, t.started_at, t.finished_at,t.expected_db_version,t.scan_engine,
                       (SELECT count(*) FROM t_virus_task_agent m WHERE m.task_id=t.id) AS total_hosts,
                       (SELECT count(*) FROM t_virus_task_agent m WHERE m.task_id=t.id AND m.state='pending') AS pending_hosts,
                       (SELECT count(*) FROM t_virus_task_agent m WHERE m.task_id=t.id AND m.state='complete') AS complete_hosts
                FROM t_virus_scan_task t ORDER BY t.id DESC LIMIT ? OFFSET ?
                """, size, (page - 1) * size);
        Map<String, Object> result = new HashMap<>();
        result.put("list", list);
        result.put("total", total == null ? 0 : total);
        return result;
    }

    public Map<String, Object> findings(Integer status, String agentId, int page, int size) {
        page=Math.max(1,page); size=Math.max(1,Math.min(size,100));
        StringBuilder where = new StringBuilder(" WHERE 1=1");
        if (status != null) {
            where.append(" AND f.status = ").append(status);
        }
        if (agentId != null && !agentId.isBlank()) {
            where.append(" AND f.agent_id = '").append(agentId.replace("'", "''")).append("'");
        }
        String cond = where.toString();

        Long total = jdbc.queryForObject(
                "SELECT count(*) FROM t_virus_finding f" + cond, Long.class);
        List<Map<String, Object>> list = jdbc.queryForList("""
                SELECT f.id, f.task_id, f.agent_id, a.hostname, f.path, f.name, f.sha256, f.size,
                       f.engine, f.severity, f.action_taken, f.status, f.created_at,f.quarantine_id,f.action_error,
                       (SELECT count(*) FROM t_virus_action_evidence h WHERE h.finding_id=f.id AND h.state='pending') AS pending_actions,
                       (SELECT h.state FROM t_virus_action_evidence h WHERE h.finding_id=f.id ORDER BY h.created_at DESC,h.id DESC LIMIT 1) AS last_action_state,
                       (SELECT h.error FROM t_virus_action_evidence h WHERE h.finding_id=f.id ORDER BY h.created_at DESC,h.id DESC LIMIT 1) AS last_action_error,
                       (SELECT count(*) FROM t_virus_whitelist w WHERE w.type='hash' AND lower(w.value)=lower(f.sha256)) AS hash_whitelisted,
                       a.virus_execution_contract
                FROM t_virus_finding f LEFT JOIN t_agent a ON a.agent_id = f.agent_id""" + cond
                + " ORDER BY f.created_at DESC LIMIT ? OFFSET ?", size, (page - 1) * size);
        Map<String, Object> result = new HashMap<>();
        result.put("list", list);
        result.put("total", total == null ? 0 : total);
        return result;
    }

    public List<Map<String, Object>> dbVersions() {
        return jdbc.queryForList("""
                SELECT id, db_version, sha256, size, hash_count, rule_count, imported_at
                FROM t_virus_db ORDER BY id DESC
                """);
    }

    public List<Map<String, Object>> whitelist() {
        return jdbc.queryForList("""
                SELECT id, type, value, remark, created_at
                FROM t_virus_whitelist ORDER BY id DESC
                """);
    }

    public Map<String, Object> stats() {
        Map<String, Object> result = new HashMap<>();
        result.put("findings30d", jdbc.queryForObject(
                "SELECT count(*) FROM t_virus_finding WHERE created_at >= ?",
                Long.class, database.startOfDayDaysAgo(30)));
        result.put("quarantined", jdbc.queryForObject(
                "SELECT count(*) FROM t_virus_finding WHERE status IN (1,2)", Long.class));
        result.put("todo",jdbc.queryForObject("SELECT count(*) FROM t_virus_finding WHERE status=0",Long.class));
        result.put("realtime",jdbc.queryForMap("SELECT realtime_enabled,realtime_action,revision FROM t_virus_state WHERE id=1"));
        result.put("latestDb", jdbc.queryForList("""
                SELECT db_version, hash_count, rule_count, imported_at
                FROM t_virus_db ORDER BY id DESC LIMIT 1
                """));
        return result;
    }

    public List<Map<String,Object>> taskEvidence(long task) {
        var rows=jdbc.queryForList("SELECT agent_id,state,evidence,evidence_sha256,received_at,late,expected_engine_version FROM t_virus_task_agent WHERE task_id=? ORDER BY agent_id",task);
        for(var row:rows) {
            String raw=String.valueOf(row.get("evidence"));
            if(!raw.isBlank()) { var json=com.alinksec.common.util.JsonUtils.read(raw); if(json.isObject()) ((com.fasterxml.jackson.databind.node.ObjectNode)json).remove("report_b64"); row.put("evidence",json); }
        }
        return rows;
    }
    public List<Map<String,Object>> actionHistory(long finding) {
        var history=new java.util.ArrayList<>(jdbc.queryForList("SELECT h.id,h.action,h.state,h.error,h.actor,u.username,h.command_id,h.created_at,h.finished_at,h.request_evidence,h.receipt FROM t_virus_action_evidence h LEFT JOIN t_user u ON u.id=h.actor WHERE h.finding_id=? ORDER BY h.created_at DESC,h.id DESC LIMIT 100",finding));
        for(var entry:history) for(String field:List.of("request_evidence","receipt")) {
            String raw=(String)entry.get(field); if(!raw.isBlank()) entry.put(field,com.alinksec.common.util.JsonUtils.read(raw));
        }
        for(var row:jdbc.queryForList("SELECT initial_evidence,created_at FROM t_virus_finding WHERE id=? AND initial_evidence<>''",finding)) {
            var initial=com.alinksec.common.util.JsonUtils.read((String)row.get("initial_evidence"));
            history.add(Map.of("action",initial.path("action").asText(),"state","observed","error",initial.path("action_error").asText(),"username","Agent 首次检出","command_id",initial.path("quarantine_id").asText(),"created_at",row.get("created_at"),"evidence",initial));
        }
        return history;
    }
}
