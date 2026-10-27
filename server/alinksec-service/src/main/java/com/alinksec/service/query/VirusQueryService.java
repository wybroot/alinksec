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
        return tasks(page,size,null,null,null);
    }
    public Map<String, Object> tasks(int page, int size,String agentId,String engine,Integer status) {
        page=Math.max(1,page); size=Math.max(1,Math.min(size,100));
        var args=new java.util.ArrayList<Object>();
        String where=" WHERE 1=1";
        if(agentId!=null && !agentId.isBlank()) { where+=" AND EXISTS (SELECT 1 FROM t_virus_task_agent m WHERE m.task_id=t.id AND m.agent_id=?)";args.add(agentId); }
        if(engine!=null && !engine.isBlank()) {
            if(!java.util.Set.of("builtin","clamav","yara").contains(engine))throw new IllegalArgumentException("扫描引擎无效");
            where+=" AND t.scan_engine=?";args.add(engine);
        }
        if(status!=null) {
            if(status<1 || status>3)throw new IllegalArgumentException("任务状态无效");
            where+=" AND t.status=?";args.add(status);
        }
        Long total = jdbc.queryForObject("SELECT count(*) FROM t_virus_scan_task t"+where, Long.class,args.toArray());
        args.add(size);args.add(((long)page-1)*size);
        List<Map<String, Object>> list = jdbc.queryForList("""
                SELECT t.id, t.task_no, t.name, t.mode, CAST(t.scope AS TEXT) AS scope, t.status, t.progress,
                       (SELECT count(*) FROM t_virus_finding f WHERE f.task_id = t.id) AS findings,
                       t.created_at, t.started_at, t.finished_at,t.expected_db_version,t.scan_engine,t.created_by,u.username,
                       (SELECT count(*) FROM t_virus_task_agent m WHERE m.task_id=t.id) AS total_hosts,
                       (SELECT count(*) FROM t_virus_task_agent m WHERE m.task_id=t.id AND m.state='pending') AS pending_hosts,
                       (SELECT count(*) FROM t_virus_task_agent m WHERE m.task_id=t.id AND m.state='complete') AS complete_hosts
                FROM t_virus_scan_task t LEFT JOIN t_user u ON u.id=t.created_by
                """+where+" ORDER BY t.id DESC LIMIT ? OFFSET ?",args.toArray());
        Map<String, Object> result = new HashMap<>();
        result.put("list", list);
        result.put("total", total == null ? 0 : total);
        return result;
    }

    public Map<String, Object> findings(Integer status, String agentId, int page, int size) {
        return findings(status,agentId,null,page,size);
    }
    public Map<String, Object> findings(Integer status, String agentId, Long taskId, int page, int size) {
        page=Math.max(1,page); size=Math.max(1,Math.min(size,100));
        var args=new java.util.ArrayList<Object>();
        StringBuilder where = new StringBuilder(" WHERE 1=1");
        if (status != null) {
            if(status<0 || status>4) throw new IllegalArgumentException("检出状态无效");
            where.append(" AND f.status = ?"); args.add(status);
        }
        if (agentId != null && !agentId.isBlank()) {
            where.append(" AND f.agent_id = ?"); args.add(agentId);
        }
        if(taskId!=null) {
            if(taskId<=0) throw new IllegalArgumentException("任务编号无效");
            where.append(" AND f.task_id = ?"); args.add(taskId);
        }
        String cond = where.toString();

        Long total = jdbc.queryForObject(
                "SELECT count(*) FROM t_virus_finding f" + cond, Long.class,args.toArray());
        args.add(size);args.add(((long)page-1)*size);
        List<Map<String, Object>> list = jdbc.queryForList("""
                SELECT f.id, f.task_id, f.agent_id, a.hostname, f.path, f.name, f.sha256, f.size,
                       f.engine, f.severity, f.action_taken, f.status, f.created_at,f.quarantine_id,f.action_error,
                       (SELECT count(*) FROM t_virus_action_evidence h WHERE h.finding_id=f.id AND h.state='pending') AS pending_actions,
                       (SELECT h.state FROM t_virus_action_evidence h WHERE h.finding_id=f.id ORDER BY h.created_at DESC,h.id DESC LIMIT 1) AS last_action_state,
                       (SELECT h.error FROM t_virus_action_evidence h WHERE h.finding_id=f.id ORDER BY h.created_at DESC,h.id DESC LIMIT 1) AS last_action_error,
                       (SELECT count(*) FROM t_virus_whitelist w WHERE w.type='hash' AND lower(w.value)=lower(f.sha256)) AS hash_whitelisted,
                       a.virus_execution_contract
                FROM t_virus_finding f LEFT JOIN t_agent a ON a.agent_id = f.agent_id""" + cond
                + " ORDER BY f.created_at DESC,f.id DESC LIMIT ? OFFSET ?", args.toArray());
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
        var rows=jdbc.queryForList("SELECT m.agent_id,a.hostname,a.ip,m.state,m.evidence,m.evidence_sha256,m.received_at,m.late,m.expected_engine_version FROM t_virus_task_agent m LEFT JOIN t_agent a ON a.agent_id=m.agent_id WHERE m.task_id=? ORDER BY m.agent_id",task);
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

    public List<Map<String,Object>> actionReceipts(List<String> ids) {
        if(ids==null || ids.isEmpty() || ids.size()>32 || ids.stream().anyMatch(id->id==null || !id.matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")) || ids.stream().distinct().count()!=ids.size())
            throw new IllegalArgumentException("请选择1至32个唯一处置编号");
        String slots=String.join(",",java.util.Collections.nCopies(ids.size(),"?"));
        var rows=jdbc.queryForList("SELECT h.id,h.finding_id,h.agent_id,a.hostname,h.action,h.state,h.error,h.actor,u.username,h.command_id,h.created_at,h.finished_at,h.request_evidence,h.receipt FROM t_virus_action_evidence h LEFT JOIN t_agent a ON a.agent_id=h.agent_id LEFT JOIN t_user u ON u.id=h.actor WHERE h.id IN ("+slots+") ORDER BY h.created_at,h.id",ids.toArray());
        for(var row:rows) for(String field:List.of("request_evidence","receipt")) {
            Object raw=row.get(field);
            row.put(field,raw instanceof String value && !value.isBlank()?com.alinksec.common.util.JsonUtils.read(value):null);
        }
        return rows;
    }
}
