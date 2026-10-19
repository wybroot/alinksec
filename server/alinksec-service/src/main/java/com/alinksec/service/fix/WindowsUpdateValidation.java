package com.alinksec.service.fix;

import com.alinksec.common.util.JsonUtils;
import com.alinksec.service.config.DatabaseDialect;
import org.springframework.jdbc.core.JdbcTemplate;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/** The same immutable scan/host/update checks apply at creation and every delivery. */
final class WindowsUpdateValidation {
    private final JdbcTemplate jdbc;
    private final DatabaseDialect database;
    WindowsUpdateValidation(JdbcTemplate jdbc,DatabaseDialect database) { this.jdbc=jdbc; this.database=database; }

    Map<String,Object> current(String agent,long candidate) {
        var hosts=jdbc.queryForList("SELECT os_type,windows_update_contract,windows_update_scan_id FROM t_agent WHERE agent_id=? AND deleted=false",agent);
        if(hosts.size()!=1 || ((Number)hosts.get(0).get("os_type")).intValue()!=2 || ((Number)hosts.get(0).get("windows_update_contract")).intValue()!=1)
            throw new IllegalArgumentException("主机未声明 Windows 原生更新执行能力，请更新 Agent 并刷新主机状态");
        var rows=jdbc.queryForList("""
                SELECT c.scan_id,c.eligible,c.metadata,s.status,s.host_identity,s.received_at,s.snapshot
                FROM t_windows_update_candidate c JOIN t_windows_update_scan s ON s.scan_id=c.scan_id
                WHERE c.id=? AND c.agent_id=? AND s.agent_id=?
                """,candidate,agent,agent);
        if(rows.size()!=1) throw new IllegalArgumentException("更新目标不存在或不属于该主机");
        var row=rows.get(0);
        if(!Integer.valueOf(1).equals(((Number)row.get("eligible")).intValue()) || !"complete".equals(row.get("status"))
                || !row.get("scan_id").equals(hosts.get(0).get("windows_update_scan_id")) || row.get("received_at")==null
                || database.readOffsetDateTime(row.get("received_at")).toInstant().isBefore(Instant.now().minus(Duration.ofHours(24)))
                || JsonUtils.read(String.valueOf(row.get("snapshot"))).path("reboot_required").asBoolean(true))
            throw new IllegalArgumentException("更新发现已过期、已被新扫描替代、目标不可自动安装或系统待重启，请重新发现并审批");
        return new LinkedHashMap<>(Map.of("contract",1,"host_identity",row.get("host_identity"),"update",JsonUtils.read(String.valueOf(row.get("metadata")),Map.class)));
    }
    Map<String,Object> validate(Map<String,Object> target) {
        var payload=new LinkedHashMap<>(JsonUtils.read(String.valueOf(target.get("fix_payload")),Map.class));
        var expected=current(String.valueOf(target.get("agent_id")),Long.parseLong(String.valueOf(target.get("ref_id"))));
        payload.remove("dispatch_deadline_unix_ms");
        if(!payload.equals(expected)) throw new IllegalArgumentException("更新任务目标与当前发现证据不一致，请重新发现并审批");
        return payload;
    }
}
