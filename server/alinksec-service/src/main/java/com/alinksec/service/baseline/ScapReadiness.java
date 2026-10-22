package com.alinksec.service.baseline;

import com.alinksec.common.util.JsonUtils;
import com.alinksec.proto.RptHeartbeat;
import org.springframework.jdbc.core.JdbcTemplate;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Readiness is a recent native version probe, not a compliance conclusion. */
public final class ScapReadiness {
    private ScapReadiness() {}
    public static void heartbeat(JdbcTemplate jdbc,String agent,RptHeartbeat heartbeat) {
        int contract=heartbeat.getScapContract()==1?1:0;
        String data="{}";
        if (contract==1) {
            if (heartbeat.getScapStatus().length()>2048) throw new IllegalArgumentException("SCAP 状态过大");
            var input=JsonUtils.read(heartbeat.getScapStatus());
            String state=input.path("state").asText(),version=input.path("version").asText(),pin=input.path("runtime_sha256").asText();
            long observed=input.path("observed_at").asLong(-1),now=System.currentTimeMillis()/1000;
            if (!input.isObject() || !Set.of("starting","disabled","ready","running","unavailable").contains(state)
                    || !ScapStore.ISSUES.contains(input.path("last_issue").asText()) || !input.path("observed_at").isIntegralNumber()
                    || observed<0 || observed>now+30 || !version.isEmpty()&&!version.equals("5.15") || !pin.isEmpty()&&!ScapStore.hash(pin)
                    || Set.of("ready","running").contains(state)&&(!version.equals("5.15")||!ScapStore.hash(pin)||observed==0))
                throw new IllegalArgumentException("SCAP 原生就绪状态无效");
            var output=JsonUtils.mapper().createObjectNode();
            for (String key:List.of("state","version","runtime_sha256","last_issue")) output.put(key,input.path(key).asText());
            output.put("observed_at",observed);data=output.toString();
        }
        jdbc.update("INSERT INTO t_scap_status(agent_id,contract,coverage,observed_at) VALUES(?,?,?,?) ON CONFLICT(agent_id) DO UPDATE SET contract=excluded.contract,coverage=excluded.coverage,observed_at=excluded.observed_at",agent,contract,data,System.currentTimeMillis());
    }
    public static String state(Map<String,Object> row,long now) {
        if (((Number)row.get("status")).intValue()!=1) return "offline";
        if (!(row.get("contract") instanceof Number contractNumber)||contractNumber.intValue()!=1) return "unsupported";
        var coverage=JsonUtils.read(row.get("coverage")==null?"{}":row.get("coverage").toString());
        long received=row.get("observed_at") instanceof Number observedNumber?observedNumber.longValue():0;
        long probe=coverage.path("observed_at").asLong()*1000;
        if (now-received>90000 || received>now+30000) return "stale";
        String state=coverage.path("state").asText("unavailable");
        if (Set.of("ready","running").contains(state)&&(probe==0||now-probe>360000||probe>now+30000)) return "stale";
        return state;
    }
    public static Map<String,Object> requireReady(JdbcTemplate jdbc,String agent) {
        var row=ScapStore.one(jdbc,"SELECT a.agent_id,a.hostname,a.os_type,a.os_version,a.status,COALESCE(s.contract,0) AS contract,s.coverage,s.observed_at FROM t_agent a LEFT JOIN t_scap_status s ON a.agent_id=s.agent_id WHERE a.agent_id=? AND a.deleted=false",agent);
        if (!state(row,System.currentTimeMillis()).equals("ready")) throw new IllegalArgumentException("目标主机的 SCAP 原生引擎尚未就绪，请检查引擎并等待心跳");
        return row;
    }
    public static List<Map<String,Object>> targets(JdbcTemplate jdbc) {
        var rows=jdbc.queryForList("SELECT a.agent_id,a.hostname,a.os_type,a.os_version,a.status,COALESCE(s.contract,0) AS contract,s.coverage,s.observed_at FROM t_agent a LEFT JOIN t_scap_status s ON a.agent_id=s.agent_id WHERE a.deleted=false AND a.status<>4 ORDER BY a.hostname,a.agent_id LIMIT 1000");
        for (var row:rows) {row.put("state",state(row,System.currentTimeMillis()));row.put("coverage",JsonUtils.read(row.get("coverage")==null?"{}":row.get("coverage").toString()));}
        return rows;
    }
}
