package com.alinksec.service.protect;

import com.alinksec.common.util.JsonUtils;
import com.alinksec.proto.Report;
import com.alinksec.proto.RptHeartbeat;
import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Explicit collection coverage is independent of a successful policy ACK. */
@Service
public class WindowsLoginService {
    private final JdbcTemplate jdbc;
    private static final Set<String> STATES=Set.of("starting","disabled","polling","behind","degraded","failed");
    private static final Set<String> ISSUES=Set.of("","journal_invalid","persist_failed","audit_query_failed","security_read_failed","event_query_failed","event_order_invalid","log_gap","block_failed","firewall_cleanup_failed","audit_disabled","backlog","event_buffer_full","event_retention_exceeded");
    public WindowsLoginService(JdbcTemplate jdbc){this.jdbc=jdbc;}

    public void heartbeat(String agentId,RptHeartbeat hb) {
        int contract=hb.getWindowsLoginContract()==1?1:0;
        String data="{}";
        if(contract==1) {
            if(hb.getWindowsLoginStatus().length()>8192) throw new IllegalArgumentException("Windows login status too large");
            var input=JsonUtils.read(hb.getWindowsLoginStatus());
            if(!input.isObject() || !STATES.contains(input.path("state").asText()) || !ISSUES.contains(input.path("issue").asText())) throw new IllegalArgumentException("invalid Windows login status");
            var output=new com.fasterxml.jackson.databind.ObjectMapper().createObjectNode();
            output.put("state",input.path("state").asText());output.put("issue",input.path("issue").asText());
            for(String key:List.of("last_poll_at","last_event_at","cursor","active_blocks","block_failures","coverage_gaps","discarded_events","rules","retained_events")) {
                var value=input.path(key);
                if(!value.isIntegralNumber() || !value.canConvertToLong() || value.asLong()<0) throw new IllegalArgumentException("invalid Windows login counter");
                output.put(key,value.asLong());
            }
            for(String key:List.of("audit_success","audit_failure")) {
                if(!input.path(key).isBoolean())throw new IllegalArgumentException("invalid Windows audit coverage");
                output.put(key,input.path(key).asBoolean());
            }
            data=output.toString();
        }
        jdbc.update("""
                INSERT INTO t_windows_login_status(agent_id,contract,coverage,observed_at) VALUES(?,?,?,?)
                ON CONFLICT(agent_id) DO UPDATE SET contract=excluded.contract,coverage=excluded.coverage,observed_at=excluded.observed_at
                """,agentId,contract,data,System.currentTimeMillis());
    }

    public Map<String,Object> status(int page,int pageSize) {
        if(page<1 || page>100000 || pageSize<1 || pageSize>100) throw new IllegalArgumentException("invalid pagination");
        var rows=jdbc.queryForList("""
                SELECT a.agent_id,a.hostname,a.ip,a.status,a.policy_version,a.last_heartbeat,
                       COALESCE(s.contract,0) AS contract,s.coverage,s.observed_at
                FROM t_agent a LEFT JOIN t_windows_login_status s ON s.agent_id=a.agent_id
                WHERE a.os_type=2 AND a.status<>4 ORDER BY a.hostname,a.agent_id LIMIT ? OFFSET ?
                """,pageSize,(page-1)*pageSize);
        long now=System.currentTimeMillis();
        for(var row:rows) {
            var detail=JsonUtils.read(row.get("coverage")==null?"{}":String.valueOf(row.get("coverage")));
            int contract=((Number)row.get("contract")).intValue();
            long seen=row.get("observed_at") instanceof Number n?n.longValue():0;
            long lastPoll=detail.path("last_poll_at").asLong();
            String state=contract!=1?"unsupported":detail.path("state").asText("unknown");
            if(((Number)row.get("status")).intValue()!=1) state="offline";
            else if(contract==1 && (now-seen>90000 || seen>now+30000))state="stale";
            else if(contract==1 && !Set.of("disabled","starting").contains(state) && (lastPoll==0 || now-lastPoll>90000 || lastPoll>now+30000))state="stalled";
            row.put("coverage",JsonUtils.read(detail.toString(),Object.class));row.put("state",state);
        }
        Long total=jdbc.queryForObject("SELECT count(*) FROM t_agent WHERE os_type=2 AND status<>4",Long.class);
        return Map.of("items",rows,"total",total==null?0:total,"page",page,"page_size",pageSize);
    }

    public static boolean outcome(Report report) {
        return report.hasSecurityEvent() && report.getReportId().endsWith("-windows-login");
    }

    /** Called in the same transaction as the alert; duplicates still receive ACK. */
    public static boolean accept(JdbcTemplate jdbc,String agentId,Report report) {
        var event=report.getSecurityEvent();
        if(event.getDetail().length()>8192 || !report.getReportId().matches("[0-9a-f]{64}-windows-login") || event.getRuleId().isBlank() || event.getRuleId().length()>128 || event.getRuleName().length()>512) throw new IllegalArgumentException("invalid Windows login identity");
        var d=JsonUtils.read(event.getDetail());String id=d.path("id").asText();
        if(!report.getReportId().equals(id+"-windows-login") || !d.path("generation").asText().matches("[0-9a-f]{32}") || !d.path("record_id").isIntegralNumber() || d.path("record_id").asLong()<=0 || !Set.of(3,10).contains(d.path("logon_type").asInt()))throw new IllegalArgumentException("invalid Windows event fields");
        if(!Set.of("alert_only","blocked_ip","block_failed","block_expired").contains(event.getActionTaken()) || !Set.of("login_crack","login_anomaly").contains(event.getType()))throw new IllegalArgumentException("invalid Windows login outcome");
        boolean failed=event.getType().equals("login_crack");
        if(d.path("event_id").asInt()!=(failed?4625:4624) || !d.path("trigger").asText().equals(failed?"windows_bruteforce":"windows_off_hours") || (!failed&&!event.getActionTaken().equals("alert_only")))throw new IllegalArgumentException("invalid Windows event scope");
        return jdbc.update("INSERT INTO t_windows_login_receipt(agent_id,event_id) VALUES(?,?) ON CONFLICT(agent_id,event_id) DO NOTHING",agentId,report.getReportId())==1;
    }
}
