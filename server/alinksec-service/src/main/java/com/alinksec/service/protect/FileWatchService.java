package com.alinksec.service.protect;

import com.alinksec.common.util.JsonUtils;
import com.alinksec.proto.RptHeartbeat;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Authenticated heartbeat evidence, independent of policy delivery ACKs. */
@Service
public class FileWatchService {
    private final JdbcTemplate jdbc;
    private static final Set<String> STATES=Set.of("starting","disabled","watching","degraded");
    private static final Set<String> ISSUES=Set.of("","unsupported","queue_overflow","kernel_overflow_or_error","watcher_unavailable","watcher_closed","root_limit","watch_budget","unsafe_path","root_unavailable","directory_unreadable","watch_add_failed","path_changed","path_limit");
    public FileWatchService(JdbcTemplate jdbc){this.jdbc=jdbc;}

    public void heartbeat(String agentId,RptHeartbeat hb) {
        int contract=hb.getFileWatchContract()==1?1:0;
        String data="{}";
        if(contract==1) {
            if(hb.getFileWatchStatus().length()>4096)throw new IllegalArgumentException("file watch status too large");
            var input=JsonUtils.read(hb.getFileWatchStatus());
            if(!input.isObject() || !STATES.contains(input.path("state").asText()) || !ISSUES.contains(input.path("issue").asText()) || !ISSUES.contains(input.path("recovery_issue").asText()) || !Set.of("inotify","ReadDirectoryChangesW","unsupported").contains(input.path("backend").asText()) || !input.path("recovering").isBoolean())throw new IllegalArgumentException("invalid file watch coverage");
            var output=new com.fasterxml.jackson.databind.ObjectMapper().createObjectNode();
            for(String key:List.of("state","issue","recovery_issue","backend"))output.put(key,input.path(key).asText());
            output.put("recovering",input.path("recovering").asBoolean());
            for(String key:List.of("roots","watches","pending","dropped","gaps","last_event_at","last_sync_at","last_sweep_at")) {
                var v=input.path(key);
                if(!v.isIntegralNumber() || !v.canConvertToLong() || v.asLong()<0)throw new IllegalArgumentException("invalid file watch counter");
                if(key.equals("watches")&&v.asLong()>1024 || key.equals("pending")&&v.asLong()>2048)throw new IllegalArgumentException("invalid file watch bound");
                output.put(key,v.asLong());
            }
            data=output.toString();
        }
        jdbc.update("""
                INSERT INTO t_file_watch_status(agent_id,contract,coverage,observed_at) VALUES(?,?,?,?)
                ON CONFLICT(agent_id) DO UPDATE SET contract=excluded.contract,coverage=excluded.coverage,observed_at=excluded.observed_at
                """,agentId,contract,data,System.currentTimeMillis());
    }

    public Map<String,Object> status(int page,int pageSize) {
        if(page<1 || page>100000 || pageSize<1 || pageSize>100)throw new IllegalArgumentException("invalid pagination");
        var rows=jdbc.queryForList("""
                SELECT a.agent_id,a.hostname,a.ip,a.os_type,a.status,a.last_heartbeat,
                       COALESCE(s.contract,0) AS contract,s.coverage,s.observed_at
                FROM t_agent a LEFT JOIN t_file_watch_status s ON s.agent_id=a.agent_id
                WHERE a.status<>4 ORDER BY a.hostname,a.agent_id LIMIT ? OFFSET ?
                """,pageSize,(page-1)*pageSize);
        long now=System.currentTimeMillis();
        for(var row:rows) {
            var d=JsonUtils.read(row.get("coverage")==null?"{}":String.valueOf(row.get("coverage")));
            int contract=((Number)row.get("contract")).intValue();
            long seen=row.get("observed_at") instanceof Number n?n.longValue():0;
            long synced=d.path("last_sync_at").asLong();
            String state=contract!=1?"unsupported":d.path("state").asText("unknown");
            if(((Number)row.get("status")).intValue()!=1)state="offline";
            else if(contract==1 && (now-seen>90000 || seen>now+30000))state="stale";
            else if(contract==1 && !Set.of("starting","disabled").contains(state) && (synced==0 || now-synced>90000 || synced>now+30000))state="stalled";
            else if(state.equals("watching") && !d.path("recovery_issue").asText().isEmpty())state="degraded";
            else if(state.equals("watching") && d.path("recovering").asBoolean())state="recovering";
            row.put("coverage",JsonUtils.read(d.toString(),Object.class));row.put("state",state);
        }
        Long total=jdbc.queryForObject("SELECT count(*) FROM t_agent WHERE status<>4",Long.class);
        return Map.of("items",rows,"total",total==null?0:total,"page",page,"page_size",pageSize);
    }
}
