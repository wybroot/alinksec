package com.alinksec.service.virus;

import com.alinksec.common.util.JsonUtils;
import com.alinksec.proto.RptHeartbeat;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import java.util.*;

/** Readiness from authenticated Agent heartbeats; never a file-coverage certificate. */
@Service
public class ClamavService {
    private final JdbcTemplate jdbc;
    private static final Set<String> STATES=Set.of("starting","disabled","ready","unavailable");
    private static final Set<String> ISSUES=Set.of("","clamav_disabled","clamav_invalid_config","clamav_timeout","clamav_unavailable","clamav_tls_identity","clamav_protocol","clamav_version_changed","clamav_file_limit","clamav_incomplete","clamav_scan_error");
    public ClamavService(JdbcTemplate jdbc){this.jdbc=jdbc;}
    public static boolean validVersion(String v) {
        return v!=null && v.startsWith("ClamAV ") && v.length()<=256 && v.codePoints().noneMatch(Character::isISOControl);
    }
    public void heartbeat(String agent,RptHeartbeat hb) {
        int contract=hb.getClamavContract()==1?1:0;
        String data="{}";
        if(contract==1) {
            if(hb.getClamavStatus().length()>2048)throw new IllegalArgumentException("ClamAV status too large");
            var input=JsonUtils.read(hb.getClamavStatus());
            String state=input.path("state").asText(),version=input.path("version").asText();
            if(!input.isObject() || !STATES.contains(state) || !ISSUES.contains(input.path("last_issue").asText()) || !input.path("realtime").isBoolean() || !input.path("version").isTextual() || !version.isEmpty()&&!validVersion(version) || state.equals("ready")&&!validVersion(version))throw new IllegalArgumentException("invalid ClamAV readiness");
            var output=new com.fasterxml.jackson.databind.ObjectMapper().createObjectNode();
            for(String key:List.of("state","version","last_issue"))output.put(key,input.path(key).asText());
            output.put("realtime",input.path("realtime").asBoolean());
            for(String key:List.of("observed_at","last_scan_at","scans","failures")) {
                var v=input.path(key);
                if(!v.isIntegralNumber()||!v.canConvertToLong()||v.asLong()<0)throw new IllegalArgumentException("invalid ClamAV counter");
                if((key.equals("observed_at")||key.equals("last_scan_at"))&&v.asLong()>4102444800L)throw new IllegalArgumentException("invalid ClamAV time");
                output.put(key,v.asLong());
            }
            if(output.path("failures").asLong()>output.path("scans").asLong())throw new IllegalArgumentException("invalid ClamAV failures");
            data=output.toString();
        }
        jdbc.update("INSERT INTO t_clamav_status(agent_id,contract,coverage,observed_at) VALUES(?,?,?,?) ON CONFLICT(agent_id) DO UPDATE SET contract=excluded.contract,coverage=excluded.coverage,observed_at=excluded.observed_at",agent,contract,data,System.currentTimeMillis());
    }
    private static String state(Map<String,Object> row,long now) {
        int contract=((Number)row.get("contract")).intValue();
        var d=JsonUtils.read(row.get("coverage")==null?"{}":row.get("coverage").toString());
        long seen=row.get("observed_at") instanceof Number n?n.longValue():0;
        long probe=d.path("observed_at").asLong()*1000;
        if(((Number)row.get("status")).intValue()!=1)return "offline";
        if(contract!=1)return "unsupported";
        if(now-seen>90000||seen>now+30000)return "stale";
        String state=d.path("state").asText("unavailable");
        if(state.equals("ready")&&(probe==0||now-probe>90000||probe>now+30000))return "stale";
        return state;
    }
    public static String requireReady(JdbcTemplate jdbc,String agent) {
        var rows=jdbc.queryForList("SELECT a.status,COALESCE(s.contract,0) AS contract,s.coverage,s.observed_at FROM t_agent a LEFT JOIN t_clamav_status s ON s.agent_id=a.agent_id WHERE a.agent_id=? AND a.deleted=false",agent);
        if(rows.size()!=1||!state(rows.get(0),System.currentTimeMillis()).equals("ready"))throw new IllegalArgumentException("目标主机的 ClamAV 尚未就绪，请检查引擎状态并等待心跳");
        String v=JsonUtils.read(rows.get(0).get("coverage").toString()).path("version").asText();
        if(!validVersion(v))throw new IllegalArgumentException("ClamAV 引擎版本无效");
        return v;
    }
    public Map<String,Object> status(int page,int size) {
        if(page<1||page>100000||size<1||size>100)throw new IllegalArgumentException("invalid pagination");
        var rows=jdbc.queryForList("SELECT a.agent_id,a.hostname,a.ip,a.os_type,a.status,COALESCE(s.contract,0) AS contract,s.coverage,s.observed_at FROM t_agent a LEFT JOIN t_clamav_status s ON s.agent_id=a.agent_id WHERE a.deleted=false AND a.status<>4 ORDER BY a.hostname,a.agent_id LIMIT ? OFFSET ?",size,(page-1)*size);
        long now=System.currentTimeMillis();
        for(var row:rows) { row.put("state",state(row,now));row.put("coverage",JsonUtils.read(row.get("coverage")==null?"{}":row.get("coverage").toString(),Object.class)); }
        Long total=jdbc.queryForObject("SELECT count(*) FROM t_agent WHERE deleted=false AND status<>4",Long.class);
        return Map.of("items",rows,"total",total==null?0:total,"page",page,"page_size",size);
    }
}
