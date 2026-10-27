package com.alinksec.service.virus;

import com.alinksec.common.util.JsonUtils;
import com.alinksec.proto.RptHeartbeat;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import java.util.*;

/** Readiness from authenticated Agent heartbeats; never a file-coverage certificate. */
@Service
public class YaraService {
    private final JdbcTemplate jdbc;
    private static final Set<String> STATES=Set.of("starting","disabled","ready","unavailable");
    private static final Set<String> ISSUES=Set.of("","yara_disabled","yara_not_built","yara_invalid_config","yara_timeout","yara_rules_unavailable","yara_rules_changed","yara_version_changed","yara_worker_failed","yara_worker_protocol","yara_resource_limit","yara_compile_error","yara_empty_rules","yara_rule_limit","yara_match_limit","yara_file_limit","yara_scan_error","yara_read_failed_or_changed");
    public YaraService(JdbcTemplate jdbc){this.jdbc=jdbc;}
    public static boolean validVersion(String v) {
        String prefix="YARA 4.5.8/sha256:"; return v!=null && v.startsWith(prefix) && v.substring(prefix.length()).matches("[0-9a-f]{64}");
    }
    public static boolean validRules(List<String> ids) {
        return ids!=null&&!ids.isEmpty()&&ids.size()<=32&&new HashSet<>(ids).size()==ids.size()
            &&ids.stream().allMatch(id->id!=null&&id.matches("[A-Za-z_][A-Za-z0-9_]{0,127}"));
    }
    public static boolean validRules(com.fasterxml.jackson.databind.JsonNode ids) {
        if(!ids.isArray())return false;
        List<String> values=new ArrayList<>();
        for(var id:ids){if(!id.isTextual())return false;values.add(id.asText());}
        return validRules(values);
    }
    public void heartbeat(String agent,RptHeartbeat hb) {
        int contract=hb.getYaraContract()==1?1:0;
        String data="{}";
        if(contract==1) {
            if(hb.getYaraStatus().length()>2048)throw new IllegalArgumentException("YARA status too large");
            var input=JsonUtils.read(hb.getYaraStatus());
            String state=input.path("state").asText(),version=input.path("version").asText();
            if(!input.isObject() || !STATES.contains(state) || !ISSUES.contains(input.path("last_issue").asText()) || !input.path("realtime").isBoolean() || !input.path("version").isTextual() || !version.isEmpty()&&!validVersion(version) || state.equals("ready")&&!validVersion(version))throw new IllegalArgumentException("invalid YARA readiness");
            var output=new com.fasterxml.jackson.databind.ObjectMapper().createObjectNode();
            for(String key:List.of("state","version","last_issue"))output.put(key,input.path(key).asText());
            output.put("realtime",input.path("realtime").asBoolean());
            for(String key:List.of("observed_at","last_scan_at","scans","failures")) {
                var v=input.path(key);
                if(!v.isIntegralNumber()||!v.canConvertToLong()||v.asLong()<0)throw new IllegalArgumentException("invalid YARA counter");
                if((key.equals("observed_at")||key.equals("last_scan_at"))&&v.asLong()>4102444800L)throw new IllegalArgumentException("invalid YARA time");
                output.put(key,v.asLong());
            }
            if(output.path("failures").asLong()>output.path("scans").asLong())throw new IllegalArgumentException("invalid YARA failures");
            if(input.has("scan_failures")) {
                var failures=input.path("scan_failures");
                var counts=failures.path("counts");
                var at=failures.path("last_at");
                String issue=failures.path("last_issue").asText();
                if(!failures.isObject()||!counts.isObject()||!at.isIntegralNumber()||!at.canConvertToLong()||at.asLong()<0||at.asLong()>output.path("last_scan_at").asLong()||!failures.path("last_issue").isTextual()||!ISSUES.contains(issue))throw new IllegalArgumentException("invalid YARA scan failures");
                var clean=output.putObject("scan_failures");
                clean.put("last_at",at.asLong());clean.put("last_issue",issue);
                var cleanCounts=clean.putObject("counts");
                long total=0,expected=output.path("failures").asLong();
                var fields=counts.fields();
                while(fields.hasNext()) {
                    var entry=fields.next();var value=entry.getValue();
                    if(entry.getKey().isEmpty()||!ISSUES.contains(entry.getKey())||!value.isIntegralNumber()||!value.canConvertToLong()||value.asLong()<=0||value.asLong()>expected-total)throw new IllegalArgumentException("invalid YARA scan failure count");
                    total+=value.asLong();cleanCounts.put(entry.getKey(),value.asLong());
                }
                if(total!=expected||expected==0&&(at.asLong()!=0||!issue.isEmpty())||expected>0&&(at.asLong()==0||issue.isEmpty()||!cleanCounts.has(issue)))throw new IllegalArgumentException("inconsistent YARA scan failures");
            }
            if(input.has("update")) {
                var update=input.path("update");
                if(!update.isObject()||!update.path("enabled").isBoolean())throw new IllegalArgumentException("invalid YARA update status");
                var clean=output.putObject("update");clean.put("enabled",update.path("enabled").asBoolean());
                String issue=update.path("last_issue").asText();
                if(!update.path("last_issue").isTextual()||!ISSUES.contains(issue)&&!Set.of("yara_update_download","yara_update_storage").contains(issue))throw new IllegalArgumentException("invalid YARA update issue");
                clean.put("last_issue",issue);
                for(String key:List.of("checked_at","success_at","changed_at","next_check_at")) {
                    var value=update.path(key);
                    if(!value.isIntegralNumber()||!value.canConvertToLong()||value.asLong()<0||value.asLong()>4102444800L)throw new IllegalArgumentException("invalid YARA update time");
                    clean.put(key,value.asLong());
                }
                if(clean.path("changed_at").asLong()>clean.path("success_at").asLong()||clean.path("success_at").asLong()>clean.path("checked_at").asLong())throw new IllegalArgumentException("inconsistent YARA update times");
            }
            data=output.toString();
        }
        jdbc.update("INSERT INTO t_yara_status(agent_id,contract,coverage,observed_at) VALUES(?,?,?,?) ON CONFLICT(agent_id) DO UPDATE SET contract=excluded.contract,coverage=excluded.coverage,observed_at=excluded.observed_at",agent,contract,data,System.currentTimeMillis());
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
        var rows=jdbc.queryForList("SELECT a.status,COALESCE(s.contract,0) AS contract,s.coverage,s.observed_at FROM t_agent a LEFT JOIN t_yara_status s ON s.agent_id=a.agent_id WHERE a.agent_id=? AND a.deleted=false",agent);
        if(rows.size()!=1||!state(rows.get(0),System.currentTimeMillis()).equals("ready"))throw new IllegalArgumentException("目标主机的 YARA 尚未就绪，请检查引擎状态并等待心跳");
        String v=JsonUtils.read(rows.get(0).get("coverage").toString()).path("version").asText();
        if(!validVersion(v))throw new IllegalArgumentException("YARA 引擎版本无效");
        return v;
    }
    public Map<String,Object> status(int page,int size) {
        if(page<1||page>100000||size<1||size>100)throw new IllegalArgumentException("invalid pagination");
        var rows=jdbc.queryForList("SELECT a.agent_id,a.hostname,a.ip,a.os_type,a.status,COALESCE(s.contract,0) AS contract,s.coverage,s.observed_at FROM t_agent a LEFT JOIN t_yara_status s ON s.agent_id=a.agent_id WHERE a.deleted=false AND a.status<>4 ORDER BY a.hostname,a.agent_id LIMIT ? OFFSET ?",size,(page-1)*size);
        long now=System.currentTimeMillis();
        for(var row:rows) { row.put("state",state(row,now));row.put("coverage",JsonUtils.read(row.get("coverage")==null?"{}":row.get("coverage").toString(),Object.class)); }
        Long total=jdbc.queryForObject("SELECT count(*) FROM t_agent WHERE deleted=false AND status<>4",Long.class);
        return Map.of("items",rows,"total",total==null?0:total,"page",page,"page_size",size);
    }
}
