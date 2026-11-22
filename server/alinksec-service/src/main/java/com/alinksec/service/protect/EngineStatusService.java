package com.alinksec.service.protect;

import com.alinksec.common.util.JsonUtils;
import com.alinksec.service.baseline.ScapReadiness;
import com.alinksec.service.virus.ClamavService;
import com.alinksec.service.virus.YaraService;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.function.BiFunction;

/** Fleet readiness uses each engine's own authenticated, recent runtime evidence. */
@Service
public class EngineStatusService {
    private final JdbcTemplate jdbc;
    public EngineStatusService(JdbcTemplate jdbc) { this.jdbc=jdbc; }

    public List<Map<String,Object>> engines() {
        long now=System.currentTimeMillis();
        var result=new ArrayList<Map<String,Object>>();
        for(var definition:List.of(
                List.of("process","恶意进程防护","进程行为规则匹配；尚无独立运行就绪证据"),
                List.of("file_tamper","关键文件防篡改","关键文件策略；尚无独立运行就绪证据"),
                List.of("login","登录防护策略","登录策略；运行观测见 Windows 登录采集"),
                List.of("decoy","勒索诱饵防护","诱饵策略；文件事件覆盖不等于可信写入者证据"))) {
            var counts=new TreeMap<String,Long>();
            jdbc.query("SELECT status,protect_enabled FROM t_agent WHERE deleted=FALSE AND status<>4",(org.springframework.jdbc.core.RowCallbackHandler)rs->{
                String state=rs.getInt("status")==0?"unknown":rs.getInt("status")!=1?"offline":!rs.getBoolean("protect_enabled")?"disabled":"unknown";
                counts.merge(state,1L,Long::sum);
            });
            result.add(summary(definition.get(0),definition.get(1),definition.get(2),counts,"unreported"));
        }
        result.add(reported("file_watch","文件事件监控","近期文件监控覆盖，不证明自动恢复或写入者归因", "t_file_watch_status",false,FileWatchService::state,now));
        result.add(reported("windows_login","Windows 登录采集","Security 日志采集覆盖，不以策略回执代替就绪", "t_windows_login_status",true,WindowsLoginService::state,now));
        result.add(reported("clamav","ClamAV 扫描引擎","近期原生引擎探测；不代表实时防护已启用", "t_clamav_status",false,ClamavService::state,now));
        result.add(reported("yara","YARA 扫描引擎","近期原生规则引擎探测；不代表所有文件已扫描", "t_yara_status",false,YaraService::state,now));
        result.add(reported("scap","SCAP 核查引擎","近期原生运行探测，不代表合规核查结论", "t_scap_status",false,ScapReadiness::state,now));
        return result;
    }

    private Map<String,Object> reported(String key,String name,String description,String table,boolean windows,
                                        BiFunction<Map<String,Object>,Long,String> classifier,long now) {
        var counts=new TreeMap<String,Long>();
        // Constant table names above; stream every applicable host, without a UI page limit.
        jdbc.query("SELECT a.status,a.protect_enabled,s.contract,s.coverage,s.observed_at FROM t_agent a LEFT JOIN "+table+
                " s ON s.agent_id=a.agent_id WHERE a.deleted=FALSE AND a.status<>4"+(windows?" AND a.os_type=2":""),
                (org.springframework.jdbc.core.RowCallbackHandler)rs->{
                    var row=new HashMap<String,Object>();
                    for(String field:List.of("status","contract","coverage","observed_at"))row.put(field,rs.getObject(field));
                    String state;
                    if(rs.getInt("status")==0)state="unknown";
                    else if(rs.getInt("status")!=1)state="offline";
                    else if(!rs.getBoolean("protect_enabled"))state="disabled";
                    else if(row.get("contract")==null)state="unknown";
                    else state=classifier.apply(row,now);
                    var detail=JsonUtils.read(row.get("coverage")==null?"{}":row.get("coverage").toString());
                    if(key.equals("file_watch")&&state.equals("watching"))state=detail.path("roots").asLong()>0&&detail.path("watches").asLong()>0?"ready":"unavailable";
                    if(key.equals("windows_login")&&state.equals("polling"))state=detail.path("audit_success").asBoolean()&&detail.path("audit_failure").asBoolean()?"ready":"degraded";
                    if(key.equals("scap")&&state.equals("running"))state="ready";
                    counts.merge(state,1L,Long::sum);
                });
        return summary(key,name,description,counts,"reported-runtime");
    }

    private static Map<String,Object> summary(String key,String name,String description,Map<String,Long> counts,String evidence) {
        long total=counts.values().stream().mapToLong(Long::longValue).sum(),ready=counts.getOrDefault("ready",0L);
        String state=total==0?"unknown":ready==total?"ready":ready>0?"partial":counts.size()==1?counts.keySet().iterator().next():"degraded";
        return Map.of("key",key,"name",name,"desc",description,"builtin",true,"status",state,
                "coverage",total==0?0:ready*100/total,"ready",ready,"total",total,"counts",counts,"evidence",evidence);
    }
}
