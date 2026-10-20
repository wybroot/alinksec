package com.alinksec.service.virus;

import com.alinksec.common.util.JsonUtils;
import com.alinksec.proto.CmdVirusScan;
import com.alinksec.proto.Command;
import com.alinksec.service.command.CommandService;
import com.alinksec.service.config.DatabaseDialect;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.time.Duration;
import java.util.*;

@Service
public class VirusTaskService {
    public static final int MODE_QUICK=1,MODE_FULL=2,MODE_CUSTOM=3;
    private final JdbcTemplate jdbc; private final CommandService commands; private final DatabaseDialect database;
    public VirusTaskService(JdbcTemplate jdbc,CommandService commands,DatabaseDialect database) { this.jdbc=jdbc; this.commands=commands; this.database=database; }
    @Transactional
    public long createTask(String name,List<String> agents,int mode,List<String> paths,Long actor) {
        return createTask(name,agents,mode,paths,actor,"builtin");
    }
    @Transactional
    public long createTask(String name,List<String> agents,int mode,List<String> paths,Long actor,String engine) {
        if(engine==null)engine="builtin";
        if(!Set.of("builtin","clamav","yara").contains(engine))throw new IllegalArgumentException("扫描引擎无效");
        boolean clamav=engine.equals("clamav"),yara=engine.equals("yara"),external=clamav||yara;
        Map<String,String> versions=new HashMap<>();
        VirusExecution.lock(jdbc); if(actor!=null) VirusExecution.actor(jdbc,actor);
        if(agents==null || agents.isEmpty() || agents.size()>500 || agents.stream().anyMatch(a->a==null || a.isBlank() || a.length()>64)) throw new IllegalArgumentException("请选择1至500台有效目标主机");
        agents=agents.stream().distinct().toList();
        if(mode<1 || mode>3 || name!=null && name.length()>128) throw new IllegalArgumentException("扫描模式或任务名称无效");
        List<String> clean=List.of();
        if(mode==MODE_CUSTOM) {
            if(paths==null || paths.isEmpty() || paths.size()>64) throw new IllegalArgumentException("自定义扫描需要1至64条绝对路径");
            clean=paths.stream().map(VirusExecution::path).distinct().toList();
        }
        for(String agent:agents) {
            var rows=jdbc.queryForList("SELECT os_type,virus_execution_contract FROM t_agent WHERE agent_id=? AND deleted=false",agent);
            if(rows.size()!=1 || ((Number)rows.get(0).get("virus_execution_contract")).intValue()!=2) throw new IllegalArgumentException("目标主机尚未上报检测执行契约2，请先更新Agent并等待心跳");
            int os=((Number)rows.get(0).get("os_type")).intValue();
            if(os!=1 && os!=2) throw new IllegalArgumentException("目标主机系统未支持");
            if(external)versions.put(agent,yara?YaraService.requireReady(jdbc,agent):ClamavService.requireReady(jdbc,agent));
            for(String path:clean) if(os==1 && !path.startsWith("/") || os==2 && !path.matches("^[A-Za-z]:[\\\\/].*")) throw new IllegalArgumentException("自定义路径与目标主机系统不匹配，请按系统分组");
        }
        String version="";
        if(!external) {
            var releases=jdbc.queryForList("SELECT db_version,hash_count,rule_count FROM t_virus_db ORDER BY id DESC LIMIT 1");
            if(releases.isEmpty() || ((Number)releases.get(0).get("hash_count")).longValue()+((Number)releases.get(0).get("rule_count")).longValue()==0) throw new IllegalArgumentException("当前特征库为空，无法创建扫描任务");
            version=String.valueOf(releases.get(0).get("db_version"));
        }
        String no="VS-"+UUID.randomUUID();
        long task=jdbc.queryForObject("INSERT INTO t_virus_scan_task(task_no,name,mode,scope,status,created_by,started_at,expected_db_version,scan_engine) VALUES(?,?,?,?,1,?,CURRENT_TIMESTAMP,?,?) RETURNING id",Long.class,no,name==null || name.isBlank()?no+" 病毒扫描":name,mode,JsonUtils.write(Map.of("agent_ids",agents,"paths",clean,"time_limit_sec",7200,"max_files",100000,"max_total_bytes",20L<<30)),actor,version,engine);
        var scan=CmdVirusScan.newBuilder().setTaskId(Long.toString(task)).setMode(mode==2?CmdVirusScan.Mode.FULL:mode==3?CmdVirusScan.Mode.CUSTOM:CmdVirusScan.Mode.QUICK).addAllPaths(clean).setExecutionContract(yara?4:clamav?3:2).setEngine(engine).setTimeLimitSec(7200).setMaxFiles(100000).setMaxTotalBytes(20L<<30);
        for(String agent:agents) {
            String pinned=external?versions.get(agent):version;
            scan.setExpectedDbVersion(pinned);
            jdbc.update("INSERT INTO t_virus_task_agent(task_id,agent_id,expected_engine_version) VALUES(?,?,?)",task,agent,pinned);
            String command=commands.dispatchAfterCommit(agent,Command.newBuilder().setVirusScan(scan),actor);
            jdbc.update("UPDATE t_virus_task_agent SET command_id=? WHERE task_id=? AND agent_id=?",command,task,agent);
        }
        return task;
    }
    @Scheduled(fixedDelay=120000,initialDelay=180000) @Transactional
    public void sweepTimeout() {
        VirusExecution.lock(jdbc);
        // Pending offline file actions must expire without needing a reconnect.
        jdbc.update("UPDATE t_virus_action_evidence SET state='timeout',error='file_action_expired',finished_at=? WHERE state='pending' AND created_at<?",java.time.Instant.now().toString(),java.time.Instant.now().minus(Duration.ofMinutes(15)).toString());
        jdbc.update("UPDATE t_virus_task_agent SET state='timeout' WHERE state='pending' AND task_id IN (SELECT id FROM t_virus_scan_task WHERE status=1 AND created_at<?)",database.timestampBefore(Duration.ofHours(2).plusMinutes(5)));
        jdbc.update("UPDATE t_virus_scan_task SET status=3,progress=100,finished_at=CURRENT_TIMESTAMP WHERE status=1 AND created_at<?",database.timestampBefore(Duration.ofHours(2).plusMinutes(5)));
    }
    @Scheduled(cron="${alinksec.virus.weekly-scan-cron:0 30 2 * * MON}") @Transactional
    public void weeklyQuickScan() {
        var releases=jdbc.queryForList("SELECT hash_count,rule_count FROM t_virus_db ORDER BY id DESC LIMIT 1");
        if(releases.isEmpty() || ((Number)releases.get(0).get("hash_count")).longValue()+((Number)releases.get(0).get("rule_count")).longValue()==0) return;
        String after="";
        while(true) {
            List<String> agents=jdbc.queryForList("SELECT agent_id FROM t_agent WHERE deleted=false AND status=1 AND virus_execution_contract=2 AND os_type IN (1,2) AND agent_id>? ORDER BY agent_id LIMIT 500",String.class,after);
            if(agents.isEmpty()) break;
            createTask("定时快扫（每周策略）",agents,1,List.of(),null);
            after=agents.get(agents.size()-1);
        }
    }
}
