package com.alinksec.service.virus;

import com.alinksec.proto.*;
import com.alinksec.service.command.CommandService;
import com.alinksec.service.protect.PolicyStoreService;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.time.Instant;
import java.util.*;

@Service
public class VirusActionService {
    private final JdbcTemplate jdbc; private final CommandService commands; private final PolicyStoreService policies;
    public VirusActionService(JdbcTemplate jdbc,CommandService commands,PolicyStoreService policies) { this.jdbc=jdbc; this.commands=commands; this.policies=policies; }
    @Transactional
    public Map<String,Object> act(List<Long> ids,String action,Long actor) {
        VirusExecution.lock(jdbc); VirusExecution.actor(jdbc,actor);
        if(ids==null || ids.isEmpty() || ids.size()>32 || ids.stream().anyMatch(i->i==null || i<=0) || ids.stream().distinct().count()!=ids.size() || action==null || !Set.of("quarantine","delete","restore","whitelist").contains(action)) throw new IllegalArgumentException("请选择1至32个唯一检出记录和有效动作");
        List<Map<String,Object>> findings=new ArrayList<>();
        for(long id:ids) {
            var rows=jdbc.queryForList("SELECT f.id,f.agent_id,f.path,f.sha256,f.status,f.quarantine_id,a.virus_execution_contract FROM t_virus_finding f JOIN t_agent a ON a.agent_id=f.agent_id WHERE f.id=? AND a.deleted=false",id);
            if(rows.size()!=1) throw new IllegalArgumentException("部分检出或主机已不存在，请刷新");
            var row=rows.get(0); VirusExecution.path((String)row.get("path")); VirusExecution.hash((String)row.get("sha256"));
            if(jdbc.queryForObject("SELECT count(*) FROM t_virus_action_evidence WHERE finding_id=? AND state='pending'",Integer.class,id)>0) throw new IllegalArgumentException("部分文件已有待确认的处置");
            int status=((Number)row.get("status")).intValue();
            if(!action.equals("whitelist")) {
                if(((Number)row.get("virus_execution_contract")).intValue()!=2) throw new IllegalArgumentException("旧Agent不支持摘要绑定处置，请先更新并等待心跳");
                if(action.equals("restore") && (status!=0 && status!=1 || !String.valueOf(row.get("quarantine_id")).matches("[0-9a-f]{32}"))) throw new IllegalArgumentException("恢复需要可复核的隔离对象编号");
                if(action.equals("quarantine") && !String.valueOf(row.get("quarantine_id")).isEmpty()) throw new IllegalArgumentException("此记录已有保留的隔离对象，请先复核恢复或删除");
                if(action.equals("quarantine") && status!=0 && status!=3 || action.equals("delete") && status!=0 && status!=1 && status!=3) throw new IllegalArgumentException("检出处置状态已变化，请刷新");
                if(status==1 && String.valueOf(row.get("quarantine_id")).isEmpty()) throw new IllegalArgumentException("旧隔离证据缺少对象编号，须由本机人工复核");
            }
            findings.add(row);
        }
        var actionIds=new ArrayList<String>();
        if(action.equals("whitelist")) {
            for(var f:findings) {
                insertWhitelist("hash",VirusExecution.hash((String)f.get("sha256")),"检出记录加白: "+f.get("path"),actor);
                actionIds.add(history(f,"",action,"committed",actor));
            }
            policies.rebuild(); return Map.of("count",findings.size(),"state","policy_committed","actionIds",actionIds);
        }
        Map<String,List<Map<String,Object>>> grouped=new LinkedHashMap<>();
        for(var f:findings) grouped.computeIfAbsent((String)f.get("agent_id"),a->new ArrayList<>()).add(f);
        var commandsOut=new ArrayList<String>();
        for(var group:grouped.entrySet()) {
            var targets=group.getValue().stream().map(f->VirusTarget.newBuilder().setFindingId(String.valueOf(f.get("id"))).setPath((String)f.get("path")).setSha256(VirusExecution.hash((String)f.get("sha256"))).setQuarantineId((String)f.get("quarantine_id")).build()).toList();
            String cmd=commands.dispatchAfterCommit(group.getKey(),Command.newBuilder().setVirusAction(CmdVirusAction.newBuilder().setExecutionContract(2).setAction(CmdVirusAction.Action.valueOf(action.toUpperCase(Locale.ROOT))).addAllTargets(targets)),actor);
            for(var f:group.getValue()) actionIds.add(history(f,cmd,action,"pending",actor));
            commandsOut.add(cmd);
        }
        return Map.of("count",findings.size(),"state","pending","commands",commandsOut,"actionIds",actionIds);
    }
    private String history(Map<String,Object> f,String command,String action,String state,Long actor) {
        String id=UUID.randomUUID().toString();
        jdbc.update("INSERT INTO t_virus_action_evidence(id,finding_id,agent_id,command_id,action,state,actor,created_at,finished_at,request_evidence) VALUES(?,?,?,?,?,?,?,?,?,?)",id,f.get("id"),f.get("agent_id"),command,action,state,actor,Instant.now().toString(),state.equals("pending")?null:Instant.now().toString(),com.alinksec.common.util.JsonUtils.write(Map.of("path",f.get("path"),"sha256",f.get("sha256"),"quarantine_id",f.get("quarantine_id"),"status",f.get("status"))));
        return id;
    }
    private void insertWhitelist(String type,String value,String remark,Long actor) {
        if(jdbc.queryForObject("SELECT count(*) FROM t_virus_whitelist WHERE type=? AND value=?",Integer.class,type,value)>0) return;
        if(jdbc.queryForObject("SELECT count(*) FROM t_virus_whitelist",Integer.class)>=1000) throw new IllegalArgumentException("白名单已达到1000条上限");
        jdbc.update("INSERT INTO t_virus_whitelist(type,value,remark,created_by) VALUES(?,?,?,?)",type,value,remark,actor);
    }
    @Transactional public void addWhitelistEntry(String type,String value,String remark,Long actor) {
        VirusExecution.lock(jdbc); VirusExecution.actor(jdbc,actor);
        if(!"hash".equals(type) && !"path".equals(type) || remark!=null && remark.length()>255) throw new IllegalArgumentException("白名单类型或说明无效");
        value="hash".equals(type)?VirusExecution.hash(value):VirusExecution.path(value);
        if(type.equals("path") && (value.equals("/") || value.matches("^[A-Za-z]:[\\\\/]$"))) throw new IllegalArgumentException("不能将整盘加入路径白名单");
        insertWhitelist(type,value,remark,actor); policies.rebuild();
    }
    @Transactional public void removeWhitelist(long id) { removeWhitelist(id,null); }
    @Transactional public void removeWhitelist(long id,Long actor) {
        VirusExecution.lock(jdbc); VirusExecution.actor(jdbc,actor);
        if(jdbc.update("DELETE FROM t_virus_whitelist WHERE id=?",id)!=1) throw new IllegalArgumentException("白名单记录不存在");
        policies.rebuild();
    }
    @Transactional public Map<String,Object> updateRealtime(boolean enabled,String action,Long actor) {
        VirusExecution.lock(jdbc); VirusExecution.actor(jdbc,actor);
        if(!Set.of("alert_only","quarantine").contains(action)) throw new IllegalArgumentException("周期检测仅支持告警或隔离");
        jdbc.update("UPDATE t_virus_state SET realtime_enabled=?,realtime_action=?,revision=revision+1 WHERE id=1",enabled?1:0,action);
        policies.rebuild(); return Map.of("enabled",enabled,"action",action,"state","policy_committed");
    }
}
