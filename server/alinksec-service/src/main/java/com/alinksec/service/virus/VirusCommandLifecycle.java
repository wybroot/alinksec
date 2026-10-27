package com.alinksec.service.virus;

import com.alinksec.common.util.JsonUtils;
import com.alinksec.proto.Command;
import com.alinksec.service.command.CommandLifecycleListener;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import java.time.Instant;
import java.util.*;

@Component
public class VirusCommandLifecycle implements CommandLifecycleListener {
    private final JdbcTemplate jdbc; private final VirusResultService results;
    public VirusCommandLifecycle(JdbcTemplate jdbc,VirusResultService results) { this.jdbc=jdbc; this.results=results; }
    @Override public void beforeAck(String agent,String command) { VirusExecution.lock(jdbc); }
    @Override public Command prepareDelivery(String agent,Command command) {
        if(!command.hasVirusScan() && !command.hasVirusAction()) return command;
        VirusExecution.lock(jdbc);
        if(jdbc.queryForObject("SELECT count(*) FROM t_agent WHERE agent_id=? AND deleted=false AND virus_execution_contract=2",Integer.class,agent)!=1) throw new IllegalArgumentException("Agent检测执行契约失效");
        if(command.hasVirusScan()) {
            var c=command.getVirusScan();
            var owner=jdbc.queryForList("SELECT created_by FROM t_virus_scan_task WHERE id=?",Long.parseLong(c.getTaskId()));
            if(!owner.isEmpty() && owner.get(0).get("created_by") instanceof Number n) VirusExecution.actor(jdbc,n.longValue());
            boolean clamav=c.getEngine().equals("clamav"),yara=c.getEngine().equals("yara");
            String engine=yara?"yara":clamav?"clamav":"builtin";
            if(c.getExecutionContract()!=(yara?4:clamav?3:2) || !Set.of("","builtin","clamav","yara").contains(c.getEngine()) || jdbc.queryForObject("SELECT count(*) FROM t_virus_task_agent m JOIN t_virus_scan_task t ON t.id=m.task_id WHERE m.command_id=? AND m.agent_id=? AND m.state='pending' AND t.status=1 AND t.scan_engine=? AND m.expected_engine_version=?",Integer.class,command.getCmdId(),agent,engine,c.getExpectedDbVersion())!=1) throw new IllegalArgumentException("扫描任务已过期或结果已接受");
            String current=yara?YaraService.requireReady(jdbc,agent):clamav?ClamavService.requireReady(jdbc,agent):jdbc.queryForObject("SELECT db_version FROM t_virus_db ORDER BY id DESC LIMIT 1",String.class);
            if(!c.getExpectedDbVersion().equals(current)) throw new IllegalArgumentException("扫描固定的特征库已被替代，请重新创建任务");
            int configured=c.getTimeLimitSec();
            if(configured<1 || configured>7200) throw new IllegalArgumentException("扫描任务预算无效");
            long millis=command.getIssuedAt()+configured*1000L-System.currentTimeMillis();
            if(millis<=0 || millis>configured*1000L) throw new IllegalArgumentException("扫描任务执行期限已失效");
            // The wire budget is whole seconds; keep a positive sub-second remainder usable.
            long remaining=(millis+999)/1000;
            return command.toBuilder().setVirusScan(c.toBuilder().setTimeLimitSec((int)remaining)).build();
        } else {
            var c=command.getVirusAction();
            if(command.getIssuedAt()<System.currentTimeMillis()-900000 || command.getIssuedAt()>System.currentTimeMillis()+300000) throw new IllegalArgumentException("文件处置请求已过期，请重新复核");
            for(var owner:jdbc.queryForList("SELECT DISTINCT actor FROM t_virus_action_evidence WHERE command_id=?",command.getCmdId())) VirusExecution.actor(jdbc,owner.get("actor") instanceof Number n?n.longValue():null);
            if(c.getExecutionContract()!=2 || c.getTargetsCount()==0 || c.getTargetsCount()>32) throw new IllegalArgumentException("处置契约无效");
            for(var target:c.getTargetsList()) if(jdbc.queryForObject("SELECT count(*) FROM t_virus_action_evidence h JOIN t_virus_finding f ON f.id=h.finding_id WHERE h.command_id=? AND h.agent_id=? AND h.finding_id=? AND h.state='pending' AND f.path=? AND f.sha256=? AND f.quarantine_id=?",Integer.class,command.getCmdId(),agent,Long.parseLong(target.getFindingId()),target.getPath(),target.getSha256(),target.getQuarantineId())!=1) throw new IllegalArgumentException("处置对象证据已失效");
        }
        return command;
    }
    @Override public void onTerminal(String agent,String command,TerminalState state,String message) {
        VirusExecution.lock(jdbc);
        var tasks=jdbc.queryForList("SELECT task_id FROM t_virus_task_agent WHERE command_id=? AND agent_id=? AND state='pending'",command,agent);
        for(var task:tasks) {
            jdbc.update("UPDATE t_virus_task_agent SET state=?,evidence=? WHERE command_id=? AND agent_id=? AND state='pending'",state==TerminalState.TIMEOUT?"timeout":"failed",JsonUtils.write(Map.of("status",state.name(),"error",state==TerminalState.DONE?"result_missing":safe(message))),command,agent);
            results.advanceProgress(((Number)task.get("task_id")).longValue());
        }
        var pending=jdbc.queryForList("SELECT id,finding_id,action FROM t_virus_action_evidence WHERE command_id=? AND agent_id=? AND state='pending' ORDER BY id",command,agent);
        if(pending.isEmpty()) return;
        Map<Long,com.fasterxml.jackson.databind.JsonNode> accepted=new HashMap<>();
        try {
            if(message==null || message.length()>16000) throw new IllegalArgumentException();
            var json=JsonUtils.read(message);
            if(json.path("virus_action_contract").asInt()!=2 || !json.path("results").isArray() || json.path("results").size()!=pending.size()) throw new IllegalArgumentException();
            for(var item:json.path("results")) { long id=Long.parseLong(item.path("finding_id").asText()); if(!item.path("success").isBoolean() || accepted.put(id,item)!=null || item.path("quarantine_id").asText().length()>32) throw new IllegalArgumentException(); }
            for(var h:pending) if(!accepted.containsKey(((Number)h.get("finding_id")).longValue())) throw new IllegalArgumentException();
        } catch(RuntimeException e) { accepted.clear(); }
        for(var h:pending) {
            long finding=((Number)h.get("finding_id")).longValue(); var item=accepted.get(finding);
            boolean success=state!=TerminalState.TIMEOUT && item!=null && item.path("success").asBoolean();
            String action=(String)h.get("action"),qid=item==null?"":item.path("quarantine_id").asText("");
            if(success && action.equals("quarantine") && !qid.matches("[0-9a-f]{32}")) success=false;
            String outcome=success?"succeeded":state==TerminalState.TIMEOUT?"timeout":"failed";
            String error=success?"":item==null?"missing_or_invalid_target_receipt":safe(item.path("error").asText("action_failed"));
            var receipt=new LinkedHashMap<String,Object>(); receipt.put("terminal",state.name()); receipt.put("target",item); receipt.put("message",message==null?"":message.substring(0,Math.min(message.length(),16000)));
            jdbc.update("UPDATE t_virus_action_evidence SET state=?,error=?,finished_at=?,receipt=? WHERE id=? AND state='pending'",outcome,error,Instant.now().toString(),JsonUtils.write(receipt),h.get("id"));
            if(success) jdbc.update("UPDATE t_virus_finding SET status=?,action_taken=?,action_error='',quarantine_id=? WHERE id=? AND agent_id=?",action.equals("quarantine")?1:action.equals("delete")?2:3,action.equals("quarantine")?"quarantined":action.equals("delete")?"deleted":"restored",action.equals("quarantine")?qid:"",finding,agent);
            else if(qid.matches("[0-9a-f]{32}")) jdbc.update("UPDATE t_virus_finding SET quarantine_id=?,action_error=? WHERE id=? AND agent_id=?",qid,error.length()>128?error.substring(0,128):error,finding,agent);
        }
    }
    private static String safe(String value) { if(value==null) return ""; return value.length()>2000?value.substring(0,2000):value; }
}
