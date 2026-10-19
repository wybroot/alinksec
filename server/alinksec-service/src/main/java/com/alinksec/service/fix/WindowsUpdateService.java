package com.alinksec.service.fix;

import com.alinksec.common.util.JsonUtils;
import com.alinksec.proto.*;
import com.alinksec.service.command.CommandLifecycleListener;
import com.alinksec.service.command.CommandService;
import com.alinksec.service.config.DatabaseDialect;
import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.*;

@Service
public class WindowsUpdateService implements CommandLifecycleListener {
    private final JdbcTemplate jdbc;
    private final CommandService commands;
    private final DatabaseDialect database;
    private final WindowsUpdateValidation validation;
    public WindowsUpdateService(JdbcTemplate jdbc,@org.springframework.context.annotation.Lazy CommandService commands,DatabaseDialect database) {
        this.jdbc=jdbc; this.commands=commands; this.database=database; validation=new WindowsUpdateValidation(jdbc,database);
    }

    @Transactional
    public Map<String,Object> scan(List<String> agents,Long actor) {
        requireActor(actor);
        if(agents==null || agents.isEmpty() || agents.size()>50 || new HashSet<>(agents).size()!=agents.size()) throw new IllegalArgumentException("请选择 1 至 50 台不同的 Windows 主机");
        var ids=new ArrayList<String>();
        for(String agent:agents.stream().sorted().toList()) {
            jdbc.update("UPDATE t_agent SET software_revision=software_revision WHERE agent_id=? AND deleted=false",agent);
            var hosts=jdbc.queryForList("SELECT os_type,status,windows_update_contract FROM t_agent WHERE agent_id=? AND deleted=false",agent);
            if(hosts.size()!=1 || ((Number)hosts.get(0).get("os_type")).intValue()!=2 || ((Number)hosts.get(0).get("status")).intValue()!=1 || ((Number)hosts.get(0).get("windows_update_contract")).intValue()!=1)
                throw new IllegalArgumentException("目标必须是在线且支持原生更新的 Windows Agent："+agent);
            Integer pending=jdbc.queryForObject("SELECT count(*) FROM t_windows_update_scan WHERE agent_id=? AND status='pending' AND deadline>?",Integer.class,agent,System.currentTimeMillis());
            if(pending!=null && pending>0) throw new IllegalArgumentException("该主机已有更新发现任务，请等待完成");
            String id=UUID.randomUUID().toString(); long deadline=System.currentTimeMillis()+Duration.ofMinutes(10).toMillis();
            jdbc.update("INSERT INTO t_windows_update_scan(scan_id,agent_id,deadline) VALUES (?,?,?)",id,agent,deadline);
            jdbc.update("UPDATE t_agent SET windows_update_scan_id=? WHERE agent_id=?",id,agent);
            String cmd=commands.dispatchAfterCommit(agent,Command.newBuilder().setWindowsUpdateScan(CmdWindowsUpdateScan.newBuilder().setScanId(id).setDeadlineUnixMs(deadline)),actor);
            jdbc.update("UPDATE t_windows_update_scan SET command_id=? WHERE scan_id=?",cmd,id); ids.add(id);
        }
        return Map.of("scanIds",ids);
    }

    @Transactional
    public void onSnapshot(String agent,RptWindowsUpdate report) {
        jdbc.update("UPDATE t_agent SET software_revision=software_revision WHERE agent_id=?",agent);
        var scans=jdbc.queryForList("SELECT status,deadline,command_id FROM t_windows_update_scan WHERE scan_id=? AND agent_id=?",report.getScanId(),agent);
        if(scans.size()!=1 || !"pending".equals(scans.get(0).get("status"))) return;
        var scan=scans.get(0);
        Integer sent=jdbc.queryForObject("SELECT count(*) FROM t_command WHERE cmd_id=? AND agent_id=? AND status IN (1,2,3,4)",Integer.class,scan.get("command_id"),agent);
        if(sent==null || sent!=1) return;
        if(((Number)scan.get("deadline")).longValue()<System.currentTimeMillis()) {
            jdbc.update("UPDATE t_windows_update_scan SET status='failed',error='scan_expired',received_at=CURRENT_TIMESTAMP WHERE scan_id=? AND status='pending'",report.getScanId()); return;
        }
        if(report.getSnapshot().length()>2_000_000) throw new IllegalArgumentException("Windows 更新发现证据超限");
        JsonNode doc=JsonUtils.read(report.getSnapshot());
        if(doc.path("contract").asInt()!=1 || !Set.of("complete","failed","unsupported").contains(doc.path("status").asText())) throw new IllegalArgumentException("无效更新发现契约");
        String status=doc.path("status").asText(), error=doc.path("error").asText();
        if(error.length()>128) throw new IllegalArgumentException("更新错误标记超限");
        var normalized=new LinkedHashMap<String,Object>(); normalized.put("contract",1); normalized.put("status",status); normalized.put("error",error);
        normalized.put("reboot_required",doc.path("reboot_required").asBoolean(true));
        String identity=doc.path("host_identity").asText();
        var updates=new ArrayList<Map<String,Object>>();
        if(status.equals("complete")) {
            if(!identity.matches("[a-f0-9]{64}") || !doc.path("reboot_required").isBoolean() || !doc.path("updates").isArray() || doc.path("updates").size()>256) throw new IllegalArgumentException("更新发现缺少完整主机身份或更新集合");
            Set<String> seen=new HashSet<>();
            for(var u:doc.path("updates")) {
                Map<String,Object> metadata=metadata(u);
                if(!seen.add(metadata.get("update_id")+":"+metadata.get("revision"))) throw new IllegalArgumentException("重复的更新身份");
                updates.add(metadata);
            }
        } else identity="";
        normalized.put("host_identity",identity); normalized.put("updates",updates);
        // First complete response owns this scan forever; later replay cannot
        // replace the approved metadata or turn an empty scan into coverage.
        int changed=jdbc.update("UPDATE t_windows_update_scan SET status=?,error=?,host_identity=?,snapshot=?,received_at=CURRENT_TIMESTAMP WHERE scan_id=? AND agent_id=? AND status='pending'",status,error,identity,JsonUtils.write(normalized),report.getScanId(),agent);
        if(changed!=1) return;
        for(var u:updates) jdbc.update("INSERT INTO t_windows_update_candidate(scan_id,agent_id,update_id,revision,title,eligible,reason,metadata) VALUES (?,?,?,?,?,?,?,?)",report.getScanId(),agent,u.get("update_id"),u.get("revision"),u.get("title"),Boolean.TRUE.equals(u.get("eligible"))?1:0,u.get("reason"),JsonUtils.write(u));
    }
    private static Map<String,Object> metadata(JsonNode u) {
        String id=u.path("update_id").asText(),title=u.path("title").asText(),eula=u.path("eula_digest").asText(),reason=u.path("reason").asText();
        if(!id.matches("[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}") || !u.path("revision").canConvertToInt() || u.path("revision").asInt()<1
                || title.isBlank() || title.length()>512 || !eula.matches("[a-f0-9]{64}") || reason.length()>128 || !u.path("eligible").isBoolean()
                || !u.path("size").isIntegralNumber() || u.path("size").asLong()<0 || u.path("size").asLong()>4L*1024*1024*1024 || !u.path("kb").isArray() || u.path("kb").size()>32)
            throw new IllegalArgumentException("更新元数据不完整或超限");
        var kb=new ArrayList<String>(); for(var k:u.path("kb")) { if(!k.isTextual() || !k.asText().matches("[0-9]{4,12}") || kb.contains(k.asText())) throw new IllegalArgumentException("无效 KB 集合"); kb.add(k.asText()); }
        if(u.path("eligible").asBoolean() && (kb.isEmpty() || !reason.isEmpty())) throw new IllegalArgumentException("更新适用性声明不一致");
        return Map.of("update_id",id,"revision",u.path("revision").asInt(),"title",title,"eula_digest",eula,"reason",reason,"eligible",u.path("eligible").asBoolean(),"size",u.path("size").asLong(),"kb",kb);
    }

    public Map<String,Object> hosts(int page,int size) {
        var items=jdbc.queryForList("""
                SELECT a.agent_id,a.hostname,a.ip,a.status AS agent_status,a.windows_update_contract,s.scan_id,s.status,s.error,s.created_at,s.received_at,s.snapshot
                FROM t_agent a LEFT JOIN t_windows_update_scan s ON s.scan_id=a.windows_update_scan_id
                WHERE a.os_type=2 AND a.deleted=false ORDER BY a.hostname,a.agent_id LIMIT ? OFFSET ?
                """,size,(page-1)*size);
        for(var item:items) {
            String state="unknown";
            if(((Number)item.get("windows_update_contract")).intValue()!=1) state="unsupported";
            else if(((Number)item.get("agent_status")).intValue()!=1) state="offline";
            else if(item.get("status")!=null) { state=String.valueOf(item.get("status")); if(state.equals("complete") && database.readOffsetDateTime(item.get("received_at")).toInstant().isBefore(Instant.now().minus(Duration.ofHours(24)))) state="stale"; }
            item.put("state",state); item.put("coverage",item.get("snapshot") instanceof String s && !s.isBlank()?JsonUtils.read(s):Map.of()); item.remove("snapshot");
        }
        return Map.of("items",items,"total",jdbc.queryForObject("SELECT count(*) FROM t_agent WHERE os_type=2 AND deleted=false",Long.class));
    }
    public List<Map<String,Object>> candidates(String agent) {
        var items=jdbc.queryForList("SELECT c.id,c.scan_id,c.metadata FROM t_windows_update_candidate c JOIN t_agent a ON a.agent_id=c.agent_id AND a.windows_update_scan_id=c.scan_id WHERE c.agent_id=? AND a.deleted=false ORDER BY c.id LIMIT 256",agent);
        for(var item:items) { item.put("update",JsonUtils.read(String.valueOf(item.remove("metadata")))); }
        return items;
    }

    @Transactional
    public Map<String,Object> createTask(List<Map<String,Object>> items,String approver,String start,String end,Long actor) {
        requireActor(actor);
        if(items==null || items.isEmpty() || items.size()>50) throw new IllegalArgumentException("请选择 1 至 50 项更新，每台主机一次一项");
        var reviewers=jdbc.queryForList("SELECT u.id,u.username FROM t_user u JOIN t_role r ON r.id=u.role_id WHERE u.username=? AND u.status=1 AND r.name IN ('admin','operator')",approver==null?"":approver.trim());
        if(reviewers.size()!=1) throw new IllegalArgumentException("请选择已启用的审批账号");
        OffsetDateTime ws=time(start),we=time(end);
        if((ws==null)!=(we==null) || ws!=null && (!we.isAfter(ws) || !we.isAfter(OffsetDateTime.now()))) throw new IllegalArgumentException("维护窗口必须同时提供有效的起止时间");
        Set<String> agents=new TreeSet<>(); for(var i:items) { if(!(i.get("agentId") instanceof String a) || a.isBlank() || !agents.add(a) || !(i.get("candidateId") instanceof Number n) || n.longValue()<1) throw new IllegalArgumentException("每台主机一次只选择一个精确更新目标"); }
        for(String agent:agents) jdbc.update("UPDATE t_agent SET software_revision=software_revision WHERE agent_id=? AND deleted=false",agent);
        var targets=new ArrayList<Map<String,Object>>();
        for(var i:items) {
            String agent=String.valueOf(i.get("agentId")); long id=((Number)i.get("candidateId")).longValue();
            Integer active=jdbc.queryForObject("SELECT count(*) FROM t_fix_record r JOIN t_fix_task t ON t.id=r.task_id WHERE r.agent_id=? AND r.ref_type='windows_update' AND (r.status IN (0,6,7)) AND t.status IN (0,1,5)",Integer.class,agent);
            if(active!=null && active>0) throw new IllegalArgumentException("主机已有待审批、执行或重启复核中的 Windows 更新任务");
            var p=validation.current(agent,id);
            targets.add(Map.of("agent_id",agent,"ref_id",String.valueOf(id),"ref_type","windows_update","fix_payload",JsonUtils.write(p)));
        }
        String no="WU"+UUID.randomUUID().toString().replace("-","");
        Long task=jdbc.queryForObject("INSERT INTO t_fix_task(task_no,name,type,scope,targets,status,created_by,approver,approver_id,approved,window_start,window_end) VALUES (?,?,2,?,?,0,?,?,?,false,?,?) RETURNING id",Long.class,no,"Windows 更新修复 "+no,JsonUtils.write(Map.of("agent_ids",agents)),JsonUtils.write(targets),actor,reviewers.get(0).get("username"),reviewers.get(0).get("id"),database.timestamp(ws),database.timestamp(we));
        for(var t:targets) jdbc.update("INSERT INTO t_fix_record(task_id,agent_id,ref_id,ref_type,fix_payload) VALUES (?,?,?,'windows_update',?)",task,t.get("agent_id"),t.get("ref_id"),t.get("fix_payload"));
        return Map.of("taskId",task,"taskNo",no,"pendingApprove",true);
    }
    private void requireActor(Long actor) {
        Integer n=actor==null?0:jdbc.queryForObject("SELECT count(*) FROM t_user u JOIN t_role r ON r.id=u.role_id WHERE u.id=? AND u.status=1 AND r.name IN ('admin','operator')",Integer.class,actor);
        if(n==null || n!=1) throw new IllegalArgumentException("需要已验证且有修复权限的登录账号");
    }
    private static OffsetDateTime time(String value) { if(value==null || value.isBlank()) return null; try { return OffsetDateTime.parse(value); } catch(RuntimeException e) { throw new IllegalArgumentException("维护窗口请使用含时区的 ISO 日期时间"); } }

    @Override public Command prepareDelivery(String agent,Command cmd) {
        if(!cmd.hasWindowsUpdateScan()) return cmd;
        var scan=cmd.getWindowsUpdateScan();
        Integer n=jdbc.queryForObject("SELECT count(*) FROM t_windows_update_scan s JOIN t_agent a ON a.agent_id=s.agent_id WHERE s.scan_id=? AND s.agent_id=? AND s.command_id=? AND s.status='pending' AND s.deadline=? AND s.deadline>? AND a.deleted=false AND a.os_type=2 AND a.windows_update_contract=1",Integer.class,scan.getScanId(),agent,cmd.getCmdId(),scan.getDeadlineUnixMs(),System.currentTimeMillis());
        if(n==null || n!=1) throw new IllegalArgumentException("Windows 更新发现指令已失效");
        return cmd;
    }
    @Override public void onTerminal(String agent,String cmd,TerminalState state,String message) {
        if(state!=TerminalState.DONE) jdbc.update("UPDATE t_windows_update_scan SET status='failed',error='command_failed',received_at=CURRENT_TIMESTAMP WHERE agent_id=? AND command_id=? AND status='pending'",agent,cmd);
    }
    @Scheduled(fixedDelay=60_000,initialDelay=60_000)
    public void expireScans() { jdbc.update("UPDATE t_windows_update_scan SET status='failed',error='scan_expired',received_at=CURRENT_TIMESTAMP WHERE status='pending' AND deadline<?",System.currentTimeMillis()); }
}
