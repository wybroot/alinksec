package com.alinksec.service.fix;

import com.alinksec.common.util.JsonUtils;
import com.alinksec.proto.Command;
import com.alinksec.proto.FixItem;
import com.alinksec.service.command.CommandLifecycleListener;
import com.alinksec.service.config.DatabaseDialect;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;

/** Applies the same authorization, window and immutable-package checks to every delivery/replay. */
@Component
public class PackageRepairCommandGuard implements CommandLifecycleListener {
    private final JdbcTemplate jdbc;
    private final PatchRepoService patches;
    private final DatabaseDialect database;
    private final PackageRepairValidation validation;
    public PackageRepairCommandGuard(JdbcTemplate jdbc,PatchRepoService patches,DatabaseDialect database) {
        this.jdbc=jdbc; this.patches=patches; this.database=database; this.validation=new PackageRepairValidation(jdbc,patches);
    }

    @Override public Command prepareDelivery(String agentId,Command command) {
        if (!command.hasVulnFix()) return command;
        if(command.getVulnFix().getFixesList().stream().noneMatch(f -> f.getType()==FixItem.FixType.PACKAGE || f.getType()==FixItem.FixType.WINDOWS_UPDATE)) {
            Integer packages=jdbc.queryForObject("SELECT count(*) FROM t_fix_task WHERE CAST(id AS TEXT)=? AND type=2",Integer.class,command.getVulnFix().getTaskId());
            if(packages!=null && packages>0) throw new IllegalArgumentException("软件包任务不能混入或替换为配置修复");
            return command;
        }
        long taskId;
        try { taskId=Long.parseLong(command.getVulnFix().getTaskId()); }
        catch (NumberFormatException e) { throw new IllegalArgumentException("软件包指令缺少有效任务身份"); }
        jdbc.update("UPDATE t_fix_task SET status=status WHERE id=?",taskId);
        var tasks=jdbc.queryForList("""
                SELECT t.status,t.approved,t.approver_id,t.approved_by,t.window_start,t.window_end,t.started_at,t.type,
                  u.status AS user_status,r.name AS role FROM t_fix_task t
                LEFT JOIN t_user u ON u.id=t.approved_by LEFT JOIN t_role r ON r.id=u.role_id WHERE t.id=?
                """,taskId);
        if (tasks.size()!=1) throw new IllegalArgumentException("软件包任务不存在");
        var task=tasks.get(0);
        if (!Integer.valueOf(2).equals(asInt(task.get("type"))) || !Integer.valueOf(1).equals(asInt(task.get("status")))
                || !DatabaseDialect.readBoolean(task.get("approved")) || task.get("approved_by")==null
                || !task.get("approved_by").equals(task.get("approver_id"))
                || !Integer.valueOf(1).equals(asInt(task.get("user_status"))) || !List.of("admin","operator").contains(task.get("role")))
            throw new IllegalArgumentException("任务未处于有效审批执行状态，停止派发和重推");
        Instant now=Instant.now();
        if (task.get("started_at")==null) throw new IllegalArgumentException("任务没有持久化派发时间");
        Instant deadline=database.readOffsetDateTime(task.get("started_at")).toInstant().plus(Duration.ofMinutes(30));
        if (task.get("window_start")!=null && now.isBefore(database.readOffsetDateTime(task.get("window_start")).toInstant())) throw new IllegalArgumentException("尚未进入维护窗口");
        if (task.get("window_end")!=null && database.readOffsetDateTime(task.get("window_end")).toInstant().isBefore(deadline)) deadline=database.readOffsetDateTime(task.get("window_end")).toInstant();
        if (!now.isBefore(deadline)) throw new IllegalArgumentException("任务或维护窗口已经过期，停止派发和重推");
        var rebuilt=command.getVulnFix().toBuilder().clearFixes();
        for (var item:command.getVulnFix().getFixesList()) {
            boolean windows=item.getType()==FixItem.FixType.WINDOWS_UPDATE;
            if (item.getType()!=FixItem.FixType.PACKAGE && !windows) throw new IllegalArgumentException("软件包任务不能混入配置修复");
            var records=jdbc.queryForList("SELECT status,fix_payload FROM t_fix_record WHERE task_id=? AND agent_id=? AND ref_id=? AND ref_type=? AND command_id=?",taskId,agentId,item.getRefId(),windows?"windows_update":"vuln_finding",command.getCmdId());
            if (records.size()!=1) throw new IllegalArgumentException("指令目标与持久化任务不一致");
            if (((Number)records.get(0).get("status")).intValue()!=0) continue;
            if(windows) {
                var payload=new WindowsUpdateValidation(jdbc,database).validate(Map.of("agent_id",agentId,"ref_id",item.getRefId(),"fix_payload",records.get(0).get("fix_payload")));
                var supplied=new java.util.LinkedHashMap<>(com.alinksec.common.util.JsonUtils.read(item.getPayload(),Map.class)); supplied.remove("dispatch_deadline_unix_ms");
                if(!payload.equals(supplied)) throw new IllegalArgumentException("更新指令与审批目标不一致");
                payload.put("dispatch_deadline_unix_ms",deadline.toEpochMilli());
                rebuilt.addFixes(item.toBuilder().setPayload(JsonUtils.write(payload))); continue;
            }
            var payload=validation.validate(Map.of("agent_id",agentId,"ref_id",item.getRefId(),"fix_payload",item.getPayload()));
            @SuppressWarnings("unchecked") var patch=(Map<String,Object>)payload.remove("validated_patch");
            var pin=(Map<?,?>)payload.get("patch_review");
            payload.put("download_url",patches.repairDownloadUrl(agentId,patch,taskId,item.getRefId(),String.valueOf(pin.get("review_id")),deadline));
            payload.put("dispatch_deadline_unix_ms",deadline.toEpochMilli());
            rebuilt.addFixes(item.toBuilder().setPayload(JsonUtils.write(payload)));
        }
        if (rebuilt.getFixesCount()==0) throw new IllegalArgumentException("所有修复项已结束，不重复安装");
        return command.toBuilder().setVulnFix(rebuilt).build();
    }

    @Override public void beforeAck(String agentId,String cmdId) {
        for (Long id:jdbc.queryForList("SELECT DISTINCT task_id FROM t_fix_record WHERE agent_id=? AND command_id=? ORDER BY task_id",Long.class,agentId,cmdId))
            jdbc.update("UPDATE t_fix_task SET status=status WHERE id=?",id);
    }

    @Override public void onTerminal(String agentId,String cmdId,TerminalState state,String message) {
        if (state==TerminalState.DONE) return; // Individual verified results drive completion, not an ACK label.
        var ids=jdbc.queryForList("SELECT DISTINCT task_id FROM t_fix_record WHERE agent_id=? AND command_id=? ORDER BY task_id",Long.class,agentId,cmdId);
        String reason=(message==null ? "修复指令失败或超时" : message); reason=reason.substring(0,Math.min(2048,reason.length()));
        for (Long id:ids) {
            jdbc.update("UPDATE t_fix_task SET status=status WHERE id=?",id);
            jdbc.update("UPDATE t_fix_record SET status=5,log=?,finished_at=CURRENT_TIMESTAMP WHERE task_id=? AND agent_id=? AND command_id=? AND status=0",reason,id,agentId,cmdId);
            jdbc.update("DELETE FROM t_agent_download_token WHERE fix_task_id=? AND agent_id=?",id,agentId);
            jdbc.update("UPDATE t_fix_task SET failure_reason=? WHERE id=? AND status=1",reason,id);
            Integer pending=jdbc.queryForObject("SELECT count(*) FROM t_fix_record WHERE task_id=? AND status=0",Integer.class,id);
            if (pending!=null && pending==0) jdbc.update("UPDATE t_fix_task SET status=3,finished_at=CURRENT_TIMESTAMP WHERE id=? AND status=1",id);
        }
    }
    private static Integer asInt(Object value) { return value instanceof Number n ? n.intValue() : null; }
}
