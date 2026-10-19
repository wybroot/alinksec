package com.alinksec.service.fix;

import com.alinksec.common.util.JsonUtils;
import com.alinksec.proto.FixResultItem;
import com.alinksec.proto.RptFixResult;
import org.springframework.jdbc.core.JdbcTemplate;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

/** Windows update results never imply that a software CVE finding is resolved. */
public final class WindowsUpdateResult {
    private WindowsUpdateResult() { }
    static boolean accept(JdbcTemplate jdbc,String agent,long task,FixResultItem item) {
        var rows=jdbc.queryForList("""
                SELECT r.status,r.fix_payload,t.status AS task_status,c.status AS command_status,c.sent_at
                FROM t_fix_record r JOIN t_fix_task t ON t.id=r.task_id
                LEFT JOIN t_command c ON c.cmd_id=r.command_id AND c.agent_id=r.agent_id
                WHERE r.task_id=? AND r.agent_id=? AND r.ref_id=? AND r.ref_type='windows_update'
                """,task,agent,item.getRefId());
        if(rows.isEmpty()) return false;
        if(rows.size()!=1) return true;
        var row=rows.get(0); int previous=((Number)row.get("status")).intValue(),ts=((Number)row.get("task_status")).intValue();
        if(!Set.of(0,5,6,7).contains(previous) || !Set.of(1,3,5).contains(ts) || row.get("sent_at")==null || !(row.get("command_status") instanceof Number sent) || !Set.of(1,2,3,4,5,6).contains(sent.intValue())) return true;
        if(item.getExecutionEvidence().length()>8192 || item.getLog().length()>8000) throw new IllegalArgumentException("更新结果证据超限");
        var evidence=JsonUtils.read(item.getExecutionEvidence()); var p=JsonUtils.read(String.valueOf(row.get("fix_payload")));
        if(evidence.path("contract").asInt()!=1 || !evidence.path("host_identity").equals(p.path("host_identity"))
                || !evidence.path("update_id").equals(p.path("update").path("update_id")) || !evidence.path("revision").equals(p.path("update").path("revision")))
            throw new IllegalArgumentException("更新结果与已审批的精确更新身份不一致");
        String phase=evidence.path("phase").asText();
        boolean verified=item.getSuccess() && item.getVerified() && !item.getRebootRequired() && phase.equals("verified") && evidence.path("installed").asBoolean() && !evidence.path("reboot_required").asBoolean(true);
        boolean pending=item.getSuccess() && !item.getVerified() && item.getRebootRequired() && phase.equals("pending_reboot") && evidence.path("installed").asBoolean() && evidence.path("reboot_required").asBoolean();
        int status=verified?1:pending?6:phase.equals("uncertain")?7:3;
        // A partial/replayed failure cannot replace an already accepted pending
        // reboot result. Only a confirmed installed outcome advances it.
        if(previous==6 && !verified) return true;
        jdbc.update("UPDATE t_fix_record SET status=?,log=?,reboot_required=?,verified=?,execution_evidence=?,finished_at=CURRENT_TIMESTAMP WHERE task_id=? AND agent_id=? AND ref_id=? AND ref_type='windows_update' AND status=?",status,item.getLog(),item.getRebootRequired()?1:0,verified?1:0,item.getExecutionEvidence(),task,agent,item.getRefId(),previous);
        return true;
    }

    public static List<String> receipts(JdbcTemplate jdbc,String agent,RptFixResult result) {
        if(result.getResultsCount()>50 || !result.getTaskId().matches("[1-9][0-9]{0,18}")) return List.of();
        var receipts=new ArrayList<String>();
        for(var item:result.getResultsList()) {
            if(!item.getRefId().matches("[1-9][0-9]{0,18}") || item.getExecutionEvidence().isBlank() || item.getExecutionEvidence().length()>8192) continue;
            var rows=jdbc.queryForList("SELECT status,execution_evidence FROM t_fix_record WHERE task_id=? AND agent_id=? AND ref_id=? AND ref_type='windows_update' AND status<>0",Long.parseLong(result.getTaskId()),agent,item.getRefId());
            if(rows.size()==1 && ((Number)rows.get(0).get("status")).intValue()==8) { receipts.add(result.getTaskId()+"-"+item.getRefId()+"-closed"); continue; }
            if(rows.size()==1 && item.getExecutionEvidence().equals(rows.get(0).get("execution_evidence"))) {
                try { receipts.add(result.getTaskId()+"-"+item.getRefId()+"-"+HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(item.getExecutionEvidence().getBytes(StandardCharsets.UTF_8)))); }
                catch(java.security.NoSuchAlgorithmException e) { throw new IllegalStateException(e); }
            }
        }
        return receipts;
    }
}
