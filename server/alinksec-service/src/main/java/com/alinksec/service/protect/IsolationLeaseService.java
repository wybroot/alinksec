package com.alinksec.service.protect;

import com.alinksec.proto.RptIsolationState;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.Set;

/** Live, current-stream observations only. Historical ACK/events never renew a lease. */
@Service
public class IsolationLeaseService {
    private static final Set<String> PHASES=Set.of("prepared","applying","active","restoring","attention","finished");
    private final JdbcTemplate jdbc;
    public IsolationLeaseService(JdbcTemplate jdbc) { this.jdbc=jdbc; }

    /** The gateway holds the connection identity lock through reconciliation and echo. */
    public boolean observe(String agent,RptIsolationState pulse) {
        if (pulse.getPhase().equals("unknown")) {
            jdbc.update("""
                    UPDATE t_agent SET isolation_status=6,isolation_error=?,isolation_updated_at=CURRENT_TIMESTAMP
                    WHERE agent_id=? AND isolation_contract=1 AND (isolation_status<>0 OR isolation_generation>0) AND status<>4 AND deleted=false
                    ""","Agent 本机隔离记录不可读，无法确认已恢复网络",agent);
            return false;
        }
        if (!PHASES.contains(pulse.getPhase()) || !pulse.getLeaseId().matches("[0-9a-f]{32}")
                || pulse.getGeneration()<=0 || pulse.getRevision()<=0 || pulse.getCommandId().isBlank()
                || pulse.getCommandId().length()>256 || pulse.getRestoreCommandId().length()>256
                || pulse.getMessage().length()>4096 || pulse.getDeadline()<=0
                || !pulse.getNonce().isEmpty() && !pulse.getNonce().matches("[0-9a-f]{32}")) return false;
        for(int retry=0;retry<3;retry++) {
            var rows=jdbc.queryForList("""
                    SELECT isolation_contract,isolation_lease_id,isolation_generation,isolation_revision,
                           isolation_lease_command_id,isolation_command_id,isolation_status
                    FROM t_agent WHERE agent_id=? AND deleted=false AND status<>4
                    """,agent);
            if(rows.size()!=1) return false;
            Map<String,Object> row=rows.getFirst();
            if(number(row,"isolation_contract")!=1) return false;
            long generation=number(row,"isolation_generation"),revision=number(row,"isolation_revision");
            String lease=text(row,"isolation_lease_id"),pending=text(row,"isolation_command_id");
            if(pulse.getGeneration()<generation) return false;
            if(pulse.getGeneration()==generation && !pending.isEmpty()
                    && !pulse.getCommandId().equals(text(row,"isolation_lease_command_id"))) return false;
            if(pulse.getGeneration()==generation && (!pulse.getLeaseId().equals(lease) || pulse.getRevision()<revision)) return false;
            if(pulse.getGeneration()>generation && !pulse.getCommandId().equals(text(row,"isolation_lease_command_id"))
                    && !pulse.getCommandId().matches("local-[0-9a-f]{32}")) return false;
            short state=switch(pulse.getPhase()) {
                case "prepared","applying" -> IsolationCommandLifecycleListener.ISOLATING;
                case "active" -> pulse.getConfirmed()?IsolationCommandLifecycleListener.ISOLATED:IsolationCommandLifecycleListener.ISOLATING;
                case "restoring" -> IsolationCommandLifecycleListener.RESTORING;
                case "attention" -> IsolationCommandLifecycleListener.RESTORE_FAILED;
                default -> IsolationCommandLifecycleListener.NORMAL;
            };
            // Do not erase a queued operator restore while the Agent is still
            // observing the previous active phase. A fresh finished state wins.
            if(!pending.isEmpty() && !pending.equals(pulse.getCommandId()) && pulse.getPhase().equals("active"))
                state=IsolationCommandLifecycleListener.RESTORING;
            String remaining=pending;
            if(pulse.getPhase().equals("finished") || pulse.getPhase().equals("active") && pulse.getConfirmed() && pending.equals(pulse.getCommandId())) remaining=null;
            String message=pulse.getPhase().equals("attention") || pulse.getAutomatic()?pulse.getMessage():null;
            int updated=jdbc.update("""
                    UPDATE t_agent SET isolation_status=?,isolation_command_id=?,isolation_error=?,
                        isolation_lease_id=?,isolation_generation=?,isolation_revision=?,isolation_lease_deadline=?,
                        isolation_automatic=?,isolation_seen_at=?,isolation_updated_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP
                    WHERE agent_id=? AND isolation_contract=1 AND deleted=false AND status<>4
                        AND isolation_generation=? AND isolation_revision=? AND COALESCE(isolation_lease_id,'')=?
                        AND COALESCE(isolation_command_id,'')=? AND isolation_status=?
                    """,state,remaining,message,pulse.getLeaseId(),pulse.getGeneration(),pulse.getRevision(),pulse.getDeadline(),
                    pulse.getAutomatic(),System.currentTimeMillis(),agent,generation,revision,lease,pending,number(row,"isolation_status"));
            if(updated==1) return pulse.getPhase().equals("active") && !pulse.getNonce().isEmpty();
        }
        return false;
    }

    // No observation is evidence of restored networking. After reports stop,
    // show uncertainty until the independent owner reports actual cleanup.
    // Use server receipt time so an Agent's wall clock cannot delay this check.
    @org.springframework.scheduling.annotation.Scheduled(fixedDelay=1000,initialDelay=1000)
    public void expireObservations() {
        jdbc.update("""
                UPDATE t_agent SET isolation_status=6,isolation_error=?,isolation_updated_at=CURRENT_TIMESTAMP
                WHERE deleted=false AND status<>4 AND isolation_status IN (1,2,3)
                    AND isolation_seen_at IS NOT NULL AND isolation_seen_at<?
                ""","隔离管理确认已中断，等待本机恢复结果；当前网络状态待确认",System.currentTimeMillis()-12000);
    }
    private static long number(Map<String,Object> row,String field) { return row.get(field) instanceof Number n?n.longValue():0; }
    private static String text(Map<String,Object> row,String field) { return row.get(field)==null?"":row.get(field).toString(); }
}
