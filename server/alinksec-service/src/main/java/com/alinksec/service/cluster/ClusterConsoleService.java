package com.alinksec.service.cluster;

import com.alinksec.service.evidence.EvidenceService;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import java.util.*;

/** Admin responses contain bounded routing/queue metadata, never report bytes or dependency credentials. */
@Service
public class ClusterConsoleService {
    private final ClusterProperties properties;
    private final ClusterRuntime runtime;
    private final RabbitTransport rabbit;
    private final JdbcTemplate jdbc;
    private final TransactionTemplate tx;
    public ClusterConsoleService(ClusterProperties properties,ClusterRuntime runtime,RabbitTransport rabbit,
                                 JdbcTemplate jdbc,PlatformTransactionManager manager) {
        this.properties=properties;this.runtime=runtime;this.rabbit=rabbit;this.jdbc=jdbc;tx=new TransactionTemplate(manager);
    }
    public Map<String,Object> status(Long actor) {
        return tx.execute(status->{
            EvidenceService.admin(jdbc,actor);
            var result=new LinkedHashMap<>(runtime.status());
            if(!properties.isEnabled()) return result;
            long now=ClusterRuntime.databaseTime(jdbc);
            result.put("observedAt",now);
            result.put("nodes",jdbc.queryForList("""
                    SELECT n.node_id,n.configuration_sha256,n.lease_until,n.started_at,
                      (SELECT COUNT(*) FROM t_cluster_session s WHERE s.node_id=n.node_id) AS sessions
                    FROM t_cluster_node n ORDER BY n.node_id LIMIT 128
                    """));
            result.put("queue",jdbc.queryForMap("""
                    SELECT COUNT(*) AS retained,
                      COALESCE(SUM(CASE WHEN state IN ('pending','retry') THEN 1 ELSE 0 END),0) AS pending,
                      COALESCE(SUM(CASE WHEN state='dead' THEN 1 ELSE 0 END),0) AS dead,
                      COALESCE(SUM(CASE WHEN state='applied' THEN 1 ELSE 0 END),0) AS applied,
                      COALESCE(SUM(CASE WHEN state<>'applied' THEN size_bytes ELSE 0 END),0) AS stored_bytes,
                      MIN(CASE WHEN state IN ('pending','retry') THEN created_at END) AS oldest_pending_at
                    FROM t_cluster_ingress
                    """));
            result.put("limits",Map.of("pendingReports",properties.getMaxPendingReports(),"storedBytes",properties.getMaxPendingBytes(),
                    "reportBytes",properties.getMaxReportBytes(),"historyReports",properties.getMaxHistoryReports(),"dedupRetentionMs",properties.getDedupRetentionMs()));
            result.put("deadReports",jdbc.queryForList("""
                    SELECT id,agent_id,report_id,payload_type,content_sha256,size_bytes,attempts,error_code,
                      created_at,finished_at,replay_count,last_retry_by,last_retry_at,last_retry_note
                    FROM t_cluster_ingress WHERE state='dead' ORDER BY sequence_id DESC LIMIT 100
                    """));
            result.put("malformedHints",rabbit.malformedHints());
            result.put("failedNotifications",jdbc.queryForObject("SELECT COUNT(*) FROM t_alert_notify_delivery WHERE delivered_at IS NULL AND attempts>=5",Long.class));
            return result;
        });
    }
    public record Retry(String sha256,String note){}
    public void retry(String id,Retry change,Long actor) {
        if(!properties.isEnabled()) throw new IllegalArgumentException("当前为单实例模式");
        if(id==null || !id.matches("[a-f0-9-]{36}") || change==null || change.sha256()==null
                || !change.sha256().matches("[a-f0-9]{64}") || change.note()==null || change.note().isBlank() || change.note().length()>500)
            throw new IllegalArgumentException("请核对报告摘要并填写 1 至 500 字重试说明");
        tx.executeWithoutResult(status->{
            EvidenceService.admin(jdbc,actor);runtime.requireActive(jdbc);
            jdbc.update("UPDATE t_cluster_state SET next_sequence=next_sequence WHERE id=1");
            var rows=jdbc.queryForList("SELECT * FROM t_cluster_ingress WHERE id=? FOR UPDATE",id);
            if(rows.size()!=1) throw new IllegalArgumentException("失败报告已被清理，请刷新");
            var row=rows.get(0);
            if(!row.get("state").equals("dead") || !row.get("content_sha256").equals(change.sha256())
                    || ((Number)row.get("replay_count")).intValue()>=3 || row.get("error_code").equals("report_rejected"))
                throw new IllegalArgumentException("报告状态已变化、内容无效或已达到三次人工重试上限");
            var states=jdbc.queryForList("SELECT status FROM t_agent WHERE agent_id=?",Integer.class,row.get("agent_id"));
            if(states.size()!=1 || states.get(0)<0 || states.get(0)>2) throw new IllegalArgumentException("主机已停用或删除，不能重试");
            long pending=jdbc.queryForObject("SELECT COUNT(*) FROM t_cluster_ingress WHERE state IN ('pending','retry')",Long.class);
            if(pending>=properties.getMaxPendingReports())throw new IllegalArgumentException("待处理报告已达到容量上限");
            jdbc.update("""
                    UPDATE t_cluster_ingress SET state='retry',attempts=0,next_attempt_at=0,published_at=0,
                      finished_at=NULL,error_code='',replay_count=replay_count+1,last_retry_by=?,last_retry_at=?,last_retry_note=?
                    WHERE id=? AND state='dead'
                    """,actor,ClusterRuntime.databaseTime(jdbc),change.note().strip(),id);
        });
    }
}
