package com.alinksec.service.cluster;

import com.alinksec.proto.Report;
import com.alinksec.service.report.ReportDispatcher;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

/** Authenticated admission is durable before publication; hints cannot authorize or replace report bytes. */
@Service
public class ClusterReportIngress {
    private static final class SupersededAsset extends IllegalStateException {}
    private static final Set<Report.PayloadCase> ASYNC=Set.of(Report.PayloadCase.ASSET,
            Report.PayloadCase.BASELINE_RESULT,Report.PayloadCase.LOG_BATCH);
    private final ClusterProperties properties;
    private final JdbcTemplate jdbc;
    private final TransactionTemplate transaction;
    private final RabbitTransport rabbit;
    private final ReportDispatcher dispatcher;
    private final ClusterRuntime runtime;

    public ClusterReportIngress(ClusterProperties properties,JdbcTemplate jdbc,PlatformTransactionManager manager,
                                RabbitTransport rabbit,ReportDispatcher dispatcher,ClusterRuntime runtime) {
        this.properties=properties;this.jdbc=jdbc;this.transaction=new TransactionTemplate(manager);
        this.rabbit=rabbit;this.dispatcher=dispatcher;this.runtime=runtime;
    }

    /** Called only inside the gateway's authenticated current-session fence. Critical receipts stay synchronous. */
    public boolean admit(String agent,Report report) {
        if(!properties.isEnabled() || !ASYNC.contains(report.getPayloadCase())) return false;
        if(!agent.equals(report.getAgentId()) || !report.getReportId().matches("[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
                || report.getSerializedSize()>properties.getMaxReportBytes())
            throw new IllegalArgumentException("invalid_queued_report_identity_or_size");
        byte[] bytes=report.toByteArray();String digest=digest(bytes);
        transaction.executeWithoutResult(status-> {
            runtime.requireActive(jdbc);
            requireAgent(agent,false);
            jdbc.update("UPDATE t_cluster_state SET next_sequence=next_sequence WHERE id=1");
            var prior=jdbc.queryForList("SELECT content_sha256 FROM t_cluster_ingress WHERE agent_id=? AND report_id=?",
                    String.class,agent,report.getReportId());
            if(!prior.isEmpty()) {
                if(!prior.get(0).equals(digest)) throw new IllegalArgumentException("queued_report_identity_reused");
                return;
            }
            var capacity=jdbc.queryForMap("""
                    SELECT count(*) AS retained,COALESCE(SUM(CASE WHEN content_b64<>'' THEN size_bytes ELSE 0 END),0) AS bytes,
                      COALESCE(SUM(CASE WHEN content_b64<>'' THEN 1 ELSE 0 END),0) AS pending FROM t_cluster_ingress
                    """);
            if(number(capacity,"retained")>=properties.getMaxHistoryReports()
                    || number(capacity,"pending")>=properties.getMaxPendingReports()
                    || number(capacity,"bytes")+bytes.length>properties.getMaxPendingBytes())
                throw new ClusterUnavailable("report_ingress_capacity");
            long sequence=jdbc.queryForObject("UPDATE t_cluster_state SET next_sequence=next_sequence+1 WHERE id=1 RETURNING next_sequence",Long.class);
            jdbc.update("""
                    INSERT INTO t_cluster_ingress(sequence_id,id,agent_id,report_id,payload_type,content_b64,content_sha256,size_bytes,created_at)
                    VALUES(?,?,?,?,?,?,?,?,?)
                    """,sequence,UUID.randomUUID().toString(),agent,report.getReportId(),report.getPayloadCase().name(),
                    Base64.getEncoder().encodeToString(bytes),digest,bytes.length,now());
        });
        return true;
    }

    @Scheduled(fixedDelay=1000,initialDelay=5000,scheduler="clusterScheduler")
    public void publishPending() {
        if(!properties.isEnabled() || !runtime.ready()) return;
        try {
            long now=now();
            var rows=jdbc.queryForList("""
                    SELECT id FROM t_cluster_ingress WHERE state IN ('pending','retry')
                      AND next_attempt_at<=? AND published_at<? ORDER BY sequence_id LIMIT 64
                    """,String.class,now,now-15_000);
            long deadline=System.nanoTime()+1_000_000_000L;
            for(String id:rows) {
                rabbit.publish(id);
                jdbc.update("UPDATE t_cluster_ingress SET published_at=? WHERE id=? AND state IN ('pending','retry')",now(),id);
                if(System.nanoTime()>=deadline) break;
            }
        } catch(RuntimeException failure) { /* The SQL fact remains pending even when publisher confirmation is lost. */ }
    }

    @Scheduled(fixedDelay=250,initialDelay=5000,scheduler="clusterScheduler")
    public void consumeFirst() { consume(0); }
    @Scheduled(fixedDelay=250,initialDelay=5000,scheduler="clusterScheduler")
    public void consumeSecond() { consume(1); }
    private void consume(int lane) {
        if(!properties.isEnabled() || !runtime.ready()) return;
        long deadline=System.nanoTime()+1_000_000_000L;
        try {
            for(int count=0;count<64 && System.nanoTime()<deadline;count++)
                if(!rabbit.receive(lane,this::processHint)) break;
        } catch(RuntimeException failure) { /* Infrastructure failures leave the exact hint unacknowledged. */ }
    }

    public void processHint(String hint) {
        var failed=new AtomicReference<Map<String,Object>>();
        try {
            transaction.executeWithoutResult(status-> {
            runtime.requireActive(jdbc);
                var hints=jdbc.queryForList("SELECT agent_id FROM t_cluster_ingress WHERE id=?",String.class,hint);
                if(hints.isEmpty()) return;
                String agent=hints.get(0);
                if(!lockQueue(agent)) return;
                var rows=jdbc.queryForList("""
                        SELECT * FROM t_cluster_ingress WHERE agent_id=? AND state IN ('pending','retry')
                        ORDER BY sequence_id LIMIT 1
                        """,agent);
                if(rows.isEmpty()) return;
                var row=rows.get(0);
                if(number(row,"next_attempt_at")>now()) return;
                failed.set(row);
                requireAgent(agent,true);
                Report report=decode(row);
                // A manually replayed failed snapshot must not replace facts from a newer snapshot.
                if(report.hasAsset() && jdbc.queryForObject("SELECT cluster_asset_sequence FROM t_agent WHERE agent_id=?",
                        Long.class,agent)>number(row,"sequence_id"))throw new SupersededAsset();
                dispatcher.dispatchQueued(agent,report);
                if(report.hasAsset())jdbc.update("UPDATE t_agent SET cluster_asset_sequence=? WHERE agent_id=?",row.get("sequence_id"),agent);
                jdbc.update("""
                        UPDATE t_cluster_ingress SET state='applied',content_b64='',finished_at=?,error_code=''
                        WHERE id=? AND state IN ('pending','retry')
                        """,now(),row.get("id"));
            });
        } catch(RuntimeException failure) {
            var row=failed.get();
            if(row==null) throw failure;
            recordFailure(row,failure);
        }
    }

    private void recordFailure(Map<String,Object> row,RuntimeException failure) {
        transaction.executeWithoutResult(status-> {
            runtime.requireActive(jdbc);
            String agent=row.get("agent_id").toString();
            if(!lockQueue(agent)) throw new ClusterUnavailable("report_retry_lock_busy");
            var fresh=jdbc.queryForList("SELECT attempts,state FROM t_cluster_ingress WHERE id=?",row.get("id"));
            if(fresh.isEmpty() || !Set.of("pending","retry").contains(fresh.get(0).get("state"))) return;
            int attempts=((Number)fresh.get(0).get("attempts")).intValue()+1;
            boolean dead=attempts>=5 || failure instanceof SecurityException || failure instanceof SupersededAsset;
            String code=failure instanceof SupersededAsset ? "asset_superseded" : failure instanceof IllegalArgumentException ? "report_rejected" : failure instanceof SecurityException ? "agent_revoked" : "processing_failed";
            long now=now();
            jdbc.update("""
                    UPDATE t_cluster_ingress SET state=?,attempts=?,next_attempt_at=?,published_at=0,error_code=?,finished_at=?
                    WHERE id=? AND state IN ('pending','retry')
                    """,dead?"dead":"retry",attempts,now+Math.min(30_000,attempts*1000L),code,dead?now:null,row.get("id"));
        });
    }

    private void requireAgent(String agent,boolean writing) {
        var statuses=jdbc.queryForList("SELECT status FROM t_agent WHERE agent_id=? FOR "+(writing?"UPDATE":"SHARE"),Integer.class,agent);
        if(statuses.size()!=1 || statuses.get(0)<0 || statuses.get(0)>2) throw new SecurityException("agent_revoked");
    }

    private boolean lockQueue(String agent) {
        byte[] hash=hash((properties.getDeploymentId()+"\0report-queue\0"+agent).getBytes(StandardCharsets.UTF_8));
        return Boolean.TRUE.equals(jdbc.queryForObject("SELECT pg_try_advisory_xact_lock(?)",Boolean.class,ByteBuffer.wrap(hash).getLong()));
    }

    private Report decode(Map<String,Object> row) {
        try {
            String encoded=row.get("content_b64").toString();
            if(encoded.length()>((properties.getMaxReportBytes()+2L)/3)*4) throw new IllegalArgumentException();
            byte[] bytes=Base64.getDecoder().decode(encoded);
            if(bytes.length!=number(row,"size_bytes") || bytes.length>properties.getMaxReportBytes()
                    || !digest(bytes).equals(row.get("content_sha256"))) throw new IllegalArgumentException();
            Report report=Report.parseFrom(bytes);
            if(!report.getAgentId().equals(row.get("agent_id")) || !report.getReportId().equals(row.get("report_id"))
                    || !report.getPayloadCase().name().equals(row.get("payload_type")) || !ASYNC.contains(report.getPayloadCase()))
                throw new IllegalArgumentException();
            return report;
        } catch(Exception failure) { throw new IllegalArgumentException("invalid_inbox_report"); }
    }

    @Scheduled(fixedDelay=60_000,initialDelay=60_000,scheduler="clusterScheduler")
    public void cleanup() {
        if(!properties.isEnabled() || !runtime.ready()) return;
        transaction.executeWithoutResult(status-> {
            runtime.requireActive(jdbc);
            jdbc.update("UPDATE t_cluster_state SET next_sequence=next_sequence WHERE id=1");
            long now=now();
            jdbc.update("""
                    DELETE FROM t_cluster_ingress WHERE sequence_id IN (
                      SELECT sequence_id FROM t_cluster_ingress WHERE state='applied' AND finished_at<?
                        OR state='dead' AND finished_at<? ORDER BY sequence_id LIMIT 1000)
                    """,now-properties.getDedupRetentionMs(),now-30L*24*60*60*1000);
        });
    }
    private long now() { return jdbc.queryForObject("SELECT (EXTRACT(EPOCH FROM clock_timestamp())*1000)::BIGINT",Long.class); }
    private static long number(Map<String,Object> row,String key) { return ((Number)row.get(key)).longValue(); }
    private static byte[] hash(byte[] bytes) {
        try { return MessageDigest.getInstance("SHA-256").digest(bytes); }
        catch(java.security.NoSuchAlgorithmException failure) { throw new IllegalStateException(failure); }
    }
    private static String digest(byte[] bytes) { return HexFormat.of().formatHex(hash(bytes)); }
}
