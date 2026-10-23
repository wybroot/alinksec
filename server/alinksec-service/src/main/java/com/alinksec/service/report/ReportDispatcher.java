package com.alinksec.service.report;

import com.alinksec.service.alert.SecurityEventService;
import com.alinksec.service.asset.AssetService;
import com.alinksec.service.baseline.BaselineResultService;
import com.alinksec.service.command.CommandService;
import com.alinksec.service.fix.FixResultService;
import com.alinksec.service.heartbeat.HeartbeatService;
import com.alinksec.service.log.LogBatchService;
import com.alinksec.service.metrics.MetricsForwarder;
import com.alinksec.service.scan.ScanResultService;
import com.alinksec.service.virus.VirusResultService;
import com.alinksec.service.config.DatabaseDialect;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;

/**
 * 上行 Report 统一分发（通信协议 §4）。
 * report_id 幂等：PG 临时去重表（M2 换 Redis SETNX + 10min TTL）。
 */
@Service
public class ReportDispatcher {

    private static final Logger log = LoggerFactory.getLogger(ReportDispatcher.class);

    private final com.alinksec.service.evidence.EvidenceService evidence;
    private final HeartbeatService heartbeatService;
    private final AssetService assetService;
    private final SecurityEventService securityEventService;
    private final CommandService commandService;
    private final BaselineResultService baselineResultService;
    private final ScanResultService scanResultService;
    private final VirusResultService virusResultService;
    private final FixResultService fixResultService;
    private final MetricsForwarder metricsForwarder;
    private final LogBatchService logBatchService;
    private final JdbcTemplate jdbc;
    private final DatabaseDialect database;
    private final com.alinksec.service.fix.WindowsUpdateService windowsUpdates;
    private final org.springframework.transaction.support.TransactionTemplate virusTransaction;

    public ReportDispatcher(HeartbeatService heartbeatService, AssetService assetService,
                            SecurityEventService securityEventService, CommandService commandService,
                            BaselineResultService baselineResultService,
                            ScanResultService scanResultService,
                            VirusResultService virusResultService,
                            FixResultService fixResultService,
                            MetricsForwarder metricsForwarder,
                            LogBatchService logBatchService,
                            JdbcTemplate jdbc, DatabaseDialect database,org.springframework.transaction.PlatformTransactionManager transactionManager,com.alinksec.service.fix.WindowsUpdateService windowsUpdates,com.alinksec.service.evidence.EvidenceService evidence) {
        this.evidence=evidence;
        this.heartbeatService = heartbeatService;
        this.assetService = assetService;
        this.securityEventService = securityEventService;
        this.commandService = commandService;
        this.baselineResultService = baselineResultService;
        this.scanResultService = scanResultService;
        this.virusResultService = virusResultService;
        this.fixResultService = fixResultService;
        this.metricsForwarder = metricsForwarder;
        this.logBatchService = logBatchService;
        this.jdbc = jdbc;
        this.windowsUpdates=windowsUpdates;
        this.database = database;
        this.virusTransaction=new org.springframework.transaction.support.TransactionTemplate(transactionManager);
    }

    public void dispatch(String agentId, com.alinksec.proto.Report report) {
        if(report.hasEvidence() || report.hasScapResult() || report.hasWindowsUpdate() || report.hasFixResult() || report.hasVirusResult() || report.hasScanResult() || isolationOutcome(report) || configOutcome(report) || ransomOutcome(report) || com.alinksec.service.protect.WindowsLoginService.outcome(report) || report.hasSecurityEvent() && report.getSecurityEvent().getType().equals("virus")) {
            virusTransaction.executeWithoutResult(s->dispatchAccepted(agentId,report));
        } else dispatchAccepted(agentId,report);
    }
    private void dispatchAccepted(String agentId,com.alinksec.proto.Report report) {
        // 幂等：10min 窗口内重复 report_id 直接丢弃（离线补传场景）
        String key=report.getReportId();
        if((report.hasEvidence() || report.hasScapResult() || report.hasWindowsUpdate() || report.hasFixResult() || report.hasVirusResult() || report.hasScanResult() || isolationOutcome(report) || configOutcome(report) || ransomOutcome(report) || com.alinksec.service.protect.WindowsLoginService.outcome(report) || report.hasSecurityEvent() && report.getSecurityEvent().getType().equals("virus")) && !key.isBlank()) {
            try { key=java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest((agentId+"\0"+key).getBytes(java.nio.charset.StandardCharsets.UTF_8))); }
            catch(java.security.NoSuchAlgorithmException e) { throw new IllegalStateException(e); }
        }
        if (!key.isBlank() && !tryAcquire(key, Duration.ofMinutes(10))) {
            log.debug("重复上报丢弃: report_id={}", report.getReportId());
            return;
        }
        switch (report.getPayloadCase()) {
            case HEARTBEAT -> heartbeatService.onHeartbeat(agentId, report.getHeartbeat());
            case ACK -> commandService.onAck(agentId, report.getAck());
            case ASSET -> assetService.replaceSnapshot(agentId, report.getAsset());
            case SECURITY_EVENT -> {
                if(com.alinksec.service.protect.WindowsLoginService.outcome(report) && !com.alinksec.service.protect.WindowsLoginService.accept(jdbc,agentId,report)) return;
                if(configOutcome(report)) {
                    var event=report.getSecurityEvent();
                    var detail=com.alinksec.common.util.JsonUtils.read(event.getDetail());
                    String id=detail.path("id").asText();
                    if(event.getDetail().length()>8192 || !id.matches("[0-9a-f]{32}")
                            || !report.getReportId().equals(id+"-config-event")
                            || !java.util.Set.of("agent.yml","policy.json","trusted_state","marker").contains(detail.path("file").asText())
                            || !event.getActionTaken().equals("trusted_config_in_use")
                            || !detail.path("action").asText().equals(event.getActionTaken())
                            || !java.util.Set.of("restored","blocked","unapproved_file_ignored","memory_snapshot_retained").contains(detail.path("shadow").asText()))
                        throw new IllegalArgumentException("invalid persistent configuration event identity");
                    if(jdbc.update("INSERT INTO t_agent_config_event_receipt(agent_id,event_id,detail) VALUES (?,?,?) ON CONFLICT(agent_id,event_id) DO NOTHING",
                            agentId,report.getReportId(),event.getDetail())==0) return;
                }
                if(isolationOutcome(report)) {
                    var detail=com.alinksec.common.util.JsonUtils.read(report.getSecurityEvent().getDetail());
                    String id=detail.path("id").asText(),phase=detail.path("phase").asText();
                    if(!id.matches("[0-9a-f]{32}") || !java.util.Set.of("finished","attention").contains(phase)
                            || !report.getReportId().equals(id+"-"+phase+"-event"))
                        throw new IllegalArgumentException("invalid persistent isolation outcome identity");
                    if(jdbc.update("INSERT INTO t_isolation_outcome_receipt(agent_id,event_id,detail) VALUES (?,?,?) ON CONFLICT(agent_id,event_id) DO NOTHING",
                            agentId,report.getReportId(),report.getSecurityEvent().getDetail())==0) return;
                }
                securityEventService.onEvent(agentId, report.getSecurityEvent());
                virusResultService.onRealtime(agentId,report.getSecurityEvent(),report.getReportId());
            }
            case METRICS -> metricsForwarder.onBatch(agentId, report.getMetrics());
            case BASELINE_RESULT -> baselineResultService.onResult(agentId, report.getBaselineResult());
            case EVIDENCE -> evidence.accept(agentId,report);
            case SCAP_RESULT -> com.alinksec.service.baseline.ScapResults.accept(jdbc,agentId,report.getScapResult());
            case SCAN_RESULT -> scanResultService.onResult(agentId, report.getScanResult());
            case VIRUS_RESULT -> virusResultService.onResult(agentId, report.getVirusResult());
            case FIX_RESULT -> fixResultService.onResult(agentId, report.getFixResult());
            case WINDOWS_UPDATE -> windowsUpdates.onSnapshot(agentId,report.getWindowsUpdate());
            case LOG_BATCH -> logBatchService.onBatch(agentId, report.getLogBatch());
            default -> log.warn("未知上报类型: {}", report.getPayloadCase());
        }
    }

    public java.util.List<String> windowsUpdateReceipts(String agent,com.alinksec.proto.RptFixResult result) {
        return com.alinksec.service.fix.WindowsUpdateResult.receipts(jdbc,agent,result);
    }
    public java.util.Optional<com.alinksec.proto.CmdEvidenceReceipt> evidenceReceipt(String agent,com.alinksec.proto.Report report) {
        return evidence.receipt(agent,report);
    }

    private static boolean isolationOutcome(com.alinksec.proto.Report report) {
        return report.hasSecurityEvent() && report.getSecurityEvent().getType().equals("self_defense")
                && report.getSecurityEvent().getRuleId().equals("host-isolation-lease");
    }

    private static boolean ransomOutcome(com.alinksec.proto.Report report) {
        return report.hasSecurityEvent() && (java.util.Set.of("decoy_tamper", "ransom_behavior")
                .contains(report.getSecurityEvent().getType()) || report.getSecurityEvent().getRuleId().equals("windows-ransom-attribution"));
    }

    private static boolean configOutcome(com.alinksec.proto.Report report) {
        return report.hasSecurityEvent() && report.getSecurityEvent().getType().equals("self_defense")
                && report.getSecurityEvent().getRuleId().equals("agent-config-integrity");
    }

    /** 去重表 SETNX 语义：插入成功 = 首次见到 */
    private boolean tryAcquire(String reportId, Duration ttl) {
        try {
            int inserted = jdbc.update("""
                    INSERT INTO t_report_dedup (report_id, expire_at)
                    VALUES (?, ?)
                    ON CONFLICT (report_id) DO NOTHING
                    """, reportId, database.timestampAfter(ttl));
            // 顺手清理过期行（低频小表，代价可忽略）
            jdbc.update("DELETE FROM t_report_dedup WHERE expire_at < CURRENT_TIMESTAMP");
            return inserted == 1;
        } catch (Exception e) {
            // 去重表异常不阻塞主链路（宁可重复处理，不可丢上报）
            log.warn("上报去重检查失败（放行）: {}", e.getMessage());
            return true;
        }
    }
}
