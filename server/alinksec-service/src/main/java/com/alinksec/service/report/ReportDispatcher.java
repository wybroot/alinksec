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

    public ReportDispatcher(HeartbeatService heartbeatService, AssetService assetService,
                            SecurityEventService securityEventService, CommandService commandService,
                            BaselineResultService baselineResultService,
                            ScanResultService scanResultService,
                            VirusResultService virusResultService,
                            FixResultService fixResultService,
                            MetricsForwarder metricsForwarder,
                            LogBatchService logBatchService,
                            JdbcTemplate jdbc, DatabaseDialect database) {
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
        this.database = database;
    }

    public void dispatch(String agentId, com.alinksec.proto.Report report) {
        // 幂等：10min 窗口内重复 report_id 直接丢弃（离线补传场景）
        if (!report.getReportId().isBlank() && !tryAcquire(report.getReportId(), Duration.ofMinutes(10))) {
            log.debug("重复上报丢弃: report_id={}", report.getReportId());
            return;
        }
        switch (report.getPayloadCase()) {
            case HEARTBEAT -> heartbeatService.onHeartbeat(agentId, report.getHeartbeat());
            case ACK -> commandService.onAck(agentId, report.getAck());
            case ASSET -> assetService.replaceSnapshot(agentId, report.getAsset());
            case SECURITY_EVENT -> securityEventService.onEvent(agentId, report.getSecurityEvent());
            case METRICS -> metricsForwarder.onBatch(agentId, report.getMetrics());
            case BASELINE_RESULT -> baselineResultService.onResult(agentId, report.getBaselineResult());
            case SCAN_RESULT -> scanResultService.onResult(agentId, report.getScanResult());
            case VIRUS_RESULT -> virusResultService.onResult(agentId, report.getVirusResult());
            case FIX_RESULT -> fixResultService.onResult(agentId, report.getFixResult());
            case LOG_BATCH -> logBatchService.onBatch(agentId, report.getLogBatch());
            default -> log.warn("未知上报类型: {}", report.getPayloadCase());
        }
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
