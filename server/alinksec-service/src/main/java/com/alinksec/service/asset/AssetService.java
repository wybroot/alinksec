package com.alinksec.service.asset;

import com.alinksec.proto.RptAssetSnapshot;
import com.alinksec.service.scan.VulnMatchService;
import com.alinksec.service.alert.SecurityEventService;
import com.alinksec.proto.RptSecurityEvent;
import com.alinksec.proto.Severity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.sql.Timestamp;
import java.time.Instant;
import com.alinksec.common.util.JsonUtils;

/**
 * 资产快照落库（数据库设计 §2.1：agent 维度全量替换）。
 * 落库后自动触发漏洞比对（t_cve_db × 软件快照，docs/04 §4.4）。
 */
@Service
public class AssetService {

    private static final Logger log = LoggerFactory.getLogger(AssetService.class);

    private final JdbcTemplate jdbc;
    private final VulnMatchService vulnMatchService;
    private final SecurityEventService securityEventService;

    public AssetService(JdbcTemplate jdbc, VulnMatchService vulnMatchService, SecurityEventService securityEventService) {
        this.jdbc = jdbc;
        this.vulnMatchService = vulnMatchService;
        this.securityEventService = securityEventService;
    }

    @Transactional
    public void replaceSnapshot(String agentId, RptAssetSnapshot snapshot) {
        jdbc.update("DELETE FROM t_asset_software WHERE agent_id = ?", agentId);
        jdbc.update("DELETE FROM t_asset_port WHERE agent_id = ?", agentId);
        jdbc.update("DELETE FROM t_asset_process WHERE agent_id = ?", agentId);
        jdbc.update("DELETE FROM t_asset_account WHERE agent_id = ?", agentId);
        jdbc.update("DELETE FROM t_asset_container WHERE agent_id = ?", agentId);

        for (var sw : snapshot.getSoftwareList()) {
            jdbc.update("""
                    INSERT INTO t_asset_software (agent_id, name, version, vendor, install_time, source)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """, agentId, sw.getName(), sw.getVersion(), sw.getVendor(),
                    sw.getInstallTime() > 0 ? Timestamp.from(Instant.ofEpochMilli(sw.getInstallTime())) : null,
                    sw.getSource());
        }
        for (var p : snapshot.getPortsList()) {
            jdbc.update("""
                    INSERT INTO t_asset_port (agent_id, port, protocol, process, bind_addr)
                    VALUES (?, ?, ?, ?, ?)
                    """, agentId, p.getPort(), p.getProtocol(), p.getProcess(), p.getBindAddr());
        }
        for (var a : snapshot.getAccountsList()) {
            jdbc.update("""
                    INSERT INTO t_asset_account (agent_id, name, uid, gid, shell, login_enabled, last_login, risky, risky_reason)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, agentId, a.getName(), a.getUid(), a.getGid(), a.getShell(), a.getLoginEnabled(),
                    a.getLastLogin() > 0 ? Timestamp.from(Instant.ofEpochMilli(a.getLastLogin())) : null,
                    a.getRisky(), a.getRiskyReason());
        }
        for (var p : snapshot.getProcessesList()) {
            jdbc.update("INSERT INTO t_asset_process (agent_id, pid, name, exe, cmdline, username, rss_bytes) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    agentId, p.getPid(), p.getName(), p.getExe(), p.getCmdline(), p.getUser(), p.getRssBytes());
        }
        for (var c : snapshot.getContainersList()) {
            jdbc.update("""
                    INSERT INTO t_asset_container (agent_id, container_id, name, image, image_id, orchestrator, namespace, status, created_at, started_at, ports, labels, risky, risk_reasons)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?::jsonb, ?::jsonb, ?, ?::jsonb)
                    """, agentId, c.getContainerId(), c.getName(), c.getImage(), c.getImageId(), c.getOrchestrator(),
                    c.getNamespace(), c.getStatus(), c.getCreatedAt() > 0 ? Timestamp.from(Instant.ofEpochMilli(c.getCreatedAt())) : null,
                    c.getStartedAt() > 0 ? Timestamp.from(Instant.ofEpochMilli(c.getStartedAt())) : null,
                    JsonUtils.write(c.getPortsList()), JsonUtils.write(c.getLabelsMap()), c.getRisky(), JsonUtils.write(c.getRiskReasonsList()));
            for (String reason : c.getRiskReasonsList()) {
                securityEventService.onEvent(agentId, RptSecurityEvent.newBuilder()
                        .setRuleId("CTR-" + reason.toUpperCase())
                        .setRuleName("Docker container: " + reason)
                        .setType("container_risk")
                        .setSeverity("privileged".equals(reason) ? Severity.SEV_HIGH : Severity.SEV_MEDIUM)
                        .setDetail(JsonUtils.write(java.util.Map.of("containerId", c.getContainerId(), "name", c.getName(), "image", c.getImage(), "reason", reason)))
                        .setActionTaken("alert_only")
                        .build());
            }
        }
        log.info("资产快照已更新: agent={} software={} ports={} accounts={} containers={}",
                agentId, snapshot.getSoftwareCount(), snapshot.getPortsCount(), snapshot.getAccountsCount(), snapshot.getContainersCount());
        // 快照触发漏洞比对（比对失败不影响快照落库——同一事务内异常会整体回滚，
        // 故捕获后仅告警；比对下一轮快照会重做）
        try {
            vulnMatchService.matchAgent(agentId, 0L);
        } catch (Exception e) {
            log.warn("快照后漏洞比对失败（快照已落库）: agent={} err={}", agentId, e.getMessage());
        }
    }
}
