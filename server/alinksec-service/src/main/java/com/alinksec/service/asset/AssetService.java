package com.alinksec.service.asset;

import com.alinksec.proto.RptAssetSnapshot;
import com.alinksec.proto.SoftwareInventory;
import com.alinksec.service.scan.PackageVersions;
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
import java.util.HashSet;
import java.util.Set;
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
        Set<String> collected = new HashSet<>(snapshot.getCollectedList());
        boolean legacyFullSnapshot = collected.isEmpty();
        boolean replaceSoftware = (legacyFullSnapshot || collected.contains("software"))
                && recordSoftwareAttempt(agentId, snapshot);
        if (replaceSoftware) {
            jdbc.update("DELETE FROM t_asset_software WHERE agent_id = ?", agentId);
        }
        if (legacyFullSnapshot || collected.contains("ports")) {
            jdbc.update("DELETE FROM t_asset_port WHERE agent_id = ?", agentId);
        }
        if (legacyFullSnapshot || collected.contains("processes")) {
            jdbc.update("DELETE FROM t_asset_process WHERE agent_id = ?", agentId);
        }
        if (legacyFullSnapshot || collected.contains("accounts")) {
            jdbc.update("DELETE FROM t_asset_account WHERE agent_id = ?", agentId);
        }
        if (legacyFullSnapshot || collected.contains("containers")) {
            jdbc.update("DELETE FROM t_asset_container WHERE agent_id = ?", agentId);
        }

        if (replaceSoftware) {
            for (var sw : snapshot.getSoftwareList()) {
                jdbc.update("""
                        INSERT INTO t_asset_software (agent_id, name, version, vendor, install_time, source, architecture)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        """, agentId, sw.getName(), sw.getVersion(), sw.getVendor(),
                        sw.getInstallTime() > 0 ? Timestamp.from(Instant.ofEpochMilli(sw.getInstallTime())) : null,
                        sw.getSource(), sw.getArchitecture());
            }
        }
        if (legacyFullSnapshot || collected.contains("ports")) {
            for (var p : snapshot.getPortsList()) {
                jdbc.update("""
                        INSERT INTO t_asset_port (agent_id, port, protocol, process, bind_addr)
                        VALUES (?, ?, ?, ?, ?)
                        """, agentId, p.getPort(), p.getProtocol(), p.getProcess(), p.getBindAddr());
            }
        }
        if (legacyFullSnapshot || collected.contains("accounts")) {
            for (var a : snapshot.getAccountsList()) {
                jdbc.update("""
                        INSERT INTO t_asset_account (agent_id, name, uid, gid, shell, login_enabled, last_login, risky, risky_reason)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """, agentId, a.getName(), a.getUid(), a.getGid(), a.getShell(), a.getLoginEnabled(),
                        a.getLastLogin() > 0 ? Timestamp.from(Instant.ofEpochMilli(a.getLastLogin())) : null,
                        a.getRisky(), a.getRiskyReason());
            }
        }
        if (legacyFullSnapshot || collected.contains("processes")) {
            for (var p : snapshot.getProcessesList()) {
                jdbc.update("INSERT INTO t_asset_process (agent_id, pid, name, exe, cmdline, username, rss_bytes) VALUES (?, ?, ?, ?, ?, ?, ?)",
                        agentId, p.getPid(), p.getName(), p.getExe(), p.getCmdline(), p.getUser(), p.getRssBytes());
            }
        }
        if (legacyFullSnapshot || collected.contains("containers")) {
            for (var c : snapshot.getContainersList()) {
                jdbc.update("""
                        INSERT INTO t_asset_container (agent_id, container_id, name, image, image_id, orchestrator, namespace, status, created_at, started_at, ports, labels, risky, risk_reasons)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
        }
        log.info("资产快照已更新: agent={} software={} ports={} accounts={} containers={}",
                agentId, snapshot.getSoftwareCount(), snapshot.getPortsCount(), snapshot.getAccountsCount(), snapshot.getContainersCount());
        // Only a replaced software inventory should initiate a new comparison.
        // A database error can still roll back the surrounding transaction.
        if (!replaceSoftware) return;
        try {
            vulnMatchService.matchAgent(agentId, 0L);
        } catch (Exception e) {
            log.warn("快照后漏洞比对失败: agent={} err={}", agentId, e.getMessage());
        }
    }

    private boolean recordSoftwareAttempt(String agentId, RptAssetSnapshot snapshot) {
        if (!snapshot.hasSoftwareInventory()) {
            jdbc.update("""
                    UPDATE t_agent SET software_collection_status='legacy', software_collection_error='',
                      software_attempted_at=CURRENT_TIMESTAMP, distro_id='', distro_version='',
                      software_inventory_source='', software_identity_error='legacy_inventory', software_succeeded_at=NULL,
                      package_repair_contract=0
                    WHERE agent_id=?
                    """, agentId);
            return true;
        }
        var inventory = snapshot.getSoftwareInventory();
        boolean complete = inventory.getStatus() == SoftwareInventory.Status.COMPLETE;
        String error = bounded(inventory.getError(), 128);
        if (complete && !validSoftware(snapshot)) {
            complete = false;
            error = "invalid_software_inventory";
        }
        if (!complete) {
            jdbc.update("""
                    UPDATE t_agent SET software_collection_status=?, software_collection_error=?,
                      software_attempted_at=CURRENT_TIMESTAMP WHERE agent_id=?
                    """, inventory.getStatus() == SoftwareInventory.Status.UNSUPPORTED ? "unsupported" : "failed",
                    error.isBlank() ? "incomplete_software_inventory" : error, agentId);
            return false;
        }
        String distroId = inventory.getDistroId(), distroVersion = inventory.getDistroVersion();
        String identityError = bounded(inventory.getIdentityError(), 128);
        if ((!distroId.isEmpty() && !distroId.matches("[a-z0-9][a-z0-9_.-]{0,63}"))
                || (!distroVersion.isEmpty() && !distroVersion.matches("[A-Za-z0-9][A-Za-z0-9._+-]{0,127}"))) {
            distroId = "";
            distroVersion = "";
            identityError = "distribution_identity_invalid";
        }
        if (!"registry".equals(inventory.getSource()) && (distroId.isEmpty() || distroVersion.isEmpty()) && identityError.isEmpty()) {
            identityError = "distribution_identity_incomplete";
        }
        jdbc.update("""
                UPDATE t_agent SET software_collection_status='complete', software_collection_error='',
                  software_attempted_at=CURRENT_TIMESTAMP, software_succeeded_at=CURRENT_TIMESTAMP,
                  distro_id=?, distro_version=?, software_inventory_source=?, software_identity_error=?, package_repair_contract=?
                WHERE agent_id=?
                """, distroId, distroVersion, inventory.getSource(), identityError,
                inventory.getPackageRepairContract() == 1 && !"registry".equals(inventory.getSource()) ? 1 : 0, agentId);
        return true;
    }

    private static boolean validSoftware(RptAssetSnapshot snapshot) {
        String source = snapshot.getSoftwareInventory().getSource();
        if (!Set.of("rpm", "dpkg", "mixed", "registry").contains(source) || snapshot.getSoftwareCount() > 100000) return false;
        Set<String> identities = new HashSet<>();
        for (var sw : snapshot.getSoftwareList()) {
            if (sw.getName().isBlank() || sw.getName().length() > 255 || sw.getVersion().length() > 255
                    || sw.getVendor().length() > 255 || sw.getArchitecture().length() > 64
                    || !Set.of("rpm", "dpkg", "registry").contains(sw.getSource())
                    || (!source.equals(sw.getSource()) && !(source.equals("mixed") && Set.of("rpm", "dpkg").contains(sw.getSource())))
                    || !identities.add(sw.getSource() + "\u0000" + sw.getName() + "\u0000" + sw.getArchitecture() + "\u0000" + sw.getVersion())) return false;
            if (Set.of("rpm", "dpkg").contains(sw.getSource())) {
                if (!sw.getArchitecture().matches("[A-Za-z0-9][A-Za-z0-9_.+-]{0,63}")) return false;
                try { PackageVersions.compare(sw.getSource(), sw.getVersion(), sw.getVersion()); }
                catch (IllegalArgumentException e) { return false; }
            }
        }
        return true;
    }

    private static String bounded(String value, int limit) {
        return value.length() <= limit ? value : value.substring(0, limit);
    }
}
