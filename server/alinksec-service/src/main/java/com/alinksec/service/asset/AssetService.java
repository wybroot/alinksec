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
        if(snapshot.getSequence()>0 && (snapshot.getCollectedCount()==0 || snapshot.getCollectionsCount()==0) || snapshot.getCollectedCount()>6 || snapshot.getCollectionsCount()>6 || snapshot.getContainerSourcesCount()>2)
            throw new IllegalArgumentException("invalid asset collection metadata");
        Set<String> collected = new HashSet<>(snapshot.getCollectedList());
        Set<String> accepted=new HashSet<>(),complete=new HashSet<>();
        if(collected.isEmpty())collected.addAll(Set.of("software","ports","processes","accounts","disks","containers"));
        if(collected.size()>6 || snapshot.getSequence()<0)throw new IllegalArgumentException("invalid asset collection sequence");
        var states=new java.util.HashMap<String,com.alinksec.proto.AssetCollection>();
        for(var state:snapshot.getCollectionsList())if(states.put(state.getCategory(),state)!=null)throw new IllegalArgumentException("duplicate collection status");
        for(String category:collected) {
            if(!Set.of("software","ports","processes","accounts","disks","containers").contains(category))throw new IllegalArgumentException("invalid asset category");
            var state=states.get(category);
            boolean legacy=state==null;
            if(legacy && snapshot.getSequence()>0)throw new IllegalArgumentException("missing collection outcome");
            String status=legacy?"legacy":state.getStatus().name().toLowerCase(java.util.Locale.ROOT);
            if(category.equals("software") && snapshot.hasSoftwareInventory())status=switch(snapshot.getSoftwareInventory().getStatus()) {
                case FAILED -> "failed";case UNSUPPORTED -> "unsupported";case UNKNOWN,UNRECOGNIZED -> "unknown";default -> status;
            };
            String error=legacy?"unknown_coverage":state.getError();
            if(error.length()>128)throw new IllegalArgumentException("invalid collection error");
            int changed=jdbc.update("INSERT INTO t_asset_collection_state(agent_id,category,sequence,status,error,collected_at) VALUES(?,?,?,?,?,?) ON CONFLICT(agent_id,category) DO UPDATE SET sequence=excluded.sequence,status=excluded.status,error=excluded.error,collected_at=excluded.collected_at WHERE excluded.sequence>t_asset_collection_state.sequence OR (excluded.sequence=0 AND t_asset_collection_state.sequence=0)",agentId,category,snapshot.getSequence(),status,error,legacy?0:state.getCollectedAt());
            if(changed==1) {
                accepted.add(category);
                if(status.equals("complete") || legacy && !status.equals("failed"))complete.add(category);
            }
        }
        boolean softwareAttempt=accepted.contains("software");
        boolean legacyFullSnapshot=false;
        collected=complete;
        var softwareSnapshot=snapshot;
        if(softwareAttempt && !collected.contains("software") && (!snapshot.hasSoftwareInventory() || snapshot.getSoftwareInventory().getStatus()==SoftwareInventory.Status.COMPLETE))
            softwareSnapshot=snapshot.toBuilder().setSoftwareInventory(SoftwareInventory.newBuilder().setStatus(SoftwareInventory.Status.FAILED).setError("collection_incomplete")).build();
        boolean replaceSoftware=softwareAttempt && recordSoftwareAttempt(agentId,softwareSnapshot) && collected.contains("software");
        if(collected.contains("disks")) {
            jdbc.update("DELETE FROM t_asset_disk WHERE agent_id=?",agentId);
            for(var disk:snapshot.getDisksList())jdbc.update("INSERT INTO t_asset_disk(agent_id,mount,fs_type,total_bytes,used_bytes) VALUES(?,?,?,?,?)",agentId,disk.getMount(),disk.getFsType(),disk.getTotalBytes(),disk.getUsedBytes());
        }
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
        Set<String> completedSources=new HashSet<>(snapshot.getContainerSourcesList());
        if(!Set.of("docker","kubernetes").containsAll(completedSources))throw new IllegalArgumentException("invalid container source");
        boolean partialContainers=accepted.contains("containers") && !collected.contains("containers") && !completedSources.isEmpty() && states.containsKey("containers") && states.get("containers").getStatus()==com.alinksec.proto.AssetCollection.Status.PARTIAL;
        if(partialContainers)for(String source:completedSources)jdbc.update("DELETE FROM t_asset_container WHERE agent_id=? AND orchestrator=?",agentId,source);
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
        if (legacyFullSnapshot || collected.contains("containers") || partialContainers) {
            for (var c : snapshot.getContainersList()) {
                if(partialContainers && !completedSources.contains(c.getOrchestrator()))continue;
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
        if (!replaceSoftware) {
            // A failed/unsupported attempt must invalidate apparent coverage even
            // while retaining the last successful software rows.
            if (softwareAttempt && snapshot.hasSoftwareInventory()) vulnMatchService.matchAgent(agentId,0L);
            return;
        }
        try {
            vulnMatchService.matchAgent(agentId, 0L);
        } catch (Exception e) {
            log.warn("快照后漏洞比对失败: agent={} err={}", agentId, e.getMessage());
        }
    }

    private boolean recordSoftwareAttempt(String agentId, RptAssetSnapshot snapshot) {
        if (!snapshot.hasSoftwareInventory()) {
            jdbc.update("""
                    UPDATE t_agent SET software_revision=software_revision+1,software_collection_status='legacy', software_collection_error='',
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
                UPDATE t_agent SET software_revision=software_revision+1,software_collection_status='complete', software_collection_error='',
                  software_attempted_at=CURRENT_TIMESTAMP, software_succeeded_at=CURRENT_TIMESTAMP,
                  distro_id=?, distro_version=?, software_inventory_source=?, software_identity_error=?, package_repair_contract=?
                WHERE agent_id=?
                """, distroId, distroVersion, inventory.getSource(), identityError,
                inventory.getPackageRepairContract() == 2 && !"registry".equals(inventory.getSource()) ? 2 : 0, agentId);
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
