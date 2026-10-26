package com.alinksec.bootstrap;

import com.alinksec.gateway.channel.ConnectionRegistry;
import com.alinksec.gateway.server.GrpcServerLifecycle;
import com.alinksec.proto.AgentChannelGrpc;
import com.alinksec.proto.CmdCollectNow;
import com.alinksec.proto.CmdProtectAction;
import com.alinksec.proto.Command;
import com.alinksec.proto.EnrollRequest;
import com.alinksec.proto.EnrollResponse;
import com.alinksec.proto.EnrollServiceGrpc;
import com.alinksec.proto.FixResultItem;
import com.alinksec.proto.HostInfo;
import com.alinksec.proto.OsType;
import com.alinksec.proto.Report;
import com.alinksec.proto.RptAck;
import com.alinksec.proto.RptAssetSnapshot;
import com.alinksec.proto.RptHeartbeat;
import com.alinksec.proto.RptFixResult;
import com.alinksec.proto.SoftwareInfo;
import com.alinksec.proto.SoftwareInventory;
import com.alinksec.service.agent.AgentEntity;
import com.alinksec.service.cert.CertService;
import com.alinksec.service.command.CommandRepository;
import com.alinksec.service.command.CommandService;
import com.alinksec.service.enroll.EnrollTokenService;
import com.alinksec.service.fix.FixTaskService;
import com.alinksec.service.fix.PatchRepoService;
import com.alinksec.service.protect.IsolationCommandLifecycleListener;
import com.alinksec.service.protect.PolicyStoreService;
import com.alinksec.service.protect.ProtectRuleService;
import com.alinksec.common.util.JsonUtils;
import io.grpc.ManagedChannel;
import io.grpc.Server;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.grpc.netty.shaded.io.grpc.netty.GrpcSslContexts;
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder;
import io.grpc.stub.StreamObserver;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ActiveProfilesResolver;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.ByteArrayInputStream;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
@ActiveProfiles(resolver = AgentChannelSecurityIntegrationTest.DatabaseProfile.class)
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
class AgentChannelSecurityIntegrationTest {

    @TempDir
    static Path tempDir;

    @Autowired JdbcTemplate jdbc;
    @Autowired CertService certificates;
    @Autowired GrpcServerLifecycle lifecycle;
    @Autowired EnrollTokenService tokens;
    @Autowired CommandService commands;
    @Autowired ConnectionRegistry connections;
    @Autowired PolicyStoreService policy;
    @Autowired FixTaskService fixTasks;
    @Autowired com.alinksec.service.library.LibraryCatalog library;
    @Autowired com.alinksec.service.scan.VulnMatchService matcher;
    @Autowired PatchRepoService patches;
    @Autowired ProtectRuleService rules;
    @Autowired com.alinksec.service.config.DatabaseDialect database;

    private final List<ManagedChannel> channels = new ArrayList<>();

    @Test
    void authenticatedHeartbeatAndDiskFactsPersistOnBothDatabaseProfiles() throws Exception {
        var owner = enroll(); var other = enroll();
        Stream stream = connect(owner);
        long boot = System.currentTimeMillis() / 1000 - 1234;
        stream.requests.onNext(report(owner.getAgentId()).setAsset(RptAssetSnapshot.newBuilder()
                .addCollected("disks").addDisks(com.alinksec.proto.DiskInfo.newBuilder()
                        .setMount("/").setFsType("ext4").setTotalBytes(1000).setUsedBytes(400))).build());
        var measured = RptHeartbeat.newBuilder().setAgentVersion("runtime-profile-test")
                .setPolicyVersion(policy.currentVersion()).setCpuUsage(0).setCpuUsageValid(true)
                .setMemUsage(37.5f).setMemUsageValid(true).setUptimeSec(1234)
                .setHost(HostInfo.newBuilder().setHostname("runtime-host").setKernel("runtime-kernel")
                        .setCpuModel("runtime-cpu").setLogicalCpus(4).setPhysicalCores(2)
                        .setMemoryTotalBytes(8L << 30).setBootTimeSec(boot));
        stream.requests.onNext(report(owner.getAgentId()).setHeartbeat(measured).build());
        await(() -> jdbc.queryForObject("SELECT COUNT(*) FROM t_host_runtime WHERE agent_id=? AND cpu_percent=0",
                Integer.class, owner.getAgentId()) == 1);
        var runtime = new com.alinksec.service.heartbeat.HostRuntimeService(jdbc).snapshot(owner.getAgentId());
        var latest = (Map<?, ?>) runtime.get("latest");
        assertEquals(0, ((Number) latest.get("cpu_percent")).doubleValue());
        assertEquals(37.5, ((Number) latest.get("memory_percent")).doubleValue());
        assertEquals("runtime-cpu", ((com.fasterxml.jackson.databind.JsonNode) latest.get("host")).path("cpu_model").asText());
        assertEquals(boot, ((com.fasterxml.jackson.databind.JsonNode) latest.get("host")).path("boot_time_sec").asLong());
        assertEquals("runtime-kernel", jdbc.queryForObject("SELECT kernel FROM t_agent WHERE agent_id=?", String.class, owner.getAgentId()));
        assertEquals(400, jdbc.queryForObject("SELECT used_bytes FROM t_asset_disk WHERE agent_id=?", Long.class, owner.getAgentId()));
        assertEquals(0, jdbc.queryForObject("SELECT COUNT(*) FROM t_host_runtime WHERE agent_id=?", Integer.class, other.getAgentId()));
        stream.requests.onNext(report(owner.getAgentId()).setHeartbeat(measured.setMemUsage(42.5f)).build());
        await(() -> jdbc.queryForObject("SELECT COUNT(*) FROM t_host_runtime WHERE agent_id=? AND memory_percent=42.5",
                Integer.class, owner.getAgentId()) == 1);
        assertEquals(1, jdbc.queryForObject("SELECT COUNT(*) FROM t_host_metric WHERE agent_id=? AND bucket=(SELECT sampled_at/60000*60000 FROM t_host_runtime WHERE agent_id=?)",
                Integer.class, owner.getAgentId(), owner.getAgentId()));
    }

    @ParameterizedTest
    @ValueSource(strings = {"baseline", "scan"})
    void resourceBusyReceiptFinishesOnlyTheOwnedActiveBulkTask(String kind) throws Exception {
        var owner = enroll(); var other = enroll();
        Stream owned = connect(owner), foreign = connect(other);
        heartbeat(owned, owner.getAgentId()); heartbeat(foreign, other.getAgentId());
        String table = kind.equals("baseline") ? "t_baseline_task" : "t_scan_task";
        List<Long> fixtures = new ArrayList<>();
        try {
            long task = resourceTask(kind, owner.getAgentId()); fixtures.add(task);
            String cmd = resourceCommand(kind, task, owner.getAgentId(), owned);
            ack(foreign, other.getAgentId(), cmd, RptAck.Stage.FAILED); heartbeat(foreign, other.getAgentId());
            assertEquals(1, jdbc.queryForObject("SELECT status FROM " + table + " WHERE id=?", Integer.class, task));
            owned.requests.onNext(report(owner.getAgentId()).setAck(RptAck.newBuilder().setCmdId(cmd)
                    .setStage(RptAck.Stage.FAILED).setCode(2).setMessage("background work busy; retry later")).build());
            heartbeat(owned, owner.getAgentId());
            assertEquals(CommandRepository.ST_FAILED, commandStatus(cmd));
            assertEquals(3, jdbc.queryForObject("SELECT status FROM " + table + " WHERE id=?", Integer.class, task));
            assertEquals(25, jdbc.queryForObject("SELECT progress FROM " + table + " WHERE id=?", Integer.class, task));
            assertNotNull(jdbc.queryForObject("SELECT CAST(finished_at AS TEXT) FROM " + table + " WHERE id=?", String.class, task));
            ack(owned, owner.getAgentId(), cmd, RptAck.Stage.DONE); heartbeat(owned, owner.getAgentId());
            assertEquals(3, jdbc.queryForObject("SELECT status FROM " + table + " WHERE id=?", Integer.class, task));
            for (int terminal : List.of(2,4)) {
                long finished = resourceTask(kind, owner.getAgentId()); fixtures.add(finished);
                jdbc.update("UPDATE " + table + " SET status=? WHERE id=?", terminal, finished);
                String late = resourceCommand(kind, finished, owner.getAgentId(), owned);
                ack(owned, owner.getAgentId(), late, RptAck.Stage.FAILED); heartbeat(owned, owner.getAgentId());
                assertEquals(terminal, jdbc.queryForObject("SELECT status FROM " + table + " WHERE id=?", Integer.class, finished));
            }
            long unrelated = resourceTask(kind, other.getAgentId()); fixtures.add(unrelated);
            String wrongScope = resourceCommand(kind, unrelated, owner.getAgentId(), owned);
            ack(owned, owner.getAgentId(), wrongScope, RptAck.Stage.FAILED); heartbeat(owned, owner.getAgentId());
            assertEquals(1, jdbc.queryForObject("SELECT status FROM " + table + " WHERE id=?", Integer.class, unrelated));
        } finally { for (long id : fixtures) jdbc.update("DELETE FROM " + table + " WHERE id=?", id); }
    }

    private long resourceTask(String kind, String agent) {
        String scope = JsonUtils.write(Map.of("agent_ids", List.of(agent)));
        if (kind.equals("baseline")) return jdbc.queryForObject("INSERT INTO t_baseline_task(task_no,scope,template_ids,status,progress) VALUES (?,?,?,1,25) RETURNING id",
                Long.class, "resource-" + UUID.randomUUID(), scope, database.encodeLongList(List.of()));
        return jdbc.queryForObject("INSERT INTO t_scan_task(task_no,type,scope,status,progress) VALUES (?,2,?,1,25) RETURNING id",
                Long.class, "resource-" + UUID.randomUUID(), scope);
    }

    private String resourceCommand(String kind, long task, String agent, Stream stream) throws Exception {
        var builder = Command.newBuilder();
        if (kind.equals("baseline")) builder.setBaselineCheck(com.alinksec.proto.CmdBaselineCheck.newBuilder().setTaskId(Long.toString(task)));
        else builder.setVulnScan(com.alinksec.proto.CmdVulnScan.newBuilder().setTaskId(Long.toString(task)));
        String id = commands.dispatch(agent, builder, null);
        assertEquals(id, stream.nextCommand().getCmdId()); return id;
    }
    private final List<String> agentIds = new ArrayList<>();
    private final List<String> enrollTokens = new ArrayList<>();
    private final List<String> reportIds = new ArrayList<>();
    private final List<Long> fixTaskIds = new ArrayList<>();
    private final List<String> cveIds = new ArrayList<>();
    private final List<Long> patchIds = new ArrayList<>();

    public static class DatabaseProfile implements ActiveProfilesResolver {
        @Override
        public String[] resolve(Class<?> testClass) {
            String database = System.getProperty("alinksec.integration.database", "sqlite");
            if (!List.of("sqlite", "postgres").contains(database)) {
                throw new IllegalArgumentException("Unsupported integration database: " + database);
            }
            return new String[]{database};
        }
    }

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        boolean postgres = "postgres".equals(System.getProperty("alinksec.integration.database"));
        registry.add("spring.datasource.url", () -> postgres
                ? requiredEnvironment("ALINKSEC_INTEGRATION_PG_URL")
                : "jdbc:sqlite:" + tempDir.resolve("security.db"));
        registry.add("spring.datasource.driver-class-name", () -> postgres
                ? "org.postgresql.Driver" : "org.sqlite.JDBC");
        registry.add("spring.datasource.username", () -> postgres
                ? requiredEnvironment("ALINKSEC_INTEGRATION_PG_USER") : "");
        registry.add("spring.datasource.password", () -> postgres
                ? requiredEnvironment("ALINKSEC_INTEGRATION_PG_PASSWORD") : "");
        registry.add("spring.datasource.hikari.maximum-pool-size", () -> 2);
        registry.add("spring.datasource.hikari.minimum-idle", () -> 1);
        registry.add("alinksec.server.port", () -> 0);
        registry.add("alinksec.server.cert-dir", () -> tempDir.resolve("certs").toString());
        registry.add("alinksec.server.web-tls-dir", () -> tempDir.resolve("web-tls").toString());
        registry.add("alinksec.server.public-host", () -> "");
        registry.add("alinksec.server.tls-sans", () -> "localhost,127.0.0.1");
        registry.add("alinksec.metrics.enabled", () -> false);
        registry.add("alinksec.signature.storage-dir", () -> tempDir.resolve("signature").toString());
        registry.add("alinksec.libraries.work-dir", () -> tempDir.resolve("libraries").toString());
        registry.add("alinksec.patch.storage-dir", () -> tempDir.resolve("patch").toString());
        registry.add("alinksec.upgrade.storage-dir", () -> tempDir.resolve("upgrade").toString());
        registry.add("ALINKSEC_BOOTSTRAP_ADMIN_PASSWORD", () -> "");
        registry.add("ALINKSEC_BOOTSTRAP_ENROLL_TOKEN", () -> "");
        registry.add("ALINKSEC_JWT_SECRET", () -> "integration-test-jwt-secret");
    }

    private Long actorId;
    private final String approverName = "grpc-reviewer-" + UUID.randomUUID();
    @org.junit.jupiter.api.BeforeEach void account() {
        actorId = jdbc.queryForObject("INSERT INTO t_user(username,password_hash,role_id,status) VALUES (?, 'unused',1,1) RETURNING id", Long.class, approverName);
    }

    @AfterEach
    void cleanUp() throws Exception {
        for (ManagedChannel channel : channels) {
            channel.shutdownNow();
            assertTrue(channel.awaitTermination(5, TimeUnit.SECONDS));
        }
        await(() -> connections.onlineCount() == 0);
        for (Long id : fixTaskIds) {
            jdbc.update("DELETE FROM t_fix_record WHERE task_id = ?", id);
            jdbc.update("DELETE FROM t_fix_task WHERE id = ?", id);
        }
        for (Long id : patchIds) {
            jdbc.update("DELETE FROM t_patch_review WHERE patch_id=?", id);
            jdbc.update("DELETE FROM t_patch_package WHERE id = ?", id);
        }
        for (String agentId : agentIds) {
            for (String table : List.of("t_command", "t_asset_software", "t_asset_port", "t_asset_account",
                    "t_asset_process", "t_asset_container", "t_alert", "t_vuln_finding", "t_vuln_coverage", "t_vuln_package_assessment", "t_agent")) {
                jdbc.update("DELETE FROM " + table + " WHERE agent_id = ?", agentId);
            }
        }
        jdbc.update("DELETE FROM t_user WHERE id=?",actorId);
        for (String token : enrollTokens) {
            jdbc.update("DELETE FROM t_enroll_token WHERE token = ?", token);
        }
        for (String cveId : cveIds) {
            jdbc.update("DELETE FROM t_cve_db WHERE cve_id = ?", cveId);
            jdbc.update("DELETE FROM t_security_cve WHERE cve_id = ?", cveId);
        }
        for (String reportId : reportIds) {
            jdbc.update("DELETE FROM t_report_dedup WHERE report_id = ?", reportId);
        }
    }

    @Test
    void enrollsWithoutClientCertificateAndUsesIssuedIdentityForCommands() throws Exception {
        EnrollResponse agent = enroll();
        assertFalse(agent.getClientCert().isEmpty());
        assertFalse(agent.getClientKey().isEmpty());
        assertFalse(agent.getCaCert().isBlank());
        assertEquals(AgentEntity.STATUS_PENDING, agentStatus(agent.getAgentId()));

        Stream stream = connect(agent);
        heartbeat(stream, agent.getAgentId());
        assertEquals(AgentEntity.STATUS_ONLINE, agentStatus(agent.getAgentId()));
        String cmdId = collect(agent.getAgentId(), stream);
        ack(stream, agent.getAgentId(), cmdId, RptAck.Stage.DONE);
        heartbeat(stream, agent.getAgentId());
        assertEquals(CommandRepository.ST_DONE, commandStatus(cmdId));
        stream.requests.onCompleted();
        assertEquals(Status.Code.OK, stream.finished.get(5, TimeUnit.SECONDS).getCode());
    }

    @Test
    void upgradeCapabilityIsReplacedByCurrentAuthenticatedConnection() throws Exception {
        EnrollResponse agent=enroll();
        Stream ready=connect(agent);
        ready.requests.onNext(report(agent.getAgentId()).setHeartbeat(RptHeartbeat.newBuilder()
                .setAgentVersion("watchdog-ready").setPolicyVersion(policy.currentVersion()).setUpgradeContract(1)).build());
        await(()->jdbc.queryForObject("SELECT upgrade_contract FROM t_agent WHERE agent_id=?",Integer.class,agent.getAgentId())==1);
        var upgrade=com.alinksec.proto.CmdAgentUpgrade.newBuilder().setExecutionContract(1).setVersion("test")
                .setDownloadUrl("https://localhost:8443/api/upgrade/download?packageKey=capability-fixture.bin&token=test");
        String first=commands.dispatch(agent.getAgentId(),Command.newBuilder().setAgentUpgrade(upgrade),null);
        assertEquals(first,ready.nextCommand().getCmdId());
        ack(ready,agent.getAgentId(),first,RptAck.Stage.RECEIVED);
        ready.requests.onCompleted();ready.finished.get(5,TimeUnit.SECONDS);
        await(()->connections.onlineCount()==0);
        String pending=commands.dispatch(agent.getAgentId(),Command.newBuilder().setAgentUpgrade(upgrade),null);
        assertEquals(CommandRepository.ST_PENDING,commandStatus(pending));
        Stream legacy=connect(agent);heartbeat(legacy,agent.getAgentId());
        assertEquals(0,jdbc.queryForObject("SELECT upgrade_contract FROM t_agent WHERE agent_id=?",Integer.class,agent.getAgentId()));
        assertEquals(CommandRepository.ST_FAILED,commandStatus(pending));
        assertTrue(jdbc.queryForObject("SELECT result FROM t_command WHERE cmd_id=?",String.class,pending).contains("升级看护契约失效"));
        assertTrue(legacy.received.stream().noneMatch(Command::hasAgentUpgrade));
    }

    @Test
    void approvesAndDispatchesCoveredPackagesAndAcceptsOnlyOwnedPendingResults() throws Exception {
        EnrollResponse first = enroll();
        EnrollResponse second = enroll();
        Stream firstStream = connect(first);
        Stream secondStream = connect(second);
        heartbeat(firstStream, first.getAgentId());
        heartbeat(secondStream, second.getAgentId());
        String pkg = "grpc-patch-" + UUID.randomUUID();
        asset(firstStream, first.getAgentId(), pkg);
        asset(secondStream, second.getAgentId(), pkg);
        String cveId = "CVE-2099-" + String.format("%019d", UUID.randomUUID().getMostSignificantBits() & Long.MAX_VALUE);
        library.cves("manual", List.of(JsonUtils.read(JsonUtils.write(Map.of("cve_id", cveId, "severity", 3, "affected",
                List.of(Map.of("name", pkg, "vrange", "<2.0", "source", "dpkg", "version_scheme", "dpkg",
                        "distro_id", "ubuntu", "distro_version", "24.04", "architecture", "amd64", "match", "exact", "fixed_version", "2.0",
                        "evidence", Map.of("basis", "manual_analysis", "assessment", "affected", "package_scope", "binary", "notes", "Disposable gRPC package fixture declaration."))))))));
        cveIds.add(cveId);
        long firstFinding = finding(first.getAgentId(), pkg, cveId);
        long secondFinding = finding(second.getAgentId(), pkg, cveId);
        List<Map<String, Object>> items = List.of(
                Map.of("agentId", first.getAgentId(), "findingId", firstFinding),
                Map.of("agentId", second.getAgentId(), "findingId", secondFinding));
        assertThrows(IllegalArgumentException.class,
                () -> fixTasks.createPackageTask("missing patch", items, approverName, null, null, actorId));
        Map<String, Object> patch = patches.importPackage(new ByteArrayInputStream(NativePatchFixture.deb(tempDir, pkg, "2.0", "amd64")),
                "patch.deb", 1, "", pkg, "2.0", "deb", "ubuntu", "24.04", "amd64", 1L);
        patchIds.add(((Number) patch.get("id")).longValue());
        review(patch, cveId);
        assertThrows(IllegalArgumentException.class, () -> fixTasks.createPackageTask("duplicate", List.of(
                items.get(0), items.get(0)), approverName, null, null, actorId));
        assertThrows(IllegalArgumentException.class, () -> fixTasks.createPackageTask("foreign finding", List.of(
                Map.of("agentId", second.getAgentId(), "findingId", firstFinding)), approverName, null, null, actorId));
        long taskId = ((Number) fixTasks.createPackageTask("approved repair", items, approverName, null, null, actorId)
                .get("taskId")).longValue();
        fixTaskIds.add(taskId);
        asset(firstStream, first.getAgentId(), pkg);
        assertEquals(0, findingStatus(firstFinding));
        assertEquals(1, jdbc.queryForObject("SELECT count(*) FROM t_vuln_finding WHERE agent_id=? AND cve_id=?",
                Integer.class, first.getAgentId(), cveId));
        fixResult(firstStream, first.getAgentId(), taskId, firstFinding, true);
        heartbeat(firstStream, first.getAgentId());
        assertEquals(0, fixStatus(taskId));
        assertEquals(0, findingStatus(firstFinding));
        assertEquals(2, pendingFixRecords(taskId));
        assertTrue(firstStream.received.isEmpty());
        assertTrue(secondStream.received.isEmpty());

        assertEquals("dispatched", fixTasks.approve(taskId, actorId).get("state"));
        Command firstCommand = firstStream.nextCommand();
        Command secondCommand = secondStream.nextCommand();
        assertEquals(String.valueOf(taskId), firstCommand.getVulnFix().getTaskId());
        assertEquals(List.of(String.valueOf(firstFinding)), firstCommand.getVulnFix().getFixesList()
                .stream().map(f -> f.getRefId()).toList());
        assertEquals(List.of(String.valueOf(secondFinding)), secondCommand.getVulnFix().getFixesList()
                .stream().map(f -> f.getRefId()).toList());
        assertTrue(firstCommand.getVulnFix().getFixes(0).getPayload().contains("download?filename="));
        assertTrue(firstCommand.getVulnFix().getFixes(0).getPayload().contains("token="));
        assertEquals(2, JsonUtils.read(firstCommand.getVulnFix().getFixes(0).getPayload()).path("inventory").path("contract").asInt());
        assertFalse(firstCommand.getVulnFix().getFixes(0).getPayload().equals(
                secondCommand.getVulnFix().getFixes(0).getPayload()));
        asset(secondStream, second.getAgentId(), pkg);
        assertEquals(0, findingStatus(secondFinding));
        assertEquals(1, jdbc.queryForObject("SELECT count(*) FROM t_vuln_finding WHERE agent_id=? AND cve_id=?",
                Integer.class, second.getAgentId(), cveId));
        fixResult(firstStream, first.getAgentId(), taskId, secondFinding, true);
        fixResult(firstStream, first.getAgentId(), taskId, Long.MAX_VALUE, true);
        heartbeat(firstStream, first.getAgentId());
        assertEquals(2, pendingFixRecords(taskId));
        assertEquals(2, jdbc.queryForObject("SELECT count(*) FROM t_fix_record WHERE task_id = ?",
                Integer.class, taskId));

        fixResult(firstStream, first.getAgentId(), taskId, firstFinding, true);
        heartbeat(firstStream, first.getAgentId());
        assertEquals(3, findingStatus(firstFinding));
        assertEquals(0, findingStatus(secondFinding));
        assertEquals(1, fixStatus(taskId));
        fixResult(firstStream, first.getAgentId(), taskId, firstFinding, false);
        heartbeat(firstStream, first.getAgentId());
        assertEquals(1, jdbc.queryForObject("SELECT status FROM t_fix_record WHERE task_id = ? AND agent_id = ?",
                Integer.class, taskId, first.getAgentId()));
        fixResult(secondStream, second.getAgentId(), taskId, secondFinding, true);
        heartbeat(secondStream, second.getAgentId());
        assertEquals(3, findingStatus(secondFinding));
        assertEquals(2, fixStatus(taskId));
        assertEquals(0, pendingFixRecords(taskId));
        assertThrows(IllegalArgumentException.class,
                () -> fixTasks.createPackageTask("already fixed", items, approverName, null, null, actorId));
    }

    private void review(Map<String, Object> patch, String cve) throws Exception {
        long id = ((Number) patch.get("id")).longValue();
        var ctx = patches.reviewContext(id, cve);
        patches.review(id, cve, String.valueOf(((Map<?, ?>) ctx.get("cve")).get("rule_digest")), String.valueOf(ctx.get("patchDigest")),
                "Disposable gRPC fixture manual confirmation", true, 1L);
    }

    private void asset(Stream stream, String agentId, String pkg) throws Exception {
        stream.requests.onNext(report(agentId).setAsset(RptAssetSnapshot.newBuilder()
                .addCollected("software")
                .setSoftwareInventory(SoftwareInventory.newBuilder().setStatus(SoftwareInventory.Status.COMPLETE)
                        .setSource("dpkg").setDistroId("ubuntu").setDistroVersion("24.04").setPackageRepairContract(2))
                .addSoftware(SoftwareInfo.newBuilder().setName(pkg).setVersion("1.0").setSource("dpkg").setArchitecture("amd64"))).build());
        heartbeat(stream, agentId);
    }

    @Test void unverifiedPackageSuccessRemainsUnfixedAndCannotBeReplacedByALaterResult() throws Exception {
        var agent = enroll(); var stream = connect(agent); heartbeat(stream, agent.getAgentId());
        String pkg = "grpc-unverified-" + UUID.randomUUID(); asset(stream, agent.getAgentId(), pkg);
        String cve = "CVE-2099-" + String.format("%019d", UUID.randomUUID().getMostSignificantBits() & Long.MAX_VALUE);
        cveIds.add(cve);
        library.cves("manual", List.of(JsonUtils.read(JsonUtils.write(Map.of("cve_id", cve, "severity", 3, "affected", List.of(
                Map.of("name", pkg, "match", "exact", "source", "dpkg", "version_scheme", "dpkg", "distro_id", "ubuntu",
                        "distro_version", "24.04", "architecture", "amd64", "vrange", "<2.0", "fixed_version", "2.0",
                        "evidence", Map.of("basis", "manual_analysis", "assessment", "affected", "package_scope", "binary", "notes", "Unverified result fixture."))))))));
        long finding = finding(agent.getAgentId(), pkg, cve);
        var patch = patches.importPackage(new ByteArrayInputStream(NativePatchFixture.deb(tempDir, pkg, "2.0", "amd64")), "unverified.deb", 1, "", pkg, "2.0", "deb", "ubuntu", "24.04", "amd64", 1L);
        patchIds.add(((Number) patch.get("id")).longValue());
        review(patch, cve);
        long task = ((Number) fixTasks.createPackageTask("unverified result", List.of(Map.of("agentId", agent.getAgentId(), "findingId", finding)), approverName, null, null, actorId).get("taskId")).longValue();
        fixTaskIds.add(task); assertEquals("dispatched", fixTasks.approve(task, actorId).get("state")); stream.nextCommand();
        stream.requests.onNext(report(agent.getAgentId()).setFixResult(RptFixResult.newBuilder().setTaskId(String.valueOf(task))
                .addResults(FixResultItem.newBuilder().setRefId(String.valueOf(finding)).setSuccess(true).setVerified(false).setLog("post-install query unavailable"))).build());
        heartbeat(stream, agent.getAgentId());
        assertEquals(0, findingStatus(finding)); assertEquals(3, fixStatus(task));
        assertEquals(3, jdbc.queryForObject("SELECT status FROM t_fix_record WHERE task_id=?", Integer.class, task));
        String stored = jdbc.queryForObject("SELECT log FROM t_fix_record WHERE task_id=?", String.class, task);
        assertTrue(stored.contains("不标记漏洞已修复"));
        fixResult(stream, agent.getAgentId(), task, finding, true); heartbeat(stream, agent.getAgentId());
        assertEquals(0, findingStatus(finding));
        assertEquals(stored, jdbc.queryForObject("SELECT log FROM t_fix_record WHERE task_id=?", String.class, task));
    }

    @Test void fullNativeVersionsAndDeclaredTargetsLongerThan64CharactersSurviveRealStorage() throws Exception {
        var agent = enroll(); var stream = connect(agent); heartbeat(stream, agent.getAgentId());
        String pkg = "grpc-long-version-" + UUID.randomUUID(), installed = "1.0+git" + "a".repeat(80) + "-1", fixed = "2.0+git" + "b".repeat(80) + "-1";
        String cve = "CVE-2099-" + String.format("%019d", UUID.randomUUID().getMostSignificantBits() & Long.MAX_VALUE);
        cveIds.add(cve);
        stream.requests.onNext(report(agent.getAgentId()).setAsset(RptAssetSnapshot.newBuilder().addCollected("software")
                .setSoftwareInventory(SoftwareInventory.newBuilder().setStatus(SoftwareInventory.Status.COMPLETE)
                        .setSource("dpkg").setDistroId("ubuntu").setDistroVersion("24.04").setPackageRepairContract(2))
                .addSoftware(SoftwareInfo.newBuilder().setName(pkg).setVersion(installed).setSource("dpkg").setArchitecture("amd64"))).build());
        heartbeat(stream, agent.getAgentId());
        var rule = Map.of("name", pkg, "vrange", "<" + fixed, "source", "dpkg", "version_scheme", "dpkg",
                "distro_id", "ubuntu", "distro_version", "24.04", "architecture", "amd64", "fixed_version", fixed,
                "evidence", Map.of("basis", "manual_analysis", "assessment", "affected", "package_scope", "binary", "notes", "Disposable long-version declaration."));
        library.cves("manual", List.of(JsonUtils.read(JsonUtils.write(Map.of("cve_id", cve, "severity", 3, "affected", List.of(rule))))));
        matcher.matchAgent(agent.getAgentId(), 0);
        var finding = jdbc.queryForMap("SELECT installed_version,fixed_version,evidence_status FROM t_vuln_finding WHERE agent_id=? AND cve_id=?", agent.getAgentId(), cve);
        assertEquals(installed, finding.get("installed_version")); assertEquals(fixed, finding.get("fixed_version"));
        assertEquals("declared", finding.get("evidence_status"));
    }

    private long finding(String agentId, String pkg, String cveId) {
        matcher.matchAgent(agentId, 0);
        return jdbc.queryForObject("SELECT id FROM t_vuln_finding WHERE agent_id=? AND software=? AND cve_id=?", Long.class, agentId, pkg, cveId);
    }

    private void fixResult(Stream stream, String agentId, long taskId, long findingId, boolean success) {
        stream.requests.onNext(report(agentId).setFixResult(RptFixResult.newBuilder()
                .setTaskId(String.valueOf(taskId)).addResults(FixResultItem.newBuilder()
                        .setRefId(String.valueOf(findingId)).setSuccess(success).setVerified(success)
                        .setLog("test repair result"))).build());
    }

    private int findingStatus(long id) {
        return jdbc.queryForObject("SELECT status FROM t_vuln_finding WHERE id = ?", Integer.class, id);
    }

    private int fixStatus(long id) {
        return jdbc.queryForObject("SELECT status FROM t_fix_task WHERE id = ?", Integer.class, id);
    }

    private int pendingFixRecords(long id) {
        return jdbc.queryForObject("SELECT count(*) FROM t_fix_record WHERE task_id = ? AND status = 0",
                Integer.class, id);
    }

    @Test
    void preservesRuleTypesAndSynchronizesEnabledAndDisabledPolicies() throws Exception {
        EnrollResponse agent = enroll();
        Stream stream = connect(agent);
        heartbeat(stream, agent.getAgentId());
        Map<String, Object> original = rules.listRules().stream()
                .filter(row -> "PR-0010".equals(row.get("rule_id"))).findFirst().orElseThrow();
        assertTrue(original.get("enabled") instanceof Boolean);
        assertTrue(original.get("match") instanceof Map);
        assertTrue(original.get("actions") instanceof List);
        try {
            for (boolean enabled : List.of(true, false)) {
                rules.updateRule("PR-0010", Map.of("enabled", enabled, "actions", List.of("alert"),
                        "match", Map.of("dirs", List.of("/tmp/policy-integration"), "count_per_dir", 2)));
                var snapshot = JsonUtils.read(policy.contentJson()).get("decoy");
                assertEquals(enabled, snapshot.get("enabled").asBoolean());
                assertEquals("/tmp/policy-integration", snapshot.get("dirs").get(0).asText());
                assertEquals("alert_only", snapshot.get("response").asText());
                Command command = stream.nextCommand();
                assertEquals(policy.currentVersion(), command.getPolicySync().getPolicyVersion());
                assertEquals(policy.contentJson(), command.getPolicySync().getPolicyJson());
                ack(stream, agent.getAgentId(), command.getCmdId(), RptAck.Stage.DONE);
                heartbeat(stream, agent.getAgentId());
                assertEquals(CommandRepository.ST_DONE, commandStatus(command.getCmdId()));
                Map<String, Object> current = rules.listRules().stream()
                        .filter(row -> "PR-0010".equals(row.get("rule_id"))).findFirst().orElseThrow();
                assertEquals(enabled, current.get("enabled"));
                assertEquals(List.of("alert"), current.get("actions"));
            }
        } finally {
            rules.updateRule("PR-0010", Map.of("enabled", original.get("enabled"),
                    "match", original.get("match"), "actions", original.get("actions")));
        }
    }

    @Test
    void rejectsInvalidEnrollmentTokenWithoutCreatingAgent() throws Exception {
        String machineId = UUID.randomUUID().toString();
        StatusRuntimeException error = assertThrows(StatusRuntimeException.class, () ->
                enrollment(channel(null)).enroll(enrollmentRequest("invalid-token", machineId)));
        assertEquals(Status.Code.INVALID_ARGUMENT, error.getStatus().getCode());
        assertTrue(error.getStatus().getDescription().contains("20001"));
        assertEquals(0, jdbc.queryForObject(
                "SELECT count(*) FROM t_agent WHERE machine_id = ?", Integer.class, machineId));
    }

    @Test
    void rejectsAnonymousMainChannel() throws Exception {
        EnrollResponse agent = enroll();
        Stream stream = connect(null);
        stream.requests.onNext(report(agent.getAgentId()).setHeartbeat(RptHeartbeat.getDefaultInstance()).build());
        assertEquals(Status.Code.UNAUTHENTICATED, stream.finished.get(5, TimeUnit.SECONDS).getCode());
        assertEquals(AgentEntity.STATUS_PENDING, agentStatus(agent.getAgentId()));
        assertNull(jdbc.queryForObject("SELECT last_heartbeat FROM t_agent WHERE agent_id = ?",
                String.class, agent.getAgentId()));
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void rejectsCrossAgentAssetOnFirstAndLaterReports(boolean authenticateFirst) throws Exception {
        EnrollResponse attacker = enroll();
        EnrollResponse victim = enroll();
        jdbc.update("INSERT INTO t_asset_software(agent_id, name, version) VALUES (?, 'original-software', '1')",
                victim.getAgentId());
        Stream stream = connect(attacker);
        if (authenticateFirst) {
            heartbeat(stream, attacker.getAgentId());
        }
        stream.requests.onNext(report(victim.getAgentId()).setAsset(RptAssetSnapshot.newBuilder()
                .addCollected("software").addSoftware(SoftwareInfo.newBuilder()
                        .setName("forged-software").setVersion("2"))).build());
        assertEquals(Status.Code.PERMISSION_DENIED, stream.finished.get(5, TimeUnit.SECONDS).getCode());
        assertEquals(List.of("original-software"), jdbc.queryForList(
                "SELECT name FROM t_asset_software WHERE agent_id = ?", String.class, victim.getAgentId()));
        assertEquals(0, jdbc.queryForObject("SELECT count(*) FROM t_asset_software WHERE agent_id = ?",
                Integer.class, attacker.getAgentId()));
        assertEquals(AgentEntity.STATUS_PENDING, agentStatus(victim.getAgentId()));
        await(() -> connections.onlineCount() == 0);
    }

    @Test
    void ignoresForeignCommandIdAndPreventsForgedIsolationCompletion() throws Exception {
        EnrollResponse attacker = enroll();
        EnrollResponse victim = enroll();
        Stream attackerStream = connect(attacker);
        Stream victimStream = connect(victim);
        heartbeat(attackerStream, attacker.getAgentId());
        heartbeat(victimStream, victim.getAgentId(), true);
        String cmdId = commands.dispatch(victim.getAgentId(), Command.newBuilder()
                .setProtectAction(CmdProtectAction.newBuilder().setAction(CmdProtectAction.Action.ISOLATE_HOST).setIsolationContract(1)), null);
        assertEquals(cmdId, victimStream.nextCommand().getCmdId());
        for (RptAck.Stage stage : List.of(RptAck.Stage.RECEIVED, RptAck.Stage.RUNNING,
                RptAck.Stage.DONE, RptAck.Stage.FAILED)) {
            ack(attackerStream, attacker.getAgentId(), cmdId, stage);
            heartbeat(attackerStream, attacker.getAgentId());
            assertEquals(CommandRepository.ST_SENT, commandStatus(cmdId));
            assertEquals(IsolationCommandLifecycleListener.ISOLATING, isolationStatus(victim.getAgentId()));
        }
        ack(victimStream, victim.getAgentId(), cmdId, RptAck.Stage.DONE);
        heartbeat(victimStream, victim.getAgentId(), true);
        assertEquals(CommandRepository.ST_DONE, commandStatus(cmdId));
        assertEquals(IsolationCommandLifecycleListener.ISOLATING, isolationStatus(victim.getAgentId()));
        var pulse=com.alinksec.proto.RptIsolationState.newBuilder().setLeaseId("a".repeat(32)).setGeneration(1).setRevision(3)
                .setCommandId(cmdId).setPhase("active").setConfirmed(true).setNonce("b".repeat(32)).setDeadline(System.currentTimeMillis()+10000);
        victimStream.requests.onNext(report(victim.getAgentId()).setIsolationState(pulse).build());
        var echo=victimStream.nextCommand();
        assertTrue(echo.getCmdId().isEmpty());
        assertEquals(pulse.getNonce(),echo.getIsolationConfirm().getNonce());
        assertEquals(pulse.getLeaseId(),echo.getIsolationConfirm().getLeaseId());
        assertEquals(IsolationCommandLifecycleListener.ISOLATED, isolationStatus(victim.getAgentId()));
        victimStream.requests.onNext(report(victim.getAgentId()).setIsolationState(pulse.setRevision(4).setPhase("finished").setNonce("").setAutomatic(true)).build());
        heartbeat(victimStream,victim.getAgentId(),true);
        assertEquals(IsolationCommandLifecycleListener.NORMAL,isolationStatus(victim.getAgentId()));
        ack(victimStream,victim.getAgentId(),cmdId,RptAck.Stage.DONE);
        heartbeat(victimStream,victim.getAgentId(),true);
        assertEquals(IsolationCommandLifecycleListener.NORMAL,isolationStatus(victim.getAgentId()));
    }

    @Test
    void persistentIsolationOutcomeDoesNotRecountAfterTransportDedupExpires() throws Exception {
        var agent=enroll(); var stream=connect(agent); heartbeat(stream,agent.getAgentId());
        String lease="d".repeat(32),eventId=lease+"-finished-event";
        reportIds.add(eventId);
        var event=com.alinksec.proto.RptSecurityEvent.newBuilder().setType("self_defense").setRuleId("host-isolation-lease")
                .setSeverity(com.alinksec.proto.Severity.SEV_HIGH).setActionTaken("restored")
                .setDetail(JsonUtils.write(Map.of("id",lease,"phase","finished","automatic",true,"cause","lease_expired")));
        stream.requests.onNext(report(agent.getAgentId()).setReportId(eventId).setSecurityEvent(event).build());
        heartbeat(stream,agent.getAgentId());
        assertEquals(1,jdbc.queryForObject("SELECT count(*) FROM t_isolation_outcome_receipt WHERE agent_id=?",Integer.class,agent.getAgentId()));
        String transportKey=java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest((agent.getAgentId()+"\0"+eventId).getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        reportIds.add(transportKey);
        assertEquals(1,jdbc.update("DELETE FROM t_report_dedup WHERE report_id=?",transportKey));
        stream.requests.onNext(report(agent.getAgentId()).setReportId(eventId).setSecurityEvent(event).build());
        heartbeat(stream,agent.getAgentId());
        assertEquals(1,jdbc.queryForObject("SELECT count(*) FROM t_isolation_outcome_receipt WHERE agent_id=?",Integer.class,agent.getAgentId()));
        assertEquals(1,jdbc.queryForObject("SELECT count FROM t_alert WHERE agent_id=? AND rule_id='host-isolation-lease'",Integer.class,agent.getAgentId()));
    }

    @Test
    void persistentConfigurationEventsSurviveReconnectAndTransportExpiryWithoutRecounting() throws Exception {
        var agent=enroll();var stream=connect(agent);heartbeat(stream,agent.getAgentId());
        String id="c".repeat(32),eventId=id+"-config-event";
        var event=com.alinksec.proto.RptSecurityEvent.newBuilder().setType("self_defense")
                .setRuleId("agent-config-integrity").setRuleName("Agent 配置防篡改")
                .setSeverity(com.alinksec.proto.Severity.SEV_HIGH).setActionTaken("trusted_config_in_use")
                .setDetail(JsonUtils.write(Map.of("id",id,"file","agent.yml","path","/private/agent.yml",
                        "reason","missing_or_unsafe_file","action","trusted_config_in_use","shadow","blocked")));
        stream.requests.onNext(report(agent.getAgentId()).setReportId(eventId).setSecurityEvent(event).build());
        heartbeat(stream,agent.getAgentId());
        assertEquals(1,jdbc.queryForObject("SELECT count(*) FROM t_agent_config_event_receipt WHERE agent_id=?",Integer.class,agent.getAgentId()));
        String key=java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256")
                .digest((agent.getAgentId()+"\0"+eventId).getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        reportIds.add(key);
        assertEquals(1,jdbc.update("DELETE FROM t_report_dedup WHERE report_id=?",key));
        var next=connect(agent);heartbeat(next,agent.getAgentId());
        next.requests.onNext(report(agent.getAgentId()).setReportId(eventId).setSecurityEvent(event).build());
        heartbeat(next,agent.getAgentId());
        assertEquals(1,jdbc.queryForObject("SELECT count FROM t_alert WHERE agent_id=? AND rule_id='agent-config-integrity'",Integer.class,agent.getAgentId()));
        assertEquals("trusted_config_in_use",jdbc.queryForObject("SELECT action_taken FROM t_alert WHERE agent_id=? AND rule_id='agent-config-integrity'",String.class,agent.getAgentId()));
        var detail=JsonUtils.read(jdbc.queryForObject("SELECT detail FROM t_alert WHERE agent_id=? AND rule_id='agent-config-integrity'",String.class,agent.getAgentId()));
        assertEquals("blocked",detail.path("shadow").asText());
        assertEquals("self_defense:agent-config-integrity:"+id,detail.path("fingerprint").asText());

        // Stable IDs are scoped to the authenticated Agent, not the raw ID alone.
        var other=enroll();var otherStream=connect(other);heartbeat(otherStream,other.getAgentId());
        otherStream.requests.onNext(report(other.getAgentId()).setReportId(eventId).setSecurityEvent(event).build());
        heartbeat(otherStream,other.getAgentId());
        assertEquals(1,jdbc.queryForObject("SELECT count FROM t_alert WHERE agent_id=? AND rule_id='agent-config-integrity'",Integer.class,other.getAgentId()));
        reportIds.add(java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256")
                .digest((other.getAgentId()+"\0"+eventId).getBytes(java.nio.charset.StandardCharsets.UTF_8))));
    }

    @Test
    void rejectsForeignAckEnvelopeAndKeepsVictimConnectionUsable() throws Exception {
        EnrollResponse attacker = enroll();
        EnrollResponse victim = enroll();
        Stream attackerStream = connect(attacker);
        Stream victimStream = connect(victim);
        heartbeat(attackerStream, attacker.getAgentId());
        heartbeat(victimStream, victim.getAgentId());
        String cmdId = collect(victim.getAgentId(), victimStream);
        ack(attackerStream, victim.getAgentId(), cmdId, RptAck.Stage.DONE);
        assertEquals(Status.Code.PERMISSION_DENIED, attackerStream.finished.get(5, TimeUnit.SECONDS).getCode());
        assertEquals(CommandRepository.ST_SENT, commandStatus(cmdId));
        ack(victimStream, victim.getAgentId(), cmdId, RptAck.Stage.DONE);
        heartbeat(victimStream, victim.getAgentId());
        assertEquals(CommandRepository.ST_DONE, commandStatus(cmdId));
        await(() -> connections.onlineCount() == 1);
    }

    @ParameterizedTest
    @ValueSource(shorts = {AgentEntity.STATUS_DISABLED, AgentEntity.STATUS_DELETED})
    void rejectsDisabledAndDeletedIdentities(short status) throws Exception {
        EnrollResponse agent = enroll();
        jdbc.update("UPDATE t_agent SET status = ? WHERE agent_id = ?", status, agent.getAgentId());
        Stream stream = connect(agent);
        stream.requests.onNext(report(agent.getAgentId()).setHeartbeat(RptHeartbeat.getDefaultInstance()).build());
        assertEquals(Status.Code.PERMISSION_DENIED, stream.finished.get(5, TimeUnit.SECONDS).getCode());
        assertEquals(status, agentStatus(agent.getAgentId()));
    }

    private EnrollResponse enroll() throws Exception {
        String token = tokens.create(null, 1, 1);
        enrollTokens.add(token);
        EnrollResponse agent = enrollment(channel(null)).enroll(enrollmentRequest(token, UUID.randomUUID().toString()));
        agentIds.add(agent.getAgentId());
        assertEquals(1, jdbc.queryForObject("SELECT used_count FROM t_enroll_token WHERE token = ?", Integer.class, token));
        return agent;
    }

    private EnrollRequest enrollmentRequest(String token, String machineId) {
        return EnrollRequest.newBuilder().setEnrollToken(token).setHost(HostInfo.newBuilder()
                .setHostname("grpc-security-test").setMachineId(machineId).setOsType(OsType.OS_LINUX)
                .setArch("amd64").setAgentVersion("test")).build();
    }

    private EnrollServiceGrpc.EnrollServiceBlockingStub enrollment(ManagedChannel channel) {
        return EnrollServiceGrpc.newBlockingStub(channel).withDeadlineAfter(10, TimeUnit.SECONDS);
    }

    private ManagedChannel channel(EnrollResponse agent) throws Exception {
        var ssl = GrpcSslContexts.forClient().trustManager(certificates.caCert());
        if (agent != null) {
            ssl.keyManager(new ByteArrayInputStream(agent.getClientCert().toByteArray()),
                    new ByteArrayInputStream(agent.getClientKey().toByteArray()));
        }
        Server server = (Server) ReflectionTestUtils.getField(lifecycle, "server");
        assertNotNull(server);
        ManagedChannel channel = NettyChannelBuilder.forAddress("localhost", server.getPort())
                .sslContext(ssl.build()).build();
        channels.add(channel);
        return channel;
    }

    private Stream connect(EnrollResponse agent) throws Exception {
        Stream stream = new Stream();
        stream.requests = AgentChannelGrpc.newStub(channel(agent)).withDeadlineAfter(30, TimeUnit.SECONDS).channel(stream);
        return stream;
    }

    private Report.Builder report(String agentId) {
        String id = UUID.randomUUID().toString();
        reportIds.add(id);
        return Report.newBuilder().setAgentId(agentId).setReportId(id).setTs(System.currentTimeMillis());
    }

    private void heartbeat(Stream stream, String agentId) throws Exception { heartbeat(stream,agentId,false); }
    private void heartbeat(Stream stream, String agentId,boolean isolationCapable) throws Exception {
        String marker = UUID.randomUUID().toString().substring(0, 20);
        stream.requests.onNext(report(agentId).setHeartbeat(RptHeartbeat.newBuilder()
                .setAgentVersion(marker).setPolicyVersion(policy.currentVersion()).setIsolationContract(isolationCapable?1:0)).build());
        // Stream ordering makes the persisted heartbeat a barrier for preceding reports.
        await(() -> marker.equals(jdbc.queryForObject(
                "SELECT agent_version FROM t_agent WHERE agent_id = ?", String.class, agentId)));
    }

    private void ack(Stream stream, String agentId, String cmdId, RptAck.Stage stage) {
        stream.requests.onNext(report(agentId).setAck(RptAck.newBuilder()
                .setCmdId(cmdId).setStage(stage).setMessage("test ack")).build());
    }

    private String collect(String agentId, Stream stream) throws Exception {
        String cmdId = commands.dispatch(agentId, Command.newBuilder()
                .setCollectNow(CmdCollectNow.newBuilder().addCollectorNames("software")), null);
        assertEquals(cmdId, stream.nextCommand().getCmdId());
        assertEquals(CommandRepository.ST_SENT, commandStatus(cmdId));
        return cmdId;
    }

    private short agentStatus(String agentId) {
        return jdbc.queryForObject("SELECT status FROM t_agent WHERE agent_id = ?", Short.class, agentId);
    }

    private short commandStatus(String cmdId) {
        return jdbc.queryForObject("SELECT status FROM t_command WHERE cmd_id = ?", Short.class, cmdId);
    }

    private short isolationStatus(String agentId) {
        return jdbc.queryForObject("SELECT isolation_status FROM t_agent WHERE agent_id = ?", Short.class, agentId);
    }

    private static void await(BooleanSupplier condition) throws Exception {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (!condition.getAsBoolean() && System.nanoTime() < deadline) {
            Thread.sleep(20);
        }
        assertTrue(condition.getAsBoolean(), "Timed out waiting for server-side state");
    }

    private static String requiredEnvironment(String key) {
        String value = System.getenv(key);
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("PostgreSQL integration requires " + key);
        }
        return value;
    }

    private static class Stream implements StreamObserver<Command> {
        final BlockingQueue<Command> received = new LinkedBlockingQueue<>();
        final CompletableFuture<Status> finished = new CompletableFuture<>();
        StreamObserver<Report> requests;

        @Override public void onNext(Command command) { received.add(command); }
        @Override public void onError(Throwable error) { finished.complete(Status.fromThrowable(error)); }
        @Override public void onCompleted() { finished.complete(Status.OK); }

        Command nextCommand() throws Exception {
            Command command = received.poll(5, TimeUnit.SECONDS);
            assertNotNull(command, "Expected a command on the authenticated stream");
            return command;
        }
    }
}
