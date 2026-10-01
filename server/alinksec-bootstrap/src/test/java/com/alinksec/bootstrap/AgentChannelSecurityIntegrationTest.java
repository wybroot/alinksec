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
    @Autowired PatchRepoService patches;
    @Autowired ProtectRuleService rules;

    private final List<ManagedChannel> channels = new ArrayList<>();
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
        registry.add("alinksec.patch.storage-dir", () -> tempDir.resolve("patch").toString());
        registry.add("alinksec.upgrade.storage-dir", () -> tempDir.resolve("upgrade").toString());
        registry.add("ALINKSEC_BOOTSTRAP_ADMIN_PASSWORD", () -> "");
        registry.add("ALINKSEC_BOOTSTRAP_ENROLL_TOKEN", () -> "");
        registry.add("ALINKSEC_JWT_SECRET", () -> "integration-test-jwt-secret");
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
            jdbc.update("DELETE FROM t_patch_package WHERE id = ?", id);
        }
        for (String agentId : agentIds) {
            for (String table : List.of("t_command", "t_asset_software", "t_asset_port", "t_asset_account",
                    "t_asset_process", "t_asset_container", "t_vuln_finding", "t_agent")) {
                jdbc.update("DELETE FROM " + table + " WHERE agent_id = ?", agentId);
            }
        }
        for (String token : enrollTokens) {
            jdbc.update("DELETE FROM t_enroll_token WHERE token = ?", token);
        }
        for (String cveId : cveIds) {
            jdbc.update("DELETE FROM t_cve_db WHERE cve_id = ?", cveId);
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
    void approvesAndDispatchesCoveredPackagesAndAcceptsOnlyOwnedPendingResults() throws Exception {
        EnrollResponse first = enroll();
        EnrollResponse second = enroll();
        Stream firstStream = connect(first);
        Stream secondStream = connect(second);
        heartbeat(firstStream, first.getAgentId());
        heartbeat(secondStream, second.getAgentId());
        String pkg = "grpc-patch-" + UUID.randomUUID();
        String cveId = "CVE-test-" + UUID.randomUUID().toString().substring(0, 20);
        jdbc.update("INSERT INTO t_cve_db(cve_id,severity,affected) VALUES (?,3,?)", cveId,
                JsonUtils.write(List.of(Map.of("name", pkg, "vrange", "<2.0"))));
        cveIds.add(cveId);
        long firstFinding = finding(first.getAgentId(), pkg, cveId);
        long secondFinding = finding(second.getAgentId(), pkg, cveId);
        List<Map<String, Object>> items = List.of(
                Map.of("agentId", first.getAgentId(), "findingId", firstFinding),
                Map.of("agentId", second.getAgentId(), "findingId", secondFinding));
        assertThrows(IllegalArgumentException.class,
                () -> fixTasks.createPackageTask("missing patch", items, "test", null, null, null));
        Map<String, Object> patch = patches.importPackage(new ByteArrayInputStream(new byte[]{1, 2, 3}),
                "patch.deb", 1, "", pkg, "2.0", "deb", null);
        patchIds.add(((Number) patch.get("id")).longValue());
        assertThrows(IllegalArgumentException.class, () -> fixTasks.createPackageTask("duplicate", List.of(
                items.get(0), items.get(0)), "test", null, null, null));
        assertThrows(IllegalArgumentException.class, () -> fixTasks.createPackageTask("foreign finding", List.of(
                Map.of("agentId", second.getAgentId(), "findingId", firstFinding)), "test", null, null, null));
        long taskId = ((Number) fixTasks.createPackageTask("approved repair", items, "test", null, null, null)
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

        assertEquals("dispatched", fixTasks.approve(taskId, "test").get("state"));
        Command firstCommand = firstStream.nextCommand();
        Command secondCommand = secondStream.nextCommand();
        assertEquals(String.valueOf(taskId), firstCommand.getVulnFix().getTaskId());
        assertEquals(List.of(String.valueOf(firstFinding)), firstCommand.getVulnFix().getFixesList()
                .stream().map(f -> f.getRefId()).toList());
        assertEquals(List.of(String.valueOf(secondFinding)), secondCommand.getVulnFix().getFixesList()
                .stream().map(f -> f.getRefId()).toList());
        assertTrue(firstCommand.getVulnFix().getFixes(0).getPayload().contains("download?filename="));
        assertTrue(firstCommand.getVulnFix().getFixes(0).getPayload().contains("token="));
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
                () -> fixTasks.createPackageTask("already fixed", items, "test", null, null, null));
    }

    private void asset(Stream stream, String agentId, String pkg) throws Exception {
        stream.requests.onNext(report(agentId).setAsset(RptAssetSnapshot.newBuilder()
                .addCollected("software").addSoftware(SoftwareInfo.newBuilder().setName(pkg).setVersion("1.0"))).build());
        heartbeat(stream, agentId);
    }

    private long finding(String agentId, String pkg, String cveId) {
        return jdbc.queryForObject("""
                INSERT INTO t_vuln_finding(task_id, agent_id, cve_id, software, installed_version, fixed_version, severity)
                VALUES (0, ?, ?, ?, '1.0', '2.0', 3) RETURNING id
                """, Long.class, agentId, cveId, pkg);
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
        heartbeat(victimStream, victim.getAgentId());
        String cmdId = commands.dispatch(victim.getAgentId(), Command.newBuilder()
                .setProtectAction(CmdProtectAction.newBuilder().setAction(CmdProtectAction.Action.ISOLATE_HOST)), null);
        assertEquals(cmdId, victimStream.nextCommand().getCmdId());
        for (RptAck.Stage stage : List.of(RptAck.Stage.RECEIVED, RptAck.Stage.RUNNING,
                RptAck.Stage.DONE, RptAck.Stage.FAILED)) {
            ack(attackerStream, attacker.getAgentId(), cmdId, stage);
            heartbeat(attackerStream, attacker.getAgentId());
            assertEquals(CommandRepository.ST_SENT, commandStatus(cmdId));
            assertEquals(IsolationCommandLifecycleListener.ISOLATING, isolationStatus(victim.getAgentId()));
        }
        ack(victimStream, victim.getAgentId(), cmdId, RptAck.Stage.DONE);
        heartbeat(victimStream, victim.getAgentId());
        assertEquals(CommandRepository.ST_DONE, commandStatus(cmdId));
        assertEquals(IsolationCommandLifecycleListener.ISOLATED, isolationStatus(victim.getAgentId()));
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

    private void heartbeat(Stream stream, String agentId) throws Exception {
        String marker = UUID.randomUUID().toString().substring(0, 20);
        stream.requests.onNext(report(agentId).setHeartbeat(RptHeartbeat.newBuilder()
                .setAgentVersion(marker).setPolicyVersion(policy.currentVersion())).build());
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
