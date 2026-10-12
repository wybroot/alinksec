package com.alinksec.bootstrap;

import com.alinksec.proto.*;
import com.alinksec.common.util.JsonUtils;
import com.alinksec.service.alert.SecurityEventService;
import com.alinksec.service.asset.AssetService;
import com.alinksec.service.command.CommandService;
import com.alinksec.service.config.AlinkSecProperties;
import com.alinksec.service.config.DatabaseDialect;
import com.alinksec.service.fix.FixTaskService;
import com.alinksec.service.fix.PatchRepoService;
import com.alinksec.service.query.HostQueryService;
import com.alinksec.service.scan.VulnMatchService;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.SingleConnectionDataSource;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import java.nio.file.Path;
import java.sql.DriverManager;
import java.util.List;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/** Real migrations and inventory/finding/task storage; command transport is mocked. */
class SoftwareInventoryIntegrationTest {
    @TempDir Path root;
    SingleConnectionDataSource dataSource;
    JdbcTemplate jdbc;
    AssetService assets;
    HostQueryService query;
    VulnMatchService matcher;
    FixTaskService fixes;
    PatchRepoService patches;
    CommandService commands;
    TransactionTemplate transaction;

    @BeforeEach void setup() throws Exception {
        dataSource = new SingleConnectionDataSource(DriverManager.getConnection("jdbc:sqlite:" + root.resolve("db.sqlite")), true);
        new SqliteDatabaseConfiguration.SqliteMigrationBeanPostProcessor().postProcessAfterInitialization(dataSource, "dataSource");
        jdbc = new JdbcTemplate(dataSource);
        transaction = new TransactionTemplate(new DataSourceTransactionManager(dataSource));
        jdbc.update("INSERT INTO t_agent(agent_id,hostname,os_type,os_version,arch) VALUES ('inventory-host','inventory-host',1,'Ubuntu 24.04','arm64')");
        matcher = new VulnMatchService(jdbc);
        assets = new AssetService(jdbc, matcher, mock(SecurityEventService.class));
        query = new HostQueryService(jdbc);
        commands = mock(CommandService.class);
        patches = mock(PatchRepoService.class);
        var properties = new AlinkSecProperties(); properties.getDatabase().setType("sqlite");
        fixes = new FixTaskService(jdbc, commands, patches, new DatabaseDialect(properties));
    }
    @AfterEach void cleanup() { dataSource.destroy(); }

    private SoftwareInfo pkg(String arch, String version) {
        return SoftwareInfo.newBuilder().setName("inventory-fixture").setVersion(version).setSource("dpkg").setArchitecture(arch).build();
    }
    private RptAssetSnapshot complete(SoftwareInfo... packages) {
        return RptAssetSnapshot.newBuilder().addCollected("software")
                .setSoftwareInventory(SoftwareInventory.newBuilder().setStatus(SoftwareInventory.Status.COMPLETE)
                        .setSource("dpkg").setDistroId("ubuntu").setDistroVersion("24.04"))
                .addAllSoftware(List.of(packages)).build();
    }
    private void replace(RptAssetSnapshot snapshot) { transaction.executeWithoutResult(status -> assets.replaceSnapshot("inventory-host", snapshot)); }
    private long finding() {
        return jdbc.queryForObject("""
                INSERT INTO t_vuln_finding(task_id,agent_id,cve_id,software,installed_version,fixed_version,severity)
                VALUES (0,'inventory-host','CVE-inventory-fixture','inventory-fixture','1.0','2.0',3) RETURNING id
                """, Long.class);
    }
    private Map<String, Object> create(long id) {
        return transaction.execute(status -> fixes.createPackageTask("inventory repair", List.of(Map.of("agentId", "inventory-host", "findingId", id)), "reviewer", null, null, null));
    }
    private Map<String, Object> approve(long task) { return transaction.execute(status -> fixes.approve(task, "reviewer")); }
    private void cover(long finding) {
        when(patches.resolveForAgents(anyList())).thenReturn(new PatchRepoService.Resolved(
                Map.of("inventory-host:" + finding, Map.of("repo_type", "deb", "sha256", "a".repeat(64))), List.of()));
        when(patches.downloadUrl(anyString(), anyMap())).thenReturn("https://fixture.invalid/patch");
    }

    @Test void retainsNativeMultiarchAndFailedInventoryWithoutOverwritingOtherAssets() {
        replace(complete(pkg("amd64", "1.0"), pkg("i386", "1.0")));
        var rows = query.software("inventory-host", null, 1, 20);
        assertEquals(List.of("amd64", "i386"), rows.stream().map(r -> r.get("architecture")).toList());
        var before = query.detail("inventory-host");
        replace(RptAssetSnapshot.newBuilder().addCollected("software").addCollected("ports")
                .setSoftwareInventory(SoftwareInventory.newBuilder().setStatus(SoftwareInventory.Status.FAILED)
                        .setError("package_query_failed").setDistroId("invented"))
                .addSoftware(pkg("arm64", "9.0")).addPorts(PortInfo.newBuilder().setPort(443).setProtocol("tcp")).build());
        assertEquals(rows, query.software("inventory-host", null, 1, 20));
        var after = query.detail("inventory-host");
        assertEquals("failed", after.get("software_collection_status"));
        assertEquals("ubuntu", after.get("distro_id"));
        assertEquals(before.get("software_succeeded_at"), after.get("software_succeeded_at"));
        assertEquals(1, query.ports("inventory-host").size());
        replace(RptAssetSnapshot.newBuilder().addCollected("processes").build());
        assertEquals(after.get("software_collection_status"), query.detail("inventory-host").get("software_collection_status"));
    }

    @Test void successfulEmptyInventoryClearsUnresolvedFindingsButPreservesHistoricalDecisions() {
        replace(complete(pkg("amd64", "1.0")));
        long unresolved = finding(), ignored = finding();
        jdbc.update("UPDATE t_vuln_finding SET status=2 WHERE id=?", ignored);
        replace(complete());
        assertTrue(query.software("inventory-host", null, 1, 20).isEmpty());
        assertEquals(0, jdbc.queryForObject("SELECT count(*) FROM t_vuln_finding WHERE id=?", Integer.class, unresolved));
        assertEquals(2, jdbc.queryForObject("SELECT status FROM t_vuln_finding WHERE id=?", Integer.class, ignored));
        assertEquals("complete", query.detail("inventory-host").get("software_collection_status"));
    }

    @Test void explicitFailureDoesNotDeleteFindingsEvenDuringManualRescan() {
        replace(complete(pkg("amd64", "1.0")));
        long id = finding();
        replace(RptAssetSnapshot.newBuilder().addCollected("software")
                .setSoftwareInventory(SoftwareInventory.newBuilder().setStatus(SoftwareInventory.Status.FAILED)).build());
        matcher.matchAgent("inventory-host", 0);
        assertEquals(1, jdbc.queryForObject("SELECT count(*) FROM t_vuln_finding WHERE id=?", Integer.class, id));
        assertThrows(IllegalArgumentException.class, () -> create(id));
        verifyNoInteractions(patches, commands);
    }

    @Test void malformedOrDuplicateCompleteReportsRetainPreviousInventory() {
        replace(complete(pkg("amd64", "1.0")));
        var before = query.software("inventory-host", null, 1, 20);
        for (var report : List.of(complete(pkg("", "1.0")), complete(pkg("amd64", "1.0"), pkg("amd64", "1.0")),
                complete(pkg("amd64", "not-a-version")))) {
            replace(report);
            assertEquals(before, query.software("inventory-host", null, 1, 20));
            assertEquals("failed", query.detail("inventory-host").get("software_collection_status"));
        }
    }

    @Test void legacyAndMissingDistributionIdentityCannotCreateRepairTasks() {
        replace(RptAssetSnapshot.newBuilder().addSoftware(SoftwareInfo.newBuilder().setName("inventory-fixture").setVersion("1.0").setSource("dpkg")).build());
        long id = finding();
        assertEquals("legacy", query.detail("inventory-host").get("software_collection_status"));
        assertEquals("", query.software("inventory-host", null, 1, 20).get(0).get("architecture"));
        assertThrows(IllegalArgumentException.class, () -> create(id));
        replace(complete(pkg("amd64", "1.0")).toBuilder().setSoftwareInventory(SoftwareInventory.newBuilder()
                .setStatus(SoftwareInventory.Status.COMPLETE).setSource("dpkg")).build());
        long missingIdentity = finding();
        assertThrows(IllegalArgumentException.class, () -> create(missingIdentity));
        verifyNoInteractions(patches, commands);
    }

    @Test void multipleArchitecturesOrInstalledVersionsBlockNameOnlyRepair() {
        for (var packages : List.of(List.of(pkg("amd64", "1.0"), pkg("i386", "1.0")),
                List.of(pkg("amd64", "1.0"), pkg("amd64", "1.1")))) {
            replace(complete(packages.toArray(SoftwareInfo[]::new)));
            long id = finding();
            assertThrows(IllegalArgumentException.class, () -> create(id));
        }
        verifyNoInteractions(patches, commands);
    }

    @Test void approvalRechecksFailureAndIdentityChangesBeforeDispatch() {
        replace(complete(pkg("amd64", "1.0")));
        long id = finding(); cover(id);
        long task = ((Number) create(id).get("taskId")).longValue();
        replace(RptAssetSnapshot.newBuilder().addCollected("software")
                .setSoftwareInventory(SoftwareInventory.newBuilder().setStatus(SoftwareInventory.Status.FAILED)).build());
        assertThrows(IllegalArgumentException.class, () -> approve(task));
        assertNull(jdbc.queryForObject("SELECT dispatched_at FROM t_fix_task WHERE id=?", String.class, task));
        assertEquals(0, jdbc.queryForObject("SELECT approved FROM t_fix_task WHERE id=?", Integer.class, task));
        replace(complete(pkg("i386", "1.0")));
        assertThrows(IllegalArgumentException.class, () -> approve(task));
        replace(complete(pkg("amd64", "1.0")).toBuilder().setSoftwareInventory(SoftwareInventory.newBuilder()
                .setStatus(SoftwareInventory.Status.COMPLETE).setSource("dpkg").setDistroId("debian").setDistroVersion("12")).build());
        assertThrows(IllegalArgumentException.class, () -> approve(task));
        verifyNoInteractions(commands);
    }

    @Test void capturesSingleNativeIdentityAndDispatchesOnlyAfterRecheck() {
        replace(complete(pkg("amd64", "1.0")));
        long id = finding(); cover(id);
        long task = ((Number) create(id).get("taskId")).longValue();
        var targets = JsonUtils.read(jdbc.queryForObject("SELECT targets FROM t_fix_task WHERE id=?", String.class, task));
        var identity = JsonUtils.read(targets.get(0).path("fix_payload").asText()).path("inventory");
        assertEquals("amd64", identity.path("architecture").asText());
        assertEquals("ubuntu", identity.path("distro_id").asText());
        assertEquals("dispatched", approve(task).get("state"));
        verify(commands).dispatch(eq("inventory-host"), any(Command.Builder.class), isNull());
    }
}
