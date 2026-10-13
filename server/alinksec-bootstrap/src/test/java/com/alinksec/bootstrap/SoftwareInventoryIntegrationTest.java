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
import com.alinksec.service.query.VulnQueryService;
import com.alinksec.service.scan.VulnMatchService;
import com.alinksec.service.library.*;
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
    LibraryCatalog catalog;

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
        catalog = new LibraryCatalog(jdbc, new LibraryProperties(), mock(LibraryFiles.class), new DatabaseDialect(properties), new DataSourceTransactionManager(dataSource));
        fixes = new FixTaskService(jdbc, commands, patches, new DatabaseDialect(properties));
    }
    @AfterEach void cleanup() { dataSource.destroy(); }

    private SoftwareInfo pkg(String arch, String version) {
        return SoftwareInfo.newBuilder().setName("inventory-fixture").setVersion(version).setSource("dpkg").setArchitecture(arch).build();
    }
    private RptAssetSnapshot complete(SoftwareInfo... packages) {
        return RptAssetSnapshot.newBuilder().addCollected("software")
                .setSoftwareInventory(SoftwareInventory.newBuilder().setStatus(SoftwareInventory.Status.COMPLETE)
                        .setSource("dpkg").setDistroId("ubuntu").setDistroVersion("24.04").setPackageRepairContract(1))
                .addAllSoftware(List.of(packages)).build();
    }
    private void replace(RptAssetSnapshot snapshot) { transaction.executeWithoutResult(status -> assets.replaceSnapshot("inventory-host", snapshot)); }
    private long finding() {
        catalog.cves("manual", List.of(JsonUtils.read(JsonUtils.write(Map.of("cve_id", "CVE-2026-45679", "severity", 3, "affected", List.of(scopedRule("amd64", "2.0")))))), 1L);
        var proof = jdbc.queryForMap("SELECT provenance,CAST(affected AS TEXT) AS affected FROM t_cve_db WHERE cve_id='CVE-2026-45679'");
        String snapshot = JsonUtils.write(Map.of("import", JsonUtils.read((String) proof.get("provenance")), "rules", JsonUtils.read((String) proof.get("affected"))));
        return jdbc.queryForObject("""
                INSERT INTO t_vuln_finding(task_id,agent_id,cve_id,software,installed_version,fixed_version,severity,
                    source,architecture,distro_id,distro_version,os_type,os_version,identity_status,rule_source_id,rule_digest,evidence_status,rule_evidence)
                SELECT 0,'inventory-host',cve_id,'inventory-fixture','1.0','2.0',3,
                    'dpkg','amd64','ubuntu','24.04',1,'Ubuntu 24.04','complete',rule_source_id,rule_digest,'declared',?
                FROM t_cve_db WHERE cve_id='CVE-2026-45679' RETURNING id
                """, Long.class, snapshot);
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
        assertEquals(1, identity.path("contract").asInt());
        assertEquals("dispatched", approve(task).get("state"));
        verify(commands).dispatch(eq("inventory-host"), any(Command.Builder.class), isNull());
    }

    @Test void oldAndUnknownExecutionContractsRetainInventoryButBlockCreationAndApproval() {
        replace(complete(pkg("amd64", "1.0")));
        long id = finding(); cover(id);
        long task = ((Number) create(id).get("taskId")).longValue();
        for (int contract : List.of(0, 2)) {
            replace(complete(pkg("amd64", "1.0")).toBuilder().setSoftwareInventory(
                    complete().getSoftwareInventory().toBuilder().setPackageRepairContract(contract)).build());
            assertEquals(1, query.software("inventory-host", null, 1, 20).size());
            assertEquals(0, ((Number) query.detail("inventory-host").get("package_repair_contract")).intValue());
            var rows = (List<Map<String, Object>>) new VulnQueryService(jdbc).findings(null, null, null, null, 1, 20).get("list");
            assertTrue(rows.stream().allMatch(r -> ((Number) r.get("execution_supported")).intValue() == 0));
            assertThrows(IllegalArgumentException.class, () -> create(id));
            assertThrows(IllegalArgumentException.class, () -> approve(task));
            assertEquals(0, jdbc.queryForObject("SELECT approved FROM t_fix_task WHERE id=?", Integer.class, task));
        }
        verifyNoInteractions(commands);
    }

    @Test void registryInventoryCannotClaimNativePackageRepairSupport() {
        jdbc.update("UPDATE t_agent SET os_type=2,os_version='Windows' WHERE agent_id='inventory-host'");
        replace(RptAssetSnapshot.newBuilder().addCollected("software")
                .setSoftwareInventory(SoftwareInventory.newBuilder().setStatus(SoftwareInventory.Status.COMPLETE)
                        .setSource("registry").setDistroId("windows").setDistroVersion("10").setPackageRepairContract(1))
                .addSoftware(SoftwareInfo.newBuilder().setName("inventory-fixture").setVersion("1.0")
                        .setSource("registry").setArchitecture("x86_64")).build());
        assertEquals("complete", query.detail("inventory-host").get("software_collection_status"));
        assertEquals(1, query.software("inventory-host", null, 1, 20).size());
        assertEquals(0, ((Number) query.detail("inventory-host").get("package_repair_contract")).intValue());
        assertThrows(IllegalArgumentException.class, () -> create(finding()));
        verifyNoInteractions(patches, commands);
    }

    private Map<String, Object> scopedRule(String architecture, String fixed) {
        return Map.of("name", "inventory-fixture", "match", "exact", "source", "dpkg", "version_scheme", "dpkg",
                "distro_id", "ubuntu", "distro_version", "24.04", "architecture", architecture, "vrange", "<2.0", "fixed_version", fixed,
                "evidence", Map.of("basis", "manual_analysis", "assessment", "affected", "package_scope", "binary", "notes", "Disposable binary package analysis declaration."));
    }
    private void rules(Map<String, Object>... rules) {
        catalog.cves("manual", List.of(JsonUtils.read(JsonUtils.write(Map.of("cve_id", "CVE-2026-45678", "severity", 3, "affected", List.of(rules))))), 1L);
    }

    @Test void scopedDecisionsDoNotHideOtherArchitecturesOrLaterInstalledVersions() {
        rules(scopedRule("*", "2.0"));
        replace(complete(pkg("amd64", "1.0"), pkg("i386", "1.0")));
        var first = jdbc.queryForList("SELECT * FROM t_vuln_finding ORDER BY architecture");
        assertEquals(2, first.size());
        assertEquals("amd64", first.get(0).get("architecture"));
        assertEquals("ubuntu", first.get(0).get("distro_id"));
        assertEquals("complete", first.get(0).get("identity_status"));
        jdbc.update("UPDATE t_vuln_finding SET status=2 WHERE architecture='amd64'");
        replace(complete(pkg("amd64", "1.0"), pkg("i386", "1.0")));
        assertEquals(1, jdbc.queryForObject("SELECT count(*) FROM t_vuln_finding WHERE status=0 AND architecture='i386'", Integer.class));
        assertEquals(1, jdbc.queryForObject("SELECT count(*) FROM t_vuln_finding WHERE architecture='amd64'", Integer.class));
        replace(complete(pkg("amd64", "1.1")));
        assertEquals(1, jdbc.queryForObject("SELECT count(*) FROM t_vuln_finding WHERE status=0 AND installed_version='1.1'", Integer.class));
    }

    @Test void historicalUnknownDecisionDoesNotSuppressACompleteIdentity() {
        replace(complete(pkg("amd64", "1.0")));
        long old = finding();
        jdbc.update("UPDATE t_vuln_finding SET cve_id='CVE-2026-45678',status=2,source='',architecture='',distro_id='',distro_version='',identity_status='legacy' WHERE id=?", old);
        jdbc.update("DELETE FROM t_cve_db WHERE cve_id='CVE-2026-45679'");
        rules(scopedRule("amd64", "2.0"));
        matcher.matchAgent("inventory-host", 1);
        assertEquals(2, jdbc.queryForObject("SELECT count(*) FROM t_vuln_finding", Integer.class));
        assertEquals(1, jdbc.queryForObject("SELECT count(*) FROM t_vuln_finding WHERE status=0 AND identity_status='complete'", Integer.class));
        jdbc.update("UPDATE t_vuln_finding SET installed_version=NULL WHERE id=?", old);
        assertDoesNotThrow(() -> matcher.matchAgent("inventory-host", 2));
        assertEquals(2, jdbc.queryForObject("SELECT count(*) FROM t_vuln_finding", Integer.class));
    }

    @Test void nativeRulesRequireTheDeclaredDistributionReleaseAndArchitecture() {
        rules(scopedRule("amd64", "2.0"));
        replace(complete(pkg("i386", "1.0")));
        assertEquals(0, jdbc.queryForObject("SELECT count(*) FROM t_vuln_finding", Integer.class));
        replace(complete(pkg("amd64", "1.0")));
        assertEquals(1, jdbc.queryForObject("SELECT count(*) FROM t_vuln_finding", Integer.class));
        for (var scope : List.of(List.of("debian", "24.04"), List.of("ubuntu", "22.04"))) {
            replace(complete(pkg("amd64", "1.0")).toBuilder().setSoftwareInventory(SoftwareInventory.newBuilder()
                    .setStatus(SoftwareInventory.Status.COMPLETE).setSource("dpkg").setDistroId(scope.get(0)).setDistroVersion(scope.get(1))).build());
            assertEquals(0, jdbc.queryForObject("SELECT count(*) FROM t_vuln_finding", Integer.class));
        }
    }

    @Test void overlappingRulesEmitOneFindingAndConflictingFixDeclarationsBlockAutomation() {
        for (var declarations : List.of(List.of("2.0", "2.1"), List.of("2.0", "", "2.1"), List.of("", "2.0", "2.1"))) {
            rules(declarations.stream().map(v -> scopedRule("amd64", v)).toArray(Map[]::new));
            replace(complete(pkg("amd64", "1.0")));
            assertEquals(1, jdbc.queryForObject("SELECT count(*) FROM t_vuln_finding", Integer.class));
            assertNull(jdbc.queryForObject("SELECT fixed_version FROM t_vuln_finding", String.class));
            assertEquals("conflicting", jdbc.queryForObject("SELECT evidence_status FROM t_vuln_finding", String.class));
            assertEquals(declarations.size(), JsonUtils.read(jdbc.queryForObject("SELECT rule_evidence FROM t_vuln_finding", String.class)).path("rules").size());
        }
    }

    @Test void queryKeepsOriginalFindingIdentityAndRepairRejectsCurrentIdentityDrift() {
        replace(complete(pkg("amd64", "1.0")));
        long id = finding();
        var api = new VulnQueryService(jdbc);
        var before = (List<Map<String, Object>>) api.findings(null, null, null, null, 1, 20).get("list");
        assertEquals(1, ((Number) before.get(0).get("identity_current")).intValue());
        jdbc.update("UPDATE t_agent SET distro_id='debian',distro_version='12' WHERE agent_id='inventory-host'");
        var after = (List<Map<String, Object>>) api.findings(null, null, null, null, 1, 20).get("list");
        assertEquals("ubuntu", after.get(0).get("distro_id"));
        assertEquals(0, ((Number) after.get(0).get("identity_current")).intValue());
        assertThrows(IllegalArgumentException.class, () -> create(id));
        verifyNoInteractions(patches, commands);
    }

    @Test void completeInventoryCannotRetroactivelySupplyHistoricalFindingIdentity() {
        replace(complete(pkg("amd64", "1.0")));
        long id = finding();
        jdbc.update("UPDATE t_vuln_finding SET identity_status='legacy',source='',architecture='',distro_id='',distro_version='' WHERE id=?", id);
        assertThrows(IllegalArgumentException.class, () -> create(id));
        verifyNoInteractions(patches, commands);
    }

    @Test void approvalRechecksFindingIdentityAndTargetEvenWhenInventoryIsUnchanged() {
        replace(complete(pkg("amd64", "1.0")));
        long id = finding(); cover(id);
        long task = ((Number) create(id).get("taskId")).longValue();
        jdbc.update("UPDATE t_vuln_finding SET architecture='i386' WHERE id=?", id);
        assertThrows(IllegalArgumentException.class, () -> approve(task));
        jdbc.update("UPDATE t_vuln_finding SET architecture='amd64',fixed_version='2.1' WHERE id=?", id);
        assertThrows(IllegalArgumentException.class, () -> approve(task));
        assertEquals(0, jdbc.queryForObject("SELECT approved FROM t_fix_task WHERE id=?", Integer.class, task));
        assertNull(jdbc.queryForObject("SELECT dispatched_at FROM t_fix_task WHERE id=?", String.class, task));
        verifyNoInteractions(commands);
    }

    @Test void backportDeclarationsUseFullPackageVersionsAndRetainTheOriginalCitation() {
        var vulnerable = new java.util.LinkedHashMap<>(scopedRule("amd64", "1.0-1ubuntu2"));
        vulnerable.put("vrange", "<1.0-1ubuntu2");
        var reference = Map.of("basis", "vendor_advisory", "assessment", "affected", "package_scope", "binary",
                "publisher", "Fixture publisher", "advisory_id", "FIXTURE-BACKPORT-1", "url", "https://fixture.invalid/advisories/backport-1",
                "notes", "Fixture declaration of a revision backport while the upstream base remains 1.0.");
        vulnerable.put("evidence", reference);
        var protectedVersion = new java.util.LinkedHashMap<>(vulnerable); protectedVersion.put("vrange", ">=1.0-1ubuntu2"); protectedVersion.put("fixed_version", "");
        var unaffected = new java.util.LinkedHashMap<>(reference); unaffected.put("assessment", "not_affected"); protectedVersion.put("evidence", unaffected);
        rules(vulnerable, protectedVersion);
        replace(complete(pkg("amd64", "1.0-1ubuntu1")));
        var found = jdbc.queryForMap("SELECT * FROM t_vuln_finding WHERE cve_id='CVE-2026-45678'");
        assertEquals("declared", found.get("evidence_status"));
        var snapshot = JsonUtils.read((String) found.get("rule_evidence"));
        assertEquals("manual", snapshot.path("import").path("source_id").asText());
        assertEquals(1, snapshot.path("import").path("imported_by").asInt());
        assertEquals("FIXTURE-BACKPORT-1", snapshot.path("rules").get(0).path("evidence").path("advisory_id").asText());
        replace(complete(pkg("amd64", "1.0-1ubuntu2")));
        assertEquals(0, jdbc.queryForObject("SELECT count(*) FROM t_vuln_finding WHERE cve_id='CVE-2026-45678'", Integer.class));
    }

    @Test void contradictoryAffectedAndUnaffectedDeclarationsCannotProvideAnAutomaticFix() {
        var excluded = new java.util.LinkedHashMap<>(scopedRule("amd64", ""));
        excluded.put("evidence", Map.of("basis", "manual_analysis", "assessment", "not_affected", "package_scope", "binary", "notes", "Conflicting fixture declaration."));
        rules(scopedRule("amd64", "2.0"), excluded);
        replace(complete(pkg("amd64", "1.0")));
        var row = jdbc.queryForMap("SELECT * FROM t_vuln_finding WHERE cve_id='CVE-2026-45678'");
        assertEquals("conflicting", row.get("evidence_status")); assertNull(row.get("fixed_version"));
        assertEquals(2, JsonUtils.read((String) row.get("rule_evidence")).path("rules").size());
        assertThrows(IllegalArgumentException.class, () -> create(((Number) row.get("id")).longValue()));
        verifyNoInteractions(patches, commands);
    }

    @Test void changedRuleEvidenceBlocksCreationAndApprovalWithoutChangingInventoryOrOverwritingTheSnapshot() {
        replace(complete(pkg("amd64", "1.0"))); long id = finding(); cover(id);
        long task = ((Number) create(id).get("taskId")).longValue();
        var before = jdbc.queryForMap("SELECT rule_digest,rule_evidence FROM t_vuln_finding WHERE id=?", id);
        var changed = new java.util.LinkedHashMap<>(scopedRule("amd64", "2.0"));
        changed.put("evidence", Map.of("basis", "manual_analysis", "assessment", "affected", "package_scope", "binary", "notes", "Corrected declaration requiring a new scan."));
        catalog.cves("manual", List.of(JsonUtils.read(JsonUtils.write(Map.of("cve_id", "CVE-2026-45679", "severity", 3, "affected", List.of(changed))))), 2L);
        assertEquals(before, jdbc.queryForMap("SELECT rule_digest,rule_evidence FROM t_vuln_finding WHERE id=?", id));
        var rows = (List<Map<String, Object>>) new VulnQueryService(jdbc).findings(null, null, null, null, 1, 20).get("list");
        assertEquals(0, ((Number) rows.get(0).get("rule_current")).intValue());
        assertThrows(IllegalArgumentException.class, () -> create(id));
        assertThrows(IllegalArgumentException.class, () -> approve(task));
        assertEquals(0, jdbc.queryForObject("SELECT approved FROM t_fix_task WHERE id=?", Integer.class, task));
        assertNull(jdbc.queryForObject("SELECT dispatched_at FROM t_fix_task WHERE id=?", String.class, task));
        verifyNoInteractions(commands);
    }

    @Test void changedEvidenceDoesNotReuseAnOldIgnoredDecisionForTheSameInstallation() {
        rules(scopedRule("amd64", "2.0")); replace(complete(pkg("amd64", "1.0")));
        jdbc.update("UPDATE t_vuln_finding SET status=2 WHERE cve_id='CVE-2026-45678'");
        var changed = new java.util.LinkedHashMap<>(scopedRule("amd64", "2.0"));
        changed.put("evidence", Map.of("basis", "manual_analysis", "assessment", "affected", "package_scope", "binary", "notes", "New evidence declaration."));
        rules(changed); matcher.matchAgent("inventory-host", 3);
        assertEquals(1, jdbc.queryForObject("SELECT count(*) FROM t_vuln_finding WHERE status=2", Integer.class));
        assertEquals(1, jdbc.queryForObject("SELECT count(*) FROM t_vuln_finding WHERE status=0", Integer.class));
    }

    @Test void currentRulesCannotRetroactivelySupplyHistoricalFindingProvenance() {
        replace(complete(pkg("amd64", "1.0"))); long id = finding();
        jdbc.update("UPDATE t_vuln_finding SET evidence_status='legacy',rule_source_id='',rule_digest='',rule_evidence='{}' WHERE id=?", id);
        assertThrows(IllegalArgumentException.class, () -> create(id));
        assertEquals("", jdbc.queryForObject("SELECT rule_digest FROM t_vuln_finding WHERE id=?", String.class, id));
        verifyNoInteractions(patches, commands);
    }
}
