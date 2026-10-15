package com.alinksec.bootstrap;

import com.alinksec.common.util.JsonUtils;
import com.alinksec.service.command.CommandService;
import com.alinksec.service.config.*;
import com.alinksec.service.download.AgentDownloadTokenService;
import com.alinksec.service.fix.*;
import com.alinksec.service.library.*;
import com.alinksec.service.query.VulnQueryService;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.*;
import org.springframework.transaction.support.TransactionTemplate;
import java.io.ByteArrayInputStream;
import java.nio.file.*;
import java.sql.DriverManager;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class PatchRepoIntegrationTest {
    @TempDir Path root;
    SingleConnectionDataSource ds; JdbcTemplate jdbc; PatchRepoService repo; LibraryFiles files; LibraryCatalog catalog;
    FixTaskService fixes; CommandService commands; TransactionTemplate tx;
    @BeforeEach void setup() throws Exception {
        ds = new SingleConnectionDataSource(DriverManager.getConnection("jdbc:sqlite:" + root.resolve("db")), true);
        new SqliteDatabaseConfiguration.SqliteMigrationBeanPostProcessor().postProcessAfterInitialization(ds, "dataSource");
        jdbc = new JdbcTemplate(ds);
        var props = new AlinkSecProperties(); props.getDatabase().setType("sqlite"); props.getPatch().setStorageDir(root.resolve("patch").toString());
        var library = new LibraryProperties(); library.setWorkDir(root.resolve("work").toString());
        var manager = new DataSourceTransactionManager(ds); tx = new TransactionTemplate(manager);
        files = new LibraryFiles(library, props); repo = new PatchRepoService(jdbc, props, mock(AgentDownloadTokenService.class), files);
        catalog = new LibraryCatalog(jdbc, library, files, new DatabaseDialect(props), manager);
        commands = mock(CommandService.class); fixes = new FixTaskService(jdbc, commands, repo, new DatabaseDialect(props), manager);
        jdbc.update("INSERT INTO t_user(id,username,password_hash,role_id,status) VALUES (7,'operator','unused',1,1)");
        rule("<2.0", "2.0", "Initial disposable fixture manual declaration");
    }
    @AfterEach void close() { files.close(); ds.destroy(); }
    void rule(String range, String fixed, String notes) {
        catalog.cves("manual", List.of(JsonUtils.read(JsonUtils.write(Map.of("cve_id", "CVE-2099-12345", "severity", 3, "affected", List.of(
                Map.of("name", "patch-fixture", "source", "dpkg", "version_scheme", "dpkg", "distro_id", "ubuntu", "distro_version", "24.04",
                        "architecture", "amd64", "vrange", range, "fixed_version", fixed, "match", "exact",
                        "evidence", Map.of("basis", "manual_analysis", "assessment", "affected", "package_scope", "binary", "notes", notes))))))), 7L);
    }
    Map<String,Object> upload(String version, String distro, String arch) throws Exception {
        return repo.importPackage(new ByteArrayInputStream(NativePatchFixture.deb(root, "patch-fixture", version, arch)), "fixture.deb", 1, "Ubuntu 24.04",
                "patch-fixture", version, "deb", distro, "24.04", arch, 7L);
    }
    Map<String,Object> target() {
        var rule = jdbc.queryForMap("SELECT rule_source_id,rule_digest FROM t_cve_db WHERE cve_id='CVE-2099-12345'");
        var t = new HashMap<String,Object>(rule); t.putAll(Map.of("agent_id", "host", "finding_id", 1L, "pkg_name", "patch-fixture", "target_version", "2.0", "cve_id", "CVE-2099-12345",
                "inventory", Map.of("source", "dpkg", "distro_id", "ubuntu", "distro_version", "24.04", "architecture", "amd64")));
        return t;
    }
    Map<String,Object> review(Map<String,Object> p) throws Exception {
        long id = ((Number)p.get("id")).longValue(); var ctx = repo.reviewContext(id, "CVE-2099-12345");
        return repo.review(id, "CVE-2099-12345", String.valueOf(((Map<?,?>)ctx.get("cve")).get("rule_digest")), String.valueOf(ctx.get("patchDigest")),
                "Manually checked disposable distribution and binary fix declaration", true, 9L);
    }
    @Test void outerTransactionRollbackRemovesNewArtifactAsWellAsItsDatabaseRow() throws Exception {
        tx.executeWithoutResult(status -> {
            try { upload("2.0", "ubuntu", "amd64"); }
            catch (Exception e) { throw new RuntimeException(e); }
            status.setRollbackOnly();
        });
        assertEquals(0, jdbc.queryForObject("SELECT count(*) FROM t_patch_package", Integer.class));
        try (var paths = Files.list(root.resolve("patch"))) { assertEquals(0, paths.count()); }
    }
    @Test void historicalSqlitePackagesKeepIdentityButRequireFreshValidationAndReview() throws Exception {
        try (var legacy = new SingleConnectionDataSource(DriverManager.getConnection("jdbc:sqlite:" + root.resolve("legacy.db")), true)) {
            var oldJdbc = new JdbcTemplate(legacy);
            try (var connection = legacy.getConnection()) {
                org.springframework.jdbc.datasource.init.ScriptUtils.executeSqlScript(connection,
                        new org.springframework.core.io.ClassPathResource("db/sqlite/V001__initial.sql"));
            }
            oldJdbc.execute("CREATE TABLE t_schema_migration(version TEXT PRIMARY KEY,description TEXT NOT NULL,checksum TEXT NOT NULL,applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)");
            try (var input = new org.springframework.core.io.ClassPathResource("db/sqlite/V001__initial.sql").getInputStream()) {
                oldJdbc.update("INSERT INTO t_schema_migration(version,description,checksum) VALUES ('001','initial',?)",
                        HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(input.readAllBytes())));
            }
            oldJdbc.update("INSERT INTO t_patch_package(id,os_type,pkg_name,target_version,repo_type,filename,sha256,size) VALUES (80,1,'patch-fixture','2.0','deb','old.deb',?,3)", "a".repeat(64));
            new SqliteDatabaseConfiguration.SqliteMigrationBeanPostProcessor().postProcessAfterInitialization(legacy,"dataSource");
            var stored = oldJdbc.queryForMap("SELECT * FROM t_patch_package WHERE id=80");
            assertEquals("old.deb",stored.get("filename")); assertEquals("a".repeat(64),stored.get("sha256")); assertEquals("legacy",stored.get("metadata_status"));
            assertEquals("",stored.get("distro_id")); assertNull(PatchRepoService.reviewedPatch(oldJdbc,target()));
            assertEquals(0,oldJdbc.queryForObject("SELECT count(*) FROM t_patch_review",Integer.class));
            new SqliteDatabaseConfiguration.SqliteMigrationBeanPostProcessor().postProcessAfterInitialization(legacy,"dataSource");
            assertEquals(1,oldJdbc.queryForObject("SELECT count(*) FROM t_patch_package",Integer.class));
        }
    }
    @Test void realBinaryMismatchMalformedAndUnsupportedImportsLeaveNoObjects() throws Exception {
        var bytes = NativePatchFixture.deb(root, "patch-fixture", "3.0", "amd64");
        assertThrows(IllegalArgumentException.class, () -> repo.importPackage(new ByteArrayInputStream(bytes), "fixture.deb", 1, "", "patch-fixture", "2.0", "deb", "ubuntu", "24.04", "amd64", 7L));
        assertThrows(IllegalArgumentException.class, () -> repo.importPackage(new ByteArrayInputStream(new byte[]{1,2,3}), "bad.deb", 1, "", "patch-fixture", "2.0", "deb", "ubuntu", "24.04", "amd64", 7L));
        assertThrows(IllegalArgumentException.class, () -> repo.importPackage(new ByteArrayInputStream(bytes), "old.deb", 1, "", "patch-fixture", "3.0", "deb", 7L));
        assertThrows(IllegalArgumentException.class, () -> repo.importPackage(new ByteArrayInputStream(bytes), "win.msu", 2, "", "patch-fixture", "3.0", "msu", "ubuntu", "24.04", "amd64", 7L));
        assertEquals(0, jdbc.queryForObject("SELECT count(*) FROM t_patch_package", Integer.class));
        if (Files.exists(root.resolve("patch"))) try (var paths = Files.list(root.resolve("patch"))) { assertEquals(0, paths.count()); }
    }
    @Test void importDoesNotImplyReviewAndExactNativeScopeHasNoGenericFallback() throws Exception {
        var wrong = upload("2.0", "debian", "amd64");
        assertThrows(IllegalArgumentException.class, () -> review(wrong));
        var p = upload("2.0", "ubuntu", "amd64");
        assertNull(PatchRepoService.reviewedPatch(jdbc, target()));
        assertEquals("validated", p.get("metadata_status")); assertTrue(String.valueOf(p.get("metadata")).contains("package_header"));
        review(p); var hit = PatchRepoService.reviewedPatch(jdbc, target()); assertNotNull(hit);
        assertEquals(9L, ((Number)hit.get("reviewed_by")).longValue());
        var wrongArch = target(); wrongArch.put("inventory", Map.of("source", "dpkg", "distro_id", "ubuntu", "distro_version", "24.04", "architecture", "arm64"));
        assertNull(PatchRepoService.reviewedPatch(jdbc, wrongArch));
    }
    @Test void stillAffectedOrUndeclaredFullTargetCannotBeReviewed() throws Exception {
        assertThrows(IllegalArgumentException.class, () -> review(upload("3.0", "ubuntu", "amd64")));
        rule("<3.0", "2.0", "An inconsistent fixed version remains affected");
        assertThrows(IllegalArgumentException.class, () -> review(upload("2.0", "ubuntu", "amd64")));
    }
    @Test void changedRuleOrPatchInvalidatesContextAndPreviouslyConfirmedPin() throws Exception {
        var p = upload("2.0", "ubuntu", "amd64"); var ctx = repo.reviewContext(((Number)p.get("id")).longValue(), "CVE-2099-12345");
        review(p); var oldTarget = target(); var pin = repo.pin(PatchRepoService.reviewedPatch(jdbc, oldTarget), oldTarget);
        rule("<2.0", "2.0", "Updated manual statement creates a different rule fingerprint");
        assertNull(PatchRepoService.reviewedPatch(jdbc, target()));
        assertThrows(IllegalArgumentException.class, () -> repo.review(((Number)p.get("id")).longValue(), "CVE-2099-12345", String.valueOf(((Map<?,?>)ctx.get("cve")).get("rule_digest")), String.valueOf(ctx.get("patchDigest")), "Old displayed evidence cannot be reused", true, 9L));
        assertThrows(IllegalArgumentException.class, () -> repo.verifyPin(pin, oldTarget));
        review(p); var t = target(); var fresh = repo.pin(PatchRepoService.reviewedPatch(jdbc, t), t);
        jdbc.update("UPDATE t_patch_package SET distro_version='22.04' WHERE id=?", p.get("id"));
        assertThrows(IllegalArgumentException.class, () -> repo.verifyPin(fresh, t));
    }
    @Test void revokedReviewAndChangedBytesBlockUseWithoutSubstitutingAnotherUpload() throws Exception {
        var first = upload("2.0", "ubuntu", "amd64"); var evidence = review(first); var t = target(); var pin = repo.pin(PatchRepoService.reviewedPatch(jdbc,t),t);
        var next = upload("2.0", "ubuntu", "amd64"); review(next);
        assertNotEquals(first.get("filename"), next.get("filename")); assertEquals(first.get("id"), repo.verifyPin(pin,t).get("id"));
        repo.revoke(((Number)first.get("id")).longValue(), String.valueOf(evidence.get("id")), 10L, "Wrong vendor applicability statement");
        assertThrows(IllegalArgumentException.class, () -> repo.verifyPin(pin,t)); assertNotNull(PatchRepoService.reviewedPatch(jdbc,t));
        var fresh = repo.pin(PatchRepoService.reviewedPatch(jdbc,t),t);
        byte[] bytes = Files.readAllBytes(root.resolve("patch").resolve(String.valueOf(next.get("filename")))); bytes[bytes.length-1] ^= 1;
        Files.write(root.resolve("patch").resolve(String.valueOf(next.get("filename"))), bytes);
        assertThrows(IllegalArgumentException.class, () -> repo.verifyPin(fresh,t));
    }
    long finding() {
        jdbc.update("INSERT INTO t_agent(agent_id,hostname,os_type,os_version,distro_id,distro_version,software_collection_status,software_identity_error,package_repair_contract) VALUES ('host','host',1,'Ubuntu 24.04','ubuntu','24.04','complete','',2)");
        jdbc.update("INSERT INTO t_asset_software(agent_id,name,version,source,architecture) VALUES ('host','patch-fixture','1.0','dpkg','amd64')");
        return jdbc.queryForObject("""
                INSERT INTO t_vuln_finding(task_id,agent_id,cve_id,software,installed_version,fixed_version,severity,source,architecture,distro_id,distro_version,os_type,os_version,identity_status,rule_source_id,rule_digest,evidence_status,current_match)
                SELECT 0,'host',cve_id,'patch-fixture','1.0','2.0',3,'dpkg','amd64','ubuntu','24.04',1,'Ubuntu 24.04','complete',rule_source_id,rule_digest,'declared',true
                FROM t_cve_db WHERE cve_id='CVE-2099-12345' RETURNING id
                """, Long.class);
    }
    long create(long finding) { return ((Number) tx.execute(s -> fixes.createPackageTask("Pinned package", List.of(Map.of("agentId","host","findingId",finding)), "operator", null,null,7L)).get("taskId")).longValue(); }
    @Test void actualTaskPinsArtifactWithoutTokenAndRevocationRollsBackApprovalAndDispatch() throws Exception {
        long f = finding(); var p = upload("2.0","ubuntu","amd64");
        assertThrows(IllegalArgumentException.class, () -> create(f));
        var review = review(p); long task = create(f);
        String saved = jdbc.queryForObject("SELECT targets FROM t_fix_task WHERE id=?", String.class, task);
        assertTrue(saved.contains("patch_review")); assertTrue(saved.contains("manual_confirmation")); assertFalse(saved.contains("token="));
        repo.revoke(((Number)p.get("id")).longValue(), String.valueOf(review.get("id")), 10L, "Withdraw fixture approval");
        assertThrows(IllegalArgumentException.class, () -> tx.execute(s -> fixes.approve(task,7L)));
        assertEquals(0, jdbc.queryForObject("SELECT approved FROM t_fix_task WHERE id=?", Integer.class,task));
        assertEquals(0, jdbc.queryForObject("SELECT count(*) FROM t_command", Integer.class)); verifyNoInteractions(commands);
        var rows = (List<Map<String,Object>>)new VulnQueryService(jdbc).findings(null,null,null,null,1,20).get("list");
        assertEquals(0, rows.get(0).get("repair_reviewed"));
    }
    @Test void realRpmHeadersPreserveEpochReleaseAndArchitectureWithoutUsingTheHostDatabase() throws Exception {
        boolean available = Files.isExecutable(Path.of("/usr/bin/rpm")) && Files.isExecutable(Path.of("/usr/bin/rpmbuild"));
        if ("true".equals(System.getenv("ALINKSEC_PATCH_NATIVE_REQUIRED"))) assertTrue(available, "Native RPM tools required by CI");
        Assumptions.assumeTrue(available, "RPM tools absent locally; required in CI");
        Path file = NativePatchFixture.rpm(root);
        var metadata = new PackageMetadataReader().inspect("rpm", file);
        assertEquals(new PackageMetadataReader.Metadata("patch-fixture", "2:2.0~rc1-3.el9", "noarch", "rpm"), metadata);
        var p = repo.importPackage(Files.newInputStream(file), "fixture.rpm", 1, "", "patch-fixture", "02:2.0~rc1-3.el9", "rpm", "rhel", "9", "noarch", 7L);
        assertEquals("2:2.0~rc1-3.el9", p.get("version_identity"));
        assertThrows(IllegalArgumentException.class, () -> repo.importPackage(Files.newInputStream(file), "wrong.rpm", 1, "", "patch-fixture", "2:2.0~rc1-4.el9", "rpm", "rhel", "9", "noarch", 7L));
    }
    @Test void fullTargetVersionsOver128CharactersAreStoredWithoutTruncation() throws Exception {
        String version = "2.0+" + "b".repeat(150) + "-1"; var p = upload(version,"ubuntu","amd64");
        assertEquals(version, p.get("target_version"));
    }
}
