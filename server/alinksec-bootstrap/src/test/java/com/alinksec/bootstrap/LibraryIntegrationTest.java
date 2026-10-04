package com.alinksec.bootstrap;

import com.alinksec.common.util.JsonUtils;
import com.alinksec.service.library.*;
import com.alinksec.service.config.*;
import com.alinksec.service.command.CommandService;
import com.alinksec.service.download.AgentDownloadTokenService;
import com.alinksec.service.virus.VirusDbService;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.SingleConnectionDataSource;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import com.sun.net.httpserver.HttpServer;
import java.io.*;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.sql.DriverManager;
import java.util.*;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.zip.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/** Uses real SQLite transactions and HTTP streams, including failed candidate publication. */
class LibraryIntegrationTest {
    @TempDir Path root;
    SingleConnectionDataSource dataSource;
    JdbcTemplate jdbc;
    LibraryProperties props;
    AlinkSecProperties platform;
    LibraryFiles files;
    LibraryCatalog catalog;
    LibrarySyncService sync;
    LibrarySchedule schedules;
    VirusDbService virus;
    CommandService commands;
    HttpServer http;
    AtomicReference<String> authHeader = new AtomicReference<>(), requestForm = new AtomicReference<>();
    @BeforeEach void setup() throws Exception {
        dataSource = new SingleConnectionDataSource(DriverManager.getConnection("jdbc:sqlite:" + root.resolve("db.sqlite")), true);
        new SqliteDatabaseConfiguration.SqliteMigrationBeanPostProcessor().postProcessAfterInitialization(dataSource, "dataSource");
        jdbc = new JdbcTemplate(dataSource);
        props = new LibraryProperties(); props.setWorkDir(root.resolve("work").toString());
        platform = new AlinkSecProperties(); platform.getDatabase().setType("sqlite");
        platform.getSignature().setStorageDir(root.resolve("signature").toString());
        platform.getPatch().setStorageDir(root.resolve("patch").toString());
        files = new LibraryFiles(props, platform);
        catalog = new LibraryCatalog(jdbc, props, files, new DatabaseDialect(platform), new DataSourceTransactionManager(dataSource));
        commands = mock(CommandService.class);
        virus = new VirusDbService(jdbc, commands, platform, mock(AgentDownloadTokenService.class), catalog, files, props);
        schedules = new LibrarySchedule(props, jdbc);
        sync = new LibrarySyncService(props, catalog, virus, new FeedDownload(files, props), jdbc, mock(com.alinksec.service.scan.VulnMatchService.class), schedules);
    }
    @AfterEach void cleanup() {
        sync.close(); files.close(); if (http != null) http.stop(0); dataSource.destroy();
    }
    private byte[] pkg(String version, String hashes, String rules) throws Exception {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try (ZipOutputStream zip = new ZipOutputStream(output)) {
            Map<String, String> entries = new LinkedHashMap<>();
            entries.put("manifest.json", JsonUtils.write(Map.of("db_version", version)));
            entries.put("hashes.txt", hashes);
            if (rules != null) entries.put("rules.json", rules);
            for (var entry : entries.entrySet()) { zip.putNextEntry(new ZipEntry(entry.getKey())); zip.write(entry.getValue().getBytes(StandardCharsets.UTF_8)); zip.closeEntry(); }
        }
        return output.toByteArray();
    }
    private String active() { return jdbc.queryForObject("SELECT db_version FROM t_virus_db ORDER BY id DESC LIMIT 1", String.class); }
    private SignaturePackage hashes(String hash, String name) { return new SignaturePackage("", Map.of(hash, SignaturePackage.checkedHash(hash, name, 4)), List.of()); }
    private String artifactHashes() throws Exception {
        var artifact = virus.downloadPackage(active() + ".zip");
        try (ZipInputStream zip = new ZipInputStream(artifact.resource().getInputStream())) {
            ZipEntry entry;
            while ((entry = zip.getNextEntry()) != null) if (entry.getName().equals("hashes.txt")) return new String(zip.readAllBytes(), StandardCharsets.UTF_8);
        }
        throw new AssertionError("hashes.txt missing");
    }
    @Test void remoteUpdatesMergeWithManualDataAndUnchangedDataDoesNotRepublish() throws Exception {
        String a = "a".repeat(64), b = "b".repeat(64);
        String rule = "{\"rules\":[{\"name\":\"Manual.Rule\",\"strings\":[{\"value\":\"harmless-test\"}]}]}";
        virus.importPackage(new ByteArrayInputStream(pkg("manual-v1", a + " Manual.Name 3\n", rule)), 1L);
        assertEquals("manual-v1", active());
        var result = catalog.signatures("remote", hashes(b, "Remote.Name"), false, null);
        assertTrue((Boolean) result.get("changed"));
        String published = active();
        assertTrue(artifactHashes().contains(a + " Manual.Name"));
        assertTrue(artifactHashes().contains(b + " Remote.Name"));
        assertEquals(1, jdbc.queryForObject("SELECT rule_count FROM t_virus_db ORDER BY id DESC LIMIT 1", Integer.class));
        assertFalse((Boolean) catalog.signatures("remote", hashes(b, "Remote.Name"), false, null).get("changed"));
        assertEquals(published, active());
        catalog.signatures("remote", hashes(a, "Remote.ConflictingName"), false, null);
        assertTrue(artifactHashes().contains(a + " Manual.Name"));
        assertFalse(artifactHashes().contains("Remote.ConflictingName"));
    }
    @Test void invalidEmptyAndOverCapacityCandidatesPreserveActiveReleaseAndSourceRows() throws Exception {
        String a = "a".repeat(64);
        virus.importPackage(new ByteArrayInputStream(pkg("v1", a + " Manual 3\n", null)), 1L);
        assertThrows(IllegalArgumentException.class, () -> virus.importPackage(new ByteArrayInputStream(pkg("empty", "", null)), 1L));
        assertThrows(IllegalArgumentException.class, () -> virus.importPackage(new ByteArrayInputStream(pkg("bad", "z".repeat(64) + " Invalid 4\n", null)), 1L));
        assertThrows(IllegalArgumentException.class, () -> virus.importPackage(new ByteArrayInputStream(pkg("rule", "", "{\"rules\":[{\"name\":\"bad\",\"strings\":[{\"type\":\"hex\",\"value\":\"zz\"}]}]}")), 1L));
        props.setMaxHashes(1);
        assertThrows(IllegalArgumentException.class, () -> catalog.signatures("remote", hashes("b".repeat(64), "Remote"), false, null));
        assertEquals("v1", active());
        assertEquals(0, jdbc.queryForObject("SELECT count(*) FROM t_security_hash WHERE source_id='remote'", Integer.class));
        try (var paths = Files.list(root.resolve("work/tmp"))) { assertEquals(0, paths.count()); }
    }
    @Test void failedStorageUploadDoesNotActivateOrCommitCandidateData() throws Exception {
        virus.importPackage(new ByteArrayInputStream(pkg("v1", "a".repeat(64) + " Manual 3\n", null)), 1L);
        props.getStorage().setBackend("s3"); // Missing credentials: exercise failure inside publication transaction.
        assertThrows(IOException.class, () -> catalog.signatures("remote", hashes("b".repeat(64), "Remote"), false, null));
        assertEquals("v1", active());
        assertEquals(0, jdbc.queryForObject("SELECT count(*) FROM t_security_hash WHERE source_id='remote'", Integer.class));
        assertNotNull(virus.downloadPackage("v1.zip")); // Existing local artifacts survive enabling S3.
    }
    @Test void importsLegacyLibraryBeforeFirstRemoteMerge() throws Exception {
        byte[] previous = pkg("legacy", "a".repeat(64) + " Legacy 4\n", null);
        Files.createDirectories(root.resolve("signature")); Files.write(root.resolve("signature/legacy.zip"), previous);
        jdbc.update("INSERT INTO t_virus_db(db_version,package_key,sha256,hash_count,rule_count) VALUES ('legacy','legacy.zip',?,1,0)", "a".repeat(64));
        catalog.signatures("remote", hashes("b".repeat(64), "Remote"), false, null);
        assertTrue(artifactHashes().contains("Legacy")); assertTrue(artifactHashes().contains("Remote"));
    }
    @Test void manualImportCanRecoverADeploymentWithAMissingLegacyArtifact() throws Exception {
        jdbc.update("INSERT INTO t_virus_db(db_version,package_key,sha256,hash_count,rule_count) VALUES ('legacy','missing.zip',?,1,0)", "a".repeat(64));
        assertThrows(IOException.class, () -> catalog.signatures("remote", hashes("b".repeat(64), "Remote"), false, null));
        assertEquals("legacy", active());
        virus.importPackage(new ByteArrayInputStream(pkg("recovered", "c".repeat(64) + " Manual 3\n", null)), 1L);
        assertEquals("recovered", active());
        assertTrue(artifactHashes().contains("c".repeat(64)));
    }
    private LibraryProperties.Source endpoint(String type, AtomicReference<String> body) throws Exception {
        http = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        http.createContext("/feed", exchange -> {
            authHeader.set(exchange.getRequestHeaders().getFirst("Auth-Key"));
            requestForm.set(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            if ("fail".equals(body.get())) { exchange.sendResponseHeaders(503, -1); exchange.close(); return; }
            if ("\"v1\"".equals(exchange.getRequestHeaders().getFirst("If-None-Match"))) { exchange.sendResponseHeaders(304, -1); exchange.close(); return; }
            byte[] bytes = body.get().getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("ETag", "\"v1\"");
            exchange.sendResponseHeaders(200, bytes.length);
            try (var out = exchange.getResponseBody()) { out.write(bytes); }
        });
        http.start();
        var source = new LibraryProperties.Source(); source.setId("provider"); source.setType(type); source.setEnabled(true);
        source.setUrl("http://127.0.0.1:" + http.getAddress().getPort() + "/feed"); props.setSources(List.of(source));
        return source;
    }
    @Test void realHttpSyncHonorsConditionalChecksAndKeepsDataDuringAnOutage() throws Exception {
        var body = new AtomicReference<>("a".repeat(64) + " Remote 4\n");
        var source = endpoint("hashes", body);
        sync.sync(source); String version = active();
        assertEquals("success", jdbc.queryForObject("SELECT status FROM t_security_feed_state WHERE source_id='provider'", String.class));
        sync.sync(source); assertEquals(version, active());
        assertEquals("\"v1\"", jdbc.queryForObject("SELECT etag FROM t_security_feed_state WHERE source_id='provider'", String.class));
        body.set("fail"); sync.sync(source); assertEquals(version, active());
        var status = sync.status();
        assertTrue(JsonUtils.write(status).contains("failed"));
        assertNotNull(jdbc.queryForObject("SELECT success_at FROM t_security_feed_state WHERE source_id='provider'", String.class));
        assertNotNull(virus.downloadPackage(version + ".zip"));
    }
    @Test void remoteRuleOnlyZipPublishesAndCountsRulesAndKeepsThemOnAnEmptyUpdate() throws Exception {
        String rules = "{\"rules\":[{\"name\":\"Remote.Rule\",\"strings\":[{\"value\":\"harmless-test\"}]}]}";
        var body = new AtomicReference<>(pkg("remote-v1", "", rules));
        http = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        http.createContext("/feed", exchange -> {
            byte[] bytes = body.get(); exchange.sendResponseHeaders(200, bytes.length);
            try (var out = exchange.getResponseBody()) { out.write(bytes); }
        }); http.start();
        var source = new LibraryProperties.Source(); source.setId("provider"); source.setType("signature-zip"); source.setEnabled(true);
        source.setUrl("http://127.0.0.1:" + http.getAddress().getPort() + "/feed"); props.setSources(List.of(source));
        sync.sync(source); String version = active();
        assertEquals(1, jdbc.queryForObject("SELECT rule_count FROM t_virus_db ORDER BY id DESC LIMIT 1", Integer.class));
        assertEquals(1, jdbc.queryForObject("SELECT entry_count FROM t_security_feed_state WHERE source_id='provider'", Integer.class));
        body.set(pkg("remote-empty", "", null)); sync.sync(source);
        assertEquals(version, active());
        assertEquals(1, jdbc.queryForObject("SELECT count(*) FROM t_security_rule WHERE source_id='provider'", Integer.class));
        assertEquals("failed", jdbc.queryForObject("SELECT status FROM t_security_feed_state WHERE source_id='provider'", String.class));
    }
    @Test void malwareBazaarUsesAuthenticatedRecentApiAndDoesNotClearOnNoResults() throws Exception {
        var body = new AtomicReference<>("{\"query_status\":\"ok\",\"data\":[{\"sha256_hash\":\"" + "a".repeat(64) + "\",\"signature\":\"Test Family\"}]}");
        var source = endpoint("malwarebazaar", body); source.setApiKey("private-test-key");
        sync.sync(source); String version = active();
        assertTrue(artifactHashes().contains("MalwareBazaar.Test_Family"));
        assertEquals("private-test-key", authHeader.get());
        assertEquals("query=get_recent&selector=time", requestForm.get());
        body.set("{\"query_status\":\"no_results\"}"); sync.sync(source); assertEquals(version, active());
        body.set("{\"query_status\":\"no_api_key\",\"private-test-key\":true}"); sync.sync(source);
        assertFalse(JsonUtils.write(sync.status()).contains("private-test-key"));
        assertEquals(version, active());
    }
    @Test void mispPostsCuratedFullSnapshotAndRemovesWithdrawnHashesWithoutReplacingManualData() throws Exception {
        String manual = "a".repeat(64), remote = "b".repeat(64);
        virus.importPackage(new ByteArrayInputStream(pkg("manual-v1", manual + " Manual.Name 3\n", null)), 1L);
        var body = new AtomicReference<>(manual + "\n" + remote + "\n");
        var source = endpoint("misp", body);
        var contentType = new AtomicReference<String>();
        http.createContext("/attributes/restSearch", exchange -> {
            authHeader.set(exchange.getRequestHeaders().getFirst("Authorization"));
            contentType.set(exchange.getRequestHeaders().getFirst("Content-Type"));
            requestForm.set(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            byte[] bytes = body.get().getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, bytes.length);
            try (var out = exchange.getResponseBody()) { out.write(bytes); }
        });
        source.setUrl(source.getUrl().replace("/feed", "/attributes/restSearch"));
        source.setApiKey("private-misp-key"); source.setMispTag("alinksec:malicious-file");
        sync.sync(source);
        assertEquals("private-misp-key", authHeader.get());
        assertEquals("application/json", contentType.get());
        var query = JsonUtils.read(requestForm.get());
        assertEquals("text", query.path("returnFormat").asText());
        assertEquals("sha256", query.path("type").asText());
        assertEquals("alinksec:malicious-file", query.path("tags").get(0).asText());
        assertTrue(query.path("published").asBoolean() && query.path("to_ids").asBoolean() && query.path("enforceWarninglist").asBoolean());
        assertFalse(query.has("page") || query.has("limit") || query.has("last"));
        assertTrue(artifactHashes().contains(manual + " Manual.Name 3"));
        assertTrue(artifactHashes().contains(remote + " MISP.KnownHash 4"));
        String first = active(); sync.sync(source); assertEquals(first, active());
        body.set(manual + "\n"); sync.sync(source);
        assertFalse(artifactHashes().contains(remote));
        assertTrue(artifactHashes().contains("Manual.Name"));
        String current = active();
        for (String invalid : List.of("\n", "{\"errors\":[\"private-misp-key\"]}", "<html>login</html>")) {
            body.set(invalid); sync.sync(source);
            assertEquals(current, active());
            assertEquals(1, jdbc.queryForObject("SELECT count(*) FROM t_security_hash WHERE source_id='provider'", Integer.class));
        }
        assertFalse(JsonUtils.write(sync.status()).contains("private-misp-key"));
        assertFalse(JsonUtils.write(sync.history("provider")).contains("private-misp-key"));
        assertEquals(6, sync.history("provider").size());
    }
    @Test void scheduleOverridesSurviveNewServiceAndResetToDeploymentDefaults() throws Exception {
        var source = endpoint("hashes", new AtomicReference<>("a".repeat(64)));
        source.setEnabled(false);
        var plan = schedules.update(source.getId(), true, 900_000L);
        assertTrue(plan.enabled() && plan.overridden());
        assertEquals(plan, new LibrarySchedule(props, jdbc).effective(source));
        var row = ((List<Map<String, Object>>) sync.status().get("sources")).get(0);
        assertTrue((Boolean) row.get("enabled"));
        assertEquals(900_000L, row.get("intervalMs"));
        assertEquals("1970-01-01T00:00:00Z", row.get("nextCheckAt"));
        schedules.update(source.getId(), false, 900_000L);
        assertThrows(IllegalArgumentException.class, () -> sync.trigger(source.getId()));
        assertFalse(schedules.reset(source.getId()).overridden());
        assertFalse(schedules.effective(source).enabled());
        assertEquals(source.getIntervalMs(), schedules.effective(source).intervalMs());
    }
    @Test void scheduleValidatesProviderReadinessAndIntervalsWithoutLeakingEndpointOrKey() throws Exception {
        var source = endpoint("misp", new AtomicReference<>("a".repeat(64)));
        assertThrows(IllegalArgumentException.class, () -> schedules.update("provider", true, 300_000L));
        source.setApiKey("private-misp-key");
        for (String tag : List.of("", "!not-malicious", "%")) {
            source.setMispTag(tag);
            assertThrows(IllegalArgumentException.class, () -> schedules.update("provider", true, 300_000L));
        }
        source.setMispTag("alinksec:malicious-file");
        schedules.update("provider", true, 300_000L);
        assertThrows(IllegalArgumentException.class, () -> schedules.update("unknown", true, 300_000L));
        assertThrows(IllegalArgumentException.class, () -> schedules.update("provider", null, 300_000L));
        assertThrows(IllegalArgumentException.class, () -> schedules.update("provider", true, 299_999L));
        assertThrows(IllegalArgumentException.class, () -> schedules.update("provider", true, Long.MAX_VALUE));
        source.setType("nvd");
        assertThrows(IllegalArgumentException.class, () -> schedules.update("provider", true, 300_000L));
        assertEquals(7_200_000L, schedules.effective(source).intervalMs());
        String status = JsonUtils.write(sync.status());
        assertFalse(status.contains("private-misp-key") || status.contains(source.getUrl()));
    }
    @Test void failedRunsBackOffAndRecoveryRestoresNormalSchedule() throws Exception {
        var body = new AtomicReference<>("fail"); var source = endpoint("hashes", body);
        schedules.update(source.getId(), true, 300_000L);
        sync.sync(source); sync.sync(source); sync.sync(source);
        var row = ((List<Map<String, Object>>) sync.status().get("sources")).get(0);
        assertEquals(3, ((Number) row.get("failure_count")).intValue());
        assertEquals(1_200_000L, row.get("retryDelayMs"));
        assertEquals(java.time.Instant.parse((String) row.get("checked_at")).plusMillis(1_200_000L).toString(), row.get("nextCheckAt"));
        assertEquals("failed", sync.history("provider").get(0).get("status"));
        body.set("a".repeat(64)); sync.sync(source);
        row = ((List<Map<String, Object>>) sync.status().get("sources")).get(0);
        assertEquals(0, ((Number) row.get("failure_count")).intValue());
        assertEquals(300_000L, row.get("retryDelayMs"));
        assertEquals("success", sync.history("provider").get(0).get("status"));
        var plan = schedules.effective(source);
        assertTrue(LibrarySchedule.delay(plan, 1000) <= 86_400_000L);
    }
    @Test void schedulerSelectsOldestDueSource() throws Exception {
        var body = new AtomicReference<>("a".repeat(64)); var first = endpoint("hashes", body);
        var older = new LibraryProperties.Source(); older.setId("older"); older.setType("hashes"); older.setUrl(first.getUrl()); older.setEnabled(true);
        props.setSources(List.of(first, older));
        for (var source : props.getSources()) {
            jdbc.update("INSERT INTO t_security_feed_state(source_id,kind,checked_at,status) VALUES (?,'hashes',?,'success')",
                    source.getId(), source == first ? "2001-01-01T00:00:00Z" : "2000-01-01T00:00:00Z");
        }
        // Real worker and HTTP fixture: the older source must win even though it is listed second.
        sync.scheduled();
        long deadline = System.nanoTime() + 5_000_000_000L;
        while (Boolean.TRUE.equals(sync.status().get("running")) && System.nanoTime() < deadline) Thread.sleep(10);
        assertFalse((Boolean) sync.status().get("running"));
        assertEquals(0, sync.history("provider").size());
        assertEquals("scheduled", sync.history("older").get(0).get("trigger_type"));
    }
    @Test void pausingAnActiveSyncKeepsItsResultAndDuplicateTriggersDoNotQueueWork() throws Exception {
        virus.importPackage(new ByteArrayInputStream(pkg("manual-v1", "a".repeat(64) + " Manual 3\n", null)), 1L);
        var source = endpoint("hashes", new AtomicReference<>("b".repeat(64)));
        var entered = new CountDownLatch(1);
        var release = new CountDownLatch(1);
        var requests = new AtomicInteger();
        var response = new AtomicInteger(200);
        http.createContext("/slow", exchange -> {
            requests.incrementAndGet();
            entered.countDown();
            try {
                if (!release.await(10, TimeUnit.SECONDS)) throw new IOException("Timed out waiting for test release");
                if (response.get() != 200) { exchange.sendResponseHeaders(response.get(), -1); return; }
                byte[] bytes = "b".repeat(64).getBytes(StandardCharsets.UTF_8);
                exchange.sendResponseHeaders(200, bytes.length);
                exchange.getResponseBody().write(bytes);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } finally { exchange.close(); }
        });
        source.setUrl(source.getUrl().replace("/feed", "/slow"));
        var other = new LibraryProperties.Source();
        other.setId("other"); other.setEnabled(true); other.setUrl(source.getUrl());
        props.setSources(List.of(source, other));
        try {
            assertTrue(sync.trigger("provider"));
            assertTrue(entered.await(5, TimeUnit.SECONDS));
            assertFalse(sync.trigger("provider"));
            assertFalse(sync.trigger("other"));
            sync.scheduled();
            schedules.update("provider", false, 300_000L);
            assertThrows(IllegalArgumentException.class, () -> sync.trigger("provider"));
        } finally {
            release.countDown();
            awaitSyncIdle();
        }
        assertEquals(1, requests.get());
        assertEquals("success", sync.history("provider").get(0).get("status"));
        assertTrue(sync.history("other").isEmpty());
        assertFalse(schedules.effective(source).enabled());
        assertTrue(artifactHashes().contains("Manual"));
        assertTrue(artifactHashes().contains("b".repeat(64)));
        String published = active();

        schedules.update("provider", true, 300_000L);
        response.set(503);
        assertTrue(sync.trigger("provider")); awaitSyncIdle();
        assertEquals("failed", sync.history("provider").get(0).get("status"));
        assertEquals(published, active());
        response.set(200);
        assertTrue(sync.trigger("provider")); awaitSyncIdle();
        assertEquals("success", sync.history("provider").get(0).get("status"));
        assertEquals(3, requests.get());
        assertEquals(published, active());
    }
    private void awaitSyncIdle() throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        while (Boolean.TRUE.equals(sync.status().get("running")) && System.nanoTime() < deadline) Thread.sleep(10);
        assertFalse((Boolean) sync.status().get("running"), "Library worker did not finish");
    }
    @Test void restartRecoveryClosesInterruptedRunAndRunHistoryIsBounded() throws Exception {
        var source = endpoint("hashes", new AtomicReference<>("a".repeat(64)));
        jdbc.update("INSERT INTO t_security_feed_state(source_id,kind,status) VALUES ('provider','hashes','running')");
        jdbc.update("INSERT INTO t_security_feed_run(id,source_id,trigger_type,started_at,status) VALUES ('interrupted','provider','scheduled','2000-01-01T00:00:00Z','running')");
        sync.recoverInterruptedRuns();
        assertEquals("interrupted", sync.history("provider").get(0).get("status"));
        assertNotNull(sync.history("provider").get(0).get("finished_at"));
        assertEquals("failed", jdbc.queryForObject("SELECT status FROM t_security_feed_state WHERE source_id='provider'", String.class));
        for (int i = 0; i < 55; i++) jdbc.update("INSERT INTO t_security_feed_run(id,source_id,trigger_type,started_at,status) VALUES (?,'provider','manual','2001-01-01T00:00:00Z','success')", "historical-" + i);
        sync.sync(source);
        assertEquals(50, jdbc.queryForObject("SELECT count(*) FROM t_security_feed_run WHERE source_id='provider'", Integer.class));
        assertEquals("success", sync.history("provider").get(0).get("status"));
        assertThrows(IllegalArgumentException.class, () -> sync.history("unknown"));
    }
    @Test void manualVulnerabilityRulesWinAndMalformedBatchIsAtomic() throws Exception {
        var manual = JsonUtils.read("{\"cve_id\":\"CVE-2026-12345\",\"title\":\"Vendor correction\",\"severity\":3,\"affected\":[{\"name\":\"openssl\",\"vrange\":\"<1.2\",\"os\":\"ubuntu22.04\"}]}");
        catalog.cves("manual", List.of(manual));
        var remote = JsonUtils.read("{\"cve_id\":\"CVE-2026-12345\",\"title\":\"Remote\",\"severity\":4,\"affected\":[]}");
        catalog.cves("provider", List.of(remote));
        assertEquals("Vendor correction", jdbc.queryForObject("SELECT title FROM t_cve_db WHERE cve_id='CVE-2026-12345'", String.class));
        var invalid = JsonUtils.read("{\"cve_id\":\"invalid\",\"severity\":4,\"affected\":[]}");
        assertThrows(IllegalArgumentException.class, () -> catalog.cves("other", List.of(remote, invalid)));
        assertEquals(0, jdbc.queryForObject("SELECT count(*) FROM t_security_cve WHERE source_id='other'", Integer.class));
        assertEquals(1, ((Number) sync.status().get("matchableCveCount")).intValue());
    }
    @Test void importedRulesProduceFindingsOnlyForTheApplicableAssetAndPreserveVendorFix() {
        jdbc.update("INSERT INTO t_agent(agent_id,hostname,os_type,os_version,machine_id) VALUES ('library-agent','fixture',1,'vendor-os','library-machine')");
        jdbc.update("INSERT INTO t_asset_software(agent_id,name,version,source) VALUES ('library-agent','fixture-app','1.5','dpkg')");
        jdbc.update("INSERT INTO t_asset_software(agent_id,name,version,source) VALUES ('library-agent','fixture-app-helper','1.5','dpkg')");
        var rule = JsonUtils.read("{\"cve_id\":\"CVE-2026-12345\",\"severity\":3,\"affected\":[{\"name\":\"fixture-app\",\"os\":\"vendor-os\",\"source\":\"dpkg\",\"ranges\":[\">=1.0\",\"<2.0\"],\"fixed_version\":\"2.0-vendor1\"}]}");
        var metadata = JsonUtils.read("{\"cve_id\":\"CVE-2026-12346\",\"severity\":4,\"affected\":[]}");
        catalog.cves("manual", List.of(rule, metadata));
        var matcher = new com.alinksec.service.scan.VulnMatchService(jdbc);
        matcher.matchAgent("library-agent", 0);
        assertEquals(1, jdbc.queryForObject("SELECT count(*) FROM t_vuln_finding WHERE agent_id='library-agent'", Integer.class));
        assertEquals("2.0-vendor1", jdbc.queryForObject("SELECT fixed_version FROM t_vuln_finding WHERE agent_id='library-agent'", String.class));
        jdbc.update("UPDATE t_agent SET os_version='other-os' WHERE agent_id='library-agent'");
        matcher.matchAgent("library-agent", 0);
        assertEquals(0, jdbc.queryForObject("SELECT count(*) FROM t_vuln_finding WHERE agent_id='library-agent'", Integer.class));
        var invalid = rule.deepCopy();
        ((com.fasterxml.jackson.databind.node.ObjectNode) invalid.path("affected").get(0)).put("match", "typo");
        assertThrows(IllegalArgumentException.class, () -> catalog.cves("manual", List.of(invalid)));
        assertEquals(1, ((Number) sync.status().get("matchableCveCount")).intValue());
    }
    @Test void nvdMetadataWithoutMappingDoesNotProduceInferredPackageFixes() {
        var cve = JsonUtils.read("{\"id\":\"CVE-2026-12345\",\"descriptions\":[{\"lang\":\"en\",\"value\":\"Test\"}],\"configurations\":[{\"nodes\":[{\"operator\":\"OR\",\"cpeMatch\":[{\"vulnerable\":true,\"criteria\":\"cpe:2.3:a:example:app:*:*:*:*:*:*:*:*\",\"versionStartIncluding\":\"1.0\",\"versionEndExcluding\":\"2.0\"}]}]}]}");
        assertTrue(NvdAdapter.normalize(cve, List.of()).path("affected").isEmpty());
        var product = new LibraryProperties.Product(); product.setCpePrefix("cpe:2.3:a:example:app:"); product.setName("Example App"); product.setOs("Windows 11"); product.setAssetSource("registry");
        var rule = NvdAdapter.normalize(cve, List.of(product)).path("affected").get(0);
        assertEquals(2, rule.path("ranges").size()); assertEquals("", rule.path("fixed_version").asText());
        ((com.fasterxml.jackson.databind.node.ObjectNode) cve.path("configurations").get(0).path("nodes").get(0)).put("operator", "AND");
        assertTrue(NvdAdapter.normalize(cve, List.of(product)).path("affected").isEmpty());
    }
    @Test void boundedDownloaderRejectsOversizeAndCredentialRedirects() throws Exception {
        var body = new AtomicReference<>("a".repeat(2000)); var source = endpoint("hashes", body);
        props.setMaxDownloadBytes(1024);
        assertThrows(IOException.class, () -> new FeedDownload(files, props).fetch(source.getUrl(), Map.of(), null));
        assertThrows(IllegalArgumentException.class, () -> new FeedDownload(files, props).fetch("http://example.com/feed", Map.of(), null));
        try (var paths = Files.list(root.resolve("work/tmp"))) { assertEquals(0, paths.count()); }
    }
    @Test void retentionPreservesLatestVersionsPendingCommandsAndActiveDownloads() throws Exception {
        for (char c : new char[]{'a','b','c','d'}) catalog.signatures("remote", hashes(String.valueOf(c).repeat(64), "Remote"), false, null);
        var rows = jdbc.queryForList("SELECT id,package_key FROM t_virus_db ORDER BY id");
        jdbc.update("UPDATE t_virus_db SET imported_at='2000-01-01 00:00:00.000'");
        props.setRetainDays(1); props.setRetainVersions(2);
        String protectedKey = (String) rows.get(1).get("package_key");
        jdbc.update("INSERT INTO t_agent_download_token(token,agent_id,resource_type,resource_key,expire_at) VALUES ('fixture','agent','virus-db',?,'2999-01-01 00:00:00.000')", protectedKey);
        jdbc.update("INSERT INTO t_command(cmd_id,agent_id,type,payload,status) VALUES ('fixture','agent','signature_update','{}',0)");
        assertEquals(0, catalog.pruneSignatures());
        jdbc.update("DELETE FROM t_command WHERE cmd_id='fixture'");
        assertEquals(1, catalog.pruneSignatures());
        assertEquals(3, jdbc.queryForObject("SELECT count(*) FROM t_virus_db", Integer.class));
        assertNull(virus.downloadPackage((String) rows.get(0).get("package_key")));
        assertNotNull(virus.downloadPackage(protectedKey));
        assertNotNull(virus.downloadPackage(active() + ".zip"));
    }
    @Test void s3ClientUploadsAndStreamsArtifactsThroughTheExistingStorageBoundary() throws Exception {
        byte[] content = "small storage fixture".getBytes(StandardCharsets.UTF_8);
        List<String> methods = new ArrayList<>();
        http = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        http.createContext("/bucket/alinksec/signature/probe.zip", exchange -> {
            assertTrue(exchange.getRequestHeaders().getFirst("Authorization").startsWith("AWS4-HMAC-SHA256"));
            methods.add(exchange.getRequestMethod());
            if ("GET".equals(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(200, content.length);
                try (var out = exchange.getResponseBody()) { out.write(content); }
            } else {
                exchange.getRequestBody().readAllBytes(); exchange.getResponseHeaders().set("ETag", "\"fixture\"");
                exchange.sendResponseHeaders(200, -1); exchange.close();
            }
        }); http.start();
        props.getStorage().setBackend("s3"); props.getStorage().setBucket("bucket");
        props.getStorage().setAccessKey("fixture-access"); props.getStorage().setSecretKey("fixture-secret");
        props.getStorage().setEndpoint("http://127.0.0.1:" + http.getAddress().getPort());
        Path candidate = root.resolve("candidate.zip"); Files.write(candidate, content);
        files.put("signature", "probe.zip", candidate);
        assertFalse(Files.exists(root.resolve("signature/probe.zip")));
        var artifact = files.download("signature", "probe.zip"); assertEquals(content.length, artifact.size());
        try (var in = artifact.resource().getInputStream()) { assertArrayEquals(content, in.readAllBytes()); }
        files.delete("signature", "probe.zip");
        assertEquals(List.of("PUT", "GET", "DELETE"), methods);
    }
    @Test void patchArtifactsAndDownloadUrlsPreserveDebianVersionCharacters() throws Exception {
        var patches = new com.alinksec.service.fix.PatchRepoService(jdbc, platform, mock(AgentDownloadTokenService.class), files);
        byte[] bytes = "harmless package fixture".getBytes(StandardCharsets.UTF_8);
        var imported = patches.importPackage(new ByteArrayInputStream(bytes), "fixture_1.0~deb12+security_amd64.deb", 1, "", "fixture", "1.0", "deb", null);
        String key = (String) imported.get("filename");
        try (var input = patches.downloadPackage(key).resource().getInputStream()) { assertArrayEquals(bytes, input.readAllBytes()); }
        String url = patches.downloadUrl("agent", imported);
        String encoded = java.net.URI.create(url).getRawQuery().split("&")[0].substring("filename=".length());
        assertEquals(key, java.net.URLDecoder.decode(encoded, StandardCharsets.UTF_8));
    }
    @Test void nvdHttpImportCheckpointsOnlyACompleteValidResponse() throws Exception {
        var body = new AtomicReference<>("{\"startIndex\":0,\"totalResults\":1,\"vulnerabilities\":[{\"cve\":{\"id\":\"CVE-2026-12345\",\"published\":\"2026-01-01T00:00:00.000\",\"descriptions\":[{\"lang\":\"en\",\"value\":\"Official metadata\"}]}}]}");
        var source = endpoint("nvd", body); source.setIntervalMs(7200000);
        sync.sync(source);
        String cursor = jdbc.queryForObject("SELECT cursor FROM t_security_feed_state WHERE source_id='provider'", String.class);
        assertFalse(cursor.isEmpty());
        assertEquals("[]", jdbc.queryForObject("SELECT affected FROM t_cve_db WHERE cve_id='CVE-2026-12345'", String.class));
        body.set("{\"startIndex\":0,\"totalResults\":1,\"vulnerabilities\":[]}");
        sync.sync(source);
        assertEquals(cursor, jdbc.queryForObject("SELECT cursor FROM t_security_feed_state WHERE source_id='provider'", String.class));
        assertEquals("failed", jdbc.queryForObject("SELECT status FROM t_security_feed_state WHERE source_id='provider'", String.class));
        assertEquals("Official metadata", jdbc.queryForObject("SELECT title FROM t_cve_db WHERE cve_id='CVE-2026-12345'", String.class));
    }
    @Test void nvdPageDownloadLimitAppliesToTheWholeBatchBeforeCheckpointing() throws Exception {
        http = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        http.createContext("/feed", exchange -> {
            authHeader.set(exchange.getRequestHeaders().getFirst("apiKey"));
            int index = exchange.getRequestURI().getQuery().contains("startIndex=1") ? 1 : 0;
            var cve = Map.of("id", "CVE-2026-" + (12345 + index), "descriptions", List.of(Map.of("lang", "en", "value", "x".repeat(600))));
            byte[] bytes = JsonUtils.write(Map.of("startIndex", index, "totalResults", 2, "vulnerabilities", List.of(Map.of("cve", cve)))).getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, bytes.length);
            try (var out = exchange.getResponseBody()) { out.write(bytes); }
        }); http.start();
        var source = new LibraryProperties.Source(); source.setId("provider"); source.setType("nvd"); source.setEnabled(true);
        source.setIntervalMs(7200000); source.setApiKey("private-nvd-key");
        source.setUrl("http://127.0.0.1:" + http.getAddress().getPort() + "/feed"); props.setSources(List.of(source));
        props.setMaxDownloadBytes(1024); sync.sync(source);
        assertEquals("", jdbc.queryForObject("SELECT cursor FROM t_security_feed_state WHERE source_id='provider'", String.class));
        assertEquals(0, jdbc.queryForObject("SELECT count(*) FROM t_security_cve", Integer.class));
        assertEquals("failed", jdbc.queryForObject("SELECT status FROM t_security_feed_state WHERE source_id='provider'", String.class));
        props.setMaxDownloadBytes(4096); sync.sync(source);
        assertEquals(2, jdbc.queryForObject("SELECT count(*) FROM t_security_cve", Integer.class));
        assertEquals("success", jdbc.queryForObject("SELECT status FROM t_security_feed_state WHERE source_id='provider'", String.class));
        assertEquals("private-nvd-key", authHeader.get());
    }
}
