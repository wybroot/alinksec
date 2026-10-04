package com.alinksec.bootstrap;

import com.alinksec.proto.RptAck;
import com.alinksec.proto.RptScanResult;
import com.alinksec.proto.RptVirusResult;
import com.alinksec.proto.WeakPwdFinding;
import com.alinksec.proto.PortServiceFinding;
import com.alinksec.proto.VirusFinding;
import com.alinksec.proto.RptSecurityEvent;
import com.alinksec.proto.Severity;
import com.alinksec.service.agent.AgentEntity;
import com.alinksec.service.agent.AgentRepository;
import com.alinksec.service.alert.SecurityEventService;
import com.alinksec.service.command.CommandRepository;
import com.alinksec.service.config.AlinkSecProperties;
import com.alinksec.service.config.DatabaseDialect;
import com.alinksec.service.enroll.EnrollTokenService;
import com.alinksec.service.notify.NotifyService;
import com.alinksec.service.query.AlertQueryService;
import com.alinksec.service.query.BaselineQueryService;
import com.alinksec.service.query.DashboardQueryService;
import com.alinksec.service.query.FixQueryService;
import com.alinksec.service.query.HostQueryService;
import com.alinksec.service.query.VirusQueryService;
import com.alinksec.service.query.VulnQueryService;
import com.alinksec.service.user.UserService;
import com.alinksec.service.scan.ScanResultService;
import com.alinksec.service.virus.VirusResultService;
import com.alinksec.service.virus.VirusActionService;
import com.alinksec.service.command.CommandService;
import com.alinksec.service.protect.PolicyStoreService;
import com.alinksec.common.util.JsonUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.SingleConnectionDataSource;
import org.springframework.beans.factory.config.YamlPropertiesFactoryBean;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.Executors;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.times;

class SqliteDatabaseIntegrationTest {

    @TempDir
    Path tempDir;

    private SingleConnectionDataSource dataSource;
    private JdbcTemplate jdbc;
    private DatabaseDialect database;
    private Properties settings;

    @BeforeEach
    void setUp() throws Exception {
        Class.forName("org.sqlite.JDBC");
        settings = new Properties();
        settings.setProperty("busy_timeout", "5000");
        settings.setProperty("foreign_keys", "true");
        settings.setProperty("journal_mode", "WAL");
        settings.setProperty("synchronous", "NORMAL");
        settings.setProperty("date_class", "TEXT");
        settings.setProperty("date_string_format", "yyyy-MM-dd HH:mm:ss.SSS");
        YamlPropertiesFactoryBean yaml = new YamlPropertiesFactoryBean();
        yaml.setResources(new ClassPathResource("application-sqlite.yml"));
        settings.setProperty("transaction_mode", yaml.getObject().getProperty(
                "spring.datasource.hikari.data-source-properties.transaction_mode"));
        Connection connection = DriverManager.getConnection(
                "jdbc:sqlite:" + tempDir.resolve("alinksec.db").toAbsolutePath(), settings);
        dataSource = new SingleConnectionDataSource(connection, true);
        new SqliteDatabaseConfiguration.SqliteMigrationBeanPostProcessor()
                .postProcessAfterInitialization(dataSource, "dataSource");
        jdbc = new JdbcTemplate(dataSource);

        AlinkSecProperties properties = new AlinkSecProperties();
        properties.getDatabase().setType("sqlite");
        database = new DatabaseDialect(properties);
    }

    @AfterEach
    void tearDown() {
        dataSource.destroy();
    }

    @Test
    void serializesReadThenWriteTransactionsDuringAgentReports() throws Exception {
        assertEquals("IMMEDIATE", settings.getProperty("transaction_mode"));
        String url = "jdbc:sqlite:" + tempDir.resolve("alinksec.db").toAbsolutePath();
        try (var executor = Executors.newSingleThreadExecutor();
             Connection first = DriverManager.getConnection(url, settings);
             Connection second = DriverManager.getConnection(url, settings)) {
            first.setAutoCommit(false);
            try (var stmt = first.createStatement(); var result = stmt.executeQuery("SELECT version FROM t_policy_state WHERE id=1")) {
                assertTrue(result.next());
            }
            CountDownLatch started = new CountDownLatch(1);
            var otherWrite = executor.submit(() -> {
                started.countDown();
                second.setAutoCommit(false);
                try (var stmt = second.createStatement()) {
                    stmt.executeUpdate("UPDATE t_policy_state SET version=version+1 WHERE id=1");
                    second.commit();
                    second.setAutoCommit(true);
                }
                return true;
            });
            assertTrue(started.await(2, TimeUnit.SECONDS));
            assertThrows(TimeoutException.class, () -> otherWrite.get(200, TimeUnit.MILLISECONDS));
            try (var stmt = first.createStatement()) {
                stmt.executeUpdate("UPDATE t_policy_state SET version=version+1 WHERE id=1");
            }
            first.commit();
            first.setAutoCommit(true);
            assertTrue(otherWrite.get(5, TimeUnit.SECONDS));
            assertEquals(3, jdbc.queryForObject("SELECT version FROM t_policy_state WHERE id=1", Integer.class));
        }
    }

    @Test
    void publishesWhitelistChangesInAgentPolicySnapshots() {
        CommandService commands = mock(CommandService.class);
        PolicyStoreService policy = new PolicyStoreService(jdbc, commands);
        policy.init();
        VirusActionService actions = new VirusActionService(jdbc, commands, policy);
        String before = policy.currentVersion();
        actions.addWhitelistEntry("hash", "a".repeat(64), "local test", 1L);
        var entries = JsonUtils.read(policy.contentJson()).path("virus_whitelist");
        assertEquals(1, entries.size());
        assertEquals("a".repeat(64), entries.get(0).path("value").asText());
        assertFalse(before.equals(policy.currentVersion()));
        long id = jdbc.queryForObject("SELECT id FROM t_virus_whitelist", Long.class);
        actions.removeWhitelist(id);
        assertEquals(0, JsonUtils.read(policy.contentJson()).path("virus_whitelist").size());
    }

    @Test
    void persistsAgentScanAndVirusResultsAndCompletesTasks() {
        String scope = "{\"agent_ids\":[\"agent-scan-1\"]}";
        long scanTask = jdbc.queryForObject("""
                INSERT INTO t_scan_task(task_no, type, scope, status)
                VALUES ('SC-LIVE', 7, ?, 1) RETURNING id
                """, Long.class, scope);
        new ScanResultService(jdbc).onResult("agent-scan-1", RptScanResult.newBuilder()
                .setTaskId(String.valueOf(scanTask))
                .addWeakPasswords(WeakPwdFinding.newBuilder()
                        .setAccount("empty-test").setType("system_empty"))
                .addPortServices(PortServiceFinding.newBuilder()
                        .setPort(4444).setProtocol("tcp").setRisky(true))
                .build());
        assertEquals(1, jdbc.queryForObject("SELECT count(*) FROM t_weakpwd_finding", Integer.class));
        assertEquals(1, jdbc.queryForObject("SELECT count(*) FROM t_port_finding", Integer.class));
        assertEquals(100, jdbc.queryForObject("SELECT progress FROM t_scan_task WHERE id=?", Integer.class, scanTask));
        assertEquals(2, jdbc.queryForObject("SELECT status FROM t_scan_task WHERE id=?", Integer.class, scanTask));
        assertNotNull(jdbc.queryForObject("SELECT finished_at FROM t_scan_task WHERE id=?", String.class, scanTask));

        long virusTask = jdbc.queryForObject("""
                INSERT INTO t_virus_scan_task(task_no, mode, scope, status)
                VALUES ('VS-LIVE', 3, ?, 1) RETURNING id
                """, Long.class, scope);
        VirusResultService viruses = new VirusResultService(jdbc);
        viruses.onResult("agent-scan-1", RptVirusResult.newBuilder()
                .setTaskId(String.valueOf(virusTask)).setFilesScanned(1)
                .addFindings(VirusFinding.newBuilder().setPath("/tmp/harmless-fixture")
                        .setName("Test.Fixture").setSha256("a".repeat(64)).setEngine("hash")
                        .setSeverity(Severity.SEV_HIGH).setActionTaken("quarantined"))
                .build());
        assertEquals(1, jdbc.queryForObject("SELECT count(*) FROM t_virus_finding", Integer.class));
        assertEquals(1, jdbc.queryForObject("SELECT status FROM t_virus_finding", Integer.class));
        assertEquals(100, jdbc.queryForObject("SELECT progress FROM t_virus_scan_task WHERE id=?", Integer.class, virusTask));
        assertEquals(2, jdbc.queryForObject("SELECT status FROM t_virus_scan_task WHERE id=?", Integer.class, virusTask));
        assertNotNull(jdbc.queryForObject("SELECT finished_at FROM t_virus_scan_task WHERE id=?", String.class, virusTask));

        long cleanTask = jdbc.queryForObject("""
                INSERT INTO t_virus_scan_task(task_no, mode, scope, status)
                VALUES ('VS-CLEAN', 3, ?, 1) RETURNING id
                """, Long.class, scope);
        viruses.onResult("agent-scan-1", RptVirusResult.newBuilder()
                .setTaskId(String.valueOf(cleanTask)).setFilesScanned(1).build());
        assertEquals(2, jdbc.queryForObject("SELECT status FROM t_virus_scan_task WHERE id=?", Integer.class, cleanTask));
    }

    @Test
    void migratesSchemaSeedsDataAndRejectsChecksumChanges() {
        assertEquals(45, jdbc.queryForObject("""
                SELECT count(*) FROM sqlite_master
                WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
                """, Integer.class));
        assertEquals(3, jdbc.queryForObject("SELECT count(*) FROM t_schema_migration", Integer.class));
        assertEquals(3, jdbc.queryForObject("SELECT count(*) FROM t_role", Integer.class));
        assertEquals(1, jdbc.queryForObject("SELECT count(*) FROM t_baseline_template", Integer.class));
        assertEquals(60, jdbc.queryForObject("SELECT count(*) FROM t_baseline_item", Integer.class));
        assertEquals(20, jdbc.queryForObject("SELECT count(*) FROM t_cve_db", Integer.class));

        new SqliteDatabaseConfiguration.SqliteMigrationBeanPostProcessor()
                .postProcessAfterInitialization(dataSource, "dataSource");
        assertEquals(60, jdbc.queryForObject("SELECT count(*) FROM t_baseline_item", Integer.class));

        jdbc.update("UPDATE t_schema_migration SET checksum = 'tampered' WHERE version = '001'");
        IllegalStateException error = assertThrows(IllegalStateException.class, () ->
                new SqliteDatabaseConfiguration.SqliteMigrationBeanPostProcessor()
                        .postProcessAfterInitialization(dataSource, "dataSource"));
        assertTrue(hasMessage(error, "Checksum mismatch"));
    }

    @Test
    void refreshesStaleSqlitePolicyWithoutChangingMatchingSnapshotsOnRestart() {
        jdbc.update("UPDATE t_policy_state SET version=7,content=? WHERE id=1",
                "{\"decoy\":{\"enabled\":false}}");
        PolicyStoreService policy = new PolicyStoreService(jdbc, mock(CommandService.class));
        policy.init();
        assertTrue(JsonUtils.read(policy.contentJson()).get("decoy").get("enabled").asBoolean());
        assertEquals("v8", policy.currentVersion());
        policy.init();
        assertEquals("v8", policy.currentVersion());
    }

    @Test
    void protectionDefaultsAreSeededOnceAndPreserveEditedRulesOnRestart() {
        PolicyStoreService policy = new PolicyStoreService(jdbc, mock(CommandService.class));
        policy.init();
        assertEquals(1, JsonUtils.read(policy.contentJson()).path("file_rules").size());
        assertEquals(1, JsonUtils.read(policy.contentJson()).path("login_rules").size());
        jdbc.update("UPDATE t_protect_rule SET enabled=false WHERE rule_id='PR-0002'");
        policy.init();
        String version = policy.currentVersion();
        policy.init();
        assertEquals(version, policy.currentVersion());
        assertFalse(JsonUtils.read(policy.contentJson()).path("file_rules").get(0).path("enabled").asBoolean());
        assertEquals("alert",JsonUtils.read(policy.contentJson()).path("login_rules").get(0).path("actions").get(0).asText());
    }

    @Test
    void repeatedProtectionEventsKeepTargetIdentityAndLatestAction() {
        jdbc.update("INSERT INTO t_agent(agent_id,hostname,os_type,status) VALUES ('agent-protection','protection',1,1)");
        SecurityEventService service = new SecurityEventService(jdbc,mock(NotifyService.class),database);
        for (String target : List.of("/etc/passwd","/etc/group")) {
            for (String action : List.of("alert_only","restored","restore_failed")) {
                service.onEvent("agent-protection",RptSecurityEvent.newBuilder().setRuleId("PR-0002").setType("file_tamper")
                        .setSeverity(Severity.SEV_HIGH).setDetail(JsonUtils.write(Map.of("path",target))).setActionTaken(action).build());
            }
        }
        assertEquals(2,jdbc.queryForObject("SELECT count(*) FROM t_alert",Integer.class));
        for (Map<String,Object> row : jdbc.queryForList("SELECT count,detail,action_taken FROM t_alert")) {
            assertEquals(3,((Number)row.get("count")).intValue());
            assertEquals("restore_failed",row.get("action_taken"));
            var detail=JsonUtils.read((String)row.get("detail"));
            assertEquals("file_tamper:PR-0002:"+detail.path("path").asText(),detail.path("fingerprint").asText());
        }
    }

    @Test
    void supportsAuthenticationEnrollmentAgentsCommandsAndAlertAggregation() {
        String hash = new BCryptPasswordEncoder().encode("sqlite-test-password");
        jdbc.update("""
                INSERT INTO t_user(username, password_hash, real_name, role_id, status)
                VALUES ('sqlite-admin', ?, 'SQLite Admin', 1, 1)
                """, hash);
        UserService users = new UserService(jdbc);
        assertTrue(users.login("sqlite-admin", "sqlite-test-password", "127.0.0.1").isPresent());
        assertFalse(users.login("sqlite-admin", "wrong-password", "127.0.0.1").isPresent());
        assertEquals(2, jdbc.queryForObject("SELECT count(*) FROM t_audit_log", Integer.class));

        EnrollTokenService tokens = new EnrollTokenService(jdbc, database);
        String token = tokens.create(1L, 2, 1);
        tokens.consume(token);
        assertEquals(1, jdbc.queryForObject(
                "SELECT used_count FROM t_enroll_token WHERE token = ?", Integer.class, token));

        AgentRepository agents = new AgentRepository(jdbc, database);
        agents.insert(new AgentEntity(null, "agent-sqlite-1", "sqlite-host", "10.0.0.8",
                (short) 1, "Linux", "6.8", "amd64", "1.0.0", "machine-sqlite-1",
                null, AgentEntity.STATUS_PENDING, true, "v1", "abc", null, null, null));
        assertEquals(1, agents.heartbeat("agent-sqlite-1", "1.0.1", "v2"));
        assertEquals(AgentEntity.STATUS_ONLINE,
                agents.findByAgentId("agent-sqlite-1").orElseThrow().status());

        jdbc.update("INSERT INTO t_asset_software(agent_id, name, version) VALUES (?, 'OpenSSH', '9.8')",
                "agent-sqlite-1");
        jdbc.update("""
                INSERT INTO t_asset_port(agent_id, port, protocol, process, bind_addr)
                VALUES (?, 22, 'tcp', 'sshd', '0.0.0.0')
                """, "agent-sqlite-1");
        jdbc.update("""
                INSERT INTO t_asset_account(agent_id, name, uid, gid, shell, login_enabled, risky)
                VALUES (?, 'root', 0, 0, '/bin/bash', TRUE, TRUE)
                """, "agent-sqlite-1");
        HostQueryService hosts = new HostQueryService(jdbc);
        Map<String, Object> hostPage = hosts.list("SQLITE", 1, null, 1, 20);
        assertEquals(1L, ((Number) hostPage.get("total")).longValue());
        assertEquals(1, hosts.software("agent-sqlite-1", "ssh", 1, 20).size());
        assertEquals(1, hosts.ports("agent-sqlite-1").size());
        assertEquals(1, hosts.accounts("agent-sqlite-1").size());

        CommandRepository commands = new CommandRepository(jdbc, database);
        commands.insert("cmd-sqlite-1", "agent-sqlite-1", "collect_now",
                "{\"command_b64\":\"AQID\"}", 1L);
        assertEquals(1, commands.markSent("cmd-sqlite-1"));
        assertEquals(1, commands.onAck("agent-sqlite-1", RptAck.newBuilder()
                .setCmdId("cmd-sqlite-1").setStage(RptAck.Stage.RECEIVED).build()));
        assertEquals(1, commands.onAck("agent-sqlite-1", RptAck.newBuilder()
                .setCmdId("cmd-sqlite-1").setStage(RptAck.Stage.DONE)
                .setCode(0).setMessage("ok").build()));
        assertEquals(CommandRepository.ST_DONE,
                ((Number) commands.findByCmdId("cmd-sqlite-1").orElseThrow().get("status")).shortValue());

        NotifyService notifications = mock(NotifyService.class);
        SecurityEventService events = new SecurityEventService(jdbc, notifications, database);
        RptSecurityEvent event = RptSecurityEvent.newBuilder()
                .setRuleId("rule-sqlite-1")
                .setRuleName("SQLite integration alert")
                .setType("process")
                .setSeverity(Severity.SEV_HIGH)
                .setDetail("{\"process_key\":\"4242:100\",\"pid\":4242}")
                .setActionTaken("killed")
                .build();
        events.onEvent("agent-sqlite-1", event);
        events.onEvent("agent-sqlite-1", event);
        assertEquals(1, jdbc.queryForObject("SELECT count(*) FROM t_alert", Integer.class));
        assertEquals(2, jdbc.queryForObject("SELECT count FROM t_alert", Integer.class));
        verify(notifications, times(1)).onAlert(
                org.mockito.ArgumentMatchers.anyString(),
                org.mockito.ArgumentMatchers.eq("agent-sqlite-1"),
                org.mockito.ArgumentMatchers.eq("process"),
                org.mockito.ArgumentMatchers.eq(Severity.SEV_HIGH_VALUE),
                org.mockito.ArgumentMatchers.anyString(),
                org.mockito.ArgumentMatchers.eq("killed"));
    }

    @Test
    void runsCoreQueryContractsAgainstSqlite() {
        jdbc.update("""
                INSERT INTO t_agent(agent_id, hostname, ip, os_type, machine_id, status)
                VALUES ('agent-query-1', 'query-host', '10.0.0.9', 1, 'machine-query-1', 1)
                """);
        jdbc.update("""
                INSERT INTO t_alert(alert_no, agent_id, rule_id, event_type, severity, title, detail, action_taken)
                VALUES ('ALT-SQLITE-QUERY', 'agent-query-1', 'rule-query', 'virus', 4,
                        'query alert', '{\"fingerprint\":\"query\"}', 'quarantined')
                """);

        jdbc.update("""
                INSERT INTO t_baseline_task(task_no, name, scope, template_ids, status, progress)
                VALUES ('BL-SQLITE-1', 'SQLite baseline', '{\"agent_ids\":[\"agent-query-1\"]}', '[1]', 2, 100)
                """);
        long baselineTask = jdbc.queryForObject(
                "SELECT id FROM t_baseline_task WHERE task_no = 'BL-SQLITE-1'", Long.class);
        jdbc.update("""
                INSERT INTO t_baseline_result(task_id, agent_id, item_id, passed, actual)
                VALUES (?, 'agent-query-1', 1, TRUE, 'ok')
                """, baselineTask);
        jdbc.update("""
                INSERT INTO t_baseline_summary(task_id, agent_id, total, passed_count, failed_count, score)
                VALUES (?, 'agent-query-1', 1, 1, 0, 100)
                """, baselineTask);

        jdbc.update("""
                INSERT INTO t_scan_task(task_no, name, type, scope, status, progress)
                VALUES ('SCAN-SQLITE-1', 'SQLite scan', 1, '{\"agent_ids\":[\"agent-query-1\"]}', 2, 100)
                """);
        long scanTask = jdbc.queryForObject(
                "SELECT id FROM t_scan_task WHERE task_no = 'SCAN-SQLITE-1'", Long.class);
        jdbc.update("""
                INSERT INTO t_vuln_finding(task_id, agent_id, cve_id, software,
                                           installed_version, fixed_version, severity, cvss)
                VALUES (?, 'agent-query-1', 'CVE-2024-6387', 'openssh', '9.7', '9.8', 4, 8.1)
                """, scanTask);

        jdbc.update("""
                INSERT INTO t_virus_scan_task(task_no, name, mode, scope, status, progress)
                VALUES ('VIRUS-SQLITE-1', 'SQLite virus scan', 1,
                        '{\"agent_ids\":[\"agent-query-1\"]}', 2, 100)
                """);
        long virusTask = jdbc.queryForObject(
                "SELECT id FROM t_virus_scan_task WHERE task_no = 'VIRUS-SQLITE-1'", Long.class);
        jdbc.update("""
                INSERT INTO t_virus_finding(task_id, agent_id, path, name, sha256, size, engine,
                                            severity, action_taken, status)
                VALUES (?, 'agent-query-1', '/tmp/eicar', 'eicar', ?, 68, 'hash', 4, 'quarantined', 1)
                """, virusTask, "a".repeat(64));

        jdbc.update("""
                INSERT INTO t_fix_task(task_no, name, type, scope, targets, status, approved)
                VALUES ('FIX-SQLITE-1', 'SQLite fix', 1,
                        '{\"agent_ids\":[\"agent-query-1\"]}', '[]', 2, TRUE)
                """);
        long fixTask = jdbc.queryForObject(
                "SELECT id FROM t_fix_task WHERE task_no = 'FIX-SQLITE-1'", Long.class);
        jdbc.update("""
                INSERT INTO t_fix_record(task_id, agent_id, ref_id, ref_type, status, log)
                VALUES (?, 'agent-query-1', '1', 'baseline_item', 1, 'ok')
                """, fixTask);

        BaselineQueryService baseline = new BaselineQueryService(jdbc, database);
        assertEquals(60L, ((Number) baseline.templateItems(1, null, null).get("total")).longValue());
        assertEquals(1L, ((Number) baseline.tasks(1, 20).get("total")).longValue());
        assertEquals(1, baseline.taskCategoryStats(baselineTask).size());
        assertEquals(1, baseline.taskAgentItems(baselineTask, "agent-query-1", true).size());

        VulnQueryService vuln = new VulnQueryService(jdbc);
        assertEquals(1L, ((Number) vuln.findings(null, null, "agent-query-1", "OPENSSH", 1, 20)
                .get("total")).longValue());
        assertEquals(1L, ((Number) vuln.tasks(1, 20).get("total")).longValue());

        VirusQueryService virus = new VirusQueryService(jdbc, database);
        assertEquals(1L, ((Number) virus.tasks(1, 20).get("total")).longValue());
        assertEquals(1L, ((Number) virus.findings(null, "agent-query-1", 1, 20)
                .get("total")).longValue());
        assertEquals(1L, ((Number) virus.stats().get("quarantined")).longValue());

        FixQueryService fixes = new FixQueryService(jdbc);
        assertEquals(1L, ((Number) fixes.tasks(1, 20).get("total")).longValue());
        assertEquals(1, ((List<?>) fixes.taskRecords(fixTask).get("list")).size());

        AlertQueryService alerts = new AlertQueryService(jdbc);
        assertEquals(1L, ((Number) alerts.list(null, null, "agent-query-1", "virus", 1, 20)
                .get("total")).longValue());

        DashboardQueryService dashboard = new DashboardQueryService(jdbc, database);
        assertNotNull(dashboard.summary().get("hosts"));
        assertEquals(7, dashboard.alertTrend(7).size());
        assertEquals(7, dashboard.screenTrend(7).size());
        assertEquals(1, dashboard.baselineCategories().size());
        assertEquals(1, dashboard.topRiskHosts(5).size());
    }

    private static boolean hasMessage(Throwable error, String expected) {
        for (Throwable current = error; current != null; current = current.getCause()) {
            if (current.getMessage() != null && current.getMessage().contains(expected)) {
                return true;
            }
        }
        return false;
    }
}
