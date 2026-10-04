package com.alinksec.bootstrap;

import com.alinksec.common.util.JsonUtils;
import com.alinksec.proto.*;
import com.alinksec.service.baseline.*;
import com.alinksec.service.command.CommandService;
import com.alinksec.service.config.*;
import com.alinksec.service.query.BaselineQueryService;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.aop.framework.ProxyFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.*;
import org.springframework.transaction.annotation.AnnotationTransactionAttributeSource;
import org.springframework.transaction.interceptor.TransactionInterceptor;

import java.io.*;
import java.nio.file.Path;
import java.sql.DriverManager;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/** Real migrations and transactions, including rollback and immutable dispatched definitions. */
class BaselinePackageIntegrationTest {
    @TempDir Path root;
    SingleConnectionDataSource source;
    JdbcTemplate jdbc;
    DataSourceTransactionManager manager;
    CommandService commands;
    BaselineTaskService tasks;
    BaselinePackageService packages;
    BaselineResultService results;
    BaselineQueryService query;
    List<Command> dispatched;
    List<String> destinations;

    @BeforeEach void setup() throws Exception {
        source = new SingleConnectionDataSource(DriverManager.getConnection("jdbc:sqlite:" + root.resolve("db.sqlite")), true);
        new SqliteDatabaseConfiguration.SqliteMigrationBeanPostProcessor().postProcessAfterInitialization(source, "dataSource");
        jdbc = new JdbcTemplate(source); manager = new DataSourceTransactionManager(source);
        var props = new AlinkSecProperties(); props.getDatabase().setType("sqlite");
        var dialect = new DatabaseDialect(props);
        commands = mock(CommandService.class); dispatched = new ArrayList<>(); destinations = new ArrayList<>();
        doAnswer(invocation -> { destinations.add(invocation.getArgument(0)); dispatched.add(((Command.Builder) invocation.getArgument(1)).build()); return "cmd"; })
                .when(commands).dispatchAfterCommit(anyString(), any(Command.Builder.class), any());
        tasks = transactional(new BaselineTaskService(jdbc, commands, dialect));
        packages = transactional(new BaselinePackageService(jdbc, tasks));
        results = transactional(new BaselineResultService(jdbc));
        query = new BaselineQueryService(jdbc, dialect);
        jdbc.update("UPDATE t_baseline_template SET enabled=false");
        agent("ubuntu", 1, "ubuntu 24.04"); agent("windows", 2, "Windows Server 2022"); agent("rocky", 1, "rocky 9.4");
    }
    @AfterEach void cleanup() { source.destroy(); }
    @SuppressWarnings("unchecked") private <T> T transactional(T target) {
        var factory = new ProxyFactory(target); factory.setProxyTargetClass(true);
        factory.addAdvice(new TransactionInterceptor(manager, new AnnotationTransactionAttributeSource()));
        return (T) factory.getProxy();
    }
    void agent(String id, int os, String version) {
        jdbc.update("INSERT INTO t_agent(agent_id,hostname,os_type,os_version,machine_id) VALUES (?,?,?,?,?)", id, id, os, version, id);
    }
    ObjectNode document(String code, int os, String pattern, String version) {
        var doc = JsonUtils.mapper().createObjectNode();
        doc.put("schemaVersion", 1).put("code", code).put("name", "Example " + code).put("standard", "Test baseline")
                .put("product", os == 1 ? "Linux" : "Windows").put("osType", os).put("osVersionPattern", pattern).put("version", version);
        doc.putObject("source").put("name", "Test definitions").put("version", "1").put("url", "https://example.org/baseline/v1").put("sha256", "a".repeat(64));
        var item = doc.putArray("items").addObject();
        item.put("code", "CHECK-1").put("ruleId", "upstream_rule_1").put("name", "Original name").put("category", "Original category").put("severity", 2).put("remediation", "Manual review only");
        item.putObject("check").put("type", "file_line").put("target", os == 1 ? "/etc/test.conf" : "C:\\Windows\\test.ini").put("operator", "contains").put("expected", "safe=1");
        doc.putArray("unsupported"); return doc;
    }
    Map<String, Object> imported(ObjectNode document) throws IOException {
        return packages.importPackage(new ByteArrayInputStream(JsonUtils.write(document).getBytes(java.nio.charset.StandardCharsets.UTF_8)), 7L);
    }
    String id(Map<String, Object> pkg) { return (String) pkg.get("id"); }
    long template(Map<String, Object> pkg) { return ((Number) pkg.get("template_id")).longValue(); }
    long test(String id, String agent) {
        return ((Number) packages.test(id, List.of(agent), 7L).get("test_task_id")).longValue();
    }
    RptBaselineResult report(long task, String agent, boolean passed) {
        var result = RptBaselineResult.newBuilder().setTaskId(String.valueOf(task));
        jdbc.queryForList("SELECT item_id FROM t_baseline_task_expected WHERE task_id=? AND agent_id=?", Long.class, task, agent)
                .forEach(item -> result.addItems(BaselineItemResult.newBuilder().setItemId(String.valueOf(item)).setPassed(passed).setActual("safe=1")));
        return result.build();
    }
    Map<String, Object> published(ObjectNode document, String agent) throws IOException {
        var pkg = imported(document); packages.review(id(pkg), true, "Reviewed checks and applicability", 7L);
        long task = test(id(pkg), agent); results.onResult(agent, report(task, agent, true));
        return packages.publish(id(pkg), "Test result reviewed", 7L);
    }

    @Test void reviewDoesNotExecuteAndPublicationRequiresCompleteExplicitTest() throws Exception {
        var pkg = imported(document("LINUX", 1, "^ubuntu 24\\.04$", "1"));
        assertEquals("candidate", pkg.get("status")); verifyNoInteractions(commands);
        pkg = packages.review(id(pkg), true, "Reviewed", 7L); verifyNoInteractions(commands);
        long tpl = template(pkg); final String packageId = id(pkg);
        assertThrows(IllegalArgumentException.class, () -> tasks.createTask(null, List.of("ubuntu"), List.of(tpl), 7L));
        assertThrows(IllegalArgumentException.class, () -> packages.publish(packageId, "No test", 7L));
        assertThrows(IllegalArgumentException.class, () -> test(packageId, "windows"));
        assertEquals(0, jdbc.queryForObject("SELECT count(*) FROM t_baseline_task", Integer.class));
        long task = test(packageId, "ubuntu");
        assertThrows(IllegalArgumentException.class, () -> packages.publish(packageId, "Incomplete test", 7L));
        results.onResult("ubuntu", report(task, "ubuntu", true));
        assertEquals("published", packages.publish(packageId, "Test passed", 7L).get("status"));
        assertEquals(1, dispatched.size(), "Only explicit test runs commands");
        assertNull(jdbc.queryForObject("SELECT fix_spec FROM t_baseline_item WHERE template_id=?", String.class, tpl));
    }

    @Test void automaticallySelectsLinuxAndWindowsWithoutCrossPlatformChecks() throws Exception {
        published(document("UBUNTU", 1, "^ubuntu 24\\.04$", "1"), "ubuntu");
        published(document("WINDOWS", 2, "^Windows Server 2022$", "1"), "windows");
        published(document("ROCKY", 1, "^rocky 9\\.4$", "1"), "rocky");
        dispatched.clear(); destinations.clear();
        var coverage = tasks.coverage(List.of("ubuntu", "windows", "rocky"), List.of());
        assertEquals(3, coverage.size()); assertTrue(coverage.stream().allMatch(row -> Boolean.TRUE.equals(row.get("covered"))));
        long task = tasks.createTask("Mixed OS", List.of("ubuntu", "windows", "rocky"), null, 7L);
        for (int i = 0; i < destinations.size(); i++) {
            var command = dispatched.get(i).getBaselineCheck(); assertEquals(1, command.getItemsCount());
            String target = JsonUtils.read(command.getItems(0).getCheck()).path("target").asText();
            assertEquals(destinations.get(i).equals("windows"), target.startsWith("C:"));
            results.onResult(destinations.get(i), report(task, destinations.get(i), true));
        }
        assertEquals(2, jdbc.queryForObject("SELECT status FROM t_baseline_task WHERE id=?", Integer.class, task));
        assertEquals(3, jdbc.queryForObject("SELECT count(*) FROM t_baseline_task_template WHERE task_id=?", Integer.class, task));
    }

    @Test void withdrawalBlocksNewTasksAndHistoryDoesNotReadChangedLiveDefinitions() throws Exception {
        var pkg = published(document("LINUX", 1, "^ubuntu 24\\.04$", "1"), "ubuntu");
        long task = tasks.createTask(null, List.of("ubuntu"), List.of(), 7L); results.onResult("ubuntu", report(task, "ubuntu", false));
        jdbc.update("UPDATE t_baseline_item SET name='Changed',category='Changed',severity=4,\"check\"=? WHERE template_id=?", "{\"type\":\"file_line\",\"target\":\"/changed\"}", template(pkg));
        var old = query.taskAgentItems(task, "ubuntu", null).get(0);
        assertEquals("Original name", old.get("name")); assertEquals("Original category", old.get("category")); assertEquals(2, ((Number) old.get("severity")).intValue());
        assertEquals("upstream_rule_1", old.get("rule_id"));
        assertEquals("Original category", query.taskCategoryStats(task).get(0).get("category"));
        assertEquals(1, ((Number) query.latestTaskRows().get("total")).intValue());
        packages.withdraw(id(pkg), "Retracted");
        assertThrows(IllegalArgumentException.class, () -> tasks.createTask(null, List.of("ubuntu"), List.of(template(pkg)), 7L));
        assertFalse((Boolean) tasks.coverage(List.of("ubuntu"), List.of()).get(0).get("covered"));
        assertEquals("Original name", query.taskAgentItems(task, "ubuntu", null).get(0).get("name"));
    }

    @Test void duplicateVersionIsIdempotentButCannotReplaceItsContent() throws Exception {
        var doc = document("LINUX", 1, "^.*$", "1"); var pkg = imported(doc);
        assertEquals(id(pkg), id(imported(doc)));
        ((ObjectNode) doc.path("items").get(0)).put("name", "Changed");
        assertThrows(IllegalArgumentException.class, () -> imported(doc));
        assertEquals(1, jdbc.queryForObject("SELECT count(*) FROM t_baseline_package", Integer.class));
        assertEquals("Original name", JsonUtils.read(String.valueOf(jdbc.queryForObject("SELECT document FROM t_baseline_package", String.class))).path("items").get(0).path("name").asText());
    }

    @Test void staleCandidateCannotOverwriteANewerPublishedVersion() throws Exception {
        published(document("LINUX", 1, "^.*$", "1"), "ubuntu");
        var a = imported(document("LINUX", 1, "^.*$", "2")); var b = imported(document("LINUX", 1, "^.*$", "3"));
        packages.review(id(a), true, "Approved", 7L); packages.review(id(b), true, "Approved", 7L);
        long first = test(id(a), "ubuntu"), second = test(id(b), "ubuntu");
        results.onResult("ubuntu", report(first, "ubuntu", true)); results.onResult("ubuntu", report(second, "ubuntu", true));
        packages.publish(id(a), "Reviewed", 7L);
        assertThrows(IllegalArgumentException.class, () -> packages.publish(id(b), "Stale", 7L));
        assertEquals(id(a), jdbc.queryForObject("SELECT id FROM t_baseline_package WHERE status='published'", String.class));
        assertEquals(1, jdbc.queryForObject("SELECT count(*) FROM t_baseline_template WHERE enabled", Integer.class));
    }

    @Test void diffTracksRemovalAndUnsupportedRulesWithoutPublishingThemAsChecks() throws Exception {
        published(document("LINUX", 1, "^.*$", "1"), "ubuntu");
        var next = document("LINUX", 1, "^.*$", "2");
        ((ObjectNode) next.path("items").get(0)).put("ruleId", "new_rule");
        next.withArray("unsupported").addObject().put("ruleId", "upstream_rule_1").put("reason", "Needs an OVAL interpreter");
        var pkg = imported(next); @SuppressWarnings("unchecked") var diff = (List<Map<String, Object>>) pkg.get("diff");
        assertEquals(2, diff.size()); assertTrue(diff.stream().anyMatch(row -> "changed".equals(row.get("change"))));
        pkg = packages.review(id(pkg), true, "Reviewed unsupported rule", 7L);
        assertEquals(1, jdbc.queryForObject("SELECT count(*) FROM t_baseline_item WHERE template_id=?", Integer.class, template(pkg)));
    }

    @Test void partialDuplicateAndForeignResultsCannotCompleteATestOrReplaceEvidence() throws Exception {
        var pkg = imported(document("LINUX", 1, "^.*$", "1")); packages.review(id(pkg), true, "Reviewed", 7L); long task = test(id(pkg), "ubuntu");
        results.onResult("ubuntu", RptBaselineResult.newBuilder().setTaskId(String.valueOf(task)).build());
        results.onResult("windows", report(task, "ubuntu", true));
        var valid = report(task, "ubuntu", true);
        results.onResult("ubuntu", valid.toBuilder().addItems(valid.getItems(0)).build());
        assertEquals(0, jdbc.queryForObject("SELECT count(*) FROM t_baseline_summary", Integer.class));
        results.onResult("ubuntu", valid);
        results.onResult("ubuntu", valid.toBuilder().addItems(BaselineItemResult.newBuilder().setItemId("999999")).build());
        assertEquals(1, jdbc.queryForObject("SELECT count(*) FROM t_baseline_result", Integer.class));
        assertEquals(100, jdbc.queryForObject("SELECT score FROM t_baseline_summary", Integer.class));
    }

    @Test void unsupportedHostAndDeletedHostRejectWholeDispatch() throws Exception {
        published(document("LINUX", 1, "^ubuntu 24\\.04$", "1"), "ubuntu"); dispatched.clear();
        assertThrows(IllegalArgumentException.class, () -> tasks.createTask(null, List.of("ubuntu", "windows"), List.of(), 7L));
        assertEquals(0, dispatched.size());
        jdbc.update("UPDATE t_agent SET deleted=true WHERE agent_id='ubuntu'");
        assertThrows(IllegalArgumentException.class, () -> tasks.createTask(null, List.of("ubuntu"), List.of(), 7L));
    }

    @Test void rejectsUnallowlistedCommandsInvalidExpressionsAndWindowsPermissions() throws Exception {
        for (String type : List.of("cmd_output", "file_perm", "file_content")) {
            var doc = document("BAD", 2, "^.*$", "1"); var check = ((ObjectNode) doc.path("items").get(0)).putObject("check");
            check.put("type", type);
            if (type.equals("cmd_output")) check.put("cmd", "whoami & echo injected").put("operator", "eq").put("expected", "x");
            else if (type.equals("file_perm")) check.put("target", "C:\\test").put("perm", "0600");
            else check.put("target", "C:\\test").put("regex", "(?=invalid)");
            assertThrows(IllegalArgumentException.class, () -> imported(doc));
        }
        assertEquals(0, jdbc.queryForObject("SELECT count(*) FROM t_baseline_package", Integer.class)); verifyNoInteractions(commands);
    }

    @Test void acceptsPlatformSpecificCompiledCommandsAndRejectsCrossPlatformSelectors() throws Exception {
        var registry = JsonUtils.mapper().readTree(BaselinePackageIntegrationTest.class.getResourceAsStream("/baseline/commands.json"));
        for (int os : List.of(1, 2)) {
            var doc = document("OS" + os, os, "^.*$", "1"); var check = ((ObjectNode) doc.path("items").get(0)).putObject("check");
            check.put("type", "cmd_output").put("cmd", registry.path(os == 1 ? "linux" : "windows").get(0).asText()).put("operator", "eq").put("expected", "1");
            imported(doc);
            check.put("cmd", registry.path(os == 1 ? "windows" : "linux").get(0).asText()); doc.put("version", "2");
            assertThrows(IllegalArgumentException.class, () -> imported(doc));
        }
    }

    @Test void rejectsEmptyOverlargeDuplicateFieldAndExecutableExtensionPackages() throws Exception {
        assertThrows(IllegalArgumentException.class, () -> packages.importPackage(new ByteArrayInputStream(new byte[BaselinePackageFormat.MAX_BYTES + 1]), 7L));
        var doc = document("LINUX", 1, "^.*$", "1"); ((ObjectNode) doc.path("items").get(0)).putObject("fix_spec").put("script", "unreviewed");
        assertThrows(IllegalArgumentException.class, () -> imported(doc));
        String duplicate = JsonUtils.write(document("LINUX", 1, "^.*$", "1")).replace("\"schemaVersion\":1", "\"schemaVersion\":1,\"schemaVersion\":1");
        assertThrows(IllegalArgumentException.class, () -> packages.importPackage(new ByteArrayInputStream(duplicate.getBytes()), 7L));
        var empty = document("LINUX", 1, "^.*$", "1"); empty.withArray("items").removeAll();
        assertThrows(IllegalArgumentException.class, () -> imported(empty));
    }

    @Test void commandsAreDurableWithSnapshotsAndSentOnlyAfterCommit() throws Exception {
        var props = new AlinkSecProperties(); props.getDatabase().setType("sqlite");
        var database = new DatabaseDialect(props);
        var config = new com.zaxxer.hikari.HikariConfig();
        config.setJdbcUrl("jdbc:sqlite:" + root.resolve("db.sqlite"));
        config.setMaximumPoolSize(1); config.setMinimumIdle(1); config.setConnectionTimeout(1000);
        config.addDataSourceProperty("transaction_mode", "IMMEDIATE");
        config.addDataSourceProperty("busy_timeout", 1000);
        try (var pool = new com.zaxxer.hikari.HikariDataSource(config)) {
            var pooledJdbc = new JdbcTemplate(pool);
            var pooledManager = new DataSourceTransactionManager(pool);
            var sender = mock(com.alinksec.service.command.CommandSender.class);
            var repository = new com.alinksec.service.command.CommandRepository(pooledJdbc, database);
            var service = transactional(new CommandService(repository, sender,
                    mock(com.alinksec.service.download.AgentDownloadTokenService.class), props, List.of(), pooledManager), pooledManager);
            try {
                var actualTasks = transactional(new BaselineTaskService(pooledJdbc, service, database), pooledManager);
                jdbc.update("UPDATE t_baseline_template SET enabled=true WHERE id=1");
                var transaction = new org.springframework.transaction.support.TransactionTemplate(pooledManager);
                assertThrows(IllegalStateException.class, () -> transaction.execute(status -> {
                    actualTasks.createTask("rolled back", List.of("ubuntu"), List.of(1L), 7L);
                    verifyNoInteractions(sender);
                    throw new IllegalStateException("rollback fixture");
                }));
                verifyNoInteractions(sender);
                assertEquals(0, jdbc.queryForObject("SELECT count(*) FROM t_command", Integer.class));
                assertEquals(0, jdbc.queryForObject("SELECT count(*) FROM t_baseline_task_item", Integer.class));
                var delivered = new java.util.concurrent.CompletableFuture<Command>();
                doAnswer(invocation -> {
                    Command command = invocation.getArgument(1);
                    try {
                        long task = Long.parseLong(command.getBaselineCheck().getTaskId());
                        assertEquals(60, pooledJdbc.queryForObject("SELECT count(*) FROM t_baseline_task_item WHERE task_id=?", Integer.class, task));
                        assertEquals(1, pooledJdbc.queryForObject("SELECT count(*) FROM t_command", Integer.class));
                        delivered.complete(command);
                    } catch (Throwable error) { delivered.completeExceptionally(error); return false; }
                    return true;
                }).when(sender).send(eq("ubuntu"), any(Command.class));
                transaction.execute(status -> {
                    actualTasks.createTask("committed", List.of("ubuntu"), List.of(1L), 7L);
                    verifyNoInteractions(sender); return null;
                });
                delivered.get(5, java.util.concurrent.TimeUnit.SECONDS);
                verify(sender).send(eq("ubuntu"), any(Command.class));
                assertEquals(1, pooledJdbc.queryForObject("SELECT status FROM t_command", Integer.class));
                transaction.execute(status -> pooledJdbc.update("INSERT INTO t_host_group(name) VALUES ('subsequent-write')"));
                assertEquals(1, pooledJdbc.queryForObject("SELECT count(*) FROM t_host_group WHERE name='subsequent-write'", Integer.class));
            } finally { service.close(); }
        }
    }

    @SuppressWarnings("unchecked") private <T> T transactional(T target, DataSourceTransactionManager transactionManager) {
        var factory = new ProxyFactory(target); factory.setProxyTargetClass(true);
        factory.addAdvice(new TransactionInterceptor(transactionManager, new AnnotationTransactionAttributeSource()));
        return (T) factory.getProxy();
    }
}
