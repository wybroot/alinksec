package com.alinksec.bootstrap;

import com.alinksec.common.util.JsonUtils;
import com.alinksec.proto.*;
import com.alinksec.service.baseline.*;
import com.alinksec.service.command.CommandService;
import com.alinksec.service.config.*;
import com.alinksec.service.query.BaselineQueryService;
import com.alinksec.service.fix.FixTaskService;
import com.alinksec.service.fix.PatchRepoService;
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
    void enableSyntheticRepairFixture() {
        jdbc.update("UPDATE t_baseline_template SET enabled=true WHERE id=1");
        jdbc.update("UPDATE t_baseline_item SET enabled=true, \"check\"=? WHERE template_id=1",
                "{\"type\":\"file_line\",\"target\":\"/test-fixture\",\"operator\":\"contains\",\"expected\":\"safe\"}");
        jdbc.update("UPDATE t_baseline_item SET fix_spec=? WHERE template_id=1 AND code='BL-LINUX-0001'",
                "{\"risk\":\"auto\",\"steps\":[{\"action\":\"file_line_ensure\",\"path\":\"/test-fixture\",\"line\":\"safe\",\"position\":\"append\"}]}");
    }
    @AfterEach void cleanup() { source.destroy(); }

    @Test void retiredLegacyTemplateCannotCreateNewTasksOrRepairs() {
        assertFalse(DatabaseDialect.readBoolean(jdbc.queryForObject("SELECT enabled FROM t_baseline_template WHERE id=1", Object.class)));
        assertEquals(60, jdbc.queryForObject("SELECT count(*) FROM t_baseline_item WHERE template_id=1 AND NOT enabled AND fix_spec IS NULL", Integer.class));
        assertEquals("Linux 旧参考模板（已停用）", jdbc.queryForObject("SELECT name FROM t_baseline_template WHERE id=1", String.class));
        assertEquals("恶意代码特征库有效性", jdbc.queryForObject("SELECT name FROM t_baseline_item WHERE code='BL-LINUX-0050'", String.class));
        assertFalse((Boolean) tasks.coverage(List.of("ubuntu"), List.of()).get(0).get("covered"));
        assertThrows(IllegalArgumentException.class, () -> tasks.createTask("Retired", List.of("ubuntu"), List.of(1L), 7L));
        assertTrue(dispatched.isEmpty());
    }

    @Test void taskCreationRejectsPersistedRetiredSelectorsWithoutPartialDispatch() throws Exception {
        var pkg = published(document("LINUX", 1, "^.*$", "1"), "ubuntu");
        var retired = JsonUtils.mapper().createObjectNode().put("type", "cmd_output")
                .put("cmd", "stat -c %U /var/log/messages 2>/dev/null || echo root").put("operator", "eq").put("expected", "root");
        jdbc.update("UPDATE t_baseline_item SET \"check\"=? WHERE template_id=?", JsonUtils.write(retired), template(pkg));
        int before = jdbc.queryForObject("SELECT count(*) FROM t_baseline_task", Integer.class);
        dispatched.clear();
        assertThrows(IllegalArgumentException.class, () -> tasks.createTask("Unsafe", List.of("ubuntu"), List.of(), 7L));
        assertEquals(before, jdbc.queryForObject("SELECT count(*) FROM t_baseline_task", Integer.class));
        assertTrue(dispatched.isEmpty());
    }

    @Test void storedCandidateMustStillMeetTheCurrentCommandPolicyAtReviewAndPublication() throws Exception {
        var pkg = imported(document("LINUX", 1, "^.*$", "1"));
        var unsafe = document("LINUX", 1, "^.*$", "1");
        ((ObjectNode) unsafe.path("items").get(0)).putObject("check").put("type", "cmd_output")
                .put("cmd", "stat -c %U /var/log/messages 2>/dev/null || echo root").put("operator", "eq").put("expected", "root");
        jdbc.update("UPDATE t_baseline_package SET document=? WHERE id=?", JsonUtils.write(unsafe), id(pkg));
        assertThrows(IllegalArgumentException.class, () -> packages.review(id(pkg), true, "Old approval", 7L));
        assertEquals("candidate", packages.detail(id(pkg)).get("status"));
        jdbc.update("UPDATE t_baseline_package SET document=? WHERE id=?", JsonUtils.write(document("LINUX", 1, "^.*$", "1")), id(pkg));
        packages.review(id(pkg), true, "Review", 7L);
        long test = test(id(pkg), "ubuntu"); results.onResult("ubuntu", report(test, "ubuntu", true));
        jdbc.update("UPDATE t_baseline_package SET document=? WHERE id=?", JsonUtils.write(unsafe), id(pkg));
        assertThrows(IllegalArgumentException.class, () -> packages.publish(id(pkg), "Prior evidence", 7L));
        assertEquals("approved", packages.detail(id(pkg)).get("status"));
        assertFalse(DatabaseDialect.readBoolean(jdbc.queryForObject("SELECT enabled FROM t_baseline_template WHERE id=?", Object.class, template(packages.detail(id(pkg))))));
    }

    @Test void checkedInCandidatesKeepUnsupportedRulesAndExcludeUnknownVersions() throws Exception {
        Path repo = Path.of("").toAbsolutePath();
        while (!java.nio.file.Files.exists(repo.resolve("deploy/baseline"))) repo = repo.getParent();
        for (String path : List.of("packages/linux-baseline.json", "packages/windows-baseline.json", "packages/reviewed/linux-baseline.json", "packages/ssh/linux-baseline.json", "packages/identity/linux-baseline.json", "packages/pam/linux-baseline.json", "packages/pam-auth/linux-baseline.json")) {
            try (var input = java.nio.file.Files.newInputStream(repo.resolve("deploy/baseline").resolve(path))) {
                var doc = BaselinePackageFormat.read(input).document();
                int os = doc.path("osType").intValue(); String pattern = doc.path("osVersionPattern").asText();
                for (String version : List.of("", "unknown", "Other OS 999"))
                    assertFalse(BaselinePackageFormat.applies(os, pattern, Map.of("os_type", os, "os_version", version)));
                assertTrue(BaselinePackageFormat.applies(os, pattern, Map.of("os_type", os,
                        "os_version", os == 1 ? "ubuntu 24.04" : "Microsoft Windows Server 2022 Standard 21H2")));
                if (path.contains("reviewed")) {
                    assertEquals(8, doc.path("items").size()); assertEquals(52, doc.path("unsupported").size());
                    var pkg = imported((ObjectNode) doc); packages.review(id(pkg), true, "Review narrow scope", 7L);
                    long task = test(id(pkg), "ubuntu");
                    assertEquals(8, jdbc.queryForObject("SELECT count(*) FROM t_baseline_task_expected WHERE task_id=?", Integer.class, task));
                    results.onResult("ubuntu", report(task, "ubuntu", false));
                    packages.publish(id(pkg), "Protocol fixture; not native host compliance evidence", 7L);
                    assertEquals(52, ((Number) packages.detail(id(pkg)).get("unsupported_count")).intValue());
                }
            }
        }
    }

    ObjectNode sshDocument() {
        var doc = document("SSH", 1, "^ubuntu 24\\.04$", "1");
        var check = ((ObjectNode) doc.path("items").get(0)).putObject("check");
        check.put("type", "sshd_effective").put("target", "/etc/ssh/sshd_config").put("option", "permitrootlogin").put("operator", "eq").put("expected", "no");
        check.putObject("connection").put("user", "root").put("host", "admin.example.invalid")
                .put("address", "192.0.2.10").put("local_address", "192.0.2.20").put("local_port", 22);
        return doc;
    }

    ObjectNode pamDocument() throws Exception {
        Path repo = Path.of("").toAbsolutePath();
        while (!java.nio.file.Files.exists(repo.resolve("deploy/baseline"))) repo = repo.getParent();
        return (ObjectNode) JsonUtils.mapper().readTree(java.nio.file.Files.readString(repo.resolve("deploy/baseline/packages/pam/linux-baseline.json")));
    }

    ObjectNode pamAuthDocument() throws Exception {
        Path repo = Path.of("").toAbsolutePath();
        while (!java.nio.file.Files.exists(repo.resolve("deploy/baseline"))) repo = repo.getParent();
        return (ObjectNode) JsonUtils.mapper().readTree(java.nio.file.Files.readString(repo.resolve("deploy/baseline/packages/pam-auth/linux-baseline.json")));
    }

    @Test void pamAuthScopeIsDispatchedAndUnconfirmedChainsBlockPublication() throws Exception {
        var doc=pamAuthDocument(); var pkg=imported(doc);
        packages.review(id(pkg),true,"Confirm exact login auth topology and finite ordinary/root lockout reference",7L);
        for(String host:List.of("windows","rocky")) assertThrows(IllegalArgumentException.class,()->test(id(pkg),host));
        long task=test(id(pkg),"ubuntu");
        var sent=dispatched.get(dispatched.size()-1).getBaselineCheck().getItems(0);
        assertEquals(doc.path("items").get(0).path("check"),JsonUtils.mapper().readTree(sent.getCheck()));
        var response=report(task,"ubuntu",false);
        results.onResult("ubuntu",response.toBuilder().setItems(0,response.getItems(0).toBuilder().setExecutionStatus("error").setMessage("Unconfirmed auth chain")).build());
        assertThrows(IllegalArgumentException.class,()->packages.publish(id(pkg),"Cannot confirm chain",7L));
        long retry=test(id(pkg),"ubuntu");
        results.onResult("ubuntu",report(retry,"ubuntu",false));
        packages.publish(id(pkg),"Protocol fixture: complete noncompliance findings retained",7L);
        String snapshot=jdbc.queryForObject("SELECT CAST(\"check\" AS TEXT) FROM t_baseline_task_item WHERE task_id=?",String.class,task);
        assertEquals(doc.path("items").get(0).path("check"),JsonUtils.mapper().readTree(snapshot));
        var next=doc.deepCopy();next.put("version","2");var changed=imported(next);
        assertThrows(IllegalArgumentException.class,()->packages.publish(id(changed),"Reuse old test",7L));
    }

    @Test void pamAuthDefinitionsRejectOtherServicesFieldsPlatformsAndWeakenedReference() throws Exception {
        for(var change:Map.of("target","/etc/pam.d/sshd","cmd","cat /etc/shadow","option","other","operator","regex","expected","deny=0","config","/tmp/policy").entrySet()){
            var doc=pamAuthDocument();((ObjectNode)doc.path("items").get(0).path("check")).put(change.getKey(),change.getValue());
            assertThrows(IllegalArgumentException.class,()->imported(doc),change.getKey());
        }
        var windows=pamAuthDocument();windows.put("osType",2);assertThrows(IllegalArgumentException.class,()->imported(windows));
        var nil=pamAuthDocument();((ObjectNode)nil.path("items").get(0).path("check")).putNull("cmd");assertThrows(IllegalArgumentException.class,()->imported(nil));
        assertEquals(0,jdbc.queryForObject("SELECT count(*) FROM t_baseline_package",Integer.class));verifyNoInteractions(commands);
    }

    @Test void pamServiceAndReferenceAreReviewedDispatchedAndSnapshotted() throws Exception {
        var doc=pamDocument();var pkg=imported(doc);
        packages.review(id(pkg),true,"Confirm passwd local-only password chain and explicit quality reference",7L);
        assertThrows(IllegalArgumentException.class,()->test(id(pkg),"windows"));
        assertThrows(IllegalArgumentException.class,()->test(id(pkg),"rocky"));
        long task=test(id(pkg),"ubuntu");var sent=dispatched.get(dispatched.size()-1).getBaselineCheck().getItemsList();
        assertEquals(2,sent.size());
        for(int i=0;i<sent.size();i++)assertEquals(doc.path("items").get(i).path("check"),JsonUtils.mapper().readTree(sent.get(i).getCheck()));
        String snapshot=jdbc.queryForObject("SELECT CAST(\"check\" AS TEXT) FROM t_baseline_task_item WHERE task_id=? AND code='BL-LINUX-0002'",String.class,task);
        assertTrue(snapshot.contains("enforce_for_root=1"));
        results.onResult("ubuntu",report(task,"ubuntu",false));packages.publish(id(pkg),"Complete protocol fixture; findings retained",7L);
        var next=doc.deepCopy();next.put("version","2");var changed=imported(next);
        assertThrows(IllegalArgumentException.class,()->packages.publish(id(changed),"Reuse previous evidence",7L));
        assertEquals(snapshot,jdbc.queryForObject("SELECT CAST(\"check\" AS TEXT) FROM t_baseline_task_item WHERE task_id=? AND code='BL-LINUX-0002'",String.class,task));
    }

    @Test void pamDefinitionsRejectOtherServicesExecutionFieldsAndWeakenedReferences() throws Exception {
        for(var change:Map.of("target","/etc/pam.d/sshd","cmd","cat /etc/shadow","option","auth","operator","regex","expected","minlen>=1","service","other").entrySet()){
            var doc=pamDocument();((ObjectNode)doc.path("items").get(0).path("check")).put(change.getKey(),change.getValue());
            assertThrows(IllegalArgumentException.class,()->imported(doc),change.getKey());
        }
        var windows=pamDocument();windows.put("osType",2);assertThrows(IllegalArgumentException.class,()->imported(windows));
        var nil=pamDocument();((ObjectNode)nil.path("items").get(0).path("check")).putNull("connection");assertThrows(IllegalArgumentException.class,()->imported(nil));
        assertEquals(0,jdbc.queryForObject("SELECT count(*) FROM t_baseline_package",Integer.class));verifyNoInteractions(commands);
    }

    ObjectNode identityDocument() throws Exception {
        Path repo = Path.of("").toAbsolutePath();
        while (!java.nio.file.Files.exists(repo.resolve("deploy/baseline"))) repo = repo.getParent();
        return (ObjectNode) JsonUtils.mapper().readTree(java.nio.file.Files.readString(repo.resolve("deploy/baseline/packages/identity/linux-baseline.json")));
    }

    @Test void localIdentityBoundsAreReviewedDispatchedAndPreservedAcrossVersions() throws Exception {
        var document = identityDocument(); var pkg = imported(document);
        packages.review(id(pkg), true, "Confirm Ubuntu file modes, shadow group and UID scope", 7L);
        assertThrows(IllegalArgumentException.class, () -> test(id(pkg), "windows"));
        assertThrows(IllegalArgumentException.class, () -> test(id(pkg), "rocky"));
        long task = test(id(pkg), "ubuntu");
        var items = dispatched.get(dispatched.size()-1).getBaselineCheck().getItemsList();
        assertEquals(7, items.size());
        for (int i=0; i<items.size(); i++) assertEquals(document.path("items").get(i).path("check"), JsonUtils.mapper().readTree(items.get(i).getCheck()));
        String snapshot = jdbc.queryForObject("SELECT CAST(\"check\" AS TEXT) FROM t_baseline_task_item WHERE task_id=? AND code='BL-LINUX-0015'", String.class, task);
        assertEquals(999, JsonUtils.mapper().readTree(snapshot).path("uid_max").intValue());
        results.onResult("ubuntu", report(task, "ubuntu", false));
        packages.publish(id(pkg), "Protocol fixture findings reviewed; no host certification", 7L);
        var next = document.deepCopy(); next.put("version", "2");
        for (var item : next.path("items")) if (item.path("code").asText().equals("BL-LINUX-0015")) ((ObjectNode)item.path("check")).put("uid_max",499);
        var changed=imported(next);
        assertNotEquals(Boolean.TRUE,packages.detail(id(changed)).get("testReady"));
        assertThrows(IllegalArgumentException.class,()->packages.publish(id(changed),"Reuse old scope evidence",7L));
        assertEquals(snapshot,jdbc.queryForObject("SELECT CAST(\"check\" AS TEXT) FROM t_baseline_task_item WHERE task_id=? AND code='BL-LINUX-0015'",String.class,task));
    }

    @Test void localIdentityRejectsArbitraryReadsProgramsAndNonLinuxPolicies() throws Exception {
        for (var change : Map.of("target","/etc/passwd-","owner","root","group","ldap","perm","0649","operator","eq","cmd","cat /etc/shadow","connection","ignored").entrySet()) {
            var doc=identityDocument();((ObjectNode)doc.path("items").get(1).path("check")).put(change.getKey(),change.getValue());
            assertThrows(IllegalArgumentException.class,()->imported(doc),change.getKey());
        }
        var windows=identityDocument();windows.put("osType",2);assertThrows(IllegalArgumentException.class,()->imported(windows));
        var numeric=identityDocument();((ObjectNode)numeric.path("items").get(1).path("check")).put("owner",0);assertThrows(IllegalArgumentException.class,()->imported(numeric));
        var rangeOnPassword=identityDocument();((ObjectNode)rangeOnPassword.path("items").get(0).path("check")).put("uid_min",1);assertThrows(IllegalArgumentException.class,()->imported(rangeOnPassword));
        assertEquals(0,jdbc.queryForObject("SELECT count(*) FROM t_baseline_package",Integer.class));
        verifyNoInteractions(commands);
    }

    @Test void localAccountScopeRejectsMissingFractionalOverflowAndDuplicateUIDFields() throws Exception {
        for (String missing : List.of("uid_min","uid_max")) {
            var doc=identityDocument();((ObjectNode)doc.path("items").get(5).path("check")).remove(missing);assertThrows(IllegalArgumentException.class,()->imported(doc));
        }
        for (long[] range : List.of(new long[]{0,999},new long[]{1000,999},new long[]{1,4294967295L},new long[]{-1,999})) {
            var doc=identityDocument();var check=(ObjectNode)doc.path("items").get(5).path("check");check.put("uid_min",range[0]).put("uid_max",range[1]);assertThrows(IllegalArgumentException.class,()->imported(doc));
        }
        var fractional=identityDocument();((ObjectNode)fractional.path("items").get(5).path("check")).put("uid_max",999.5);assertThrows(IllegalArgumentException.class,()->imported(fractional));
        var doc=identityDocument();((ObjectNode)doc.path("items").get(5).path("check")).put("uid_max",4294967294L);imported(doc);
        String duplicate=JsonUtils.write(identityDocument()).replace("\"uid_max\":999","\"uid_max\":1000,\"uid_max\":999");
        assertThrows(IllegalArgumentException.class,()->packages.importPackage(new ByteArrayInputStream(duplicate.getBytes(java.nio.charset.StandardCharsets.UTF_8)),7L));
    }

    @Test void sshContextIsReviewedDispatchedAndPreservedInTaskSnapshots() throws Exception {
        var first = sshDocument(); var pkg = imported(first);
        packages.review(id(pkg), true, "Confirm this specific connection", 7L);
        long test = test(id(pkg), "ubuntu");
        var sent = JsonUtils.mapper().readTree(dispatched.get(dispatched.size() - 1).getBaselineCheck().getItems(0).getCheck());
        assertEquals(first.path("items").get(0).path("check"), sent);
        results.onResult("ubuntu", report(test, "ubuntu", false));
        packages.publish(id(pkg), "Configuration-only protocol fixture; not live daemon validation", 7L);
        assertFalse((Boolean) tasks.coverage(List.of("rocky"), List.of()).get(0).get("covered"));
        String snapshot = jdbc.queryForObject("SELECT CAST(\"check\" AS TEXT) FROM t_baseline_task_item WHERE task_id=?", String.class, test);
        assertEquals(sent, JsonUtils.mapper().readTree(snapshot));
        var next = first.deepCopy(); next.put("version", "2");
        ((ObjectNode) next.path("items").get(0).path("check").path("connection")).put("address", "198.51.100.10");
        var changed = imported(next);
        assertEquals("candidate", changed.get("status"));
        assertNotEquals(Boolean.TRUE, packages.detail(id(changed)).get("testReady"));
        assertThrows(IllegalArgumentException.class, () -> packages.publish(id(changed), "Reuse previous context evidence", 7L));
        assertEquals(snapshot, jdbc.queryForObject("SELECT CAST(\"check\" AS TEXT) FROM t_baseline_task_item WHERE task_id=?", String.class, test));
    }

    @Test void sshPackagesRejectMissingInjectedAndCrossPlatformConnections() {
        for (String field : List.of("user", "host", "address", "local_address", "local_port")) {
            var doc = sshDocument(); ((ObjectNode) doc.path("items").get(0).path("check").path("connection")).remove(field);
            assertThrows(IllegalArgumentException.class, () -> imported(doc), field);
        }
        for (var invalid : Map.of("user", "root,addr=198.51.100.10", "host", "localhost;touch /tmp/probe", "address", "example.org", "local_address", "fe80::1%eth0").entrySet()) {
            var doc = sshDocument(); ((ObjectNode) doc.path("items").get(0).path("check").path("connection")).put(invalid.getKey(), invalid.getValue());
            assertThrows(IllegalArgumentException.class, () -> imported(doc));
        }
        var wrongUser = sshDocument(); ((ObjectNode) wrongUser.path("items").get(0).path("check").path("connection")).put("user", "other");
        assertThrows(IllegalArgumentException.class, () -> imported(wrongUser));
        for (String value : List.of("127.000.0.1", "256.0.0.1", "::ffff:192.0.2.1", "::ffff:c000:201")) {
            var doc = sshDocument(); ((ObjectNode) doc.path("items").get(0).path("check").path("connection")).put("address", value);
            assertThrows(IllegalArgumentException.class, () -> imported(doc));
        }
        for (int port : List.of(0, 65536)) {
            var doc = sshDocument(); ((ObjectNode) doc.path("items").get(0).path("check").path("connection")).put("local_port", port);
            assertThrows(IllegalArgumentException.class, () -> imported(doc));
        }
        for (String extension : List.of("cmd", "binary", "flags")) {
            var doc = sshDocument(); ((ObjectNode) doc.path("items").get(0).path("check")).put(extension, "unreviewed");
            assertThrows(IllegalArgumentException.class, () -> imported(doc));
        }
        var windows = sshDocument(); windows.put("osType", 2);
        assertThrows(IllegalArgumentException.class, () -> imported(windows));
        var unsupported = sshDocument(); ((ObjectNode) unsupported.path("items").get(0).path("check")).put("option", "authorizedkeyscommand");
        assertThrows(IllegalArgumentException.class, () -> imported(unsupported));
        var numericPort = sshDocument(); ((ObjectNode) numericPort.path("items").get(0).path("check").path("connection")).put("local_port", "22");
        assertThrows(IllegalArgumentException.class, () -> imported(numericPort));
        assertEquals(0, jdbc.queryForObject("SELECT count(*) FROM t_baseline_package", Integer.class));
        verifyNoInteractions(commands);
    }

    @Test void sshConnectionSupportsIPv6AndRejectsDuplicateNestedFields() throws Exception {
        var doc = sshDocument(); var connection = (ObjectNode) doc.path("items").get(0).path("check").path("connection");
        connection.put("address", "2001:db8::10").put("local_address", "2001:db8::20");
        imported(doc);
        doc.put("version", "2");
        String duplicate = JsonUtils.write(doc).replace("\"user\":\"root\"", "\"user\":\"wrong\",\"user\":\"root\"");
        assertThrows(IllegalArgumentException.class, () -> packages.importPackage(new ByteArrayInputStream(duplicate.getBytes(java.nio.charset.StandardCharsets.UTF_8)), 7L));
    }

    @Test void legacyRetirementPreservesTaskSnapshotsAndUnrelatedTemplates() throws Exception {
        try (var old = new SingleConnectionDataSource(DriverManager.getConnection("jdbc:sqlite:" + root.resolve("retirement.sqlite")), true)) {
            var legacy = new JdbcTemplate(old);
            try (var connection = old.getConnection()) {
                for (String path : List.of("db/sqlite/V001__initial.sql", "db/common/V002__security_libraries.sql", "db/common/V003__library_schedules.sql"))
                    org.springframework.jdbc.datasource.init.ScriptUtils.executeSqlScript(connection, new org.springframework.core.io.ClassPathResource(path));
                legacy.update("INSERT INTO t_baseline_task(task_no,name,scope,template_ids,status) VALUES('historical','Historical','{}','[1]',2)");
                legacy.update("INSERT INTO t_baseline_result(task_id,agent_id,item_id,passed,actual,message) VALUES(1,'old-agent',1,true,'original evidence','original message')");
                for (String path : List.of("db/common/V004__baseline_packages.sql", "db/common/V005__baseline_execution_evidence.sql"))
                    org.springframework.jdbc.datasource.init.ScriptUtils.executeSqlScript(connection, new org.springframework.core.io.ClassPathResource(path));
                var snapshot = legacy.queryForMap("SELECT * FROM t_baseline_task_item WHERE task_id=1");
                var evidence = legacy.queryForMap("SELECT * FROM t_baseline_result WHERE task_id=1");
                legacy.update("INSERT INTO t_baseline_template(code,name,os_type,enabled) VALUES('USER-REFERENCE','User reference',1,true)");
                for (int repeat = 0; repeat < 2; repeat++)
                    for (String path : List.of("db/common/V006__retire_legacy_baseline.sql", "db/common/V007__baseline_log_target.sql"))
                        org.springframework.jdbc.datasource.init.ScriptUtils.executeSqlScript(connection, new org.springframework.core.io.ClassPathResource(path));
                assertEquals(snapshot, legacy.queryForMap("SELECT * FROM t_baseline_task_item WHERE task_id=1"));
                assertEquals(evidence, legacy.queryForMap("SELECT * FROM t_baseline_result WHERE task_id=1"));
                assertTrue(DatabaseDialect.readBoolean(legacy.queryForObject("SELECT enabled FROM t_baseline_template WHERE code='USER-REFERENCE'", Object.class)));
                assertEquals(60, legacy.queryForObject("SELECT count(*) FROM t_baseline_item WHERE template_id=1 AND NOT enabled AND fix_spec IS NULL", Integer.class));
            }
        }
    }
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
                .forEach(item -> result.addItems(BaselineItemResult.newBuilder().setItemId(String.valueOf(item)).setPassed(passed).setExecutionStatus(passed ? "pass" : "fail").setActual("safe=1")));
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
        @SuppressWarnings("unchecked") var detail = (Map<String, Object>) query.taskDetail(task).get("task");
        assertEquals(List.of(2L, 3L, 4L), detail.get("template_ids"));
        @SuppressWarnings("unchecked") var taskRows = (List<Map<String, Object>>) query.tasks(1, 10).get("list");
        assertEquals(List.of(2L, 3L, 4L), taskRows.get(0).get("template_ids"));
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

    @Test void executionErrorsAndLegacyReportsRequireANewExplicitTest() throws Exception {
        var pkg = imported(document("LINUX", 1, "^.*$", "1"));
        String packageId = id(pkg); packages.review(packageId, true, "Reviewed", 7L);
        for (String outcome : List.of("error", "")) {
            long task = test(packageId, "ubuntu");
            var valid = report(task, "ubuntu", false);
            var item = valid.getItems(0).toBuilder().setExecutionStatus(outcome).setMessage("Unable to check");
            results.onResult("ubuntu", valid.toBuilder().clearItems().addItems(item).build());
            assertEquals(2, jdbc.queryForObject("SELECT status FROM t_baseline_task WHERE id=?", Integer.class, task));
            assertEquals(false, packages.detail(packageId).get("testReady"));
            assertThrows(IllegalArgumentException.class, () -> packages.publish(packageId, "Reviewed", 7L));
            results.onResult("ubuntu", report(task, "ubuntu", true));
            assertEquals(0, jdbc.queryForObject("SELECT score FROM t_baseline_summary WHERE task_id=?", Integer.class, task), "Retries preserve accepted evidence");
        }
        long successfulTest = test(packageId, "ubuntu");
        // A valid negative result proves the check ran; compliance is separate
        // from deciding whether its reviewed template may be published.
        results.onResult("ubuntu", report(successfulTest, "ubuntu", false));
        assertEquals(true, packages.detail(packageId).get("testReady"));
        assertEquals("published", packages.publish(packageId, "Valid test", 7L).get("status"));
    }

    @Test void contradictoryOutcomesCannotCompleteATestAndEvidenceIsBounded() throws Exception {
        var pkg = imported(document("LINUX", 1, "^.*$", "1")); packages.review(id(pkg), true, "Reviewed", 7L);
        long task = test(id(pkg), "ubuntu"); var valid = report(task, "ubuntu", true);
        for (String outcome : List.of("fail", "error", "unknown")) {
            results.onResult("ubuntu", valid.toBuilder().clearItems().addItems(valid.getItems(0).toBuilder().setExecutionStatus(outcome)).build());
        }
        assertEquals(0, jdbc.queryForObject("SELECT count(*) FROM t_baseline_summary", Integer.class));
        String large = "取证😀".repeat(3000);
        results.onResult("ubuntu", valid.toBuilder().clearItems().addItems(valid.getItems(0).toBuilder().setActual(large).setMessage(large).setDurationMs(-1)).build());
        var evidence = query.taskAgentItems(task, "ubuntu", null).get(0);
        assertTrue(((String) evidence.get("actual")).length() <= 4097);
        assertTrue(((String) evidence.get("message")).length() <= 2049);
        assertEquals(4294967295L, ((Number) evidence.get("duration_ms")).longValue());
        results.onResult("ubuntu", report(task, "ubuntu", false));
        assertEquals(100, jdbc.queryForObject("SELECT score FROM t_baseline_summary WHERE task_id=?", Integer.class, task));
    }

    @Test void latePartialReportsPreserveTimeoutAndCancellationRejectsReports() throws Exception {
        published(document("LINUX", 1, "^.*$", "1"), "ubuntu");
        long task = tasks.createTask("Timeout", List.of("ubuntu", "rocky"), List.of(), 7L);
        jdbc.update("UPDATE t_baseline_task SET status=3,finished_at='2026-01-01 00:00:00' WHERE id=?", task);
        results.onResult("ubuntu", report(task, "ubuntu", true));
        assertEquals(3, jdbc.queryForObject("SELECT status FROM t_baseline_task WHERE id=?", Integer.class, task));
        assertEquals(50, jdbc.queryForObject("SELECT progress FROM t_baseline_task WHERE id=?", Integer.class, task));
        assertEquals("2026-01-01 00:00:00", jdbc.queryForObject("SELECT finished_at FROM t_baseline_task WHERE id=?", String.class, task));
        results.onResult("rocky", report(task, "rocky", true));
        assertEquals(2, jdbc.queryForObject("SELECT status FROM t_baseline_task WHERE id=?", Integer.class, task));
        long cancelled = tasks.createTask("Cancelled", List.of("ubuntu"), List.of(), 7L);
        jdbc.update("UPDATE t_baseline_task SET status=4 WHERE id=?", cancelled);
        results.onResult("ubuntu", report(cancelled, "ubuntu", true));
        assertEquals(0, jdbc.queryForObject("SELECT count(*) FROM t_baseline_result WHERE task_id=?", Integer.class, cancelled));
    }

    @Test void configurationRepairRequiresCurrentFailedEvidenceAndApplicableEnabledTemplate() {
        enableSyntheticRepairFixture();
        var props = new AlinkSecProperties(); props.getDatabase().setType("sqlite");
        var fixes = transactional(new FixTaskService(jdbc, commands, mock(PatchRepoService.class), new DatabaseDialect(props)));
        long item = jdbc.queryForObject("SELECT id FROM t_baseline_item WHERE template_id=1 AND fix_spec IS NOT NULL AND CAST(fix_spec AS TEXT) NOT LIKE '%manual%' LIMIT 1", Long.class);
        var target = List.<Map<String, Object>>of(Map.of("agentId", "ubuntu", "itemId", item));
        assertThrows(IllegalArgumentException.class, () -> fixes.createTask("No evidence", target, 7L));
        long task = tasks.createTask("Before repair", List.of("ubuntu"), List.of(1L), 7L);
        results.onResult("ubuntu", report(task, "ubuntu", false));
        dispatched.clear();
        long repair = fixes.createTask("Valid repair", target, 7L);
        assertEquals(1, dispatched.size()); assertEquals(FixItem.FixType.CONFIG, dispatched.get(0).getVulnFix().getFixes(0).getType());
        assertEquals(1, jdbc.queryForObject("SELECT count(*) FROM t_fix_record WHERE task_id=?", Integer.class, repair));
        dispatched.clear();
        jdbc.update("UPDATE t_baseline_template SET enabled=false WHERE id=1");
        assertThrows(IllegalArgumentException.class, () -> fixes.createTask("Disabled", target, 7L));
        enableSyntheticRepairFixture();
        jdbc.update("UPDATE t_agent SET os_type=2 WHERE agent_id='ubuntu'");
        assertThrows(IllegalArgumentException.class, () -> fixes.createTask("Wrong OS", target, 7L));
        jdbc.update("UPDATE t_agent SET os_type=1 WHERE agent_id='ubuntu'");
        jdbc.update("UPDATE t_baseline_item SET \"check\"='{}' WHERE id=?", item);
        assertThrows(IllegalArgumentException.class, () -> fixes.createTask("Stale definition", target, 7L));
        assertTrue(dispatched.isEmpty());
    }

    @Test void configurationRepairRejectsExecutionErrorsAndLaterSuccessfulResults() {
        enableSyntheticRepairFixture();
        var props = new AlinkSecProperties(); props.getDatabase().setType("sqlite");
        var fixes = transactional(new FixTaskService(jdbc, commands, mock(PatchRepoService.class), new DatabaseDialect(props)));
        long item = jdbc.queryForObject("SELECT id FROM t_baseline_item WHERE template_id=1 AND fix_spec IS NOT NULL AND CAST(fix_spec AS TEXT) NOT LIKE '%manual%' LIMIT 1", Long.class);
        var target = List.<Map<String, Object>>of(Map.of("agentId", "ubuntu", "itemId", item));
        for (String outcome : List.of("fail", "error", "legacy", "pass")) {
            long task = tasks.createTask(outcome, List.of("ubuntu"), List.of(1L), 7L);
            var response = report(task, "ubuntu", outcome.equals("pass")).toBuilder();
            if (outcome.equals("error") || outcome.equals("legacy")) {
                var first = response.getItemsList().stream().filter(value -> value.getItemId().equals(String.valueOf(item))).findFirst().orElseThrow();
                int index = response.getItemsList().indexOf(first);
                response.setItems(index, first.toBuilder().setExecutionStatus(outcome.equals("legacy") ? "" : "error"));
            }
            results.onResult("ubuntu", response.build());
            dispatched.clear();
            if (!outcome.equals("fail")) {
                assertFalse(DatabaseDialect.readBoolean(query.taskAgentItems(task, "ubuntu", null).stream().filter(row -> ((Number) row.get("item_id")).longValue() == item).findFirst().orElseThrow().get("fixable")));
                assertThrows(IllegalArgumentException.class, () -> fixes.createTask(outcome, target, 7L));
                assertTrue(dispatched.isEmpty());
            }
        }
    }

    @Test void executionMigrationKeepsHistoricalEvidenceWithoutInventingAConfirmedOutcome() throws Exception {
        try (var old = new SingleConnectionDataSource(DriverManager.getConnection("jdbc:sqlite:" + root.resolve("legacy.sqlite")), true)) {
            var legacy = new JdbcTemplate(old);
            try (var connection = old.getConnection()) {
                for (String path : List.of("db/sqlite/V001__initial.sql", "db/common/V002__security_libraries.sql",
                        "db/common/V003__library_schedules.sql", "db/common/V004__baseline_packages.sql")) {
                    org.springframework.jdbc.datasource.init.ScriptUtils.executeSqlScript(connection, new org.springframework.core.io.ClassPathResource(path));
                }
                legacy.update("INSERT INTO t_baseline_task(task_no,name,scope,template_ids,status) VALUES('legacy','Legacy','{}','[1]',2)");
                legacy.update("INSERT INTO t_baseline_result(task_id,agent_id,item_id,passed,actual,message) VALUES(1,'old-agent',1,false,'retained','retained reason')");
                legacy.update("INSERT INTO t_baseline_summary(task_id,agent_id,total,passed_count,failed_count,score) VALUES(1,'old-agent',1,0,1,0)");
                org.springframework.jdbc.datasource.init.ScriptUtils.executeSqlScript(connection,
                        new org.springframework.core.io.ClassPathResource("db/common/V005__baseline_execution_evidence.sql"));
            }
            assertEquals("legacy", legacy.queryForObject("SELECT execution_status FROM t_baseline_result", String.class));
            assertEquals("retained", legacy.queryForObject("SELECT actual FROM t_baseline_result", String.class));
            assertEquals("retained reason", legacy.queryForObject("SELECT message FROM t_baseline_result", String.class));
            assertEquals(1, legacy.queryForObject("SELECT legacy_count FROM t_baseline_summary", Integer.class));
            assertEquals(0, legacy.queryForObject("SELECT error_count FROM t_baseline_summary", Integer.class));
            assertFalse(DatabaseDialect.readBoolean(legacy.queryForObject("SELECT fix_current FROM v_baseline_result_definition", Object.class)));
        }
    }

    @Test void automaticSelectionCannotAddANewlyPublishedSeriesAfterTakingItsLocks() throws Exception {
        var first = published(document("FIRST", 1, "^.*$", "1"), "ubuntu");
        var next = imported(document("NEXT", 1, "^.*$", "1"));
        packages.review(id(next), true, "Reviewed", 7L);
        long candidate = ((Number) packages.detail(id(next)).get("template_id")).longValue();
        var interleaved = new JdbcTemplate(source) {
            @Override public int update(String sql, Object... args) {
                if (sql.equals("UPDATE t_baseline_package_gate SET revision=revision+1 WHERE code=?")) {
                    jdbc.update("UPDATE t_baseline_template SET enabled=true WHERE id=?", candidate);
                }
                return super.update(sql, args);
            }
        };
        var props = new AlinkSecProperties(); props.getDatabase().setType("sqlite");
        var creator = transactional(new BaselineTaskService(interleaved, commands, new DatabaseDialect(props)));
        dispatched.clear();
        long task = creator.createTask("Publication interleaving", List.of("ubuntu"), List.of(), 7L);
        assertEquals(List.of(template(first)), jdbc.queryForList("SELECT template_id FROM t_baseline_task_template WHERE task_id=?", Long.class, task));
        assertEquals(1, dispatched.size()); assertEquals(1, dispatched.get(0).getBaselineCheck().getItemsCount());
    }

    @Test void aLateOlderTaskCannotReplaceNewerComplianceEvidenceForRepair() {
        enableSyntheticRepairFixture();
        var props = new AlinkSecProperties(); props.getDatabase().setType("sqlite");
        var fixes = transactional(new FixTaskService(jdbc, commands, mock(PatchRepoService.class), new DatabaseDialect(props)));
        long item = jdbc.queryForObject("SELECT id FROM t_baseline_item WHERE template_id=1 AND fix_spec IS NOT NULL AND CAST(fix_spec AS TEXT) NOT LIKE '%manual%' LIMIT 1", Long.class);
        var target = List.<Map<String, Object>>of(Map.of("agentId", "ubuntu", "itemId", item));
        long old = tasks.createTask("Older delayed task", List.of("ubuntu"), List.of(1L), 7L);
        long latest = tasks.createTask("Latest task", List.of("ubuntu"), List.of(1L), 7L);
        results.onResult("ubuntu", report(latest, "ubuntu", true));
        results.onResult("ubuntu", report(old, "ubuntu", false));
        dispatched.clear();
        assertThrows(IllegalArgumentException.class, () -> fixes.createTask("Stale late evidence", target, 7L));
        assertTrue(dispatched.isEmpty());
        assertTrue(query.taskAgentItems(old, "ubuntu", null).stream().noneMatch(row -> DatabaseDialect.readBoolean(row.get("fixable"))));
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
                enableSyntheticRepairFixture();
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
