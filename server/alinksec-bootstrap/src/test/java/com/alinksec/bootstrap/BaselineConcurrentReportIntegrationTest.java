package com.alinksec.bootstrap;

import com.alinksec.common.util.JsonUtils;
import com.alinksec.proto.BaselineItemResult;
import com.alinksec.proto.RptBaselineResult;
import com.alinksec.service.baseline.BaselineResultService;
import com.alinksec.service.config.AlinkSecProperties;
import com.alinksec.service.config.DatabaseDialect;
import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.aop.framework.ProxyFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.transaction.annotation.AnnotationTransactionAttributeSource;
import org.springframework.transaction.interceptor.TransactionInterceptor;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

/** Runs on SQLite locally and the migrated PostgreSQL DML-only role in CI. */
class BaselineConcurrentReportIntegrationTest {
    @TempDir Path root;

    @Test void simultaneousCompleteReportsCannotLeaveACompletedTaskAtHalfProgress() throws Exception {
        boolean postgres = "postgres".equals(System.getProperty("alinksec.integration.database"));
        var config = new HikariConfig();
        config.setJdbcUrl(postgres ? required("ALINKSEC_INTEGRATION_PG_URL") : "jdbc:sqlite:" + root.resolve("reports.db"));
        if (postgres) {
            config.setUsername(required("ALINKSEC_INTEGRATION_PG_USER")); config.setPassword(required("ALINKSEC_INTEGRATION_PG_PASSWORD"));
        } else {
            config.addDataSourceProperty("transaction_mode", "IMMEDIATE"); config.addDataSourceProperty("busy_timeout", 5000);
        }
        config.setMaximumPoolSize(2); config.setMinimumIdle(1); config.setConnectionTimeout(5000);
        try (var pool = new HikariDataSource(config)) {
            if (!postgres) new SqliteDatabaseConfiguration.SqliteMigrationBeanPostProcessor().postProcessAfterInitialization(pool, "dataSource");
            var jdbc = new JdbcTemplate(pool);
            var delayedJdbc = new JdbcTemplate(pool) {
                @Override public <T> T queryForObject(String sql, Class<T> type, Object... args) {
                    T value = super.queryForObject(sql, type, args);
                    // Expose the stale-count interleaving that PostgreSQL allows
                    // when reports commit without holding the shared task row.
                    if (sql.equals("SELECT count(*) FROM t_baseline_summary WHERE task_id = ?") && Integer.valueOf(1).equals(value)) {
                        try { Thread.sleep(300); } catch (InterruptedException e) { Thread.currentThread().interrupt(); throw new IllegalStateException(e); }
                    }
                    return value;
                }
            };
            var factory = new ProxyFactory(new BaselineResultService(delayedJdbc)); factory.setProxyTargetClass(true);
            factory.addAdvice(new TransactionInterceptor(new DataSourceTransactionManager(pool), new AnnotationTransactionAttributeSource()));
            var results = (BaselineResultService) factory.getProxy();
            var props = new AlinkSecProperties(); props.getDatabase().setType(postgres ? "postgres" : "sqlite");
            String suffix = UUID.randomUUID().toString();
            var agents = List.of("baseline-a-" + suffix, "baseline-b-" + suffix);
            long task = jdbc.queryForObject("INSERT INTO t_baseline_task(task_no,name,scope,template_ids,status) VALUES(?,?,?,?,1) RETURNING id", Long.class,
                    "concurrent-" + suffix, "Concurrent baseline report", JsonUtils.write(Map.of("agent_ids", agents)), new DatabaseDialect(props).encodeLongList(List.of(1L)));
            var executor = Executors.newFixedThreadPool(2);
            try {
                for (String agent : agents) {
                    jdbc.update("INSERT INTO t_agent(agent_id,hostname,os_type) VALUES(?,?,1)", agent, agent);
                    jdbc.update("INSERT INTO t_baseline_task_expected(task_id,agent_id,item_id) VALUES(?,?,1)", task, agent);
                }
                var ready = new CountDownLatch(2); var start = new CountDownLatch(1);
                var jobs = agents.stream().map(agent -> executor.submit(() -> {
                    ready.countDown(); assertTrue(start.await(5, TimeUnit.SECONDS));
                    results.onResult(agent, RptBaselineResult.newBuilder().setTaskId(String.valueOf(task))
                            .addItems(BaselineItemResult.newBuilder().setItemId("1").setPassed(true).setExecutionStatus("pass")).build());
                    return null;
                })).toList();
                assertTrue(ready.await(5, TimeUnit.SECONDS)); start.countDown();
                for (var job : jobs) job.get(10, TimeUnit.SECONDS);
                assertEquals(2, jdbc.queryForObject("SELECT count(*) FROM t_baseline_summary WHERE task_id=?", Integer.class, task));
                assertEquals(2, jdbc.queryForObject("SELECT status FROM t_baseline_task WHERE id=?", Integer.class, task));
                assertEquals(100, jdbc.queryForObject("SELECT progress FROM t_baseline_task WHERE id=?", Integer.class, task));
            } finally {
                executor.shutdownNow(); assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS));
                for (String table : List.of("t_baseline_result", "t_baseline_summary", "t_baseline_task_expected")) jdbc.update("DELETE FROM " + table + " WHERE task_id=?", task);
                jdbc.update("DELETE FROM t_baseline_task WHERE id=?", task);
                agents.forEach(agent -> jdbc.update("DELETE FROM t_agent WHERE agent_id=?", agent));
            }
        }
    }

    private static String required(String name) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) throw new IllegalStateException("Missing integration fixture: " + name);
        return value;
    }
}
