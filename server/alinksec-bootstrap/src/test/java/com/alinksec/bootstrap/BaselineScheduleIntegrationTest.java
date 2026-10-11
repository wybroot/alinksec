package com.alinksec.bootstrap;

import com.alinksec.proto.*;
import com.alinksec.service.command.CommandService;
import com.alinksec.service.config.*;
import com.alinksec.service.virus.VirusTaskService;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.aop.framework.ProxyFactory;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.core.env.MapPropertySource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.*;
import org.springframework.scheduling.annotation.ScheduledAnnotationBeanPostProcessor;
import org.springframework.scheduling.config.CronTask;
import org.springframework.scheduling.support.ScheduledMethodRunnable;
import org.springframework.scheduling.concurrent.ThreadPoolTaskScheduler;
import org.springframework.transaction.annotation.AnnotationTransactionAttributeSource;
import org.springframework.transaction.interceptor.TransactionInterceptor;

import java.nio.file.Path;
import java.sql.DriverManager;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/** Platform scheduling is distinct from host baseline score and local cron. */
class BaselineScheduleIntegrationTest {
    @TempDir Path root;
    SingleConnectionDataSource source;
    JdbcTemplate jdbc;
    CommandService commands;
    VirusTaskService service;
    List<String> destinations;
    List<Command> dispatched;

    @BeforeEach void setup() throws Exception {
        source = new SingleConnectionDataSource(DriverManager.getConnection("jdbc:sqlite:" + root.resolve("schedule.sqlite")), true);
        new SqliteDatabaseConfiguration.SqliteMigrationBeanPostProcessor().postProcessAfterInitialization(source, "dataSource");
        jdbc = new JdbcTemplate(source);
        var props = new AlinkSecProperties(); props.getDatabase().setType("sqlite");
        commands = mock(CommandService.class); destinations = new ArrayList<>(); dispatched = new ArrayList<>();
        doAnswer(call -> { destinations.add(call.getArgument(0)); dispatched.add(((Command.Builder)call.getArgument(1)).build()); return "schedule-command"; })
                .when(commands).dispatchAfterCommit(anyString(), any(Command.Builder.class), any());
        var factory = new ProxyFactory(new VirusTaskService(jdbc, commands, new DatabaseDialect(props))); factory.setProxyTargetClass(true);
        factory.addAdvice(new TransactionInterceptor(new DataSourceTransactionManager(source), new AnnotationTransactionAttributeSource()));
        service = (VirusTaskService)factory.getProxy();
    }
    @AfterEach void close() { source.destroy(); }
    void agent(String id, int status, boolean deleted) {
        jdbc.update("INSERT INTO t_agent(agent_id,host_name,os_type,os_version,status,deleted) VALUES (?,?,1,'ubuntu 24.04',?,?)", id, id, status, deleted);
    }
    void signature() {
        jdbc.update("INSERT INTO t_virus_db(db_version,hash_count,rule_count,sha256,size,package_key) VALUES ('schedule-fixture',1,0,?,1,'isolated-fixture')", "a".repeat(64));
    }

    @Test void noLibraryAndNoEligibleHostsDoNotCreateFakeSuccessfulTasks() {
        agent("online",1,false); service.weeklyQuickScan();
        assertEquals(0,jdbc.queryForObject("SELECT count(*) FROM t_virus_scan_task",Integer.class)); verifyNoInteractions(commands);
        signature(); jdbc.update("UPDATE t_agent SET status=2"); service.weeklyQuickScan();
        assertEquals(0,jdbc.queryForObject("SELECT count(*) FROM t_virus_scan_task",Integer.class)); verifyNoInteractions(commands);
    }

    @Test void weeklyPolicyDispatchesQuickOnlyToOnlineNondeletedHostsWithoutBaselineScore() {
        signature(); agent("online",1,false); agent("offline",2,false); agent("deleted",1,true);
        service.weeklyQuickScan();
        assertEquals(List.of("online"),destinations); assertEquals(1,dispatched.size());
        assertEquals(CmdVirusScan.Mode.QUICK,dispatched.get(0).getVirusScan().getMode());
        assertEquals(0,dispatched.get(0).getVirusScan().getPathsCount());
        assertEquals(1,jdbc.queryForObject("SELECT status FROM t_virus_scan_task",Integer.class));
        assertEquals(0,jdbc.queryForObject("SELECT count(*) FROM t_baseline_result",Integer.class));
        assertEquals(0,jdbc.queryForObject("SELECT count(*) FROM t_baseline_summary",Integer.class));
    }

    @Test void scheduledDispatchFailureRollsBackTaskMetadata() {
        signature(); agent("online",1,false);
        doThrow(new IllegalStateException("dispatch refusal fixture")).when(commands).dispatchAfterCommit(anyString(),any(Command.Builder.class),any());
        assertThrows(IllegalStateException.class,service::weeklyQuickScan);
        assertEquals(0,jdbc.queryForObject("SELECT count(*) FROM t_virus_scan_task",Integer.class));
    }

    @Test void actualSpringSchedulingRegistersDefaultCronAndHonorsDisableProperty() {
        for (String cron : List.of("0 30 2 * * MON", "-")) {
            try (var context = new AnnotationConfigApplicationContext()) {
                context.getEnvironment().getPropertySources().addFirst(new MapPropertySource("schedule-fixture",Map.of("alinksec.virus.weekly-scan-cron",cron)));
                context.getBeanFactory().addEmbeddedValueResolver(context.getEnvironment()::resolveRequiredPlaceholders);
                context.registerBean("taskScheduler",ThreadPoolTaskScheduler.class,() -> {
                    var scheduler = new ThreadPoolTaskScheduler(); scheduler.setPoolSize(1); scheduler.setDaemon(true); return scheduler;
                });
                context.registerBean(ScheduledAnnotationBeanPostProcessor.class);
                context.registerBean(VirusTaskService.class,() -> service);
                context.refresh();
                var tasks = context.getBean(ScheduledAnnotationBeanPostProcessor.class).getScheduledTasks().stream()
                        .filter(task -> task.getTask().getRunnable() instanceof ScheduledMethodRunnable runnable && runnable.getMethod().getName().equals("weeklyQuickScan")).toList();
                assertEquals(cron.equals("-") ? 0 : 1,tasks.size());
                if (!tasks.isEmpty()) assertEquals(cron,((CronTask)tasks.get(0).getTask()).getExpression());
            }
        }
        verifyNoInteractions(commands);
    }
}
