package com.alinksec.bootstrap;

import com.alinksec.service.alert.SecurityEventService;
import com.alinksec.service.audit.AuditService;
import com.alinksec.service.command.AgentDownloadTokenService;
import com.alinksec.service.command.CommandLifecycleListener;
import com.alinksec.service.command.CommandRepository;
import com.alinksec.service.command.CommandSender;
import com.alinksec.service.command.CommandService;
import com.alinksec.service.config.AlinkSecProperties;
import com.alinksec.service.config.DatabaseDialect;
import com.alinksec.service.notify.NotifyService;
import com.alinksec.service.response.ResponseAutomationService;
import com.alinksec.service.waf.WafEngineService;
import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;

import java.io.Closeable;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.mockito.Mockito.mock;

public class IntegrationTestFixture implements Closeable {
    public final AnnotationConfigApplicationContext context;
    public final JdbcTemplate jdbc;
    private final HikariDataSource dataSource;
    private final Path tempDir;

    private IntegrationTestFixture(AnnotationConfigApplicationContext context, JdbcTemplate jdbc, HikariDataSource dataSource, Path tempDir) {
        this.context = context;
        this.jdbc = jdbc;
        this.dataSource = dataSource;
        this.tempDir = tempDir;
    }

    public static IntegrationTestFixture create() {
        try {
            Path tempDir = Files.createTempDirectory("alinksec-fixture-");
            HikariConfig config = new HikariConfig();
            config.setJdbcUrl("jdbc:sqlite:" + tempDir.resolve("fixture.db").toAbsolutePath());
            config.addDataSourceProperty("foreign_keys", "true");
            config.addDataSourceProperty("busy_timeout", "10000");
            config.setMaximumPoolSize(2);
            config.setMinimumIdle(1);
            HikariDataSource dataSource = new HikariDataSource(config);

            new SqliteDatabaseConfiguration.SqliteMigrationBeanPostProcessor()
                    .postProcessAfterInitialization(dataSource, "dataSource");

            JdbcTemplate jdbc = new JdbcTemplate(dataSource);
            DataSourceTransactionManager txManager = new DataSourceTransactionManager(dataSource);

            AnnotationConfigApplicationContext ctx = new AnnotationConfigApplicationContext();
            ctx.registerBean(JdbcTemplate.class, () -> jdbc);
            ctx.registerBean(DataSourceTransactionManager.class, () -> txManager);

            AlinkSecProperties props = new AlinkSecProperties();
            props.getDatabase().setType("sqlite");
            DatabaseDialect dialect = new DatabaseDialect(props);
            ctx.registerBean(AlinkSecProperties.class, () -> props);
            ctx.registerBean(DatabaseDialect.class, () -> dialect);

            NotifyService notifyService = mock(NotifyService.class);
            ctx.registerBean(NotifyService.class, () -> notifyService);

            AuditService auditService = new AuditService(jdbc);
            ctx.registerBean(AuditService.class, () -> auditService);

            CommandRepository commandRepository = new CommandRepository(jdbc, dialect);
            ctx.registerBean(CommandRepository.class, () -> commandRepository);

            CommandSender commandSender = mock(CommandSender.class);
            ctx.registerBean(CommandSender.class, () -> commandSender);

            AgentDownloadTokenService downloadTokens = new AgentDownloadTokenService(jdbc, dialect);
            ctx.registerBean(AgentDownloadTokenService.class, () -> downloadTokens);

            List<CommandLifecycleListener> listeners = new ArrayList<>();
            CommandService commandService = new CommandService(commandRepository, commandSender, downloadTokens, props, listeners, txManager);
            ctx.registerBean(CommandService.class, () -> commandService);

            ResponseAutomationService responseService = new ResponseAutomationService(jdbc, commandService, auditService);
            listeners.add(responseService);
            ctx.registerBean(ResponseAutomationService.class, () -> responseService);

            SecurityEventService eventService = new SecurityEventService(jdbc, notifyService, dialect, ctx.getBeanProvider(ResponseAutomationService.class));
            ctx.registerBean(SecurityEventService.class, () -> eventService);

            WafEngineService wafService = new WafEngineService(jdbc, eventService);
            ctx.registerBean(WafEngineService.class, () -> wafService);

            ctx.refresh();

            return new IntegrationTestFixture(ctx, jdbc, dataSource, tempDir);
        } catch (Exception e) {
            throw new RuntimeException("Failed to create IntegrationTestFixture", e);
        }
    }

    @Override
    public void close() {
        if (context != null) {
            context.close();
        }
        if (dataSource != null) {
            dataSource.close();
        }
        if (tempDir != null) {
            try {
                org.springframework.util.FileSystemUtils.deleteRecursively(tempDir);
            } catch (Exception ignored) {
            }
        }
    }
}
