package com.alinksec.bootstrap;

import com.alinksec.proto.*;
import com.alinksec.service.command.CommandService;
import com.alinksec.service.config.AlinkSecProperties;
import com.alinksec.service.download.AgentDownloadTokenService;
import com.alinksec.service.upgrade.*;
import com.zaxxer.hikari.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.jdbc.core.JdbcTemplate;
import java.nio.file.Path;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.mockito.ArgumentMatchers.*;

class UpgradeWatchdogIntegrationTest {
    @TempDir Path root;
    HikariDataSource pool; JdbcTemplate jdbc; String agent; long pkg;
    @BeforeEach void setup() {
        boolean pg="postgres".equals(System.getProperty("alinksec.integration.database"));
        var cfg=new HikariConfig();cfg.setJdbcUrl(pg?System.getenv("ALINKSEC_INTEGRATION_PG_URL"):"jdbc:sqlite:"+root.resolve("db"));
        if(pg) { cfg.setUsername(System.getenv("ALINKSEC_INTEGRATION_PG_USER"));cfg.setPassword(System.getenv("ALINKSEC_INTEGRATION_PG_PASSWORD")); }
        cfg.setMaximumPoolSize(1);pool=new HikariDataSource(cfg);
        if(!pg) new SqliteDatabaseConfiguration.SqliteMigrationBeanPostProcessor().postProcessAfterInitialization(pool,"dataSource");
        jdbc=new JdbcTemplate(pool);agent="upgrade-"+UUID.randomUUID();
        jdbc.update("INSERT INTO t_agent(agent_id,hostname,os_type,arch,status) VALUES(?,?,1,'amd64',1)",agent,agent);
        pkg=jdbc.queryForObject("INSERT INTO t_agent_upgrade_package(version,platform,package_key,sha256,size) VALUES(?,'linux-amd64',?, ?,1) RETURNING id",Long.class,agent,agent+".bin","a".repeat(64));
    }
    @AfterEach void close() { if(jdbc!=null) { jdbc.update("DELETE FROM t_agent_upgrade_package WHERE id=?",pkg);jdbc.update("DELETE FROM t_agent WHERE agent_id=?",agent); } if(pool!=null) pool.close(); }
    @Test void upgradeRequiresCurrentDeclaredCapabilityAndRechecksOfflineDelivery() {
        var commands=mock(CommandService.class);var props=new AlinkSecProperties();
        var tokens=mock(AgentDownloadTokenService.class);
        var service=new UpgradeService(jdbc,commands,props,tokens);
        assertEquals(0,jdbc.queryForObject("SELECT upgrade_contract FROM t_agent WHERE agent_id=?",Integer.class,agent));
        assertThrows(IllegalArgumentException.class,()->service.dispatch(pkg,List.of(agent),null));
        jdbc.update("UPDATE t_agent SET upgrade_contract=1 WHERE agent_id=?",agent);
        assertEquals(1,service.dispatch(pkg,List.of(agent),null).get("dispatched"));
        var capture=org.mockito.ArgumentCaptor.forClass(Command.Builder.class);
        verify(commands).dispatch(eq(agent),capture.capture(),isNull());
        Command command=capture.getValue().build();assertEquals(1,command.getAgentUpgrade().getExecutionContract());
        var lifecycle=new UpgradeCommandLifecycle(jdbc);assertSame(command,lifecycle.prepareDelivery(agent,command));
        jdbc.update("UPDATE t_agent SET upgrade_contract=0 WHERE agent_id=?",agent);
        assertThrows(IllegalArgumentException.class,()->lifecycle.prepareDelivery(agent,command));
        jdbc.update("UPDATE t_agent SET upgrade_contract=1 WHERE agent_id=?",agent);
        Command legacy=command.toBuilder().setAgentUpgrade(command.getAgentUpgrade().toBuilder().clearExecutionContract()).build();
        assertThrows(IllegalArgumentException.class,()->lifecycle.prepareDelivery(agent,legacy));
        jdbc.update("UPDATE t_agent SET deleted=true WHERE agent_id=?",agent);
        assertThrows(IllegalArgumentException.class,()->lifecycle.prepareDelivery(agent,command));
    }
}
