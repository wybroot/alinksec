package com.alinksec.service.upgrade;

import com.alinksec.proto.Command;
import com.alinksec.service.command.CommandLifecycleListener;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

/** Recheck capability when an offline/retried upgrade actually reaches a host. */
@Component
public class UpgradeCommandLifecycle implements CommandLifecycleListener {
    private final JdbcTemplate jdbc;
    public UpgradeCommandLifecycle(JdbcTemplate jdbc) { this.jdbc=jdbc; }
    @Override public Command prepareDelivery(String agent,Command command) {
        if (!command.hasAgentUpgrade()) return command;
        Integer count=jdbc.queryForObject("SELECT count(*) FROM t_agent WHERE agent_id=? AND deleted=false AND status<>4 AND upgrade_contract=1",Integer.class,agent);
        if (command.getAgentUpgrade().getExecutionContract()!=1 || count==null || count!=1)
            throw new IllegalArgumentException("Agent原生升级看护契约失效；旧升级指令需要重新创建");
        return command;
    }
}
