package com.alinksec.service.protect;

import com.alinksec.common.util.JsonUtils;
import com.alinksec.proto.Command;
import com.alinksec.service.command.CommandLifecycleListener;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

/** Offline replay cannot reinstate an obsolete whitelist or detection switch. */
@Component
public class PolicyCommandGuard implements CommandLifecycleListener {
    private final JdbcTemplate jdbc;
    public PolicyCommandGuard(JdbcTemplate jdbc) { this.jdbc=jdbc; }
    @Override public Command prepareDelivery(String agent,Command command) {
        if(!command.hasPolicySync()) return command;
        jdbc.update("UPDATE t_policy_state SET version=version WHERE id=1");
        var rows=jdbc.queryForList("SELECT version,CAST(content AS TEXT) AS content FROM t_policy_state WHERE id=1");
        var sync=command.getPolicySync();
        if(rows.size()!=1 || !sync.getPolicyVersion().equals("v"+rows.get(0).get("version")) || sync.getPolicyJson().isBlank()
                || !JsonUtils.read(sync.getPolicyJson()).equals(JsonUtils.read((String)rows.get(0).get("content"))))
            throw new IllegalArgumentException("策略快照已被替代，不派发旧白名单或旧防护开关");
        return command;
    }
}
