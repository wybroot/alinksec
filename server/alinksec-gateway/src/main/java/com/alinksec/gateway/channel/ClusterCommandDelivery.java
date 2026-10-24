package com.alinksec.gateway.channel;

import com.alinksec.service.command.CommandService;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/** SQL pending rows survive a REST request landing on another replica or a lost routing hint. */
@Component
public class ClusterCommandDelivery {
    private final ConnectionRegistry registry;
    private final CommandService commands;
    private int cursor;
    public ClusterCommandDelivery(ConnectionRegistry registry,CommandService commands) {
        this.registry=registry;this.commands=commands;
    }
    @Scheduled(fixedDelay=250,initialDelay=5000,scheduler="clusterScheduler")
    public void deliver() {
        if(!registry.deferredDelivery()) return;
        var agents=registry.localAgentIds();
        if(agents.isEmpty()) return;
        int count=Math.min(256,agents.size());
        var batch=new java.util.ArrayList<String>(count);
        for(int i=0;i<count;i++) {
            batch.add(agents.get(Math.floorMod(cursor++,agents.size())));
        }
        // Empty streams require one batch query rather than one query per Agent.
        // deliverPending still checks the current identity and command row state.
        for(String agent:commands.pendingAgents(batch)) {
            try { commands.deliverPending(agent); }
            catch(RuntimeException failure) { /* Pending facts remain durable for the next bounded pass. */ }
        }
    }
}
