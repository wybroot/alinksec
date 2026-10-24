package com.alinksec.service.cluster;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

/** Slot admission and all resulting durable commands commit in the same transaction. */
@Component
public class ClusterSlots {
    private final ClusterProperties properties;
    private final ClusterRuntime runtime;
    private final JdbcTemplate jdbc;
    private final TransactionTemplate transaction;
    public ClusterSlots(ClusterProperties properties,ClusterRuntime runtime,JdbcTemplate jdbc,PlatformTransactionManager manager) {
        this.properties=properties;this.runtime=runtime;this.jdbc=jdbc;transaction=new TransactionTemplate(manager);
    }
    private long clock() {return properties.isEnabled()?ClusterRuntime.databaseTime(jdbc):System.currentTimeMillis();}
    public String weeklySlot() {
        return java.time.Instant.ofEpochMilli(clock()).atZone(java.time.ZoneId.of("Asia/Shanghai")).toLocalDate()
                .with(java.time.DayOfWeek.MONDAY).toString();
    }
    public String intervalSlot(long interval) {return Long.toString(clock()/Math.max(60_000,interval));}
    public void once(String name,String slot,Runnable action) {
        if(!properties.isEnabled()) { action.run();return; }
        transaction.executeWithoutResult(status->{
            runtime.requireActive(jdbc);
            long now=ClusterRuntime.databaseTime(jdbc);
            if(jdbc.update("INSERT INTO t_cluster_job_slot(name,slot,completed_at) VALUES(?,?,?) ON CONFLICT(name,slot) DO NOTHING",name,slot,now)==0) return;
            action.run();
            jdbc.update("DELETE FROM t_cluster_job_slot WHERE name=? AND completed_at<?",name,now-366L*86_400_000);
        });
    }
}
