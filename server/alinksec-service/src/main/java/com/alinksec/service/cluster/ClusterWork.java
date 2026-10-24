package com.alinksec.service.cluster;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;

/** Long library downloads do not hold a SQL connection; each publication checks the renewable token. */
@Component
public class ClusterWork {
    private static final String NAME="library-sync";
    private static final ThreadLocal<Owner> CURRENT=new ThreadLocal<>();
    private static final class Owner {
        final ClusterWork work;final String token=UUID.randomUUID().toString();
        volatile boolean lost;
        Owner(ClusterWork work) { this.work=work; }
    }
    private final ClusterProperties properties;
    private final ClusterRuntime runtime;
    private final JdbcTemplate jdbc;
    private final TransactionTemplate transaction;
    private final ConcurrentHashMap<String,Owner> active=new ConcurrentHashMap<>();
    public ClusterWork(ClusterProperties properties,ClusterRuntime runtime,JdbcTemplate jdbc,PlatformTransactionManager manager) {
        this.properties=properties;this.runtime=runtime;this.jdbc=jdbc;
        transaction=new TransactionTemplate(manager);transaction.setTimeout(10);
    }
    public boolean enabled() { return properties.isEnabled(); }
    private static void authority(JdbcTemplate jdbc) {
        if(jdbc.update("UPDATE t_vuln_rule_state SET revision=revision WHERE id=1")!=1)
            throw new ClusterUnavailable("library_authority_missing");
    }

    public <T> T library(Supplier<T> action,T busy) {
        if(!enabled()) return action.get();
        if(CURRENT.get()!=null) return action.get();
        Owner owner=claim();
        if(owner==null)return busy;
        return owned(owner,action);
    }
    private Owner claim() {
        Owner owner=new Owner(this);
        Boolean claimed=transaction.execute(status->{
            authority(jdbc);runtime.requireActive(jdbc);
            jdbc.update("INSERT INTO t_cluster_work(name) VALUES(?) ON CONFLICT(name) DO NOTHING",NAME);
            long now=ClusterRuntime.databaseTime(jdbc);
            return jdbc.update("""
                    UPDATE t_cluster_work SET token=?,node_id=?,lease_until=?,generation=generation+1
                    WHERE name=? AND lease_until<=?
                    """,owner.token,properties.getNodeId(),now+properties.getLeaseMs(),NAME,now)==1;
        });
        if(!Boolean.TRUE.equals(claimed))return null;
        active.put(owner.token,owner);return owner;
    }
    public boolean enqueueLibrary(java.util.concurrent.Executor executor,Runnable action) {
        if(!enabled()) {executor.execute(action);return true;}
        Owner owner=claim();
        if(owner==null)return false;
        try {executor.execute(()->owned(owner,()->{action.run();return null;}));return true;}
        catch(RuntimeException failure) {release(owner);throw failure;}
    }
    private <T> T owned(Owner owner,Supplier<T> action) {
        CURRENT.set(owner);
        try { return action.get(); }
        finally {
            CURRENT.remove();release(owner);
        }
    }
    private void release(Owner owner) {
            active.remove(owner.token);
            try { transaction.executeWithoutResult(status->{
                authority(jdbc);
                jdbc.update("UPDATE t_cluster_work SET lease_until=0 WHERE name=? AND token=?",NAME,owner.token);
            }); } catch(RuntimeException ignored) { /* Expiry and token fencing recover an interrupted worker. */ }
    }

    public void library(Runnable action) { library(()->{action.run();return true;},false); }

    /** Invoke after the same authority row is locked, inside the publishing transaction. */
    public static void assertLibraryOwner(JdbcTemplate jdbc) {
        Owner owner=CURRENT.get();
        if(owner==null) return;
        if(owner.lost) throw new ClusterUnavailable("library_worker_lease_lost");
        owner.work.runtime.requireActive(jdbc);
        Long count=jdbc.queryForObject("""
                SELECT COUNT(*) FROM t_cluster_work WHERE name=? AND token=?
                  AND lease_until>(EXTRACT(EPOCH FROM clock_timestamp())*1000)::BIGINT
                """,Long.class,NAME,owner.token);
        if(count==null || count!=1) { owner.lost=true;throw new ClusterUnavailable("library_worker_lease_lost"); }
    }

    public static <T> T write(JdbcTemplate jdbc,Supplier<T> action) {
        Owner owner=CURRENT.get();
        if(owner==null) return action.get();
        return owner.work.transaction.execute(status->{authority(jdbc);assertLibraryOwner(jdbc);return action.get();});
    }
    public static int update(JdbcTemplate jdbc,String sql,Object... arguments) {
        return write(jdbc,()->jdbc.update(sql,arguments));
    }

    @Scheduled(fixedDelay=5000,initialDelay=5000,scheduler="clusterScheduler")
    public void renew() {
        if(!enabled()) return;
        for(Owner owner:active.values()) {
            if(owner.lost) continue;
            try { transaction.executeWithoutResult(status->{
                authority(jdbc);runtime.requireActive(jdbc);
                long now=ClusterRuntime.databaseTime(jdbc);
                if(jdbc.update("UPDATE t_cluster_work SET lease_until=? WHERE name=? AND token=? AND lease_until>?",
                        now+properties.getLeaseMs(),NAME,owner.token,now)!=1) throw new ClusterUnavailable("library_worker_lease_lost");
            }); } catch(RuntimeException failure) { owner.lost=true; }
        }
    }
}
