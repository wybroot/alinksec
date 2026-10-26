package com.alinksec.service.cluster;

import com.alinksec.common.util.JsonUtils;
import com.alinksec.service.baseline.BaselineUpstreamProperties;
import com.alinksec.service.cert.CertService;
import com.alinksec.service.config.AlinkSecProperties;
import com.alinksec.service.library.LibraryProperties;
import com.zaxxer.hikari.HikariDataSource;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import org.springframework.core.env.Environment;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import javax.sql.DataSource;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

/** A process incarnation must own both a SQL lease and the same shared material as its peers. */
@Component
public class ClusterRuntime {
    private final ClusterProperties properties;
    private final JdbcTemplate jdbc;
    private final TransactionTemplate transaction;
    private final DataSource dataSource;
    private final AlinkSecProperties app;
    private final LibraryProperties libraries;
    private final BaselineUpstreamProperties upstream;
    private final Environment environment;
    private final RedisLeases redis;
    private final RabbitTransport rabbit;
    private final String incarnation=UUID.randomUUID().toString();
    private final String probe=UUID.randomUUID().toString().replace("-","")+UUID.randomUUID().toString().replace("-","");
    private volatile boolean ready,replaced,claimed;
    private volatile String issue="initializing";
    private volatile long checkedNanos;
    private String configuration="";
    private Path root,probeFile;

    public ClusterRuntime(ClusterProperties properties,JdbcTemplate jdbc,PlatformTransactionManager manager,
                          DataSource dataSource,CertService certificates,AlinkSecProperties app,
                          LibraryProperties libraries,BaselineUpstreamProperties upstream,Environment environment,
                          RedisLeases redis,RabbitTransport rabbit) {
        this.properties=properties;this.jdbc=jdbc;this.transaction=new TransactionTemplate(manager);
        this.dataSource=dataSource;this.app=app;this.libraries=libraries;this.upstream=upstream;
        this.environment=environment;this.redis=redis;this.rabbit=rabbit;
        transaction.setTimeout(5);
    }

    @PostConstruct
    public void initialize() {
        if(!properties.isEnabled()) {
            String pinned=jdbc.queryForObject("SELECT deployment_id FROM t_cluster_state WHERE id=1",String.class);
            if(pinned!=null && !pinned.isEmpty())throw new ClusterUnavailable("cluster_database_requires_cluster_mode");
            ready=true;issue="";return;
        }
        try {
            root=ClusterFiles.root(properties.getSharedDir(),properties.getDeploymentId());
            for(String directory:List.of(app.getServer().getCertDir(),app.getServer().getWebTlsDir(),
                    app.getSignature().getStorageDir(),app.getPatch().getStorageDir(),app.getUpgrade().getStorageDir(),libraries.getWorkDir()))
                ClusterFiles.directory(root,directory);
            if(!(dataSource instanceof HikariDataSource pool) || pool.getMaximumPoolSize()<4)
                throw new ClusterUnavailable("cluster_connection_pool_too_small");
            var role=jdbc.queryForMap("SELECT rolsuper,rolcreatedb,rolcreaterole FROM pg_roles WHERE rolname=current_user");
            if(role.values().stream().anyMatch(Boolean.TRUE::equals)) throw new ClusterUnavailable("cluster_requires_restricted_database_role");
            configuration=fingerprint();
            if(!redis.healthy()) throw new ClusterUnavailable("redis_unavailable");
            if(!rabbit.healthy()) throw new ClusterUnavailable("rabbit_unavailable");
            Path probes=ClusterFiles.directory(root,root.resolve(".cluster-probes").toString());
            probeFile=probes.resolve(properties.getNodeId());
            transaction.executeWithoutResult(status->{
                var state=jdbc.queryForMap("SELECT * FROM t_cluster_state WHERE id=1 FOR UPDATE");
                if(!state.get("deployment_id").equals("") && (!state.get("deployment_id").equals(properties.getDeploymentId())
                        || !state.get("configuration_sha256").equals(configuration))) throw new ClusterUnavailable("cluster_configuration_mismatch");
                jdbc.update("UPDATE t_cluster_state SET deployment_id=?,configuration_sha256=? WHERE id=1",properties.getDeploymentId(),configuration);
            });
            redis.requireConfiguration(configuration);
            transaction.executeWithoutResult(status->{
                // Membership never holds the inbox/state row while waiting for a node's in-flight readers.
                jdbc.queryForObject("SELECT pg_advisory_xact_lock(7287105346218)",Object.class);
                long now=databaseTime(jdbc);
                var previous=jdbc.queryForList("SELECT lease_until FROM t_cluster_node WHERE node_id=?",Long.class,properties.getNodeId());
                if(!previous.isEmpty() && previous.get(0)>now) throw new ClusterUnavailable("cluster_node_id_in_use");
                if(jdbc.queryForObject("SELECT COUNT(*) FROM t_cluster_node WHERE lease_until>?",Long.class,now)>=16)
                    throw new ClusterUnavailable("cluster_node_capacity");
                jdbc.update("DELETE FROM t_cluster_node WHERE lease_until<? AND node_id<>?",now-86_400_000,properties.getNodeId());
                if(previous.isEmpty() && jdbc.queryForObject("SELECT COUNT(*) FROM t_cluster_node",Long.class)>=128)
                    throw new ClusterUnavailable("cluster_node_history_capacity");
                try { ClusterFiles.privateAtomicWrite(probeFile,probe); }
                catch(java.io.IOException failure) { throw new ClusterUnavailable("cluster_shared_probe_unwritable"); }
                jdbc.update("""
                        INSERT INTO t_cluster_node(node_id,incarnation,configuration_sha256,probe_token,lease_until,started_at)
                        VALUES(?,?,?,?,?,?) ON CONFLICT(node_id) DO UPDATE SET incarnation=EXCLUDED.incarnation,
                        configuration_sha256=EXCLUDED.configuration_sha256,probe_token=EXCLUDED.probe_token,
                        lease_until=EXCLUDED.lease_until,started_at=EXCLUDED.started_at
                        """,properties.getNodeId(),incarnation,configuration,probe,now+properties.getLeaseMs(),now);
                verifyProbes(now);
            });
            claimed=true;ready=true;issue="";checkedNanos=System.nanoTime();
        } catch(ClusterUnavailable failure) { issue=failure.getMessage();throw failure; }
        catch(RuntimeException failure) { throw new ClusterUnavailable("cluster_initialization_failed"); }
    }

    private String fingerprint() {
        try {
            var digest=MessageDigest.getInstance("SHA-256");
            Map<String,Object> values=new TreeMap<>();
            values.put("compatibility","alinksec-0.0.4-schema37-cluster1");
            values.put("deployment",properties.getDeploymentId());
            values.put("shared",root.toString());
            values.put("publicHost",app.getServer().getPublicHost());
            values.put("sans",new TreeSet<>(app.getServer().getTlsSans()));
            values.put("agentCertDays",app.getServer().getAgentCertDays());
            values.put("signature",app.getSignature());values.put("patch",app.getPatch());values.put("upgrade",app.getUpgrade());
            values.put("metrics",app.getMetrics());values.put("libraries",libraries);values.put("baselineUpstream",upstream);
            values.put("redis",properties.getRedisUri());values.put("rabbit",properties.getRabbitUri());
            values.put("databaseUrl",environment.getProperty("spring.datasource.url",""));
            values.put("databaseUser",environment.getProperty("spring.datasource.username",""));
            values.put("signaturePushInterval",environment.getProperty("alinksec.signature.push-interval-ms","3600000"));
            values.put("weeklyScanCron",environment.getProperty("alinksec.virus.weekly-scan-cron","0 30 2 * * MON"));
            values.put("limits",List.of(properties.getLeaseMs(),properties.getMaxPendingReports(),properties.getMaxPendingBytes(),
                    properties.getMaxReportBytes(),properties.getMaxHistoryReports(),properties.getDedupRetentionMs()));
            digest.update(JsonUtils.write(values).getBytes(StandardCharsets.UTF_8));
            Path certs=Path.of(app.getServer().getCertDir());
            for(String name:List.of("ca.crt","ca.key","server.crt","server.key")) {
                Path file=certs.resolve(name);
                if(!Files.isRegularFile(file,LinkOption.NOFOLLOW_LINKS) || Files.size(file)>65_536) throw new IllegalStateException();
                if(name.endsWith(".key"))requirePrivate(file);
                digest.update(name.getBytes(StandardCharsets.UTF_8));digest.update(Files.readAllBytes(file));
            }
            Path web=Path.of(app.getServer().getWebTlsDir());requirePrivate(web.resolve("server.key"));
            for(String name:List.of("server.crt","server.key"))
                if(Files.mismatch(certs.resolve(name),web.resolve(name))!=-1)throw new IllegalStateException();
            String jwt=environment.getProperty("ALINKSEC_JWT_SECRET","");
            if(jwt.isBlank()) {
                Path file=certs.getParent().resolve("jwt.secret");
                if(!Files.isRegularFile(file,LinkOption.NOFOLLOW_LINKS) || Files.size(file)>4096) throw new IllegalStateException();
                requirePrivate(file);jwt=Files.readString(file).strip();
            }
            if(jwt.length()<32 || jwt.length()>4096) throw new IllegalStateException();
            digest.update(jwt.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest.digest());
        } catch(Exception failure) { throw new ClusterUnavailable("cluster_material_invalid"); }
    }

    private static void requirePrivate(Path file)throws java.io.IOException {
        var permissions=Files.getPosixFilePermissions(file,LinkOption.NOFOLLOW_LINKS);
        for(var permission:permissions)if(!java.util.Set.of(java.nio.file.attribute.PosixFilePermission.OWNER_READ,
                java.nio.file.attribute.PosixFilePermission.OWNER_WRITE).contains(permission))throw new java.io.IOException();
    }
    private void verifyProbes(long now) {
        for(var node:jdbc.queryForList("SELECT node_id,probe_token,configuration_sha256 FROM t_cluster_node WHERE lease_until>?",now)) {
            if(!configuration.equals(node.get("configuration_sha256"))) throw new ClusterUnavailable("cluster_configuration_mismatch");
            try {
                Path file=root.resolve(".cluster-probes").resolve(node.get("node_id").toString());
                if(!Files.isRegularFile(file,LinkOption.NOFOLLOW_LINKS) || Files.size(file)!=64
                        || !Files.readString(file).equals(node.get("probe_token"))) throw new IllegalStateException();
            } catch(Exception failure) { throw new ClusterUnavailable("cluster_shared_storage_mismatch"); }
        }
    }

    @Scheduled(fixedDelay=5000,initialDelay=5000,scheduler="clusterScheduler")
    public void heartbeat() {
        if(!properties.isEnabled() || !claimed || replaced) return;
        try {
            if(!fingerprint().equals(configuration)) throw new ClusterUnavailable("cluster_material_changed");
            transaction.executeWithoutResult(status->{
                long now=databaseTime(jdbc);
                if(jdbc.update("UPDATE t_cluster_node SET lease_until=? WHERE node_id=? AND incarnation=?",now+properties.getLeaseMs(),properties.getNodeId(),incarnation)!=1) {
                    replaced=true;throw new ClusterUnavailable("cluster_node_replaced");
                }
                verifyProbes(now);
            });
            if(!redis.healthy()) throw new ClusterUnavailable("redis_unavailable");
            redis.requireConfiguration(configuration);
            if(!rabbit.healthy()) throw new ClusterUnavailable("rabbit_unavailable");
            checkedNanos=System.nanoTime();issue="";ready=true;
        } catch(ClusterUnavailable failure) { ready=false;issue=failure.getMessage(); }
        catch(RuntimeException failure) { ready=false;issue="postgres_unavailable"; }
    }

    public boolean ready() { return !properties.isEnabled() || ready && System.nanoTime()-checkedNanos<15_000_000_000L; }

    public void requireActive(JdbcTemplate sql) {
        if(!properties.isEnabled()) return;
        if(!ready()) throw new ClusterUnavailable(issue.isEmpty()?"cluster_readiness_expired":issue);
        try {
        var nodes=sql.queryForList("""
                SELECT node_id FROM t_cluster_node WHERE node_id=? AND incarnation=? AND configuration_sha256=?
                  AND lease_until>(EXTRACT(EPOCH FROM clock_timestamp())*1000)::BIGINT FOR SHARE
                """,String.class,properties.getNodeId(),incarnation,configuration);
        if(nodes.size()!=1) throw new ClusterUnavailable("cluster_node_replaced_or_expired");
        } catch(org.springframework.dao.DataAccessException failure) {throw new ClusterUnavailable("agent_fence_database_unavailable");}
    }

    public Map<String,Object> status() {
        if(!properties.isEnabled()) return Map.of("mode","single","ready",true);
        return Map.of("mode","cluster","ready",ready(),"issue",issue,"nodeId",properties.getNodeId(),
                "deploymentId",properties.getDeploymentId(),"configurationSha256",configuration);
    }
    public static long databaseTime(JdbcTemplate jdbc) {
        return jdbc.queryForObject("SELECT (EXTRACT(EPOCH FROM clock_timestamp())*1000)::BIGINT",Long.class);
    }

    @PreDestroy public void close() {
        ready=false;
        if(!claimed) return;
        try { transaction.executeWithoutResult(status->{
            jdbc.update("UPDATE t_cluster_node SET lease_until=0 WHERE node_id=? AND incarnation=?",properties.getNodeId(),incarnation);
        }); } catch(RuntimeException ignored) { /* The database lease expires without successful shutdown. */ }
    }
}
