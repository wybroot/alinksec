package com.alinksec.service.cluster;

import io.lettuce.core.ClientOptions;
import io.lettuce.core.RedisClient;
import io.lettuce.core.RedisURI;
import io.lettuce.core.ScriptOutputType;
import io.lettuce.core.SetArgs;
import io.lettuce.core.api.StatefulRedisConnection;
import io.lettuce.core.resource.DefaultClientResources;
import jakarta.annotation.PreDestroy;
import org.springframework.stereotype.Component;

import java.time.Duration;

/** A lost lease is never renewed or deleted by an older stream. SQL fencing serializes claims. */
@Component
public class RedisLeases {
    private static final String RENEW = "if redis.call('GET',KEYS[1])==ARGV[1] then return redis.call('PEXPIRE',KEYS[1],ARGV[2]) else return 0 end";
    private static final String RELEASE = "if redis.call('GET',KEYS[1])==ARGV[1] then return redis.call('DEL',KEYS[1]) else return 0 end";
    private final ClusterProperties properties;
    private DefaultClientResources resources;
    private RedisClient client;
    private StatefulRedisConnection<String, String> connection;

    public RedisLeases(ClusterProperties properties) { this.properties = properties; }

    private synchronized StatefulRedisConnection<String, String> connection() {
        if (!properties.isEnabled()) throw new IllegalStateException("cluster_disabled");
        try {
            if (client == null) {
                resources = DefaultClientResources.builder().ioThreadPoolSize(2).computationThreadPoolSize(2).build();
                RedisURI uri = RedisURI.create(properties.getRedisUri());
                uri.setTimeout(Duration.ofSeconds(2));
                client = RedisClient.create(resources, uri);
                client.setOptions(ClientOptions.builder().autoReconnect(true)
                        .disconnectedBehavior(ClientOptions.DisconnectedBehavior.REJECT_COMMANDS).build());
            }
            if (connection == null || !connection.isOpen()) connection = client.connect();
            return connection;
        } catch (RuntimeException failure) { throw new ClusterUnavailable("redis_unavailable"); }
    }

    private String key(String agent) { return "alinksec:" + properties.getDeploymentId() + ":agent:" + agent; }

    public void claim(String agent, String token) {
        try {
            if (!"OK".equals(connection().sync().set(key(agent), token, SetArgs.Builder.px(properties.getLeaseMs()))))
                throw new ClusterUnavailable("redis_claim_rejected");
        } catch (RuntimeException failure) { throw new ClusterUnavailable("redis_unavailable"); }
    }

    public boolean current(String agent, String token) {
        try { return token.equals(connection().sync().get(key(agent))); }
        catch (RuntimeException failure) { throw new ClusterUnavailable("redis_unavailable"); }
    }

    public boolean renew(String agent, String token) {
        try {
            Long result = connection().sync().eval(RENEW, ScriptOutputType.INTEGER,
                    new String[]{key(agent)}, token, Long.toString(properties.getLeaseMs()));
            return Long.valueOf(1).equals(result);
        } catch (RuntimeException failure) { throw new ClusterUnavailable("redis_unavailable"); }
    }

    public void release(String agent, String token) {
        try { connection().sync().eval(RELEASE, ScriptOutputType.INTEGER, new String[]{key(agent)}, token); }
        catch (RuntimeException failure) { throw new ClusterUnavailable("redis_unavailable"); }
    }

    public boolean loginLimit(String hash,String action) {
        try {
            String prefix="alinksec:"+properties.getDeploymentId()+":login:";
            Long result=connection().sync().eval(ClusterLoginLimiter.SCRIPT,ScriptOutputType.INTEGER,
                    new String[]{prefix+"clients",prefix+hash},hash,action);
            return Long.valueOf(1).equals(result);
        } catch(RuntimeException failure) {throw new ClusterUnavailable("login_coordination_unavailable");}
    }

    public void requireConfiguration(String fingerprint) {
        try {
            String key="alinksec:"+properties.getDeploymentId()+":configuration";
            connection().sync().set(key,fingerprint,SetArgs.Builder.nx());
            if(!fingerprint.equals(connection().sync().get(key)))throw new ClusterUnavailable("cluster_redis_configuration_mismatch");
        } catch(ClusterUnavailable failure) {throw failure;}
        catch(RuntimeException failure) {throw new ClusterUnavailable("redis_unavailable");}
    }

    public boolean healthy() {
        try { return "PONG".equals(connection().sync().ping()); }
        catch (RuntimeException failure) { return false; }
    }

    @PreDestroy
    public synchronized void close() {
        if (connection != null) connection.close();
        if (client != null) client.shutdown(Duration.ZERO, Duration.ofSeconds(2));
        if (resources != null) resources.shutdown(0, 2, java.util.concurrent.TimeUnit.SECONDS);
    }
}
