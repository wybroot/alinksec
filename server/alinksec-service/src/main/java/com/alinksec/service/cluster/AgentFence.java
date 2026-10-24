package com.alinksec.service.cluster;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.SingleConnectionDataSource;
import org.springframework.stereotype.Component;

import javax.sql.DataSource;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.Connection;
import java.util.function.Supplier;

/**
 * One PostgreSQL lock orders stream replacement, dispatch and the committed current-stream receipt.
 * Its connection is separate from business transactions so receipts follow their commits.
 */
@Component
public class AgentFence {
    private record Held(String agent, Connection connection, JdbcTemplate jdbc) {}
    private final ThreadLocal<Held> held = new ThreadLocal<>();
    private final ClusterProperties properties;
    private final DataSource dataSource;

    public AgentFence(ClusterProperties properties, DataSource dataSource) {
        this.properties = properties;
        this.dataSource = dataSource;
    }

    public <T> T with(String agent, Supplier<T> action) {
        if (!properties.isEnabled()) return action.get();
        if (agent == null || !agent.matches("[A-Za-z0-9_-]{1,64}"))
            throw new IllegalArgumentException("invalid_agent_fence_identity");
        Held current = held.get();
        if (current != null) {
            if (!current.agent().equals(agent)) throw new ClusterUnavailable("cross_agent_nested_fence");
            assertAlive();
            return action.get();
        }
        try (Connection connection = dataSource.getConnection()) {
            connection.setNetworkTimeout(Runnable::run, 3000);
            connection.setAutoCommit(false);
            boolean committed = false;
            try {
                try (var query = connection.prepareStatement("SELECT pg_try_advisory_xact_lock(?)")) {
                    query.setQueryTimeout(2);
                    query.setLong(1, key(agent));
                    try (var result = query.executeQuery()) {
                        if (!result.next() || !result.getBoolean(1)) throw new ClusterUnavailable("agent_fence_busy");
                    }
                }
                var jdbc = new JdbcTemplate(new SingleConnectionDataSource(connection, true));
                jdbc.setQueryTimeout(2);
                held.set(new Held(agent, connection, jdbc));
                T value = action.get();
                connection.commit();
                committed = true;
                return value;
            } finally {
                held.remove();
                if (!committed) {
                    try { connection.rollback(); }
                    catch (java.sql.SQLException failure) { connection.abort(Runnable::run); }
                }
            }
        } catch (java.sql.SQLException failure) {
            throw new ClusterUnavailable("agent_fence_database_unavailable");
        }
    }

    public void with(String agent, Runnable action) { with(agent, () -> { action.run(); return null; }); }

    JdbcTemplate jdbc() {
        Held current = held.get();
        if (current == null) throw new IllegalStateException("agent_fence_not_held");
        return current.jdbc();
    }

    public void assertAlive() {
        try {
            if (properties.isEnabled() && !Integer.valueOf(1).equals(jdbc().queryForObject("SELECT 1", Integer.class)))
                throw new ClusterUnavailable("agent_fence_database_unavailable");
        } catch(org.springframework.dao.DataAccessException failure) {throw new ClusterUnavailable("agent_fence_database_unavailable");}
    }

    private long key(String agent) {
        try {
            return ByteBuffer.wrap(MessageDigest.getInstance("SHA-256")
                    .digest((properties.getDeploymentId() + "\0agent\0" + agent).getBytes(StandardCharsets.UTF_8))).getLong();
        } catch (java.security.NoSuchAlgorithmException failure) { throw new IllegalStateException(failure); }
    }
}
