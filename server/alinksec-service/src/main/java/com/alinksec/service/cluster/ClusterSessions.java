package com.alinksec.service.cluster;

import org.springframework.stereotype.Service;
import java.util.UUID;
import java.util.function.Supplier;

/** SQL stores the connection generation; Redis advertises only its expiring routing lease. */
@Service
public class ClusterSessions {
    private final ClusterProperties properties;
    private final AgentFence fence;
    private final RedisLeases redis;
    private final ClusterRuntime runtime;
    public ClusterSessions(ClusterProperties properties, AgentFence fence, RedisLeases redis,ClusterRuntime runtime) {
        this.properties = properties; this.fence = fence; this.redis = redis;this.runtime=runtime;
    }
    public boolean enabled() { return properties.isEnabled(); }
    public boolean ready() { return runtime.ready(); }
    public boolean healthy() { return runtime.ready() && redis.healthy(); }
    public String claim(String agent) {
        if (!enabled()) return "";
        return fence.with(agent, () -> {
            runtime.requireActive(fence.jdbc());
            String token = UUID.randomUUID().toString();
            redis.claim(agent, token);
            try { fence.jdbc().update("""
                    INSERT INTO t_cluster_session(agent_id,node_id,token,generation,updated_at)
                    VALUES(?,?,?,1,CURRENT_TIMESTAMP)
                    ON CONFLICT(agent_id) DO UPDATE SET node_id=EXCLUDED.node_id,token=EXCLUDED.token,
                      generation=t_cluster_session.generation+1,updated_at=CURRENT_TIMESTAMP
                    """, agent, properties.getNodeId(), token);
            } catch(org.springframework.dao.DataAccessException failure) { throw new ClusterUnavailable("agent_fence_database_unavailable"); }
            return token;
        });
    }
    private void requireCurrent(String agent, String token) {
        runtime.requireActive(fence.jdbc());
        try {
            var tokens = fence.jdbc().queryForList("SELECT token FROM t_cluster_session WHERE agent_id=?", String.class, agent);
            if (tokens.size() != 1 || !tokens.get(0).equals(token) || !redis.current(agent, token))
                throw new ClusterUnavailable("agent_session_replaced_or_expired");
            fence.assertAlive();
        } catch(org.springframework.dao.DataAccessException failure) { throw new ClusterUnavailable("agent_fence_database_unavailable"); }
    }
    public <T> T current(String agent, String token, Supplier<T> action) {
        if (!enabled()) return action.get();
        return fence.with(agent, () -> { requireCurrent(agent, token); return action.get(); });
    }
    public void current(String agent, String token, Runnable action) {
        current(agent, token, () -> { action.run(); return null; });
    }
    public boolean renew(String agent, String token) {
        if (!enabled()) return true;
        return fence.with(agent, () -> {
            requireCurrent(agent, token);
            if (!redis.renew(agent, token)) return false;
            try { fence.jdbc().update("UPDATE t_cluster_session SET updated_at=CURRENT_TIMESTAMP WHERE agent_id=? AND token=?", agent, token); }
            catch(org.springframework.dao.DataAccessException failure) { throw new ClusterUnavailable("agent_fence_database_unavailable"); }
            return true;
        });
    }
    public void release(String agent, String token) {
        if (!enabled()) return;
        fence.with(agent, () -> {
            redis.release(agent, token);
            fence.jdbc().update("DELETE FROM t_cluster_session WHERE agent_id=? AND token=?", agent, token);
        });
    }
}
