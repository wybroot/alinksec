package com.alinksec.service.agent;

import com.alinksec.service.config.DatabaseDialect;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

import java.sql.Timestamp;
import java.time.OffsetDateTime;
import java.time.Duration;
import java.util.List;
import java.util.Optional;

/**
 * t_agent 访问层。
 */
@Repository
public class AgentRepository {

    private final JdbcTemplate jdbc;
    private final DatabaseDialect database;

    public AgentRepository(JdbcTemplate jdbc, DatabaseDialect database) {
        this.jdbc = jdbc;
        this.database = database;
    }

    private static final RowMapper<AgentEntity> MAPPER = (rs, i) -> new AgentEntity(
            rs.getLong("id"),
            rs.getString("agent_id"),
            rs.getString("hostname"),
            rs.getString("ip"),
            rs.getShort("os_type"),
            rs.getString("os_version"),
            rs.getString("kernel"),
            rs.getString("arch"),
            rs.getString("agent_version"),
            rs.getString("machine_id"),
            (Long) rs.getObject("group_id"),
            rs.getShort("status"),
            rs.getBoolean("protect_enabled"),
            rs.getString("policy_version"),
            rs.getString("cert_serial"),
            toOdt(rs.getTimestamp("last_heartbeat")),
            toOdt(rs.getTimestamp("created_at")),
            toOdt(rs.getTimestamp("updated_at")));

    private static OffsetDateTime toOdt(Timestamp ts) {
        return ts == null ? null : ts.toInstant().atOffset(OffsetDateTime.now().getOffset());
    }

    public Optional<AgentEntity> findByAgentId(String agentId) {
        List<AgentEntity> list = jdbc.query(
                "SELECT * FROM t_agent WHERE agent_id = ?", MAPPER, agentId);
        return list.stream().findFirst();
    }

    public Optional<AgentEntity> findByMachineId(String machineId) {
        List<AgentEntity> list = jdbc.query(
                "SELECT * FROM t_agent WHERE machine_id = ?", MAPPER, machineId);
        return list.stream().findFirst();
    }

    public void insert(AgentEntity a) {
        jdbc.update("""
                INSERT INTO t_agent (agent_id, hostname, ip, os_type, os_version, kernel, arch,
                                     agent_version, machine_id, group_id, status, policy_version,
                                     cert_serial)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                a.agentId(), a.hostname(), a.ip(), a.osType(), a.osVersion(), a.kernel(), a.arch(),
                a.agentVersion(), a.machineId(), a.groupId(), a.status(), a.policyVersion(),
                a.certSerial());
    }

    /** 心跳：置在线、刷新心跳时间与版本信息 */
    public int heartbeat(String agentId, String agentVersion, String policyVersion) {
        return jdbc.update("""
                UPDATE t_agent
                SET status = 1, last_heartbeat = CURRENT_TIMESTAMP, agent_version = ?, policy_version = ?, updated_at = CURRENT_TIMESTAMP
                WHERE agent_id = ?
                """, agentVersion, policyVersion, agentId);
    }

    public int updateStatus(String agentId, short status) {
        return jdbc.update("UPDATE t_agent SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE agent_id = ?",
                status, agentId);
    }

    public List<AgentEntity> findByStatus(short status) {
        return jdbc.query("SELECT * FROM t_agent WHERE status = ?", MAPPER, status);
    }

    /** 离线判定：超过阈值未心跳的在线主机（供离线扫描 job 使用） */
    public List<AgentEntity> findStaleOnline(int staleSeconds) {
        return jdbc.query("""
                SELECT * FROM t_agent
                WHERE status = 1 AND last_heartbeat < ?
                """, MAPPER, database.timestampBefore(Duration.ofSeconds(staleSeconds)));
    }
}
