package com.alinksec.service.command;

import com.alinksec.common.util.JsonUtils;
import com.alinksec.proto.RptAck;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.sql.Timestamp;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * t_command 访问层。状态机（通信协议 §3.1）：
 * 0 PENDING → 1 SENT → 2 RECEIVED → 3 RUNNING → 4 DONE / 5 FAILED；6 TIMEOUT。
 */
@Repository
public class CommandRepository {

    /** 指令下发后 30s 未 RECEIVED 则重推，最多 3 次 */
    public static final int ACK_TIMEOUT_SECONDS = 30;
    public static final int MAX_RETRY = 3;

    public static final short ST_PENDING = 0;
    public static final short ST_SENT = 1;
    public static final short ST_RECEIVED = 2;
    public static final short ST_RUNNING = 3;
    public static final short ST_DONE = 4;
    public static final short ST_FAILED = 5;
    public static final short ST_TIMEOUT = 6;

    private final JdbcTemplate jdbc;

    public CommandRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public void insert(String cmdId, String agentId, String type, String payloadJson, Long issuedBy) {
        jdbc.update("""
                INSERT INTO t_command (cmd_id, agent_id, type, payload, status, issued_by)
                VALUES (?, ?, ?, ?, ?, ?)
                """, cmdId, agentId, type, payloadJson, ST_PENDING, issuedBy);
    }

    public int markSent(String cmdId) {
        return jdbc.update("UPDATE t_command SET status = ? WHERE cmd_id = ? AND status = ?",
                ST_SENT, cmdId, ST_PENDING);
    }

    public int bumpRetry(String cmdId) {
        return jdbc.update("""
                UPDATE t_command SET retry_count = retry_count + 1, status = ?
                WHERE cmd_id = ?
                """, ST_SENT, cmdId);
    }

    public int markTimeout(String cmdId) {
        return jdbc.update("""
                UPDATE t_command SET status = ?, finished_at = now(), result = ?
                WHERE cmd_id = ?
                """, ST_TIMEOUT, JsonUtils.write(Map.of("reason", "ack-timeout")), cmdId);
    }

    /** Agent ACK 推进状态机；终态附带结果 JSON */
    public int onAck(RptAck ack) {
        short target = switch (ack.getStage()) {
            case RECEIVED -> ST_RECEIVED;
            case RUNNING -> ST_RUNNING;
            case DONE -> ST_DONE;
            case FAILED -> ST_FAILED;
            default -> -1;
        };
        if (target < 0) {
            return 0;
        }
        boolean terminal = target == ST_DONE || target == ST_FAILED;
        String result = terminal
                ? JsonUtils.write(Map.of("code", ack.getCode(), "message", ack.getMessage()))
                : null;
        if (terminal) {
            return jdbc.update("""
                    UPDATE t_command
                    SET status = ?, acked_at = COALESCE(acked_at, now()), finished_at = now(),
                        result = ?
                    WHERE cmd_id = ? AND status NOT IN (4, 5, 6)
                    """, target, result, ack.getCmdId());
        }
        return jdbc.update("""
                UPDATE t_command
                SET status = ?, acked_at = COALESCE(acked_at, now())
                WHERE cmd_id = ? AND status NOT IN (4, 5, 6)
                """, target, ack.getCmdId());
    }

    /** 待超时判定的 SENT 指令：下发超过 30s 仍未 RECEIVED */
    public List<Map<String, Object>> findAckTimedout() {
        return jdbc.queryForList("""
                SELECT id, cmd_id, agent_id, retry_count
                FROM t_command
                WHERE status = ? AND created_at < now() - ? * interval '1 second'
                """, ST_SENT, ACK_TIMEOUT_SECONDS);
    }

    public Optional<Map<String, Object>> findByCmdId(String cmdId) {
        return jdbc.queryForList("SELECT * FROM t_command WHERE cmd_id = ?", cmdId).stream().findFirst();
    }

    public int markFailed(String cmdId, String reason) {
        return jdbc.update("""
                UPDATE t_command SET status = ?, finished_at = now(), result = ?
                WHERE cmd_id = ? AND status NOT IN (?, ?, ?)
                """, ST_FAILED, JsonUtils.write(Map.of("reason", reason)), cmdId,
                ST_DONE, ST_FAILED, ST_TIMEOUT);
    }

    public List<Map<String, Object>> findPendingByAgent(String agentId) {
        return jdbc.queryForList("""
                SELECT * FROM t_command
                WHERE agent_id = ? AND status = ?
                ORDER BY created_at, id
                """, agentId, ST_PENDING);
    }

    /** Counts pending rows created before complete protobuf command persistence existed. */
    public int countLegacyPending() {
        Integer count = jdbc.queryForObject("""
                SELECT count(*) FROM t_command
                WHERE status = ? AND COALESCE(payload ->> 'command_b64', '') = ''
                """, Integer.class, ST_PENDING);
        return count == null ? 0 : count;
    }

    /** Explicitly resolves unrecoverable legacy commands instead of failing on each Agent reconnect. */
    public int failLegacyPending() {
        return jdbc.update("""
                UPDATE t_command
                SET status = ?, finished_at = now(), result = ?
                WHERE status = ? AND COALESCE(payload ->> 'command_b64', '') = ''
                """, ST_FAILED, JsonUtils.write(Map.of("reason", "legacy command payload cannot be replayed")),
                ST_PENDING);
    }

    public List<Map<String, Object>> recentByAgent(String agentId, int limit) {
        return jdbc.queryForList("""
                SELECT * FROM t_command WHERE agent_id = ? ORDER BY created_at DESC LIMIT ?
                """, agentId, limit);
    }
}
