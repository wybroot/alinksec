-- Capability is re-established on each authenticated connection. Current lease
-- state is distinct from historical command ACKs and offline security events.
ALTER TABLE t_agent ADD COLUMN isolation_contract INTEGER NOT NULL DEFAULT 0;
ALTER TABLE t_agent ADD COLUMN isolation_lease_id VARCHAR(32);
ALTER TABLE t_agent ADD COLUMN isolation_generation BIGINT NOT NULL DEFAULT 0;
ALTER TABLE t_agent ADD COLUMN isolation_revision BIGINT NOT NULL DEFAULT 0;
ALTER TABLE t_agent ADD COLUMN isolation_lease_command_id VARCHAR(256);
ALTER TABLE t_agent ADD COLUMN isolation_lease_deadline BIGINT;
ALTER TABLE t_agent ADD COLUMN isolation_automatic BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE t_agent ADD COLUMN isolation_seen_at BIGINT;

-- Durable replay is not limited to the generic ten-minute transport dedup TTL.
CREATE TABLE t_isolation_outcome_receipt (
    agent_id VARCHAR(64) NOT NULL REFERENCES t_agent(agent_id) ON DELETE CASCADE,
    event_id VARCHAR(96) NOT NULL,
    detail TEXT NOT NULL,
    received_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (agent_id,event_id)
);
