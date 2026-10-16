-- Configuration evidence is replayed after reconnect/restart with stable IDs.
-- Keep receipts beyond the generic transport TTL, in the alert transaction.
CREATE TABLE t_agent_config_event_receipt (
    agent_id VARCHAR(64) NOT NULL REFERENCES t_agent(agent_id) ON DELETE CASCADE,
    event_id VARCHAR(96) NOT NULL,
    detail TEXT NOT NULL,
    received_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (agent_id,event_id)
);
