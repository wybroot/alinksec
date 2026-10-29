-- Preserve the last successful inventory when a source fails or is partial.
CREATE TABLE t_asset_collection (
    agent_id TEXT NOT NULL REFERENCES t_agent(agent_id) ON DELETE CASCADE,
    source TEXT NOT NULL,
    status TEXT NOT NULL,
    error TEXT NOT NULL DEFAULT '',
    attempted_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    succeeded_at TIMESTAMP,
    PRIMARY KEY (agent_id, source)
);
