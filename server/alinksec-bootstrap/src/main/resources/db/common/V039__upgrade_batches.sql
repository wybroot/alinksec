CREATE TABLE t_upgrade_batch (
    id TEXT PRIMARY KEY,
    package_id BIGINT NOT NULL REFERENCES t_agent_upgrade_package(id),
    created_by BIGINT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE t_upgrade_target (
    batch_id TEXT NOT NULL REFERENCES t_upgrade_batch(id) ON DELETE CASCADE,
    agent_id TEXT NOT NULL,
    command_id TEXT NOT NULL UNIQUE,
    PRIMARY KEY (batch_id, agent_id)
);
