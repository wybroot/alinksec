-- Real heartbeat samples: latest values plus one hour of minute buckets.
CREATE TABLE t_host_runtime (
    agent_id TEXT PRIMARY KEY REFERENCES t_agent(agent_id) ON DELETE CASCADE,
    sampled_at BIGINT NOT NULL,
    cpu_percent REAL,
    memory_percent REAL,
    uptime_sec BIGINT,
    host_info TEXT,
    host_info_at BIGINT
);
CREATE TABLE t_host_metric (
    agent_id TEXT NOT NULL REFERENCES t_agent(agent_id) ON DELETE CASCADE,
    bucket BIGINT NOT NULL,
    sampled_at BIGINT NOT NULL,
    cpu_percent REAL,
    memory_percent REAL,
    PRIMARY KEY (agent_id, bucket)
);
CREATE INDEX idx_host_metric_time ON t_host_metric(bucket);
CREATE TABLE t_asset_disk (
    agent_id TEXT NOT NULL REFERENCES t_agent(agent_id) ON DELETE CASCADE,
    mount TEXT NOT NULL,
    fs_type TEXT NOT NULL,
    total_bytes BIGINT NOT NULL,
    used_bytes BIGINT NOT NULL,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (agent_id, mount)
);
