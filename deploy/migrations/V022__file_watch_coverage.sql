CREATE TABLE t_file_watch_status (
 agent_id VARCHAR(64) PRIMARY KEY REFERENCES t_agent(agent_id) ON DELETE CASCADE,
 contract INTEGER NOT NULL DEFAULT 0,
 coverage TEXT NOT NULL DEFAULT '{}',
 observed_at BIGINT NOT NULL
);
