CREATE TABLE t_windows_login_status (
 agent_id VARCHAR(64) PRIMARY KEY REFERENCES t_agent(agent_id) ON DELETE CASCADE,
 contract INTEGER NOT NULL DEFAULT 0,
 coverage TEXT NOT NULL DEFAULT '{}',
 observed_at BIGINT NOT NULL DEFAULT 0
);
CREATE TABLE t_windows_login_receipt (
 agent_id VARCHAR(64) NOT NULL REFERENCES t_agent(agent_id) ON DELETE CASCADE,
 event_id VARCHAR(80) NOT NULL,
 received_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
 PRIMARY KEY(agent_id,event_id)
);
