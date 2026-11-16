ALTER TABLE t_user ADD COLUMN auth_version BIGINT NOT NULL DEFAULT 0;
CREATE TABLE t_user_session (
 session_id VARCHAR(64) PRIMARY KEY,
 user_id BIGINT NOT NULL REFERENCES t_user(id) ON DELETE CASCADE,
 auth_version BIGINT NOT NULL,
 role_name VARCHAR(16) NOT NULL,
 expires_at BIGINT NOT NULL
);
CREATE INDEX idx_user_session_user ON t_user_session(user_id);
CREATE TABLE t_asset_collection_state (
 agent_id VARCHAR(64) NOT NULL REFERENCES t_agent(agent_id) ON DELETE CASCADE,
 category VARCHAR(16) NOT NULL,
 sequence BIGINT NOT NULL DEFAULT 0,
 status VARCHAR(24) NOT NULL,
 error VARCHAR(128) NOT NULL DEFAULT '',
 collected_at BIGINT NOT NULL DEFAULT 0,
 PRIMARY KEY(agent_id,category)
);
CREATE TABLE t_asset_disk (
 agent_id VARCHAR(64) NOT NULL REFERENCES t_agent(agent_id) ON DELETE CASCADE,
 mount VARCHAR(1024) NOT NULL,
 fs_type VARCHAR(128) NOT NULL,
 total_bytes BIGINT NOT NULL,
 used_bytes BIGINT NOT NULL,
 PRIMARY KEY(agent_id,mount)
);
ALTER TABLE t_agent ADD COLUMN maintenance_until BIGINT NOT NULL DEFAULT 0;
ALTER TABLE t_agent ADD COLUMN offline_alerted BOOLEAN NOT NULL DEFAULT FALSE;
CREATE TABLE t_automatic_response (
 agent_id VARCHAR(64) NOT NULL REFERENCES t_agent(agent_id) ON DELETE CASCADE,
 report_id VARCHAR(128) NOT NULL,
 action VARCHAR(64) NOT NULL,
 received_at BIGINT NOT NULL,
 PRIMARY KEY(agent_id,report_id)
);
CREATE INDEX idx_automatic_response_time ON t_automatic_response(received_at);
