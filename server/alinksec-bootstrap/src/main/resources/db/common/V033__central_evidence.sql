ALTER TABLE t_agent ADD COLUMN evidence_contract INTEGER NOT NULL DEFAULT 0;

CREATE TABLE t_evidence_gate (
 id INTEGER PRIMARY KEY,
 revision BIGINT NOT NULL DEFAULT 0
);
INSERT INTO t_evidence_gate(id) VALUES(1);

CREATE TABLE t_evidence_request (
 id VARCHAR(36) PRIMARY KEY,
 agent_id VARCHAR(64) NOT NULL,
 kind VARCHAR(32) NOT NULL,
 finding_id BIGINT,
 quarantine_id VARCHAR(32) NOT NULL DEFAULT '',
 original_path VARCHAR(4096) NOT NULL DEFAULT '',
 expected_sha256 VARCHAR(64) NOT NULL DEFAULT '',
 reason VARCHAR(256) NOT NULL,
 actor BIGINT NOT NULL,
 command_id VARCHAR(36) NOT NULL DEFAULT '',
 state VARCHAR(16) NOT NULL DEFAULT 'pending',
 error_code VARCHAR(128) NOT NULL DEFAULT '',
 created_at BIGINT NOT NULL,
 deadline BIGINT NOT NULL,
 expires_at BIGINT NOT NULL,
 collected_at BIGINT,
 received_at BIGINT,
 content_sha256 VARCHAR(64) NOT NULL DEFAULT '',
 size_bytes BIGINT NOT NULL DEFAULT 0,
 content_b64 TEXT NOT NULL DEFAULT '',
 download_count BIGINT NOT NULL DEFAULT 0,
 last_download_by BIGINT,
 last_download_at BIGINT
);
CREATE INDEX idx_evidence_agent ON t_evidence_request(agent_id,created_at);
CREATE UNIQUE INDEX idx_evidence_command ON t_evidence_request(command_id) WHERE command_id<>'';
