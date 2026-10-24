CREATE TABLE t_cluster_state (
 id INTEGER PRIMARY KEY,
 deployment_id VARCHAR(36) NOT NULL DEFAULT '',
 configuration_sha256 VARCHAR(64) NOT NULL DEFAULT '',
 next_sequence BIGINT NOT NULL DEFAULT 0
);
INSERT INTO t_cluster_state(id) VALUES(1);

CREATE TABLE t_cluster_node (
 node_id VARCHAR(64) PRIMARY KEY,
 incarnation VARCHAR(36) NOT NULL,
 configuration_sha256 VARCHAR(64) NOT NULL,
 probe_token VARCHAR(64) NOT NULL,
 lease_until BIGINT NOT NULL,
 started_at BIGINT NOT NULL
);
CREATE TABLE t_cluster_session (
 agent_id VARCHAR(64) PRIMARY KEY,
 node_id VARCHAR(64) NOT NULL,
 token VARCHAR(36) NOT NULL,
 generation BIGINT NOT NULL,
 updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_cluster_session_node ON t_cluster_session(node_id);

CREATE TABLE t_cluster_ingress (
 sequence_id BIGINT PRIMARY KEY,
 id VARCHAR(36) NOT NULL UNIQUE,
 agent_id VARCHAR(64) NOT NULL,
 report_id VARCHAR(128) NOT NULL,
 payload_type VARCHAR(32) NOT NULL,
 content_b64 TEXT NOT NULL,
 content_sha256 VARCHAR(64) NOT NULL,
 size_bytes BIGINT NOT NULL,
 state VARCHAR(16) NOT NULL DEFAULT 'pending',
 attempts INTEGER NOT NULL DEFAULT 0,
 next_attempt_at BIGINT NOT NULL DEFAULT 0,
 published_at BIGINT NOT NULL DEFAULT 0,
 created_at BIGINT NOT NULL,
 finished_at BIGINT,
 error_code VARCHAR(64) NOT NULL DEFAULT '',
 replay_count INTEGER NOT NULL DEFAULT 0,
 last_retry_by BIGINT,
 last_retry_at BIGINT,
 last_retry_note TEXT NOT NULL DEFAULT '',
 UNIQUE(agent_id,report_id)
);
CREATE INDEX idx_cluster_ingress_pending ON t_cluster_ingress(state,published_at,sequence_id);
CREATE INDEX idx_cluster_ingress_agent ON t_cluster_ingress(agent_id,state,sequence_id);

CREATE TABLE t_cluster_work (
 name VARCHAR(96) PRIMARY KEY,
 token VARCHAR(36) NOT NULL DEFAULT '',
 node_id VARCHAR(64) NOT NULL DEFAULT '',
 lease_until BIGINT NOT NULL DEFAULT 0,
 generation BIGINT NOT NULL DEFAULT 0
);
CREATE TABLE t_cluster_job_slot (
 name VARCHAR(96) NOT NULL,
 slot VARCHAR(64) NOT NULL,
 completed_at BIGINT NOT NULL,
 PRIMARY KEY(name,slot)
);

ALTER TABLE t_alert_notify_delivery ADD COLUMN claim_token VARCHAR(36) NOT NULL DEFAULT '';
ALTER TABLE t_alert_notify_delivery ADD COLUMN lease_until BIGINT NOT NULL DEFAULT 0;
ALTER TABLE t_alert_notify_delivery ADD COLUMN next_attempt_at BIGINT NOT NULL DEFAULT 0;
ALTER TABLE t_agent ADD COLUMN cluster_asset_sequence BIGINT NOT NULL DEFAULT 0;
