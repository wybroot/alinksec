ALTER TABLE t_agent ADD COLUMN virus_execution_contract INTEGER NOT NULL DEFAULT 0;
ALTER TABLE t_agent ADD COLUMN virus_db_version VARCHAR(128) NOT NULL DEFAULT '';
ALTER TABLE t_virus_scan_task ADD COLUMN expected_db_version VARCHAR(128) NOT NULL DEFAULT '';
ALTER TABLE t_virus_finding ADD COLUMN quarantine_id VARCHAR(32) NOT NULL DEFAULT '';
ALTER TABLE t_virus_finding ADD COLUMN action_error VARCHAR(128) NOT NULL DEFAULT '';
ALTER TABLE t_virus_finding ADD COLUMN event_key VARCHAR(64) NOT NULL DEFAULT '';
ALTER TABLE t_virus_finding ADD COLUMN initial_evidence TEXT NOT NULL DEFAULT '';
CREATE UNIQUE INDEX idx_virus_realtime_event ON t_virus_finding(agent_id,event_key) WHERE event_key<>'';

CREATE TABLE t_virus_task_agent (
 task_id BIGINT NOT NULL,
 agent_id VARCHAR(64) NOT NULL,
 command_id VARCHAR(36) NOT NULL DEFAULT '',
 state VARCHAR(16) NOT NULL DEFAULT 'pending',
 evidence TEXT NOT NULL DEFAULT '',
 evidence_sha256 VARCHAR(64) NOT NULL DEFAULT '',
 received_at VARCHAR(40),
 late INTEGER NOT NULL DEFAULT 0,
 PRIMARY KEY(task_id,agent_id)
);
CREATE INDEX idx_virus_task_command ON t_virus_task_agent(command_id);

CREATE TABLE t_virus_action_evidence (
 id VARCHAR(36) PRIMARY KEY,
 finding_id BIGINT NOT NULL,
 agent_id VARCHAR(64) NOT NULL,
 command_id VARCHAR(36) NOT NULL,
 action VARCHAR(16) NOT NULL,
 state VARCHAR(16) NOT NULL DEFAULT 'pending',
 error VARCHAR(2000) NOT NULL DEFAULT '',
 request_evidence TEXT NOT NULL DEFAULT '',
 receipt TEXT NOT NULL DEFAULT '',
 actor BIGINT,
 created_at VARCHAR(40) NOT NULL,
 finished_at VARCHAR(40)
);
CREATE INDEX idx_virus_action_finding ON t_virus_action_evidence(finding_id,created_at);
CREATE INDEX idx_virus_action_command ON t_virus_action_evidence(command_id,state);

CREATE TABLE t_virus_state (
 id INTEGER PRIMARY KEY,
 realtime_enabled INTEGER NOT NULL DEFAULT 1,
 realtime_action VARCHAR(16) NOT NULL DEFAULT 'quarantine',
 revision BIGINT NOT NULL DEFAULT 1
);
INSERT INTO t_virus_state(id) VALUES(1);
