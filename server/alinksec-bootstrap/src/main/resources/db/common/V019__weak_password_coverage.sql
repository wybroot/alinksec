ALTER TABLE t_agent ADD COLUMN weak_password_contract INTEGER NOT NULL DEFAULT 0;
CREATE TABLE t_scan_task_agent (
 task_id BIGINT NOT NULL REFERENCES t_scan_task(id) ON DELETE CASCADE,
 agent_id VARCHAR(64) NOT NULL,
 command_id VARCHAR(36) NOT NULL DEFAULT '',
 state VARCHAR(16) NOT NULL DEFAULT 'pending',
 weak_status VARCHAR(16) NOT NULL DEFAULT 'pending',
 evidence TEXT NOT NULL DEFAULT '',
 evidence_sha256 VARCHAR(64) NOT NULL DEFAULT '',
 received_at VARCHAR(40),
 late INTEGER NOT NULL DEFAULT 0,
 PRIMARY KEY(task_id,agent_id)
);
CREATE INDEX idx_scan_task_command ON t_scan_task_agent(command_id);
-- Remove historical plaintext/ambiguous remarks. Never retain credentials in
-- findings, transport receipts or new evidence. Original findings stay visible.
UPDATE t_weakpwd_finding SET remark=NULL;
