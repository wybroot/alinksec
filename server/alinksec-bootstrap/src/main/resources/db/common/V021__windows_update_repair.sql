ALTER TABLE t_agent ADD COLUMN windows_update_contract INTEGER NOT NULL DEFAULT 0;
ALTER TABLE t_agent ADD COLUMN windows_update_scan_id VARCHAR(36) NOT NULL DEFAULT '';
CREATE TABLE t_windows_update_scan (
 scan_id VARCHAR(36) PRIMARY KEY,
 agent_id VARCHAR(64) NOT NULL REFERENCES t_agent(agent_id) ON DELETE CASCADE,
 command_id VARCHAR(36) NOT NULL DEFAULT '',
 status VARCHAR(24) NOT NULL DEFAULT 'pending',
 error VARCHAR(128) NOT NULL DEFAULT '',
 host_identity VARCHAR(64) NOT NULL DEFAULT '',
 snapshot TEXT NOT NULL DEFAULT '',
 created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
 received_at TIMESTAMP,
 deadline BIGINT NOT NULL
);
CREATE INDEX idx_windows_update_scan_agent ON t_windows_update_scan(agent_id,created_at);
CREATE TABLE t_windows_update_candidate (
 id BIGSERIAL PRIMARY KEY,
 scan_id VARCHAR(36) NOT NULL REFERENCES t_windows_update_scan(scan_id) ON DELETE CASCADE,
 agent_id VARCHAR(64) NOT NULL REFERENCES t_agent(agent_id) ON DELETE CASCADE,
 update_id VARCHAR(36) NOT NULL,
 revision INTEGER NOT NULL,
 title VARCHAR(512) NOT NULL,
 eligible INTEGER NOT NULL DEFAULT 0,
 reason VARCHAR(128) NOT NULL DEFAULT '',
 metadata TEXT NOT NULL,
 UNIQUE(scan_id,update_id,revision)
);
CREATE INDEX idx_windows_update_candidate_agent ON t_windows_update_candidate(agent_id);
ALTER TABLE t_fix_record ADD COLUMN reboot_required INTEGER NOT NULL DEFAULT 0;
ALTER TABLE t_fix_record ADD COLUMN verified INTEGER NOT NULL DEFAULT 0;
ALTER TABLE t_fix_record ADD COLUMN execution_evidence TEXT NOT NULL DEFAULT '';
ALTER TABLE t_fix_record ADD COLUMN fix_payload TEXT NOT NULL DEFAULT '';
