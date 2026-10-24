ALTER TABLE t_agent_log ADD COLUMN raw_content TEXT;
ALTER TABLE t_agent_log ADD COLUMN event_key VARCHAR(64);
ALTER TABLE t_agent_log ADD COLUMN content_sha256 VARCHAR(64);
ALTER TABLE t_agent_log ADD COLUMN time_kind VARCHAR(24) NOT NULL DEFAULT 'legacy_unknown';
ALTER TABLE t_agent_log ADD COLUMN stored_bytes BIGINT NOT NULL DEFAULT 0;
UPDATE t_agent_log SET stored_bytes=LENGTH(content)*4+LENGTH(COALESCE(CAST(fields AS TEXT),''))*4+256;
CREATE UNIQUE INDEX idx_agent_log_event ON t_agent_log(agent_id,source,event_key);
CREATE INDEX idx_agent_log_received ON t_agent_log(created_at,id);
CREATE TABLE t_agent_log_state (
    id INTEGER PRIMARY KEY CHECK(id=1),
    retained_rows BIGINT NOT NULL,
    retained_bytes BIGINT NOT NULL
);
INSERT INTO t_agent_log_state(id,retained_rows,retained_bytes)
SELECT 1,COUNT(*),COALESCE(SUM(stored_bytes),0) FROM t_agent_log;
