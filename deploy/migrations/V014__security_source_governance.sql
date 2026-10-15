-- Keep original declarations and source rows while removing their current authority.
CREATE TABLE t_security_source_lifecycle (
  source_id VARCHAR(64) PRIMARY KEY,
  retired INTEGER NOT NULL DEFAULT 0,
  retired_at VARCHAR(40),
  retired_by BIGINT,
  retirement_note VARCHAR(2000) NOT NULL DEFAULT ''
);
ALTER TABLE t_security_cve ADD COLUMN locally_withdrawn INTEGER NOT NULL DEFAULT 0;
ALTER TABLE t_cve_db ADD COLUMN rule_status VARCHAR(16) NOT NULL DEFAULT 'active';
ALTER TABLE t_security_feed_state ADD COLUMN nvd_window_seconds BIGINT NOT NULL DEFAULT 0;
CREATE TABLE t_security_governance_event (
  id VARCHAR(36) PRIMARY KEY,
  source_id VARCHAR(64) NOT NULL,
  cve_id VARCHAR(32) NOT NULL DEFAULT '',
  operation VARCHAR(32) NOT NULL,
  actor BIGINT,
  recorded_at VARCHAR(40) NOT NULL,
  note VARCHAR(2000) NOT NULL DEFAULT '',
  document_sha256 VARCHAR(64) NOT NULL DEFAULT '',
  snapshot TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX idx_security_governance_source ON t_security_governance_event(source_id,recorded_at,id);
