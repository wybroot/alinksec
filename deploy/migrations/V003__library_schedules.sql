CREATE TABLE IF NOT EXISTS t_security_feed_schedule (
  source_id VARCHAR(64) PRIMARY KEY,
  enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
  interval_ms BIGINT NOT NULL CHECK (interval_ms BETWEEN 300000 AND 604800000),
  updated_at VARCHAR(40) NOT NULL
);
ALTER TABLE t_security_feed_state ADD COLUMN failure_count INTEGER NOT NULL DEFAULT 0;
CREATE TABLE IF NOT EXISTS t_security_feed_run (
  id VARCHAR(36) PRIMARY KEY,
  source_id VARCHAR(64) NOT NULL,
  trigger_type VARCHAR(16) NOT NULL,
  started_at VARCHAR(40) NOT NULL,
  finished_at VARCHAR(40),
  status VARCHAR(16) NOT NULL,
  entry_count INTEGER NOT NULL DEFAULT 0,
  error VARCHAR(512) NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_security_feed_run_source ON t_security_feed_run(source_id, started_at);
