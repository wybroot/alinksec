CREATE TABLE t_report_gate (
  id INTEGER PRIMARY KEY CHECK(id=1),
  revision BIGINT NOT NULL DEFAULT 0
);
INSERT INTO t_report_gate(id) VALUES(1);
CREATE TABLE t_report_snapshot (
  id VARCHAR(36) PRIMARY KEY,
  title VARCHAR(128) NOT NULL,
  created_by BIGINT NOT NULL,
  generated_at BIGINT NOT NULL,
  expires_at BIGINT NOT NULL,
  schedule_id VARCHAR(36),
  scheduled_at BIGINT,
  document TEXT NOT NULL,
  sha256 VARCHAR(64) NOT NULL,
  UNIQUE(schedule_id,scheduled_at)
);
CREATE INDEX idx_report_expiry ON t_report_snapshot(expires_at);
CREATE INDEX idx_report_generated ON t_report_snapshot(generated_at,id);
CREATE TABLE t_report_schedule (
  id VARCHAR(36) PRIMARY KEY,
  title VARCHAR(128) NOT NULL,
  cadence VARCHAR(8) NOT NULL CHECK(cadence IN ('daily','weekly','monthly')),
  days INTEGER NOT NULL CHECK(days BETWEEN 1 AND 366),
  group_id BIGINT,
  os_type INTEGER CHECK(os_type IN (1,2)),
  enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),
  revision BIGINT NOT NULL CHECK(revision>0),
  owner_id BIGINT NOT NULL,
  next_run BIGINT NOT NULL,
  retry_at BIGINT NOT NULL DEFAULT 0,
  failures INTEGER NOT NULL DEFAULT 0,
  last_error VARCHAR(255) NOT NULL DEFAULT '',
  last_snapshot VARCHAR(36),
  last_run BIGINT
);
CREATE INDEX idx_report_due ON t_report_schedule(enabled,next_run,retry_at);

CREATE INDEX idx_report_baseline_period ON t_baseline_task(created_at,id);
CREATE INDEX idx_report_summary_period ON t_baseline_summary(checked_at,agent_id);
CREATE INDEX idx_report_vuln_period ON t_vuln_finding(created_at,agent_id);
CREATE INDEX idx_report_alert_period ON t_alert(first_time,agent_id);
