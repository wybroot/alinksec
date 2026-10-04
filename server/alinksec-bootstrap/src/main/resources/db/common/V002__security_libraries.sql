CREATE TABLE IF NOT EXISTS t_security_feed_state (
  source_id VARCHAR(64) PRIMARY KEY,
  kind VARCHAR(32) NOT NULL,
  checked_at VARCHAR(40),
  success_at VARCHAR(40),
  status VARCHAR(16) NOT NULL DEFAULT 'never',
  error VARCHAR(512) NOT NULL DEFAULT '',
  cursor VARCHAR(128) NOT NULL DEFAULT '',
  etag VARCHAR(512) NOT NULL DEFAULT '',
  last_modified VARCHAR(128) NOT NULL DEFAULT '',
  entry_count INTEGER NOT NULL DEFAULT 0,
  version VARCHAR(64) NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS t_security_hash (
  source_id VARCHAR(64) NOT NULL,
  sha256 VARCHAR(64) NOT NULL,
  name VARCHAR(255) NOT NULL,
  severity INTEGER NOT NULL,
  PRIMARY KEY (source_id, sha256)
);
CREATE INDEX IF NOT EXISTS idx_security_hash_digest ON t_security_hash(sha256);
CREATE TABLE IF NOT EXISTS t_security_rule (
  source_id VARCHAR(64) NOT NULL,
  name VARCHAR(255) NOT NULL,
  document TEXT NOT NULL,
  PRIMARY KEY (source_id, name)
);
CREATE TABLE IF NOT EXISTS t_security_cve (
  source_id VARCHAR(64) NOT NULL,
  cve_id VARCHAR(32) NOT NULL,
  document TEXT NOT NULL,
  matchable INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (source_id, cve_id)
);
CREATE INDEX IF NOT EXISTS idx_security_cve_id ON t_security_cve(cve_id);
