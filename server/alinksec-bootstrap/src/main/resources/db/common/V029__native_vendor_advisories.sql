CREATE TABLE IF NOT EXISTS t_vendor_document (
  id VARCHAR(36) PRIMARY KEY,
  source_id VARCHAR(64) NOT NULL,
  document_id VARCHAR(255) NOT NULL,
  format VARCHAR(32) NOT NULL,
  publisher VARCHAR(128) NOT NULL,
  title TEXT NOT NULL,
  vendor_version VARCHAR(128) NOT NULL,
  vendor_updated_at VARCHAR(40) NOT NULL,
  configuration_sha256 VARCHAR(64) NOT NULL,
  origin TEXT NOT NULL,
  origin_kind VARCHAR(32) NOT NULL,
  sha256 VARCHAR(64) NOT NULL,
  size_bytes BIGINT NOT NULL,
  raw_base64 TEXT,
  current_version INTEGER NOT NULL DEFAULT 1,
  cve_count INTEGER NOT NULL,
  rule_count INTEGER NOT NULL,
  imported_at VARCHAR(40) NOT NULL,
  checked_at VARCHAR(40) NOT NULL,
  etag VARCHAR(512) NOT NULL DEFAULT '',
  last_modified VARCHAR(128) NOT NULL DEFAULT '',
  UNIQUE(source_id,document_id,configuration_sha256,sha256)
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_vendor_current_document
  ON t_vendor_document(source_id,document_id) WHERE current_version=1;
CREATE INDEX IF NOT EXISTS idx_vendor_archive_source ON t_vendor_document(source_id,imported_at);
CREATE TABLE IF NOT EXISTS t_vendor_contribution (
  source_id VARCHAR(64) NOT NULL,
  document_id VARCHAR(255) NOT NULL,
  cve_id VARCHAR(32) NOT NULL,
  raw_document_id VARCHAR(36) NOT NULL REFERENCES t_vendor_document(id),
  document TEXT NOT NULL,
  PRIMARY KEY(source_id,document_id,cve_id)
);
CREATE INDEX IF NOT EXISTS idx_vendor_contribution_cve ON t_vendor_contribution(source_id,cve_id);
CREATE TABLE IF NOT EXISTS t_vendor_sync_state (
  source_id VARCHAR(64) PRIMARY KEY,
  configuration_sha256 VARCHAR(64) NOT NULL,
  index_base64 TEXT NOT NULL DEFAULT '',
  index_sha256 VARCHAR(64) NOT NULL DEFAULT '',
  etag VARCHAR(512) NOT NULL DEFAULT '',
  last_modified VARCHAR(128) NOT NULL DEFAULT '',
  discovered_count INTEGER NOT NULL DEFAULT 0,
  pending_count INTEGER NOT NULL DEFAULT 0,
  checked_count INTEGER NOT NULL DEFAULT 0,
  updated_at VARCHAR(40) NOT NULL
);
