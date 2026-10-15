-- SQLite rebuild removes the legacy replacement key while preserving every old object and ID.
CREATE TABLE t_patch_package_next (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  os_type INTEGER NOT NULL,
  os_version VARCHAR(64) NOT NULL DEFAULT '',
  pkg_name VARCHAR(255) NOT NULL,
  target_version VARCHAR(255) NOT NULL,
  repo_type VARCHAR(8) NOT NULL,
  filename VARCHAR(255) NOT NULL,
  sha256 VARCHAR(64) NOT NULL,
  size BIGINT NOT NULL DEFAULT 0,
  imported_by BIGINT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  source TEXT NOT NULL DEFAULT '',
  distro_id TEXT NOT NULL DEFAULT '',
  distro_version TEXT NOT NULL DEFAULT '',
  architecture TEXT NOT NULL DEFAULT '',
  version_identity TEXT NOT NULL DEFAULT '',
  metadata_status TEXT NOT NULL DEFAULT 'legacy',
  metadata TEXT NOT NULL DEFAULT '{}'
);
INSERT INTO t_patch_package_next(id,os_type,os_version,pkg_name,target_version,repo_type,filename,sha256,size,imported_by,created_at)
  SELECT id,os_type,os_version,pkg_name,target_version,repo_type,filename,sha256,size,imported_by,created_at FROM t_patch_package;
DROP TABLE t_patch_package;
ALTER TABLE t_patch_package_next RENAME TO t_patch_package;
CREATE INDEX idx_patch_pkg ON t_patch_package(pkg_name);
CREATE INDEX idx_patch_scope ON t_patch_package(distro_id,distro_version,source,architecture,pkg_name,version_identity);

CREATE TABLE t_patch_review (
  id TEXT PRIMARY KEY,
  patch_id BIGINT NOT NULL REFERENCES t_patch_package(id),
  patch_sha256 TEXT NOT NULL,
  patch_digest TEXT NOT NULL,
  cve_id TEXT NOT NULL,
  rule_source_id TEXT NOT NULL,
  rule_digest TEXT NOT NULL,
  reviewed_by BIGINT NOT NULL,
  reviewed_at TEXT NOT NULL,
  notes TEXT NOT NULL,
  revoked_by BIGINT,
  revoked_at TEXT,
  revocation_note TEXT
);
CREATE INDEX idx_patch_review_rule ON t_patch_review(patch_id,cve_id,rule_source_id,rule_digest,revoked_at);
