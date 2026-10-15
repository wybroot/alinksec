-- Imported binary fields and distribution declarations are separate from authenticated manual review.
ALTER TABLE t_patch_package DROP CONSTRAINT t_patch_package_os_type_os_version_pkg_name_target_version_key;
ALTER TABLE t_patch_package ALTER COLUMN target_version TYPE VARCHAR(255);
ALTER TABLE t_patch_package ADD COLUMN source TEXT NOT NULL DEFAULT '';
ALTER TABLE t_patch_package ADD COLUMN distro_id TEXT NOT NULL DEFAULT '';
ALTER TABLE t_patch_package ADD COLUMN distro_version TEXT NOT NULL DEFAULT '';
ALTER TABLE t_patch_package ADD COLUMN architecture TEXT NOT NULL DEFAULT '';
ALTER TABLE t_patch_package ADD COLUMN version_identity TEXT NOT NULL DEFAULT '';
ALTER TABLE t_patch_package ADD COLUMN metadata_status TEXT NOT NULL DEFAULT 'legacy';
ALTER TABLE t_patch_package ADD COLUMN metadata TEXT NOT NULL DEFAULT '{}';
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
