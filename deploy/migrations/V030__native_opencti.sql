CREATE TABLE IF NOT EXISTS t_opencti_source (
    source_id TEXT PRIMARY KEY,
    configuration_sha256 TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    revision BIGINT NOT NULL,
    server_version TEXT NOT NULL,
    snapshot_sha256 TEXT NOT NULL,
    snapshot_at TEXT NOT NULL,
    evaluated_at TEXT NOT NULL,
    visible_count INTEGER NOT NULL,
    hash_count INTEGER NOT NULL,
    page_count INTEGER NOT NULL,
    policy TEXT NOT NULL,
    statistics TEXT NOT NULL,
    expiry_error TEXT NOT NULL DEFAULT '',
    delivery_deferred INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS t_opencti_indicator (
    source_id TEXT NOT NULL REFERENCES t_opencti_source(source_id),
    indicator_id TEXT NOT NULL,
    document TEXT NOT NULL,
    document_sha256 TEXT NOT NULL,
    document_bytes INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    included INTEGER NOT NULL,
    reason TEXT NOT NULL,
    expires_at BIGINT NOT NULL DEFAULT -1,
    PRIMARY KEY(source_id,indicator_id)
);
CREATE INDEX IF NOT EXISTS idx_opencti_expiry ON t_opencti_indicator(included,expires_at,source_id);
CREATE INDEX IF NOT EXISTS idx_opencti_hash ON t_opencti_indicator(source_id,sha256,included);
