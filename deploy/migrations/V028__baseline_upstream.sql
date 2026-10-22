-- Signed publisher indexes add candidates; existing publication/task tables stay immutable.
CREATE TABLE t_baseline_upstream_gate (
    id INTEGER PRIMARY KEY CHECK(id=1), revision BIGINT NOT NULL DEFAULT 0,
    lease_owner TEXT NOT NULL DEFAULT '', lease_until BIGINT NOT NULL DEFAULT 0
);
INSERT INTO t_baseline_upstream_gate(id) VALUES(1);
CREATE TABLE t_baseline_upstream_source (
    id TEXT PRIMARY KEY, config_hash TEXT NOT NULL, configured INTEGER NOT NULL DEFAULT 1,
    enabled INTEGER NOT NULL DEFAULT 0, interval_ms BIGINT NOT NULL, revision BIGINT NOT NULL DEFAULT 0,
    sequence BIGINT NOT NULL DEFAULT 0, payload_sha256 TEXT NOT NULL DEFAULT '', receipt_id TEXT,
    etag TEXT NOT NULL DEFAULT '', modified TEXT NOT NULL DEFAULT '', next_poll BIGINT NOT NULL DEFAULT 0,
    last_outcome TEXT NOT NULL DEFAULT '', last_checked BIGINT NOT NULL DEFAULT 0
);
CREATE TABLE t_baseline_upstream_receipt (
    id TEXT PRIMARY KEY, source_id TEXT NOT NULL REFERENCES t_baseline_upstream_source(id),
    sequence BIGINT NOT NULL, payload_sha256 TEXT NOT NULL, key_sha256 TEXT NOT NULL,
    config_hash TEXT NOT NULL, expires_at BIGINT NOT NULL, envelope TEXT NOT NULL,
    fetched_at BIGINT NOT NULL, UNIQUE(source_id,sequence)
);
CREATE TABLE t_baseline_upstream_release (
    id TEXT PRIMARY KEY, source_id TEXT NOT NULL REFERENCES t_baseline_upstream_source(id),
    kind TEXT NOT NULL CHECK(kind IN ('baseline','scap')), code TEXT NOT NULL, version TEXT NOT NULL,
    os_type INTEGER NOT NULL CHECK(os_type IN (1,2)), url TEXT NOT NULL, sha256 TEXT NOT NULL,
    size_bytes BIGINT NOT NULL, remote_status TEXT NOT NULL CHECK(remote_status IN ('active','withdrawn')),
    first_receipt TEXT NOT NULL REFERENCES t_baseline_upstream_receipt(id),
    current_receipt TEXT NOT NULL REFERENCES t_baseline_upstream_receipt(id),
    state TEXT NOT NULL CHECK(state IN ('pending','imported','failed')), attempts INTEGER NOT NULL DEFAULT 0,
    issue TEXT NOT NULL DEFAULT '', package_id TEXT, artifact TEXT, imported_at BIGINT,
    UNIQUE(source_id,kind,code,version), UNIQUE(kind,package_id)
);
CREATE TABLE t_baseline_upstream_attempt (
    id TEXT PRIMARY KEY, source_id TEXT NOT NULL REFERENCES t_baseline_upstream_source(id),
    trigger_type TEXT NOT NULL, actor BIGINT NOT NULL, started_at BIGINT NOT NULL,
    finished_at BIGINT, outcome TEXT NOT NULL, issue TEXT NOT NULL DEFAULT '',
    imported INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_baseline_upstream_attempt ON t_baseline_upstream_attempt(source_id,started_at);
