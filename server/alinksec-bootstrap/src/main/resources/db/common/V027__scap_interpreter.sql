-- Reviewed offline SCAP content is independent of legacy check mappings.
CREATE TABLE t_scap_package_gate (
    code TEXT PRIMARY KEY,
    revision BIGINT NOT NULL DEFAULT 0
);
CREATE TABLE t_scap_package (
    id TEXT PRIMARY KEY,
    code TEXT NOT NULL,
    version TEXT NOT NULL,
    name TEXT NOT NULL,
    os_type INTEGER NOT NULL CHECK(os_type IN (1,2)),
    os_version_pattern TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('candidate','approved','published','withdrawn','rejected')),
    revision INTEGER NOT NULL DEFAULT 0,
    source_sha256 TEXT NOT NULL,
    source_zip TEXT NOT NULL,
    resolution TEXT NOT NULL,
    content_sha256 TEXT NOT NULL,
    content_zip TEXT NOT NULL,
    metadata TEXT NOT NULL,
    last_test_task TEXT,
    created_by BIGINT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(code,version)
);
CREATE TABLE t_scap_package_review (
    package_id TEXT NOT NULL REFERENCES t_scap_package(id),
    revision INTEGER NOT NULL,
    action TEXT NOT NULL,
    note TEXT NOT NULL,
    actor BIGINT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY(package_id,revision)
);
CREATE TABLE t_scap_status (
    agent_id TEXT PRIMARY KEY,
    contract INTEGER NOT NULL,
    coverage TEXT NOT NULL,
    observed_at BIGINT NOT NULL
);
CREATE TABLE t_scap_task (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    package_id TEXT NOT NULL REFERENCES t_scap_package(id),
    content_zip TEXT NOT NULL,
    content_sha256 TEXT NOT NULL,
    snapshot TEXT NOT NULL,
    snapshot_sha256 TEXT NOT NULL,
    test_mode BOOLEAN NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('running','complete','partial')),
    created_by BIGINT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    finished_at TIMESTAMP
);
CREATE TABLE t_scap_task_agent (
    task_id TEXT NOT NULL REFERENCES t_scap_task(id),
    agent_id TEXT NOT NULL,
    command_id TEXT NOT NULL,
    runtime_sha256 TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('pending','complete','failed','timeout')),
    issue TEXT NOT NULL DEFAULT '',
    evidence_sha256 TEXT NOT NULL DEFAULT '',
    evidence TEXT NOT NULL DEFAULT '{}',
    finished_at TIMESTAMP,
    PRIMARY KEY(task_id,agent_id),
    UNIQUE(command_id)
);
CREATE INDEX idx_scap_task_created ON t_scap_task(created_at);
CREATE INDEX idx_scap_task_agent_state ON t_scap_task_agent(task_id,state);
