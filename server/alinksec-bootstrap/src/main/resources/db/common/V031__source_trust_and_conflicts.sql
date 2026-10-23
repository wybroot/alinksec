-- Empty policy/decision tables preserve legacy manual-first ranking until an administrator acts.
CREATE TABLE t_security_source_policy (
  source_id VARCHAR(64) PRIMARY KEY,
  tier INTEGER NOT NULL CHECK(tier BETWEEN 0 AND 2),
  priority INTEGER NOT NULL CHECK(priority BETWEEN 0 AND 100),
  quarantined INTEGER NOT NULL CHECK(quarantined IN (0,1)),
  revision BIGINT NOT NULL CHECK(revision>0),
  actor BIGINT NOT NULL,
  updated_at VARCHAR(40) NOT NULL,
  note VARCHAR(2000) NOT NULL
);
CREATE TABLE t_security_item_decision (
  kind VARCHAR(8) NOT NULL CHECK(kind IN ('hash','rule','cve')),
  item_key VARCHAR(255) NOT NULL,
  action VARCHAR(16) NOT NULL CHECK(action IN ('automatic','select','suppress')),
  selected_source VARCHAR(64) NOT NULL DEFAULT '',
  context_digest VARCHAR(64) NOT NULL,
  revision BIGINT NOT NULL CHECK(revision>0),
  actor BIGINT NOT NULL,
  decided_at VARCHAR(40) NOT NULL,
  note VARCHAR(2000) NOT NULL,
  PRIMARY KEY(kind,item_key)
);
CREATE TABLE t_security_selection_event (
  id VARCHAR(36) PRIMARY KEY,
  kind VARCHAR(8) NOT NULL,
  item_key VARCHAR(255) NOT NULL,
  operation VARCHAR(16) NOT NULL,
  actor BIGINT NOT NULL,
  recorded_at VARCHAR(40) NOT NULL,
  note VARCHAR(2000) NOT NULL,
  snapshot TEXT NOT NULL
);
CREATE INDEX idx_security_selection_event ON t_security_selection_event(kind,item_key,recorded_at,id);
CREATE INDEX idx_security_cve_candidates ON t_security_cve(cve_id,source_id);
CREATE INDEX idx_security_hash_candidates ON t_security_hash(sha256,source_id);
CREATE INDEX idx_security_rule_candidates ON t_security_rule(name,source_id);
CREATE TABLE t_security_selection_delivery (
  id INTEGER PRIMARY KEY CHECK(id=1),
  signature_release_id BIGINT NOT NULL DEFAULT 0,
  signature_pending INTEGER NOT NULL DEFAULT 0 CHECK(signature_pending IN (0,1)),
  rule_revision BIGINT NOT NULL DEFAULT 0,
  match_pending INTEGER NOT NULL DEFAULT 0 CHECK(match_pending IN (0,1))
);
INSERT INTO t_security_selection_delivery(id) VALUES (1);
