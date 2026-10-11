-- Immutable candidate documents, review decisions and task definitions.
CREATE TABLE t_baseline_package_gate (
  code TEXT PRIMARY KEY,
  revision BIGINT NOT NULL DEFAULT 0
);
CREATE TABLE t_baseline_package (
  id TEXT PRIMARY KEY,
  code TEXT NOT NULL,
  name TEXT NOT NULL,
  os_type INTEGER NOT NULL,
  product TEXT NOT NULL,
  supported_count INTEGER NOT NULL,
  unsupported_count INTEGER NOT NULL,
  version TEXT NOT NULL,
  content_sha256 TEXT NOT NULL,
  document TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'candidate'
    CHECK (status IN ('candidate','approved','published','withdrawn','rejected')),
  base_package_id TEXT,
  template_id BIGINT REFERENCES t_baseline_template(id),
  test_task_id BIGINT REFERENCES t_baseline_task(id),
  imported_by BIGINT,
  reviewed_by BIGINT,
  review_note TEXT,
  publication_note TEXT,
  created_at TEXT NOT NULL,
  reviewed_at TEXT,
  published_at TEXT,
  UNIQUE (code, version)
);
CREATE UNIQUE INDEX uq_baseline_package_active ON t_baseline_package(code) WHERE status='published';
ALTER TABLE t_baseline_item ADD COLUMN rule_id TEXT;
ALTER TABLE t_baseline_template ADD COLUMN package_id TEXT;
ALTER TABLE t_baseline_template ADD COLUMN os_version_pattern TEXT;
CREATE TABLE t_baseline_task_template (
  task_id BIGINT NOT NULL,
  template_id BIGINT NOT NULL,
  code TEXT NOT NULL,
  name TEXT NOT NULL,
  version TEXT NOT NULL,
  package_id TEXT,
  content_sha256 TEXT,
  PRIMARY KEY (task_id, template_id)
);
CREATE TABLE t_baseline_task_item (
  task_id BIGINT NOT NULL,
  item_id BIGINT NOT NULL,
  template_id BIGINT NOT NULL,
  code TEXT NOT NULL,
  name TEXT NOT NULL,
  category TEXT,
  severity INTEGER NOT NULL,
  "check" TEXT NOT NULL,
  remediation TEXT,
  fix_spec TEXT,
  rule_id TEXT,
  PRIMARY KEY (task_id, item_id)
);
CREATE TABLE t_baseline_task_expected (
  task_id BIGINT NOT NULL,
  agent_id TEXT NOT NULL,
  item_id BIGINT NOT NULL,
  PRIMARY KEY (task_id, agent_id, item_id)
);
-- Existing completed results retain the definitions available at upgrade time.
INSERT INTO t_baseline_task_item(task_id,item_id,template_id,code,name,category,severity,"check",remediation,fix_spec)
SELECT DISTINCT r.task_id,i.id,i.template_id,i.code,i.name,i.category,i.severity,
       CAST(i."check" AS TEXT),i.remediation,CAST(i.fix_spec AS TEXT)
FROM t_baseline_result r JOIN t_baseline_item i ON i.id=r.item_id;
INSERT INTO t_baseline_task_template(task_id,template_id,code,name,version,package_id,content_sha256)
SELECT DISTINCT i.task_id,t.id,t.code,t.name,t.version,NULL,NULL
FROM t_baseline_task_item i JOIN t_baseline_template t ON t.id=i.template_id;

-- Prefer the captured definition; the fallback serves tasks started before this migration.
CREATE VIEW v_baseline_result_definition AS
SELECT r.id AS result_id,r.item_id AS id,
       COALESCE(s.template_id,i.template_id) AS template_id,
       COALESCE(s.code,i.code) AS code,COALESCE(s.name,i.name) AS name,
       COALESCE(s.category,i.category) AS category,COALESCE(s.severity,i.severity) AS severity,
       CASE WHEN s.item_id IS NULL THEN CAST(i."check" AS TEXT) ELSE s."check" END AS "check",
       CASE WHEN s.item_id IS NULL THEN CAST(i.fix_spec AS TEXT) ELSE s.fix_spec END AS fix_spec,
       COALESCE(s.rule_id,i.rule_id) AS rule_id,
       COALESCE(st.version,t.version) AS template_version,st.package_id,st.content_sha256,
       (t.enabled AND (s.item_id IS NULL OR
         (s."check"=CAST(i."check" AS TEXT) AND COALESCE(s.fix_spec,'')=COALESCE(CAST(i.fix_spec AS TEXT),'')))) AS fix_current
FROM t_baseline_result r
LEFT JOIN t_baseline_task_item s ON s.task_id=r.task_id AND s.item_id=r.item_id
LEFT JOIN t_baseline_item i ON i.id=r.item_id
LEFT JOIN t_baseline_template t ON t.id=i.template_id
LEFT JOIN t_baseline_task_template st ON st.task_id=r.task_id AND st.template_id=COALESCE(s.template_id,i.template_id);
