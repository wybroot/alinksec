-- Preserve explicit execution outcomes separately from noncompliance.
ALTER TABLE t_baseline_result ADD COLUMN execution_status TEXT NOT NULL DEFAULT 'legacy'
  CHECK (execution_status IN ('pass','fail','error','legacy'));
ALTER TABLE t_baseline_result ADD COLUMN duration_ms BIGINT NOT NULL DEFAULT 0;
ALTER TABLE t_baseline_summary ADD COLUMN error_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE t_baseline_summary ADD COLUMN legacy_count INTEGER NOT NULL DEFAULT 0;
UPDATE t_baseline_summary SET legacy_count=total;
CREATE INDEX idx_baseline_expected_agent_item ON t_baseline_task_expected(agent_id,item_id,task_id DESC);
CREATE INDEX idx_baseline_result_agent_item ON t_baseline_result(agent_id,item_id,task_id DESC,id DESC);

DROP VIEW v_baseline_result_definition;
CREATE VIEW v_baseline_result_definition AS
SELECT r.id AS result_id,r.item_id AS id,
       COALESCE(s.template_id,i.template_id) AS template_id,
       COALESCE(s.code,i.code) AS code,COALESCE(s.name,i.name) AS name,
       COALESCE(s.category,i.category) AS category,COALESCE(s.severity,i.severity) AS severity,
       CASE WHEN s.item_id IS NULL THEN CAST(i."check" AS TEXT) ELSE s."check" END AS "check",
       CASE WHEN s.item_id IS NULL THEN CAST(i.fix_spec AS TEXT) ELSE s.fix_spec END AS fix_spec,
       COALESCE(s.rule_id,i.rule_id) AS rule_id,
       COALESCE(st.version,t.version) AS template_version,st.package_id,st.content_sha256,
       (t.enabled AND i.enabled AND r.execution_status = 'fail' AND s.item_id IS NOT NULL
         AND s."check"=CAST(i."check" AS TEXT) AND COALESCE(s.fix_spec,'')=COALESCE(CAST(i.fix_spec AS TEXT),'')
         AND NOT EXISTS (SELECT 1 FROM t_baseline_task_expected newer
           WHERE newer.agent_id=r.agent_id AND newer.item_id=r.item_id AND newer.task_id>r.task_id)) AS fix_current
FROM t_baseline_result r
LEFT JOIN t_baseline_task_item s ON s.task_id=r.task_id AND s.item_id=r.item_id
LEFT JOIN t_baseline_item i ON i.id=r.item_id
LEFT JOIN t_baseline_template t ON t.id=i.template_id
LEFT JOIN t_baseline_task_template st ON st.task_id=r.task_id AND st.template_id=COALESCE(s.template_id,i.template_id);
