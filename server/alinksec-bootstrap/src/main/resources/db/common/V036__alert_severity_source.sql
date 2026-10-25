-- Keep historical raw values and their previous interpretation; their source
-- cannot be reconstructed reliably. New events declare their wire contract.
ALTER TABLE t_alert ADD COLUMN severity_source VARCHAR(32) NOT NULL DEFAULT 'legacy_unclassified'
  CHECK (severity_source IN ('legacy_unclassified', 'agent_proto_v1'));

CREATE VIEW v_alert_severity AS
SELECT a.*,
  CASE WHEN severity_source = 'agent_proto_v1' THEN
    CASE WHEN severity BETWEEN 1 AND 5 THEN severity - 1 ELSE -1 END
  ELSE
    CASE WHEN severity BETWEEN 1 AND 4 THEN severity WHEN severity = 5 THEN 4 ELSE -1 END
  END AS severity_level
FROM t_alert a;
