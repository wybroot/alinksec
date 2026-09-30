-- Upgrade databases created before the versioned migration runner was introduced.

CREATE TABLE IF NOT EXISTS t_asset_process (
  id BIGSERIAL PRIMARY KEY, agent_id VARCHAR(64) NOT NULL, pid INTEGER NOT NULL,
  name VARCHAR(255), exe TEXT, cmdline TEXT, username VARCHAR(255),
  rss_bytes BIGINT NOT NULL DEFAULT 0, updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(agent_id, pid)
);
CREATE INDEX IF NOT EXISTS idx_process_agent_rss ON t_asset_process(agent_id, rss_bytes DESC);

CREATE TABLE IF NOT EXISTS t_asset_container (
  id BIGSERIAL PRIMARY KEY, agent_id VARCHAR(64) NOT NULL, container_id VARCHAR(128) NOT NULL,
  name VARCHAR(255), image VARCHAR(512), image_id VARCHAR(128),
  orchestrator VARCHAR(32) NOT NULL DEFAULT 'docker', namespace VARCHAR(255), status VARCHAR(255),
  created_at TIMESTAMPTZ, started_at TIMESTAMPTZ, ports JSONB NOT NULL DEFAULT '[]',
  labels JSONB NOT NULL DEFAULT '{}', risky BOOLEAN NOT NULL DEFAULT FALSE,
  risk_reasons JSONB NOT NULL DEFAULT '[]', updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(agent_id, container_id)
);
ALTER TABLE t_asset_container ADD COLUMN IF NOT EXISTS risky BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE t_asset_container ADD COLUMN IF NOT EXISTS risk_reasons JSONB NOT NULL DEFAULT '[]';
ALTER TABLE t_asset_container ADD COLUMN IF NOT EXISTS orchestrator VARCHAR(32) NOT NULL DEFAULT 'docker';
ALTER TABLE t_asset_container ADD COLUMN IF NOT EXISTS namespace VARCHAR(255);
CREATE INDEX IF NOT EXISTS idx_container_agent ON t_asset_container(agent_id);
CREATE INDEX IF NOT EXISTS idx_container_orchestrator ON t_asset_container(orchestrator, namespace);

CREATE TABLE IF NOT EXISTS t_alert_notify_delivery (
  id BIGSERIAL PRIMARY KEY, alert_no VARCHAR(64) NOT NULL, channel_id BIGINT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0, attempted_at TIMESTAMPTZ, delivered_at TIMESTAMPTZ,
  last_error TEXT, UNIQUE (alert_no, channel_id)
);
CREATE INDEX IF NOT EXISTS idx_alert_notify_pending
  ON t_alert_notify_delivery (delivered_at, attempted_at);

ALTER TABLE t_agent ADD COLUMN IF NOT EXISTS isolation_status SMALLINT NOT NULL DEFAULT 0;
ALTER TABLE t_agent ADD COLUMN IF NOT EXISTS isolation_command_id VARCHAR(64);
ALTER TABLE t_agent ADD COLUMN IF NOT EXISTS isolation_error VARCHAR(512);
ALTER TABLE t_agent ADD COLUMN IF NOT EXISTS isolation_updated_at TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS idx_agent_isolation_status ON t_agent(isolation_status);

WITH inserted AS (
  INSERT INTO t_protect_rule (rule_id, name, type, match, actions, severity, enabled, built_in)
  VALUES ('PR-0001', 'EDR miner process block', 'process',
          '{"exe_regex":"(?i)(^|/)(xmrig|minerd|kdevtmpfsi|kinsing)$"}'::jsonb,
          '["kill","alert"]'::jsonb, 4, TRUE, TRUE)
  ON CONFLICT (rule_id) DO NOTHING
  RETURNING 1
)
UPDATE t_policy_state SET content = '{}'::jsonb, updated_at = now()
WHERE id = 1 AND EXISTS (SELECT 1 FROM inserted);

UPDATE t_audit_log SET body_digest = NULL WHERE body_digest IS NOT NULL;
