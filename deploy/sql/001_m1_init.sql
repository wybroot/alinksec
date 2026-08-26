-- ALinkSec M1 初始化（资产域核心表 + 系统域 + 告警域 + 上报去重表）
-- 完整 schema 见 docs/03-数据库设计.md，M2 补齐基线/扫描/病毒/修复域

-- ============ 资产域 ============
CREATE TABLE IF NOT EXISTS t_host_group (
  id          BIGSERIAL PRIMARY KEY,
  name        VARCHAR(128) NOT NULL UNIQUE,
  parent_id   BIGINT,
  description VARCHAR(512)
);

CREATE TABLE IF NOT EXISTS t_agent (
  id             BIGSERIAL PRIMARY KEY,
  agent_id       VARCHAR(64)  NOT NULL UNIQUE,
  hostname       VARCHAR(255) NOT NULL,
  ip             VARCHAR(64),
  os_type        SMALLINT     NOT NULL,
  os_version     VARCHAR(128),
  kernel         VARCHAR(128),
  arch           VARCHAR(16),
  agent_version  VARCHAR(32),
  machine_id     VARCHAR(128),
  group_id       BIGINT       REFERENCES t_host_group(id),
  status         SMALLINT     NOT NULL DEFAULT 0,
  protect_enabled BOOLEAN      NOT NULL DEFAULT TRUE,
  policy_version VARCHAR(32),
  cert_serial    VARCHAR(64),
  last_heartbeat TIMESTAMPTZ,
  tags           JSONB        NOT NULL DEFAULT '{}',
  created_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
  updated_at     TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_agent_group ON t_agent(group_id);
CREATE INDEX IF NOT EXISTS idx_agent_status ON t_agent(status);
CREATE UNIQUE INDEX IF NOT EXISTS uq_agent_machine ON t_agent(machine_id) WHERE machine_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS t_asset_software (
  id           BIGSERIAL PRIMARY KEY,
  agent_id     VARCHAR(64) NOT NULL,
  name         VARCHAR(255) NOT NULL,
  version      VARCHAR(64),
  vendor       VARCHAR(255),
  install_time TIMESTAMPTZ,
  source       VARCHAR(32),
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_sw_agent ON t_asset_software(agent_id);
CREATE INDEX IF NOT EXISTS idx_sw_name  ON t_asset_software(name, version);

CREATE TABLE IF NOT EXISTS t_asset_port (
  id        BIGSERIAL PRIMARY KEY,
  agent_id  VARCHAR(64) NOT NULL,
  port      INTEGER NOT NULL,
  protocol  VARCHAR(8)  NOT NULL,
  process   VARCHAR(255),
  bind_addr VARCHAR(64),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_port_agent ON t_asset_port(agent_id);

CREATE TABLE IF NOT EXISTS t_asset_account (
  id          BIGSERIAL PRIMARY KEY,
  agent_id    VARCHAR(64) NOT NULL,
  name        VARCHAR(128) NOT NULL,
  uid         INTEGER,
  gid         INTEGER,
  shell       VARCHAR(128),
  login_enabled BOOLEAN,
  last_login  TIMESTAMPTZ,
  risky       BOOLEAN DEFAULT FALSE,
  risky_reason VARCHAR(512),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(agent_id, name)
);

-- ============ 告警域 ============
CREATE TABLE IF NOT EXISTS t_alert (
  id          BIGSERIAL PRIMARY KEY,
  alert_no    VARCHAR(64) NOT NULL UNIQUE,
  agent_id    VARCHAR(64),
  rule_id     VARCHAR(64),
  event_type  VARCHAR(32) NOT NULL,
  severity    SMALLINT NOT NULL,
  title       VARCHAR(255) NOT NULL,
  detail      JSONB NOT NULL,
  action_taken VARCHAR(255),
  status      SMALLINT NOT NULL DEFAULT 0,
  assignee    BIGINT,
  count       INTEGER NOT NULL DEFAULT 1,
  first_time  TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_time   TIMESTAMPTZ NOT NULL DEFAULT now(),
  handle_remark TEXT,
  handled_by   BIGINT,
  handled_at   TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_alert_status ON t_alert(status, severity);
CREATE INDEX IF NOT EXISTS idx_alert_agent ON t_alert(agent_id, last_time DESC);

-- ============ 系统域 ============
CREATE TABLE IF NOT EXISTS t_enroll_token (
  id         BIGSERIAL PRIMARY KEY,
  token      VARCHAR(64) NOT NULL UNIQUE,
  max_uses   INTEGER NOT NULL DEFAULT 100,
  used_count INTEGER NOT NULL DEFAULT 0,
  expire_at  TIMESTAMPTZ NOT NULL,
  created_by BIGINT,
  status     SMALLINT NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS t_command (
  id          BIGSERIAL PRIMARY KEY,
  cmd_id      VARCHAR(64) NOT NULL UNIQUE,
  agent_id    VARCHAR(64) NOT NULL,
  type        VARCHAR(32) NOT NULL,
  payload     JSONB NOT NULL,
  status      SMALLINT NOT NULL DEFAULT 0,
  result      JSONB,
  retry_count SMALLINT NOT NULL DEFAULT 0,
  issued_by   BIGINT,
  acked_at    TIMESTAMPTZ,
  finished_at TIMESTAMPTZ,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_cmd_agent_status ON t_command(agent_id, status);

-- ============ 上报去重（report_id 幂等，M2 迁 Redis） ============
CREATE TABLE IF NOT EXISTS t_report_dedup (
  report_id  VARCHAR(64) PRIMARY KEY,
  expire_at  TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_report_dedup_expire ON t_report_dedup(expire_at);
