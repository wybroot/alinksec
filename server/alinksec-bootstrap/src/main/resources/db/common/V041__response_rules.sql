CREATE TABLE IF NOT EXISTS t_system_config (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    property_key VARCHAR(128) NOT NULL UNIQUE,
    property_value TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_system_config_key ON t_system_config(property_key);

CREATE TABLE IF NOT EXISTS t_response_rule (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name VARCHAR(128) NOT NULL,
    alert_type VARCHAR(64) NOT NULL,
    min_severity SMALLINT NOT NULL DEFAULT 3,
    trigger_rule_id VARCHAR(128) NOT NULL DEFAULT '',
    host_tag VARCHAR(64) NOT NULL DEFAULT '',
    action VARCHAR(32) NOT NULL CHECK (action IN ('isolate_host', 'restore_isolation', 'kill_process', 'block_ip')),
    location VARCHAR(32) NOT NULL DEFAULT 'local' CHECK (location IN ('local', 'server', 'agent')),
    target_agent_id VARCHAR(64) NOT NULL DEFAULT '',
    timeout_sec INTEGER NOT NULL DEFAULT 0,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    require_admin_auth BOOLEAN NOT NULL DEFAULT FALSE,
    approved_by BIGINT,
    approved_at TIMESTAMP,
    description TEXT NOT NULL DEFAULT '',
    created_by BIGINT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_response_rule_type ON t_response_rule(alert_type, min_severity, enabled);

CREATE TABLE IF NOT EXISTS t_response_execution (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    command_id VARCHAR(64) NOT NULL UNIQUE,
    alert_id BIGINT NOT NULL,
    agent_id VARCHAR(64) NOT NULL,
    rule_id BIGINT REFERENCES t_response_rule(id),
    action VARCHAR(32) NOT NULL,
    target VARCHAR(255) NOT NULL DEFAULT '',
    status VARCHAR(32) NOT NULL DEFAULT 'dispatched',
    evidence TEXT NOT NULL,
    reversal_scheduled_at TIMESTAMP,
    reversal_dispatched_at TIMESTAMP,
    reversal_executed_at TIMESTAMP,
    reversal_command_id VARCHAR(64),
    reversal_status VARCHAR(32),
    created_by BIGINT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_response_exec_alert ON t_response_execution(alert_id, created_at);
CREATE INDEX IF NOT EXISTS idx_response_exec_reversal ON t_response_execution(status, reversal_scheduled_at);

INSERT INTO t_protect_rule (rule_id, name, type, match, actions, severity, enabled, built_in) VALUES
  ('PR-0005', '反弹 Shell 行为检测', 'process',
   '{"platforms":["linux"],"cmdline_regex":"(?i)(?:bash|sh|zsh|dash)\\s+.*(?:-i\\s+.*>&|/dev/tcp/[0-9.]+/|nc\\s+.*-e\\s+/(?:bin/)?(?:ba)?sh|socat\\s+exec:.*pty|pty\\.spawn\\()"}',
   '["alert"]', 4, TRUE, TRUE),
  ('PR-0006', '非交互式远程工具衍生', 'process',
   '{"platforms":["linux"],"exe_regex":"(?i)(^|/)(ncat|socat|chisel|frpc|frps|gost)$"}',
   '["alert"]', 3, TRUE, TRUE),
  ('PR-0007', '常见渗透与 C2 工具特征', 'process',
   '{"platforms":["linux","windows"],"exe_regex":"(?i)(?:^|[/\\\\])(?:fscan|mimikatz|bloodhound|sliver-client|havoc)(?:\\\\.exe)?$"}',
   '["alert"]', 4, TRUE, TRUE),
  ('PR-0008', '恶意持久化与历史清除', 'process',
   '{"platforms":["linux"],"cmdline_regex":"(?i)(?:rm\\s+-[a-zA-Z]*f?[a-zA-Z]*\\s+.*(?:/\\.bash_history|/\\.zsh_history)|history\\s+-c|unset\\s+HISTFILE|export\\s+HISTSIZE=0|echo\\s+.*>>\\s*/var/spool/cron/|echo\\s+.*>>\\s*/etc/crontab)"}',
   '["alert"]', 3, TRUE, TRUE)
ON CONFLICT (rule_id) DO NOTHING;
