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
    description TEXT NOT NULL DEFAULT '',
    created_by BIGINT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_response_rule_type ON t_response_rule(alert_type, min_severity, enabled);

-- 扩充 t_alert_response 支持 kill_process, block_ip, timeout_reversal
-- 在 SQLite 中如果已有表定义，通过兼容迁移或独立记录
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
    reversal_scheduled_at TEXT,
    reversal_executed_at TEXT,
    reversal_command_id VARCHAR(64),
    created_by BIGINT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_response_exec_alert ON t_response_execution(alert_id, created_at);
CREATE INDEX IF NOT EXISTS idx_response_exec_reversal ON t_response_execution(status, reversal_scheduled_at);
