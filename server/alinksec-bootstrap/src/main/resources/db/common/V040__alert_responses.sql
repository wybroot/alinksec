CREATE TABLE t_alert_response (
    command_id TEXT PRIMARY KEY,
    alert_id BIGINT NOT NULL REFERENCES t_alert(id),
    agent_id TEXT NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('isolate','restore')),
    evidence TEXT NOT NULL,
    created_by BIGINT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_alert_response_alert ON t_alert_response(alert_id,created_at);
