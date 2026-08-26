-- =============================================================
-- ALinkSec 003：M2 指标/日志补充表
-- =============================================================

-- Agent 采集日志（LOG_BATCH 落库；登录/安全日志，供排障与入侵检测回溯）
CREATE TABLE IF NOT EXISTS t_agent_log (
    id          BIGSERIAL PRIMARY KEY,
    agent_id    VARCHAR(64)  NOT NULL,
    source      VARCHAR(64)  NOT NULL,                 -- secure / windows-security / custom:<path>
    content     VARCHAR(4000) NOT NULL,                -- 单行内容（超长已在 Agent 侧截断）
    fields      JSONB,                                 -- 结构化字段（解析后，可空）
    log_ts      BIGINT       NOT NULL,                 -- 行时间戳（ms）
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_agent_log_agent_time ON t_agent_log (agent_id, log_ts DESC);
CREATE INDEX IF NOT EXISTS idx_agent_log_source     ON t_agent_log (source);
