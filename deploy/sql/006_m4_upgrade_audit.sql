-- =====================================================================
-- 006 M4：Agent 灰度升级 + 平台操作审计 + 通知渠道
-- =====================================================================

-- Agent 升级包（docs/01 §6.4：上传 → 灰度下发 → 心跳上报新版本）
CREATE TABLE IF NOT EXISTS t_agent_upgrade_package (
    id            BIGSERIAL PRIMARY KEY,
    version       VARCHAR(64)  NOT NULL UNIQUE,     -- 包版本（如 1.2.0）
    platform      VARCHAR(32)  NOT NULL,            -- linux-amd64 / linux-arm64 / windows-amd64
    package_key   VARCHAR(200) NOT NULL,            -- 存储文件名（下载端点用）
    sha256        VARCHAR(64)  NOT NULL,
    size          BIGINT       NOT NULL,
    notes         TEXT,                             -- 发布说明
    uploaded_by   BIGINT,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- 平台操作审计（docs/01 §6.1：所有写操作入审计表，含来源 IP）
CREATE TABLE IF NOT EXISTS t_audit_log (
    id          BIGSERIAL PRIMARY KEY,
    uid         BIGINT,                             -- 操作人（null=匿名/Agent 通道）
    username    VARCHAR(64),
    method      VARCHAR(10) NOT NULL,               -- POST/PUT/DELETE
    path        VARCHAR(200) NOT NULL,
    body_digest VARCHAR(500),                       -- 请求体摘要（截断，不存敏感明文）
    source_ip   VARCHAR(64),
    status      INT          NOT NULL,              -- 响应码
    cost_ms     INT,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_audit_log_time ON t_audit_log (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_log_uid  ON t_audit_log (uid);

-- 通知渠道（M4：告警 webhook 通知；enabled 关闭时不发送）
CREATE TABLE IF NOT EXISTS t_notify_channel (
    id          BIGSERIAL PRIMARY KEY,
    name        VARCHAR(64)  NOT NULL,
    type        VARCHAR(16)  NOT NULL DEFAULT 'webhook',
    webhook_url TEXT         NOT NULL,
    min_severity SMALLINT    NOT NULL DEFAULT 3,    -- 通知门槛：≥high（4=critical）
    enabled     BOOLEAN      NOT NULL DEFAULT true,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- t_alert 补通知标记（已通知的告警不重复推送；失败由定时任务对未标记的重试）
ALTER TABLE t_alert ADD COLUMN IF NOT EXISTS notified BOOLEAN NOT NULL DEFAULT false;

-- RBAC 三角色补全（docs/01 §6.1）：安全运维角色（viewer 只读已在 002 初始化）
-- 权限点为声明式说明；接口级强制由 JwtAuthInterceptor 写权限矩阵执行
INSERT INTO t_role (id, name, permissions) VALUES
  (3, 'operator', '["*:view","scan:run","fix:apply","alert:handle","report:export"]'::jsonb)
ON CONFLICT (id) DO NOTHING;
