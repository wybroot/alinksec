-- ============================================================
-- ALinkSec M3(05-扩展能力) 勒索诱饵防护
-- 范围：防护策略域（docs/03 §t_protect_rule）
-- 依赖：001_m1_init.sql
-- 说明：Agent 侧诱饵参数走本地 agent.yml（本地秒级响应不依赖服务端在线），
--       本表为平台侧规则源与展示（拦截记录复用 t_alert，不新建事件表）
-- ============================================================

CREATE TABLE IF NOT EXISTS t_protect_rule (
  id         BIGSERIAL PRIMARY KEY,
  rule_id    VARCHAR(64) NOT NULL UNIQUE,       -- PR-0010
  name       VARCHAR(128) NOT NULL,
  type       VARCHAR(32) NOT NULL,              -- process/file_integrity/login/decoy/ransom_behavior
  match      JSONB NOT NULL,                    -- 匹配条件（dirs/count_per_dir/exclude_exes 等）
  actions    JSONB NOT NULL,                    -- ["kill","alert"]
  severity   SMALLINT NOT NULL DEFAULT 3,       -- 1低 2中 3高 4严重
  enabled    BOOLEAN NOT NULL DEFAULT TRUE,
  built_in   BOOLEAN NOT NULL DEFAULT FALSE,
  version    BIGINT NOT NULL DEFAULT 1,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 内置规则：诱饵防护 / 加密行为分析（docs/05 §2，match 字段同时作为前端编辑源）
INSERT INTO t_protect_rule (rule_id, name, type, match, actions, severity, enabled, built_in) VALUES
  ('PR-0010', '勒索诱饵防护', 'decoy',
   '{"dirs":["/home","/srv","/opt"],"count_per_dir":4,"exclude_exes":["/usr/bin/rsync","D:\\\\backup\\\\agent.exe"]}'::jsonb,
   '["kill","alert"]'::jsonb, 4, TRUE, TRUE),
  ('PR-0011', '加密行为分析', 'ransom_behavior',
   '{"rate_window_sec":10,"rate_threshold":50,"ext_change_ratio":0.8}'::jsonb,
   '["kill","alert"]'::jsonb, 4, TRUE, TRUE)
ON CONFLICT (rule_id) DO NOTHING;

-- 策略版本与全量快照（单行表；t_protect_rule 变更 → version 递增 + content 重建，PolicySync 热下发）
CREATE TABLE IF NOT EXISTS t_policy_state (
  id         INT PRIMARY KEY DEFAULT 1 CHECK (id = 1),   -- 单行约束
  version    BIGINT NOT NULL DEFAULT 1,                  -- 策略版本（Agent 心跳 policy_version 比对）
  content    JSONB  NOT NULL DEFAULT '{}'::jsonb,        -- 全量策略快照（policy_json：decoy 段等）
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO t_policy_state (id, version) VALUES (1, 1) ON CONFLICT (id) DO NOTHING;
