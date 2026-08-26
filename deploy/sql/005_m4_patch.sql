-- ============================================================
-- M4 软件包类漏洞修复（docs/05 §3.3/§3.4）
-- ============================================================

-- 离线补丁仓库清单（文件落平台存储目录，t_patch_package 记元数据；
-- 导入为实施/运维离线操作，SOW 明确约定）
CREATE TABLE IF NOT EXISTS t_patch_package (
  id             BIGSERIAL PRIMARY KEY,
  os_type        SMALLINT NOT NULL,              -- 1 Linux 2 Windows
  os_version     VARCHAR(64) NOT NULL DEFAULT '',-- centos7 / ubuntu2204 / win2019（空 = 通用）
  pkg_name       VARCHAR(255) NOT NULL,          -- openssl / openssl-devel / KB5034441
  target_version VARCHAR(128) NOT NULL,          -- 1.1.1k-26.el7_9（rpm/deb 完整版本；msu 为 KB 号）
  repo_type      VARCHAR(8)  NOT NULL,           -- rpm / deb / msu
  filename       VARCHAR(255) NOT NULL,          -- 存储文件名（下载端点按名取件）
  sha256         VARCHAR(64)  NOT NULL,
  size           BIGINT NOT NULL DEFAULT 0,
  imported_by    BIGINT,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (os_type, os_version, pkg_name, target_version)
);
CREATE INDEX IF NOT EXISTS idx_patch_pkg ON t_patch_package(pkg_name);

-- 修复任务审批与维护窗口（软件包类必填审批；配置类沿用现有字段不受影响）
ALTER TABLE t_fix_task ADD COLUMN IF NOT EXISTS approver     VARCHAR(128);
ALTER TABLE t_fix_task ADD COLUMN IF NOT EXISTS approved     BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE t_fix_task ADD COLUMN IF NOT EXISTS approved_at  TIMESTAMPTZ;
ALTER TABLE t_fix_task ADD COLUMN IF NOT EXISTS window_start TIMESTAMPTZ;  -- 维护窗口起（空 = 审批后立即执行）
ALTER TABLE t_fix_task ADD COLUMN IF NOT EXISTS window_end   TIMESTAMPTZ;
ALTER TABLE t_fix_task ADD COLUMN IF NOT EXISTS dispatched_at TIMESTAMPTZ; -- 实际派发时间（窗口调度判定）
-- type 扩展：1配置类 2软件包类；status 语义扩展：0待执行/待审批
COMMENT ON COLUMN t_fix_task.type IS '1配置类 2软件包类';
