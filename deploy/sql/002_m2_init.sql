-- ============================================================
-- ALinkSec M2 初始化脚本
-- 范围：基线核查域 / 安全扫描域 / 病毒查杀域 / 修复域 / 用户权限域
-- 依赖：001_m1_init.sql（t_agent / t_alert / t_command 等基础表）
-- 说明：docker-compose 首次启动自动执行；已有环境手动补跑即可（幂等：ON CONFLICT / IF NOT EXISTS）
-- ============================================================

-- ------------------------------------------------------------
-- 0. 用户权限域（REST 登录）
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS t_role (
  id          BIGSERIAL PRIMARY KEY,
  name        VARCHAR(64) NOT NULL UNIQUE,
  permissions JSONB       NOT NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS t_user (
  id             BIGSERIAL PRIMARY KEY,
  username       VARCHAR(64) NOT NULL UNIQUE,
  password_hash  VARCHAR(128) NOT NULL,          -- bcrypt（由服务端启动时种子生成）
  real_name      VARCHAR(64),
  role_id        BIGINT      NOT NULL REFERENCES t_role(id),
  status         SMALLINT    NOT NULL DEFAULT 1, -- 1启用 0禁用
  last_login_at  TIMESTAMPTZ,
  last_login_ip  VARCHAR(64),
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS t_audit_log (
  id         BIGSERIAL PRIMARY KEY,
  user_id    BIGINT,
  username   VARCHAR(64),
  action     VARCHAR(64) NOT NULL,               -- login/logout/task_create/...
  target     VARCHAR(255),
  detail     JSONB,
  source_ip  VARCHAR(64),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_audit_time ON t_audit_log(created_at DESC);

INSERT INTO t_role (id, name, permissions) VALUES
  (1, 'admin', '["*"]'::jsonb),
  (2, 'viewer', '["asset:view","baseline:view","vuln:view","virus:view","alert:view"]'::jsonb)
ON CONFLICT (id) DO NOTHING;

-- ------------------------------------------------------------
-- 1. 基线核查域
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS t_baseline_template (
  id         BIGSERIAL PRIMARY KEY,
  code       VARCHAR(64) NOT NULL UNIQUE,
  name       VARCHAR(128) NOT NULL,
  standard   VARCHAR(64),
  os_type    SMALLINT NOT NULL,
  version    VARCHAR(32) NOT NULL DEFAULT '1.0',
  item_count INTEGER  NOT NULL DEFAULT 0,
  enabled    BOOLEAN  NOT NULL DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS t_baseline_item (
  id          BIGSERIAL PRIMARY KEY,
  template_id BIGINT NOT NULL REFERENCES t_baseline_template(id),
  code        VARCHAR(64) NOT NULL,
  name        VARCHAR(255) NOT NULL,
  category    VARCHAR(64),
  severity    SMALLINT NOT NULL,                 -- 1低 2中 3高 4严重
  check       JSONB   NOT NULL,                  -- Agent 端解释执行（热更新）
  remediation TEXT,
  fix_spec    JSONB,                             -- 可自动修复步骤（NULL=不可自动修复）
  enabled     BOOLEAN NOT NULL DEFAULT TRUE,
  UNIQUE (template_id, code)
);

CREATE TABLE IF NOT EXISTS t_baseline_task (
  id           BIGSERIAL PRIMARY KEY,
  task_no      VARCHAR(64) NOT NULL UNIQUE,
  name         VARCHAR(128),
  scope        JSONB NOT NULL,                   -- {"group_ids":[],"agent_ids":[]}
  template_ids BIGINT[] NOT NULL,
  status       SMALLINT NOT NULL DEFAULT 0,      -- 0待执行 1执行中 2完成 3部分失败 4取消
  progress     SMALLINT NOT NULL DEFAULT 0,
  created_by   BIGINT,
  started_at   TIMESTAMPTZ,
  finished_at  TIMESTAMPTZ,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS t_baseline_result (
  id         BIGSERIAL PRIMARY KEY,
  task_id    BIGINT NOT NULL,
  agent_id   VARCHAR(64) NOT NULL,
  item_id    BIGINT NOT NULL,
  passed     BOOLEAN NOT NULL,
  actual     TEXT,
  message    TEXT,                -- 失败原因（Agent 检查引擎产出）
  checked_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_bl_result ON t_baseline_result(task_id, agent_id);
CREATE INDEX IF NOT EXISTS idx_bl_result_fail ON t_baseline_result(task_id) WHERE passed = FALSE;

CREATE TABLE IF NOT EXISTS t_baseline_summary (
  task_id      BIGINT NOT NULL,
  agent_id     VARCHAR(64) NOT NULL,
  total        INTEGER NOT NULL,
  passed_count INTEGER NOT NULL,
  failed_count INTEGER NOT NULL,
  score        NUMERIC(5,2) NOT NULL,
  checked_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (task_id, agent_id)
);

-- ------------------------------------------------------------
-- 2. 安全扫描域（漏洞 / 弱口令）
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS t_scan_task (
  id         BIGSERIAL PRIMARY KEY,
  task_no    VARCHAR(64) NOT NULL UNIQUE,
  name       VARCHAR(128),
  type       SMALLINT NOT NULL,                  -- 1漏洞 2弱口令 3端口服务（可组合）
  scope      JSONB NOT NULL,
  status     SMALLINT NOT NULL DEFAULT 0,
  progress   SMALLINT NOT NULL DEFAULT 0,
  created_by BIGINT,
  started_at TIMESTAMPTZ,
  finished_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS t_vuln_finding (
  id                BIGSERIAL PRIMARY KEY,
  task_id           BIGINT NOT NULL,
  agent_id          VARCHAR(64) NOT NULL,
  cve_id            VARCHAR(32) NOT NULL,
  software          VARCHAR(255) NOT NULL,
  installed_version VARCHAR(64),
  fixed_version     VARCHAR(64),
  severity          SMALLINT NOT NULL,
  cvss              NUMERIC(3,1),
  status            SMALLINT NOT NULL DEFAULT 0, -- 0新增 1已确认 2已忽略 3已修复
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_vuln_task ON t_vuln_finding(task_id);
CREATE INDEX IF NOT EXISTS idx_vuln_agent ON t_vuln_finding(agent_id, status);

CREATE TABLE IF NOT EXISTS t_weakpwd_finding (
  id         BIGSERIAL PRIMARY KEY,
  task_id    BIGINT NOT NULL,
  agent_id   VARCHAR(64) NOT NULL,
  account    VARCHAR(128) NOT NULL,
  type       VARCHAR(32) NOT NULL,               -- system_empty / system_weak / uid0_nonroot / pwd_stale
  remark     VARCHAR(255),                      -- 补充说明（如 pwd_stale 的未修改天数）
  status     SMALLINT NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS t_port_finding (
  id           BIGSERIAL PRIMARY KEY,
  task_id      BIGINT NOT NULL,
  agent_id     VARCHAR(64) NOT NULL,
  port         INTEGER NOT NULL,
  protocol     VARCHAR(8)  NOT NULL,
  process      VARCHAR(255),
  service      VARCHAR(64),                          -- 指纹识别出的服务名
  risky        BOOLEAN NOT NULL DEFAULT FALSE,
  risky_reason VARCHAR(512),
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_port_finding_agent ON t_port_finding(agent_id);
CREATE INDEX IF NOT EXISTS idx_port_finding_task ON t_port_finding(task_id);

CREATE TABLE IF NOT EXISTS t_cve_db (
  cve_id       VARCHAR(32) PRIMARY KEY,
  title        VARCHAR(512),
  severity     SMALLINT NOT NULL,
  cvss         NUMERIC(3,1),
  affected     JSONB NOT NULL,                   -- [{"name":"openssl","vrange":"<1.1.1k","os":"centos7"}]
  description  TEXT,
  published_at TIMESTAMPTZ,
  imported_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_cve_name ON t_cve_db USING GIN (affected jsonb_path_ops);

-- ------------------------------------------------------------
-- 3. 病毒查杀域
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS t_virus_db (
  id          BIGSERIAL PRIMARY KEY,
  db_version  VARCHAR(32) NOT NULL UNIQUE,
  package_key VARCHAR(512) NOT NULL,             -- 特征包文件 key（本地存储路径标识）
  sha256      VARCHAR(64) NOT NULL,
  size        BIGINT,
  hash_count  INTEGER,
  rule_count  INTEGER,
  imported_by BIGINT,
  imported_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS t_virus_scan_task (
  id         BIGSERIAL PRIMARY KEY,
  task_no    VARCHAR(64) NOT NULL UNIQUE,
  name       VARCHAR(128),
  mode       SMALLINT NOT NULL,                  -- 1快速 2全盘 3自定义
  scope      JSONB NOT NULL,
  status     SMALLINT NOT NULL DEFAULT 0,
  progress   SMALLINT NOT NULL DEFAULT 0,
  created_by BIGINT,
  started_at TIMESTAMPTZ,
  finished_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS t_virus_finding (
  id           BIGSERIAL PRIMARY KEY,
  task_id      BIGINT,                           -- NULL=实时防护检出
  agent_id     VARCHAR(64) NOT NULL,
  path         VARCHAR(512) NOT NULL,
  name         VARCHAR(255) NOT NULL,
  sha256       VARCHAR(64) NOT NULL,
  size         BIGINT,
  engine       VARCHAR(16) NOT NULL,             -- hash / yara
  severity     SMALLINT NOT NULL,
  action_taken VARCHAR(32),                      -- quarantined / deleted / alert_only
  status       SMALLINT NOT NULL DEFAULT 0,      -- 0新增 1已隔离 2已删除 3已恢复 4已加白
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_virus_agent ON t_virus_finding(agent_id, status);

CREATE TABLE IF NOT EXISTS t_virus_whitelist (
  id         BIGSERIAL PRIMARY KEY,
  type       VARCHAR(16) NOT NULL,               -- path / hash
  value      VARCHAR(512) NOT NULL,
  remark     VARCHAR(255),
  created_by BIGINT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ------------------------------------------------------------
-- 4. 修复域（M2 配置类；软件包类 M4）
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS t_fix_task (
  id           BIGSERIAL PRIMARY KEY,
  task_no      VARCHAR(64) NOT NULL UNIQUE,
  name         VARCHAR(128),
  type         SMALLINT NOT NULL,                -- 1配置类
  scope        JSONB NOT NULL,
  targets      JSONB NOT NULL,                   -- [{ref_type:"baseline_item", ref_id, fix_payload}]
  status       SMALLINT NOT NULL DEFAULT 0,      -- 0待执行 1执行中 2完成 3部分失败 4已取消
  created_by   BIGINT,
  started_at   TIMESTAMPTZ,
  finished_at  TIMESTAMPTZ,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS t_fix_record (
  id          BIGSERIAL PRIMARY KEY,
  task_id     BIGINT NOT NULL,
  agent_id    VARCHAR(64) NOT NULL,
  ref_id      VARCHAR(64) NOT NULL,
  ref_type    VARCHAR(16) NOT NULL,
  status      SMALLINT NOT NULL DEFAULT 0,       -- 0待执行 1成功 2失败已回滚 3失败未回滚 4跳过 5复核未通过
  log         TEXT,
  finished_at TIMESTAMPTZ,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_fix_record ON t_fix_record(task_id, agent_id);

-- ------------------------------------------------------------
-- 增量补丁（已有环境补跑；新环境建表已含）
-- ------------------------------------------------------------
ALTER TABLE t_weakpwd_finding ADD COLUMN IF NOT EXISTS remark VARCHAR(255);

-- ============================================================
-- 种子数据
-- ============================================================

-- ------------------------------------------------------------
-- 等保 2.0 服务器 Linux 基线模板（60 项）
-- check 规范见 docs/04 §3.2：file_line / file_content / file_perm / cmd_output
-- fix_spec 规范见 docs/05 §3.2：sysctl_set / file_line_ensure / chmod / service_restart
-- ------------------------------------------------------------
INSERT INTO t_baseline_template (id, code, name, standard, os_type, version, item_count)
VALUES (1, 'DJBH2.0-LINUX', '等保 2.0 服务器基线（Linux）', '等保2.0', 1, '1.0', 60)
ON CONFLICT (id) DO NOTHING;

-- ---------- 身份鉴别（10 项）----------
INSERT INTO t_baseline_item (template_id, code, name, category, severity, check, remediation, fix_spec) VALUES
(1,'BL-LINUX-0001','口令最小长度不小于 8 位','身份鉴别',3,
 '{"type":"file_content","target":"/etc/login.defs","regex":"^\\s*PASS_MIN_LEN\\s+([8-9]|[1-9]\\d+)\\s*$"}',
 '在 /etc/login.defs 中设置 PASS_MIN_LEN 8 以上；同时建议配置 pam_pwquality minlen=8',
 '{"risk":"auto","steps":[{"action":"file_line_ensure","path":"/etc/login.defs","line":"PASS_MIN_LEN   8","position":"replace_regex","pattern":"^\\s*PASS_MIN_LEN\\s+\\d+"}]}'),
(1,'BL-LINUX-0002','口令复杂度要求（大写/小写/数字/特殊字符至少三类）','身份鉴别',3,
 '{"type":"file_line","target":"/etc/security/pwquality.conf","operator":"regex","expected":"^\\s*minlen\\s*=\\s*8"}',
 '在 /etc/security/pwquality.conf 配置 minlen=8、minclass=3（至少三类字符）',
 '{"risk":"auto","steps":[{"action":"file_line_ensure","path":"/etc/security/pwquality.conf","line":"minlen = 8","position":"append"},{"action":"file_line_ensure","path":"/etc/security/pwquality.conf","line":"minclass = 3","position":"append"}]}'),
(1,'BL-LINUX-0003','口令有效期不超过 90 天','身份鉴别',3,
 '{"type":"file_content","target":"/etc/login.defs","regex":"^\\s*PASS_MAX_DAYS\\s+([1-9]|[1-8][0-9]|90)\\s*$"}',
 '在 /etc/login.defs 中设置 PASS_MAX_DAYS 90 以内',
 '{"risk":"auto","steps":[{"action":"file_line_ensure","path":"/etc/login.defs","line":"PASS_MAX_DAYS   90","position":"replace_regex","pattern":"^\\s*PASS_MAX_DAYS\\s+\\d+"}]}'),
(1,'BL-LINUX-0004','口令更换警告期不少于 7 天','身份鉴别',2,
 '{"type":"file_content","target":"/etc/login.defs","regex":"^\\s*PASS_WARN_AGE\\s+([7-9]|[1-9]\\d+)\\s*$"}',
 '在 /etc/login.defs 中设置 PASS_WARN_AGE 7 以上',
 '{"risk":"auto","steps":[{"action":"file_line_ensure","path":"/etc/login.defs","line":"PASS_WARN_AGE   7","position":"replace_regex","pattern":"^\\s*PASS_WARN_AGE\\s+\\d+"}]}'),
(1,'BL-LINUX-0005','SSH 登录失败锁定已配置','身份鉴别',4,
 '{"type":"file_line","target":"/etc/pam.d/sshd","operator":"contains","expected":"auth required pam_faillock.so preauth"}',
 '在 /etc/pam.d/sshd 中增加 pam_faillock 配置（deny=5 unlock_time=600），实现登录失败锁定',
 '{"risk":"auto","requires_restart":"sshd","steps":[{"action":"file_line_ensure","path":"/etc/pam.d/sshd","line":"auth required pam_faillock.so preauth audit deny=5 unlock_time=600","position":"after","pattern":"^#%PAM"}]}'),
(1,'BL-LINUX-0006','口令加密算法使用 SHA512','身份鉴别',3,
 '{"type":"file_line","target":"/etc/login.defs","operator":"regex","expected":"^\\s*ENCRYPT_METHOD\\s+SHA512"}',
 '在 /etc/login.defs 中设置 ENCRYPT_METHOD SHA512',
 '{"risk":"auto","steps":[{"action":"file_line_ensure","path":"/etc/login.defs","line":"ENCRYPT_METHOD SHA512","position":"replace_regex","pattern":"^\\s*ENCRYPT_METHOD\\s+\\w+"}]}'),
(1,'BL-LINUX-0007','禁止 root 直接远程 SSH 登录','身份鉴别',3,
 '{"type":"file_content","target":"/etc/ssh/sshd_config","regex":"^\\s*PermitRootLogin\\s+no\\s*$"}',
 '在 /etc/ssh/sshd_config 设置 PermitRootLogin no，先确保有其他管理账号再启用',
 '{"risk":"manual","requires_restart":"sshd","steps":[{"action":"file_line_ensure","path":"/etc/ssh/sshd_config","line":"PermitRootLogin no","position":"replace_regex","pattern":"^\\s*#?\\s*PermitRootLogin\\s+\\w+"}]}'),
(1,'BL-LINUX-0008','SSH MaxAuthTries 不超过 4 次','身份鉴别',2,
 '{"type":"file_content","target":"/etc/ssh/sshd_config","regex":"^\\s*MaxAuthTries\\s+[1-4]\\s*$"}',
 '在 /etc/ssh/sshd_config 设置 MaxAuthTries 4 以内',
 '{"risk":"auto","requires_restart":"sshd","steps":[{"action":"file_line_ensure","path":"/etc/ssh/sshd_config","line":"MaxAuthTries 4","position":"replace_regex","pattern":"^\\s*#?\\s*MaxAuthTries\\s+\\d+"}]}'),
(1,'BL-LINUX-0009','无空口令账户','身份鉴别',4,
 '{"type":"cmd_output","cmd":"awk -F: ''($2==\"\"){print $1}'' /etc/shadow","operator":"eq","expected":"","timeout_ms":5000}',
 '为空口令账户设置强口令或锁定：passwd -l <账号>',
 NULL),
(1,'BL-LINUX-0010','已配置登录会话超时自动退出','身份鉴别',2,
 '{"type":"file_line","target":"/etc/profile","operator":"regex","expected":"^\\s*(readonly\\s+)?TMOUT="}',
 '在 /etc/profile 设置 TMOUT=600（含 readonly），超时自动注销',
 '{"risk":"auto","steps":[{"action":"file_line_ensure","path":"/etc/profile","line":"readonly TMOUT=600; export TMOUT","position":"append"}]}');

-- ---------- 访问控制（10 项）----------
INSERT INTO t_baseline_item (template_id, code, name, category, severity, check, remediation, fix_spec) VALUES
(1,'BL-LINUX-0011','/etc/passwd 文件权限应为 644','访问控制',3,
 '{"type":"file_perm","target":"/etc/passwd","perm":"0644","owner":"root","group":"root"}',
 'chmod 644 /etc/passwd；chown root:root /etc/passwd',
 '{"risk":"auto","steps":[{"action":"chmod","path":"/etc/passwd","mode":"0644"},{"action":"chown","path":"/etc/passwd","owner":"root","group":"root"}]}'),
(1,'BL-LINUX-0012','/etc/shadow 文件权限应为 600','访问控制',4,
 '{"type":"file_perm","target":"/etc/shadow","perm":"0600","owner":"root","group":"root"}',
 'chmod 600 /etc/shadow；chown root:root /etc/shadow',
 '{"risk":"auto","steps":[{"action":"chmod","path":"/etc/shadow","mode":"0600"},{"action":"chown","path":"/etc/shadow","owner":"root","group":"root"}]}'),
(1,'BL-LINUX-0013','/etc/group 文件权限应为 644','访问控制',2,
 '{"type":"file_perm","target":"/etc/group","perm":"0644","owner":"root","group":"root"}',
 'chmod 644 /etc/group；chown root:root /etc/group',
 '{"risk":"auto","steps":[{"action":"chmod","path":"/etc/group","mode":"0644"},{"action":"chown","path":"/etc/group","owner":"root","group":"root"}]}'),
(1,'BL-LINUX-0014','/etc/gshadow 文件权限应为 600','访问控制',3,
 '{"type":"file_perm","target":"/etc/gshadow","perm":"0600","owner":"root","group":"root"}',
 'chmod 600 /etc/gshadow；chown root:root /etc/gshadow',
 '{"risk":"auto","steps":[{"action":"chmod","path":"/etc/gshadow","mode":"0600"},{"action":"chown","path":"/etc/gshadow","owner":"root","group":"root"}]}'),
(1,'BL-LINUX-0015','非必要系统账号已锁定（lp/sync/halt/news 等）','访问控制',2,
 '{"type":"cmd_output","cmd":"grep -E \"^(lp|sync|shutdown|halt|news|uucp|operator|games|gopher):\" /etc/passwd | grep -vE \"nologin|false$\" | wc -l","operator":"eq","expected":"0","timeout_ms":5000}',
 '将非必要系统账号 shell 改为 /sbin/nologin：usermod -s /sbin/nologin <账号>',
 NULL),
(1,'BL-LINUX-0016','UID=0 的账号只有 root','访问控制',4,
 '{"type":"cmd_output","cmd":"awk -F: ''($3==0 && $1!=\"root\"){print $1}'' /etc/passwd","operator":"eq","expected":"","timeout_ms":5000}',
 '检查 UID=0 异常账号并删除或降权：userdel / usermod -u',
 NULL),
(1,'BL-LINUX-0017','默认 umask 应为 027（至少 022）','访问控制',2,
 '{"type":"file_content","target":"/etc/profile","regex":"^\\s*umask\\s+0(2[27]|07)\\s*$"}',
 '在 /etc/profile 设置 umask 027',
 '{"risk":"auto","steps":[{"action":"file_line_ensure","path":"/etc/profile","line":"umask 027","position":"replace_regex","pattern":"^\\s*umask\\s+\\d+"}]}'),
(1,'BL-LINUX-0018','sudo 配置中禁止 NOPASSWD','访问控制',3,
 '{"type":"file_line","target":"/etc/sudoers","operator":"not_contains","expected":"NOPASSWD"}',
 '检查 visudo 中 NOPASSWD 配置，改为需要口令验证',
 NULL),
(1,'BL-LINUX-0019','/etc/crontab 权限应为 600','访问控制',2,
 '{"type":"file_perm","target":"/etc/crontab","perm":"0600","owner":"root","group":"root"}',
 'chmod 600 /etc/crontab；chown root:root /etc/crontab',
 '{"risk":"auto","steps":[{"action":"chmod","path":"/etc/crontab","mode":"0600"},{"action":"chown","path":"/etc/crontab","owner":"root","group":"root"}]}'),
(1,'BL-LINUX-0020','SSH 禁用不安全的 DNS 反查（UseDNS no）','访问控制',1,
 '{"type":"file_content","target":"/etc/ssh/sshd_config","regex":"^\\s*UseDNS\\s+no\\s*$"}',
 '在 /etc/ssh/sshd_config 设置 UseDNS no，加快登录并减少信息泄露',
 '{"risk":"auto","requires_restart":"sshd","steps":[{"action":"file_line_ensure","path":"/etc/ssh/sshd_config","line":"UseDNS no","position":"replace_regex","pattern":"^\\s*#?\\s*UseDNS\\s+\\w+"}]}');

-- ---------- 安全审计（10 项）----------
INSERT INTO t_baseline_item (template_id, code, name, category, severity, check, remediation, fix_spec) VALUES
(1,'BL-LINUX-0021','auditd 审计服务已安装','安全审计',3,
 '{"type":"cmd_output","cmd":"command -v auditctl >/dev/null 2>&1 && echo yes || echo no","operator":"eq","expected":"yes","timeout_ms":5000}',
 '安装审计组件：yum install audit 或 apt install auditd',
 NULL),
(1,'BL-LINUX-0022','auditd 审计服务正在运行','安全审计',3,
 '{"type":"cmd_output","cmd":"systemctl is-active auditd 2>/dev/null || echo inactive","operator":"eq","expected":"active","timeout_ms":5000}',
 'systemctl enable --now auditd',
 '{"risk":"auto","steps":[{"action":"service_restart","service":"auditd","mode":"enable_start"}]}'),
(1,'BL-LINUX-0023','审计日志目录 /var/log/audit 权限应为 750','安全审计',2,
 '{"type":"file_perm","target":"/var/log/audit","perm":"0750","owner":"root","group":"root"}',
 'chmod 750 /var/log/audit；chown root:root /var/log/audit',
 '{"risk":"auto","steps":[{"action":"chmod","path":"/var/log/audit","mode":"0750"},{"action":"chown","path":"/var/log/audit","owner":"root","group":"root"}]}'),
(1,'BL-LINUX-0024','rsyslog 日志服务已运行','安全审计',2,
 '{"type":"cmd_output","cmd":"systemctl is-active rsyslog 2>/dev/null || echo inactive","operator":"eq","expected":"active","timeout_ms":5000}',
 'systemctl enable --now rsyslog',
 '{"risk":"auto","steps":[{"action":"service_restart","service":"rsyslog","mode":"enable_start"}]}'),
(1,'BL-LINUX-0025','审计规则覆盖身份鉴别文件变更（/etc/passwd 等）','安全审计',3,
 '{"type":"file_line","target":"/etc/audit/rules.d/audit.rules","operator":"contains","expected":"-w /etc/passwd"}',
 '在 /etc/audit/rules.d/audit.rules 增加 -w /etc/passwd -p wa -k identity，并 augenrules --load',
 '{"risk":"auto","steps":[{"action":"file_line_ensure","path":"/etc/audit/rules.d/audit.rules","line":"-w /etc/passwd -p wa -k identity","position":"append"},{"action":"file_line_ensure","path":"/etc/audit/rules.d/audit.rules","line":"-w /etc/shadow -p wa -k identity","position":"append"},{"action":"file_line_ensure","path":"/etc/audit/rules.d/audit.rules","line":"-w /etc/group -p wa -k identity","position":"append"}]}'),
(1,'BL-LINUX-0026','history 记录带时间戳','安全审计',2,
 '{"type":"file_line","target":"/etc/profile","operator":"regex","expected":"^\\s*export\\s+HISTTIMEFORMAT"}',
 '在 /etc/profile 设置 export HISTTIMEFORMAT="%F %T "',
 '{"risk":"auto","steps":[{"action":"file_line_ensure","path":"/etc/profile","line":"export HISTTIMEFORMAT=\"%F %T \"","position":"append"}]}'),
(1,'BL-LINUX-0027','/var/log/btmp 权限应为 600','安全审计',2,
 '{"type":"file_perm","target":"/var/log/btmp","perm":"0600","owner":"root","group":"root"}',
 'chmod 600 /var/log/btmp',
 '{"risk":"auto","steps":[{"action":"chmod","path":"/var/log/btmp","mode":"0600"},{"action":"chown","path":"/var/log/btmp","owner":"root","group":"utmp"}]}'),
(1,'BL-LINUX-0028','/var/log/wtmp 权限应为 664','安全审计',1,
 '{"type":"file_perm","target":"/var/log/wtmp","perm":"0664","owner":"root","group":"utmp"}',
 'chmod 664 /var/log/wtmp',
 '{"risk":"auto","steps":[{"action":"chmod","path":"/var/log/wtmp","mode":"0664"},{"action":"chown","path":"/var/log/wtmp","owner":"root","group":"utmp"}]}'),
(1,'BL-LINUX-0029','审计规则覆盖 sudo 使用（/var/log/audit）','安全审计',2,
 '{"type":"file_line","target":"/etc/audit/rules.d/audit.rules","operator":"contains","expected":"-w /var/log/audit/"}',
 '在 /etc/audit/rules.d/audit.rules 增加 -w /var/log/audit/ -p wa -k auditlog，并 augenrules --load',
 '{"risk":"auto","steps":[{"action":"file_line_ensure","path":"/etc/audit/rules.d/audit.rules","line":"-w /var/log/audit/ -p wa -k auditlog","position":"append"}]}'),
(1,'BL-LINUX-0030','日志文件 /var/log/messages 属主应为 root','安全审计',2,
 '{"type":"cmd_output","cmd":"stat -c %U /var/log/messages 2>/dev/null || echo root","operator":"eq","expected":"root","timeout_ms":5000}',
 'chown root /var/log/messages',
 '{"risk":"auto","steps":[{"action":"chown","path":"/var/log/messages","owner":"root"}]}');

-- ---------- 入侵防范（12 项）----------
INSERT INTO t_baseline_item (template_id, code, name, category, severity, check, remediation, fix_spec) VALUES
(1,'BL-LINUX-0031','SYN Flood 防护（tcp_syncookies=1）','入侵防范',3,
 '{"type":"cmd_output","cmd":"sysctl -n net.ipv4.tcp_syncookies","operator":"eq","expected":"1","timeout_ms":5000}',
 'sysctl -w net.ipv4.tcp_syncookies=1 并写入 /etc/sysctl.conf',
 '{"risk":"auto","steps":[{"action":"sysctl_set","key":"net.ipv4.tcp_syncookies","value":"1"}]}'),
(1,'BL-LINUX-0032','禁止接受 ICMP 重定向包','入侵防范',3,
 '{"type":"cmd_output","cmd":"sysctl -n net.ipv4.conf.all.accept_redirects","operator":"eq","expected":"0","timeout_ms":5000}',
 'sysctl -w net.ipv4.conf.all.accept_redirects=0（含 default 与ipv6）',
 '{"risk":"auto","steps":[{"action":"sysctl_set","key":"net.ipv4.conf.all.accept_redirects","value":"0"},{"action":"sysctl_set","key":"net.ipv4.conf.default.accept_redirects","value":"0"}]}'),
(1,'BL-LINUX-0033','禁止 IPv6 ICMP 重定向（若启用 IPv6）','入侵防范',2,
 '{"type":"cmd_output","cmd":"sysctl -n net.ipv6.conf.all.accept_redirects 2>/dev/null || echo 0","operator":"eq","expected":"0","timeout_ms":5000}',
 'sysctl -w net.ipv6.conf.all.accept_redirects=0',
 '{"risk":"auto","steps":[{"action":"sysctl_set","key":"net.ipv6.conf.all.accept_redirects","value":"0"}]}'),
(1,'BL-LINUX-0034','禁止源路由转发','入侵防范',3,
 '{"type":"cmd_output","cmd":"sysctl -n net.ipv4.conf.all.accept_source_route","operator":"eq","expected":"0","timeout_ms":5000}',
 'sysctl -w net.ipv4.conf.all.accept_source_route=0',
 '{"risk":"auto","steps":[{"action":"sysctl_set","key":"net.ipv4.conf.all.accept_source_route","value":"0"},{"action":"sysctl_set","key":"net.ipv4.conf.default.accept_source_route","value":"0"}]}'),
(1,'BL-LINUX-0035','忽略 ICMP 广播请求','入侵防范',2,
 '{"type":"cmd_output","cmd":"sysctl -n net.ipv4.icmp_echo_ignore_broadcasts","operator":"eq","expected":"1","timeout_ms":5000}',
 'sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1',
 '{"risk":"auto","steps":[{"action":"sysctl_set","key":"net.ipv4.icmp_echo_ignore_broadcasts","value":"1"}]}'),
(1,'BL-LINUX-0036','开启反向路径过滤（rp_filter=1）','入侵防范',2,
 '{"type":"cmd_output","cmd":"sysctl -n net.ipv4.conf.all.rp_filter","operator":"eq","expected":"1","timeout_ms":5000}',
 'sysctl -w net.ipv4.conf.all.rp_filter=1',
 '{"risk":"auto","steps":[{"action":"sysctl_set","key":"net.ipv4.conf.all.rp_filter","value":"1"}]}'),
(1,'BL-LINUX-0037','记录欺骗地址/martian 数据包','入侵防范',1,
 '{"type":"cmd_output","cmd":"sysctl -n net.ipv4.conf.all.log_martians","operator":"eq","expected":"1","timeout_ms":5000}',
 'sysctl -w net.ipv4.conf.all.log_martians=1',
 '{"risk":"auto","steps":[{"action":"sysctl_set","key":"net.ipv4.conf.all.log_martians","value":"1"}]}'),
(1,'BL-LINUX-0038','非路由主机应关闭 IP 转发','入侵防范',3,
 '{"type":"cmd_output","cmd":"sysctl -n net.ipv4.ip_forward","operator":"eq","expected":"0","timeout_ms":5000}',
 '非网关/路由主机执行 sysctl -w net.ipv4.ip_forward=0（注意：容器宿主机/K8S 节点常需=1，请按角色确认）',
 NULL),
(1,'BL-LINUX-0039','禁止 core dump（安全加固项）','入侵防范',2,
 '{"type":"file_line","target":"/etc/security/limits.conf","operator":"contains","expected":"* hard core 0"}',
 '在 /etc/security/limits.conf 增加 * hard core 0；* soft core 0',
 '{"risk":"auto","steps":[{"action":"file_line_ensure","path":"/etc/security/limits.conf","line":"* soft core 0","position":"append"},{"action":"file_line_ensure","path":"/etc/security/limits.conf","line":"* hard core 0","position":"append"}]}'),
(1,'BL-LINUX-0040','SELinux 或 AppArmor 处于启用状态','入侵防范',2,
 '{"type":"cmd_output","cmd":"sh -c \"(getenforce 2>/dev/null | grep -q Enforcing && echo enabled) || (aa-status --enabled 2>/dev/null && echo enabled) || echo disabled\"","operator":"eq","expected":"enabled","timeout_ms":5000}',
 '启用 SELinux（/etc/selinux/config = enforcing）或 AppArmor（systemctl enable --now apparmor）',
 NULL),
(1,'BL-LINUX-0041','/etc/ld.so.conf 权限应为 644','入侵防范',2,
 '{"type":"file_perm","target":"/etc/ld.so.conf","perm":"0644","owner":"root","group":"root"}',
 'chmod 644 /etc/ld.so.conf',
 '{"risk":"auto","steps":[{"action":"chmod","path":"/etc/ld.so.conf","mode":"0644"},{"action":"chown","path":"/etc/ld.so.conf","owner":"root","group":"root"}]}'),
(1,'BL-LINUX-0042','SUID/SGID 文件无近期异常新增','入侵防范',2,
 '{"type":"cmd_output","cmd":"find /usr/bin /usr/sbin /usr/local/bin -perm -4000 -newer /etc/passwd 2>/dev/null | wc -l","operator":"eq","expected":"0","timeout_ms":15000}',
 '检查新增 SUID 文件是否为正常软件安装，可疑文件执行 chmod -s',
 NULL);

-- ---------- 剩余信息保护（6 项）----------
INSERT INTO t_baseline_item (template_id, code, name, category, severity, check, remediation, fix_spec) VALUES
(1,'BL-LINUX-0043','登录前显示安全告警横幅（sshd Banner）','剩余信息保护',1,
 '{"type":"file_content","target":"/etc/ssh/sshd_config","regex":"^\\s*Banner\\s+\\S+"}',
 '在 /etc/ssh/sshd_config 配置 Banner /etc/issue.net，并编辑告警文案',
 '{"risk":"manual","requires_restart":"sshd","steps":[{"action":"file_line_ensure","path":"/etc/ssh/sshd_config","line":"Banner /etc/issue.net","position":"replace_regex","pattern":"^\\s*#?\\s*Banner\\s+\\S*"}]}'),
(1,'BL-LINUX-0044','shell 退出时清理历史命令（HISTSIZE 限制）','剩余信息保护',1,
 '{"type":"file_content","target":"/etc/profile","regex":"^\\s*export\\s+HISTSIZE=\\d+"}',
 '在 /etc/profile 设置 export HISTSIZE=500（按需），敏感环境可设置 0',
 '{"risk":"auto","steps":[{"action":"file_line_ensure","path":"/etc/profile","line":"export HISTSIZE=500","position":"append"}]}'),
(1,'BL-LINUX-0045','/etc/bashrc（或 bash.bashrc）umask 一致','剩余信息保护',2,
 '{"type":"cmd_output","cmd":"sh -c \"f=/etc/bashrc; [ -f \\\"$f\\\" ] || f=/etc/bash.bashrc; grep -E ''^\\s*umask\\s+0(2[27]|07)'' \\\"$f\\\" >/dev/null 2>&1 && echo yes || echo no\"","operator":"eq","expected":"yes","timeout_ms":5000}',
 '在 /etc/bashrc（Debian 系为 /etc/bash.bashrc）设置 umask 027',
 '{"risk":"auto","steps":[{"action":"file_line_ensure","path":"/etc/bashrc","line":"umask 027","position":"replace_regex","pattern":"^\\s*umask\\s+\\d+","optional_path":"/etc/bash.bashrc"}]}'),
(1,'BL-LINUX-0046','systemd-tmpfiles 定期清理 /tmp','剩余信息保护',2,
 '{"type":"cmd_output","cmd":"systemctl list-timers --no-pager 2>/dev/null | grep -c systemd-tmpfiles","operator":"gt","expected":"0","timeout_ms":5000}',
 '确保 systemd-tmpfiles-clean.timer 启用：systemctl enable --now systemd-tmpfiles-clean.timer',
 NULL),
(1,'BL-LINUX-0047','/tmp 分区挂载 nosuid/nodev（独立分区时）','剩余信息保护',2,
 '{"type":"cmd_output","cmd":"sh -c \"findmnt -n /tmp >/dev/null 2>&1 && findmnt -no OPTIONS /tmp | grep -cE ''nosuid|nodev'' || echo 1\"","operator":"gt","expected":"0","timeout_ms":5000}',
 '将 /tmp 挂载选项增加 nosuid,nodev（/etc/fstab）',
 NULL),
(1,'BL-LINUX-0048','crond 服务日志已启用（rsyslog cron.facility）','剩余信息保护',1,
 '{"type":"file_line","target":"/etc/rsyslog.conf","operator":"regex","expected":"cron\\."}',
 '在 /etc/rsyslog.conf 配置 cron.* /var/log/cron，并重启 rsyslog',
 '{"risk":"auto","requires_restart":"rsyslog","steps":[{"action":"file_line_ensure","path":"/etc/rsyslog.conf","line":"cron.*                                                  /var/log/cron","position":"append"}]}');

-- ---------- 恶意代码防范（6 项）----------
INSERT INTO t_baseline_item (template_id, code, name, category, severity, check, remediation, fix_spec) VALUES
(1,'BL-LINUX-0049','主机已部署 ALinkSec Agent（恶意代码防护）','恶意代码防范',3,
 '{"type":"cmd_output","cmd":"command -v alinksec-agent >/dev/null 2>&1 && echo yes || echo no","operator":"eq","expected":"yes","timeout_ms":5000}',
 '安装 ALinkSec Agent 并接入平台管理',
 NULL),
(1,'BL-LINUX-0050','病毒特征库文件存在且非空','恶意代码防范',3,
 '{"type":"file_perm","target":"/var/lib/alinksec-agent/signature.db","perm_exists":true}',
 '等待 Agent 首次特征库同步（平台下发或默认内置库）',
 NULL),
(1,'BL-LINUX-0051','rpm 安装启用 GPG 校验（gpgcheck=1）','恶意代码防范',2,
 '{"type":"file_line","target":"/etc/yum.conf","operator":"contains","expected":"gpgcheck=1"}',
 '在 /etc/yum.conf 设置 gpgcheck=1',
 '{"risk":"auto","steps":[{"action":"file_line_ensure","path":"/etc/yum.conf","line":"gpgcheck=1","position":"replace_regex","pattern":"^\\s*gpgcheck\\s*=\\s*\\d+"}]}'),
(1,'BL-LINUX-0052','apt 不允许未认证软件源','恶意代码防范',2,
 '{"type":"cmd_output","cmd":"sh -c \"apt-config dump 2>/dev/null | grep -c AllowUnauthenticated \\\"1\\\"\" || echo 0","operator":"eq","expected":"0","timeout_ms":5000}',
 '移除 APT 配置中的 AllowUnauthenticated \"1\"',
 NULL),
(1,'BL-LINUX-0053','软件源地址为 https 或内部可信源','恶意代码防范',1,
 '{"type":"cmd_output","cmd":"sh -c \"grep -rhE ''^(baseurl|deb)\\s+\\S+'' /etc/yum.repos.d/ /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null | grep -vcE ''https|file:///|ftp://内网|^[[:space:]]*#'' || echo 0\"","operator":"eq","expected":"0","timeout_ms":5000}',
 '将软件源改为 https 协议或内部镜像源，防止投毒',
 NULL),
(1,'BL-LINUX-0054','定期病毒扫描任务已配置（cron）','恶意代码防范',2,
 '{"type":"file_perm","target":"/etc/cron.d/alinksec-scan","perm_exists":true}',
 '由平台下发定时扫描策略（M2 起支持），或手工配置 cron',
 NULL);

-- ---------- 资源控制（8 项）----------
INSERT INTO t_baseline_item (template_id, code, name, category, severity, check, remediation, fix_spec) VALUES
(1,'BL-LINUX-0055','时间同步服务（chronyd/ntpd）已启用','资源控制',2,
 '{"type":"cmd_output","cmd":"sh -c \"systemctl is-active chronyd 2>/dev/null || systemctl is-active ntpd 2>/dev/null || echo inactive\"","operator":"eq","expected":"active","timeout_ms":5000}',
 '安装并启用 chrony：yum install chrony && systemctl enable --now chronyd',
 NULL),
(1,'BL-LINUX-0056','文件句柄数限制已设置（nofile）','资源控制',2,
 '{"type":"file_line","target":"/etc/security/limits.conf","operator":"regex","expected":"^\\*\\s+(soft|hard)\\s+nofile\\s+\\d+"}',
 '在 /etc/security/limits.conf 设置 * soft/hard nofile 65535',
 '{"risk":"auto","steps":[{"action":"file_line_ensure","path":"/etc/security/limits.conf","line":"* soft nofile 65535","position":"append"},{"action":"file_line_ensure","path":"/etc/security/limits.conf","line":"* hard nofile 65535","position":"append"}]}'),
(1,'BL-LINUX-0057','用户进程数限制已设置（nproc）','资源控制',2,
 '{"type":"file_line","target":"/etc/security/limits.conf","operator":"regex","expected":"^\\*\\s+(soft|hard)\\s+nproc\\s+\\d+"}',
 '在 /etc/security/limits.conf 设置 * soft/hard nproc 65535（按业务评估）',
 '{"risk":"manual","steps":[{"action":"file_line_ensure","path":"/etc/security/limits.conf","line":"* soft nproc 65535","position":"append"},{"action":"file_line_ensure","path":"/etc/security/limits.conf","line":"* hard nproc 65535","position":"append"}]}'),
(1,'BL-LINUX-0058','/etc/securetty 权限应为 600','资源控制',2,
 '{"type":"file_perm","target":"/etc/securetty","perm":"0600","owner":"root","group":"root"}',
 'chmod 600 /etc/securetty（限定 root 可登录的终端）',
 '{"risk":"auto","steps":[{"action":"chmod","path":"/etc/securetty","mode":"0600"},{"action":"chown","path":"/etc/securetty","owner":"root","group":"root"}]}'),
(1,'BL-LINUX-0059','单用户模式（rescue/emergency）需要认证','资源控制',3,
 '{"type":"cmd_output","cmd":"sh -c \"grep -hE ''^ExecStart=.*sulogin'' /usr/lib/systemd/system/rescue.service /usr/lib/systemd/system/emergency.service 2>/dev/null | wc -l\"","operator":"eq","expected":"2","timeout_ms":5000}',
 '确认 rescue.service / emergency.service 的 ExecStart 使用 sulogin（发行版默认满足）',
 NULL),
(1,'BL-LINUX-0060','Ctrl-Alt-Del 重启组合键已禁用','资源控制',2,
 '{"type":"cmd_output","cmd":"sh -c \"systemctl is-enabled ctrl-alt-del.target 2>/dev/null || echo enabled\"","operator":"eq","expected":"disabled","timeout_ms":5000}',
 'systemctl mask ctrl-alt-del.target 防止物理接触者重启主机',
 '{"risk":"auto","steps":[{"action":"cmd_run","cmd":"systemctl mask ctrl-alt-del.target"}]}');

-- ------------------------------------------------------------
-- CVE 样例库（演示比对能力；生产由 NVD/OVAL 离线导入替换）
-- affected 格式：[{"name":"软件名(小写)","vrange":"<固定版本","os":"centos7|ubuntu2204|*"}]
-- ------------------------------------------------------------
INSERT INTO t_cve_db (cve_id, title, severity, cvss, affected, description, published_at) VALUES
('CVE-2024-6387','OpenSSH regreSSHion 远程代码执行','4',8.1,
 '[{"name":"openssh","vrange":"<9.8p1","os":"*"}]'::jsonb,
 'OpenSSH 服务端信号处理程序竞争条件（SIGALRM/CVE-2024-6387），未认证远程利用可能 RCE。升级至 9.8p1 及以上或应用发行版补丁。','2024-07-01'),
('CVE-2024-1086','Linux 内核 nf_tables UAF 本地提权','4',7.8,
 '[{"name":"kernel","vrange":"<6.7.10","os":"*"}]'::jsonb,
 'netfilter nf_tables 通用 set 垃圾回收 UAF，本地低权用户可提权至 root。及时更新内核并重启。','2024-02-01'),
('CVE-2023-4966','Citrix Bleed 会话令牌泄露','4',9.4,
 '[{"name":"netscaler-gateway","vrange":"<13.1-49.15","os":"*"}]'::jsonb,
 'NetScaler ADC/Gateway 敏感信息泄露，可绕过 MFA 会话接管。','2023-10-01'),
('CVE-2023-44487','HTTP/2 Rapid Reset 拒绝服务','4',7.5,
 '[{"name":"nginx","vrange":"<1.25.3","os":"*"},{"name":"apache-httpd","vrange":"<2.4.58","os":"*"}]'::jsonb,
 'HTTP/2 协议层 DoS，攻击者可低成本打瘫服务。升级或调低并发流上限。','2023-10-01'),
('CVE-2023-38545','curl SOCKS5 堆溢出','4',8.8,
 '[{"name":"curl","vrange":"<8.4.0","os":"*"}]'::jsonb,
 'curl SOCKS5 代理握手堆缓冲区溢出，恶意服务端可控溢出长度。升级 curl 8.4.0+。','2023-10-01'),
('CVE-2022-0778','OpenSSL BN_mod_sqrt() 无限循环 DoS','3',7.5,
 '[{"name":"openssl","vrange":"<1.1.1n","os":"*"}]'::jsonb,
 '畸形证书可触发 OpenSSL CPU 空转。升级至修复版本。','2022-03-01'),
('CVE-2021-4034','sudo Baron Samedit 本地提权','4',7.8,
 '[{"name":"sudo","vrange":"<1.9.5p2","os":"*"}]'::jsonb,
 'sudo 对以反斜杠结尾的参数 argv[0] 堆溢出，任意本地用户免密提权 root。','2022-01-01'),
('CVE-2021-3156','sudo heap-based 溢出（配合 4034 前置披露）','4',7.8,
 '[{"name":"sudo","vrange":"<1.9.5p2","os":"*"}]'::jsonb,
 'sudoedit 环境变量转义堆溢出，本地提权。','2021-01-01'),
('CVE-2021-44228','Apache Log4j2 JNDI RCE（Log4Shell）','4',10.0,
 '[{"name":"log4j-core","vrange":"<2.15.0","os":"*"}]'::jsonb,
 'JNDI 注入远程代码执行，影响面极广。升级 2.17.1+。','2021-12-01'),
('CVE-2019-5716','OpenSSH 客户端内存破坏','3',6.5,
 '[{"name":"openssh","vrange":"<7.9p1","os":"*"}]'::jsonb,
 '恶意 SSH 服务端可造成客户端内存破坏。','2019-01-01'),
('CVE-2018-15473','OpenSSH 用户名枚举','2',5.3,
 '[{"name":"openssh","vrange":"<7.8","os":"*"}]'::jsonb,
 '可远程枚举有效用户名，配合字典爆破。','2018-08-01'),
('CVE-2016-5195','Linux 内核 Dirty COW 本地提权','4',7.8,
 '[{"name":"kernel","vrange":"<4.8.3","os":"*"}]'::jsonb,
 'get_user_page() 竞争条件写只读内存映射，本地提权。','2016-10-01'),
('CVE-2014-6271','Bash Shellshock RCE','4',9.8,
 '[{"name":"bash","vrange":"<4.3","os":"*"}]'::jsonb,
 '环境变量函数定义尾部注入命令执行。','2014-09-01'),
('CVE-2023-5678','OpenSSL DH 检查 DoS','3',5.3,
 '[{"name":"openssl","vrange":"<3.0.12","os":"*"}]'::jsonb,
 'DH 密钥参数校验可触发长时间计算。','2023-11-01'),
('CVE-2020-1472','Zerologon 域控提权','4',10.0,
 '[{"name":"samba","vrange":"<4.12.11","os":"*"}]'::jsonb,
 'Netlogon 特权提升（Windows 域控/Samba DC），重置域控机器账户密码。','2020-08-01'),
('CVE-2022-22965','Spring Framework RCE（Spring4Shell）','4',9.8,
 '[{"name":"spring-core","vrange":"<5.2.20","os":"*"}]'::jsonb,
 '数据绑定绕过 ClassLoader 属性访问 RCE，JDK9+ + Tomcat 部署形态受影响。','2022-03-01'),
('CVE-2023-34362','MOVEit Transfer SQL 注入','4',9.8,
 '[{"name":"moveit-transfer","vrange":"<2023.0.1","os":"*"}]'::jsonb,
 '未认证 SQL 注入导致 RCE 与数据窃取。','2023-05-01'),
('CVE-2024-21762','Fortinet FortiOS 路径穿越 RCE','4',9.6,
 '[{"name":"fortios","vrange":"<7.4.2","os":"*"}]'::jsonb,
 'SSL VPN 路径穿越写文件 RCE。','2024-02-01'),
('CVE-2021-34527','Windows Print Spooler RCE（PrintNightmare）','4',8.8,
 '[{"name":"spooler","vrange":"<10.0","os":"windows"}]'::jsonb,
 '打印后台处理服务 RCE/本地提权，禁用 Print Spooler 或打补丁。','2021-06-01'),
('CVE-2017-0144','Windows SMBv1 远程执行（EternalBlue）','4',8.1,
 '[{"name":"smb","vrange":"<6.0.0","os":"windows"}]'::jsonb,
 'MS17-010，勒索蠕虫（WannaCry/Petya）主要传播途径。','2017-04-01')
ON CONFLICT (cve_id) DO NOTHING;
