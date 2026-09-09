-- ALinkSec unified bootstrap schema. Run only against an empty PostgreSQL database.
-- ALinkSec M1 鍒濆鍖栵紙璧勪骇鍩熸牳蹇冭〃 + 绯荤粺鍩?+ 鍛婅鍩?+ 涓婃姤鍘婚噸琛級
-- 瀹屾暣 schema 瑙?docs/03-鏁版嵁搴撹璁?md锛孧2 琛ラ綈鍩虹嚎/鎵弿/鐥呮瘨/淇鍩?

-- ============ 璧勪骇鍩?============
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
  deleted        BOOLEAN      NOT NULL DEFAULT FALSE,
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

CREATE TABLE IF NOT EXISTS t_asset_process (
  id BIGSERIAL PRIMARY KEY, agent_id VARCHAR(64) NOT NULL, pid INTEGER NOT NULL,
  name VARCHAR(255), exe TEXT, cmdline TEXT, username VARCHAR(255), rss_bytes BIGINT NOT NULL DEFAULT 0,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(), UNIQUE(agent_id, pid)
);
CREATE INDEX IF NOT EXISTS idx_process_agent_rss ON t_asset_process(agent_id, rss_bytes DESC);

CREATE TABLE IF NOT EXISTS t_asset_container (
  id           BIGSERIAL PRIMARY KEY,
  agent_id     VARCHAR(64) NOT NULL,
  container_id VARCHAR(128) NOT NULL,
  name         VARCHAR(255),
  image        VARCHAR(512),
  image_id     VARCHAR(128),
  orchestrator VARCHAR(32) NOT NULL DEFAULT 'docker',
  namespace    VARCHAR(255),
  status       VARCHAR(255),
  created_at   TIMESTAMPTZ,
  started_at   TIMESTAMPTZ,
  ports        JSONB NOT NULL DEFAULT '[]',
  labels       JSONB NOT NULL DEFAULT '{}',
  risky        BOOLEAN NOT NULL DEFAULT FALSE,
  risk_reasons JSONB NOT NULL DEFAULT '[]',
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(agent_id, container_id)
);
CREATE INDEX IF NOT EXISTS idx_container_agent ON t_asset_container(agent_id);
CREATE INDEX IF NOT EXISTS idx_container_orchestrator ON t_asset_container(orchestrator, namespace);

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

-- ============ 鍛婅鍩?============
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

-- ============ 绯荤粺鍩?============
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

-- ============ 涓婃姤鍘婚噸锛坮eport_id 骞傜瓑锛孧2 杩?Redis锛?============
CREATE TABLE IF NOT EXISTS t_report_dedup (
  report_id  VARCHAR(64) PRIMARY KEY,
  expire_at  TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_report_dedup_expire ON t_report_dedup(expire_at);

-- ============ 骞冲彴瀹¤ ============
-- Platform audit records.
CREATE TABLE IF NOT EXISTS t_audit_log (
  id          BIGSERIAL PRIMARY KEY,
  uid         BIGINT,
  username    VARCHAR(64),
  method      VARCHAR(16) NOT NULL,
  path        VARCHAR(200) NOT NULL,
  body_digest VARCHAR(500),
  source_ip   VARCHAR(64),
  status      INT NOT NULL,
  cost_ms     INT,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_audit_log_time ON t_audit_log(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_log_uid ON t_audit_log(uid);

CREATE TABLE IF NOT EXISTS t_agent_download_token (
  token         VARCHAR(128) PRIMARY KEY,
  agent_id      VARCHAR(64) NOT NULL,
  resource_type VARCHAR(32) NOT NULL,
  resource_key  VARCHAR(255) NOT NULL,
  expire_at     TIMESTAMPTZ NOT NULL,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_agent_download_token_expire ON t_agent_download_token(expire_at);

-- ============================================================
-- ALinkSec M2 鍒濆鍖栬剼鏈?
-- 鑼冨洿锛氬熀绾挎牳鏌ュ煙 / 瀹夊叏鎵弿鍩?/ 鐥呮瘨鏌ユ潃鍩?/ 淇鍩?/ 鐢ㄦ埛鏉冮檺鍩?
-- 渚濊禆锛?01_m1_init.sql锛坱_agent / t_alert / t_command 绛夊熀纭€琛級
-- 璇存槑锛歞ocker-compose 棣栨鍚姩鑷姩鎵ц锛涘凡鏈夌幆澧冩墜鍔ㄨˉ璺戝嵆鍙紙骞傜瓑锛歄N CONFLICT / IF NOT EXISTS锛?
-- ============================================================

-- ------------------------------------------------------------
-- 0. 鐢ㄦ埛鏉冮檺鍩燂紙REST 鐧诲綍锛?
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
  password_hash  VARCHAR(128) NOT NULL,          -- bcrypt锛堢敱鏈嶅姟绔惎鍔ㄦ椂绉嶅瓙鐢熸垚锛?
  real_name      VARCHAR(64),
  role_id        BIGINT      NOT NULL REFERENCES t_role(id),
  status         SMALLINT    NOT NULL DEFAULT 1, -- 1鍚敤 0绂佺敤
  last_login_at  TIMESTAMPTZ,
  last_login_ip  VARCHAR(64),
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);


INSERT INTO t_role (id, name, permissions) VALUES
  (1, 'admin', '["*"]'::jsonb),
  (2, 'viewer', '["asset:view","baseline:view","vuln:view","virus:view","alert:view"]'::jsonb)
ON CONFLICT (id) DO NOTHING;

-- ------------------------------------------------------------
-- 1. 鍩虹嚎鏍告煡鍩?
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
  severity    SMALLINT NOT NULL,                 -- 1浣?2涓?3楂?4涓ラ噸
  check       JSONB   NOT NULL,                  -- Agent 绔В閲婃墽琛岋紙鐑洿鏂帮級
  remediation TEXT,
  fix_spec    JSONB,                             -- 鍙嚜鍔ㄤ慨澶嶆楠わ紙NULL=涓嶅彲鑷姩淇锛?
  enabled     BOOLEAN NOT NULL DEFAULT TRUE,
  UNIQUE (template_id, code)
);

CREATE TABLE IF NOT EXISTS t_baseline_task (
  id           BIGSERIAL PRIMARY KEY,
  task_no      VARCHAR(64) NOT NULL UNIQUE,
  name         VARCHAR(128),
  scope        JSONB NOT NULL,                   -- {"group_ids":[],"agent_ids":[]}
  template_ids BIGINT[] NOT NULL,
  status       SMALLINT NOT NULL DEFAULT 0,      -- 0寰呮墽琛?1鎵ц涓?2瀹屾垚 3閮ㄥ垎澶辫触 4鍙栨秷
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
  message    TEXT,                -- 澶辫触鍘熷洜锛圓gent 妫€鏌ュ紩鎿庝骇鍑猴級
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
-- 2. 瀹夊叏鎵弿鍩燂紙婕忔礊 / 寮卞彛浠わ級
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS t_scan_task (
  id         BIGSERIAL PRIMARY KEY,
  task_no    VARCHAR(64) NOT NULL UNIQUE,
  name       VARCHAR(128),
  type       SMALLINT NOT NULL,                  -- 1婕忔礊 2寮卞彛浠?3绔彛鏈嶅姟锛堝彲缁勫悎锛?
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
  status            SMALLINT NOT NULL DEFAULT 0, -- 0鏂板 1宸茬‘璁?2宸插拷鐣?3宸蹭慨澶?
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
  remark     VARCHAR(255),                      -- 琛ュ厖璇存槑锛堝 pwd_stale 鐨勬湭淇敼澶╂暟锛?
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
  service      VARCHAR(64),                          -- 鎸囩汗璇嗗埆鍑虹殑鏈嶅姟鍚?
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
-- 3. 鐥呮瘨鏌ユ潃鍩?
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS t_virus_db (
  id          BIGSERIAL PRIMARY KEY,
  db_version  VARCHAR(32) NOT NULL UNIQUE,
  package_key VARCHAR(512) NOT NULL,             -- 鐗瑰緛鍖呮枃浠?key锛堟湰鍦板瓨鍌ㄨ矾寰勬爣璇嗭級
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
  mode       SMALLINT NOT NULL,                  -- 1蹇€?2鍏ㄧ洏 3鑷畾涔?
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
  task_id      BIGINT,                           -- NULL=瀹炴椂闃叉姢妫€鍑?
  agent_id     VARCHAR(64) NOT NULL,
  path         VARCHAR(512) NOT NULL,
  name         VARCHAR(255) NOT NULL,
  sha256       VARCHAR(64) NOT NULL,
  size         BIGINT,
  engine       VARCHAR(16) NOT NULL,             -- hash / yara
  severity     SMALLINT NOT NULL,
  action_taken VARCHAR(32),                      -- quarantined / deleted / alert_only
  status       SMALLINT NOT NULL DEFAULT 0,      -- 0鏂板 1宸查殧绂?2宸插垹闄?3宸叉仮澶?4宸插姞鐧?
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
-- 4. 淇鍩燂紙M2 閰嶇疆绫伙紱杞欢鍖呯被 M4锛?
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS t_fix_task (
  id           BIGSERIAL PRIMARY KEY,
  task_no      VARCHAR(64) NOT NULL UNIQUE,
  name         VARCHAR(128),
  type         SMALLINT NOT NULL,                -- 1閰嶇疆绫?
  scope        JSONB NOT NULL,
  targets      JSONB NOT NULL,                   -- [{ref_type:"baseline_item", ref_id, fix_payload}]
  status       SMALLINT NOT NULL DEFAULT 0,      -- 0寰呮墽琛?1鎵ц涓?2瀹屾垚 3閮ㄥ垎澶辫触 4宸插彇娑?
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
  status      SMALLINT NOT NULL DEFAULT 0,       -- 0寰呮墽琛?1鎴愬姛 2澶辫触宸插洖婊?3澶辫触鏈洖婊?4璺宠繃 5澶嶆牳鏈€氳繃
  log         TEXT,
  finished_at TIMESTAMPTZ,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_fix_record ON t_fix_record(task_id, agent_id);

-- ------------------------------------------------------------
-- 澧為噺琛ヤ竵锛堝凡鏈夌幆澧冭ˉ璺戯紱鏂扮幆澧冨缓琛ㄥ凡鍚級
-- ------------------------------------------------------------
ALTER TABLE t_weakpwd_finding ADD COLUMN IF NOT EXISTS remark VARCHAR(255);

-- ============================================================
-- 绉嶅瓙鏁版嵁
-- ============================================================

-- ------------------------------------------------------------
-- 绛変繚 2.0 鏈嶅姟鍣?Linux 鍩虹嚎妯℃澘锛?0 椤癸級
-- check 瑙勮寖瑙?docs/04 搂3.2锛歠ile_line / file_content / file_perm / cmd_output
-- fix_spec 瑙勮寖瑙?docs/05 搂3.2锛歴ysctl_set / file_line_ensure / chmod / service_restart
-- ------------------------------------------------------------
INSERT INTO t_baseline_template (id, code, name, standard, os_type, version, item_count)
VALUES (1, 'DJBH2.0-LINUX', '绛変繚 2.0 鏈嶅姟鍣ㄥ熀绾匡紙Linux锛?, '绛変繚2.0', 1, '1.0', 60)
ON CONFLICT (id) DO NOTHING;

-- ---------- 韬唤閴村埆锛?0 椤癸級----------
INSERT INTO t_baseline_item (template_id, code, name, category, severity, check, remediation, fix_spec) VALUES
(1,'BL-LINUX-0001','鍙ｄ护鏈€灏忛暱搴︿笉灏忎簬 8 浣?,'韬唤閴村埆',3,
 '{"type":"file_content","target":"/etc/login.defs","regex":"^\\s*PASS_MIN_LEN\\s+([8-9]|[1-9]\\d+)\\s*$"}',
 '鍦?/etc/login.defs 涓缃?PASS_MIN_LEN 8 浠ヤ笂锛涘悓鏃跺缓璁厤缃?pam_pwquality minlen=8',
 '{"risk":"auto","steps":[{"action":"file_line_ensure","path":"/etc/login.defs","line":"PASS_MIN_LEN   8","position":"replace_regex","pattern":"^\\s*PASS_MIN_LEN\\s+\\d+"}]}'),
(1,'BL-LINUX-0002','鍙ｄ护澶嶆潅搴﹁姹傦紙澶у啓/灏忓啓/鏁板瓧/鐗规畩瀛楃鑷冲皯涓夌被锛?,'韬唤閴村埆',3,
 '{"type":"file_line","target":"/etc/security/pwquality.conf","operator":"regex","expected":"^\\s*minlen\\s*=\\s*8"}',
 '鍦?/etc/security/pwquality.conf 閰嶇疆 minlen=8銆乵inclass=3锛堣嚦灏戜笁绫诲瓧绗︼級',
 '{"risk":"auto","steps":[{"action":"file_line_ensure","path":"/etc/security/pwquality.conf","line":"minlen = 8","position":"append"},{"action":"file_line_ensure","path":"/etc/security/pwquality.conf","line":"minclass = 3","position":"append"}]}'),
(1,'BL-LINUX-0003','鍙ｄ护鏈夋晥鏈熶笉瓒呰繃 90 澶?,'韬唤閴村埆',3,
 '{"type":"file_content","target":"/etc/login.defs","regex":"^\\s*PASS_MAX_DAYS\\s+([1-9]|[1-8][0-9]|90)\\s*$"}',
 '鍦?/etc/login.defs 涓缃?PASS_MAX_DAYS 90 浠ュ唴',
 '{"risk":"auto","steps":[{"action":"file_line_ensure","path":"/etc/login.defs","line":"PASS_MAX_DAYS   90","position":"replace_regex","pattern":"^\\s*PASS_MAX_DAYS\\s+\\d+"}]}'),
(1,'BL-LINUX-0004','鍙ｄ护鏇存崲璀﹀憡鏈熶笉灏戜簬 7 澶?,'韬唤閴村埆',2,
 '{"type":"file_content","target":"/etc/login.defs","regex":"^\\s*PASS_WARN_AGE\\s+([7-9]|[1-9]\\d+)\\s*$"}',
 '鍦?/etc/login.defs 涓缃?PASS_WARN_AGE 7 浠ヤ笂',
 '{"risk":"auto","steps":[{"action":"file_line_ensure","path":"/etc/login.defs","line":"PASS_WARN_AGE   7","position":"replace_regex","pattern":"^\\s*PASS_WARN_AGE\\s+\\d+"}]}'),
(1,'BL-LINUX-0005','SSH 鐧诲綍澶辫触閿佸畾宸查厤缃?,'韬唤閴村埆',4,
 '{"type":"file_line","target":"/etc/pam.d/sshd","operator":"contains","expected":"auth required pam_faillock.so preauth"}',
 '鍦?/etc/pam.d/sshd 涓鍔?pam_faillock 閰嶇疆锛坉eny=5 unlock_time=600锛夛紝瀹炵幇鐧诲綍澶辫触閿佸畾',
 '{"risk":"auto","requires_restart":"sshd","steps":[{"action":"file_line_ensure","path":"/etc/pam.d/sshd","line":"auth required pam_faillock.so preauth audit deny=5 unlock_time=600","position":"after","pattern":"^#%PAM"}]}'),
(1,'BL-LINUX-0006','鍙ｄ护鍔犲瘑绠楁硶浣跨敤 SHA512','韬唤閴村埆',3,
 '{"type":"file_line","target":"/etc/login.defs","operator":"regex","expected":"^\\s*ENCRYPT_METHOD\\s+SHA512"}',
 '鍦?/etc/login.defs 涓缃?ENCRYPT_METHOD SHA512',
 '{"risk":"auto","steps":[{"action":"file_line_ensure","path":"/etc/login.defs","line":"ENCRYPT_METHOD SHA512","position":"replace_regex","pattern":"^\\s*ENCRYPT_METHOD\\s+\\w+"}]}'),
(1,'BL-LINUX-0007','绂佹 root 鐩存帴杩滅▼ SSH 鐧诲綍','韬唤閴村埆',3,
 '{"type":"file_content","target":"/etc/ssh/sshd_config","regex":"^\\s*PermitRootLogin\\s+no\\s*$"}',
 '鍦?/etc/ssh/sshd_config 璁剧疆 PermitRootLogin no锛屽厛纭繚鏈夊叾浠栫鐞嗚处鍙峰啀鍚敤',
 '{"risk":"manual","requires_restart":"sshd","steps":[{"action":"file_line_ensure","path":"/etc/ssh/sshd_config","line":"PermitRootLogin no","position":"replace_regex","pattern":"^\\s*#?\\s*PermitRootLogin\\s+\\w+"}]}'),
(1,'BL-LINUX-0008','SSH MaxAuthTries 涓嶈秴杩?4 娆?,'韬唤閴村埆',2,
 '{"type":"file_content","target":"/etc/ssh/sshd_config","regex":"^\\s*MaxAuthTries\\s+[1-4]\\s*$"}',
 '鍦?/etc/ssh/sshd_config 璁剧疆 MaxAuthTries 4 浠ュ唴',
 '{"risk":"auto","requires_restart":"sshd","steps":[{"action":"file_line_ensure","path":"/etc/ssh/sshd_config","line":"MaxAuthTries 4","position":"replace_regex","pattern":"^\\s*#?\\s*MaxAuthTries\\s+\\d+"}]}'),
(1,'BL-LINUX-0009','鏃犵┖鍙ｄ护璐︽埛','韬唤閴村埆',4,
 '{"type":"cmd_output","cmd":"awk -F: ''($2==\"\"){print $1}'' /etc/shadow","operator":"eq","expected":"","timeout_ms":5000}',
 '涓虹┖鍙ｄ护璐︽埛璁剧疆寮哄彛浠ゆ垨閿佸畾锛歱asswd -l <璐﹀彿>',
 NULL),
(1,'BL-LINUX-0010','宸查厤缃櫥褰曚細璇濊秴鏃惰嚜鍔ㄩ€€鍑?,'韬唤閴村埆',2,
 '{"type":"file_line","target":"/etc/profile","operator":"regex","expected":"^\\s*(readonly\\s+)?TMOUT="}',
 '鍦?/etc/profile 璁剧疆 TMOUT=600锛堝惈 readonly锛夛紝瓒呮椂鑷姩娉ㄩ攢',
 '{"risk":"auto","steps":[{"action":"file_line_ensure","path":"/etc/profile","line":"readonly TMOUT=600; export TMOUT","position":"append"}]}');

-- ---------- 璁块棶鎺у埗锛?0 椤癸級----------
INSERT INTO t_baseline_item (template_id, code, name, category, severity, check, remediation, fix_spec) VALUES
(1,'BL-LINUX-0011','/etc/passwd 鏂囦欢鏉冮檺搴斾负 644','璁块棶鎺у埗',3,
 '{"type":"file_perm","target":"/etc/passwd","perm":"0644","owner":"root","group":"root"}',
 'chmod 644 /etc/passwd锛沜hown root:root /etc/passwd',
 '{"risk":"auto","steps":[{"action":"chmod","path":"/etc/passwd","mode":"0644"},{"action":"chown","path":"/etc/passwd","owner":"root","group":"root"}]}'),
(1,'BL-LINUX-0012','/etc/shadow 鏂囦欢鏉冮檺搴斾负 600','璁块棶鎺у埗',4,
 '{"type":"file_perm","target":"/etc/shadow","perm":"0600","owner":"root","group":"root"}',
 'chmod 600 /etc/shadow锛沜hown root:root /etc/shadow',
 '{"risk":"auto","steps":[{"action":"chmod","path":"/etc/shadow","mode":"0600"},{"action":"chown","path":"/etc/shadow","owner":"root","group":"root"}]}'),
(1,'BL-LINUX-0013','/etc/group 鏂囦欢鏉冮檺搴斾负 644','璁块棶鎺у埗',2,
 '{"type":"file_perm","target":"/etc/group","perm":"0644","owner":"root","group":"root"}',
 'chmod 644 /etc/group锛沜hown root:root /etc/group',
 '{"risk":"auto","steps":[{"action":"chmod","path":"/etc/group","mode":"0644"},{"action":"chown","path":"/etc/group","owner":"root","group":"root"}]}'),
(1,'BL-LINUX-0014','/etc/gshadow 鏂囦欢鏉冮檺搴斾负 600','璁块棶鎺у埗',3,
 '{"type":"file_perm","target":"/etc/gshadow","perm":"0600","owner":"root","group":"root"}',
 'chmod 600 /etc/gshadow锛沜hown root:root /etc/gshadow',
 '{"risk":"auto","steps":[{"action":"chmod","path":"/etc/gshadow","mode":"0600"},{"action":"chown","path":"/etc/gshadow","owner":"root","group":"root"}]}'),
(1,'BL-LINUX-0015','闈炲繀瑕佺郴缁熻处鍙峰凡閿佸畾锛坙p/sync/halt/news 绛夛級','璁块棶鎺у埗',2,
 '{"type":"cmd_output","cmd":"grep -E \"^(lp|sync|shutdown|halt|news|uucp|operator|games|gopher):\" /etc/passwd | grep -vE \"nologin|false$\" | wc -l","operator":"eq","expected":"0","timeout_ms":5000}',
 '灏嗛潪蹇呰绯荤粺璐﹀彿 shell 鏀逛负 /sbin/nologin锛歶sermod -s /sbin/nologin <璐﹀彿>',
 NULL),
(1,'BL-LINUX-0016','UID=0 鐨勮处鍙峰彧鏈?root','璁块棶鎺у埗',4,
 '{"type":"cmd_output","cmd":"awk -F: ''($3==0 && $1!=\"root\"){print $1}'' /etc/passwd","operator":"eq","expected":"","timeout_ms":5000}',
 '妫€鏌?UID=0 寮傚父璐﹀彿骞跺垹闄ゆ垨闄嶆潈锛歶serdel / usermod -u',
 NULL),
(1,'BL-LINUX-0017','榛樿 umask 搴斾负 027锛堣嚦灏?022锛?,'璁块棶鎺у埗',2,
 '{"type":"file_content","target":"/etc/profile","regex":"^\\s*umask\\s+0(2[27]|07)\\s*$"}',
 '鍦?/etc/profile 璁剧疆 umask 027',
 '{"risk":"auto","steps":[{"action":"file_line_ensure","path":"/etc/profile","line":"umask 027","position":"replace_regex","pattern":"^\\s*umask\\s+\\d+"}]}'),
(1,'BL-LINUX-0018','sudo 閰嶇疆涓姝?NOPASSWD','璁块棶鎺у埗',3,
 '{"type":"file_line","target":"/etc/sudoers","operator":"not_contains","expected":"NOPASSWD"}',
 '妫€鏌?visudo 涓?NOPASSWD 閰嶇疆锛屾敼涓洪渶瑕佸彛浠ら獙璇?,
 NULL),
(1,'BL-LINUX-0019','/etc/crontab 鏉冮檺搴斾负 600','璁块棶鎺у埗',2,
 '{"type":"file_perm","target":"/etc/crontab","perm":"0600","owner":"root","group":"root"}',
 'chmod 600 /etc/crontab锛沜hown root:root /etc/crontab',
 '{"risk":"auto","steps":[{"action":"chmod","path":"/etc/crontab","mode":"0600"},{"action":"chown","path":"/etc/crontab","owner":"root","group":"root"}]}'),
(1,'BL-LINUX-0020','SSH 绂佺敤涓嶅畨鍏ㄧ殑 DNS 鍙嶆煡锛圲seDNS no锛?,'璁块棶鎺у埗',1,
 '{"type":"file_content","target":"/etc/ssh/sshd_config","regex":"^\\s*UseDNS\\s+no\\s*$"}',
 '鍦?/etc/ssh/sshd_config 璁剧疆 UseDNS no锛屽姞蹇櫥褰曞苟鍑忓皯淇℃伅娉勯湶',
 '{"risk":"auto","requires_restart":"sshd","steps":[{"action":"file_line_ensure","path":"/etc/ssh/sshd_config","line":"UseDNS no","position":"replace_regex","pattern":"^\\s*#?\\s*UseDNS\\s+\\w+"}]}');

-- ---------- 瀹夊叏瀹¤锛?0 椤癸級----------
INSERT INTO t_baseline_item (template_id, code, name, category, severity, check, remediation, fix_spec) VALUES
(1,'BL-LINUX-0021','auditd 瀹¤鏈嶅姟宸插畨瑁?,'瀹夊叏瀹¤',3,
 '{"type":"cmd_output","cmd":"command -v auditctl >/dev/null 2>&1 && echo yes || echo no","operator":"eq","expected":"yes","timeout_ms":5000}',
 '瀹夎瀹¤缁勪欢锛歽um install audit 鎴?apt install auditd',
 NULL),
(1,'BL-LINUX-0022','auditd 瀹¤鏈嶅姟姝ｅ湪杩愯','瀹夊叏瀹¤',3,
 '{"type":"cmd_output","cmd":"systemctl is-active auditd 2>/dev/null || echo inactive","operator":"eq","expected":"active","timeout_ms":5000}',
 'systemctl enable --now auditd',
 '{"risk":"auto","steps":[{"action":"service_restart","service":"auditd","mode":"enable_start"}]}'),
(1,'BL-LINUX-0023','瀹¤鏃ュ織鐩綍 /var/log/audit 鏉冮檺搴斾负 750','瀹夊叏瀹¤',2,
 '{"type":"file_perm","target":"/var/log/audit","perm":"0750","owner":"root","group":"root"}',
 'chmod 750 /var/log/audit锛沜hown root:root /var/log/audit',
 '{"risk":"auto","steps":[{"action":"chmod","path":"/var/log/audit","mode":"0750"},{"action":"chown","path":"/var/log/audit","owner":"root","group":"root"}]}'),
(1,'BL-LINUX-0024','rsyslog 鏃ュ織鏈嶅姟宸茶繍琛?,'瀹夊叏瀹¤',2,
 '{"type":"cmd_output","cmd":"systemctl is-active rsyslog 2>/dev/null || echo inactive","operator":"eq","expected":"active","timeout_ms":5000}',
 'systemctl enable --now rsyslog',
 '{"risk":"auto","steps":[{"action":"service_restart","service":"rsyslog","mode":"enable_start"}]}'),
(1,'BL-LINUX-0025','瀹¤瑙勫垯瑕嗙洊韬唤閴村埆鏂囦欢鍙樻洿锛?etc/passwd 绛夛級','瀹夊叏瀹¤',3,
 '{"type":"file_line","target":"/etc/audit/rules.d/audit.rules","operator":"contains","expected":"-w /etc/passwd"}',
 '鍦?/etc/audit/rules.d/audit.rules 澧炲姞 -w /etc/passwd -p wa -k identity锛屽苟 augenrules --load',
 '{"risk":"auto","steps":[{"action":"file_line_ensure","path":"/etc/audit/rules.d/audit.rules","line":"-w /etc/passwd -p wa -k identity","position":"append"},{"action":"file_line_ensure","path":"/etc/audit/rules.d/audit.rules","line":"-w /etc/shadow -p wa -k identity","position":"append"},{"action":"file_line_ensure","path":"/etc/audit/rules.d/audit.rules","line":"-w /etc/group -p wa -k identity","position":"append"}]}'),
(1,'BL-LINUX-0026','history 璁板綍甯︽椂闂存埑','瀹夊叏瀹¤',2,
 '{"type":"file_line","target":"/etc/profile","operator":"regex","expected":"^\\s*export\\s+HISTTIMEFORMAT"}',
 '鍦?/etc/profile 璁剧疆 export HISTTIMEFORMAT="%F %T "',
 '{"risk":"auto","steps":[{"action":"file_line_ensure","path":"/etc/profile","line":"export HISTTIMEFORMAT=\"%F %T \"","position":"append"}]}'),
(1,'BL-LINUX-0027','/var/log/btmp 鏉冮檺搴斾负 600','瀹夊叏瀹¤',2,
 '{"type":"file_perm","target":"/var/log/btmp","perm":"0600","owner":"root","group":"root"}',
 'chmod 600 /var/log/btmp',
 '{"risk":"auto","steps":[{"action":"chmod","path":"/var/log/btmp","mode":"0600"},{"action":"chown","path":"/var/log/btmp","owner":"root","group":"utmp"}]}'),
(1,'BL-LINUX-0028','/var/log/wtmp 鏉冮檺搴斾负 664','瀹夊叏瀹¤',1,
 '{"type":"file_perm","target":"/var/log/wtmp","perm":"0664","owner":"root","group":"utmp"}',
 'chmod 664 /var/log/wtmp',
 '{"risk":"auto","steps":[{"action":"chmod","path":"/var/log/wtmp","mode":"0664"},{"action":"chown","path":"/var/log/wtmp","owner":"root","group":"utmp"}]}'),
(1,'BL-LINUX-0029','瀹¤瑙勫垯瑕嗙洊 sudo 浣跨敤锛?var/log/audit锛?,'瀹夊叏瀹¤',2,
 '{"type":"file_line","target":"/etc/audit/rules.d/audit.rules","operator":"contains","expected":"-w /var/log/audit/"}',
 '鍦?/etc/audit/rules.d/audit.rules 澧炲姞 -w /var/log/audit/ -p wa -k auditlog锛屽苟 augenrules --load',
 '{"risk":"auto","steps":[{"action":"file_line_ensure","path":"/etc/audit/rules.d/audit.rules","line":"-w /var/log/audit/ -p wa -k auditlog","position":"append"}]}'),
(1,'BL-LINUX-0030','鏃ュ織鏂囦欢 /var/log/messages 灞炰富搴斾负 root','瀹夊叏瀹¤',2,
 '{"type":"cmd_output","cmd":"stat -c %U /var/log/messages 2>/dev/null || echo root","operator":"eq","expected":"root","timeout_ms":5000}',
 'chown root /var/log/messages',
 '{"risk":"auto","steps":[{"action":"chown","path":"/var/log/messages","owner":"root"}]}');

-- ---------- 鍏ヤ镜闃茶寖锛?2 椤癸級----------
INSERT INTO t_baseline_item (template_id, code, name, category, severity, check, remediation, fix_spec) VALUES
(1,'BL-LINUX-0031','SYN Flood 闃叉姢锛坱cp_syncookies=1锛?,'鍏ヤ镜闃茶寖',3,
 '{"type":"cmd_output","cmd":"sysctl -n net.ipv4.tcp_syncookies","operator":"eq","expected":"1","timeout_ms":5000}',
 'sysctl -w net.ipv4.tcp_syncookies=1 骞跺啓鍏?/etc/sysctl.conf',
 '{"risk":"auto","steps":[{"action":"sysctl_set","key":"net.ipv4.tcp_syncookies","value":"1"}]}'),
(1,'BL-LINUX-0032','绂佹鎺ュ彈 ICMP 閲嶅畾鍚戝寘','鍏ヤ镜闃茶寖',3,
 '{"type":"cmd_output","cmd":"sysctl -n net.ipv4.conf.all.accept_redirects","operator":"eq","expected":"0","timeout_ms":5000}',
 'sysctl -w net.ipv4.conf.all.accept_redirects=0锛堝惈 default 涓巌pv6锛?,
 '{"risk":"auto","steps":[{"action":"sysctl_set","key":"net.ipv4.conf.all.accept_redirects","value":"0"},{"action":"sysctl_set","key":"net.ipv4.conf.default.accept_redirects","value":"0"}]}'),
(1,'BL-LINUX-0033','绂佹 IPv6 ICMP 閲嶅畾鍚戯紙鑻ュ惎鐢?IPv6锛?,'鍏ヤ镜闃茶寖',2,
 '{"type":"cmd_output","cmd":"sysctl -n net.ipv6.conf.all.accept_redirects 2>/dev/null || echo 0","operator":"eq","expected":"0","timeout_ms":5000}',
 'sysctl -w net.ipv6.conf.all.accept_redirects=0',
 '{"risk":"auto","steps":[{"action":"sysctl_set","key":"net.ipv6.conf.all.accept_redirects","value":"0"}]}'),
(1,'BL-LINUX-0034','绂佹婧愯矾鐢辫浆鍙?,'鍏ヤ镜闃茶寖',3,
 '{"type":"cmd_output","cmd":"sysctl -n net.ipv4.conf.all.accept_source_route","operator":"eq","expected":"0","timeout_ms":5000}',
 'sysctl -w net.ipv4.conf.all.accept_source_route=0',
 '{"risk":"auto","steps":[{"action":"sysctl_set","key":"net.ipv4.conf.all.accept_source_route","value":"0"},{"action":"sysctl_set","key":"net.ipv4.conf.default.accept_source_route","value":"0"}]}'),
(1,'BL-LINUX-0035','蹇界暐 ICMP 骞挎挱璇锋眰','鍏ヤ镜闃茶寖',2,
 '{"type":"cmd_output","cmd":"sysctl -n net.ipv4.icmp_echo_ignore_broadcasts","operator":"eq","expected":"1","timeout_ms":5000}',
 'sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1',
 '{"risk":"auto","steps":[{"action":"sysctl_set","key":"net.ipv4.icmp_echo_ignore_broadcasts","value":"1"}]}'),
(1,'BL-LINUX-0036','寮€鍚弽鍚戣矾寰勮繃婊わ紙rp_filter=1锛?,'鍏ヤ镜闃茶寖',2,
 '{"type":"cmd_output","cmd":"sysctl -n net.ipv4.conf.all.rp_filter","operator":"eq","expected":"1","timeout_ms":5000}',
 'sysctl -w net.ipv4.conf.all.rp_filter=1',
 '{"risk":"auto","steps":[{"action":"sysctl_set","key":"net.ipv4.conf.all.rp_filter","value":"1"}]}'),
(1,'BL-LINUX-0037','璁板綍娆洪獥鍦板潃/martian 鏁版嵁鍖?,'鍏ヤ镜闃茶寖',1,
 '{"type":"cmd_output","cmd":"sysctl -n net.ipv4.conf.all.log_martians","operator":"eq","expected":"1","timeout_ms":5000}',
 'sysctl -w net.ipv4.conf.all.log_martians=1',
 '{"risk":"auto","steps":[{"action":"sysctl_set","key":"net.ipv4.conf.all.log_martians","value":"1"}]}'),
(1,'BL-LINUX-0038','闈炶矾鐢变富鏈哄簲鍏抽棴 IP 杞彂','鍏ヤ镜闃茶寖',3,
 '{"type":"cmd_output","cmd":"sysctl -n net.ipv4.ip_forward","operator":"eq","expected":"0","timeout_ms":5000}',
 '闈炵綉鍏?璺敱涓绘満鎵ц sysctl -w net.ipv4.ip_forward=0锛堟敞鎰忥細瀹瑰櫒瀹夸富鏈?K8S 鑺傜偣甯搁渶=1锛岃鎸夎鑹茬‘璁わ級',
 NULL),
(1,'BL-LINUX-0039','绂佹 core dump锛堝畨鍏ㄥ姞鍥洪」锛?,'鍏ヤ镜闃茶寖',2,
 '{"type":"file_line","target":"/etc/security/limits.conf","operator":"contains","expected":"* hard core 0"}',
 '鍦?/etc/security/limits.conf 澧炲姞 * hard core 0锛? soft core 0',
 '{"risk":"auto","steps":[{"action":"file_line_ensure","path":"/etc/security/limits.conf","line":"* soft core 0","position":"append"},{"action":"file_line_ensure","path":"/etc/security/limits.conf","line":"* hard core 0","position":"append"}]}'),
(1,'BL-LINUX-0040','SELinux 鎴?AppArmor 澶勪簬鍚敤鐘舵€?,'鍏ヤ镜闃茶寖',2,
 '{"type":"cmd_output","cmd":"sh -c \"(getenforce 2>/dev/null | grep -q Enforcing && echo enabled) || (aa-status --enabled 2>/dev/null && echo enabled) || echo disabled\"","operator":"eq","expected":"enabled","timeout_ms":5000}',
 '鍚敤 SELinux锛?etc/selinux/config = enforcing锛夋垨 AppArmor锛坰ystemctl enable --now apparmor锛?,
 NULL),
(1,'BL-LINUX-0041','/etc/ld.so.conf 鏉冮檺搴斾负 644','鍏ヤ镜闃茶寖',2,
 '{"type":"file_perm","target":"/etc/ld.so.conf","perm":"0644","owner":"root","group":"root"}',
 'chmod 644 /etc/ld.so.conf',
 '{"risk":"auto","steps":[{"action":"chmod","path":"/etc/ld.so.conf","mode":"0644"},{"action":"chown","path":"/etc/ld.so.conf","owner":"root","group":"root"}]}'),
(1,'BL-LINUX-0042','SUID/SGID 鏂囦欢鏃犺繎鏈熷紓甯告柊澧?,'鍏ヤ镜闃茶寖',2,
 '{"type":"cmd_output","cmd":"find /usr/bin /usr/sbin /usr/local/bin -perm -4000 -newer /etc/passwd 2>/dev/null | wc -l","operator":"eq","expected":"0","timeout_ms":15000}',
 '妫€鏌ユ柊澧?SUID 鏂囦欢鏄惁涓烘甯歌蒋浠跺畨瑁咃紝鍙枒鏂囦欢鎵ц chmod -s',
 NULL);

-- ---------- 鍓╀綑淇℃伅淇濇姢锛? 椤癸級----------
INSERT INTO t_baseline_item (template_id, code, name, category, severity, check, remediation, fix_spec) VALUES
(1,'BL-LINUX-0043','鐧诲綍鍓嶆樉绀哄畨鍏ㄥ憡璀︽í骞咃紙sshd Banner锛?,'鍓╀綑淇℃伅淇濇姢',1,
 '{"type":"file_content","target":"/etc/ssh/sshd_config","regex":"^\\s*Banner\\s+\\S+"}',
 '鍦?/etc/ssh/sshd_config 閰嶇疆 Banner /etc/issue.net锛屽苟缂栬緫鍛婅鏂囨',
 '{"risk":"manual","requires_restart":"sshd","steps":[{"action":"file_line_ensure","path":"/etc/ssh/sshd_config","line":"Banner /etc/issue.net","position":"replace_regex","pattern":"^\\s*#?\\s*Banner\\s+\\S*"}]}'),
(1,'BL-LINUX-0044','shell 閫€鍑烘椂娓呯悊鍘嗗彶鍛戒护锛圚ISTSIZE 闄愬埗锛?,'鍓╀綑淇℃伅淇濇姢',1,
 '{"type":"file_content","target":"/etc/profile","regex":"^\\s*export\\s+HISTSIZE=\\d+"}',
 '鍦?/etc/profile 璁剧疆 export HISTSIZE=500锛堟寜闇€锛夛紝鏁忔劅鐜鍙缃?0',
 '{"risk":"auto","steps":[{"action":"file_line_ensure","path":"/etc/profile","line":"export HISTSIZE=500","position":"append"}]}'),
(1,'BL-LINUX-0045','/etc/bashrc锛堟垨 bash.bashrc锛塽mask 涓€鑷?,'鍓╀綑淇℃伅淇濇姢',2,
 '{"type":"cmd_output","cmd":"sh -c \"f=/etc/bashrc; [ -f \\\"$f\\\" ] || f=/etc/bash.bashrc; grep -E ''^\\s*umask\\s+0(2[27]|07)'' \\\"$f\\\" >/dev/null 2>&1 && echo yes || echo no\"","operator":"eq","expected":"yes","timeout_ms":5000}',
 '鍦?/etc/bashrc锛圖ebian 绯讳负 /etc/bash.bashrc锛夎缃?umask 027',
 '{"risk":"auto","steps":[{"action":"file_line_ensure","path":"/etc/bashrc","line":"umask 027","position":"replace_regex","pattern":"^\\s*umask\\s+\\d+","optional_path":"/etc/bash.bashrc"}]}'),
(1,'BL-LINUX-0046','systemd-tmpfiles 瀹氭湡娓呯悊 /tmp','鍓╀綑淇℃伅淇濇姢',2,
 '{"type":"cmd_output","cmd":"systemctl list-timers --no-pager 2>/dev/null | grep -c systemd-tmpfiles","operator":"gt","expected":"0","timeout_ms":5000}',
 '纭繚 systemd-tmpfiles-clean.timer 鍚敤锛歴ystemctl enable --now systemd-tmpfiles-clean.timer',
 NULL),
(1,'BL-LINUX-0047','/tmp 鍒嗗尯鎸傝浇 nosuid/nodev锛堢嫭绔嬪垎鍖烘椂锛?,'鍓╀綑淇℃伅淇濇姢',2,
 '{"type":"cmd_output","cmd":"sh -c \"findmnt -n /tmp >/dev/null 2>&1 && findmnt -no OPTIONS /tmp | grep -cE ''nosuid|nodev'' || echo 1\"","operator":"gt","expected":"0","timeout_ms":5000}',
 '灏?/tmp 鎸傝浇閫夐」澧炲姞 nosuid,nodev锛?etc/fstab锛?,
 NULL),
(1,'BL-LINUX-0048','crond 鏈嶅姟鏃ュ織宸插惎鐢紙rsyslog cron.facility锛?,'鍓╀綑淇℃伅淇濇姢',1,
 '{"type":"file_line","target":"/etc/rsyslog.conf","operator":"regex","expected":"cron\\."}',
 '鍦?/etc/rsyslog.conf 閰嶇疆 cron.* /var/log/cron锛屽苟閲嶅惎 rsyslog',
 '{"risk":"auto","requires_restart":"rsyslog","steps":[{"action":"file_line_ensure","path":"/etc/rsyslog.conf","line":"cron.*                                                  /var/log/cron","position":"append"}]}');

-- ---------- 鎭舵剰浠ｇ爜闃茶寖锛? 椤癸級----------
INSERT INTO t_baseline_item (template_id, code, name, category, severity, check, remediation, fix_spec) VALUES
(1,'BL-LINUX-0049','涓绘満宸查儴缃?ALinkSec Agent锛堟伓鎰忎唬鐮侀槻鎶わ級','鎭舵剰浠ｇ爜闃茶寖',3,
 '{"type":"cmd_output","cmd":"command -v alinksec-agent >/dev/null 2>&1 && echo yes || echo no","operator":"eq","expected":"yes","timeout_ms":5000}',
 '瀹夎 ALinkSec Agent 骞舵帴鍏ュ钩鍙扮鐞?,
 NULL),
(1,'BL-LINUX-0050','鐥呮瘨鐗瑰緛搴撴枃浠跺瓨鍦ㄤ笖闈炵┖','鎭舵剰浠ｇ爜闃茶寖',3,
 '{"type":"file_perm","target":"/var/lib/alinksec-agent/signature.db","perm_exists":true}',
 '绛夊緟 Agent 棣栨鐗瑰緛搴撳悓姝ワ紙骞冲彴涓嬪彂鎴栭粯璁ゅ唴缃簱锛?,
 NULL),
(1,'BL-LINUX-0051','rpm 瀹夎鍚敤 GPG 鏍￠獙锛坓pgcheck=1锛?,'鎭舵剰浠ｇ爜闃茶寖',2,
 '{"type":"file_line","target":"/etc/yum.conf","operator":"contains","expected":"gpgcheck=1"}',
 '鍦?/etc/yum.conf 璁剧疆 gpgcheck=1',
 '{"risk":"auto","steps":[{"action":"file_line_ensure","path":"/etc/yum.conf","line":"gpgcheck=1","position":"replace_regex","pattern":"^\\s*gpgcheck\\s*=\\s*\\d+"}]}'),
(1,'BL-LINUX-0052','apt 涓嶅厑璁告湭璁よ瘉杞欢婧?,'鎭舵剰浠ｇ爜闃茶寖',2,
 '{"type":"cmd_output","cmd":"sh -c \"apt-config dump 2>/dev/null | grep -c AllowUnauthenticated \\\"1\\\"\" || echo 0","operator":"eq","expected":"0","timeout_ms":5000}',
 '绉婚櫎 APT 閰嶇疆涓殑 AllowUnauthenticated \"1\"',
 NULL),
(1,'BL-LINUX-0053','杞欢婧愬湴鍧€涓?https 鎴栧唴閮ㄥ彲淇℃簮','鎭舵剰浠ｇ爜闃茶寖',1,
 '{"type":"cmd_output","cmd":"sh -c \"grep -rhE ''^(baseurl|deb)\\s+\\S+'' /etc/yum.repos.d/ /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null | grep -vcE ''https|file:///|ftp://鍐呯綉|^[[:space:]]*#'' || echo 0\"","operator":"eq","expected":"0","timeout_ms":5000}',
 '灏嗚蒋浠舵簮鏀逛负 https 鍗忚鎴栧唴閮ㄩ暅鍍忔簮锛岄槻姝㈡姇姣?,
 NULL),
(1,'BL-LINUX-0054','瀹氭湡鐥呮瘨鎵弿浠诲姟宸查厤缃紙cron锛?,'鎭舵剰浠ｇ爜闃茶寖',2,
 '{"type":"file_perm","target":"/etc/cron.d/alinksec-scan","perm_exists":true}',
 '鐢卞钩鍙颁笅鍙戝畾鏃舵壂鎻忕瓥鐣ワ紙M2 璧锋敮鎸侊級锛屾垨鎵嬪伐閰嶇疆 cron',
 NULL);

-- ---------- 璧勬簮鎺у埗锛? 椤癸級----------
INSERT INTO t_baseline_item (template_id, code, name, category, severity, check, remediation, fix_spec) VALUES
(1,'BL-LINUX-0055','鏃堕棿鍚屾鏈嶅姟锛坈hronyd/ntpd锛夊凡鍚敤','璧勬簮鎺у埗',2,
 '{"type":"cmd_output","cmd":"sh -c \"systemctl is-active chronyd 2>/dev/null || systemctl is-active ntpd 2>/dev/null || echo inactive\"","operator":"eq","expected":"active","timeout_ms":5000}',
 '瀹夎骞跺惎鐢?chrony锛歽um install chrony && systemctl enable --now chronyd',
 NULL),
(1,'BL-LINUX-0056','鏂囦欢鍙ユ焺鏁伴檺鍒跺凡璁剧疆锛坣ofile锛?,'璧勬簮鎺у埗',2,
 '{"type":"file_line","target":"/etc/security/limits.conf","operator":"regex","expected":"^\\*\\s+(soft|hard)\\s+nofile\\s+\\d+"}',
 '鍦?/etc/security/limits.conf 璁剧疆 * soft/hard nofile 65535',
 '{"risk":"auto","steps":[{"action":"file_line_ensure","path":"/etc/security/limits.conf","line":"* soft nofile 65535","position":"append"},{"action":"file_line_ensure","path":"/etc/security/limits.conf","line":"* hard nofile 65535","position":"append"}]}'),
(1,'BL-LINUX-0057','鐢ㄦ埛杩涚▼鏁伴檺鍒跺凡璁剧疆锛坣proc锛?,'璧勬簮鎺у埗',2,
 '{"type":"file_line","target":"/etc/security/limits.conf","operator":"regex","expected":"^\\*\\s+(soft|hard)\\s+nproc\\s+\\d+"}',
 '鍦?/etc/security/limits.conf 璁剧疆 * soft/hard nproc 65535锛堟寜涓氬姟璇勪及锛?,
 '{"risk":"manual","steps":[{"action":"file_line_ensure","path":"/etc/security/limits.conf","line":"* soft nproc 65535","position":"append"},{"action":"file_line_ensure","path":"/etc/security/limits.conf","line":"* hard nproc 65535","position":"append"}]}'),
(1,'BL-LINUX-0058','/etc/securetty 鏉冮檺搴斾负 600','璧勬簮鎺у埗',2,
 '{"type":"file_perm","target":"/etc/securetty","perm":"0600","owner":"root","group":"root"}',
 'chmod 600 /etc/securetty锛堥檺瀹?root 鍙櫥褰曠殑缁堢锛?,
 '{"risk":"auto","steps":[{"action":"chmod","path":"/etc/securetty","mode":"0600"},{"action":"chown","path":"/etc/securetty","owner":"root","group":"root"}]}'),
(1,'BL-LINUX-0059','鍗曠敤鎴锋ā寮忥紙rescue/emergency锛夐渶瑕佽璇?,'璧勬簮鎺у埗',3,
 '{"type":"cmd_output","cmd":"sh -c \"grep -hE ''^ExecStart=.*sulogin'' /usr/lib/systemd/system/rescue.service /usr/lib/systemd/system/emergency.service 2>/dev/null | wc -l\"","operator":"eq","expected":"2","timeout_ms":5000}',
 '纭 rescue.service / emergency.service 鐨?ExecStart 浣跨敤 sulogin锛堝彂琛岀増榛樿婊¤冻锛?,
 NULL),
(1,'BL-LINUX-0060','Ctrl-Alt-Del 閲嶅惎缁勫悎閿凡绂佺敤','璧勬簮鎺у埗',2,
 '{"type":"cmd_output","cmd":"sh -c \"systemctl is-enabled ctrl-alt-del.target 2>/dev/null || echo enabled\"","operator":"eq","expected":"disabled","timeout_ms":5000}',
 'systemctl mask ctrl-alt-del.target 闃叉鐗╃悊鎺ヨЕ鑰呴噸鍚富鏈?,
 '{"risk":"auto","steps":[{"action":"cmd_run","cmd":"systemctl mask ctrl-alt-del.target"}]}');

-- ------------------------------------------------------------
-- CVE 鏍蜂緥搴擄紙婕旂ず姣斿鑳藉姏锛涚敓浜х敱 NVD/OVAL 绂荤嚎瀵煎叆鏇挎崲锛?
-- affected 鏍煎紡锛歔{"name":"杞欢鍚?灏忓啓)","vrange":"<鍥哄畾鐗堟湰","os":"centos7|ubuntu2204|*"}]
-- ------------------------------------------------------------
INSERT INTO t_cve_db (cve_id, title, severity, cvss, affected, description, published_at) VALUES
('CVE-2024-6387','OpenSSH regreSSHion 杩滅▼浠ｇ爜鎵ц','4',8.1,
 '[{"name":"openssh","vrange":"<9.8p1","os":"*"}]'::jsonb,
 'OpenSSH 鏈嶅姟绔俊鍙峰鐞嗙▼搴忕珵浜夋潯浠讹紙SIGALRM/CVE-2024-6387锛夛紝鏈璇佽繙绋嬪埄鐢ㄥ彲鑳?RCE銆傚崌绾ц嚦 9.8p1 鍙婁互涓婃垨搴旂敤鍙戣鐗堣ˉ涓併€?,'2024-07-01'),
('CVE-2024-1086','Linux 鍐呮牳 nf_tables UAF 鏈湴鎻愭潈','4',7.8,
 '[{"name":"kernel","vrange":"<6.7.10","os":"*"}]'::jsonb,
 'netfilter nf_tables 閫氱敤 set 鍨冨溇鍥炴敹 UAF锛屾湰鍦颁綆鏉冪敤鎴峰彲鎻愭潈鑷?root銆傚強鏃舵洿鏂板唴鏍稿苟閲嶅惎銆?,'2024-02-01'),
('CVE-2023-4966','Citrix Bleed 浼氳瘽浠ょ墝娉勯湶','4',9.4,
 '[{"name":"netscaler-gateway","vrange":"<13.1-49.15","os":"*"}]'::jsonb,
 'NetScaler ADC/Gateway 鏁忔劅淇℃伅娉勯湶锛屽彲缁曡繃 MFA 浼氳瘽鎺ョ銆?,'2023-10-01'),
('CVE-2023-44487','HTTP/2 Rapid Reset 鎷掔粷鏈嶅姟','4',7.5,
 '[{"name":"nginx","vrange":"<1.25.3","os":"*"},{"name":"apache-httpd","vrange":"<2.4.58","os":"*"}]'::jsonb,
 'HTTP/2 鍗忚灞?DoS锛屾敾鍑昏€呭彲浣庢垚鏈墦鐦湇鍔°€傚崌绾ф垨璋冧綆骞跺彂娴佷笂闄愩€?,'2023-10-01'),
('CVE-2023-38545','curl SOCKS5 鍫嗘孩鍑?,'4',8.8,
 '[{"name":"curl","vrange":"<8.4.0","os":"*"}]'::jsonb,
 'curl SOCKS5 浠ｇ悊鎻℃墜鍫嗙紦鍐插尯婧㈠嚭锛屾伓鎰忔湇鍔＄鍙帶婧㈠嚭闀垮害銆傚崌绾?curl 8.4.0+銆?,'2023-10-01'),
('CVE-2022-0778','OpenSSL BN_mod_sqrt() 鏃犻檺寰幆 DoS','3',7.5,
 '[{"name":"openssl","vrange":"<1.1.1n","os":"*"}]'::jsonb,
 '鐣稿舰璇佷功鍙Е鍙?OpenSSL CPU 绌鸿浆銆傚崌绾ц嚦淇鐗堟湰銆?,'2022-03-01'),
('CVE-2021-4034','sudo Baron Samedit 鏈湴鎻愭潈','4',7.8,
 '[{"name":"sudo","vrange":"<1.9.5p2","os":"*"}]'::jsonb,
 'sudo 瀵逛互鍙嶆枩鏉犵粨灏剧殑鍙傛暟 argv[0] 鍫嗘孩鍑猴紝浠绘剰鏈湴鐢ㄦ埛鍏嶅瘑鎻愭潈 root銆?,'2022-01-01'),
('CVE-2021-3156','sudo heap-based 婧㈠嚭锛堥厤鍚?4034 鍓嶇疆鎶湶锛?,'4',7.8,
 '[{"name":"sudo","vrange":"<1.9.5p2","os":"*"}]'::jsonb,
 'sudoedit 鐜鍙橀噺杞箟鍫嗘孩鍑猴紝鏈湴鎻愭潈銆?,'2021-01-01'),
('CVE-2021-44228','Apache Log4j2 JNDI RCE锛圠og4Shell锛?,'4',10.0,
 '[{"name":"log4j-core","vrange":"<2.15.0","os":"*"}]'::jsonb,
 'JNDI 娉ㄥ叆杩滅▼浠ｇ爜鎵ц锛屽奖鍝嶉潰鏋佸箍銆傚崌绾?2.17.1+銆?,'2021-12-01'),
('CVE-2019-5716','OpenSSH 瀹㈡埛绔唴瀛樼牬鍧?,'3',6.5,
 '[{"name":"openssh","vrange":"<7.9p1","os":"*"}]'::jsonb,
 '鎭舵剰 SSH 鏈嶅姟绔彲閫犳垚瀹㈡埛绔唴瀛樼牬鍧忋€?,'2019-01-01'),
('CVE-2018-15473','OpenSSH 鐢ㄦ埛鍚嶆灇涓?,'2',5.3,
 '[{"name":"openssh","vrange":"<7.8","os":"*"}]'::jsonb,
 '鍙繙绋嬫灇涓炬湁鏁堢敤鎴峰悕锛岄厤鍚堝瓧鍏哥垎鐮淬€?,'2018-08-01'),
('CVE-2016-5195','Linux 鍐呮牳 Dirty COW 鏈湴鎻愭潈','4',7.8,
 '[{"name":"kernel","vrange":"<4.8.3","os":"*"}]'::jsonb,
 'get_user_page() 绔炰簤鏉′欢鍐欏彧璇诲唴瀛樻槧灏勶紝鏈湴鎻愭潈銆?,'2016-10-01'),
('CVE-2014-6271','Bash Shellshock RCE','4',9.8,
 '[{"name":"bash","vrange":"<4.3","os":"*"}]'::jsonb,
 '鐜鍙橀噺鍑芥暟瀹氫箟灏鹃儴娉ㄥ叆鍛戒护鎵ц銆?,'2014-09-01'),
('CVE-2023-5678','OpenSSL DH 妫€鏌?DoS','3',5.3,
 '[{"name":"openssl","vrange":"<3.0.12","os":"*"}]'::jsonb,
 'DH 瀵嗛挜鍙傛暟鏍￠獙鍙Е鍙戦暱鏃堕棿璁＄畻銆?,'2023-11-01'),
('CVE-2020-1472','Zerologon 鍩熸帶鎻愭潈','4',10.0,
 '[{"name":"samba","vrange":"<4.12.11","os":"*"}]'::jsonb,
 'Netlogon 鐗规潈鎻愬崌锛圵indows 鍩熸帶/Samba DC锛夛紝閲嶇疆鍩熸帶鏈哄櫒璐︽埛瀵嗙爜銆?,'2020-08-01'),
('CVE-2022-22965','Spring Framework RCE锛圫pring4Shell锛?,'4',9.8,
 '[{"name":"spring-core","vrange":"<5.2.20","os":"*"}]'::jsonb,
 '鏁版嵁缁戝畾缁曡繃 ClassLoader 灞炴€ц闂?RCE锛孞DK9+ + Tomcat 閮ㄧ讲褰㈡€佸彈褰卞搷銆?,'2022-03-01'),
('CVE-2023-34362','MOVEit Transfer SQL 娉ㄥ叆','4',9.8,
 '[{"name":"moveit-transfer","vrange":"<2023.0.1","os":"*"}]'::jsonb,
 '鏈璇?SQL 娉ㄥ叆瀵艰嚧 RCE 涓庢暟鎹獌鍙栥€?,'2023-05-01'),
('CVE-2024-21762','Fortinet FortiOS 璺緞绌胯秺 RCE','4',9.6,
 '[{"name":"fortios","vrange":"<7.4.2","os":"*"}]'::jsonb,
 'SSL VPN 璺緞绌胯秺鍐欐枃浠?RCE銆?,'2024-02-01'),
('CVE-2021-34527','Windows Print Spooler RCE锛圥rintNightmare锛?,'4',8.8,
 '[{"name":"spooler","vrange":"<10.0","os":"windows"}]'::jsonb,
 '鎵撳嵃鍚庡彴澶勭悊鏈嶅姟 RCE/鏈湴鎻愭潈锛岀鐢?Print Spooler 鎴栨墦琛ヤ竵銆?,'2021-06-01'),
('CVE-2017-0144','Windows SMBv1 杩滅▼鎵ц锛圗ternalBlue锛?,'4',8.1,
 '[{"name":"smb","vrange":"<6.0.0","os":"windows"}]'::jsonb,
 'MS17-010锛屽嫆绱㈣爼铏紙WannaCry/Petya锛変富瑕佷紶鎾€斿緞銆?,'2017-04-01')
ON CONFLICT (cve_id) DO NOTHING;

-- =============================================================
-- ALinkSec 003锛歁2 鎸囨爣/鏃ュ織琛ュ厖琛?
-- =============================================================

-- Agent 閲囬泦鏃ュ織锛圠OG_BATCH 钀藉簱锛涚櫥褰?瀹夊叏鏃ュ織锛屼緵鎺掗殰涓庡叆渚垫娴嬪洖婧級
CREATE TABLE IF NOT EXISTS t_agent_log (
    id          BIGSERIAL PRIMARY KEY,
    agent_id    VARCHAR(64)  NOT NULL,
    source      VARCHAR(64)  NOT NULL,                 -- secure / windows-security / custom:<path>
    content     VARCHAR(4000) NOT NULL,                -- 鍗曡鍐呭锛堣秴闀垮凡鍦?Agent 渚ф埅鏂級
    fields      JSONB,                                 -- 缁撴瀯鍖栧瓧娈碉紙瑙ｆ瀽鍚庯紝鍙┖锛?
    log_ts      BIGINT       NOT NULL,                 -- 琛屾椂闂存埑锛坢s锛?
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_agent_log_agent_time ON t_agent_log (agent_id, log_ts DESC);
CREATE INDEX IF NOT EXISTS idx_agent_log_source     ON t_agent_log (source);

-- ============================================================
-- ALinkSec M3(05-鎵╁睍鑳藉姏) 鍕掔储璇遍サ闃叉姢
-- 鑼冨洿锛氶槻鎶ょ瓥鐣ュ煙锛坉ocs/03 搂t_protect_rule锛?
-- 渚濊禆锛?01_m1_init.sql
-- 璇存槑锛欰gent 渚ц楗靛弬鏁拌蛋鏈湴 agent.yml锛堟湰鍦扮绾у搷搴斾笉渚濊禆鏈嶅姟绔湪绾匡級锛?
--       鏈〃涓哄钩鍙颁晶瑙勫垯婧愪笌灞曠ず锛堟嫤鎴褰曞鐢?t_alert锛屼笉鏂板缓浜嬩欢琛級
-- ============================================================

CREATE TABLE IF NOT EXISTS t_protect_rule (
  id         BIGSERIAL PRIMARY KEY,
  rule_id    VARCHAR(64) NOT NULL UNIQUE,       -- PR-0010
  name       VARCHAR(128) NOT NULL,
  type       VARCHAR(32) NOT NULL,              -- process/file_integrity/login/decoy/ransom_behavior
  match      JSONB NOT NULL,                    -- 鍖归厤鏉′欢锛坉irs/count_per_dir/exclude_exes 绛夛級
  actions    JSONB NOT NULL,                    -- ["kill","alert"]
  severity   SMALLINT NOT NULL DEFAULT 3,       -- 1浣?2涓?3楂?4涓ラ噸
  enabled    BOOLEAN NOT NULL DEFAULT TRUE,
  built_in   BOOLEAN NOT NULL DEFAULT FALSE,
  version    BIGINT NOT NULL DEFAULT 1,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 鍐呯疆瑙勫垯锛氳楗甸槻鎶?/ 鍔犲瘑琛屼负鍒嗘瀽锛坉ocs/05 搂2锛宮atch 瀛楁鍚屾椂浣滀负鍓嶇缂栬緫婧愶級
INSERT INTO t_protect_rule (rule_id, name, type, match, actions, severity, enabled, built_in) VALUES
  ('PR-0010', '鍕掔储璇遍サ闃叉姢', 'decoy',
   '{"dirs":["/home","/srv","/opt"],"count_per_dir":4,"exclude_exes":["/usr/bin/rsync","D:\\\\backup\\\\agent.exe"]}'::jsonb,
   '["kill","alert"]'::jsonb, 4, TRUE, TRUE),
  ('PR-0011', '鍔犲瘑琛屼负鍒嗘瀽', 'ransom_behavior',
   '{"rate_window_sec":10,"rate_threshold":50,"ext_change_ratio":0.8}'::jsonb,
   '["kill","alert"]'::jsonb, 4, TRUE, TRUE),
  ('PR-0001', 'EDR miner process block', 'process',
   '{"exe_regex":"(?i)(^|/)(xmrig|minerd|kdevtmpfsi|kinsing)$"}'::jsonb,
   '["kill","alert"]'::jsonb, 4, TRUE, TRUE)
ON CONFLICT (rule_id) DO NOTHING;

-- 绛栫暐鐗堟湰涓庡叏閲忓揩鐓э紙鍗曡琛紱t_protect_rule 鍙樻洿 鈫?version 閫掑 + content 閲嶅缓锛孭olicySync 鐑笅鍙戯級
CREATE TABLE IF NOT EXISTS t_policy_state (
  id         INT PRIMARY KEY DEFAULT 1 CHECK (id = 1),   -- 鍗曡绾︽潫
  version    BIGINT NOT NULL DEFAULT 1,                  -- 绛栫暐鐗堟湰锛圓gent 蹇冭烦 policy_version 姣斿锛?
  content    JSONB  NOT NULL DEFAULT '{}'::jsonb,        -- 鍏ㄩ噺绛栫暐蹇収锛坧olicy_json锛歞ecoy 娈电瓑锛?
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO t_policy_state (id, version) VALUES (1, 1) ON CONFLICT (id) DO NOTHING;

-- ============================================================
-- M4 杞欢鍖呯被婕忔礊淇锛坉ocs/05 搂3.3/搂3.4锛?
-- ============================================================

-- 绂荤嚎琛ヤ竵浠撳簱娓呭崟锛堟枃浠惰惤骞冲彴瀛樺偍鐩綍锛宼_patch_package 璁板厓鏁版嵁锛?
-- 瀵煎叆涓哄疄鏂?杩愮淮绂荤嚎鎿嶄綔锛孲OW 鏄庣‘绾﹀畾锛?
CREATE TABLE IF NOT EXISTS t_patch_package (
  id             BIGSERIAL PRIMARY KEY,
  os_type        SMALLINT NOT NULL,              -- 1 Linux 2 Windows
  os_version     VARCHAR(64) NOT NULL DEFAULT '',-- centos7 / ubuntu2204 / win2019锛堢┖ = 閫氱敤锛?
  pkg_name       VARCHAR(255) NOT NULL,          -- openssl / openssl-devel / KB5034441
  target_version VARCHAR(128) NOT NULL,          -- 1.1.1k-26.el7_9锛坮pm/deb 瀹屾暣鐗堟湰锛沵su 涓?KB 鍙凤級
  repo_type      VARCHAR(8)  NOT NULL,           -- rpm / deb / msu
  filename       VARCHAR(255) NOT NULL,          -- 瀛樺偍鏂囦欢鍚嶏紙涓嬭浇绔偣鎸夊悕鍙栦欢锛?
  sha256         VARCHAR(64)  NOT NULL,
  size           BIGINT NOT NULL DEFAULT 0,
  imported_by    BIGINT,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (os_type, os_version, pkg_name, target_version)
);
CREATE INDEX IF NOT EXISTS idx_patch_pkg ON t_patch_package(pkg_name);

-- 淇浠诲姟瀹℃壒涓庣淮鎶ょ獥鍙ｏ紙杞欢鍖呯被蹇呭～瀹℃壒锛涢厤缃被娌跨敤鐜版湁瀛楁涓嶅彈褰卞搷锛?
ALTER TABLE t_fix_task ADD COLUMN IF NOT EXISTS approver     VARCHAR(128);
ALTER TABLE t_fix_task ADD COLUMN IF NOT EXISTS approved     BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE t_fix_task ADD COLUMN IF NOT EXISTS approved_at  TIMESTAMPTZ;
ALTER TABLE t_fix_task ADD COLUMN IF NOT EXISTS window_start TIMESTAMPTZ;  -- 缁存姢绐楀彛璧凤紙绌?= 瀹℃壒鍚庣珛鍗虫墽琛岋級
ALTER TABLE t_fix_task ADD COLUMN IF NOT EXISTS window_end   TIMESTAMPTZ;
ALTER TABLE t_fix_task ADD COLUMN IF NOT EXISTS dispatched_at TIMESTAMPTZ; -- 瀹為檯娲惧彂鏃堕棿锛堢獥鍙ｈ皟搴﹀垽瀹氾級
-- type 鎵╁睍锛?閰嶇疆绫?2杞欢鍖呯被锛泂tatus 璇箟鎵╁睍锛?寰呮墽琛?寰呭鎵?
COMMENT ON COLUMN t_fix_task.type IS '1閰嶇疆绫?2杞欢鍖呯被';

-- =====================================================================
-- 006 M4锛欰gent 鐏板害鍗囩骇 + 骞冲彴鎿嶄綔瀹¤ + 閫氱煡娓犻亾
-- =====================================================================

-- Agent 鍗囩骇鍖咃紙docs/01 搂6.4锛氫笂浼?鈫?鐏板害涓嬪彂 鈫?蹇冭烦涓婃姤鏂扮増鏈級
CREATE TABLE IF NOT EXISTS t_agent_upgrade_package (
    id            BIGSERIAL PRIMARY KEY,
    version       VARCHAR(64)  NOT NULL UNIQUE,     -- 鍖呯増鏈紙濡?1.2.0锛?
    platform      VARCHAR(32)  NOT NULL,            -- linux-amd64 / linux-arm64 / windows-amd64
    package_key   VARCHAR(200) NOT NULL,            -- 瀛樺偍鏂囦欢鍚嶏紙涓嬭浇绔偣鐢級
    sha256        VARCHAR(64)  NOT NULL,
    size          BIGINT       NOT NULL,
    notes         TEXT,                             -- 鍙戝竷璇存槑
    uploaded_by   BIGINT,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- 骞冲彴鎿嶄綔瀹¤锛坉ocs/01 搂6.1锛氭墍鏈夊啓鎿嶄綔鍏ュ璁¤〃锛屽惈鏉ユ簮 IP锛?

-- 閫氱煡娓犻亾锛圡4锛氬憡璀?webhook 閫氱煡锛沞nabled 鍏抽棴鏃朵笉鍙戦€侊級
CREATE TABLE IF NOT EXISTS t_notify_channel (
    id          BIGSERIAL PRIMARY KEY,
    name        VARCHAR(64)  NOT NULL,
    type        VARCHAR(16)  NOT NULL DEFAULT 'webhook',
    webhook_url TEXT         NOT NULL,
    min_severity SMALLINT    NOT NULL DEFAULT 3,    -- 閫氱煡闂ㄦ锛氣墺high锛?=critical锛?
    enabled     BOOLEAN      NOT NULL DEFAULT true,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- Delivery state is tracked per alert and channel so a retry does not resend
-- notifications that were already accepted by another channel.
CREATE TABLE IF NOT EXISTS t_alert_notify_delivery (
    id           BIGSERIAL PRIMARY KEY,
    alert_no     VARCHAR(64) NOT NULL,
    channel_id   BIGINT      NOT NULL,
    attempts     INTEGER     NOT NULL DEFAULT 0,
    attempted_at TIMESTAMPTZ,
    delivered_at TIMESTAMPTZ,
    last_error   TEXT,
    UNIQUE (alert_no, channel_id)
);
CREATE INDEX IF NOT EXISTS idx_alert_notify_pending
    ON t_alert_notify_delivery (delivered_at, attempted_at);

-- t_alert 琛ラ€氱煡鏍囪锛堝凡閫氱煡鐨勫憡璀︿笉閲嶅鎺ㄩ€侊紱澶辫触鐢卞畾鏃朵换鍔″鏈爣璁扮殑閲嶈瘯锛?
ALTER TABLE t_alert ADD COLUMN IF NOT EXISTS notified BOOLEAN NOT NULL DEFAULT false;

-- RBAC 涓夎鑹茶ˉ鍏紙docs/01 搂6.1锛夛細瀹夊叏杩愮淮瑙掕壊锛坴iewer 鍙宸插湪 002 鍒濆鍖栵級
-- 鏉冮檺鐐逛负澹版槑寮忚鏄庯紱鎺ュ彛绾у己鍒剁敱 JwtAuthInterceptor 鍐欐潈闄愮煩闃垫墽琛?
INSERT INTO t_role (id, name, permissions) VALUES
  (3, 'operator', '["*:view","scan:run","fix:apply","alert:handle","report:export"]'::jsonb)
ON CONFLICT (id) DO NOTHING;
