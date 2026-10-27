# ALinkSec Agent 详细设计与策略规范

> 版本基线：v0.0.4。已按本版核对「ALinkSec Agent 详细设计与策略规范」的操作、实现引用与适用边界；历史日期及验证结果仍只对应其原始提交。版本差异见[发布说明](releases/v0.0.4.md)，全部资料见[文档索引](README.md)。

> 适用版本：v0.0.4；更新日期：2026-10-25。

当前 Agent 源码产品版本为 `0.0.4`，可执行 `alinksec-agent version` 查询。构建目标为 Linux amd64、Linux arm64 和 Windows amd64 原生二进制；Linux 使用随包 systemd 单元，Windows `run` 自动接入 SCM。安装与服务配置见 [部署文档第 8 节](06-部署文档.md)。内置默认告警策略、实际 Linux 文件/SSH 防护配置见 [防护说明](11-登录与文件防护.md)。本文资源指标是设计目标，已测资源与平台覆盖以 [原生 Agent 验收](12-原生Agent本机验收记录.md)和 [ARM64 验收](14-ARM64支持.md)为准。
> 语言/运行时：Go 1.24+，CGO_ENABLED=0 原生成品（linux/amd64、linux/arm64、windows/amd64）。

`linux/arm64` 构建与原生 CI 已合并；Agent 按自身构建架构上报 `amd64` / `arm64`，平台兼容旧版本上报的 `x86_64` / `aarch64`。升级下发核对整批目标的 OS 与架构，Agent 替换自身前再次校验包内构建平台。ARM64 从 v0.0.2 提供，v0.0.1 成品不包含 ARM64，见 [ARM64 部署](14-ARM64支持.md)。

新增能力的运行契约、真实平台证据及异常边界分别见[升级](55-Agent升级看护与自动回退.md)、[隔离](56-主机隔离租约与失联撤销.md)、[配置恢复](57-Agent配置防篡改与可信恢复.md)、[资源适配](58-Agent资源自适应与有界补传.md)、[Windows 登录](60-Windows登录防护与覆盖状态.md)、[ETW](61-Windows勒索进程归因与安全响应.md)、[WUA](62-Windows更新发现与自动修复.md)、[SCAP](68-XCCDF与OVAL原生解释.md)和[取证](74-集中取证与自动恢复点.md)。目录树是结构摘要，实际新增包以 [internal](../agent/internal)为准。

## 1. 工程结构

```text
agent/
├── cmd/agent/          # run / install / uninstall / version，平台服务入口
└── internal/
    ├── comm/          # gRPC、注册、状态、指令、策略与 JSONL 离线队列
    ├── config/        # agent.yml、默认值与约束
    ├── identity/      # 身份与概要指标、AgentVersion
    ├── collector/     # 主机资产、容器和本机工作负载
    ├── baseline/      # 结构化基线与白名单命令检查
    ├── scan/          # 漏洞、弱口令与端口扫描
    ├── virusscan/     # SHA256、内部规则、白名单与隔离
    ├── fixer/         # 配置及软件包修复
    ├── guard/         # 进程、文件、SSH、诱饵与隔离
    ├── logcollect/    # 日志采集与上报
    ├── sysmetrics/    # 性能指标
    ├── isolation/     # 认证租约、原生独立看护与专属防火墙规则
    ├── securestate/   # 私有原子恢复记录及跨进程锁
    ├── upgrade/       # 下载、SHA256 校验、独立看护与失败回退
    └── proto/         # 当前生成的 Go 协议类型
```

实际依赖以 [go.mod](../agent/go.mod)为准：gopsutil v3/v4、gRPC、Protobuf、yaml.v3、x/sys、Windows WMI 及固定版本 tailscale/wf（动态 WFP）。默认成品不依赖 Agent SQLite、kardianos/service、go-yara 或 lumberjack；可选原生 YARA 使用项目自己的 CGO 接口和独立审核运行库；Linux 由 systemd 管理，Windows 直接接入 x/sys/windows/svc。

| 平台 | 默认配置与工作目录 | 常驻日志 |
| --- | --- | --- |
| Linux | `/var/lib/alinksec-agent/agent.yml`，工作目录 `/var/lib/alinksec-agent` | systemd journal |
| Windows | `C:\\ProgramData\\alinksec-agent\\agent.yml`，工作目录 `C:\\ProgramData\\alinksec-agent` | 按服务部署环境配置输出采集 |

工作目录保存 `state.yml`、`policy.json`、`certs/`、`queue/pending.jsonl` 与病毒/防护状态，可用 `--workdir` 显式覆盖。敏感状态和证书由权限控制，不打入发布包。

## 2. 模块设计

### 2.1 comm（通信）

- 维护单条 gRPC 双向流，发送通道容量 256；接收循环按 Command 类型分发。
- 重连：指数退避 1s→30s（±20% 抖动）；重连成功先发心跳并触发策略版本比对。
- 业务报告先持久化到 `queue/pending.jsonl`，发送失败保留、重连后补传；默认限速 100 msg/s。心跳等实时状态按当前连接采样。

### 2.2 scheduler（采集调度）

- 每个 collector 注册 `{name, interval, run}`，调度器按 interval 派发（错峰：初始随机延迟 < interval）。
- 支持 `CmdCollectNow` 立即触发；支持 `PAUSE_COLLECT` 全局暂停（防护不暂停）。

### 2.3 采集项清单

| 采集项 | 频率（默认，可配） | Linux 实现 | Windows 实现 |
|--------|------|-----------|--------------|
| CPU/内存/load | 10s | gopsutil（/proc/stat、/proc/meminfo） | gopsutil（PDH 计数器） |
| 磁盘容量 | 60s | statfs | GetDiskFreeSpaceEx |
| 磁盘 IO | 10s | /proc/diskstats | PDH Disk 计数器 |
| 网络 IO | 10s | /proc/net/dev | GetIfTable |
| 进程快照 | 60s | /proc + gopsutil | WMI Win32_Process |
| 监听端口 | 60s | /proc/net/tcp、tcp6（无需 root 权限的部分字段降级） | GetExtendedTcpTable/GetExtendedUdpTable |
| 软件清单 | 24h 或 dpkg/rpm 数据库 mtime 变更触发 | rpm -qa --qf / dpkg-query -l | 注册表 Uninstall 键枚举 |
| 账户清单 | 24h | /etc/passwd、/etc/shadow（需 root） | Win32_UserAccount + SAM 状态 |
| 容器/本机工作负载 | 随资产快照（默认 6h） | Docker CLI 只读清点；本机 `kubectl` 按 `spec.nodeName` 只读清点 | 本期不采集 |
| 登录日志 | 增量读取 | /var/log/secure、/var/log/auth.log | 原生 Event Log API 每 5 秒查询 Security 4624/4625，限定远程类型 3/10；见 [Windows 登录说明](60-Windows登录防护与覆盖状态.md) |
| 文件完整性 | 事件驱动 | inotify（目录递归 watch） | ReadDirectoryChangesW |

进程快照包含 PID、进程名、所属用户、可执行文件路径、命令行和 RSS。命令行在 Agent 本机脱敏后才上报：
`password`、`token`、`secret`、访问密钥、客户端密钥、认证头和 Cookie 等参数（含 `db-password`、
`access_key` 等前缀写法）均只保留参数名，值替换为 `***`。

资产快照的 `collected` 字段表示本轮实际执行的类别。服务端按该字段逐类替换软件、端口、进程、账户和
容器资产；这使指定采集器的即时采集不会误删未执行类别的历史快照。字段为空时保留旧 Agent 的全量快照语义。

**降级策略**：无 root/管理员权限时，敏感采集（shadow、/proc/net/tcp 完整信息）降级并在心跳中上报 `guard_status=degraded`，平台侧提示权限不足。

容器数据仅用于宿主机安全研判。Docker 和 Kubernetes 查询彼此独立；Kubernetes 仅查询调度到本机节点的 Pod，默认节点名为宿主机 hostname，可通过 `kubernetes_node_name` 覆盖。Agent 不执行容器或 Kubernetes 生命周期操作。

## 3. 基线核查引擎（task/baseline）

### 3.1 核查项规范（对应 t_baseline_item.check JSONB）

```json
{
  "id": "BL-LINUX-0001",
  "name": "SSH 登录失败锁定已配置",
  "template": "DJBH2.0-LINUX",
  "category": "身份鉴别",
  "severity": 3,
  "os": ["linux"],
  "check": {
    "type": "file_line",
    "target": "/etc/pam.d/sshd",
    "operator": "contains",
    "expected": "auth required pam_faillock.so preauth"
  },
  "remediation": "在 /etc/pam.d/sshd 中增加 pam_faillock 配置并重启 sshd",
  "fix_spec": {
    "risk": "auto",
    "steps": [
      {"action": "file_line_ensure", "path": "/etc/pam.d/sshd",
       "line": "auth required pam_faillock.so preauth", "position": "append"}
    ],
    "requires_restart": "sshd"
  }
}
```

### 3.2 检查类型（type）与解释器

| type | 语义 | 关键字段 | 示例 |
|------|------|----------|------|
| `file_line` | 文件中是否存在/不存在匹配行 | target、operator(contains/not_contains/regex)、expected、ignore_case | 检查 pam 配置 |
| `file_content` | 文件整体内容正则校验 | target、regex | 文件中是否含指定文本（不解释产品配置） |
| `file_perm` | 文件/目录权限位 | target、perm(如 0644)、owner、group | /etc/passwd 644 |
| `cmd_output` | 执行 Agent 内置白名单命令并比对输出 | cmd、operator(eq/gt/lt/regex)、expected、timeout_ms | `sysctl -n net.ipv4.tcp_syncookies` = 1 |
| `sshd_effective` | Linux OpenSSH 解释磁盘配置及明确连接条件 | target、option、connection(user/host/address/local_address/local_port)、operator(eq/regex)、expected、timeout_ms | 指定 root 连接的 PermitRootLogin 为 no；详见 [OpenSSH 配置核查](21-OpenSSH配置核查.md) |
| `local_identity_file` | Linux 固定本地身份普通文件元数据 | target、perm、owner(0)、group(0/shadow)、operator(subset)、timeout_ms | 权限允许位上限、数值UID/GID与ACL确认；详见 [本地身份文件核查](22-本地身份文件核查.md) |
| `local_accounts` | 本地 passwd/shadow 的账户字段与明确范围 | target、option、operator(eq)、expected；system_shells 必填 uid_min/uid_max | 空口令字段、指定非root UID范围shell及UID0名称；不输出口令/哈希、不读取外部身份源 |
| `pam_password` | passwd 服务已支持本地 password 链的质量/新口令散列参考 | 固定 target、option(quality/unix_hash)、operator(eq)、明确 expected、timeout_ms | Include、控制顺序及 pwquality 覆盖；其他链保持无法确认，见 [PAM口令链核查](23-PAM口令链核查.md) |
| `systemd_service` | 本地 systemd 系统管理器的 auditd/rsyslog 当前单元状态 | 固定 target、operator(eq)、expected(loaded/active/running)、timeout_ms | 缺失、总线/查询错误和切换状态保持error；不是审计事件或日志投递证明，见 [服务状态核查](25-systemd服务状态核查.md) |
| `linux_log_metadata` | Linux固定审计目录及btmp/wtmp元数据 | 固定target、perm、owner(0)、group(0/utmp)、operator(subset)、timeout_ms | 类型、数值ID与ACL边界；不解析实际日志目标/写入策略，见 [固定日志元数据核查](26-固定日志元数据核查.md) |
| `service_status` | 服务启用状态 | name、expected(enabled/disabled/running) | sshd 禁 root 时 firewalld 状态 |
| `account_policy` | 口令/账户策略 | key(minlen/maxdays/lockout…)、operator、expected | 密码最长有效期 90 天 |
| `mount_opt` | 挂载点选项 | mount、option(nosuid/noexec/nodev)、required(bool) | /tmp nodev,nosuid |
| `registry` | Windows 注册表值 | path、name、type、expected | 禁用 SMBv1 |
| `package_version` | 已装软件版本约束 | name、vrange | openssl >= 1.1.1k |
| `process_check` | 进程存在性 | exe/cmdline、required | 审计进程运行中 |

**执行器要求**：

- 单项超时 5s（可覆写）；单项 panic recover，异常记为 `failed(unknown)` 不影响其余项。
- `cmd_output` 的命令值必须与 Agent 内置基线命令逐字匹配；服务端下发的未知或被篡改命令在创建进程前被拒绝。新增命令型检查必须随 Agent 版本发布，不提供通用 Shell 或脚本下发能力。
- 结果必须带 `actual`（取证值），供报告展示。
- 模板全量下发至 Agent 本地执行（SQLite 缓存），核查在 **Agent 本地完成**，只回传结果——避免每项一次交互。

### 3.3 内置模板规划

| 模板 code | 项数（一期目标） | 依据 |
|-----------|------------------|------|
| DJBH2.0-LINUX | 60 | 等保 2.0 主机安全要求 |
| DJBH2.0-WINDOWS | 40 | 等保 2.0 主机安全要求 |
| CIS-CENTOS7 / CIS-UBUNTU | 30（二期） | CIS Benchmark 精选 |

## 4. 安全扫描引擎（task/scan）

### 4.1 漏洞扫描（本地比对，不联网）

```
① 软件清单（collector/software 产出本地缓存）
② Agent 从平台拉取 CVE 特征库增量（t_cve_db 导出物，含 affected JSON）
③ 本地比对：name 匹配 + 版本区间比较（dpkg/rpm 语义版本比较器）
④ 产出 VulnFinding 列表上报
```

- 特征库按平台（centos7/ubuntu2204/win2019…）分片，Agent 只拉本机 OS 对应分片，控制包体 < 5MB。
- 版本比较实现 rpm-evr / dpkg 语义（epoch、tilde 规则），不使用字符串比较。

### 4.2 弱口令检测（本机离线有限字典）

Linux 固定读取本地 passwd/shadow，使用版本化 100 项字典核对 MD5/SHA crypt、有限成本 bcrypt 与 yescrypt；锁定账户和已知非登录 shell 排除，未支持算法、读取异常及预算耗尽明确显示覆盖缺失。Windows 和外部身份源未支持。保留空口令、UID=0 非 root 和口令长期未改的有限参考；不推断真实认证能力。

口令与哈希不回传；任务绑定成员与指令，首次结果不可覆盖，逐主机覆盖与历史风险分别展示。完整算法参数、资源上限、错误和重放边界见 [Linux 弱口令检测](59-Linux弱口令字典检测与覆盖证据.md)。

### 4.3 端口服务识别

- 基于 Agent 侧本地信息（监听表 + 进程映射）+ 内置服务指纹表（端口→常见服务、可执行文件路径特征）。
- 不做主动外连探测（被动识别），风险项：高危端口清单（135/137/138/139/445/593/1025 等，清单可配）。

## 5. 实时防护引擎（guard）

### 5.1 规则规范（对应 t_protect_rule）

```yaml
rules:
  - id: PR-0001
    name: 挖矿进程阻断
    type: process
    match:
      exe_regex: "(?i)(/tmp/.*xmrig|minerd|kdevtmpfsi|kinsing)"
      # 可选：cmdline_regex、user_exclude: [root]
    actions: [kill, alert]          # kill / alert / quarantine(隔离样本到证据目录)
    severity: critical

  - id: PR-0002
    name: 关键文件防篡改
    type: file_integrity
    match:
      paths: ["/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/ssh/sshd_config"]
      recursive: false
    actions: [alert, restore]       # restore: 从 MinIO/本地基线备份恢复
    severity: high

  - id: PR-0003
    name: SSH 暴力破解封禁
    type: login
    match:
      service: sshd                 # sshd / rdp / smb
      window_sec: 60                # 滑动窗口
      threshold: 5                  # 失败次数阈值
      whitelist: ["10.0.0.0/8"]     # 白名单网段不封禁
    actions: [block_ip, alert]
    severity: high
    duration_sec: 1800              # 封禁时长，0=永久
```

### 5.2 进程防护实现

- **Linux / Windows**：2s 轮询进程表；仅对 Agent 启动或策略热更新后的新增进程执行规则匹配，按 PID + 创建时间识别 PID 复用。Linux 通过进程接口读取 `exe`、`cmdline` 与父链；ETW / auditd 订阅为后续事件驱动增强项。
- **处置**：`kill`（Linux: SIGKILL；Windows: TerminateProcess）；`quarantine`：进程二进制复制到证据目录并上报 MinIO。
- **取证**：命中时采集进程五元组（pid、ppid、exe、cmdline、user）+ 文件 SHA256 + 最多 8 层父进程链，写入事件 detail 与证据文件。

### 5.3 文件完整性实现

- 首次启用：对 match.paths 建基线（SHA256+size+mtime）存本地 + 上报 `t_file_baseline`。
- 监听变更（inotify / ReadDirectoryChangesW）→ 重算哈希比对 → 告警；`restore` 动作从本地备份目录恢复（备份于基线建立时）。
- 自我豁免：Agent 自身二进制与工作目录变更由 selfprotect 处理，不触发防篡改告警。

### 5.4 登录防护实现

- Linux 增量读取 OpenSSH Failed/Accepted 日志；Windows 通过原生 Event Log API 读取具有效远程来源的 Security 4624/4625，按字段名解析 XML。Windows 规则独立、默认停用，首次启用从当前日志建立基线。
- 按规则和来源 IP 统计滑动窗口，信任来源和排除账户不参与计数；超阈值告警，显式选择 `block_ip` 才限时封禁。成功登录只参与异常时段告警。
- **封禁落地**：

| 平台 | 当前落地 |
|------|-----------|
| Linux | 独立 iptables/ip6tables 链，只限制指定来源进入 SSH TCP 端口；见 [Linux 防护说明](11-登录与文件防护.md) |
| Windows | 原生动态 WFP 入站过滤器，精确限定来源 IP、TCP 与配置端口；独立计时到期、进程退出撤销，持久化意图与告警回执；见 [Windows 登录说明](60-Windows登录防护与覆盖状态.md) |

- 封禁规则持久化本地（重启不丢失），`t_block_ip` 到期后由服务端下发解封或 Agent 定时自查过期。

### 5.5 主机隔离（ISOLATE_HOST）

- 原生 systemd/SCM 服务声明 `isolation_contract=1`；平台在创建、派发和当前认证连接复核能力。旧 Agent、前台与容器进程拒绝新隔离。
- Linux：独立看护创建本次专属 iptables/ip6tables 链及 INPUT/OUTPUT/FORWARD 首部跳转，放行回环、解析时固定的管理端 TCP IP/端口与 IPv6 邻居发现；其余流量丢弃，包含既有业务连接。保留管理员策略，仅清理本次带身份标记的规则。
- Windows：独立 SCM 看护持有动态 WFP 会话，在 IPv4/IPv6 ALE 连接与接收授权层安装本次过滤器；放行回环和管理 TCP 端点，不改 Windows 防火墙配置文件默认策略。
- 隔离生效后，Agent 必须经当前认证通道完成新随机数往返，才记录成功；每次有效往返续租 10 秒。独立看护按持久化期限撤销隔离，主 Agent 崩溃不妨碍撤销；看护重启清理旧隔离，不重置期限或重新隔离。
- 平台只依据当前通道的租约状态更新隔离状态，历史 ACK 不覆盖较新恢复结果。失去后续状态时显示“隔离状态待确认”，收到本机实际清理结果后显示正常及自动解除原因。
- `RESTORE_ISOLATION` 等待本机清理完成才成功；清理失败保留记录、提示失败并重试。卸载在隔离尚未清理时拒绝，持有隔离事务锁直到 Agent 服务确认停止。
- 适用性、失败边界与验收入口见 [主机隔离租约与失联撤销](56-主机隔离租约与失联撤销.md)。

### 5.6 勒索诱饵防护（decoy，详见 05-扩展能力设计 §2）

- **诱饵文件由 Agent 本地生成**（文件名模板池随机组合，随机字节 + 合理文件头，不依赖平台下载），投放目录与数量由防护策略下发（默认用户文档/共享目录，每目录 4 个）。
- **双触发**：诱饵被写入/篡改（高置信）+ 受监听目录写速率异常（10s 窗口 >50 文件重命名且扩展变化率 >80%，典型加密拖尾特征）。
- **归因**：已发布 v0.0.4 的 Linux 实现曾按 `/proc/*/fd` 与进程启动时间推测写入者；该证据不足以支持自动终止。当前未发布 develop 已移除这两条推测路径：Linux 缺少可信写入者采集时跳过自动终止，保留告警、取证和按配置隔离。Windows amd64 继续通过内核文件 ETW 的成功操作与原生进程实例关联，无法核实时跳过终止，见 [归因与安全响应](61-Windows勒索进程归因与安全响应.md)及[防护能力核查](84-防护能力与开源实现差距.md)。
- **本地响应链**（不依赖服务端在线）：Linux 递归结束涉事进程及后代；Windows 只终止已核实的写入进程（均保留进程链取证）→ 主机隔离（复用 §5.5 的 10 秒认证租约；离线不续租自动解除）→ 证据快照 → `RptSecurityEvent(type=decoy_tamper/ransom_behavior, severity=critical)`。
- **误报防护**：备份/杀毒/索引类进程按 exe 路径排除（策略可配）；诱饵目录避开业务工作区；响应级别可配（alert_only / kill / kill_and_isolate，默认 kill_and_isolate）。

## 6. 本地自治与策略缓存（policystore / offlineq）

```
policy-store（SQLite 表）
├─ meta(key=version)                 -- 当前策略版本
├─ baseline_items(json)              -- 核查项缓存
├─ protect_rules(json)               -- 防护规则缓存
└─ config(采集频率/限流参数)

offline-queue（SQLite 表：id, report_id, payload blob, ts, status）
```

- 策略同步：心跳发现版本不一致 → 收 `CmdPolicySync` → 全量写入 → 原子替换（事务）。
- **断网语义**：guard 读 policystore 启动，断网期间规则持续生效；事件写 offlineq；重连后按序补传，服务端按 report_id 幂等。
- 环形清理：offlineq 超过 500MB 或 24h 数据自动淘汰最旧（监控数据优先丢弃，安全事件最后淘汰）。

## 7. 自升级与自我保护

### 7.1 升级流程

```
收到契约 1 的 CmdAgentUpgrade → 后台限速下载、SHA256 与平台校验
  → 复制旧版本为独立 systemd/SCM 看护，等待就绪
  → 持久化事务 → 旧版本备份 → 候选原子替换 → 退出，由原服务重新启动
  → 候选完成初始化，目标版本/摘要/进程身份一致，同一 mTLS 通道连续心跳至少 5 秒
  → 看护持久化最终成功；60 秒启动期限内未确认则恢复旧版本并回传失败事件
```

原生服务条件、健康确认、独立看护、自动回退与旧 Agent 兼容边界见 [Agent 升级看护](55-Agent升级看护与自动回退.md)。

### 7.2 自我保护

| 项 | 实现 |
|----|------|
| 崩溃拉起 | systemd Restart=always（RestartSec=5）；Windows 服务恢复策略（失败 5000ms 重启，无限次） |
| 防卸载 | 卸载子命令需 `--uninstall-token`（平台动态生成，5min 有效） |
| 配置防篡改 | agent.yml 与平台策略使用私有可信留存和 SHA256 检查；异常恢复可信配置、保留管理连接与证书并持久上报事件 |
| 资源反馈 | 每 10s 读取 Agent 进程 CPU/RSS；单核口径 CPU 连续 5min 超 3% 逐级降频，RSS 达 100MiB（主动病毒扫描期间 250MiB）触发回收及上报；恢复带滞回，阈值不构成 OS 硬限制 |

配置首次信任、合法改配、离线及重启恢复和权限边界见 [配置防篡改](57-Agent配置防篡改与可信恢复.md)。

资源阈值、调整范围、补传内存边界及原生验收见 [Agent资源自适应](58-Agent资源自适应与有界补传.md)。

## 8. 资源约束指标（验收红线）

| 指标 | 红线 |
|------|------|
| 常驻内存 RSS | 性能验收目标 < 100MiB，主动扫描峰值 < 250MiB；自适应阈值不证明该目标在任意工作负载均成立 |
| CPU 平均占用 | 性能验收目标 < 2%（8C 参考机，需注明口径）；反馈控制按单逻辑核口径计算，规模和长稳性能另行验收 |
| 磁盘占用 | 工作目录 < 500MB（含缓存，环形覆盖） |
| 断网数据保全 | 安全事件 ≥ 24h，指标 ≥ 1h |
| 重启恢复 | JSONL 业务队列重新加载，持久化策略与证书保持 |

## 9. 病毒查杀引擎（virusscan，详见 05-扩展能力设计 §1）

- **双层引擎**：L1 使用当前普通文件字节计算 SHA256，不再由 size/mtime clean 缓存跳过读取；L2 `rules.json` 内部字符串/十六进制规则，不链接 libyara。缓存命中率取决于实际工作负载。
- **模式**：快速（关键路径）/ 全盘（源文件读取限速 10 MiB/s）/ 事件实时检测（独立于诱饵，Linux inotify / Windows ReadDirectoryChangesW；有界队列及增量恢复遍历，单文件读取预算 2 秒/20 MiB）/ 自定义绝对路径。扫描与事件检测均有覆盖限制，不能推断整机安全。
- **处置**：本地受控隔离 / 删除 / 恢复 / 平台全局白名单。Agent 持久化白名单并在主动扫描和实时检测前应用，不提供 MinIO 样本上传。
- **特征库**：`CmdSignatureUpdate` 支持相邻版本增量与全量回退（单包最多 20 MiB，包和完整内容摘要校验，验证后切换）；旧 Agent 使用全量，断网沿用本地库，见[增量更新](66-病毒特征库增量更新.md)。
- **边界**：定位已知样本查杀（挖矿/蠕虫/后门/勒索家族），未知威胁仍可能漏检，诱饵与行为规则也不能证明整机安全。执行预算、逐主机证据和跨平台恢复边界见 [检测执行说明](53-检测执行与文件处置证据.md)。

## 10. 漏洞修复执行器（fixer，详见 05-扩展能力设计 §3）

- **配置类**：按 `fix_spec` 步骤执行（sysctl_set / file_line_ensure / file_replace / chmod / chown / service_restart / registry_set / audit_rule），事务化：全量备份 → 按序执行 → 复核（重跑 check）→ 失败自动回滚 → 上报 rolled_back；`requires_restart` 服务重启默认仅提示不执行（可配）。
- **Linux 软件包类**：前置检查（磁盘/依赖）→ 临时仓库源安装（yum `--repofrompath` / 临时 sources.list.d，**不污染客户 repo 配置**）→ 修复后自动重扫关联 CVE → 需重启标记 `reboot_required`，**不自动重启主机**。
- **Windows 更新**：使用当前 Windows Update/WSUS 的 WUA 接口发现适用更新，固定 UpdateID、修订与来源证据，经指定账号审批后静默安装；中断后只读复核，不自动重装或重启，结果不直接关闭 CVE。任意上传 MSU 不作为自动安装目标，范围见 [Windows 更新发现与自动修复](62-Windows更新发现与自动修复.md)。
- **回滚策略**：配置类自动回滚；包类不自动回滚（降级风险大于收益），rpm 环境记录旧版本号供人工降级参考。

文件事件监听的数量、深度、溢出恢复和心跳覆盖状态见[事件驱动实时监控](63-事件驱动实时监控与覆盖状态.md)。进程规则仍按原周期轮询，Windows ETW 写入者归因独立运行。
