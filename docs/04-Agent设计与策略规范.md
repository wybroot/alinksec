# ALinkSec Agent 详细设计与策略规范

> 版本：V1.0（设计评审稿）
> 日期：2026-08-25
> 语言/运行时：Go 1.22+，静态编译单二进制（linux/amd64、linux/arm64、windows/amd64）

## 1. 工程结构

```
alinksec-agent/
├── cmd/agent/main.go              # 入口：安装/卸载/运行 子命令
├── internal/
│   ├── comm/                      # gRPC 长连接、mTLS、重连、收发循环
│   ├── config/                    # 配置加载（agent.yml）
│   ├── scheduler/                 # 采集调度器（频率/暂停/立即触发）
│   ├── collector/                 # 采集器
│   │   ├── cpu.go  mem.go  disk.go  net.go  process.go  port.go
│   │   ├── software_linux.go  software_windows.go
│   │   └── account_linux.go  account_windows.go
│   ├── logcollect/                # 登录日志采集解析（secure/wtmp/WinEventLog）
│   ├── task/                      # 任务执行器：基线核查引擎、扫描引擎
│   │   ├── baseline/              #   核查项解释器（check JSONB → 执行）
│   │   └── scan/                  #   漏洞比对、弱口令、端口服务
│   ├── virusscan/                 # 病毒查杀引擎：L1 哈希情报 + L2 YARA（详见 05 §1）
│   ├── fixer/                     # 漏洞/基线修复执行器：备份/执行/回滚/复核（详见 05 §3）
│   ├── guard/                     # 实时防护引擎：进程/文件完整性/登录防护/勒索诱饵
│   ├── policystore/               # 本地策略缓存（SQLite）+ 版本比对
│   ├── offlineq/                  # 断网数据缓存队列（SQLite 环形）
│   ├── upgrade/                   # 自升级（下载/校验/替换/回滚）
│   ├── selfprotect/               # 自我保护（防卸载/防篡改配置）
│   └── winutil/                   # Windows API 封装（服务、防火墙、事件日志）
└── packaging/                     # systemd unit、Windows 服务安装脚本
```

**核心依赖库**：

| 库 | 用途 |
|----|------|
| `github.com/shirou/gopsutil/v3` | CPU/内存/磁盘/网络/进程（跨平台） |
| `google.golang.org/grpc` | 通信 |
| `modernc.org/sqlite` | 本地 SQLite（纯 Go，交叉编译免 CGO） |
| `github.com/kardianos/service` | systemd / Windows 服务统一封装 |
| `github.com/hillu/go-yara/v4` | YARA 规则引擎（CGO 静态链接 libyara；BSD-3 可闭源嵌入；构建标签 `yara`，可降级 hash-only 构建） |
| `gopkg.in/natefinch/lumberjack.v2` | 日志轮转 |

**目录约定**：

| 平台 | 配置 | 工作目录（SQLite/证书/缓存） | 日志 |
|------|------|------------------------------|------|
| Linux | `/etc/alinksec/agent.yml` | `/var/lib/alinksec/` | `/var/log/alinksec/`（lumberjack 轮转，单文件 50MB×3） |
| Windows | `C:\ProgramData\ALinkSec\agent.yml` | `C:\ProgramData\ALinkSec\` | 同目录 `\logs\` |

## 2. 模块设计

### 2.1 comm（通信）

- 维护单条 gRPC 双向流；发送通道 `chan *Report`（容量 1024），接收 goroutine 分发 Command。
- 重连：指数退避 1s→30s（±20% 抖动）；重连成功先发心跳并触发策略版本比对。
- 出口统一走 `offlineq`：发送失败（断网/服务端拒绝）→ 落 SQLite 队列；队列管理器负责补传（限速 100 msg/s）。

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
| 登录日志 | 实时 tail | /var/log/secure（inotify）+ wtmp/btmp 增量解析 | Windows Event Log（Security 4624/4625/4720）订阅 |
| 文件完整性 | 事件驱动 | inotify（目录递归 watch） | ReadDirectoryChangesW |

**降级策略**：无 root/管理员权限时，敏感采集（shadow、/proc/net/tcp 完整信息）降级并在心跳中上报 `guard_status=degraded`，平台侧提示权限不足。

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
| `file_content` | 文件整体内容正则校验 | target、regex | 检查配置值 `PermitRootLogin no` |
| `file_perm` | 文件/目录权限位 | target、perm(如 0644)、owner、group | /etc/passwd 644 |
| `cmd_output` | 执行命令并比对输出 | cmd、operator(eq/gt/lt/regex)、expected、timeout_ms | `sysctl -n net.ipv4.tcp_syncookies` = 1 |
| `service_status` | 服务启用状态 | name、expected(enabled/disabled/running) | sshd 禁 root 时 firewalld 状态 |
| `account_policy` | 口令/账户策略 | key(minlen/maxdays/lockout…)、operator、expected | 密码最长有效期 90 天 |
| `mount_opt` | 挂载点选项 | mount、option(nosuid/noexec/nodev)、required(bool) | /tmp nodev,nosuid |
| `registry` | Windows 注册表值 | path、name、type、expected | 禁用 SMBv1 |
| `package_version` | 已装软件版本约束 | name、vrange | openssl >= 1.1.1k |
| `process_check` | 进程存在性 | exe/cmdline、required | 审计进程运行中 |

**执行器要求**：

- 单项超时 5s（可覆写）；单项 panic recover，异常记为 `failed(unknown)` 不影响其余项。
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

### 4.2 弱口令检测（**不做在线爆破**）

| 检测 | Linux | Windows |
|------|-------|---------|
| 空口令 | /etc/shadow 密码字段为空 | 账户密码过期策略/空密码标志 |
| 系统弱口令 | 与内置弱口令字典（top100，配置于策略）做本地哈希比对（仅当 hash 算法可离线验证：md5crypt/sha512crypt） | SAM 不可离线读取——仅做策略检测（密码长度/复杂度/历史） |
| 账户风险 | UID=0 非 root、可登录 nologin 检查 | Guest 启用、永不过期账户 |

> 设计决策：**不做 SSH/MySQL 等在线爆破**——有锁账户与被溯源风险，企业内网交付易触发客户风控。检测范围限定"本机可离线验证"项。

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

- **Linux**：1s tick 扫描 /proc（读 `comm`、`exe`、`cmdline`；命中正则后再读完整信息取证）。可选启用 `auditd` 订阅（进程 exec 事件驱动，需客户允许安装 audit 规则）。
- **Windows**：2s 轮询 WMI `Win32_Process`（ETW 为二期演进项）。
- **处置**：`kill`（Linux: SIGKILL；Windows: TerminateProcess）；`quarantine`：进程二进制复制到证据目录并上报 MinIO。
- **取证**：命中时采集进程五元组（pid、ppid、exe、cmdline、user）+ 文件 SHA256 + 父进程链，写入事件 detail 与证据文件。

### 5.3 文件完整性实现

- 首次启用：对 match.paths 建基线（SHA256+size+mtime）存本地 + 上报 `t_file_baseline`。
- 监听变更（inotify / ReadDirectoryChangesW）→ 重算哈希比对 → 告警；`restore` 动作从本地备份目录恢复（备份于基线建立时）。
- 自我豁免：Agent 自身二进制与工作目录变更由 selfprotect 处理，不触发防篡改告警。

### 5.4 登录防护实现

- 解析登录失败事件（Linux: secure tail + btmp 解析；Windows: 4625 事件订阅）。
- 内存滑动窗口计数 `{src_ip: [timestamps]}`，超阈值且不在白名单 → 封禁。
- **封禁落地**：

| 平台 | 优先级顺序 |
|------|-----------|
| Linux | firewalld（rich rule）→ nftables set → iptables（探测可用性后选择） |
| Windows | Windows 防火墙出站/入站规则（WFP COM 接口） |

- 封禁规则持久化本地（重启不丢失），`t_block_ip` 到期后由服务端下发解封或 Agent 定时自查过期。

### 5.5 主机隔离（ISOLATE_HOST）

- Linux：iptables INPUT 链默认 DROP，仅放行 Agent↔Server 通信 IP:9443 与既有关联会话。
- Windows：防火墙新建阻断规则 + 放行规则。
- **双向确认**：隔离指令下发后 Agent 必须在 10s 内 ACK，超时视为失败并自动回滚（防止把客户的机器"锁死"后失联）；解封指令 `RESTORE_ISOLATION` 恢复。

### 5.6 勒索诱饵防护（decoy，详见 05-扩展能力设计 §2）

- **诱饵文件由 Agent 本地生成**（文件名模板池随机组合，随机字节 + 合理文件头，不依赖平台下载），投放目录与数量由防护策略下发（默认用户文档/共享目录，每目录 4 个）。
- **双触发**：诱饵被写入/篡改（高置信）+ 受监听目录写速率异常（10s 窗口 >50 文件重命名且扩展变化率 >80%，典型加密拖尾特征）。
- **归因**：Linux 经 `/proc/*/fd` 反查写入进程 inode；Windows 经 Restart Manager API 查锁定进程。
- **本地响应链**（不依赖服务端在线）：kill 涉事进程（含进程链取证）→ 主机隔离（复用 §5.5 的 10s ACK 回滚安全垫）→ 证据快照 → `RptSecurityEvent(type=decoy_tamper/ransom_behavior, severity=critical)`。
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
收到 CmdAgentUpgrade → 后台 goroutine 限速下载（2MB/s，不抢占业务）
  → SHA256 校验 → 新二进制写入 {workdir}/agent.new
  → 备份当前二进制 → 原子 rename + 重启服务（kardianos/service Restart）
  → 启动后心跳上报新版本
  → 失败（启动超时 60s 由 watchdog 判定）→ 自动回滚旧版本并上报失败事件
```

### 7.2 自我保护

| 项 | 实现 |
|----|------|
| 崩溃拉起 | systemd Restart=always（RestartSec=5）；Windows 服务恢复策略（失败 5000ms 重启，无限次） |
| 防卸载 | 卸载子命令需 `--uninstall-token`（平台动态生成，5min 有效） |
| 配置防篡改 | agent.yml 哈希自校验，异常时用内嵌默认值并上报事件 |
| 资源红线 | RSS 上限 100MB（超出时自动收缩缓存并自检报告）；CPU 由采集频率自适应（连续 5min 超 3% 自动降频并上报） |

## 8. 资源约束指标（验收红线）

| 指标 | 红线 |
|------|------|
| 常驻内存 RSS | < 100MB（典型 30-50MB）；全盘病毒扫描期间峰值 < 250MB（扫描结束释放规则缓存） |
| CPU 平均占用 | < 2%（8C 参考机） |
| 磁盘占用 | 工作目录 < 500MB（含缓存，环形覆盖） |
| 断网数据保全 | 安全事件 ≥ 24h，指标 ≥ 1h |
| 断电恢复 | SQLite WAL 模式，重启自动 recover 队列 |

## 9. 病毒查杀引擎（virusscan，详见 05-扩展能力设计 §1）

- **双层引擎**：L1 哈希情报（纯 Go，SHA256 精确匹配 + clean 文件缓存跳扫，命中率 >95%）；L2 YARA 规则（CGO 静态链接，规则按平台分片，仅对 PE/ELF/脚本/office 类且 <50MB 对象执行）。
- **模式**：快速（关键路径）/ 全盘（IO 限速默认 10MB/s，排除目录/扩展/大文件可配）/ 实时（复用 guard 文件事件通道，CLOSE_WRITE 触发，单文件超时 2s 放行并计数）/ 自定义路径。
- **处置**：隔离（本地隔离目录权限拒绝 + 样本限速上传 MinIO）/ 删除 / 恢复 / 加白（平台全局生效，防本机白名单绕过）。
- **特征库**：`CmdSignatureUpdate` 全量更新（包体 <20MB，sha256 校验，原子替换）；断网沿用本地库；心跳携带 db_version，落后自动触发更新。
- **边界**：定位已知样本查杀（挖矿/蠕虫/后门/勒索家族），未知威胁由勒索诱饵与行为防护补位。

## 10. 漏洞修复执行器（fixer，详见 05-扩展能力设计 §3）

- **配置类**：按 `fix_spec` 步骤执行（sysctl_set / file_line_ensure / file_replace / chmod / chown / service_restart / registry_set / audit_rule），事务化：全量备份 → 按序执行 → 复核（重跑 check）→ 失败自动回滚 → 上报 rolled_back；`requires_restart` 服务重启默认仅提示不执行（可配）。
- **软件包类**：前置检查（磁盘/依赖）→ 临时仓库源安装（yum `--repofrompath` / 临时 sources.list.d，**不污染客户 repo 配置**；Windows 走 MSU `wusa /quiet /norestart` 或 WSUS）→ 修复后自动重扫关联 CVE → 需重启标记 `reboot_required`，**不自动重启主机**。
- **回滚策略**：配置类自动回滚；包类不自动回滚（降级风险大于收益），rpm 环境记录旧版本号供人工降级参考。
