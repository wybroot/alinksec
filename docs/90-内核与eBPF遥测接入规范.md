# 90. 内核与 eBPF 遥测接入规范 (Falco / Elkeid Driver)

> **2026-10-29 复核提示：** 当前实现主要为外部事件接收与展示，存在鉴权／启停、严重度映射、探针健康和事件身份缺口，见 [91 · R01、R14、R15](91-安全组件缺陷与补全清单.md)。本文的“100% 捕获”不成立，接口存在也不代表真实探针部署与可靠传输已完成；下列接入说明须补齐认证和目标环境验收后使用。

> **修订日期：** 2026-10-29  
> **适用版本：** v0.0.4+ (Phase 6 / F01-kernel ~ F04-kernel)  
> **基准参考：** CNCF Falco (eBPF probe/Plugin) · ByteDance Elkeid Driver (Kprobe LKM)

---

## 1. 架构目标与能力边界

### 1.1 架构定位
ALinkSec 的 Agent 原生设计为跨平台纯用户态轻量化监控（进程定时枚举、文件 inotify/ReadDirectoryChangesW、SSH/Windows 登录审计）。
为了在不破坏宿主机稳定性、无需强制部署编译环境的前提下获取内核级深层遥测，平台设计了**可插拔式内核遥测接入网关 (Kernel Telemetry Gateway)**：
- **解耦部署：** 允许独立部署 Falco（采用现代 CO-RE eBPF probe）或 Elkeid Driver，通过安全 Webhook 将高精度内核事件流式推送至 ALinkSec 服务端。
- **无感降级：** 当环境中未部署内核采集器时，服务端与前端组件健康明确标明“`disabled / 未启用内核遥测；Agent 采用内置轻量级安全轮询机制`”，不产生告警噪音，不将组件判定为异常。

### 1.2 采集能力对照

| 维度 | ALinkSec Agent (原生) | Falco eBPF 接入 | Elkeid Driver 接入 |
|---|---|---|---|
| **采集方式** | 用户态轮询 (2s) + 文件变更事件 | 内核 eBPF ring buffer 实时捕获 | 内核 Kprobe 钩子实时采集 |
| **短命进程捕获** | ⚠️ 可能遗漏（运行 < 2s） | ✅ 100% 捕获 execve | ✅ 100% 捕获 execve (59) |
| **容器上下文富化** | 自动提取 cgroup container_id | 运行时实时关联 Pod/Image/Labels | 内核 namespace nodename 关联 |
| **特权提权检测** | 离线比对 sudo/passwd 配置 | 实时追踪 setuid/setns 系统调用 | update_cred (604) 实时拦截上报 |
| **无文件攻击** | 进程启动特征检测 | 内存执行/memfd 规则检测 | memfd_create (356) 内核级捕获 |
| **Rootkit 检测** | 暂无 | 暂无 | 内核虚假模块/syscall 挂钩检测 (700-703) |

---

## 2. 接口规格与数据格式

### 2.1 Falco HTTP Webhook 接入 (F01-kernel)
- **接入端点：** `POST /api/telemetry/falco/events`
- **鉴权方式：** HTTP Header `X-Falco-Token: <配置密钥>`（若配置了 `alinksec.telemetry.falco-secret`）
- **数据载荷格式 (JSON)：**
```json
{
  "output": "15:20:30.123456 Notice Shell spawned in container (user=root container_id=c123456789ab container_name=web-app image=nginx:latest cmdline=bash)",
  "priority": "Notice",
  "rule": "Terminal shell in container",
  "time": "2026-10-29T15:20:30.123456789Z",
  "output_fields": {
    "container.id": "c123456789ab",
    "container.name": "web-app",
    "container.image.repository": "nginx:latest",
    "proc.cmdline": "bash",
    "proc.name": "bash",
    "proc.pid": 1234,
    "nodename": "node-k8s-01"
  },
  "tags": ["container", "mitre_execution", "T1059"]
}
```

### 2.2 Elkeid Driver 遥测接入 (F02-kernel)
- **接入端点：** `POST /api/telemetry/elkeid/events`
- **数据载荷格式 (JSON)：**
```json
{
  "data_type": 604,
  "exe": "/tmp/exp",
  "pid": 4567,
  "ppid": 1000,
  "uid": 1001,
  "nodename": "db-server-01",
  "pid_tree": "1:systemd -> 1000:bash -> 4567:exp"
}
```
**支持的核心 Hook 数据类型映射：**
- `59`: execve (常规进程遥测，Severity 1)
- `356`: memfd_create (无文件攻击，Severity 3)
- `603`: load_module (内核模块加载，Severity 3)
- `604`: update_cred (提权触发，Severity 4)
- `611`: privilege_escalation (提权检测，Severity 4)
- `700 ~ 703`: proc/syscall/interrupt/module hook (Rootkit 检测，Severity 4)

---

## 3. Falco 部署与对接指南

### 3.1 Falco 原生配置 (`falco.yaml`)
由于 Falco 原生 `http_output` 模块不直接支持自由添加 `custom_headers` 请求头（R73），ALinkSec 服务端全面兼容 **URL 参数 Token**、**Falcosidekick 转发** 与 **标准请求头** 三种接入机制：

**方案一：原生 HTTP 直连（推荐，通过 URL 携带 Token）**
```yaml
http_output:
  enabled: true
  url: "https://<alinksec-server>:8443/api/telemetry/falco/events?token=<your-secure-token>"
  user_agent: "falco/0.45"
  insecure: false
  ca_cert: "/etc/falco/certs/alinksec-ca.crt"
  mtls: false
```

**方案二：配合官方 Falcosidekick 中继转发（标准请求头）**
Falco 将事件输出给本地 `falcosidekick`，由 sidekick 添加 Header 投递：
```yaml
# falcosidekick 配置
webhook:
  address: "https://<alinksec-server>:8443/api/telemetry/falco/events"
  customheaders: "X-Falco-Token:<your-secure-token>"
  checkcert: true
```

**方案三：Falco 原生 Program Output + curl**
```yaml
program_output:
  enabled: true
  keep_alive: false
  program: "curl -s -X POST -H 'Content-Type: application/json' -H 'X-Falco-Token: <your-secure-token>' --cacert /etc/falco/certs/alinksec-ca.crt -d @- https://<alinksec-server>:8443/api/telemetry/falco/events"
```

### 3.2 联调验证步骤
1. 在装有 Falco 的测试节点上执行测试攻击指令：
   ```bash
   docker run --rm -it alpine sh
   ```
2. 观察 ALinkSec 服务端控制台日志：
   ```text
   INFO c.a.s.a.SecurityEventService : 新告警: agent=c123456789ab type=process severity=2 rule=falco-terminal-shell-in-container
   ```
3. 在 Web 前端【告警中心】列表查看到 `[可疑进程] Falco: Terminal shell in container`，点击【查看内核遥测详情】查看 MITRE ATT&CK 标签、容器镜像及完整命令行。

---

## 4. 生产建议与稳定性防护

1. **资源配额防雪崩：** Falco 或 Elkeid Driver 的高频事件可能造成高并发 HTTP 请求。建议在接入网关前部署 Nginx 或消息队列（如 Kafka/RabbitMQ）进行流量削峰。
2. **内核版本约束：**
   - Falco 优先使用 Modern eBPF 驱动（Linux Kernel >= 5.8 且启用 BTF）。
   - Elkeid Driver 目前仅支持 Linux 内核 2.6.32 至 6.3。生产环境绝勿在未充分压力测试的低版本内核上强制加载驱动模块。
