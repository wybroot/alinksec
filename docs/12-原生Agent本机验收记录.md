# 原生 Agent 本机验收记录

日期：2026-10-02。部署模型：server/web 使用容器，Agent 原生安装到目标主机，通过管理端的 9443/8443 通信。本次在管理端所在 Linux 主机安装成品，运行中容器始终只有原有 server/web 两个。

## 成品与服务

- 本机 Go 串行构建 Linux amd64 成品，使用 `CGO_ENABLED=0`、`-trimpath`、`-ldflags '-s -w'`，文件大小 14,725,280 字节，约 14.04 MiB。
- 安装位置：`/usr/local/bin/alinksec-agent`；工作目录：`/var/lib/alinksec-agent`；服务：`alinksec-agent.service`，已设置开机启动。
- 安装后二进制 SHA-256 与构建产物相同：`ca1cf1d100f98d651798d0c781978c4dc79273d406d371f9246e5ebcb84e4d2d`。
- 使用发布的 `deploy/agent/alinksec-agent.service`，`systemd-analyze verify` 通过。宿主系统的 xfs_scrub 服务有 CPUAccounting 选项过时提示，与 Agent 单元无关。
- 本机专用 drop-in：`MemoryHigh=128M`、`MemoryMax=192M`、`MemorySwapMax=96M`、`CPUQuota=50%`、`TasksMax=96`，以及 `GOMAXPROCS=1`、`GOMEMLIMIT=96MiB`。这些是本次低内存主机的运行限制，不是所有目标主机的默认额度。

## 实际功能

| 检查 | 结果与证据 |
| --- | --- |
| 注册、mTLS、心跳与策略 | 单次注册码完成注册；平台显示本机真实 hostname，心跳持续更新；仅告警策略持久化 |
| 本机资产 | 首次采集 1267 个软件、144 个进程、33 个账户、17 个监听端口；即时采集后数据刷新 |
| 空闲运行 | 连续两分钟稳定采样，心跳持续刷新，服务保持 active |
| 平台即时采集 | 正常 API 下发，实际 collect_now 指令完成，资产报告更新 |
| Linux 内置基线 | 60 项只读检查全部完成，22 项合规；任务执行通过不代表开发主机满足全部安全基线 |
| 文件完整性 | 专用测试文件变更产生真实 file_tamper 告警，动作 alert_only，文件保持变更后的内容 |
| 服务自动重启 | 对 Agent 主进程发送 SIGTERM，正常退出且日志显示 Deactivated successfully；Restart=always 自动拉起，NRestarts=1；身份及客户端证书保持不变，新心跳到达 |

测试没有新增 Agent 容器。平台规则采用仅告警响应，诱饵投放到 `/var/lib/alinksec-agent/validation/decoys/{a,b,c}`；结束后删除了测试文件路径的策略监控项。原生 Agent 保留运行及上述仅告警配置，临时采样进程已退出。既有隔离环境全功能证据见 [全功能联动](10-本机全功能联动验收记录.md)及 [登录与文件防护](11-登录与文件防护.md)。

## 资源采样

主机 2 个 CPU 核心、1735 MiB 内存、4095 MiB swap。每秒采样一次，共 198 次，覆盖约 197 秒。CPU 来自 systemd 服务 cgroup 的累计用时，100% 表示占满一个核心，包含 Agent 的辅助子进程；RSS 为该服务内进程的合计，不是整机内存。

| 阶段 | 有效样本 | 平均 CPU | 采样 CPU 峰值 | RSS 范围 |
| --- | ---: | ---: | ---: | ---: |
| 启动与首次采集 | 22 | 0.98% | 4.23% | 19.91～20.21 MiB |
| 稳定空闲 | 120 | 0.80% | 2.08% | 19.29～20.36 MiB |
| 平台即时采集 | 7 | 2.58% | 7.89% | 20.18～47.48 MiB |
| 基线执行 | 1 | 17.28% | 17.28% | 31.95 MiB |
| 文件监控验证 | 9 | 1.35% | 4.36% | 19.01～20.25 MiB |
| 重启后稳定运行 | 30 | 0.81% | 1.72% | 19.44～21.11 MiB |

基线任务很短，只有一个有效采样点，不能据此推导长时间扫描负载。服务重启期间 cgroup 消失及 CPU 计数重置的区间不计算 CPU 百分比；每秒采样也不能捕获所有瞬时峰值。本次不包含全盘病毒扫描或大型弱口令字典任务。

整段测试最低可用内存 **988.75 MiB**，最低 swap 剩余 **3458.20 MiB**，最高一分钟负载 **0.57**，最高 memory full PSI avg10 **0.54%**。服务的 memory.events 未出现 high/max/oom/oom_kill 事件，资源保护未触发。稳定运行时 cgroup memory.current 约 10～12 MiB；它的计费口径与进程 RSS 不同，不能直接互换。

## 服务修复与验证范围

Linux 部署说明改为复制发布单元，修复 systemd 行内注释使 Restart 设置无效的问题；SIGTERM 正常退出不再输出 context canceled 错误。Linux 实际安装、正常退出自动拉起和通信均在本机验证。

Windows Agent 的 run 增加 SCM 服务处理，并保留命令行前台模式。服务控制测试覆盖 Running、Interrogate、Stop、Shutdown、取消主循环和失败退出码。本机交叉编译 Windows 成品与测试程序并完成静态检查，Windows 执行证据见下节，与 Linux 本机测量独立记录。

后续构建优先本机串行完成；原生构建使用一个 worker、256 MiB 语言堆上限，保留至少 384 MiB 可用内存并观察 PSI，遇到压力停止。其他平台执行或超出本机安全容量的检查才使用 CI。约定见 [AGENTS.md](../AGENTS.md)。

## Windows 服务补充实测

提交 `f480735` 的[完整 CI](https://github.com/wybroot/alinksec/actions/runs/36970504397)已通过，包含 Windows 服务单元测试。随后补充 `TestNativeWindowsService`，使用实际构建的成品 exe 在 Windows Server 2025 上进行 SCM 验证。

测试启动时 Go 会切换到包目录，首次相对路径配置未找到 exe；已修正为绝对路径，并在测试入口拒绝相对路径。修正后提交 `2f71ab7` 的 [Windows job](https://github.com/wybroot/alinksec/actions/runs/36973031084/job/110730859500)通过，实际测试耗时 6.34 秒。

| 实测节点 | 证据 |
| --- | --- |
| 成品安装与注册 | exe 和工作目录均包含空格，真实 install 子命令通过临时 CA 注册，注册码从配置清除 |
| SCM 运行与查询 | 实际服务 RUNNING，支持 Interrogate |
| 实际通信与资产 | 校验客户端证书 CN 与上报身份的 mTLS 通道，回传 401 个软件、144 个进程、4 个账户 |
| 采集指令 | 指定 software 采集器实际回传数据，collect_now ACK 为 DONE |
| 手动停止与启动 | 停止退出码为零且进程退出；再次启动得到新进程和新心跳 |
| 自动恢复 | Agent 收到 RESTART 后正常退出，SCM 自动拉起新进程，重新建立 mTLS 通道 |
| 身份保持 | 客户端证书 SHA-256 不变，服务重启全程只注册一次 |
| 手动停止保持停止 | 等待超过恢复延时，服务保持 STOPPED，没有额外通信会话 |
| 清理 | 关闭恢复动作，停止、删除测试服务，关闭 TLS fixture，删除临时文件 |

专项采用 Go 协议 fixture，不是 Java 管理平台；不将此结果宣称为完整 Windows 安全引擎验收。测试仅允许显式启用的临时 Windows 环境，并拒绝覆盖已有 alinksec-agent 服务。重现命令见 [验证说明](../deploy/tests/README.md#native-windows-service)。

本次通过 windows_only 手动入口只运行 Windows job，Linux 构建和数据库 job 为 skipped，沿用 `f480735` 的完整验证证据。纯 Markdown 推送跳过 CI，避免验收文档更新重新触发整套构建。

## 复核

```bash
systemctl status alinksec-agent
systemctl show alinksec-agent \
  -p MainPID -p NRestarts -p Restart -p MemoryCurrent -p MemoryMax -p TasksMax
journalctl -u alinksec-agent -n 30 --no-pager
cat /sys/fs/cgroup/system.slice/alinksec-agent.service/cpu.stat
cat /sys/fs/cgroup/system.slice/alinksec-agent.service/memory.events
free -m
```

私有原始证据：`.tmp/local-run/native-agent/{installation,result,samples,summary}.json` 及 `journal.log`。注册码、私钥与完整资产明细不入库。
