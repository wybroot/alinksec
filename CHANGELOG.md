# Changelog

## v0.0.2 - 2026-10-03

- 增加 Linux ARM64（aarch64）Agent、原生 ARM64 CI，以及 server/web/SQLite 维护镜像的 amd64 + arm64 发布流程。
- 发布门禁要求两种 Linux 架构均通过，镜像清单记录各架构实际验证过的 digest，Agent 附件校验真实二进制架构。
- 主机详情显示实际架构；升级下发预先核对全部目标的平台，Agent 替换自身前再次检查升级包平台。
- 正式发布要求同一版本 main 提交的 amd64、ARM64、Windows 和数据库 CI 全部成功，再完成真实双架构镜像与附件校验；发布清单记录该提交和 CI。

变更与平台范围见 [v0.0.2 发布说明](docs/releases/v0.0.2.md)。v0.0.1 历史成品仍为 amd64。

## v0.0.1 - 2026-10-02

首次开发阶段发布。server/web 提供 Linux amd64 容器镜像，Agent 提供 Linux amd64 与 Windows amd64 原生二进制。

- 主机注册、gRPC mTLS、心跳与资产清点，指令 ACK 状态及断网落盘补传。
- 基线检查与配置修复、漏洞/弱口令/端口扫描、软件包审批与维护窗口。
- 哈希与规则病毒检测、隔离与恢复、白名单和特征库热更新。
- 进程行为、勒索诱饵及加密速率检测；Linux 文件完整性与 SSH 登录防护，默认仅告警。
- 主机网络隔离及恢复、Agent 更新与授权卸载、Webhook、审计、三角色 RBAC、控制台及安全大屏。
- PostgreSQL 17 + VictoriaMetrics 模式与单实例 SQLite WAL 轻量模式；SQLite 按需备份、校验和恢复。
- Linux systemd 常驻与 Windows SCM 服务启停和自动恢复；发布 CI、版本一致性检查、校验文件及镜像 digest 清单。

验收范围与限制见 [v0.0.1 发布说明](docs/releases/v0.0.1.md)。
