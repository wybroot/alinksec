# Changelog

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
