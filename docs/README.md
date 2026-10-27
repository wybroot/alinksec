# ALinkSec 文档索引

版本基线：v0.0.4。当前功能开发范围已完成；发布交付与现场验收分别记录。安装从[部署文档](06-部署文档.md)开始，版本变更见[v0.0.4 发布说明](releases/v0.0.4.md)，交接与待验项目见[交付清单](80-发版准备与现场交付.md)。

历史验收、设计估算和分批实施计数保持原始日期／提交范围。源码包不能预知自身最终提交哈希或发布工作流 ID；正式来源绑定以附件 `release-manifest.json` 和 Release 实际结果为准。

## 入口与约束

| 文档 | 主题 |
| --- | --- |
| [AGENTS.md](../AGENTS.md) | Local validation constraints |
| [CHANGELOG.md](../CHANGELOG.md) | Changelog |
| [LICENSE](../LICENSE) | Apache License 2.0（原文保留） |
| [README-cn.md](../README-cn.md) | 🛡️ ALinkSec |
| [README.md](../README.md) | 🛡️ ALinkSec |

## 部署与验证

| 文档 | 主题 |
| --- | --- |
| [deploy/cluster/README.md](../deploy/cluster/README.md) | 服务集群（第 22／23 项） |
| [deploy/tests/README.md](../deploy/tests/README.md) | Deployment Validation |
| [deploy/部署检查清单.md](../deploy/部署检查清单.md) | ALinkSec 真机部署检查清单 |

## 当前说明与历史记录

| 文档 | 主题 |
| --- | --- |
| [docs/86-扫描任务管理与失败复扫.md](86-扫描任务管理与失败复扫.md) | 主机扫描入口、预算、关联复扫、任务检出及逐文件处置回执 |
| [docs/01-总体架构与技术选型.md](01-总体架构与技术选型.md) | ALinkSec 安全监测与管理平台 — 总体架构与技术选型 |
| [docs/02-通信协议设计.md](02-通信协议设计.md) | ALinkSec 通信协议设计（gRPC / Protobuf） |
| [docs/03-数据库设计.md](03-数据库设计.md) | ALinkSec 数据库设计（PostgreSQL / SQLite + VictoriaMetrics） |
| [docs/04-Agent设计与策略规范.md](04-Agent设计与策略规范.md) | ALinkSec Agent 详细设计与策略规范 |
| [docs/05-扩展能力设计.md](05-扩展能力设计.md) | ALinkSec 扩展能力设计（病毒查杀 / 勒索诱饵防护 / 漏洞一键修复） |
| [docs/06-部署文档.md](06-部署文档.md) | ALinkSec 部署文档（详细版） |
| [docs/07-封版缺陷清单.md](07-封版缺陷清单.md) | ALinkSec 封版缺陷清单 |
| [docs/08-双数据库轻量化部署改造计划.md](08-双数据库轻量化部署改造计划.md) | ALinkSec 双数据库与轻量化部署改造计划 |
| [docs/09-剩余节点验收记录.md](09-剩余节点验收记录.md) | 剩余节点验收记录 |
| [docs/10-本机全功能联动验收记录.md](10-本机全功能联动验收记录.md) | 本机全功能联动验收记录 |
| [docs/11-登录与文件防护.md](11-登录与文件防护.md) | Linux 登录与文件完整性防护 |
| [docs/12-原生Agent本机验收记录.md](12-原生Agent本机验收记录.md) | 原生 Agent 本机验收记录 |
| [docs/13-版本发布流程.md](13-版本发布流程.md) | ALinkSec 版本发布流程 |
| [docs/14-ARM64支持.md](14-ARM64支持.md) | Linux ARM64 支持 |
| [docs/15-安全库同步与存储.md](15-安全库同步与存储.md) | 安全库同步与存储 |
| [docs/16-开源安全平台对接指南.md](16-开源安全平台对接指南.md) | 开源安全平台对接指南 |
| [docs/17-安全数据接入与演进.md](17-安全数据接入与演进.md) | 安全数据接入与演进 |
| [docs/18-基线模板审核与系统适配.md](18-基线模板审核与系统适配.md) | 基线模板审核与系统适配 |
| [docs/19-模块完善计划.md](19-模块完善计划.md) | 模块完善计划 |
| [docs/20-旧基线模板内容审核.md](20-旧基线模板内容审核.md) | 旧 Linux 基线内容审核与迁移 |
| [docs/21-OpenSSH配置核查.md](21-OpenSSH配置核查.md) | OpenSSH 指定连接配置核查 |
| [docs/22-本地身份文件核查.md](22-本地身份文件核查.md) | Ubuntu 24.04 本地身份文件参考核查 |
| [docs/23-PAM口令链核查.md](23-PAM口令链核查.md) | Ubuntu 24.04 passwd 口令链参考核查 |
| [docs/24-PAM登录失败锁定核查.md](24-PAM登录失败锁定核查.md) | Ubuntu 24.04 login PAM 登录失败锁定核查 |
| [docs/25-systemd服务状态核查.md](25-systemd服务状态核查.md) | Ubuntu 24.04 systemd 服务状态核查 |
| [docs/26-固定日志元数据核查.md](26-固定日志元数据核查.md) | Ubuntu24.04 固定日志路径元数据核查 |
| [docs/27-内核审计与身份文件watch核查.md](27-内核审计与身份文件watch核查.md) | Ubuntu24.04 内核审计与身份文件 watch 核查 |
| [docs/28-auditd磁盘配置与日志目标核查.md](28-auditd磁盘配置与日志目标核查.md) | Ubuntu24.04 auditd 磁盘配置与日志目标核查 |
| [docs/29-Debian-cron系统任务元数据核查.md](29-Debian-cron系统任务元数据核查.md) | Ubuntu24 Debian cron 系统任务元数据核查 |
| [docs/30-rsyslog-cron磁盘路由核查.md](30-rsyslog-cron磁盘路由核查.md) | rsyslog cron 专用日志磁盘路由核查 |
| [docs/31-sudoers磁盘策略核查.md](31-sudoers磁盘策略核查.md) | sudoers 磁盘策略核查 |
| [docs/32-APT默认磁盘安装策略核查.md](32-APT默认磁盘安装策略核查.md) | APT 默认磁盘安装策略核查 |
| [docs/33-APT默认磁盘源认证声明核查.md](33-APT默认磁盘源认证声明核查.md) | APT 默认磁盘源认证声明核查 |
| [docs/34-Ctrl-Alt-Del当前systemd策略核查.md](34-Ctrl-Alt-Del当前systemd策略核查.md) | Ctrl-Alt-Del 当前 systemd 策略核查 |
| [docs/35-PAM会话资源限制核查.md](35-PAM会话资源限制核查.md) | Ubuntu24 login PAM 会话资源限制参考 |
| [docs/36-OpenSSH名称解析与横幅声明核查.md](36-OpenSSH名称解析与横幅声明核查.md) | OpenSSH 名称解析与横幅磁盘声明核查 |
| [docs/37-Shadow新账户口令有效期与预警默认声明核查.md](37-Shadow新账户口令有效期与预警默认声明核查.md) | Shadow 新账户口令有效期与预警默认声明核查 |
| [docs/38-Bash全局启动与历史声明核查.md](38-Bash全局启动与历史声明核查.md) | Bash 全局启动与历史声明核查 |
| [docs/39-IPv4主机角色与全部接口当前参考核查.md](39-IPv4主机角色与全部接口当前参考核查.md) | IPv4 主机角色与全部接口当前参考核查 |
| [docs/40-systemd清理调度与内核同步指示核查.md](40-systemd清理调度与内核同步指示核查.md) | systemd 清理调度与内核同步指示核查 |
| [docs/41-链接器元数据与SUID-SGID审核清单核查.md](41-链接器元数据与SUID-SGID审核清单核查.md) | 链接器元数据与 SUID/SGID 审核清单核查 |
| [docs/42-rescue-emergency当前启动声明核查.md](42-rescue-emergency当前启动声明核查.md) | rescue/emergency 当前启动声明核查 |
| [docs/43-AppArmor当前根策略模式核查.md](43-AppArmor当前根策略模式核查.md) | AppArmor当前根策略模式核查 |
| [docs/44-基线模块收尾与认证-Agent-DNF核查.md](44-基线模块收尾与认证-Agent-DNF核查.md) | 基线模块收尾与认证、Agent、DNF核查 |
| [docs/45-RPM-DPKG完整版本比较与epoch保留.md](45-RPM-DPKG完整版本比较与epoch保留.md) | RPM/DPKG 完整版本比较与 epoch 保留 |
| [docs/46-软件包身份与采集完整性.md](46-软件包身份与采集完整性.md) | 软件包身份与采集完整性 |
| [docs/47-漏洞规则与检测结果身份范围.md](47-漏洞规则与检测结果身份范围.md) | 漏洞规则与检测结果身份范围 |
| [docs/48-漏洞规则来源与回移声明.md](48-漏洞规则来源与回移声明.md) | 漏洞规则来源与回移声明 |
| [docs/49-软件包修复执行契约与身份复核.md](49-软件包修复执行契约与身份复核.md) | 软件包修复执行契约与身份复核 |
| [docs/50-补丁包头核验与修复目标人工复核.md](50-补丁包头核验与修复目标人工复核.md) | 补丁包头核验与修复目标人工复核 |
| [docs/51-漏洞覆盖历史与审批派发闭环.md](51-漏洞覆盖历史与审批派发闭环.md) | 漏洞覆盖、历史与审批派发闭环 |
| [docs/52-安全来源治理与有界NVD同步.md](52-安全来源治理与有界NVD同步.md) | 安全来源治理与有界 NVD 同步 |
| [docs/53-检测执行与文件处置证据.md](53-检测执行与文件处置证据.md) | 检测执行与文件处置证据 |
| [docs/54-部署维护与成套恢复.md](54-部署维护与成套恢复.md) | 部署维护与成套恢复 |
| [docs/55-Agent升级看护与自动回退.md](55-Agent升级看护与自动回退.md) | Agent 升级看护与自动回退 |
| [docs/56-主机隔离租约与失联撤销.md](56-主机隔离租约与失联撤销.md) | 主机隔离租约与失联撤销 |
| [docs/57-Agent配置防篡改与可信恢复.md](57-Agent配置防篡改与可信恢复.md) | Agent 配置防篡改与可信恢复 |
| [docs/58-Agent资源自适应与有界补传.md](58-Agent资源自适应与有界补传.md) | Agent 资源自适应与有界补传 |
| [docs/59-Linux弱口令字典检测与覆盖证据.md](59-Linux弱口令字典检测与覆盖证据.md) | Linux 弱口令字典检测与覆盖证据 |
| [docs/60-Windows登录防护与覆盖状态.md](60-Windows登录防护与覆盖状态.md) | Windows 登录防护与覆盖状态 |
| [docs/61-Windows勒索进程归因与安全响应.md](61-Windows勒索进程归因与安全响应.md) | Windows 勒索进程归因与安全响应 |
| [docs/62-Windows更新发现与自动修复.md](62-Windows更新发现与自动修复.md) | Windows 更新发现与自动修复 |
| [docs/63-事件驱动实时监控与覆盖状态.md](63-事件驱动实时监控与覆盖状态.md) | 事件驱动实时监控与覆盖状态 |
| [docs/64-ClamAV引擎与扫描证据.md](64-ClamAV引擎与扫描证据.md) | ClamAV 引擎与扫描证据 |
| [docs/65-原生YARA引擎与规则证据.md](65-原生YARA引擎与规则证据.md) | 原生 YARA 引擎与规则证据 |
| [docs/66-病毒特征库增量更新.md](66-病毒特征库增量更新.md) | 病毒特征库增量更新 |
| [docs/67-等保2.0主机合规规则包.md](67-等保2.0主机合规规则包.md) | 等保 2.0 主机合规规则包 |
| [docs/68-XCCDF与OVAL原生解释.md](68-XCCDF与OVAL原生解释.md) | XCCDF／OVAL 原生解释与离线内容审核 |
| [docs/69-基线模板上游自动更新.md](69-基线模板上游自动更新.md) | 基线模板上游自动更新 |
| [docs/70-厂商漏洞公告原生接入.md](70-厂商漏洞公告原生接入.md) | 厂商漏洞公告原生接入 |
| [docs/71-OpenCTI原生指标接入.md](71-OpenCTI原生指标接入.md) | OpenCTI 原生指标接入 |
| [docs/72-多来源可信度与冲突处理.md](72-多来源可信度与冲突处理.md) | 多来源可信度与冲突处理 |
| [docs/73-报表增强与历史快照.md](73-报表增强与历史快照.md) | 报表增强与历史快照 |
| [docs/74-集中取证与自动恢复点.md](74-集中取证与自动恢复点.md) | 集中取证与自动恢复点 |
| [docs/75-原始日志集中检索.md](75-原始日志集中检索.md) | 原始日志集中检索 |
| [docs/76-系统适配与规模验收.md](76-系统适配与规模验收.md) | 系统适配与规模验收 |
| [docs/77-真实外部服务联调.md](77-真实外部服务联调.md) | 真实外部服务联调 |
| [docs/78-告警等级与采集查询修正.md](78-告警等级与采集查询修正.md) | 告警等级与采集查询修正 |
| [docs/79-证据回执并发读取与失败诊断.md](79-证据回执并发读取与失败诊断.md) | 证据回执并发读取与失败诊断 |
| [docs/80-发版准备与现场交付.md](80-发版准备与现场交付.md) | 发版准备与现场交付 |
| [docs/81-发布后启动凭据核查.md](81-发布后启动凭据核查.md) | 发布后启动凭据核查 |

## 历史发布说明

| 文档 | 主题 |
| --- | --- |
| [docs/releases/v0.0.1.md](releases/v0.0.1.md) | ALinkSec v0.0.1 |
| [docs/releases/v0.0.2.md](releases/v0.0.2.md) | ALinkSec v0.0.2 |
| [docs/releases/v0.0.3.md](releases/v0.0.3.md) | ALinkSec v0.0.3 |

## 本版新增资料

- [v0.0.4 发布说明](releases/v0.0.4.md)
- [全量文档核对与封版范围](82-v0.0.4文档核对与封版范围.md)

## develop 维护与全量真机验收

- [主机详情、组件健康及全量验收要求](83-主机详情与组件健康及全量验收.md)：未发布维护批次，开发只在 develop；全量现场验收尚不能由历史 CI 或短时可用性替代。
- [防护能力与开源实现差距](84-防护能力与开源实现差距.md)：逐项检测和处置机制、未覆盖范围、开源参照及 Linux 勒索误杀修正。
- [病毒库自动更新](85-病毒库自动更新.md)：哈希情报、FreshClam、原生 YARA 的定时更新、生效证据与尚未启用范围。

## 当前实现依据

- [协议](../proto/agent.proto)、[应用配置](../server/alinksec-bootstrap/src/main/resources/application.yml)、[数据库迁移](../deploy/migrations)。
- [发布门禁](../deploy/release/ci-gate.mjs)、[版本校验](../deploy/release/check-version.mjs)、[平台校验](../deploy/release/platforms.mjs)。
- [标准 Compose](../deploy/docker/docker-compose.yml)、[轻量 Compose](../deploy/docker/docker-compose.lite.yml)、[集群 Compose](../deploy/cluster/compose.yml)。
