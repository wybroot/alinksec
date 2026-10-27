# 病毒定义自动更新

这是未发布 develop 的部署配置；不会自动安装引擎、注册服务或改变现有主机。
完整入口及验收边界见 [病毒库自动更新](../../docs/85-病毒库自动更新.md)。

## 已选定的公开来源

无需填写密钥的配置已提供，可直接部署：

| 用途 | 配置文件 | 来源与周期 |
| --- | --- | --- |
| 恶意 SHA256 | [libraries.public.yml](libraries.public.yml) → 服务端 `/app/data/libraries.yml` | [LOKI Signature-Base](https://github.com/Neo23x0/signature-base)，每小时完整快照 |
| Linux 原生 YARA | [yara.public.yml](yara.public.yml) → Agent `agent.yml` 的 `yara` 段 | [ReversingLabs](https://github.com/reversinglabs/reversinglabs-yara-rules)，10 份规则，每小时整批检查 |
| ClamAV | [freshclam.conf](freshclam.conf) → `/etc/alinksec/freshclam.conf` | 官方 `database.clamav.net`，每天 24 次检查 |

LOKI 原始文件同时含 MD5、SHA1、SHA256；`loki-hashes` 适配器仅接收 SHA256，
拒绝格式异常、空 SHA256 集合和超限候选，成功时撤销上游已删除的哈希。它保留既有
手工及其他来源数据，自动发布并推送 Agent。上游采用
[DRL 1.1](sources/SignatureBase.LICENSE)，来源标识为 `LOKI.SignatureBase.KnownHash`。

YARA 当前选择 BPFDoor、GTPDOOR、AutoColor、NoodRAT、PygmyGoat、Pumakit、
GwisinLocker、Helldown、KillDisk、BiBiWiper；这是明确的 Linux 子集。保留原作者与
规则名，将 [MIT 许可](sources/ReversingLabs.LICENSE) 同部署到 Agent 的
`yara-updates/ReversingLabs.LICENSE`。`update_urls` 最多 16 个 HTTPS 地址，与
`update_url` 互斥，合并源码仍限制 256 KiB，共享一轮 30 秒下载/编译期限；任何文件
下载或整批编译失败都保留上次完整快照。增加或删除来源会使旧来源快照失效。

配置使用 GitHub Contents API 的原始文件响应，不需要注册账号；原生下载器对
`api.github.com` 发送 `Accept: application/vnd.github.raw+json`，不会把 JSON 外壳
当作规则。大量 Agent 共用出口时需统一到内部 HTTPS 发布源，避免公开 API 的共享
额度不足。部署源地址及密钥在受保护配置文件中管理；控制台可调整服务端同步开关
和周期，不能直接修改本机信任的 YARA 来源。

## ClamAV

使用官方 FreshClam 获取 main/daily/bytecode 数据库。随附配置每小时检查一次，
启用增量更新和新库加载校验，成功后通知本机 clamd 重载。无需第三方 API Key。
检查成功而库内容未变化是正常结果，不能把每次检查都算成新版本。
[官方更新说明](https://docs.clamav.net/manual/Usage/SignatureManagement.html)。

Linux systemd 主机须先安装受支持的 ClamAV、确认 `/usr/bin/freshclam` 和 `clamav`
账号存在，并按 [引擎文档](../../docs/64-ClamAV引擎与扫描证据.md)建立本机受保护的
clamd/TLS 通道。配置中的数据库目录和 clamd 配置路径必须与实际服务一致；若使用
不同路径，同时修改配置、unit 的 ExecStart/ReadWritePaths。不要让两个 FreshClam
进程同时维护同一数据库，包括发行版已有的 `clamav-freshclam` 服务。

随附 [check-clamav.py](check-clamav.py) 是只读的 Linux 首次初始化检查，需要 Python 3。
它核对真实 FreshClam 能否解析配置、专用账号及目录权限、FreshClam/clamd 数据库
路径一致、官方来源、每小时检查及库加载校验，并检查已运行的更新进程。ClamAV 1.5
还需要软件包自带的 CVD 验签证书；解包工具测试不能只提供 HTTPS CA。
此配置默认使用发行版 `/etc/clamav/certs`；如果自定义 `CVDCertsDirectory`，也需在
FreshClam 的实际运行环境中设置相同的 `CVD_CERTS_DIR`，供库加载校验使用。
本项目初始化前保守要求至少 3 GiB **可用内存**及数据库文件系统 3 GiB 余量
（包括保留的 2 GiB 和初始化空间）。这是部署检查门槛，不是构建阈值，也不代替
完整库加载及重载的实测；仅有 2 GiB 总内存的本机不满足要求。
检查失败退出 2，成功退出 0；JSON 中 `onlineUpdateAccepted` 和
`clamdAndAgentProtectionAccepted` 始终为 false，检查本身不能算实际启用。

在正式目标机确认完整库下载、加载及重载所需的内存和磁盘后，首次部署执行：

```sh
sudo install -d -m 0755 /etc/alinksec
sudo install -d -o clamav -g clamav -m 0750 /var/lib/clamav
sudo install -m 0644 deploy/antivirus/freshclam.conf /etc/alinksec/freshclam.conf
# 先配置实际 clamd，并检查、停止原有 FreshClam 服务和其他定时入口。
sudo python3 deploy/antivirus/check-clamav.py
# 只在检查通过后继续初始化；修复失败项后重新检查。
sudo -u clamav /usr/bin/freshclam --config-file=/etc/alinksec/freshclam.conf
sudo install -m 0644 deploy/antivirus/alinksec-freshclam.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now alinksec-freshclam.service
sudo systemctl status alinksec-freshclam.service
sudo journalctl -u alinksec-freshclam.service --since '2 hours ago'
```

首次初始化成功后启动/验证 clamd。后续由 FreshClam 后台定时检查及通知重载，不需
逐次执行上述命令。clamd 配置须启用合适的 SelfCheck 作为通知失败后的重载补查。
同时确认 clamd 的 VERSION 已反映更新，Agent 心跳与新扫描任务使用该版本。
旧扫描任务固定版本，更新中发生版本变化时可能需要重新发起；不能把该失败记为干净。

429/403、DNS、TLS、下载、库校验或重载失败必须检查日志；已有可加载库不等于最新库。
FreshClam 自带 CDN 冷却/重试规则，不要另外加高频 curl 或删除其状态文件强制重试。
本机约 2 GiB 的开发环境不启动完整官方库，生产完整库在线更新与长期运行仍须验收。
2026-10-27 已在独立临时目录使用 Ubuntu 软件包的 FreshClam 1.5.4 实际下载官方
bytecode 第 339 版（80 条特征、281,702 字节），库加载校验及随后无变化复查通过。
这次检查仅限 bytecode，不包含 main/daily、clamd、TLS 前置或 Agent 启用；不据此
改变完整 ClamAV 防护未就绪的状态。首次因临时解包环境缺少默认 CVD 验签证书路径
导致的加载失败保留记录；补充软件包自带证书路径后复验成功，没有关闭库校验。
该 unit 适用于 Linux systemd；Windows 可使用官方 freshclam.exe 的 daemon 模式，
其系统服务托管及原生更新验收不在本次 Linux 模板结论内。

## YARA

使用原生 YARA Agent，在受配置防篡改保护的 agent.yml 中配置批准的规则发布地址：

```yaml
yara:
  enabled: true
  realtime: true
  update_url: https://rules.example.org/approved/host.yar
  update_interval_sec: 3600
  timeout_sec: 10
  # 私有 HTTPS 发布服务可配置受保护的本机 CA 文件；公开源使用系统信任库。
  # update_ca_file: /etc/alinksec/rules-publisher-ca.crt
```

上面是自建发布服务示例；公开 Linux 配置直接采用 `yara.public.yml`。源必须提供完整 UTF-8 YARA 源码，不接受 HTML、
ZIP、include 或预编译对象。URL 不允许密钥、查询参数、用户信息或重定向。可选的
rules_file/rules_sha256 用作首次成功更新前的已核验基础规则，现有固定规则模式继续
支持；启用 URL 后不需每次人工修改 rules_sha256 或重启 Agent。

批准的是该来源的后续内容更新权限，HTTPS 不保证规则无误报。应选定可信项目/内部
审核发布源；社区仓库中的规则、模块和许可并不统一，不能假定 YARA 有一个完整的
官方病毒库。新内容通过现有有界原生子进程编译后原子切换，失败保留旧快照；每次
扫描仍固定实际源码 SHA256。控制台分别展示成功检查、内容变更、下一次检查和错误。

## 哈希情报

服务端 libraries.yml 的 MISP/OpenCTI/MalwareBazaar 等来源使用已有持久调度。通过
校验的新内容会自动发布，在线 Agent 自动接收；离线 Agent 回连通过心跳补更新。
无需给每台 Agent 配置上游密钥。配置和权限见 [安全库同步](../../docs/15-安全库同步与存储.md)。

MalwareBazaar 当前 API 和导出均需要 Auth-Key；请通过受保护的部署配置提供，不要
把密钥发到聊天或提交仓库。没有来源/认证配置的环境应明确显示未配置，不能填入
测试包或无效源后宣称定时更新已经生效。
