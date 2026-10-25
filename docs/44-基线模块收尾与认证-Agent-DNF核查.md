# 基线模块收尾与认证、Agent、DNF核查

> 版本基线：v0.0.4。核查定义、适用系统和 pass／fail／error 边界沿用本文有限参考；分批实施计数仅属当时记录，当前旧规则处置及合规包分别见[收尾](44-基线模块收尾与认证-Agent-DNF核查.md)和[条款包](67-等保2.0主机合规规则包.md)。版本差异见[发布说明](releases/v0.0.4.md)，全部资料见[文档索引](README.md)。

旧 Linux 60 项逐条保留来源、修正后的观察范围和迁移记录。本批补齐 0001、0049、0050、0051、0058 五项，累计 59 项有限实现（8 项通用观测、51 项独立产品候选）。0054 根据本产品架构明确排除主机本地 cron 参考，由平台调度行为验证承担；它不生成检查、不进入得分，也不记为主机通过。通用审核包不可变版本为 25，仍为 8 项下发、52 项排除；PAM 包版本为 2，其余本批包版本为 1。产品范围、检查 JSON、人工说明与来源摘要保留在审核、不可变版本和任务快照中。

## passwd 最小长度与 login 终端限制

0001 使用 Ubuntu 24.04 已支持的 passwd password 链、libpwquality 默认值、全部有限 drop-in、主配置和模块参数覆盖顺序，独立核对 `minlen>=8,credits<=0,enforcing=1,enforce_for_root=1,use_authtok=1`。它不要求 0002 的三类别和长度 12 参考，两个结论可以不同。根属主/属组、非组或其他用户可写、访问/默认 ACL、非链接普通输入和变化边界均需确认；未知链或不可信输入为 error。实际调用、已有口令、其他服务及模块完整性未验证。生产不读取口令，不修改 PAM，不触发认证。

0058 只解释 Ubuntu 24.04 login auth 链首个 pam_securetty 后接已支持的本地 unix/deny/permit 链；模块路径限定本机标准目录或已知别名。项目参考为首模块 required 或 requisite、明确 `noconsole`、可信 `/etc/securetty` 非空且仅含 tty1 至 tty6。可识别的 optional/sufficient、无模块、空清单和其他终端为 fail；未知控制流、缺失输入、链接、ACL、权限、重复或未支持文本保持 error。文件逐字有界读取，CRLF 不归一化，也不把注释当允许项。实际模块调用、身份解析、模块完整性、其他服务和终端交付未验证。

Linux-PAM 的 pam_securetty 默认允许非 root 用户，并在缺文件时可能成功；没有 `noconsole` 时还会解释内核 console 例外，因此文件存在或权限不能代替上述完整参考。CI 专用 Ubuntu24 PAM 容器对新口令长度做真实探针对照；对 securetty 做 6 次配置观察和 9 次真实认证比较，包括 root、非 root、`/dev/tty1`、pts、optional、空清单、缺文件和提前 bypass。仅隔离容器设置临时口令；生产主机认证配置不变，凭据不进入日志或报告。强制逻辑边界组与原生结果分别记录。

## 当前 Agent 会话与哈希库缓存

0049 的上下文由执行该任务的 Client 提供，JSON 不能指定进程、路径、地址或其他 Agent。当前进程执行本检查，且当前 mTLS session 活跃、同一代次成功 Send/Recv 均在 60 秒内才满足参考。连接激活时清空历史，重连增加代次，旧回调不能写入新会话；两次观测允许时间戳前进，回退、未来时间或代次/状态变化为 error。完整断线、未成功收发或过期为 fail。Send 成功表示客户端传输调用成功；服务器业务接受、持久化、其他 Agent 和防护能力均未验证。报告不包含端点、令牌或证书。

0050 只核对该 Client 内生工作目录中的非空 hash-only 清单与当前全局已加载数据库缓存。工作目录及祖先、virus/db、manifest.json、hashes.txt 和可选空 rules.json 均需可信元数据、ACL 和读取稳定性；数据库路径必须匹配。manifest 严格四字段、唯一键、无 null 或尾随值；版本、数量、SHA256、名称及严重程度按有限语法解释。最多 1024 条、64 KiB 单文件、三种已知文件；非零规则、未知文件、重复或计数错误保持 error。两次只读缓存代次和完整集合必须相同；与磁盘版本、计数、集合完全相等且非空才 pass，完整空或缓存偏差为 fail。检查不加载、刷新或下载数据库，只返回数量与摘要；原版本、威胁名称和哈希条目不回显。来源真实性、时效、检测覆盖、具体引擎实例和包摘要认证仍未验证。

真实 Go Agent 流程使用 Ubuntu24 隔离主机、真实 Java 平台、TLS 注册和 mTLS 通道，验证正常缓存、修改磁盘后两次仍为旧缓存、重启正常加载后的匹配。基线观察不能修复陈旧缓存。连接、缓存互斥等待支持共同截止时间，竞争和重连由 race 检查覆盖；缺少执行上下文的通用 Run 和 Windows 返回 error。

## Rocky 9 DNF 签名声明

0051 限定 Rocky 9 的 DNF 4.14.x 默认磁盘配置。固定查询 RPM 已安装版本前后相等，读取 `/etc/dnf/dnf.conf` 和 `/etc/yum.repos.d`、`/etc/yum/repos.d`、`/etc/distro.repos.d` 中全部直接 .repo。显式 reposdir 必须精确等于默认三目录。有限 INI 不接受 include、重复键/仓库、续行和未知布尔；根可信元数据、ACL、文件/行/仓库数量以及读取变化都受约束。main 的 gpgcheck、repo_gpgcheck、localpkg_gpgcheck 均为 true，仓库集合非空且全部仓库的前两项为 true 才满足；仓库继承 main，禁用仓库也检查，缺省签名标记为 false。完整偏差为 fail，无法可靠解释为 error。

只回传版本、布尔、数量与仓库集合摘要，不输出 URL、仓库名、密钥或凭据。实际调用与命令行、密钥身份、真实签名验证、插件以及其他包管理器未验证。生产不执行 DNF、不联网、不安装包。Rocky9 一次性容器使用 libdnf Python 配置对象独立比较 8 次，包括继承、覆盖、禁用仓库、第三默认目录、本地包与空集合。探针不加载元数据或插件，不修改宿主；单独 CGO-free 测试二进制避免跨 glibc 假设。

## 0054 平台调度处置

`VirusTaskService.weeklyQuickScan` 由 `alinksec.virus.weekly-scan-cron` 注册，缺省周一 02:30（服务端时区），`-` 关闭。仅存在已发布库且主机在线、未删除时创建 QUICK 扫描并下发；不存在统一 Agent 本地 cron。审核保留 `status=unsupported` 以继续排除下发，同时标记 `disposition=out_of_scope`、`implementationBacklog=false`。这项架构处置不表示扫描引擎能力或扫描成功。

定时入口自身加入事务，避免 self-call 绕过 createTask 事务；扫描任务改用 CommandService 的提交后发送接口，任务和待发命令先共同提交，再向 Agent 暴露。同步下发准备异常传播并回滚任务元数据，由调度框架记录失败。真实 SQLite 迁移与事务代理验证无库/无适用主机、只发在线未删除主机、QUICK/空路径、事务中的下发准备、无基线得分及失败回滚；实际 CommandService 与命令表另验证提交前不调用发送器、回滚时任务和命令一起消失。真实 Spring 调度注册验证默认表达式和 `-` 关闭，注册检查不等待周一定时触发。提交后的网络发送失败仍按既有持久队列重推契约处理，不宣称网络发送与数据库的分布式原子性。

## 模块验收

模板内容、适用性、执行异常、审核发布、结果历史、修复权限与角色体验按[模块完成条件](19-模块完善计划.md)收尾；59 项有限观察与一个明确架构排除均可追溯，没有未处置的旧规则实施待办。单项 pass 只表示满足审核参考，不能推出完整等保、CIS、STIG 合规。同步内核或文件系统调用可能不能即时抢占；共同预算在边界和可取消等待处检查，所有快照均为非原子，不能排除变化后恢复。

服务端新增候选用真实 SQLite 事务、逐项定义与历史快照、新版本 fresh evidence、error 阻止发布、完整已知 fail 可发布验收。SQLite/PostgreSQL REST 和真实生产 bundle 另保存协议夹具，核对完整定义、实测值、未知边界、桌面手机与 viewer 无写权限；这些协议报告不替代前面的原生证据。本机资源看门狗拒绝高压力编译后不加限重试；原生、race、构建和部署回归使用精确提交的独立 CI runner，同一 runner 串行清理。源码树、日志、产物摘要及截图绑定最终成功 HEAD；完成状态仅在这些检查成功后记录。合并和版本发布按用户指示安排。

来源：[pam_securetty 实现](https://github.com/linux-pam/linux-pam/blob/v1.5.3/modules/pam_securetty/pam_securetty.c)、[libpwquality 配置](https://github.com/libpwquality/libpwquality/blob/libpwquality-1.4.5/doc/pwquality.conf.5.pod)、[libdnf main 默认](https://github.com/rpm-software-management/libdnf/blob/0.69.0/libdnf/conf/ConfigMain.cpp)、[仓库继承](https://github.com/rpm-software-management/libdnf/blob/0.69.0/libdnf/conf/ConfigRepo.cpp)、本项目 Client/缓存/平台调度源码。阈值是项目审核参考，不能作为上游认证要求。
