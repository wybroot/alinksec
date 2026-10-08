# APT 默认磁盘源认证声明核查

旧 `BL-LINUX-0053` 收窄为默认磁盘源认证与显式签名范围声明。独立候选 [apt-sources-definitions.json](../deploy/baseline/apt-sources-definitions.json) 和 [模板包](../deploy/baseline/packages/apt-sources/linux-baseline.json) 仅适用 Ubuntu 24.04 完整安装的 `apt/libapt-pkg6.0t64 2.8.3`。管理员确认包可信及默认入口适用性；包状态查询不证明二进制或库未被修改。通用观测包仍排除此项，旧模板、历史任务及 V001–V007 不改写，无自动修复。

## 参考和结果

新增 `apt_sources_policy` 固定 `/etc/apt`、`eq` 和完整参考，后端与 Agent 拒绝弱化参考、任意路径或额外字段，包括 `null`。Windows 明确返回执行异常。配置与源列表串行读取，两个包前后查询共用一次截止时间。

| 范围 | 要求 |
|---|---|
| apt 和 apt-get 默认配置 | `Acquire::AllowInsecureRepositories`、`Acquire::AllowWeakRepositories`、`Acquire::AllowDowngradeToInsecureRepositories` 都为 false；即使某源显式 false，仍要求全局无绕过声明 |
| 每个活动源 | `Trusted` 缺失或 false，三种单行源 `allow-*` 绕过选项缺失或 false |
| 每个活动 URI/套件声明 | 显式 `Signed-By` 至少包含一个 `/etc/apt/keyrings` 或 `/usr/share/keyrings` 直接 `.gpg/.asc` 文件；可附 40 位指纹及 `!` |
| keyring 与其直接目录 | UID/GID 0、组其他不可写、无访问/默认 ACL；文件非空、单硬链接、普通文件、最多 1 MiB、所有用户可读 |
| 活动源范围 | 至少一个活动声明；同 URI/套件的认证和 Signed-By 声明一致 |

已完整解析的声明不满足参考为 `fail`；未知语法/字段/布尔值、冲突或输入安全边界不能确认为 `error`。无活动源、缺 `Signed-By` 或仅指纹也为 fail：这些情况可能依赖全局 keyring 或已获取 Release 的签名范围，本参考明确要求磁盘源自身提供文件范围。`Trusted=no` 只表示显式不信任，满足无强制信任参考不证明源可用于安装。

## 有限解析

配置沿用默认 `apt.conf.d` 按原生名称选择与字节排序，再读取存在的 `apt.conf`；保留空节点、顶层 `#clear` 与 apt/apt-get Binary 覆盖语义。源列表先读取存在的 `sources.list`，再读取 `sources.list.d` 中非隐藏、ASCII 有限文件名且扩展名精确为 `.list/.sources` 的片段。冒号名称可被原生选中；大写扩展名、备份、隐藏名称不解释，但完整名称集合仍参与稳定性检查。选中名称指向非普通输入时严格 error，较原生忽略行为更保守。要求默认源目录存在。

单行格式支持 `deb/deb-src`、有限无凭据 HTTP/HTTPS URI、普通套件/组件名称，选项限 `signed-by`、`trusted`、三个 `allow-*` 与 `arch`。Deb822 支持 Types、URIs、Suites、Components、Signed-By、Trusted、Enabled、Architectures，字段名不区分大小写、支持续行和列首注释。多 URI/套件按笛卡尔积解释，deb/deb-src 与多个组件共享 Release 范围。原生先验证 `Types` 再判断 `Enabled`；禁用段落缺失/未知类型也保持 error。`Enabled=no` 的已支持段落不检查密钥路径，全部字段与基本语法仍需在有限范围内。

APT 2.8.3 的 `ParseStanza` **没有映射** Deb822 `Allow-Insecure/Allow-Weak/Allow-Downgrade-To-Insecure` 字段。本候选对这些字段报 error，避免把字段文字误当作有效原生覆盖。此行为由固定版本源码及真实 libapt 对照确认；不能套用其他版本的语义。

未知或重复字段/选项、大小写错误的单行选项、引号/转义、内嵌密钥、其他密钥位置、平坦源、变量、其他 URI 方法、凭据/查询/片段及需要进一步规范化的路径不支持。源加载入口改写、额外 `APT::Sources::With`、清除相关加载树、include、RootDir 等保持 error。普通未知配置项仅作为有限语法数据，钩子不会执行。

配置与源各最多 32 片段，另可存在两个主文件；单文件 64 KiB，合计 256 KiB/4096 行，行 4096 字节、目录 128 名称、64 个 URI/套件声明、每 Signed-By 16 选择器、16 个不同 keyring 文件。配置作用域与 token/statement 上限沿用 [默认安装策略检查](32-APT默认磁盘安装策略核查.md)。

## 输入与未验证范围

输入逐段 O_PATH/NOFOLLOW 打开并持有最终 fd，配置/源读取同 inode；结束重新打开核对 inode、模式、UID/GID、链接数、ctime、大小、mtime、父身份/访问元数据和目录完整名称集合。缺失、链接、特殊输入、不可信元数据、ACL、读取失败、超限、超时、期间变化均不能产生通过结论。keyring 仅核对元数据，不读取内容；这不是完整父目录授权或对 root 持续篡改的证明。

结果明确标记 environment_state、command_line_state、key_identity_state、key_material_state、repository_signature_state、cached_release_state、installation_state 全部 unverified。pass 只证明限定默认磁盘声明；不证明密钥有效/未撤销、指纹存在、仓库为官方源、算法安全、索引或包真实性、签名验证实际成功、调用环境/命令行或其他前端覆盖。HTTPS 本身不证明软件源可信。管理员必须独立确认可信密钥与实际仓库认证。生产不调用 APT/apt-config/gpg，不读取密钥内容或缓存 Release，不执行钩子、安装、更新索引或网络访问。

## 验证与来源

隔离 Ubuntu24 专用容器固定 APT 2.8.3，network=none、128 MiB 内存/192 MiB 含 swap、CPU 1、pids 64、cap-drop=ALL、no-new-privileges、源码只读。测试专用 C++ oracle 链接真实 libapt，用原生配置初始化、Binary MoveSubTree、ReadMainList 和 Release 元数据接口，只解析私有夹具。它不发起 acquire、网络、缓存生成、密钥解析或签名验证。候选值与硬编码预期及原生 Trusted、Signed-By、三种绕过状态比较；保留原有 APT 安装策略对照。UID、访问/默认 ACL、链接、特殊输入、变化与 deadline 在原生容器中必跑。

有意使用非密钥字节的私有 keyring 夹具，证明元数据检查和原生源解析都不验证密钥内容，不能当作真实签名证据。原生默认源与受控声明的检查也不等于用户主机仓库验签。SQLite/PostgreSQL REST、发布异常阻断、任务快照及桌面/手机报告用明确协议夹具验证。

主来源为 [Ubuntu APT 2.8.3 sources.list 手册](https://manpages.ubuntu.com/manpages/noble/man5/sources.list.5.html)、[apt-secure 手册](https://manpages.ubuntu.com/manpages/noble/man8/apt-secure.8.html) 和已取得并按官方 dsc 哈希核对的 APT 2.8.3 源码（sourcelist.cc、debmetaindex.cc、init.cc、fileutl.cc、configuration.cc、private-cmndline.cc）。源码哈希核对不等于 dsc 签名验证。
