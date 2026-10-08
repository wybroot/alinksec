# sudoers 磁盘策略核查

独立 [Ubuntu24 sudoers 候选包](../deploy/baseline/packages/sudoers/linux-baseline.json) 将旧 BL-LINUX-0018 收窄为统一认证声明参考，将 BL-LINUX-0029 重映射为获准命令日志文件声明。它解释限定配置语法，不计算某个账户的最终有效授权，也不证明每次认证或日志交付。两端需升级；未知类型、无法完整解释配置或读取失败返回执行异常并阻止候选发布。

适用范围为 Ubuntu 24.04、完整安装 `sudo 1.9.15p5-3ubuntu5.24.04.4`，管理员确认可信安装、默认 sudoers 插件和 `/etc/sudoers` 入口。Agent 固定查询 `/usr/bin/dpkg-query` 和 `/var/lib/dpkg`，使用清洁环境，读取前后确认精确软件包状态；这不验证可执行文件、插件或配置入口的真实性。产品版本依据 [Ubuntu 软件包记录](https://packages.ubuntu.com/en/noble-updates/sudo)。

| 检查项 | 完整固定参考 | 结论 |
|---|---|---|
| authentication | `authenticate=on,exempt_group=unset,nopasswd_tags=0` | 全局最后声明显式开启 authenticate，未指定豁免组，全部已解释正命令声明均无 NOPASSWD 标签 |
| allowed_logging | `log_allowed=on,logfile=/var/log/sudo.log` | 全局最后声明显式开启获准命令事件日志，并指向固定日志文件 |

至少需要一个已支持的正命令声明；空策略不通过。参考要求显式 authenticate 与 log_allowed，不假定编译默认值。厂商默认文件通常没有这些显式声明，所以不满足本项目参考；不能将其解释为默认 sudo 不认证或没有 syslog 日志。指定其他日志路径也可能有效，但不满足这个固定路径参考。

## 有限解析范围

固定主文件允许唯一一次 `@includedir /etc/sudoers.d`，或从行首开始的 `#includedir /etc/sudoers.d`。包含在原位置展开，禁止嵌套和重复。读取目录内没有任何点且不以 `~` 结尾的条目，接受唯一两位数字前缀名或厂商 `README`，按字节顺序读取；点文件和备份名被忽略，但整个名称集合参与变化检查。语义依据精确上游 [toke.l](https://github.com/sudo-project/sudo/blob/SUDO_1_9_15p5/plugins/sudoers/toke.l)。

支持全局 authenticate、log_allowed、exempt_group、logfile 声明及其已支持清除形式，依次应用后声明覆盖；另外解释 env_reset、mail_badpass、use_pty、log_denied 和两种固定厂商 secure_path 值。用户、主机、运行身份、命令作用域 Defaults 以及其他选项均返回 error。未知选项即使看似与当前检查无关，也不会被跳过。

正授权只接受一个小写命名用户、命名 `%组` 或 ALL 主体，ALL 主机，显式 root/ALL 运行用户和可选 root/ALL 组，ALL 或无参数的规范绝对命令路径。命令列表解释 PASSWD/NOPASSWD 标签继承，在下一个授权声明重置。别名、数字UID/GID、主机匹配、否定、参数、通配、摘要、其他标签、续行和转义均未支持。注释不计为标签；数字 UID 开头不会被当作注释跳过。

认证参考要求**所有声明**不含免认证标签。即使后续匹配授权可能覆盖早先 NOPASSWD，本检查仍不满足该声明参考。显式 PASSWD 可能覆盖全局 !authenticate 的实际命令行为，本检查仍要求全局 authenticate 开启。证据不会据此声称真实账户获得了免口令权限。root、相同运行身份、认证缓存和 PAM 行为需另行确认，见上游 [check.c](https://github.com/sudo-project/sudo/blob/SUDO_1_9_15p5/plugins/sudoers/check.c) 与 [sudoers 手册](https://github.com/sudo-project/sudo/blob/SUDO_1_9_15p5/docs/sudoers.man.in)。

## 输入、执行和证据边界

配置必须为 UID/GID 0、组及其他用户不可写的无链接普通文件或目录；文件仅一个硬链接，拒绝访问/默认 ACL。路径逐段以 O_PATH/NOFOLLOW 打开并持有最终文件描述符，读取已持有文件。结束前重新打开核对 inode、访问元数据、ctime、大小和mtime，核对父目录身份/访问元数据及包含目录名称集合。未实现父目录完整有效授权证明。

上限为 32 个包含文件、单文件 64 KiB、总计 256 KiB、4096 行、每行 4096 字节、目录 128 条目，限定 ASCII/LF 且最后一行终止。前后软件包查询和全部输入共用一个 deadline。缺失、特殊文件、链接/硬链接、ACL、不可信元数据、未知形式、超限、期间变化或超时为 error；完整解释后的参考偏差为 fail。失败信息不回显未知配置内容。

证据始终标注：

```text
scope=on-disk-sudoers-declarations
 authorization_state=unverified authentication_state=unverified delivery_state=unverified
```

生产不调用 sudo、visudo 或 cvtsudoers，不执行配置命令，不查询 NSS/PAM，不加载插件，不读取日志或修改配置。cvtsudoers 启动也会读取 sudo.conf 的调试设置，见 [cvtsudoers.c](https://github.com/sudo-project/sudo/blob/SUDO_1_9_15p5/plugins/sudoers/cvtsudoers.c)，因此只在隔离验收中调用。日志声明不证明 sudo.conf 审计插件、NSS来源、实际插件入口、日志文件类型/授权/写入/轮转或事件交付；无自动修复。

## 验证

Go 检查覆盖明确声明、厂商无声明、注释、命令标签继承与重置、被后续覆盖的免认证声明、全局开关/豁免组清除、日志关闭/其他路径、包含位置与顺序、忽略备份名、空策略，以及不可信文件、ACL、未知语法、软件包和文件变化、超时。

[原生脚本](../deploy/tests/sudoers-native.sh) 在精确软件包的一次性 Ubuntu24 容器中运行。容器无网络、capabilities 为零、128 MiB 内存、工作区只读。使用真实 visudo 验证私有配置语法，cvtsudoers 输出 JSON，独立从原生 AST 核对最终显式 Defaults 和命令标签/数量，再与候选结果比较。16组语义场景全部必跑；访问/默认 ACL 和未知输入边界在原生容器中不能跳过。这只验证配置声明，不执行提权命令、不操作账户或密码，也不提供实际认证/日志交付证据。

服务端验证定义弱化、额外字段（包括null）、Windows平台和不适用主机拒绝；任务快照、异常阻止发布、完整不合规允许管理员评估、旧版本证据不可复用。REST 与浏览器使用明确协议样本，展示一个认证声明通过、一个日志路径偏差及50分，测试桌面/手机证据和只读角色。最终验收以绑定源码提交的 CI 结果为准；基线模块整体继续保持草稿。
