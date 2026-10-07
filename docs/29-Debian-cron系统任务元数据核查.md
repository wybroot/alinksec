# Ubuntu24 Debian cron 系统任务元数据核查

独立候选 [cron/linux-baseline.json](../deploy/baseline/packages/cron/linux-baseline.json) v1 实现旧 `BL-LINUX-0019` 的有限产品范围：Ubuntu24.04 已完整安装的 Debian cron `3.0pl1-184ubuntu2`，默认系统任务表 `/etc/crontab`、目录 `/etc/cron.d` 及其**全部直接条目**的当前磁盘元数据。不适用于 Cronie、bcron、BusyBox cron、其他版本或自定义路径。OS 匹配只是选模条件，Agent 还需两次确认固定 dpkg 数据库中的精确软件包状态；管理员确认可信安装和路径适用性。包登记不能证明二进制未被替换或该实例正在使用这些路径。

源码与官方依据：[Ubuntu noble cron 软件包](https://packages.ubuntu.com/noble/cron)、[3.0pl1 原始源码](https://archive.ubuntu.com/ubuntu/pool/main/c/cron/cron_3.0pl1.orig.tar.gz)、[184ubuntu2 补丁](https://archive.ubuntu.com/ubuntu/pool/main/c/cron/cron_3.0pl1-184ubuntu2.debian.tar.xz) 中 `Drop-in-drop.d-directory-support.patch` 及应用全部补丁后的 `database.c`，另参考 [Debian cron(8)](https://manpages.debian.org/bookworm/cron/cron.8.en.html)。Ubuntu manpage 的同名入口可能展示 Cronie，本实现以精确 Debian cron 包源码和原生二进制验证为准。

## 明确参考

检查类型 `debian_cron_metadata`，固定 `target=system-tables`、`operator=eq`，参考 `crontab<=0644,cron.d<=0755,all_entries<=0644,uid=0,gid=0`。服务端与 Agent 同时拒绝任意路径、命令、权限放宽或其他字段（包括额外 null 字段）。Linux 以外返回 error。

| 对象 | 类型及权限位上限 | 属主与属组 |
|---|---|---|
| `/etc/crontab` | 普通单硬链接文件，0644 | 数值 UID/GID 均 0 |
| `/etc/cron.d` | 目录，0755 | 数值 UID/GID 均 0 |
| 目录的全部直接条目 | 普通单硬链接文件，0644 | 数值 UID/GID 均 0 |

这是本候选的较窄参考，不是 cron 原生加载条件的完整等价表达。Debian cron 原生拒绝组/其他可写、非 root 属主的系统任务表；它允许符合属主条件的部分符号链接，也允许 root 执行位。候选对链接保持 error，对多余执行位保持完整 fail，另外明确要求 GID 0。更严格模式满足位上限，不证明可读或可用。

候选不依赖 cron 启动时的传统/LSB 文件名筛选。点文件、`.placeholder`、备份名等全部计入；即使原生 cron 忽略某个名字，它的明确权限偏差仍为 fail。只检查直接条目，不递归；子目录、特殊文件、符号/硬链接、访问 ACL 或默认 ACL、无法确认 ACL、缺失/读取失败、未支持文件名、超过 128 条目均为 error。支持名字是 1–128 字节 ASCII 字母、数字、点、下划线、横线；未知输入不会被跳过后宣称通过。

## 只读边界与证据

Agent 只运行固定 `/usr/bin/dpkg-query --admindir=/var/lib/dpkg --show --showformat=... -- cron`，清空继承环境中的 DPKG_ROOT 等重定向变量，输出与进程组使用现有 64 KiB、超时与清理边界。查询需精确 `ii ` 状态和已支持版本，缺失、其他版本或命令失败为 error。两次查询共享全检查 deadline。

文件逐段以持有的目录 fd、`O_PATH/O_NOFOLLOW` 打开；不打开任务内容，不会被 FIFO 阻塞。仅为枚举固定目录打开其持有 fd 对应的只读目录描述符，一次最多取得129个名字，超过128立即 error。检查访问/默认 ACL；保留文件描述符并在最终重新核对路径、inode、模式、UID/GID、链接数、ctime、目录 mtime 和条目集合，发现变化或超时则 error。最多保持130个目标描述符，另有少量临时描述符；证据只汇总已检查数、违规数和最多四个违规路径的元数据，不读取或回报任务命令。

证据始终注明 `scope=on-disk-debian-cron-system-tables loaded_state=unverified`，附精确产品版本、固定对象模式、条目总数、检查总数、违规总数、参考及有限违规样例。完整模式/UID/GID偏差为 fail，无法完整确认则 error；一个聚合检查项不会因为某些文件安全而掩盖其他文件的不确定性。异常仍阻止模板发布，完整 fail 允许管理员评估候选，不代表主机合规。没有自动 chmod/chown、修复、服务操作或生产任务执行。

这项观察不证明 scheduler 已加载/运行、任务语法/时间/用户/命令正确、任务成功执行、用户 spool、run-parts 的 hourly/daily/weekly/monthly 目录、完整父目录授权、轮换后属性或日志生效/交付。旧0048 cron日志和0054扫描任务契约仍未支持；候选中明确列为未支持。

## 验证

本地串行验证覆盖定义边界、空目录、点文件和备份名、严格模式、16 MiB文件只查元数据、权限偏差、缺失/链接/FIFO/硬链接/子目录、名字及条目上限、共享超时、文件/目录/软件包变化。相关后端检查精确快照、错误阻止发布、完整失败与新版本重新测试；SQLite/PostgreSQL REST覆盖同一协议，桌面/手机显示具体备份文件权限偏差和有限范围证据。

两架构 CI 的 [cron-native.sh](../deploy/tests/cron-native.sh) 使用专用 Ubuntu24 一次性容器：网络关闭、仓库只读、128 MiB内存、192 MiB含swap、1 CPU、64 PID，移除默认 capabilities，仅允许私有文件chown和cron子进程setuid/setgid。安装精确cron包时禁止自动启动。测试替换容器私有PAM入口为permit，清空私有系统/用户任务区，安装受控 `@reboot touch` 标记任务后实际运行 `/usr/sbin/cron -f -L 15`，每实例最多观察3秒并清理整个进程组。测试必须位于带固定标记的专用容器，不修改宿主 cron 或用户服务。

原生验证覆盖安全文件、组可写、错误UID、root执行位、root符号链接、点号备份名、访问ACL、目录默认ACL，另做真实GID和硬链接边界。通过受控主任务标记确认实例处理已开始，再核对被测条目是否在有界窗口执行；不能把负例的窗口内未执行扩大成长期保证。原生行为与候选更窄参考分别记录，ACL检查必须执行而不能静默跳过。这些容器任务仅验证文件选择与元数据边界，不认证实际业务任务或 cron 日志。

旧60项目前28项有有限范围实现，32项未实现；通用审核候选v10仍只有8项和52项自身未包含，其中20项转到独立产品候选。旧任务快照、既有包版本和V001–V007迁移不改写；本候选不自动导入或发布。基线模块整体继续完善，PR保留草稿，不合并或发版。
