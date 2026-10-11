# AppArmor当前根策略模式核查

旧BL-LINUX-0040的SELinux/AppArmor shell OR链无法区分查询失败与禁用。本批独立Ubuntu24候选仅实现AppArmor当前根视图的启用及模式参考，固定`apparmor_runtime/current-kernel/eq`与完整`enabled=Y,lsm=apparmor,global_mode=enforce,root_unstacked_view,profiles=nonempty/all_enforce`。服务端和Agent拒绝其他路径、命名空间、命令、弱比较及额外字段（含null）。候选[定义](../deploy/baseline/apparmor-definitions.json)与[不可变包v1](../deploy/baseline/packages/apparmor/linux-baseline.json)限定Ubuntu24.04 amd64/arm64，管理员按实际Agent版本和主机条件审核测试后发布。

生产只读固定内核接口：`/sys/module/apparmor/parameters/enabled`及`mode`，`/sys/kernel/security/lsm`，以及`/sys/kernel/security/apparmor`下的`.ns_level/.stacked/.ns_stacked/profiles`。从`/sys`逐级openat，禁止符号链接与阻塞特殊文件，校验目录/普通接口类型、数值UID/GID 0、非组/其他可写，以及sysfs/securityfs文件系统身份；保留FD并在读取后核对路径/FD身份及元数据。不能用普通磁盘伪造内核输入。AppArmor的policy魔术链接不参与观测；生产不执行aa-status、加载策略或访问用户指定路径。

先核对完整Y/N启用参数及有限LSM列表。securityfs的LSM接口返回无末尾换行的逗号分隔名称，必须由有界读取到达EOF；名称与重复校验不接受换行或空白。enabled=N且LSM不含AppArmor，或enabled=Y但LSM不含AppArmor，完整稳定时为不满足启用参考，mode/profiles明确not_observed；不会虚构空策略或enforce值。N但LSM含AppArmor视为不一致error。接口不存在、securityfs未挂载、读取拒绝均error，即使该主机可能已禁用，也不能借查询失败得出确定结论。

启用且AppArmor存在时，要求`.ns_level=0`、`.stacked=no`和`.ns_stacked=no`，并完整读取全局模式与profiles。只有当前有限根非叠加视图受支持；嵌套、叠加、子命名空间行、别名式或无法解释的值保持error。策略列表使用有限ASCII根名称与四种模式：enforce、complain、kill、unconfined。支持名称内空格与`//`子hat，拒绝可见控制字节、转义、括号、冒号、`&`、重复名称、未知模式或不完整行。清单是内核文本形式的当前观测，不是策略内容解析器；不能证明完整主机范围或名称之外的策略身份。

通过需全局mode=enforce、清单非空且每项enforce。完整空清单、全局或任一策略处于complain/kill/unconfined时为fail。kill仍不匹配本项目精确enforce参考，不意味着kill更弱；Ubuntu默认unconfined应用策略也可能使此严格参考fail，不据此作全局安全结论。未知模式（包括未实现的prompt）、不可解释或超限输入为error，不当作已知不合规或成功。任何error都阻止候选发布。

资源限制：策略清单256KiB、最多1024行、每行1024字节，LSM最多1024字节/32项，其他参数2..32字节；两次完整观测共享一个100..30000ms截止时间（缺省5000，显式0/null拒绝）。Agent锁定观测线程，读取前后与两次快照之间检查截止时间；同步内核文件调用自身不具备用户态抢占保证。每次重新打开固定接口并复核身份，两次值/路径身份有变化为error。观测非原子，不能排除变化后恢复或内核读调用期间的中间状态。

报告仅含启用/视图/全局模式、四类策略数量和原清单SHA256；不回显策略名称、原接口内容或读取错误原文。成功、fail和error均保留`policy_content_state/application_attachment_state/effective_access_state/unloaded_profiles_state/other_security_mechanisms_state/host_policy_coverage_state/persistence_state=unverified`以及`snapshot_state=non_atomic`。实际规则内容、应用绑定、真实访问拒绝、未加载磁盘策略、SELinux等其他机制、完整主机覆盖和重启持久均未验证，无自动修复。

逻辑验证涵盖严格定义/平台、四种完整模式、禁用与LSM缺失/不一致、空策略、未知/重复/截断/命名空间/限额、名称脱敏、两次变化与截止时间。Linux读取夹具验证缺失、链接目录/文件、FIFO、额外可写、硬链接、普通文件系统伪造、路径/目录替换及元数据变化；普通目录测试入口不能由CheckSpec选择。

`bash deploy/tests/apparmor-native.sh`仅允许一次性GitHub-hosted Ubuntu24 runner且需root、显式两开关与已编译原生测试。双架构各验证7次当前真实内核观察及独立aa-status JSON完整模式清单对照：初始、唯一无attachment策略enforce→complain→kill→unconfined→enforce，以及移除。只替换唯一命名策略，不附着应用、不修改既有策略或全局模式；成功与失败均清理唯一策略及临时文件。缺少内核接口或受支持视图必须失败，不能用普通Go测试的skip充当原生验收；五组定义/状态/限额/变化/受保护读取边界在原生步骤内强制执行。初始主机已有非enforce策略时整体参考可合理fail；原生预期由全部真实模式决定，而非假定runner符合参考。

后端真实SQLite测试覆盖完整定义下发、任务快照、错误阻止发布、完整fail允许发布、新不可变timeout版本需新证据，以及Windows/Rocky与弱化定义拒绝。REST在SQLite/PostgreSQL分别保存error/pass/完整fail协议夹具；浏览器回放捕获API并使用生产构建，检查完整JSON、模式差异、七个未验证边界及viewer桌面/手机行为。协议夹具不证明真实内核或应用访问控制；最终验收须绑定本批最新提交的双架构、Windows和schema CI。

语义依据Linux v6.8的[AppArmor securityfs及命名空间观测](https://github.com/torvalds/linux/blob/v6.8/security/apparmor/apparmorfs.c)、[全局mode/enabled参数](https://github.com/torvalds/linux/blob/v6.8/security/apparmor/lsm.c)、[label模式/名称输出](https://github.com/torvalds/linux/blob/v6.8/security/apparmor/label.c)、[securityfs LSM的EOF输出](https://github.com/torvalds/linux/blob/v6.8/security/inode.c)，及Ubuntu24的[aa-status手册](https://manpages.ubuntu.com/manpages/noble/man8/aa-status.8.html)。所引用源码用于明确接口含义，原生测试验证当前runner实际ABI；不把上游文档或本项目阈值当作发行版认证。
