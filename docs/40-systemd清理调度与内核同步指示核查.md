# systemd 清理调度与内核同步指示核查

独立[systemd-maintenance/linux-baseline.json](../deploy/baseline/packages/systemd-maintenance/linux-baseline.json)版本1成组提供旧0046/0055。限定Ubuntu24 amd64/arm64、本地已加载systemd255系统管理器及可查询的systemctl/busctl。两项分别观察systemd-tmpfiles-clean.timer/service和systemd-timesyncd.service，不把服务活动推断为实际删除或已同步到可信来源。

| 原规则 | 当前完整参考 |
|---|---|
| 0046 | timer loaded/active/waiting、正确service目标、有限正单调调度值；service loaded/oneshot、inactive/dead、RemainAfterExit=no；主命令为systemd-tmpfiles及独立`--clean`参数 |
| 0055 | timesyncd loaded/active/running、有效MainPID、Type=notify、正确主命令；adjtimex(modes=0)返回0..4且无STA_UNSYNC/STA_CLOCKERR |

清理主命令固定`/usr/bin/systemd-tmpfiles`，两个argv：程序名或绝对路径、`--clean`。时间主命令固定`/usr/lib/systemd/systemd-timesyncd`，只允许一个程序名或绝对路径argv。两项均不得忽略主命令错误。零个或多个ExecStart、其他完整命令/参数、服务与定时器完整已知偏差为fail。systemctl的ExecStart文本会丢失参数边界，因此生产仅用其状态属性；命令参数通过busctl指定ExecStart属性的带类型JSON读取，不使用拼接文字作断言。定时器NextElapseUSecMonotonic也直接读取uint64，0和infinity不满足参考，避免猜测人类可读时长。

生产只查询固定本地systemd管理器和固定单元，清理继承的D-Bus地址、SYSTEMD_*环境及远程路径开关。systemctl查询可让未保留的单元被管理器重新加载，此时观察新加载状态；不启动、停止、重载或触发服务。规范Id必须匹配，别名、缺失/加载失败、NeedDaemonReload不为no、未知/切换状态、属性/签名/类型错误保持error。64KiB输出、最多8 ExecStart、32 argv，单路径/参数1024字节；只请求选中属性，不请求GetAll、环境或凭据，不回传其他命令原文。结构化结果拒绝重复/额外字段、null、非规范整数、溢出与尾部数据。异常保持error，不采用成功默认值。

两次完整查询与时钟读取共用100至30000ms截止时间，默认5000ms；显式0/null被两端拒绝。复核管理器、单元、主命令完整结构/摘要、定时器调度及内核状态/位，变化为error。误差估计随时间自然变化，仅分别保留两次证据，不作为稳定性条件或准确性证明。观察非原子，短暂变化/ABA变化仍可能未捕获。一项error阻止维护两项整批发布；新版本改变任何一项仍需两项完整新测试，旧任务快照保留。两端拒绝弱比较、自选单元/远程管理器、命令及null扩展；无自动修复。

adjtimex始终使用全零输入的modes=0，不设置时钟、频率、偏移或状态，不请求CAP_SYS_TIME。0为TIME_OK，1..4是已知闰秒状态，5/TIME_ERROR是已观察到的不满足；syscall失败、未知状态/位或估计格式为error。同步指示是内核维护的状态，不能证明timesyncd是当前实际提供者、当前来源可信、NTP/NTS认证、偏移准确、没有其他调整者或持续同步。即使内核指示通过，选定timesyncd不运行或主命令不符仍fail；其他时间产品须使用独立候选。

清理项不解释tmpfiles配置、路径/年龄、凭据输入、条件、其他执行阶段、文件系统命名空间和访问能力，不证明过去/未来实际删除、调度周期上限或启动持久性。当前等待状态及正调度值只说明选中维护入口的当前参考。两项明确标注cleanup_configuration/delivery、ntp_provider、peer_identity、offset_accuracy、execution_environment和persistence为unverified及snapshot为non_atomic；组件完整性由管理员确认。管理员按[模板流程](18-基线模板审核与系统适配.md)独立审核并选择相应产品测试。

原生CI在双Ubuntu24架构的可删除GitHub-hosted runner串行执行。root、显式双开关及runner身份缺一拒绝修改。仅创建唯一运行时timer/service，清理timer设六小时之后且在120秒测试预算内停止/删除；真实清理命令只作为已加载声明，绝不触发宿主清理。唯一通知型sleep服务不能凭名称伪装timesyncd；不会启动/停止真实时间服务或修改宿主时钟。仅测试阶段加载/查询/重载/移除唯一夹具，恢复manager后对真实固定选择器只读观察并保留item ID。

十三次真实状态对照覆盖缺失、未活动、等待、恶意继承环境、错误目标、RemainAfterExit、其他主命令、与正常文本相同的单argv伪装、恢复、待重载、重载、停止及运行的错误时间程序。只读C ABI探针独立读取内核状态，始终modes=0；实际时钟观察不要求主机通过参考。强制类型/argv/整数/状态、变化及共同截止时间不跳过。运行服务但内核不同步的完整正/负组合由标注的协议夹具验证，不修改真实时钟构造同步状态。REST和页面同样是协议夹具，不能替代原生观察或实际删除/准确性证明。每批验收绑定对应提交CI。

语义来源：[Ubuntu24 busctl](https://manpages.ubuntu.com/manpages/noble/en/man1/busctl.1.html)、[timer](https://manpages.ubuntu.com/manpages/noble/en/man5/systemd.timer.5.html)、[adjtimex](https://manpages.ubuntu.com/manpages/noble/en/man2/adjtimex.2.html)，及systemd255[清理service](https://github.com/systemd/systemd/blob/v255/units/systemd-tmpfiles-clean.service)、[清理timer](https://github.com/systemd/systemd/blob/v255/units/systemd-tmpfiles-clean.timer)、[busctl类型JSON转换](https://github.com/systemd/systemd/blob/v255/src/busctl/busctl.c)。这是项目有限参考，不宣称完整等保、CIS或STIG合规。

旧60项现50项具有限定范围实现、10项未支持；通用review版本21仍8项/52排除，其中42项指向独立产品候选。基线模块继续当前分支，PR保持草稿。
