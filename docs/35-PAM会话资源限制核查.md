# Ubuntu24 login PAM 会话资源限制参考

独立 [三项候选](../deploy/baseline/packages/pam-limits/linux-baseline.json) 版本1成组处理旧0039、0056、0057：core、文件句柄与用户进程的soft/hard声明。共用一个有限session链和limits配置解析器；每项独立返回pass/fail/error。一项error会阻止整包发布，另外两项的通过不能掩盖它。定义、版本差异和每项任务快照保留完整范围。

产品限定Ubuntu24.04，固定查询`libpam-modules`的`1.5.3-5ubuntu5`及数字更新版本。固定入口`/etc/pam.d/login`，只读session管理组、`/etc/security/limits.conf`和`limits.d`。不会调用生产PAM会话或修改Agent/其他进程的资源限制。安装包版本是产品条件，不能证明磁盘模块与运行实例的完整性。

| 旧编号 | option | 本项目声明参考 |
|---|---|---|
| 0039 | core | 默认与显式root的soft/hard均为0 |
| 0056 | nofile | 默认与显式root的soft/hard均在1024..65536 |
| 0057 | nproc | 默认与显式root的soft/hard均在1..4096 |

这些上下限是本项目可审核的容量参考，不是Ubuntu/PAM给所有业务规定的安全阈值。core以limits配置的KiB为单位，nofile和nproc为计数；管理员需按业务容量选择适用候选。生产核对明确声明及已支持的配置流程，**不据此断言真实登录已调用此链或现存进程已受限**。nproc也不证明UID0或具有豁免能力的主体受到内核进程数强制限制。

```json
{"type":"pam_limits","target":"/etc/pam.d/login","option":"core","operator":"eq","expected":"default_and_explicit_root_soft=0,hard=0","timeout_ms":5000}
```

其他两项使用相同type/target，expected分别是`default_and_explicit_root_soft=1024..65536,hard=1024..65536`和`default_and_explicit_root_soft=1..4096,hard=1..4096`。两端拒绝其他入口、资源、运算符、弱化参考和额外字段，包括值为null的额外字段。Windows明确返回执行异常。无自动修复。

## 有限session链

复用有界PAM include展开：支持`@include`及`session include`，仅在固定PAM目录内，拒绝循环、路径逃逸和substack。只接受无参数的`required pam_limits.so`、`required pam_unix.so`和`required pam_permit.so`；limits必须恰好出现一次。允许同架构已知固定模块路径，不接受任意模块路径。其他管理组不在此检查范围。

已知链中缺少limits为fail；重复limits、optional/sufficient、自定义跳转、其他模块或参数为error。尤其不猜测`conf=`、`set_all`和未知模块是否改变限制。真实Ubuntu默认login通常含更多session模块，未支持拓扑会返回error；不能在生产直接删改现有认证链以迎合此候选。需要该拓扑时应扩展解释器和对应原生证据。

## limits解释与读取

主文件先读，随后按C字节顺序读取全部非隐藏`*.conf`。备份名称只要以`.conf`结尾也进入读取；其他扩展名和隐藏文件按原生glob规则排除。每个soft/hard分别使用同域最后一个声明，`-`同时设置二者。仅支持`*`默认和字面`root`两种域，以及core/nofile/nproc三种资源；显式root要求是本参考自身的要求，不把缺少root声明推断为root实际无限。

Ubuntu的显式root补丁要求root字面声明，默认/组声明不用于root；本候选保留默认与显式root两套数值。输出原始声明和归一化soft：如soft=12000、hard=8192，原生PAM会把soft降为8192。缺少任一声明仍是unspecified，不读取或猜测应用继承的rlimit。完整非负整数最大2147483647，允许前导零并归一化。`-1`、`unlimited`、`infinity`不满足本参考的显式有限要求；nofile的无限值在原生模块中尝试转换为nr_open，本检查不会将它猜成一个有限声明。Ubuntu的EPERM补丁可能在提高hard上限失败时仍返回PAM成功，保留继承值；因此required模块存在或返回成功均不证明限制已经应用。

命名用户、组、UID/GID范围、`<domain> -`豁免、其他资源、未知或不完整语法为error；错误不回显未知值或配置原文。若其他资源或账户策略存在，不表示它们不合规，而是超出此候选的解释范围。

每文件最多64KiB/1024行，limits物理行短于1023字节；include深度8、展开模块64、目录条目128、drop-in64、总读取1MiB/96个文件目录。配置入口、目录及选中文件拒绝符号链接/特殊文件；配置须root:root、不能组/其他可写或有硬链接。保持描述符，检查结束复核inode、时间、大小、路径与目录成员变化；缺少limits.d可接受但结束复核仍缺少。单一截止时间覆盖包查询及所有读取；串行多文件观测不是原子快照。

证据始终明确`invocation_state=unverified`、`existing_process_state=unverified`、`core_delivery_state=unverified`与`nproc_privileged_enforcement_state=unverified`。core=0的rlimit声明也不证明内核core管道、systemd-coredump或其他崩溃处理机制被关闭。

## 原生与流程验证

专用一次性Ubuntu24 PAM镜像共享已有口令/登录锁定验证基础设施。新增C探针在独立子进程打开实际login PAM session，读取三种getrlimit；普通用户降权后检查有界文件打开和fork被拒绝，并对照root的nproc例外。仅在有专用标记、root且确认容器的环境写入隔离/etc；仓库只读挂载、无宿主/etc/数据卷、无网络，容器结束移除。探针不索取口令、不输出账户凭据或哈希，不制造崩溃/core文件。

原生对照包括三项普通/root会话、有序drop-in、root优先级、soft归一化、三种独立不满足、无限值及nofile提高上限被拒绝但PAM成功、提前sufficient跳过limits、conf选项跳过drop-in，以及实际普通文件/fork拒绝和root例外。原生结果须绑定当前提交的amd64/arm64 CI。SQLite/PostgreSQL与浏览器完整报告是明确标注的协议夹具；混合2通过/1失败和2通过/1异常分别保留，后者阻断发布，版本改变一项仍需整包新证据。

解释依据固定Linux-PAM1.5.3 [模块源码](https://github.com/linux-pam/linux-pam/blob/v1.5.3/modules/pam_limits/pam_limits.c)、[limits手册源文件](https://github.com/linux-pam/linux-pam/blob/v1.5.3/modules/pam_limits/limits.conf.5.xml)、[模块手册源文件](https://github.com/linux-pam/linux-pam/blob/v1.5.3/modules/pam_limits/pam_limits.8.xml)和[控制流程](https://github.com/linux-pam/linux-pam/blob/v1.5.3/libpam/pam_dispatch.c)，以及[Ubuntu24 limits手册](https://manpages.ubuntu.com/manpages/noble/man5/limits.conf.5.html)。另核对官方Ubuntu [1.5.3-5ubuntu5.7源码补丁包](https://archive.ubuntu.com/ubuntu/pool/main/p/pam/pam_1.5.3-5ubuntu5.7.debian.tar.xz)中的显式root、初始化、soft默认及EPERM补丁和构建选项；该包未启用vendor配置目录。来源文件经Git blob和SHA256核对，不声称tag/软件包签名认证。

旧60项现41项具有限定范围实现、19项未支持。通用review版本18仍8项/52排除，其中33项指向独立产品候选，不扩大通用包覆盖。基线模块整体仍未完成，继续按[模块计划](19-模块完善计划.md)在当前分支推进，PR保持草稿。
