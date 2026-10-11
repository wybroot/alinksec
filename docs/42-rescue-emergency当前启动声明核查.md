# rescue/emergency 当前启动声明核查

独立[systemd-rescue/linux-baseline.json](../deploy/baseline/packages/systemd-rescue/linux-baseline.json)版本1将旧0059收窄为Ubuntu24 amd64/arm64、本地已加载systemd255的联合启动参考。生产只读，不启动维护模式、不触发登录、不读取口令字段，无自动修复。通过仅表示以下完整声明匹配，实际维护模式认证仍未验证。

| 输入 | 项目参考 |
|---|---|
| 两个单元 | `rescue.service`和`emergency.service`均loaded、Id精确、Type=idle、无待重载、已知稳定状态 |
| 主命令 | 带类型`ExecStartEx`恰好一条`/usr/lib/systemd/systemd-sulogin-shell`，argv0为该路径或basename，第二参数精确rescue/emergency；无额外参数 |
| 命令标记 | 默认`ignore-failure`或无标记；已知privileged/no-setuid/ambient/no-env-expand偏离此参考 |
| force输入 | 管理器Environment、各单元Environment及固定`/proc/cmdline`的`SYSTEMD_SULOGIN_FORCE`均缺省或明确false |

systemd255的sulogin-shell先查询环境布尔声明，再查询同名内核参数。启用force后可向sulogin传递`--force`，root锁定时存在无口令入口，故只匹配主命令不足。这里核对全部有限输入声明，不计算管理器true被单元false覆盖后的最终进程环境；该情况仍为已知偏差。其他环境变量不作有效性判断，环境数组只在内存中解析，报告不输出命令、环境或内核参数原文，包括查询/解析失败。

环境只接受有界`NAME=value`数组，名称规范且无重复；force布尔支持大小写不敏感的0/no/false/off或1/yes/true/on，空值/其他文本error。环境文件、PassEnvironment、UnsetEnvironment非空以及PAMName、RootDirectory、RootImage链非空保持error，不读取环境文件或替代根。内核参数只接受有限ASCII空白分词，短横线与下划线按systemd键比较语义等价；bare force为true。重复force、引号、反斜杠、`--`、initrd force声明或未知布尔保持error，不能靠字符串包含判定。

带类型D-Bus ABI`a(sasasttttuii)`保留路径、argv边界、完整标记和运行整数；先完整验证全部命令结构，即使多条已偏离参考也不能跳过后续未知内容。未知签名、null、重复JSON字段、尾随内容、非规范整数或超限error。固定systemctl/busctl参数与精简环境不继承DBUS_SYSTEM_BUS_ADDRESS、SYSTEMD_UNIT_PATH等连接覆盖；只查明确属性，不使用GetAll、原始磁盘grep、Shell、远程管理器或用户总线。

缺失、别名、加载异常、切换状态、未知属性/版本、待重载、查询错误、读取错误、超限、超时及变化保持error。完整已知命令/模式/服务类型/标记/force偏差或masked为fail。全部输入匹配时pass；fail可作为完整测试证据发布候选，error阻断发布。新版本或超时定义变化需fresh完整测试，旧任务快照保留，按[审核流程](18-基线模板审核与系统适配.md)选择适用主机。

两次串行完整查询共用100至30000ms deadline，默认5000ms，显式0/null拒绝；比较管理器、单元标量、完整命令摘要及环境/启动参数字节，变化为error。每次命令查询64KiB、主命令最多8项、每argv最多32项/1024字节、每环境数组128项/字符串4096字节、启动参数16KiB/1024词。输出只有固定范围、版本/稳定状态和匹配/force状态，最终报告遵守2048字节上限。观察非原子，短暂/ABA变化不保证捕获。

报告明确保留`authentication_state`、`root_account_state`、`executable_integrity_state`、`auxiliary_commands_state`、`execution_namespace_state`、`boot_paths_state`、`persistence_state`为unverified，以及`snapshot_state=non_atomic`。主命令不能证明可执行文件、sulogin实现、root口令状态、辅助执行阶段、条件/依赖/其他命名空间与启动路径、重启后持久或实际认证。管理员需独立确认可信组件与恢复需求后在主机完成实际认证测试；本候选不认证完整等保/CIS/STIG或所有单用户入口。

双架构原生CI通过[systemd-native.sh](../deploy/tests/systemd-native.sh)执行，仅root、双开关及GitHub hosted Ubuntu24允许创建唯一`/run/systemd/system`测试单元并清理/daemon-reload；维护服务从不start，维护入口激活与口令读取数为0。待重载场景仅启用6小时后触发的唯一临时timer，保持未启动服务的loaded对象，避免systemd回收后查询直接加载新文件；timer在120秒测试预算内停止、移除。原生对照覆盖缺失、两个完整typed命令、客户端环境覆盖、unit force true/false、模式/命令/argv伪装/扩展标记、环境文件与传递/移除链、待重载及恢复，并与systemctl另一表示独立对照。管理器/内核force、未知/重复/限额/变化/截止时间/泄漏测试作为强制逻辑边界，不修改管理器force、内核启动参数、root口令或实际认证链。真实固定选择器只读观察、保留item ID。后端及SQLite/PostgreSQL REST验证审核/拒绝系统/下发定义/快照/error阻断/fail可发布/fresh版本；生产网页用捕获API响应展示完整参考与未验证认证边界、viewer和桌面/手机。完整报告与页面为协议夹具，不能扩展为实际维护认证证据。验收需绑定此批最终提交的完整CI。

依据：[systemd255 rescue单元](https://github.com/systemd/systemd/blob/v255/units/rescue.service.in)、[emergency单元](https://github.com/systemd/systemd/blob/v255/units/emergency.service.in)、[sulogin-shell实现](https://github.com/systemd/systemd/blob/v255/src/sulogin-shell/sulogin-shell.c)、[D-Bus service ABI](https://github.com/systemd/systemd/blob/v255/src/core/dbus-service.c)、[内核参数解析](https://github.com/systemd/systemd/blob/v255/src/basic/proc-cmdline.c)。这些来源用于界定观察语义，阈值和有限链是项目参考。

旧60项现53项具有限定范围实现、7项未支持；通用review版本23仍8项/52排除，其中45项指向独立产品候选。基线继续当前分支，PR保持草稿。
