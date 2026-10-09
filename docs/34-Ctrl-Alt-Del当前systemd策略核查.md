# Ctrl-Alt-Del 当前 systemd 策略核查

旧 `BL-LINUX-0060` 收窄为 Ubuntu 24.04 已加载 systemd 255 本地系统管理器的当前目标屏蔽和连续按键动作。独立 [定义](../deploy/baseline/ctrl-alt-del-definitions.json) 与 [候选包](../deploy/baseline/packages/ctrl-alt-del/linux-baseline.json) 要求管理员确认系统管理器可信和产品适用性；查询版本不证明二进制或总线未被修改。通用观测包仍排除此项，旧迁移和历史任务保留，无自动修复。

## 两条当前管理器路径

systemd 255 普通 Ctrl-Alt-Del 信号尝试启动 `ctrl-alt-del.target`；连续按键超过限额时可以直接执行 `CtrlAltDelBurstAction`。因此单独 `disabled`、单独屏蔽目标或只检查配置文件文字都不足以满足本参考。[固定版本信号处理源码](https://github.com/systemd/systemd/blob/v255/src/core/manager.c)、[管理器动作配置](https://github.com/systemd/systemd/blob/v255/man/systemd-system.conf.xml) 与 [D-Bus 属性](https://github.com/systemd/systemd/blob/v255/src/core/dbus-manager.c)。

新增 `systemd_ctrl_alt_del` 固定 `ctrl-alt-del.target`、`eq` 与完整 `masked/inactive/dead,burst_action=none`。两端拒绝其他目标、路径、远端/用户管理器、弱化参考和额外字段（包括 null），Windows 明确 error。

| 观察对象 | 固定属性及参考 |
|---|---|
| 系统管理器 | Version 为有限 systemd255 版本形式；SystemState 为 running/degraded/maintenance；CtrlAltDelBurstAction 为 none |
| 指定目标 | Names 包含查询名及规范 Id；通过时 Id 恰为 ctrl-alt-del.target，LoadState=masked、ActiveState=inactive、SubState=dead |
| 目标文件状态 | UnitFileState=masked 或 masked-runtime，NeedDaemonReload=no |

`masked-runtime` 仅表示当前状态，不证明重启后仍屏蔽。加载别名（例如默认指向 reboot.target）、disabled/static/其他受支持未屏蔽状态、活动目标或四种支持的非 none 连续按键动作为 fail。目标缺失、加载异常、属性缺失/重复/污染、未知身份/状态、待重载、管理器版本未支持或切换状态为 error。缺失属性不填默认值，不把总线失败当作 none。

## 执行和证据边界

使用固定 `/usr/bin/systemctl --system --no-pager show --all --property=...`，无 shell。清除继承的 D-Bus 地址及 SYSTEMD_* 重定向环境。先查管理器、再查目标，重复一次；四次串行查询共用检查截止时间和既有有界命令输出/进程终止机制。对规范化后的完整观察比较，期间变化保持 error；这不是原子快照，也不能排除两次查询之间发生并恢复的变化。

证据明确保存 `scope=loaded-systemd-ctrl-alt-del`，并标记 `persistence_state`、`keyboard_path_state`、`trigger_test_state` 全部 unverified。pass 只表示所查询管理器当前已加载的两项设置，不证明所有物理键盘、内核 Ctrl-Alt-Del 模式、桌面会话/输入代理、固件或其他关机入口的行为，也不证明重启后策略。生产不读写配置文件、不屏蔽/启停/重载目标或管理器、不发信号、不模拟按键、不测试重启。

## 验证

Go 故障注入覆盖目标已屏蔽但 burst=reboot-force、运行中再屏蔽、disabled 与 loaded alias、待重载、未知版本/属性、查询退出失败、共同截止时间和两次状态变化。后端覆盖严格导入、系统范围、快照及完整执行异常阻止发布；定义版本更新必须取得新测试证据。SQLite/PostgreSQL REST 和生产前端报告使用明确协议夹具，桌面/手机均展示 masked 但 burst 非 none 的不合规实测值与未验证边界。

原生测试只允许临时 GitHub-hosted Ubuntu24 runner：使用唯一无依赖普通 target 和唯一 `/run/systemd/system.conf.d` 片段，验证真实管理器加载 none 及四种动作属性、runtime mask、活动/disabled 状态及未重载变化。测试只启动/停止唯一无关 target，清理片段后重载并核对原 burst 值；真实 `ctrl-alt-del.target` 仅作只读查询和 Run 调度核对。测试从不启动真实 Ctrl-Alt-Del/重启/关机目标，从不发送 SIGINT 或按键事件。原生查询证明属性观察与分类，不提供实际重启触发证据。

源码语义依据固定 systemd v255 的 manager.c、main.c、dbus-manager.c、dbus-unit.c、emergency-action.c 及手册；源码摘要用于记录来源，不作为 Ubuntu 包或标签签名认证。
