# Ubuntu 24.04 systemd 服务状态核查

独立候选包 [systemd/linux-baseline.json](../deploy/baseline/packages/systemd/linux-baseline.json) 版本 1 对旧 `BL-LINUX-0022`、`BL-LINUX-0024` 提供明确范围的状态观察。适用范围为 Ubuntu 24.04、systemd 255 的本地系统管理器，以及可查询的 `auditd.service`、`rsyslog.service` 单元。其他日志产品、非 systemd 系统、用户管理器和远程管理器不在范围内；管理员应先确认本机产品选择，再按 [模板流程](18-基线模板审核与系统适配.md) 导入、审核、选主机测试和发布。两端需升级，旧 Agent 不支持新类型时保持执行异常。

`systemd_service` 的目标只允许这两个服务，`operator` 固定 `eq`，`expected` 固定 `loaded/active/running`。定义不能带命令、配置路径、总线地址或其他产品字段。生产 Agent 使用绝对路径、固定参数和隔离的客户端环境执行：

```text
/usr/bin/systemctl --system --no-pager show --all --property=Id,LoadState,ActiveState,SubState,MainPID -- auditd.service
```

检查保留本地系统管理器、目标单元、实际 Id、加载/运行状态与 MainPID。属性必须完整、唯一、格式有效，Id 必须为请求的单元；不隐式把其他单元的别名当成该产品。命令有时间、输出和进程组上限；退出失败不会被默认状态或成功输出覆盖，继承的 D-Bus 地址和 SYSTEMD 客户端开关不能将查询重定向到另一管理器。

| 观测 | 结果 |
|---|---|
| loaded、active、running，MainPID 为有效且大于 1 的整数 | pass：当前单元满足运行参考 |
| loaded、inactive/dead 或 failed/failed | fail：当前单元未运行 |
| loaded、active/exited | fail：完成的 oneshot 不满足守护进程运行参考 |
| masked 且可解析的稳定状态 | fail：未满足 loaded 参考；masked 与运行状态相互独立，不能假定已停止 |
| 单元缺失、加载错误、未知或切换状态、别名、属性异常、缺少运行主进程证据 | error：无法完成这次范围内的状态观察 |
| 无 systemd 系统管理器、总线不可达、权限错误、超时、输出超限或非零退出 | error：查询异常，阻止候选发布 |

参考只表示查询时的单元状态与管理器报告的主进程，不能证明进程的实际程序身份、内核审计启用、审计规则、事件捕获、日志写入/投递、开机启用或持续运行。系统状态可能在查询后变化；切换状态应由管理员稍后重试。不读取日志、审计规则或凭据，不启动、停止、重载或修复服务；候选没有自动修复定义。

来源为 systemd 255 的 [systemctl 手册源文件](https://github.com/systemd/systemd/blob/v255/man/systemctl.xml)、[D-Bus 属性说明](https://github.com/systemd/systemd/blob/v255/man/org.freedesktop.systemd1.xml)及 [service 状态实现](https://github.com/systemd/systemd/blob/v255/src/core/service.c)。`LoadState` 与 `ActiveState` 独立，`active` 包含 `exited`，所以不能只比较 is-active 或把 systemctl 失败转成 inactive。auditd 的职责见 [Ubuntu24.04 auditd 手册](https://manpages.ubuntu.com/manpages/noble/man8/auditd.8.html)；rsyslog 服务和独立配置验证见 [上游安装说明](https://docs.rsyslog.com/doc/getting_started/beginner_tutorials/01-installation.html)。本项目的运行参考不是这些上游的完整合规标准。

从固定定义重建候选：

```bash
python3 -B deploy/baseline/build-package.py \
  --definitions deploy/baseline/systemd-definitions.json --platform linux \
  --output-dir .tmp/systemd-candidate
```

验证包括伪成功输出但非零退出、部分/重复属性、无效 PID、别名、状态切换和未知状态。两架构 CI 的 Ubuntu24.04 原生 systemd 检查使用唯一的一次性测试单元，串行验证缺失、inactive、真实 running、停止、active/exited、failed、masked 和无效定义，并验证客户端环境重定向不会污染生产查询。测试只管理自己的单元，结束后删除、清除失败状态并重载管理器；真实 auditd/rsyslog 名称另作只读观测，不要求 runner 满足本参考。不在本机或 PAM 容器中冒充原生 systemd 验证。

SQLite/PostgreSQL REST 和生产网页使用明确协议夹具，覆盖定义快照、错误阻止发布、完整 pass/fail 证据、桌面与手机展示；它们不能冒充主机上的审计事件或日志交付。最终验收须绑定本批提交的完整 CI，不借用上一批成功结果。
