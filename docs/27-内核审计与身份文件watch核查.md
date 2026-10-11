# Ubuntu24.04 内核审计与身份文件 watch 核查

独立候选 [audit/linux-baseline.json](../deploy/baseline/packages/audit/linux-baseline.json) 版本1覆盖旧0021和0025的限定参考。0021更名为内核审计当前启用状态，0025限定四个本地身份文件当前加载的watch规则。产品范围是Ubuntu24.04 Linux audit UAPI、初始用户/PID命名空间和CAP_AUDIT_CONTROL；管理员需确认实际规则形式。系统版本匹配只决定选模，两端需升级，旧Agent遇到新类型为error。按[模板流程](18-基线模板审核与系统适配.md)审核、选主机测试并评估证据后发布。

| 检查项 | 固定参考 | 明确不满足 |
|---|---|---|
| enabled | 内核AUDIT_GET的enabled为1或2 | enabled=0 |
| identity_watches | enabled为1或2；四个文件各有always/exit/all的w+a覆盖 | 无规则、某文件缺少w/a，或内核禁用 |

`linux_audit`仅接受target=kernel、operator=eq、两个固定option和对应expected，不接受命令、任意路径或其他产品字段，包括额外null字段。生产Agent通过NETLINK_AUDIT只发送AUDIT_GET和AUDIT_LIST_RULES；不调用auditctl、不设置审计状态、不注册守护进程、不订阅事件或修改规则，不读取身份文件内容。即使客户端未安装也能查询内核；缺CAP或处于容器命名空间时返回error，不把UID 0或可执行文件存在当成查询能力。

启用项只观察当前内核状态，enabled=2表示锁定，仍满足本项的启用参考。证据中的daemon_pid、lost、backlog是附带观测，不作为此项合规条件；pid=0或已有丢失计数不能被本项的pass掩盖为“审计完整”。守护进程、事件生成、交付、日志完整性、持久配置和进程审计上下文都需要另行验证。

身份项固定为/etc/passwd、/etc/shadow、/etc/group、/etc/gshadow。逐段O_PATH/O_NOFOLLOW打开普通文件，不接受路径组件链接或多硬链接，并持有描述符；检查结束重新核对文件和父目录身份。读取两次内核规则列表和前后启用状态；规则内容、顺序、启用状态或路径变化时error并提示重试。这是有界重复观测，不是连续监控或整个系统的原子快照。

已实现形式严格限定AUDIT_ALWAYS、AUDIT_FILTER_EXIT、无arch/UID/syscall等过滤，全部实际syscall掩码位，以及相等匹配的WATCH、PERM和可选KEY。内核展开并清除最后16个保留syscall-class位，解析器核对该规范布局。每个固定路径的权限掩码至少覆盖write和attribute，可合并同一路径的已支持正向规则；额外r/x不影响本参考。KEY仅结构校验，不回显。读取内核原始动作避免auditctl文本格式丢失动作造成误报。

任何never、task、exclude、目录watch、arch/UID条件、特定syscall或其他未支持形式，即使看似无关，都使全局覆盖无法确认，保持error；不尝试从未知形式推导合规或将其当成缺失。规则缺少覆盖只有在完整取得且全部形式已支持时才为fail。该保守范围可能拒绝等价的其他规则形式，需要另一个经过实现和验证的候选版本，不能通过修改本类型的字段绕过。

每次检查共享100–30000毫秒的截止时间，默认5000；非阻塞socket加Poll限制收发时间。只接受内核单播来源、对应序号和完整Netlink消息，规则列表需收到完成标志。截断、丢包、未知状态布局、意外消息/标志、超过256条规则或512KiB响应均error，阻止发布。证据只包含限定状态、规则数和四个路径的w/a覆盖，不输出原始规则、账户或凭据。

参考含义来自[Ubuntu24 auditctl手册](https://manpages.ubuntu.com/manpages/noble/man8/auditctl.8.html)、[Linux 6.8 audit UAPI](https://github.com/torvalds/linux/blob/v6.8/include/uapi/linux/audit.h)、[内核状态处理](https://github.com/torvalds/linux/blob/v6.8/kernel/audit.c)和[规则转换与列表](https://github.com/torvalds/linux/blob/v6.8/kernel/auditfilter.c)。audit-userspace 3.1.2的[watch文本格式实现](https://github.com/linux-audit/audit-userspace/blob/v3.1.2/src/auditctl-listing.c)在判断watch时未核对action，故不把该文本作为动作证据。

```bash
python3 -B deploy/baseline/build-package.py \
  --definitions deploy/baseline/audit-definitions.json --platform linux \
  --output-dir .tmp/audit-candidate
```

测试覆盖禁用/启用/锁定、守护进程缺失仍不扩大启用结论、全部身份路径、缺w/a、分离掩码、never动作、未知形式、异常字符串、协议截断/外来消息、截止时间和字段越界。双架构Linux CI必须在一次性GitHub托管Ubuntu24 runner查询真实内核，再只为私有临时文件增加/删除watch：完整、缺项、缺属性位和never返回动作均由真实内核往返验证。私有规则覆盖断言明确假设enabled=1，不改变机器的enabled状态，不冒充真实身份文件合规。真实两项另外只读观测，允许runner不满足参考。测试不清空或修改已有规则，结束核对原规则和enabled原样保留。

SQLite/PostgreSQL REST和生产网页使用明确协议夹具验证精确下发与快照、error阻止发布、完整pass/fail结果、不可复用旧版本测试、桌面/手机证据。网页夹具的enabled=1和gshadow缺失属于协议样本，不能代替真实内核测试。没有自动修复，也不宣称完整等保、CIS或STIG认证。最终验收使用本批源码提交的CI。
