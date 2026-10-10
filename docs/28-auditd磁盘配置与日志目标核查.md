# Ubuntu24.04 auditd 磁盘配置与日志目标核查

独立候选 [auditd/linux-baseline.json](../deploy/baseline/packages/auditd/linux-baseline.json) 版本1提供三项新增参考：固定磁盘配置的本地日志写入声明、keep_logs声明，以及配置所指日志文件的元数据。这些新增项不替代旧0029的sudo使用审计或0048的cron日志策略；旧60项仍有33项未实现。匹配Ubuntu24.04后仍需管理员确认auditd 3.1.2及默认配置入口，按[模板流程](18-基线模板审核与系统适配.md)审核、测试、评估证据后发布。

| option | 参考 | 已观察不满足 |
|---|---|---|
| local_logging | local_events=yes、write_logs=yes、log_format=raw或enriched | no或nolog |
| keep_logs | 本地写入参考；max_log_file至少1MiB；max_log_file_action=keep_logs | 大小0、rotate/ignore/syslog/suspend或写入声明不满足 |
| log_file_metadata | 本地写入参考；普通文件、模式允许位上限0640、UID0、GID等于声明的数值log_group | 已完整观察的模式/ID偏差或写入声明不满足 |

证据始终带`scope=on-disk-auditd-3.1.2`和`loaded_state=unverified`。只观察磁盘，不调用auditd、auditctl、服务控制或NSS，不证明进程使用该入口、已经重新加载、记录捕获/交付、容量、保留天数或外部轮转。默认配置包含命名`log_group=root`的主机可以观察前两项，但第三项保持error：不能把名称或本地group文件当作实际NSS解析结果。需管理员确认数值GID及实际组件条件，不能以默认成功结果绕过异常。

固定`/etc/audit/auditd.conf`需UID0、组和其他用户不可写、无访问ACL的普通单硬链接文件，总读取上限64KiB。每个路径组件以O_PATH/O_NOFOLLOW相对打开；持有描述符读取配置并复核元数据和父路径身份。日志目标来自已支持log_file或3.1.2默认值，仅限`/var/log/`下长度不超过128字节的规范ASCII路径；只以O_PATH查询元数据和访问ACL，绝不读取日志内容。缺失、链接、FIFO、设备、目录、多硬链接、访问ACL、读取异常或检查期间路径/ctime变化为error。繁忙日志的变化可能需要重试；这里不是原子系统快照或持续监控，也不证明父目录完整授权。

每项共享100–30000毫秒截止时间，默认5000。配置语法采用3.1.2标量子集：完整行注释、空行、独立空格分隔`key = value`、大小写不敏感的已支持关键字/枚举、十进制整数。采用核实的默认local_events/write_logs=yes、log_format=enriched、log_file=/var/log/audit/audit.log、log_group=0、max_log_file=0、max_log_file_action=ignore。NOLOG按源码顺序关闭write_logs；后续声明可以覆盖该值，但NOLOG仍不满足本参考。

拒绝重复关键字、超过158字节行、缺最终换行、制表/CR/非ASCII、行内注释、未知/未实现字段、脚本exec、远程transport、名称解析、百分比阈值和自定义plugin目录。原生get_line使用160字节缓冲，会跳过长行和未换行末行；本实现不静默模仿这种丢弃。已支持freq/num_logs/max_log_file、空间阈值、队列/重启等数值有界；space_left需大于admin_space_left，incremental刷新需正freq，与源码已实现的交叉条件一致。明确未支持形式保持error，不代表它们必然无效或不安全。

来源是[Ubuntu24 auditd.conf手册](https://manpages.ubuntu.com/manpages/noble/man5/auditd.conf.5.html)、[3.1.2配置解析源码](https://github.com/linux-audit/audit-userspace/blob/v3.1.2/src/auditd-config.c)及[启动源码](https://github.com/linux-audit/audit-userspace/blob/v3.1.2/src/auditd.c)。阈值为项目参考策略，不宣称完整等保、CIS或STIG。

```bash
python3 -B deploy/baseline/build-package.py \
  --definitions deploy/baseline/auditd-definitions.json --platform linux \
  --output-dir .tmp/auditd-candidate
```

测试覆盖配置歧义、默认/大小写/NOLOG顺序、完整不满足与异常分离、实际自定义目标、权限/ID、链接/FIFO/ACL和变化。双架构CI在专用一次性Ubuntu24容器里运行真实auditd 3.1.2解析器；全部capabilities移除、无网络、workspace只读，直接以-f -n -s nochange调用。原生有效配置的退出1来自解析后的权限拒绝，退出6是配置异常；这只能验证解析接受/拒绝，不能证明守护进程运行或日志写入。重复与长行原生可接受但Agent保守error。容器私有配置/日志可以更改，生产检查纯只读，不修改宿主审计状态或规则。SQLite/PostgreSQL REST与桌面/手机使用明确协议夹具验证下发快照、异常阻止发布和完整不合规证据；最终验收绑定本批源码CI。
