# rsyslog cron 专用日志磁盘路由核查

本候选只适用于 Ubuntu24.04 已完整安装 `rsyslog 8.2312.0-3ubuntu9.4` 的默认配置入口。旧0048转为这项有限产品参考，名称不再暗示日志运行状态。独立候选 `ALINKSEC-UBUNTU24-RSYSLOG-CRON` 版本1；通用审核参考版本11仍8项，自身52项排除中21项指向其他产品候选。旧60项当前29项有有限实现、31项未实现。旧cron元数据候选版本1的排除记录保留，不改写历史包、迁移或任务。

管理员需确认可信安装、实际入口及主机适用性。软件包查询固定 `/usr/bin/dpkg-query --admindir=/var/lib/dpkg --show --showformat=... -- rsyslog`，清洁环境、无shell，检查前后须完整安装且精确版本匹配，共用一个100–30000ms期限。软件包声明不证明二进制或所有依赖完整性。

检查 `rsyslog_cron_routing` 固定 `target=/etc/rsyslog.conf`、`operator=eq`、完整参考 `imuxsock=on,cron.emerg..debug=/var/log/cron.log`。服务端和Agent都拒绝其他路径、弱化参考、额外字段及null额外字段；Windows运行返回error。候选不含自动修复。

解释范围为主配置及主配置中唯一一次 `$IncludeConfig /etc/rsyslog.d/*.conf`，在包含位置按顺序展开。包含文件限唯一两位数字前缀 `NN-name.conf`，后缀限ASCII字母数字横线下划线；前缀不重复，使支持范围的顺序不依赖后缀排序。glob不匹配点文件和非`.conf`备份；它们只参与目录名称稳定性快照，不读取其内容。嵌套、其他或重复包含返回error，不把无法读取的包含当作空集。明确空目录可以继续解析。最多32包含文件，单文件64KiB、总256KiB、4096行、单行4096字节、目录128条目；ASCII文本、LF行终止。

仅支持传统facility/severity选择器：已列出的Linux facility名、`*`、`,`组合、`;`组合、八级名称及原生别名、阈值、`=`精确级别、`!`否定、`none`。精确包源码 `DecodePRIFilter` 中正条件累加位，否定清除位，`none`清空，`*`设全部。因此 `cron.*;cron.err` 仍覆盖八级；`cron.*;cron.!err` 仅保留warning至debug。不能用“后者覆盖前者”简化。数字名称、特殊级别的`=`、大小写变体或歧义格式不在范围。

动作只支持 `/var/log` 下规范静态路径及可选前导`-`、厂商`:omusrmsg:*`通知和`~`/`stop`丢弃；`&`仅继承明确相邻规则选择器。逐条跟踪仍可到达的八级，已写到参考目标后再丢弃不会撤销先前路由；提前丢弃会阻止后续规则。所有输入均解析，即使提前stop也不会掩盖后面的未知语法。更广facility选择器也可满足cron路由声明，不证明cron.log只含cron事件。

有限声明支持精确 `module(load="imuxsock")` 和`SysSock.Use="on|off"`、厂商imklog声明，以及厂商固定所有者/模式/工作目录/特权下降/重复合并和两个内置文件模板声明。重复声明拒绝。RainerScript表达式、属性过滤、其他规则集、模板定义、队列、输入、模块、远程/动态/命令动作、动作内联注释等一律error。厂商主配置中的模块内联注释可解析。配置声明不解析NSS，不保证模块初始化或文件写入权限。

配置读取逐段`O_PATH/NOFOLLOW`、保留fd，普通文件单硬链接，配置/包含目录需UID0且组/其他用户不可写，拒绝访问/默认ACL和无法确认ACL。固定路径缺失、目录匹配`.conf`、链接/特殊文件、读取失败/超限或元数据/内容/父目录身份及访问元数据/包含名称集合在期间变化均error。最后重新打开比较inode、模式、IDs、nlink、ctime、size/mtime与目录集合。父目录完整授权不属于结论。读取内容只用于解释，不回显配置、注释或秘密。

完整支持图若未声明imuxsock输入开启，或八级不能在丢弃前到达固定目标，则fail；满足声明则pass。证据包含 `scope=on-disk-rsyslog-cron-routing loaded_state=unverified delivery_state=unverified`、精确包、输入声明、目标、八位覆盖/缺失掩码与文件/规则计数。`0x80`代表缺少debug。Ubuntu厂商默认专用cron行被注释，cron仍可能送入syslog；该配置不满足本专用文件参考，不等于“没有cron日志”。

生产不调用rsyslogd（包括`-N1`）、不执行配置动作、不读日志、不修改文件或服务。不证明实际运行入口/已加载配置、cron实际发送、系统socket与systemd激活、限流、重复合并、队列/丢包、目标文件类型或授权/可写性、日志轮转和事件交付。管理员需根据实际业务另行核对这些状态。

原生CI使用Ubuntu24精确包、禁止服务自启的专用容器，无网络、capabilities全部删除、128MiB内存/192MiB含swap、1CPU、64PID、repo只读。仅修改容器私有配置和Unix socket，受控daemon使用私有pid并在每场景结束清理。真实`rsyslogd -N1`解析有限夹具，再通过imuxsock发送八个不同severity的cron datagram和其他facility负例；私有control.log确保消息已处理，daemon正常关闭后比对cron.log实际八位掩码。覆盖正条件累加、精确/否定、none、提前/后置丢弃、连续动作、包含顺序/位置、注释和ACL拒绝边界。容器还必跑全部不可信/歧义输入边界，包括访问与包含目录默认ACL；必跑模式不能跳过ACL夹具。原生能读取ACL配置不扩张本候选的无ACL范围。这里证明精确产品有限夹具中的路由语义，不能证明用户主机事件交付。

审核/下发/任务快照/错误阻止发布、完成fail允许发布和新版本需独立证据的协议测试，以及双数据库REST与桌面/移动端证据展示，均与原生结果分开。资源受限本机串行验证，双架构CI独立runner并行。

源码依据为[Ubuntu精确包归档](https://archive.ubuntu.com/ubuntu/pool/main/r/rsyslog/)、[Ubuntu源包](https://packages.ubuntu.com/en/source/noble/rsyslog)、[上游8.2312.0选择器源码](https://github.com/rsyslog/rsyslog/blob/v8.2312.0/runtime/conf.c)、[上游包含实现](https://github.com/rsyslog/rsyslog/blob/v8.2312.0/grammar/rainerscript.c)、[上游系统socket声明](https://docs.rsyslog.com/doc/reference/parameters/imuxsock-syssock-use.html)。实现以精确源码及原生对照为准，不将当前文档推广到所有版本。

后端测试在JDK21测试JVM启动时预加载现有版本Byte Buddy instrumentation，避免CI反复发生Mockito自挂载初始化失败。依赖仅test scope，Surefire保留调用者argLine；本地在动态Agent加载和Attach均关闭的条件下检查完整测试，受资源watchdog保护。依据[Mockito5.11实现](https://github.com/mockito/mockito/blob/v5.11.0/src/main/java/org/mockito/internal/creation/bytebuddy/InlineDelegateByteBuddyMockMaker.java)。
