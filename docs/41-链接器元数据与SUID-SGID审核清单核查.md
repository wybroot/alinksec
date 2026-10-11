# 链接器元数据与 SUID/SGID 审核清单核查

独立[program-files/linux-baseline.json](../deploy/baseline/packages/program-files/linux-baseline.json)版本1成组提供旧0041/0042。限定Ubuntu24 amd64/arm64、完整安装libc-bin/libc6 `2.39-0ubuntu8`系列。默认示例必须由管理员审核，不能当成全部Linux的权限/授权结论；生产只读，无自动修复。

| 原规则 | 有限当前参考 |
|---|---|
| 0041 | `/etc/ld.so.conf`与其唯一固定包含下的全部非隐藏直接`.conf`配置文件模式上限0644，目录上限0755，UID/GID0与可信输入 |
| 0042 | `/usr/bin`、`/usr/sbin`全部直接普通文件中SUID/SGID模式位集合，按当前架构与审核清单逐项匹配路径、完整模式、UID/GID及内容SHA256 |

链接器仅接受主配置唯一`include /etc/ld.so.conf.d/*.conf`、完整UTF8注释行及规范ASCII绝对目录行。包含按C字节顺序枚举，隐藏或非`.conf`成员不解释，成员变化仍被复核。额外/递归/相对包含、hwcap、引号/转义/变量/未知语法均error。缺失、链接、普通硬链接、非root:root、组/其他写、访问或目录默认ACL及不可确认ACL为error；可信输入的已知模式上限偏差为fail，更严格模式接受。不读取库目录/库文件、cache/preload、环境或运行实例，不证明库目标安全、ldconfig真实调用或完整动态链接策略。

SUID/SGID需要管理员人工准备`/etc/alinksec/privileged-files.reference`，并在新候选0042的完整expected中绑定原始字节SHA256。清单及全部父目录必须root:root、无组/其他写、链接、普通文件硬链接和访问/默认ACL；缺失、摘要不符、未知格式或不可信输入是error。示例[空批准集](../deploy/baseline/privileged-reference-empty.txt)没有生产授权含义，不自动安装或自动学习当前主机文件。

清单头部固定如下，最后也必须换行；两架构可以共用一份文件，分别选择其条目：

```text
alinksec-privileged-reference-v1
scope=/usr/bin,/usr/sbin
```

其后每行六列，以一个TAB分隔：架构(`amd64`/`arm64`)、固定目录直接路径、四位八进制完整模式、规范UID0、规范uint32 GID、64位小写内容SHA256。按架构/路径排序，禁止重复或越界路径；模式必须含SUID或SGID且无组/其他写。每架构最多128条，未列文件属于未批准集合；参考为空时只有观测集合也为空才能满足集合参考。管理员独立确认软件来源与授权后生成新候选及完整两项测试证据；批准文件被软件更新改变内容也须重新审核，不使用passwd修改时间或存在性代替授权。

枚举固定两个目录的全部直接成员并记录元数据，包含隐藏名字。只对普通文件模式位集合读取内容；链接、子目录与非普通条目分别计数，明确排除其目标/后代。未选中普通文件只复核元数据。路径名限完整可枚举的1..255个无空白/斜杠/反斜杠的可打印ASCII字节；未知名称或枚举不完整error。选中文件硬链接、ACL、读取失败、超限或变化为error；全部路径/模式/UID/GID/内容与参考的已知集合差异为fail。Linux是否实际应用这些位还依赖文件类型、nosuid、no_new_privs、LSM等；文件能力、其他路径、链接目标、后代、实际提权及授权流程均unverified。它是当前审核集合核对，不能认证所有特权路径或认定谁实施了未授权变更。

父目录/配置/清单描述符持有到稳定性复核；选中普通文件相对目录描述符以非阻塞、不跟随链接方式打开，分块哈希，打开前/读取后及路径元数据核对。扫描两次，比较全部成员、选中内容和全部条目元数据，读取引起的atime不作变化条件。每目录4096条；每文件8MiB、单次选中内容总16MiB，两次最多32MiB加增长探测边界；同时最多一选中文件内容描述符。配置/清单单64KiB、共256KiB、配置1024行/每行1024字节、32片段/128成员，引用清单每行1024字节。软件包前后固定查询、读取和复核共用100至30000ms deadline，默认5000ms，显式0/null拒绝，观察非原子，短暂/ABA变化未必捕获。

两端只接受固定type/target/option/eq及完整元数据或SHA参考，拒绝命令、其他根目录/清单路径、弱比较和额外字段含null。一项error阻止两项整批发布，改变清单摘要也必须整批fresh证据，旧快照保留。完整观测摘要、差异数和受限样本进入报告；不会因报告2048字节上限漏掉判定中的文件。按[审核流程](18-基线模板审核与系统适配.md)选择适用产品和主机测试。

双架构原生CI复用Ubuntu24 PAM镜像，在无网络128MiB单CPU可删除容器使用独立文件系统副本，仓库只读，无宿主/etc或数据卷。root、双开关与镜像隔离标记缺一拒绝夹具修改；CHOWN/FOWNER/FSETID只用于数值属主/SGID夹具，SYS_CHROOT只用于私有根的`ldconfig -r ... -N -X`只读配置对照。不执行任何特权夹具文件、不运行宿主ldconfig、不写生产审核清单。普通stat/sha256sum独立核对数值模式/属主/内容；覆盖空集合、SUID及非零GID SGID、完整参考、差异/内容/模式、链接/目录排除、UID/GID/访问默认ACL、硬链接/FIFO、限额、摘要、版本/成员/文件变化及共同deadline，强制边界不得跳过。真实固定生产选择器只读保留item ID，未准备参考的主机保持error。完整REST与页面是协议夹具，不扩大为实际提权或完整授权证据。

来源：[Ubuntu24 ldconfig](https://manpages.ubuntu.com/manpages/noble/en/man8/ldconfig.8.html)、[glibc2.39配置解析](https://github.com/bminor/glibc/blob/glibc-2.39/elf/ldconfig.c)、[Linux execve](https://manpages.ubuntu.com/manpages/noble/en/man2/execve.2.html)。项目的权限上限与清单参考须按业务审核，不是完整等保/CIS/STIG认证。

旧60项现52项具有限定范围实现、8项未支持；通用review版本22仍8项/52排除，其中44项指向独立产品候选。基线继续当前分支，PR保持草稿。
