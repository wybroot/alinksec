# OpenSSH 名称解析与横幅磁盘声明核查

独立 [ssh-notice/linux-baseline.json](../deploy/baseline/packages/ssh-notice/linux-baseline.json) 版本1成组提供旧0020和0043。限定Ubuntu24.04及可查询的`openssh-server 1:9.6p1-3ubuntu13`系列（含`.数字`更新），固定主配置`/etc/ssh/sshd_config`。现有[SSH连接配置候选](21-OpenSSH配置核查.md)版本1保持两项原范围；新包单独审核、测试和发布，不改变历史任务或旧包。

0020核对原生扩展测试输出的`UseDNS=no`，是本项目减少远端名称解析依赖的参考，**不是通用安全要求**。该选项是全局配置，不允许放入Match；原生语法错误保持error。0043先确定指定连接的有效Banner选择，再核对固定`/etc/issue.net`的审核原始字节SHA256；不是只检查任意非空路径或文件存在。

## 明确连接与审核文案

仓库连接仍是示例：`root,admin.example.invalid,192.0.2.10,192.0.2.20,22`。检查用固定`/usr/sbin/sshd -T -f /etc/ssh/sshd_config -C ...`，由OpenSSH解释优先值、Include与Match。不得把示例连接结论扩大到真实用户或其他连接。实际来源主机/地址、目的地址/端口与用户进入两项定义、审核差异、摘要、下发和任务快照；改变任何条件都需新版本与完整两项测试。

参考横幅见[ssh-banner-reference.txt](../deploy/baseline/ssh-banner-reference.txt)，仅作为可审核示例。管理员应先审核实际需要的完整文案，再从原始UTF-8字节计算SHA256，在复制的[ssh-notice-definitions.json](../deploy/baseline/ssh-notice-definitions.json)中修改0043的`expected`：

```text
file=/etc/issue.net,sha256=<64位小写十六进制>
```

摘要保留换行、空格及全部原始字节差异，不做文本归一化。Agent要求非空/非纯空白、有效UTF-8、最多16KiB，拒绝除换行、回车和制表外的控制字符；不会输出横幅原文。SHA256比对确认内容与审核参考相同，不自动评判文案是否合法、充分或适用。

修改复制定义的包code、version、source.version及真实连接/内容摘要后，使用现有[生成工具](../deploy/baseline/build-package.py)创建独立不可变候选。两端拒绝任意Banner路径、弱比较、其他配置入口或可执行扩展。无需新增迁移；两端需升级，管理员按[模板流程](18-基线模板审核与系统适配.md)重新审核测试。

## 有限配置与输入边界

原生查询之前，先有界读取主配置和所有可到达Include文件（包括不匹配连接的条件分支），确保原生解析器不会绕过已发现输入。该候选只支持无引号、无反斜杠转义的配置行及普通字母关键字；行内注释需由空白分隔。Include可用固定`/etc/ssh`内的绝对路径或相对于该目录的路径，目录段必须是普通目录，末段仅支持`*`/`?`通配；不支持目录通配、字符集合、`~`或`.`/`..`跳转。未匹配的通配可以为空，直接缺少的Include文件记录缺失并在结束复核；缺少Include父目录保持error。引号/转义及其他未支持语法即使位于非匹配分支也保持error，不能删改生产策略以迁就候选。

配置、父目录、Include目录及所选横幅均要求非链接、root:root、无组/其他写权限；普通文件不得有硬链接，拒绝访问ACL及目录默认ACL或无法确认ACL。非阻塞/不跟随链接打开，持有描述符并核对inode、大小、mtime/ctime、路径和目录变化。配置每文件64KiB、1024行、单行小于16KiB，共1MiB/96个输入、64次文件展开、Include深度8、每通配目录最多128条。横幅最多16KiB并计入总量。包查询、预检、两次原生查询和文件复核共用单一截止时间；原生命令有64KiB输出和进程组清理限制。底层文件系统调用仍受存储响应约束。

两次原生查询的UseDNS/Banner选择必须一致，读取输入也须稳定。这是串行多文件观察，**不是原子快照**，不证明其他Include/文件/运行状态永远不变化。包不能注入程序、额外选项、Shell、NSS设置或动态库环境；子进程使用固定PATH与C语言环境。

| 情况 | 结果 |
|---|---|
| UseDNS=no | 满足名称解析依赖参考 |
| UseDNS=yes | fail；不宣称一定不安全 |
| Banner=none或选择其他路径 | fail；不会打开其他路径 |
| 选中issue.net且文本/完整摘要满足审核参考 | pass |
| 空/纯空白或摘要不同 | fail，保留字节数/摘要，原文不回传 |
| 选中文件缺失、无效UTF-8、控制字符、超限或不可信输入 | error |
| 查询失败、语法不支持、解析项缺失/重复、输入或观测变化 | error；不能用默认值通过 |

一项error阻止整个两项包发布，即使另一项通过；完整不合规保留证据，管理员评估后才可发布。变更横幅摘要也须新版本的完整两项证据；旧版本任务快照保持不变。无需自动修复。

## 运行状态与原生证据

实测始终声明`loaded_state=unverified command_line_state=unverified banner_delivery_state=unverified name_resolution_state=unverified snapshot_state=non_atomic`。不启动监听、不发送SSH认证、不修改配置、Banner、服务或主机密钥。Match Group等原生解析可能调用主机NSS，不能把固定配置测试说成完全没有身份查询。

`-C host=...`是合成输入。原生夹具明确验证：即使UseDNS=no，提供的合成Host仍可让Match Host命中；实际连接的名称来源及匹配方式不能由这一测试推断。UseDNS=no对基于来源名称的既有Match或authorized_keys from策略可能影响适用性，管理员需核对实际配置。Banner内容摘要也不证明运行实例已加载文件或用户真实收到提示。

当前提交CI在Ubuntu24 amd64/arm64独立runner中生成临时主机密钥与私有配置，用真实OpenSSH验证六组场景、十次原生比较：默认值、Include词法顺序/首值、两个Address上下文、合成Host、文案变化/缺失与原生语法错误。必跑root夹具覆盖数值UID/GID、访问/默认ACL、链接/硬链接/FIFO、超限、循环、变化与共同截止时间，不能跳过；实际生产选择器仅只读观察并保留item ID。原有SSH/PAM等原生回归保留。REST和页面完整回报是标注的协议夹具，与原生证据分开，生产前端验收绑定当前提交。

root执行的`sshd -T`还要求运行目录`/run/sshd`存在且可信。CI仅在独立runner缺少该目录时创建root:root、0755目录，不启动SSH服务；生产检查不会代建目录，缺少原生运行前提仍保持error。隔离夹具查询失败时记录解析器诊断，生产配置错误继续脱敏。

语义来源为[Ubuntu24 sshd_config手册](https://manpages.ubuntu.com/manpages/noble/man5/sshd_config.5.html)及OpenSSH9.6源码的[配置解释](https://github.com/openssh/openssh-portable/blob/V_9_6_P1/servconf.c)、[横幅读取与发送](https://github.com/openssh/openssh-portable/blob/V_9_6_P1/auth2.c)。原生横幅读取允许更大文本并在真实认证阶段发送；本项目16KiB及审核摘要是更窄的参考，不能把`-T`输出当成原生已读取或交付横幅。

旧60项现46项具有限定范围实现、14项未支持；通用review版本19仍8项/52排除，其中38项指向独立产品候选。基线模块尚未完成，PR保持草稿，继续本模块成组推进。
