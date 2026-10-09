# Shadow 新账户口令有效期与预警默认声明核查

独立 [shadow-defaults/linux-baseline.json](../deploy/baseline/packages/shadow-defaults/linux-baseline.json) 版本1成组提供旧0003/0004。仅支持Ubuntu24.04 amd64/arm64、可查询的`passwd 1:4.13+dfsg1-4ubuntu3`系列（含`.数字`更新），固定读取`/etc/login.defs`。这是本项目的有限新普通本地账户默认声明参考，需独立审核、完整两项测试及发布；不是完整等保、CIS或STIG结论。

| 项目 | 完整参考 |
|---|---|
| 0003 最大口令有效期默认声明 | `max_days=1..90,min_days<=max_days` |
| 0004 到期预警天数默认声明 | `warn_days=7..14,warn_days<=max_days` |

0003要求明确声明`PASS_MAX_DAYS`为1至90；若声明`PASS_MIN_DAYS`，还须小于等于最大值。未声明最小值不会推断原生默认值。0004要求明确声明`PASS_WARN_AGE`为7至14、最大值为正且预警不大于最大值；不借用0003的90天上限。例如最大值99999、预警7时，两项分别fail/pass，不能把一项失败扩散为另一项执行异常。阈值是本项目参考，管理员应判断实际产品适用性。

## 声明与账户状态的边界

login.defs参数是新建账户时的默认输入，不会自动更新已有账户。`useradd -r`系统账户、`-K`显式覆盖、`-R`替代根和`-P`替代前缀不在本候选的创建调用范围。实际创建命令、现存shadow字段、认证链执行、到期阻止及预警交付均未验证。生产检查不调用useradd、不读取shadow口令字段、不创建或修改账户、不改配置、不执行认证，也不提供自动修复。

实测始终声明`creation_invocation_state=unverified existing_account_state=unverified expiry_enforcement_state=unverified warning_delivery_state=unverified snapshot_state=non_atomic`。不能把磁盘参考pass解释为已有用户已具备该策略或用户实际收到预警。原生夹具会直接验证CLI覆盖、系统账户和已有账户与当前默认声明可不同。

## 有限语法、可信输入及失败处理

三个选中键必须使用唯一的大写名称，值仅接受规范十进制`-1`、`0`或无前导零的正整数，范围-1至2147483647；只以ASCII空格/制表分隔。重复、大小写变体、引号、转义、八/十六进制、额外字段和选中声明行内注释保持error。其他login.defs设置不作策略解释。所有物理行（包括注释及其他键）最多1000字节，防止原生1024字节行缓冲分片产生隐藏声明；每文件64KiB、1024行。更复杂原生语法属于未支持范围，不能为了通过参考而删改生产策略。

`/`、`/etc`和文件均要求root:root、无组/其他写权限、非链接；文件必须是普通文件且无硬链接。拒绝访问ACL、目录默认ACL或无法确认ACL。使用非阻塞/不跟随链接打开，持有描述符并复核inode、大小、mtime/ctime、路径与权限。单一截止时间覆盖两次固定`/usr/bin/dpkg-query --show --showformat=${Version} passwd`、有界读取及稳定性复核；包版本必须相同。命令使用固定PATH和C语言环境，输出64KiB上限及进程组清理。串行观察不是原子快照；底层文件系统调用仍受存储响应约束。

| 情况 | 结果 |
|---|---|
| 所需键缺少、已知0/-1、参考之外或天数关系不满足 | fail，保留明确缺失或数字 |
| 语法未支持、越界、读取失败、包不匹配、输入不可信/变化或共同截止时间耗尽 | error |
| 明确声明及关系满足该项完整参考 | pass，仅限磁盘声明 |

两端只允许固定type/target/option/eq及完整参考，拒绝弱比较、任意文件、命令、账户字段和额外扩展（包括null）。缺省超时5000ms，显式超时必须100至30000ms，拒绝0/null。一项error阻止整包发布；完整fail可以保留证据供管理员评估。新版本改变任一声明定义仍须完整两项新证据，旧任务快照保持不变。管理员需升级两端并按[模板流程](18-基线模板审核与系统适配.md)审核；候选不会自动导入、启用或发布。

## 原生验证与来源

当前提交CI在Ubuntu24 amd64/arm64独立runner串行运行专用无网络临时容器，复用前一项PAM验证镜像、只读挂载仓库、不挂载宿主/etc或数据卷。测试要求root、两个独立显式开关及隔离标记，缺少任何前提立即失败。容器内才创建无home/mail/login的锁定测试账户；只比较所需天数字段，不输出shadow记录或口令哈希，完成后删除容器。

八组原生场景、二十次useradd与声明对照覆盖普通账户、0/-1/关系/32位边界、缺省、最小值大于最大值、CLI覆盖、系统账户、已有账户不随默认更新，以及强制执行的安全/有限语法/变化/共同截止时间边界。数值UID/GID、访问/默认ACL、链接/硬链接/FIFO和原生缓冲分片等检查不得跳过。REST与页面完整回报是协议夹具，不能替代原生证据；桌面和移动页面检查使用当前提交生产前端。

语义来源为[Ubuntu24 login.defs手册](https://manpages.ubuntu.com/manpages/noble/man5/login.defs.5.html)、[useradd手册](https://manpages.ubuntu.com/manpages/noble/man8/useradd.8.html)以及Shadow4.13源码的[配置读取](https://github.com/shadow-maint/shadow/blob/4.13/lib/getdef.c)和[账户创建](https://github.com/shadow-maint/shadow/blob/4.13/src/useradd.c)。源码tag及Ubuntu Debian补丁归档用于交叉核对，摘要校验不宣称发行商签名认证；实际安装产品语义由隔离原生验证确认。手册与源码对未声明最小天数存在不同表述，本检查保留缺失状态，不凭任一默认值判定。

旧60项现46项具有限定范围实现、14项未支持。通用review版本19仍8项/52排除，其中38项指向独立产品候选。基线模块尚未完成，PR保持草稿，继续本模块成组推进。
