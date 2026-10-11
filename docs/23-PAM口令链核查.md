# Ubuntu 24.04 passwd 口令链参考核查

独立 [PAM 候选](../deploy/baseline/packages/pam/linux-baseline.json) 版本1增加0002口令质量和0006新口令散列选择两项。范围为 Ubuntu24.04 的 Linux-PAM1.5.3/libpwquality1.4.5，入口固定 `/etc/pam.d/passwd`，只解释 password 管理组。它不证明应用确实调用该服务、现存口令符合要求、登录认证链有效、外部身份源或其他服务受相同策略约束。参考要求由本项目选择，不是完整合规标准。

```json
{"type":"pam_password","target":"/etc/pam.d/passwd","option":"quality","operator":"eq","expected":"minlen>=12,minclass>=3,credits<=0,enforcing=1,enforce_for_root=1,use_authtok=1","timeout_ms":5000}
```

散列项使用相同固定入口，option 为 unix_hash、expected 为 yescrypt。两端拒绝其他入口、任意执行字段及隐式改变参考要求；范围完整进入不可变包、审核、任务快照与下发。此批不增加迁移，也不提供 PAM 或口令自动修复。

## 已支持的链

解析 @include 和 password include，展开所选目录中的普通配置文件。允许注释、空白、基本管理组名称大小写、续行，以及标准括号控制字段的键排列。仅接受以下本地链：

```text
password requisite pam_pwquality.so retry=1
password [success=1 default=ignore] pam_unix.so obscure yescrypt use_authtok
password requisite pam_deny.so
password required pam_permit.so
```

质量模块可以缺少：此时明确返回质量参考不满足，散列项仍核对已支持链的显式算法。质量模块存在时须为第一个模块且使用 requisite；unix、deny、permit 的顺序和控制必须与上例相同。unix 的 use_authtok 明确要求使用先前的口令，缺少时质量项未满足本项目参考。Linux-PAM1.5.3 在口令令牌已存在时仍会复用它，缺少此选项不等于这个链必然重新索取口令。仅出现质量模块的文本不能证明强制检查，提前 sufficient permit 或改变跳转仍可能改变结果。

仅处理上述已知模块及参数。未知模块、额外身份源、substack、自定义控制/跳转、重复/冲突散列选项、缺少显式散列、路径逃逸、循环、缺失模块或无法解释的配置返回 error，阻止发布。支持模块的常规名称和该架构固定 /usr/lib 或 /lib 路径，不接受任意模块路径。需要其他拓扑时应新增明确实现与候选，不能用已成功测试的旧版本代替。

## 质量配置与参考

按 libpwquality1.4.5 的设置顺序处理：默认值、按字节排序的有效 .conf drop-in、主 pwquality.conf，最后是模块参数。主文件可以覆盖 drop-in，模块参数再次覆盖；重复设置取最后一次。minlen 最小6、minclass 最大4的归一化进入实测值。缺少主文件保持 error，即使上游有默认文件缺失容错；缺少 drop-in 目录可以接受，检查结束再确认其仍缺少。

本参考要求 minlen至少12、minclass至少3、四项credit均不大于0、enforcing为1、enforce_for_root启用，以及unix use_authtok。credit 正值可能给长度加分，不能把minlen的数值直接当作实际字符长度下限。libpwquality1.4.5 的 enforce_for_root 是 SET 标记，出现即启用，包括写成 enforce_for_root=0；不能按常规布尔赋值解释它。local_users_only 引入的额外身份分支保持无法确认。

结果保留实际长度、类别、credit、执行标记、口令传递状态、服务、模块链、输入数量和算法。其他已知质量设置可解析，但本规则不据此认证字典、用户名称、相似度或完整口令质量。字符串设置不回显。算法项只核对 pam_unix 明确选择，不读取或返回现存口令哈希；不同算法为 fail，没有显式选择则无法确认编译默认值。

## 读取和证据

入口、include 文件及主/drop-in配置均须为非链接普通文件。PAM目录及drop-in目录拒绝链接。每文件64KiB、最多1024物理行、PAM行16KiB、pwquality行须短于1023字节；include深度最多8、展开项最多64、drop-in最多64个且目录最多128项；总输入最多1MiB、最多96个文件/目录，并有检查超时。特殊文件不会因等待内容阻塞。保持输入描述符，在结束时核对inode、大小、修改/元数据时间与路径，变化返回error。多个文件依次读取，不宣称所有配置的原子快照，也不证明模块加载或运行期行为始终与本次观察一致。

错误不回显配置原文、未知参数值或凭据。账户口令和哈希不进入生产检查。完整REST/浏览器报告是明确标注的协议夹具：质量未满足与明确散列满足分开显示，未知链阻止发布；不是主机生产认证。

原生测试只在专用一次性Ubuntu24.04镜像中执行实际PAM口令更新。源码挂载只读，容器没有网络和宿主/etc挂载，测试写入均属于其隔离文件系统；容器结束即移除，无数据卷。专用标记、root与容器检查防止测试在普通验证环境运行。真实PAM验证强/弱口令、root/enforcing例外、drop-in/主文件/模块覆盖、include/续行、缺少use_authtok时当前链仍复用已检查令牌、提前permit成功但未更新凭据，以及实际生成yescrypt/sha512。探针仅输出返回码、算法名称和验证布尔值，绝不输出口令、对话内容或哈希。两架构CI必须实际通过；本机镜像下载失败时不能把原生项标记为本地已通过。

解释依据 Ubuntu24.04 的 [PAM配置](https://manpages.ubuntu.com/manpages/noble/man5/pam.d.5.html)、[pam_pwquality](https://manpages.ubuntu.com/manpages/noble/man8/pam_pwquality.8.html)、[pwquality.conf](https://manpages.ubuntu.com/manpages/noble/man5/pwquality.conf.5.html) 和 [pam_unix](https://manpages.ubuntu.com/manpages/noble/man8/pam_unix.8.html) 手册，及 libpwquality1.4.5 的 [设置读取实现](https://github.com/libpwquality/libpwquality/blob/libpwquality-1.4.5/src/settings.c) 与 [PAM模块实现](https://github.com/libpwquality/libpwquality/blob/libpwquality-1.4.5/src/pam_pwquality.c)。令牌复用依据 Linux-PAM1.5.3 的 [pam_get_authtok实现](https://github.com/linux-pam/linux-pam/blob/v1.5.3/libpam/pam_get_authtok.c)。

旧60项目前有8通用观测、2SSH、7身份文件、2PAM口令与1PAM登录失败锁定产品检查，40项仍未实现。通用包版本6自身仍未包含52项，并指向12项独立候选；详见[逐项审核](20-旧基线模板内容审核.md)及[模块计划](19-模块完善计划.md)。
