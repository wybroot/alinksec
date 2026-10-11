# Ubuntu 24.04 login PAM 登录失败锁定核查

独立候选 `ALINKSEC-UBUNTU24-PAM-AUTH` 版本1映射旧 `BL-LINUX-0005`。范围固定为 Ubuntu24.04、Linux-PAM1.5.3及 `/etc/pam.d/login` 的已支持本地 auth 链；检查只读配置，不尝试认证、不访问账户口令、散列或失败计数记录，也不修改PAM配置。它不证明应用实际调用该服务、其他登录入口、NSS身份来源、模块运行期行为、计数文件可写或重启后锁定仍保留。系统版本匹配后仍须管理员确认实际组件与链条。

```bash
python3 -B deploy/baseline/build-package.py \
  --definitions deploy/baseline/pam-auth-definitions.json --platform linux \
  --output-dir .tmp/pam-auth-candidate
```

可导入[候选包](../deploy/baseline/packages/pam-auth/linux-baseline.json)，按[模板流程](18-基线模板审核与系统适配.md)审核、选主机测试和发布。定义固定 `type=pam_auth`、`target=/etc/pam.d/login`、`option=faillock`、`operator=eq` 与以下参考：

```text
deny=1..5,fail_interval>=900,unlock_time=900..86400,explicit_even_deny_root=1,root_unlock_time=900..86400
```

有限解锁是本项目明确参考，不把永久锁定视为自动通过。两端拒绝弱化参考、任意服务、配置路径和执行字段；更改产品范围需独立实现和不可变新版本，重新审核测试。无新数据库迁移，无自动修复。

## 支持的认证链

展开固定PAM目录中的 `@include` 和 `auth include`，只核对auth组。唯一支持的锁定拓扑为：

```text
auth required pam_faillock.so preauth silent
auth [success=1 default=bad] pam_unix.so
auth [default=die] pam_faillock.so authfail
auth sufficient pam_faillock.so authsucc
auth required pam_deny.so
```

预检、失败记录、成功清零三个阶段均须明确，unix成功跳过失败阶段。每个阶段分别应用配置和参数，计数目录、次数、窗口、普通与root解锁时间、显式root标记必须一致；仅在authfail写 `deny=1` 不代表其他阶段也按一次失败拒绝。`silent`、日志与延迟标记不进入锁定参数的一致性比较。本规则不认证用户枚举防护或完整认证安全。

另一明确支持的 unix/deny/permit 三项auth链没有faillock，返回参考不满足。其他缺失阶段、提前permit、未知模块或身份源、跳转/控制变化、substack、任意模块路径均返回error，阻止发布。默认发行版login链包含本实现未支持的其他模块时也是error，不能删除或改变现场模块来制造通过；应新增相应产品实现。account/password/session组不在该规则范围，不能用此结果证明账户授权、会话或完整login服务安全。

## 配置和证据

要求固定 `/etc/security/faillock.conf` 为可读、非链接普通文件。按Linux-PAM1.5.3默认值、主文件逐行覆盖、每阶段模块参数顺序解释；不读取drop-in或vendor回退。模块 `conf=` 仅允许同一固定文件，计数目录仅接受 `/run/faillock` 或默认 `/var/run/faillock`，三个阶段须使用同一字面路径，不假设两路径实际等价，不检查运行期内容。

默认deny=3、窗口900秒、普通解锁600秒。root解锁未明确时继承最终普通解锁值；参考额外要求显式 `even_deny_root`，不依据仅有root解锁数字推断标记。`even_deny_root=0` 与其他已支持SET标记仍表示出现并启用。整数只接受完整无符号十进制，deny最多65535，时间最多604800；0或never解锁为已理解的参考不满足。非法、溢出、尾随文本、未知设置、重复模块参数及 `admin_group`/`local_users_only` 额外身份分支保持error。

文件读取沿用[PAM口令链](23-PAM口令链核查.md)的超时、64KiB单文件、1MiB总输入、行数、展开项、深度和描述符稳定性限制；faillock配置行须短于1023字节。文件缺失、特殊文件、链接、超限、循环和读取变化保持error。已知策略不满足为fail，无法确认是error，二者不互换。证据保留服务、拓扑、deny、窗口、两个解锁时间、显式root标记、固定计数目录名称及输入数量，不回显未知配置原文或凭据。多文件读取不是原子快照。

## 原生验证

`deploy/tests/pam-password-native.sh` 在一次性Ubuntu24.04镜像中依次运行口令和登录链测试。工作区只读、无网络、无宿主/etc挂载或数据卷；专用标记、root和容器检查防止普通环境运行。认证探针只输出PAM返回码，测试账户、配置和计数都属于隔离文件系统。用实际 `pam_authenticate` 验证连续失败阈值与root锁定、成功清零、模块覆盖及SET标记、缺少显式root设置的例外、禁用锁定与有限解锁、提前permit绕过，以及阶段阈值不一致。两架构CI必须实际执行，普通Go测试跳过不能替代此验收。

REST和生产网页使用单独标注的协议夹具，覆盖完整error/fail/pass报告、异常阻止发布、实测值、不可变下发和版本快照、桌面/手机展示及禁止修复；这些报告不代表生产主机实际认证。

解释依据Ubuntu24.04的 [pam_faillock手册](https://manpages.ubuntu.com/manpages/noble/man8/pam_faillock.8.html)、[faillock.conf手册](https://manpages.ubuntu.com/manpages/noble/man5/faillock.conf.5.html)，以及Linux-PAM1.5.3的[认证阶段实现](https://github.com/linux-pam/linux-pam/blob/v1.5.3/modules/pam_faillock/pam_faillock.c)、[配置读取实现](https://github.com/linux-pam/linux-pam/blob/v1.5.3/modules/pam_faillock/faillock_config.c)和[数值范围定义](https://github.com/linux-pam/linux-pam/blob/v1.5.3/modules/pam_faillock/faillock_config.h)。

旧60项目前有8项通用观测和12项独立产品检查，40项尚未实现。通用包版本6仍明确列出自身未包含的52项。继续留在基线分支和草稿PR；其余模块只保留有序待办。
