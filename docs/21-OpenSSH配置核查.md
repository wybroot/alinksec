# OpenSSH 指定连接配置核查

独立候选 [ssh/linux-baseline.json](../deploy/baseline/packages/ssh/linux-baseline.json) 版本 1 提供两个原始规则：BL-LINUX-0007 要求指定连接的 `PermitRootLogin` 为 `no`；BL-LINUX-0008 要求 `MaxAuthTries` 为 1 至 4。阈值是本项目参考策略，不是 OpenSSH 默认值或完整合规标准。候选限定 Ubuntu 24.04 LTS，需 `/usr/sbin/sshd`、可读取的配置及主机密钥。其他发行版或 Windows 不在该候选的匹配范围内。

检查使用固定程序 `/usr/sbin/sshd -T -f <配置路径> -C <连接条件>`，只执行扩展配置测试，不启动监听或建立 SSH 连接。由 OpenSSH 处理注释、Include、重复声明的优先顺序和 Match 条件；不再把主文件中的任意匹配行当作生效结论。默认配置查询、用户、来源主机、来源地址、本地地址和本地端口全部明确进入检查定义、候选摘要、审核差异、任务快照及实测证据。若改变连接条件，须建立新候选版本并重新审核、测试、发布。

## 为实际连接建立候选

仓库附带的连接条件是 **示例**：`user=root, host=admin.example.invalid, address=192.0.2.10, local_address=192.0.2.20, local_port=22`。它只用于展示配置解释流程，不能作为实际来源或其他连接的合规结论。上线前复制 [ssh-definitions.json](../deploy/baseline/ssh-definitions.json)，在两项检查的 `connection` 中填写每类实际连接条件，并按实际实例确认 `target` 配置路径。host 是 OpenSSH 所采用的解析后来源主机名，address 是客户端地址，local_address 是服务端目标地址；不是把目标服务器名称填入 host。为不同实例/连接选择独立包 code，并设置新的包 version 和来源 version；生成的 source.sha256 绑定此次定义文件。

```json
{
  "type": "sshd_effective",
  "target": "/etc/ssh/sshd_config",
  "option": "permitrootlogin",
  "connection": {
    "user": "root",
    "host": "admin.example.invalid",
    "address": "192.0.2.10",
    "local_address": "192.0.2.20",
    "local_port": 22
  },
  "operator": "eq",
  "expected": "no",
  "timeout_ms": 5000
}
```

修改复制的定义后，使用现有工具生成不可变候选：

```bash
python3 -B deploy/baseline/build-package.py \
  --definitions .tmp/site-ssh-definitions.json --platform linux \
  --output-dir .tmp/site-ssh-candidate
```

按 [模板审核流程](18-基线模板审核与系统适配.md) 导入、确认来源及连接条件、选适用主机测试，然后评估完整证据再发布。查询得到 `yes`、`prohibit-password`（旧同义名称 `without-password`）或 `forced-commands-only` 均不满足本参考的 root 登录 `no` 要求；不能把禁止口令误当成禁止全部 root 登录。原始输出名称保留在证据中。某个连接满足条件不代表其他用户、地址、端口或主机条件也满足。

## 执行与证据边界

`sshd_effective` 只允许 Linux、两个已实现的配置项及 `eq`/RE2 `regex` 比较。连接字段要求完整，root 登录检查要求用户为 root；IPv4 不接受带前导零形式，IPv6 使用十六进制形式且不带区域或 IPv4 映射，端口为 1 至 65535。两端拒绝重复字段、未知字段、逗号/空白/命令文本和可执行扩展。Agent 固定程序与参数位置，包不能指定程序、附加选项或 Shell。

主配置必须是普通文件且不超过 8 MiB。进程保留检查超时、Linux 进程组清理和 64 KiB 输出上限；缺少程序/主机密钥、配置语法错误、权限不足、查询失败、配置项缺失/重复或 Include 阻塞均返回 `error`，不能用默认值通过。配置值未达到参考策略返回 `fail`。两种情况都保存明确连接条件；页面同时显示实测值和失败原因。

该查询解释磁盘上的配置文件，不证明运行实例已经重新加载它们、SSH 服务可连接、全部认证链有效或全部连接都被覆盖。实际服务如使用自定义 `-f`、`-o`、多个实例或产品包装程序，部署方须先确认启动方式；本包不能自动合并命令行覆盖值。不能用本候选替代实际服务与认证验证，也不提供自动修复。

新检查类型需要同时更新服务端与 Agent。旧 Agent 无法解释该类型时返回异常/无法确认结果，审核发布仍要求重新取得完整、明确且无执行异常的测试报告。旧模板保持停用，历史迁移和历史证据不改写；本批没有新增数据库迁移。

## 来源与验证

配置含义依据 [OpenSSH sshd 手册](https://man.openbsd.org/sshd)的扩展测试/连接条件说明、[sshd_config 手册](https://man.openbsd.org/sshd_config)的优先值、Include、Match、PermitRootLogin 与 MaxAuthTries，以及 [Ubuntu 24.04 sshd 手册](https://manpages.ubuntu.com/manpages/noble/man8/sshd.8.html)。实际实现使用 `-T -C`，而不是依赖不同版本的配置打印选项兼容性。

原生测试在临时目录生成主机密钥和隔离配置，用真实 `/usr/sbin/sshd` 验证 Include、注释、重复项、两个 Match 连接、语法失败、缺失文件、非普通文件及 FIFO Include 超时，不改动系统 SSH 配置或启动服务。本机 Ubuntu 26.04/OpenSSH 10.2 的原生夹具证据验证引擎行为；候选的 Ubuntu 24.04 amd64/arm64 范围以当前提交 CI 的原生证据为准，不扩展为其他产品认证。REST 和浏览器的完整回报是明确标注的协议夹具，与原生执行证据分开记录。

旧60项中目前有8项通用观测、2项独立 SSH 配置候选及7项 [本地身份文件候选](22-本地身份文件核查.md)，另有2项 [passwd PAM口令链候选](23-PAM口令链核查.md)，剩余41项尚未实现。通用观测包版本5仍列出自己未包含的52项，包含十一项独立候选指引；独立 SSH 包另外保留 UseDNS 与横幅的未支持原因。逐项记录见 [旧基线模板内容审核](20-旧基线模板内容审核.md)。
