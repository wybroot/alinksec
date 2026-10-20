# 原生 YARA 引擎与规则证据

原生 YARA 是可选的 Agent 构建。它把 YARA 4.5.8 静态链接到 Agent，在一次性子进程中编译、扫描管理员提供的规则源码。Linux amd64、Linux arm64、Windows amd64 使用相同的规则入口；默认 `CGO_ENABLED=0` 构建报告不支持原生 YARA。内置 SHA256、内部 JSON 规则及本机 ClamAV 各有独立入口。

## 构建和配置

构建脚本只在开发/CI 环境下载源码，运行中的 Agent 不下载、安装引擎或规则。`deploy/tests/yara-build.sh OUTPUT_DIRECTORY` 需要本机 GCC、make、autoconf、automake、libtool、curl、sha256sum。Windows 使用 MSYS2 MINGW64；应使用各目标系统的原生工具链。完整三平台验收入口为 `deploy/tests/yara-native.sh`。

上游固定为 [YARA v4.5.8](https://github.com/VirusTotal/yara/releases/tag/v4.5.8)，提交 `84b0e3cc0e42f8f8e6b84d19c97ec3ac6ff8aee8`，codeload 源码包 SHA256 为 `da7eb424e88360de6165d4af5fa88d6f72c22676f517d9d436a7cd67624b7119`。脚本校验摘要后单线程构建静态库，并生成 `build.json`。构建 Agent 时设置：

```sh
export CGO_ENABLED=1
export CGO_CFLAGS="-I/absolute/build/install/include"
export CGO_LDFLAGS="-L/absolute/build/install/lib"
cd agent
go build -tags nativeyara -trimpath -o alinksec-agent-yara ./cmd/agent
```

Windows 给 Go 的路径用 `cygpath -m` 转换。库和 MinGW 运行时静态链接；Linux 的系统 C 运行库保持系统依赖，应在兼容目标 glibc 的环境构建。CI 原生构建产物单独保留，不改变现有发布渠道，也不自动部署。

管理员先审核规则，将一个 UTF-8 `.yar` 源文件放在 Agent 可读取的受保护本地路径，用 `sha256sum` 或 PowerShell `Get-FileHash -Algorithm SHA256` 计算完整源码摘要：

```yaml
yara:
  enabled: true
  realtime: false
  rules_file: /etc/alinksec/rules/local.yar
  rules_sha256: <64位源码SHA256>
  timeout_sec: 10
```

Windows 使用本机绝对路径，例如 `C:/ProgramData/ALinkSec/rules/local.yar`。规则文件须是管理员维护的普通文件，并由管理员保护写权限；读取沿用配置安全读取器，拒绝链接、身份变化或超限文件。通过现有 `agent config apply --from ... --workdir ...` 批准配置，重启 Agent 后生效。更新规则时须同时审核源码和新摘要并批准配置；源码单独变化立即拒绝继续使用。此模块不提供规则分发、增量更新或自动信任社区规则。

## 语言范围和执行限制

使用原生编译器，支持 YARA 的字符串、hex、正则、条件表达式、整数读取、规则引用及多规则命中。模块集合为 `pe`、`elf`、`math`、`time`、`string`、`console`、`tests`。构建不使用 OpenSSL，禁用 dotnet、magic、cuckoo、macho、dex，并显式取消注册 hash 模块以保持三平台一致；部分依赖密码学的 PE 功能不可用。未列出的模块、外部变量及模块数据不提供。原生 JSON 内部规则入口仍使用原有格式。

只接受完整 UTF-8 源码，不接受预编译规则；include 回调禁用。管理员可把审核后的多条规则合并成一个文件。源码最多 256 KiB、2,000 条规则、每条 1,000 个字符串、栈深 4,096。`meta: severity = 1..5` 可选，默认 4；类型或范围不符会导致就绪验证失败。命中按严重程度降序、规则标识符升序排列，第一条作为主检出名，最多保留 32 个不同规则标识符；超过上限拒绝整个文件结果。不会上传匹配字节、字符串位置、规则源码、任意元数据或 console 输出。

文件最多 20 MiB，扫描完整、已验证身份的普通文件字节；不解包压缩内容，不扫描进程内存，不执行规则中的外部程序。父进程负责打开文件、计算完整 SHA256、检查大小/身份/目录边界，将规则与文件字节通过管道发送给同一 Agent 可执行文件的专用工作入口。子进程不接收目标路径。父进程仅接受正常退出、版本一致且满足协议/规则标识符限制的结果，扫描后再次核对规则摘要。隔离与恢复沿用文件 SHA256 绑定及处置回执。

主动与实时扫描共用每个 YARA 客户端的串行门。每文件默认 10 秒，可设 1–30 秒，包含等待、编译、数据传递与扫描；父进程到期终止子进程。主动任务的总时间预算也覆盖首次就绪验证，沿用最多 2 小时、10 万文件、20 GiB 读取及路径排除规则。超大文件、编译失败、源文件变化、超时、资源不足、异常退出或不完整响应均报告失败，不依据部分原生结果隔离文件。

工作进程的 Go 软堆目标为 32 MiB。Linux 使用 `RLIMIT_DATA=192 MiB`（Linux 4.7+ 将私有匿名映射计入此限制）、CPU 30 秒、禁用 core；Windows 使用 Job Object 的 192 MiB 进程内存限制、单进程及关闭 Job 时终止。工作进程读取输入前确认实际分配限制已生效。该限制约束分配/提交内存，不能等同 Linux 全部 RSS 上限；Go 虚拟地址预留不算实际分配。子进程隔离和资源限制不构成抵御原生引擎漏洞的完整操作系统沙箱，管理员仍需审核规则、保护程序及源码，并维护引擎安全更新。

## 状态、任务和证据

Agent 心跳使用 `yara_contract=1` 报告受限状态。控制台的“YARA 引擎状态”区分正在验证、禁用、就绪、不可用、不支持、离线和过期；仅接受认证心跳，90 秒过期状态不允许创建新任务。就绪只说明最近编译检查通过，不代表主机文件已扫描。

创建任务时明确选择“原生 YARA”。每台主机固定 `YARA 4.5.8/sha256:<完整源码摘要>`，投递时再次检查就绪和版本。主动任务使用执行契约 4；旧 Agent 和默认无原生能力构建无法执行。服务端校验引擎、逐主机固定版本、文件大小、不同规则标识符、主检出名及执行结果一致性；非 YARA 任务不得报告原生规则命中。首次检出证据保留原生版本和全部匹配规则，后续隔离、恢复和重放不修改首次证据。

实时扫描还须在本机设 `realtime: true`，并启用平台周期检测策略。实时单次共享 2 秒/20 MiB 的内置、ClamAV、YARA 预算，沿用文件事件覆盖、周期补查、路径/哈希白名单与告警/隔离选项。原生失败时，有完整有效快照的内置引擎仍可独立判定；多个引擎读取的字节可能不同，最终操作始终使用该检出自身的 SHA256。

## 验证和许可

CI 独立运行三平台原生任务，保留 `yara-validation-linux-amd64`、`yara-validation-linux-arm64`、`yara-validation-windows-amd64`：源码版本/摘要、真实编译扫描、规则错误和超限、超时终止后恢复、OS 分配限制、隔离与恢复、实际文件事件、实际 Agent 的注册/mTLS/心跳/任务与失败回报。无害规则测试包含原生 text/hex/regex、整数读取、math 模块、多规则及超过 2 MiB 位置命中。SQLite、PostgreSQL 使用 V024 迁移，验证就绪、版本固定、回报拒绝、实时证据及首次证据保留；生产构建的浏览器检查保存桌面/手机截图。无害小规则不能证明任意规则集的兼容性、吞吐或恶意软件覆盖率。

YARA 使用 [BSD 3-Clause 许可](https://github.com/VirusTotal/yara/blob/v4.5.8/COPYING)。静态链接的原生产物与对应 `LICENSE-YARA.txt` 一同保留，分发时必须携带该版权/许可文本，并遵守构建工具链及各组件适用的许可要求。
