# XCCDF／OVAL 原生解释与离线内容审核

模块 14 在独立的「标准核查」页面导入 SCAP 内容。服务端使用 OpenSCAP 的 `xccdf resolve --force` 完成 XCCDF 标准加载与继承解析，目标 Agent 使用固定 SCC 5.15 运行原生 OVAL／CPE 探测。Profile 选择、变量覆盖、逻辑组合、定义继承及原生得分由标准解释器处理。

当前支持 Linux amd64、Linux arm64、Windows amd64。具体 OVAL 探针和目标系统的支持范围依 SCC 5.15；未支持的探针、权限不足和适用性结果保持可见。当前原生验收环境为 Ubuntu 24.04 两种架构和 GitHub Windows runner，不能据此宣称每一种发行版、Windows 版本或上游 Profile 均已验收。

## 离线内容格式

ZIP 根目录放置 `alinksec-scap.json`，其余文件为本地 XML。示例：

```json
{
  "schemaVersion": 1,
  "code": "ORGANIZATION-LINUX",
  "version": "2026.10.1",
  "name": "已审核的 Linux 主机标准",
  "osType": 1,
  "osVersionPattern": "ubuntu.*",
  "benchmarkFile": "content-ds.xml",
  "benchmarkId": "xccdf_org.example_benchmark_linux",
  "profileId": "xccdf_org.example_profile_server"
}
```

`osType` 为 Linux `1` 或 Windows `2`；`osVersionPattern` 是 RE2 全匹配表达式。包内必须恰好有一个 XCCDF 1.1／1.2 Benchmark，选定的 Profile 必须存在，规则 ID 不得重复。支持独立 Benchmark 和含本地 catalog 引用的 SCAP Data Stream。当前传输边界为压缩包 2 MiB、解压后 32 MiB、128 个文件和 2,000 条规则；超限内容须重新组织，不能静默截断。

导入前校验 UTF-8、ZIP 路径、XML 深度与数量、本地引用、内容身份及摘要。拒绝 DTD、外部实体、XInclude、xml:base、远程检查引用、SCE、内嵌脚本、修复脚本及 Shell／PowerShell／SQL 命令探针。OCIL 不自动代答，未完成的人工检查保留原生结果。链接式说明和 schemaLocation 不作为可下载的执行依赖。

导入保留上传 ZIP 的原始字节与 SHA256；执行包经过标准解析和确定性 ZIP 规范化，具有独立 SHA256。解析来源记录 OpenSCAP 实际版本、原始与解析后 Benchmark 摘要、原始规范包摘要。Agent 拒绝未标记 resolved 或仍含 extends 的执行内容。

原始包中的 XML 签名保留在原始下载中。派生内容改变字节，移除失效签名；当前信任依据是人工审核及固定摘要，不声称验证了上游 XML 签名。审核者必须分别查看内容来源、原始包和下发包。

## 内容审核与任务

管理员导入待审核内容并填写批准／拒绝说明。批准后选择 1～10 台系统适用、在线且原生引擎就绪的主机测试。测试需要完整结果且所有主机均无 error／unknown 才能发布；fail 表示规则检测到不符合项，可用于证明内容确实执行。发布不代表测试主机合规。

管理员或操作员可对已发布内容创建任务，单次最多 20 台主机。观察员可查看内容、引擎状态、任务和证据并下载。审核记录绑定 JWT 操作人及修订号；并发审核拒绝过期修订。同编号同版本重新导入仅接受相同规范原始内容。

任务冻结执行 ZIP、两种内容摘要、Benchmark／Profile、规则清单、解析来源、目标集合及各主机运行时摘要。撤回、被新版本替代或后续内容变化不会改变历史任务。就绪状态必须来自近期原生版本探测及心跳；过期、离线、错误版本、未启用和运行中主机不能作为新任务目标。

V027 为 SQLite／PostgreSQL 增加六张独立表；旧基线任务与等保条款复核记录继续可读。迁移总数为 27，应用表及迁移记录表合计 76。

## 安装与启用

服务端镜像包含发行版提供的 OpenSCAP 和 util-linux。当前 Jammy 镜像由 `libopenscap8` 提供 `/usr/bin/oscap`；Ubuntu 24.04 的原生验证安装 `openscap-scanner`。裸 JAR 部署同样需要 `/usr/bin/oscap`、`setsid`、`prlimit`、`setpriv`。解析在临时目录中完成，最多一个解析进程；root 服务端会降为 nobody 执行解析。外层设置地址空间、数据段、CPU、文件大小、描述符和 15 秒单次执行上限。原生解析发生在数据库写事务之前。

Agent 默认未启用 SCC。管理员手动运行 `python3 deploy/baseline/scap/install-runtime.py <安装目录>`（Windows 使用对应 Python 命令），安装器从发布者固定地址获取 SCC 5.15，校验官方 bundle、内部归档和 CLI 的 SHA256，生成 `alinksec-runtime.json`。保留整个原生运行目录及 Documentation 中的许可证和第三方说明；不会安装系统服务或启用随包附带的基准内容。此步骤属于显式本地安装，不是自动更新机制。

将生成清单的 SHA256 和实际包含 cscc／cscc.exe 的绝对目录写入 Agent 配置：

```yaml
scap:
  enabled: true
  runtime_dir: /opt/alinksec-scap/scc_5.15
  runtime_sha256: "替换为实际 alinksec-runtime.json 的 64 位小写 SHA256"
  timeout_sec: 600
```

Windows 使用相应绝对路径。沿用 Agent 的 `config apply` 审批配置，再重启进程生效；平台指令不能替换本地批准的运行时或摘要。启用需要目标系统管理员／root 权限。清单最多 4,096 个文件、512 MiB，每个文件均逐次验摘要并通过受保护路径读取；运行副本只包含清单列出的文件。

每次任务使用独立工作进程与私有运行副本，关闭外部文件下载、应用与内容更新、补救操作及无关报告。Linux 的 SCC 启动器不支持应用路径含空格，因此执行副本使用 `/tmp` 下原子创建的 0700 私有目录，不依赖 Agent 工作目录或 TMPDIR；Windows 使用系统临时目录，并通过系统 API 将 DOS 短路径展开为长路径，以满足原生选项 schema。执行环境只允许必要的系统路径、Windows 账户／计算机名和用户目录，不继承 Perl 模块搜索变量。Agent 工作目录和经批准的原生安装源可含空格。父进程在任务结束或取消、清理进程树之后删除运行副本。执行期间检查工作目录预算；只接受新建且唯一、与指令内容／Benchmark／Profile 绑定的完整 XCCDF 结果。SCC 即使返回零退出码，也可能没有有效结果，因此必须验证结果而非只看退出码。原生 stderr 非空时整次执行失败。

Agent 与其他重任务共用执行槽并纳入资源反馈。Linux 限制每进程数据段 256 MiB、CPU、文件大小和文件描述符，取消时清理进程组；Windows 使用总内存 384 MiB、最多 16 个进程及关闭时终止的 Job Object。超时默认 600 秒，可配置 30～1,200 秒；工作目录、报告数量及字节数另有上限。Linux 数据段限制不是整个进程组的总 RSS 上限，现场仍应按主机资源规划任务。

## 结果与证据

九种 XCCDF 结果分别保留：pass、fail、error、unknown、notapplicable、notchecked、notselected、informational、fixed。页面同时显示标准名称和中文含义；fixed 不改写为 pass。原生模型得分保留 system、value、maximum，不用简单通过率替代。

报告绑定主机、任务、指令、执行契约、内容摘要、Benchmark／Profile、引擎版本和运行时摘要；规则集合必须完整，无重复且得分有限。失败执行不携带部分成功结论。指令 DONE、FAILED 或超时占位不构造核查证据；第一份真实结果冻结保存，晚到真实结果可替换无证据占位。最近 1,000 条已完成指令的最终 ACK 与指令内容摘要以有界私有记录持久化，重启后重放 ACK，不重复执行探测。中断且尚无最终记录的只读指令允许重新执行；更早已淘汰指令不提供永久去重承诺。

证据包含标准结果、权重、原生得分和原生 XCCDF 文件的 SHA256。不会上传 OVAL collected host values，也不提供原始 ARF 导出。保存的规范证据可原样下载，附件响应提供 SHA256；网页再次校验后才保存文件。

## 验收证据

独立原生流程使用生产 OpenSCAP 解析含继承关系的原始 Profile，随后在三个目标平台运行 SCC，观察临时文件；验证外部变量、local concat、AND、否定、extend_definition、取消选择和 CPE 不适用结果。独立 Agent 工作者及实际 Agent 注册／mTLS 指令、结果上报、重启去重和错误运行时摘要路径也必须通过。

Java 测试覆盖真实迁移和事务、错误绑定、完整结果集合、错误状态、迟到报告及审核发布门槛。SQLite／PostgreSQL REST 与网页用明确标记的协议结果夹具覆盖九种结果、角色、修订竞争、下载摘要、撤回后快照、就绪状态和移动布局；这些夹具不是原生合规证明。模块状态、完整 CI 和原始产物验收记录保存在模块检查点；全部必需验证完成后才合并。

参考：[NIST XCCDF 1.2](https://csrc.nist.gov/publications/detail/nistir/7275/rev-4/final)、[OpenSCAP 原生 resolve 实现](https://github.com/OpenSCAP/openscap/blob/main/utils/oscap-xccdf.c)、[NIWC Atlantic SCC](https://www.niwcatlantic.navy.mil/Technology/SCAP/)、[SCC 5.15 发布者摘要](https://dl.dod.cyber.mil/wp-content/uploads/stigs/txt/SCC_5.15_Checksums.txt)、[Ubuntu Jammy oscap 文件来源](https://packages.ubuntu.com/jammy-updates/arm64/libopenscap8/filelist)。
