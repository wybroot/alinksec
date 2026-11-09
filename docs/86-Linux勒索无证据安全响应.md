# Linux 勒索无证据安全响应

日期：2026-11-09。基于 v0.0.4 源码 `b40dc90895ff6dde30e730af7000b7b773e18234`；修复分支 `fix/rev-011-linux-ransom-attribution`。本项对应复查编号 REV-011，当前 **VERIFY**。

## 问题与行为

原 Linux 归因把同目录文件句柄持有者，或近期启动且 PID 较大的进程当作写入者，随后可以终止其整个进程树。这些条件不能证明实际写入，存在中断无关业务的风险。

本批删除上述候选选择与回退。在没有可信文件操作来源、没有与当前进程实例绑定的写入证据时，Linux 不选择终止目标，终止闭包也明确拒绝执行。该限制同时适用于诱饵和速率触发：

| 配置 | 本批 Linux 行为 |
| --- | --- |
| `alert_only` | 告警与取证，不终止进程 |
| `kill` | 告警与取证，不终止进程 |
| `kill_and_isolate` | 不终止进程，主机隔离仍按既有配置独立执行，最终结果如实报告 |

告警详情保存 `source=linux_writer_evidence`、`status=unavailable`、`reason=writer_evidence_unavailable`。防护配置和告警证据弹窗说明缺少写入者证据，不能显示为“已结束进程”。Windows 继续使用内核文件 ETW 和进程实例复核，不使用 Linux 回退逻辑。

这只是消除无证据误杀路径，**尚未实现 Linux 可信写入者采集或准确自动终止**。该能力继续登记为 BKL-055，后续须对指定内核／架构的实际文件操作来源、进程实例、丢事件、并发写入、权限及资源成本单独设计和验收。既定防护目标不因本次安全降级而被记为完成。

## 本地验证

所有本地验证串行，保留已有用户服务；本任务未启动应用服务器。临时 Go 1.24.13 工具链通过官方 SHA256 核验。Go 构建及测试使用一个工作线程、256 MiB Go 堆与资源看护：最低可用内存 384 MiB、full memory PSI 10%、进程组 RSS 上限 640 MiB。

- `go test -p 1 -count=1 -timeout=3m ./internal/guard`：通过。
- `go test -race -p 1 -count=1 -timeout=3m ./internal/guard`：通过。
- 新增 `TestNativeLinuxRansomAttribution`：只读目标、只读／可写邻居、写后关闭、写入者退出、多个写入者、目标缺失及无文件共 8 类。每类存在近期无关进程及其子进程；三种响应配置均不选 PID，终止闭包拒绝动作。`kill`／`alert_only` 的诱饵和速率事件仍产生告警及取证，测试进程与后代仍存活。开发机没有执行主机隔离或生产终止函数。
- 原生测试生成 `.tmp/linux-ransom-native/event.json`，供浏览器按 API 行格式回放；该方式验证展示，不冒充数据库取回证据。
- `web` 现有 `node --test test/*.test.js`：5 个测试文件通过。
- 全量前端构建在 256 MiB 堆上限失败，未增加限制或反复重建。当前源码 Alerts／RansomAttribution 的单页面预览构建通过。
- 首轮浏览器因主机缺少 `libatk-1.0.so.0` 等库无法启动。续接时仅从系统软件源下载 12 个库包并解包至 `/tmp/alinksec-browser-libs`，不安装宿主机软件；用 `LD_LIBRARY_PATH` 为测试进程指定。补齐字体前截图没有实际绘制文本，早期 DOM 断言不计为视觉验收；随后临时解包 Noto CJK／DejaVu 字体，通过 `FONTCONFIG_FILE=/tmp/alinksec-fonts.conf` 指定后重跑。
- `node test/linux-ransom-browser.mjs`：单页面预览通过，回放原生 Agent 事件，验证 viewer／operator、Linux 未归因说明、实际仅告警、无虚构进程证据及移动端布局。截图已人工复核文字可读、无横向溢出。
- `node test/windows-ransom-browser.mjs`：单页面预览通过，回放 Java／SQLite 实际查询 fixture，覆盖读取失败重试、已归因／未知／多写入者／Linux 不可用、精确进程实例区分、viewer／operator 和移动端弹窗。字体补齐后的截图已复核。
- 两组检查串行，每次一个 Chromium，沿用 640 MiB RSS、384 MiB 最低可用内存和 full PSI 10% 看护；临时浏览器及回环预览均已退出。结果／截图分别在 `.tmp/linux-ransom-browser/`、`.tmp/windows-ransom-browser/`，范围为当前源码单页面预览，**不替代完整生产 bundle 或原生 Windows 进程响应验收**。
- Java／SQLite `WindowsRansomIntegrationTest`：3 项测试通过，0 失败／错误／跳过。使用现有 Maven 3.9.9／Java 21 Alpine 镜像，单个一次性容器限制 640 MiB／单 CPU；Maven 堆 256 MiB，测试堆 192 MiB。首轮缺少 gRPC 生成器所需 glibc 兼容层，第二轮仅在容器安装 gcompat 后成功；容器已自动清理。命令：`mvn -B -q -pl alinksec-bootstrap -am -Dtest=WindowsRansomIntegrationTest -Dsurefire.failIfNoSpecifiedTests=false -DargLine=-Xmx192m test`。
- 原始 Surefire XML 与本地结果汇总保留在 `.tmp/rev011-validation/`，Java 数据库取回 fixture 在 `.tmp/windows-ransom-fixtures/`。这些本地证据不替代远端 CI。

## 待远端验收

用户已选择本轮先完成本地修复与验证，保留远端验收。当前主机没有 GitHub 认证，未创建 PR、推送、合并、发布或部署。

CI 新增 Linux 双架构的具名原生回归、真实 Agent 告警回放浏览器检查及证据留存；既有 Windows 归因测试保留。新增 Java 测试保存未归因告警并生成 Linux API 响应 fixture，已有 Windows 浏览器用例同时核对 Linux 降级展示。

后续须在精确提交上完成完整 CI：Linux amd64／arm64、Windows 安全响应、SQLite／PostgreSQL 持久化、生产前端构建及桌面／移动浏览器。通过后再按工作流 review、创建 PR、合并并验收精确 merged-main CI。本项保持 VERIFY，不能以本地绿灯直接关闭或称为生产可用。
