# 服务集群（第 22／23 项）

此配置启用 PostgreSQL 上的应用多副本、Redis 会话租约和 RabbitMQ 持久队列。SQLite 保持单实例；普通部署无需 Redis 或 RabbitMQ。

## 拓扑与前提

`compose.yml` 提供两个应用副本、HAProxy 和 HTTPS 控制台。Agent 使用 9443 的 TLS 透传入口；控制台使用 8443，REST 仅在容器内部转发。HAProxy 根据 `/api/ready` 检查副本，示例将 Agent 优先送到 B，B 退出后转到 A。`/api/health` 只表示进程存活。

两个副本在同一 Compose 宿主机运行的示例只能应对应用进程故障。生产跨机可用性还需要：

- 外部 PostgreSQL HA 入口、经过备份恢复验证的数据卷和受限 `alinksec_app` 角色；每副本连接池至少 4，按负载预留更多连接。
- 一个可故障切换的 Redis 地址，支持认证、Lua、TTL 和非集群跨键操作。当前客户端使用单一地址，不提供 Redis Cluster 分片或 Sentinel 地址发现；可使用受管 HA 端点。配置 `noeviction` 并监测容量。
- 一个可故障切换的 RabbitMQ 地址，非 guest 用户，允许声明部署专用 durable quorum 队列及发布、读取和确认消息。生产 quorum 集群通常需要三个独立节点；入口需能连接存活节点。
- 所有应用副本挂载**同一份 POSIX 共享存储**，在容器内使用相同绝对路径 `/app/data`，支持原子重命名和私有文件权限。PKI、JWT、签名库、补丁、升级包、安全库工作目录以及节点探针全部共享。定期恢复演练须包含数据库和这份目录。
- 冗余入口、跨机编排与相同版本的应用镜像。示例的单 HAProxy、单 web 容器也需要在生产拓扑中消除单点。

Redis/RabbitMQ URI 密码至少 16 字符，推荐独立随机凭据；跨主机网络使用 `rediss://`、`amqps://` 及受信任的服务证书。AMQPS 显式校验证书链和主机名，使用 JVM 默认信任库；内部 CA 需预先加入两个副本共同使用的 JVM 信任库（可通过独立 Compose 覆盖文件挂载并配置 Java trustStore）。PostgreSQL 跨机连接也应通过部署覆盖项设置带 `sslmode=verify-full` 的 `SPRING_DATASOURCE_URL` 与受信任根证书。不要公开 PostgreSQL、Redis、AMQP 或内部 REST 端口。共享目录包含 CA 私钥，应限制给应用运行身份；web 只挂载叶证书目录。

## 首次初始化与启动

先按现有 PostgreSQL 安装步骤执行 `deploy/sql` 和全部 `deploy/migrations`，包括 V034；使用迁移脚本授予受限应用权限。不要使用数据库超级用户启动应用。迁移和材料变更都在停止全部应用的维护窗口执行。

在权限为 0600 的独立环境文件中设置以下变量，通过 `docker compose --env-file /secure/cluster.env -f deploy/cluster/compose.yml ...` 执行下列命令：

| 变量 | 含义 |
| --- | --- |
| `ALINKSEC_CLUSTER_SERVER_IMAGE`、`ALINKSEC_CLUSTER_WEB_IMAGE` | 从本版本构建、已验证的镜像引用 |
| `ALINKSEC_PG_HOST`、`ALINKSEC_PG_PORT`、`ALINKSEC_PG_USER`、`ALINKSEC_PG_PASSWORD` | 同一数据库 HA 入口、受限角色及密码，数据库名为 `alinksec` |
| `ALINKSEC_CLUSTER_REDIS_URI` | 同一 Redis HA URI，例如 `rediss://default:密码@地址:6379/0` |
| `ALINKSEC_CLUSTER_RABBIT_URI` | 同一 RabbitMQ URI，例如 `amqps://用户名:密码@地址:5671/%2F` |
| `ALINKSEC_CLUSTER_DEPLOYMENT_ID` | 一次性生成的小写 UUID，后续保持不变 |
| `ALINKSEC_CLUSTER_SHARED_PATH` | 已挂载共享卷的宿主机绝对路径 |
| `HOST_IP`、`ALINKSEC_BIND_ADDRESS` | Agent 可达入口名／IPv4，以及本机明确绑定的 IPv4 |
| `ALINKSEC_NODE_A_ID`、`ALINKSEC_NODE_B_ID` | 不同且稳定的节点 ID，默认 `node-a`、`node-b` |
| `ALINKSEC_BOOTSTRAP_ADMIN_PASSWORD`、`ALINKSEC_BOOTSTRAP_ENROLL_TOKEN` | 仅首次单进程初始化需要的管理员密码和注册码 |

1. 构建或获取已验证镜像：`docker compose ... build server-a web`。
2. **仅首次空部署**启动单进程初始化：`docker compose ... --profile initialize up -d --no-deps init`。等待 `/api/health` 成功、初始管理员写入数据库、共享目录生成 `certs`、`web-tls`、`jwt.secret`。初始化容器不公开端口，可在内部读取健康探针。已存在部署应先备份，并复用原 PKI/JWT，不重新生成身份。
3. 执行 `docker compose ... --profile initialize stop init`，确认所有旧单实例和应用副本已停止。初始化服务是常驻应用，必须显式停止。
4. 在能读写共享卷的主机执行 `python3 deploy/cluster/prepare-shared.py /实际共享目录 部署UUID`。它核对已生成材料、收紧私钥权限并独占创建部署标记，拒绝覆盖已有标记；外部提供 JWT 时，需给脚本传入与应用相同的 `ALINKSEC_JWT_SECRET`。
5. 执行 `docker compose ... up -d --no-deps server-a server-b`，确认两个副本 `/api/ready` 均为 200。然后执行 `docker compose ... up -d --no-deps entry web`。从 HTTPS 控制台的“系统管理 → 服务集群”检查节点、队列和失败报告。
6. 移除初始化密码／注册码变量。后续只启动集群服务。已经绑定集群身份的数据库会拒绝关闭集群模式后启动的单实例。

所有副本的数据库地址、依赖 URI、公共入口、业务配置、存储路径和 PKI/JWT 必须一致。节点 ID 和监听端口可以不同。应用同时核对 SQL／Redis 中的配置摘要和共享探针；缺失材料、重复活跃节点 ID、私钥权限过宽或不一致配置会启动失败。不要把单实例维护／恢复脚本直接用于运行中的集群。

## 处理边界与故障恢复

SQL 保存指令事实和会话代次，Redis 保存短期路由租约。更换连接、派发指令和当前流回执由 PostgreSQL 锁串行保护；失去会话或依赖协调能力的旧流关闭。所属节点每秒有界补推数据库待发送指令，节点恢复／Agent 重连后继续处理。

资产、基线结果和日志批次先持久写入 SQL 收件箱，再发布只含收件箱 ID 的 RabbitMQ 消息。处理器按 Agent 接收顺序消费，业务写入与已处理状态在同一事务提交，提交后确认 MQ。提示丢失或确认丢失通过 SQL 重发和幂等恢复。需要当前流即时确认的隔离、修复和取证等流程保留同步提交。普通 Agent 报告协议没有通用接收 ACK，因此排队恢复承诺从 **SQL 接纳成功**开始；不能将 Agent 写出流等同于服务端持久接收。

默认限制为每报告 1 MiB、待处理 10,000 条／128 MiB、历史 500,000 条。处理失败最多自动尝试 5 次，之后进入失败清单，不再阻塞该 Agent 的后续报告。停用／删除主机禁止应用排队事实。处理成功后立即清除原始字节，保留至少 10 分钟去重元数据；失败载荷最多保留 30 天。容量满或依赖故障会拒绝新接纳，不静默丢弃。管理员复核主机状态后，可以提交摘要和说明重试失败报告，最多 3 次；损坏载荷禁止重试；已有较新资产快照生效时，旧资产报告也禁止重放，应重新采集。消费端会再次核对，避免并发重试覆盖新事实。界面与日志不返回原始载荷或依赖凭据。

安全库同步使用跨副本可续期租约，每次发布核对所有权。新节点启动和存活节点的分钟轮询只在取得租约后恢复残留运行状态，重试沿用来源计划与退避。每周扫描和签名推送使用事务性自然时间槽。通知由 SQL 领取并绑定发送令牌；HTTP 使用稳定 `Idempotency-Key`，接收方应去重，远端响应丢失仍可能再次投递。

依赖、共享材料或探针故障会使 `/api/ready` 返回 503；运行中的依赖轮询每 5 秒执行一次，就绪缓存最多 15 秒。修复依赖后副本可以恢复就绪。默认节点／工作租约 45 秒；异常退出后的同名节点重启需等待旧租约过期。替代节点已取得身份时，旧进程必须退出后重新启动。

更换 PKI、JWT、业务配置或依赖 URI 会改变固定摘要，不能直接修改后重启或让新配置加入现有集群。当前支持相同配置重启，尚无配置摘要迁移工具。此类变更需专项离线迁移：停止**全部**副本和初始化实例、备份数据库与共享材料、确认旧租约过期，再使用针对目标版本审阅和验证的材料／SQL／Redis 迁移方案；必须保留部署 UUID、收件箱和指令事实。不要仅删除共享标记、单独清空摘要或将数据库改回单实例。升级不应假定支持滚动混用版本。

## 验证范围

`cluster` CI 在 AMD64、ARM64 独立 runner 上依次执行真实 PostgreSQL／Redis／RabbitMQ 集成用例，启动两个实际 Java 应用、原生 Agent 和这份 HAProxy 配置，验证跨节点指令、强杀所属服务后的重连、依赖重启、配置拒绝及回执恢复。AMD64 还使用实际数据库和 REST 捕获校验生产控制台的角色、重试、故障状态和移动布局。证据包含精确源码、镜像平台、Agent 摘要、测试报告及进程清理结果；不将单宿主验证描述成跨机或外部依赖 HA 演练。大规模负载能力由后续性能项单独测量。

依赖镜像使用 PostgreSQL 17、Redis 7.4.11、RabbitMQ 4.3.7、HAProxy 3.4.7；CI 核对实际多架构 manifest 并拉取对应平台。部署前固定受审阅的镜像摘要。版本依据：[RabbitMQ 支持信息](https://www.rabbitmq.com/release-information)、[Redis 官方镜像清单](https://github.com/docker-library/official-images/blob/master/library/redis)、[RabbitMQ 官方镜像清单](https://github.com/docker-library/official-images/blob/master/library/rabbitmq)、[HAProxy 官方发布信息](https://www.haproxy.org/)。
