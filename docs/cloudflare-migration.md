# Cloudflare 迁移

迁移目标是让 subs-bot 的 Telegram 处理、订阅与分享数据、导出和后台任务都运行在 Cloudflare。Telegram、GitHub、订阅提供方和已配置的可信短链服务仍是业务接口。完成切换后，服务无需维护者管理 VPS、轮询进程或外部数据库。

## 首个隔离环境

首个 Worker 切片只包含 D1 元数据、私有 R2 快照和只读 HTTP 路径。隔离验证使用本项目专用 `workers.dev` 主机名和合成数据。

| 路径 | 首个切片的行为 |
| --- | --- |
| `GET` 或 `HEAD /health` | 返回部署的 40 位 Git commit SHA，供部署验收核对 |
| `GET` 或 `HEAD /sub/{token}/{format}` | 读取当前已发布快照并导出已有 URI，支持 `base64`、`v2ray` 和 `mixed` |

能力链接视同凭据。成功与失败响应均使用 `Cache-Control: no-store, private`、`Referrer-Policy: no-referrer` 和 `X-Content-Type-Options: nosniff`。`HEAD` 保留 `GET` 的状态和响应头，响应体为空。未知能力链接返回 `404`，未支持的导出格式返回 `406`，节点缺少可导出的分享 URI 或分享文本超过 16 MiB 返回 `422`，已引用的快照不可用或完整性校验失败返回 `503`。处理在发送 `200` 之前校验快照，按块编码 Base64，避免生成一个完整的编码后字符串。

聚合、结构化节点生成分享 URI、其他导出格式、数据导入界面、Telegram Webhook、订阅拉取和生产域名属于后续阶段。

## 组件边界

- **TypeScript Worker** 处理 HTTP、Telegram Webhook、权限与任务编排，通过平台绑定访问 D1、R2 和未来的 Queues。现有 Python 逻辑及回归样例是迁移对照。Python Workers 使用 Pyodide，依赖与文件系统行为与目前的 CPython 服务不同。单独移植轮询、进程内锁和本地 SQLite 仍需重新设计数据和事件生命周期。 [Python Workers 标准库](https://developers.cloudflare.com/workers/languages/python/stdlib/) · [Python 依赖支持](https://developers.cloudflare.com/workers/languages/python/packages/)
- **D1** 保存用户归属、授权、订阅元数据、能力链接、操作状态和当前快照指针。列表与权限检查只读取必要列。授权与领取使用数据库约束和有条件写入，关键读从主库获取。 [D1 Binding API](https://developers.cloudflare.com/d1/worker-api/d1-database/) · [D1 读取一致性](https://developers.cloudflare.com/d1/best-practices/read-replication/)
- **私有 R2** 存储体积较大的节点快照和受控备份。对象通过 Worker 绑定读取。禁用公开访问和边缘缓存。 [R2 一致性](https://developers.cloudflare.com/r2/reference/consistency/) · [R2 限制](https://developers.cloudflare.com/r2/platform/limits/)
- **Queues 与 Cron** 在引入长任务时启用。Queues 传递短任务 ID，D1 记录实际进度及重试状态。Cron 按 UTC 调度到期刷新、补发和过期清理。需要按会话严格排序或按提供方节流时，先验证 D1 的条件写入和租约。只有在云端验证表明需要额外协调时，再引入 Durable Objects。 [Queues 投递语义](https://developers.cloudflare.com/queues/reference/delivery-guarantees/) · [Cron Triggers](https://developers.cloudflare.com/workers/configuration/cron-triggers/) · [Durable Objects 限制](https://developers.cloudflare.com/durable-objects/platform/limits/)

### 快照发布和恢复

1. 按订阅 ID 和随机快照 ID 写入一组不可变 NDJSON 对象，再写清单。清单按顺序记录每块的字节数、节点数和 SHA-256。
2. 所有对象写入成功后，使用订阅 ID、用户归属和上一代编号对 D1 进行条件更新，同时发布新快照 ID、清单摘要、节点计数和元数据。并发请求中只有一个写入能更新同一代。R2 写入失败或条件不匹配时，旧指针仍有效。
3. 读取时先核对 D1 中的清单摘要，再按顺序读取和校验各块。快照上限为 64 MiB、256 块、100,000 个节点。单块和单条记录分别最多 512 KiB，清单最多 64 KiB。HTTP 导出的 16 MiB 分享文本上限单独生效，并包含行分隔符。部署后用真实分布和并发验证这些上限适用。
4. 已发布旧版本和发布结果不明的候选对象先保留。确认发布失败时，可清理本次新写入且尚未发布的对象。启用历史版本回收前，必须确认对象未被活动订阅、回收站、回滚版本或备份引用，并超过约定的恢复期。桶生命周期规则只适用于可证明安全的备份或临时对象前缀。 [R2 生命周期](https://developers.cloudflare.com/r2/buckets/object-lifecycles/)

## 分阶段交付

| 阶段 | 依赖、变更和验收 |
| --- | --- |
| 现有缺陷修复 | 在 Python 服务上独立修复凭据作用域和导出。由 GitHub 托管 runner 复现并验证，迁移以合并后的代码及样例为基准。 |
| 隔离 HTTP 与存储 | 将首个切片单独提交。GitHub 构建和测试后，将对应提交的不可变产物部署至项目隔离 Worker。用真实绑定验证提交 SHA、成功导出、内容完整性、错误状态和能力边界。 |
| Telegram 与权限 | 在已验收的存储模型上加入 Webhook、持久收件箱和发件箱、用户和会话隔离、管理员授权、私密领取，以及对应的并发和故障测试。用明确归属的测试 Bot 和测试会话验收。 |
| 导出、导入和刷新 | 补齐聚合、短链、临时节点、回收站、路径规则、流量与到期、内联与格式转换。加入可恢复的批量刷新。真实提供方必须通过隔离环境出网测试，再开启远程订阅拉取。 |
| 数据迁移与生产切换 | 先对备份进行隔离恢复和端到端验收，再审核切换窗口、旧服务写入边界、域名、Telegram 和回滚步骤。获得生产切换决定后执行。 |

### Telegram 收件、发件与权限验收

- Webhook 仅接收指定路径上的 HTTPS POST，以恒定时间比较核对 `X-Telegram-Bot-Api-Secret-Token`，限制请求大小及允许的 update 类型。用 `(bot_id, update_id)` 唯一键持久记录更新。提交后返回 `2xx`，已持久化的重复更新也返回 `2xx`。暂时无法持久化时返回可重试错误。接受乱序更新，去重保留期覆盖重投窗口。 [Telegram `Update`](https://core.telegram.org/bots/api#update) · [Telegram `setWebhook`](https://core.telegram.org/bots/api#setwebhook)
- 用户数据按 Telegram 用户 ID 归属，私聊和群聊共用其个人数据。重命名、翻页等交互使用 `(user_id, chat_id)`，内联查询以发起人身份授权。管理员、初始白名单和显式授权覆盖沿用现有语义。授权撤销应在下一次检查生效，权限变更和受保护的写入要用数据库条件约束，避免旧授权快照继续写入。
- 私密领取保留现有的分享能力语义。检查到期、指定用户和剩余份数，使用 `(share_code, user_id)` 唯一约束在同一事务中记录领取及扣减。已成功领取的用户可在有效期内再次查看而无需扣减。并发测试必须覆盖同一人重试和不同用户争抢最后一份。
- 在业务变更的事务内写入待发送动作，用稳定动作 ID 去重。消费者持有租约并跟踪 Telegram 返回的消息 ID，成功后更新发件箱。对网络超时后可能已送达的动作标记结果不明，按动作类型恢复或人工核对。Telegram 发送接口没有通用幂等键，验收须覆盖收到成功响应后写回失败的情形。 [Telegram `sendMessage`](https://core.telegram.org/bots/api#sendmessage)

### 刷新与出网验收

- 刷新任务保存订阅、发起人、期望版本、尝试次数和错误类别。租约带过期时间及递增凭据，过期消费者的写入由条件检查拒绝。队列消息重复投递时复用同一任务。重试按错误类别退避并遵守提供方限速，耗尽后进入死信或可审计的失败状态。用 Cron 补发已入库但未成功入队的任务。拉取或解析失败只记录错误状态，上一份有效快照继续服务。 [Queues 重试与死信](https://developers.cloudflare.com/queues/configuration/batching-retries/)
- 任意用户 URL 开放前，验证 HTTP(S) URL、允许端口和重定向策略。每一跳重新解析 A/AAAA，拒绝私有、环回、保留及混合公网和私网结果，并确保实际连接到通过检查的 IP，同时保持原 Host、TLS SNI 和证书校验。带凭据的请求禁止将凭据转发至新来源。延续现有解压后 10 MiB 上限，并对上传、重定向次数、总耗时、节点数和 YAML 深度或别名设置限额。
- Worker `fetch()` 的 `resolveOverride` 有同 Zone 限制，预先查询 DNS 后再调用普通 `fetch()` 无法证明连接使用了已审查的 IP。Workers TCP 又限制对 Cloudflare IP 的直接连接。先在隔离环境验证平台支持的安全拨号方案和真实提供方。若无法同时满足地址固定、TLS 校验和兼容性，再使用项目专用 Cloudflare Container 承载受控抓取，并按需复用 Python 解析。Container 通过 Worker 内部入口接收有界任务，使用逐跳地址校验、网络策略和默认拒绝的出网边界。持久数据仍在 D1 和 R2。 [Workers Request](https://developers.cloudflare.com/workers/runtime-apis/request/#the-cf-property-requestinitcfproperties) · [Workers TCP](https://developers.cloudflare.com/workers/runtime-apis/tcp-sockets/) · [Containers 出网](https://developers.cloudflare.com/containers/configuration/outbound-traffic/)
- 测试包括实际提供方的鉴权、重定向、编码、流量头、IPv4/IPv6、阻断行为与限速。输出只记录分类结果和耗时。覆盖 DNS 重绑定、跨来源重定向、压缩超限和异常 YAML，并核对失败不会改变旧快照。真实联调使用获准的测试订阅和会话。

## 部署、数据迁移和回滚

1. 先只读核对 Cloudflare 目标账户、Zone、`subs-bot.lilyya.top` 的 DNS、Worker 路由和 Custom Domain 绑定。新资源记录账号、环境及资源 ID，隔离与生产分别使用各自的 Worker、D1、R2 和队列。现有配置冲突须在改动前报告。目标主机名可用且切换获准后，仅增加所需的 Custom Domain 绑定。 [Custom Domains](https://developers.cloudflare.com/workers/configuration/routing/custom-domains/)
2. `Worker CI` 在 GitHub 托管 runner 上安装依赖、检查类型、构建和测试。构建产物标记准确提交与摘要，由授权的部署步骤核对并上传至隔离 Worker。普通 PR CI 使用只读权限和合成数据。部署 Token 通过独立的受控步骤使用。云端 smoke 显式指定隔离环境和提交，核对 `/health` 与提交、已知测试快照的输出和负面用例。分别记录测试、构建、部署和真实运行结果。
3. 对旧 SQLite 执行一致性备份并确认 WAL 已纳入。生成受保护的迁移清单，在隔离环境恢复。校验每类记录数、用户归属、节点数和摘要，以及有效订阅 Token、短码和仍有效的领取记录。分开处理活动订阅、回收站、路径、临时节点、授权覆盖、分享与领取、短链。旧群级数据存在时由维护者确认归属，跨域链接依赖另行核对。
4. 备份须同时保存 D1 元数据和清单引用的 R2 对象。保存 D1 导出或恢复书签、R2 清单及摘要，并在项目专用隔离环境演练还原。Workers Paid 的 D1 Time Travel 可用于最近 30 天的原地恢复，会覆盖目标 D1；它不能还原 R2。恢复前冻结写入并确认 D1 与 R2 指向同一备份代。 [D1 Time Travel](https://developers.cloudflare.com/d1/reference/time-travel/)
5. 生产切换前冻结旧写入、完成最后一次同步、验证旧链接和授权，再切换 Telegram Webhook 或流量。保留待处理更新，先处理旧轮询目前配置 `drop_pending_updates=True` 的回滚风险。验收失败时先停止新写入，核对是否需要回放迁移后写入，再恢复已审核的旧入口和 Telegram 模式。仅回滚 Worker 版本无法回滚 D1 或 R2。 [Telegram `setWebhook` / `deleteWebhook`](https://core.telegram.org/bots/api#setwebhook) · [Worker 版本与部署](https://developers.cloudflare.com/workers/versions-and-deployments/)

## 限额、成本和凭据

- Workers Paid 的 Worker 内存为每 isolate 128 MB，HTTP CPU 默认 30 秒，可配置至 5 分钟，每次调用默认最多 10,000 个子请求。D1 单个字符串、BLOB 或数据行上限 2,000,000 字节，Paid 单库上限 10 GB。Queues 单条消息上限 128 KB。上线前用最坏体积和并发样例验证 CPU、内存超限计数、延时和实际子请求量。 [Workers 限制](https://developers.cloudflare.com/workers/platform/limits/) · [D1 限制](https://developers.cloudflare.com/d1/platform/limits/) · [Queues 限制](https://developers.cloudflare.com/queues/platform/limits/)
- 成本按实测请求数与 CPU、D1 读写行数、R2 容量及对象读写、队列投递与重试计算。若启用 Container，再核对实例运行时间、内存和磁盘配额、活动 CPU、区域出网及关联 Durable Objects 用量。隔离验收以按需启动和可睡眠为前提。显著新增费用或需要常驻时先提交估算和影响。 [Workers 定价](https://developers.cloudflare.com/workers/platform/pricing/) · [R2 定价](https://developers.cloudflare.com/r2/pricing/) · [Queues 定价](https://developers.cloudflare.com/queues/platform/pricing/) · [Containers 定价](https://developers.cloudflare.com/containers/platform/pricing/)
- 资源管理分开使用只读核查、派生 Token 创建和项目部署权限。新 Token 按目标账户、所需操作和有效期收窄。平台权限无法限定到单个资源时，执行步骤须核对项目专用资源 ID。应用通过绑定和 Secrets 使用运行所需权限。高权限管理凭据留在受控管理位置。 [Cloudflare API Token](https://developers.cloudflare.com/fundamentals/api/get-started/create-token/) · [Workers Secrets](https://developers.cloudflare.com/workers/configuration/secrets/)
- Worker、反代及其他链路避免记录能力路径、查询参数、Telegram 更新、订阅内容、鉴权头或上游异常正文。Cloudflare 自动 invocation 日志可能包含带凭据的 URL，发布前禁用或验证脱敏，并核对追踪、异常和外部转发的字段。允许的运行信号限于路由类别、状态、计数、耗时和内部操作 ID。私密数据和密钥不得出现在公共缓存、Git、构建产物或测试日志。 [Workers Logs](https://developers.cloudflare.com/workers/observability/logs/workers-logs/)
