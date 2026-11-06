# Cloudflare 迁移

迁移目标是让 subs-bot 的 Telegram 处理、订阅与分享数据、导出和后台任务都运行在 Cloudflare。Telegram、GitHub、订阅提供方和已配置的可信短链服务仍是业务接口。完成切换后，服务无需维护者管理 VPS、轮询进程或外部数据库。

## 首个隔离环境

首个 Worker 切片只包含 D1 元数据、私有 R2 快照和只读 HTTP 路径。隔离验证使用本项目专用 `workers.dev` 主机名和合成数据。

| 路径 | 首个切片的行为 |
| --- | --- |
| `GET` 或 `HEAD /health` | 返回部署的 40 位 Git commit SHA，供部署验收核对 |
| `GET` 或 `HEAD /sub/{token}/{format}` | 读取当前已发布快照并导出已有 URI，支持 `base64`、`v2ray` 和 `mixed` |

能力链接视同凭据。成功与失败响应均使用 `Cache-Control: no-store, private`、`Referrer-Policy: no-referrer` 和 `X-Content-Type-Options: nosniff`。`HEAD` 执行同样的预检并返回相同状态，响应体为空。未知能力链接返回 `404`，未支持的导出格式返回 `406`，节点缺少可导出的分享 URI 或分享文本超过 16 MiB 返回 `422`。若预检时发现已引用的快照不可用或校验失败，返回 `503`。

`GET` 在预检时验证已选定的快照并计算编码长度。通过后再读取同一个不可变快照，按原有块顺序编码，通过 `FixedLengthStream` 发送。两遍读取各自最多同时预读四个块，下游消费一块后再补下一块。若第二遍读取在成功响应头发出后失败，响应流会中止，客户端应把读取错误或未读满声明长度视为失败。响应流取消后停止补读，已发出的存储请求可能仍会完成。 [Workers FixedLengthStream](https://developers.cloudflare.com/workers/runtime-apis/streams/transformstream/#fixedlengthstream) · [Workers Content-Length](https://developers.cloudflare.com/workers/runtime-apis/response/#set-the-content-length-header)

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
| 现有缺陷修复 | 在 Python 服务上独立修复凭据作用域、结构化导出和 Hysteria 2 文本导入。由 GitHub 托管 runner 复现并验证，迁移以合并后的代码及样例为基准。 |
| 隔离 HTTP 与存储 | 将首个切片单独提交。GitHub 构建和测试后，将对应提交的不可变产物部署至项目隔离 Worker。用真实绑定验证提交 SHA、成功导出、内容完整性、错误状态和能力边界。 |
| 隔离发布与迁移基线 | 在 GitHub 托管 runner 上复核合并产物的来源和摘要。先识别已有 D1 结构和迁移历史，再登记或增量升级。重复触发同一版本应得到相同结果。 |
| Telegram 与权限 | 在已验收的存储模型上加入 Webhook、持久收件箱和发件箱、用户和会话隔离、管理员授权、私密领取，以及对应的并发和故障测试。用明确归属的测试 Bot 和测试会话验收。 |
| 导出、导入和刷新 | 补齐聚合、短链、临时节点、回收站、路径规则、流量与到期、内联与格式转换。加入可恢复的批量刷新。真实提供方必须通过隔离环境出网测试，再开启远程订阅拉取。 |
| 容量与数据迁移 | 比较旧 SQLite 正文与转换后快照和分享原文的实际字节数。先用云端合成样本验证容量边界、并发与失败，再对获准的真实备份做隔离恢复、数据对账和双账号验收。 |
| 生产切换 | 核对切换窗口、旧服务写入边界、域名、Telegram 和回滚步骤。获得生产切换决定后执行。 |

### 功能对照与阶段边界

| 功能 | 迁移与验收路径 |
| --- | --- |
| 订阅列表、重命名和回收站 | D1 所有者范围内分页和条件写入。Telegram 的 `/list`、`/expire` 和 `/recycle` 支持只读翻页，详情、重命名、删除和恢复交互另行接入。 |
| 私聊、群聊、内联及授权 | Webhook 和 D1 记录更新与授权。用指定管理员、普通用户和测试群验收；后续增加持久会话状态、按钮与内联更新。 |
| 私密分享 | 单独迁移有效期、指定用户、份数及领取事务。验证重复领取、争抢最后一份、撤权及过期。 |
| 导入、格式与链接 | 覆盖 URL、文档、文本与 Base64 导入。补齐旧路径、协议及 Clash、Sing-box、Surge、Quantumult X 格式，再接入聚合、短链、路径映射和临时节点。旧链接和授权由迁移对账验证。 |
| 更新、批量任务与搜索 | 持久任务记录进度、重试和恢复；上游失败保留上一版快照。对照旧 Bot 的搜索和导出入口，用获准的真实提供方验证出网。 |
| 备份与交接 | 在独立恢复目标核对 D1 元数据、R2 清单、账号归属、旧能力和完整字节，演练版本回滚后再准备切换。 |

回收操作在同一 D1 事务内将订阅元数据移出活动表。旧 Worker 在回滚时也无法用活动查询读取已回收订阅。恢复保留原 ID、能力令牌、快照指针及到期和流量信息，便于继续使用原链接和 R2 对象。回收站显示和恢复均以 D1 时间为准，保留 30 天的操作窗口。超出窗口的元数据和 R2 对象留待受控清理。已开始的导出可以继续读取原快照，后续请求需要重新查询活动表。

重命名、回收和恢复增加订阅生命周期版本。发布快照时同时检查节点代数与生命周期版本，避免延迟任务跨过回收和恢复边界覆盖当前快照。回滚只切换已验证的 Worker 版本，保留增量表，后续重新部署仍使用完整的迁移历史。

### Telegram 收件、发件与权限验收

- 隔离入口 `/telegram/webhook` 首批接收 `/start`、`/help`、`/list` 和 `/auth`。只接受指定测试 Bot 的两个用户及指定群。管理员在自己的私聊管理另一名测试用户的授权，群消息和普通用户的响应不显示授权详情。群和私聊的订阅读取都使用发起者的用户 ID。
- Webhook 仅接收指定路径上的 HTTPS POST，以恒定时间比较核对 `X-Telegram-Bot-Api-Secret-Token`，限制请求大小及允许的 update 类型。用 `(bot_id, update_id)` 唯一键持久记录更新。提交后返回 `2xx`，已持久化的重复更新也返回 `2xx`。暂时无法持久化时返回可重试错误。接受乱序更新，去重保留期覆盖重投窗口。 [Telegram `Update`](https://core.telegram.org/bots/api#update) · [Telegram `setWebhook`](https://core.telegram.org/bots/api#setwebhook)
- 收件记录只保留归属、消息 ID 和已识别的命令。授权变更和回复意图与收件记录在同一 D1 事务提交。同一用户和聊天的回复按入库顺序处理。发送前复核授权，已经发起的外部请求无法撤回。只有明确的 Telegram 限流拒绝可在到期前重试。超时和无法确认的发送标记为 `uncertain`，保留以供核对。 [D1 事务批处理](https://developers.cloudflare.com/d1/worker-api/d1-database/#batch) · [Telegram `ResponseParameters`](https://core.telegram.org/bots/api#responseparameters)
- 只读视图每页至多八条，按订阅 ID、到期时间或删除时间翻页。按钮只传随机值，D1 仅存摘要，绑定原发起人、聊天、话题、已确认发送的消息和尝试号，十分钟内只能消费一次。回调去重、按钮消费和下一页回复同批提交。回滚至支持回执标记的版本时，普通命令继续处理，视图回执留待新版处理。 [Telegram `CallbackQuery`](https://core.telegram.org/bots/api#callbackquery)
- 用户数据按 Telegram 用户 ID 归属，私聊和群聊共用其个人数据。重命名、翻页等交互使用 `(user_id, chat_id)`，内联查询以发起人身份授权。管理员、初始白名单和显式授权覆盖沿用现有语义。授权撤销应在下一次检查生效，权限变更和受保护的写入要用数据库条件约束，避免旧授权快照继续写入。
- 私密领取保留现有的分享能力语义。`0005` 按 Bot 存储分享码摘要，使用独立的私有 R2 对象保存最多 64 KiB 的私密正文。领取前核对正文长度、摘要和 UTF-8，D1 在同一事务复核到期、指定用户及剩余份数，以 `(share_id, actor_id)` 唯一键记录领取。份数以实际领取记录计数，已成功领取的用户在有效期内可再次查看。此存储阶段的 GitHub 验证覆盖竞争、重复和损坏正文，Telegram 分享入口与真实领取另行接入。
- 在业务变更的事务内写入待发送动作，用稳定动作 ID 去重。消费者持有租约并跟踪 Telegram 返回的消息 ID，成功后更新发件箱。对网络超时后可能已送达的动作标记结果不明，按动作类型恢复或人工核对。Telegram 发送接口没有通用幂等键，验收须覆盖收到成功响应后写回失败的情形。 [Telegram `sendMessage`](https://core.telegram.org/bots/api#sendmessage)

### 刷新与出网验收

- 刷新任务保存订阅、发起人、期望版本、尝试次数和错误类别。租约带过期时间及递增凭据，过期消费者的写入由条件检查拒绝。队列消息重复投递时复用同一任务。重试按错误类别退避并遵守提供方限速，耗尽后进入死信或可审计的失败状态。用 Cron 补发已入库但未成功入队的任务。拉取或解析失败只记录错误状态，上一份有效快照继续服务。 [Queues 重试与死信](https://developers.cloudflare.com/queues/configuration/batching-retries/)
- 任意用户 URL 开放前，验证 HTTP(S) URL、允许端口和重定向策略。每一跳重新解析 A/AAAA，拒绝私有、环回、保留及混合公网和私网结果，并确保实际连接到通过检查的 IP，同时保持原 Host、TLS SNI 和证书校验。带凭据的请求禁止将凭据转发至新来源。延续现有解压后 10 MiB 上限，并对上传、重定向次数、总耗时、节点数和 YAML 深度或别名设置限额。
- Worker `fetch()` 的 `resolveOverride` 有同 Zone 限制，预先查询 DNS 后再调用普通 `fetch()` 无法证明连接使用了已审查的 IP。Workers TCP 又限制对 Cloudflare IP 的直接连接。先在隔离环境验证平台支持的安全拨号方案和真实提供方。若无法同时满足地址固定、TLS 校验和兼容性，再使用项目专用 Cloudflare Container 承载受控抓取，并按需复用 Python 解析。Container 通过 Worker 内部入口接收有界任务，使用逐跳地址校验、网络策略和默认拒绝的出网边界。持久数据仍在 D1 和 R2。 [Workers Request](https://developers.cloudflare.com/workers/runtime-apis/request/#the-cf-property-requestinitcfproperties) · [Workers TCP](https://developers.cloudflare.com/workers/runtime-apis/tcp-sockets/) · [Containers 出网](https://developers.cloudflare.com/containers/configuration/outbound-traffic/)
- 测试包括实际提供方的鉴权、重定向、编码、流量头、IPv4/IPv6、阻断行为与限速。输出只记录分类结果和耗时。覆盖 DNS 重绑定、跨来源重定向、压缩超限和异常 YAML，并核对失败不会改变旧快照。真实联调使用获准的测试订阅和会话。

## 部署、数据迁移和回滚

### 隔离环境发布

1. 在 GitHub 建立仅允许 `main` 的 `subs-bot-isolation` Environment。将核对过的资源标识保存为此环境的 Secret `SUBS_BOT_CF_ISOLATION_TARGET_JSON`，包含 `accountId`、`workerId`、`workerCreatedOn`、`d1Id`、`d1CreatedAt`、`r2CreatedOn` 和 `namespace`。把数据和 Worker 部署凭据分别保存在此环境的 `SUBS_BOT_CF_BOOTSTRAP_TOKEN`、`SUBS_BOT_CF_DEPLOY_TOKEN`。普通 PR CI 和构建产物不使用这些凭据。 [GitHub Environment 保护规则](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments)
2. 查找当前 `main` 的成功 `Worker CI` 运行。若该提交只改动旧 Python 服务，先手动对 `main` 运行 `Worker CI` 生成同一 SHA 的产物。以该运行 ID 启动 `gh workflow run worker-isolation-deploy.yml --ref main -f source_run_id=<run-id>`。
3. 发布流程重新核对运行、提交、ZIP 摘要、包内文件清单及独立摘要，验证已登记的资源身份。D1 只接管结构完全一致且已清理合成数据的 `0001` 基线，使用 `subs_bot_schema_migrations` 记录已核对的摘要。后续通过同一流程应用增量建表和建索引。涉及现有数据或表结构变更时单独审查迁移和恢复步骤。 [D1 迁移](https://developers.cloudflare.com/d1/reference/migrations/)
4. Worker 的候选版本通过内容与绑定回读后才启用。记录实际版本、部署及 `/health` 中的提交。遇到不明确的写入结果，先读取实际状态；Worker 回滚仅恢复此前验证的版本，D1 和 R2 状态独立处理。 [Cloudflare Worker 回滚](https://developers.cloudflare.com/workers/versions-and-deployments/rollbacks/)
5. 含 `0002_telegram.sql` 的隔离版本从同一 Environment 的 `SUBS_BOT_TELEGRAM_TEST_CONFIG` 注入加密配置。配置包含已核对的测试 Bot、两个账号、测试群和 Webhook 密钥。Worker 就绪后配置每分钟 Cron，用于恢复持久回复。测试 Bot 的 Webhook 首次设置前，核对 Bot 身份和现有 Webhook；仅在目标是该隔离地址时接收 `message` 更新并保留待处理更新。真实账号的消息验收在内置浏览器执行。 [Workers Cron](https://developers.cloudflare.com/workers/configuration/cron-triggers/) · [Telegram Webhook](https://core.telegram.org/bots/api#setwebhook)
6. 发布含 `0004_telegram_views.sql` 的版本前，先确认已发布并记录支持回执标记的回滚版本。激活新版并核对实际版本后，只为同一隔离测试 Bot 将 `allowed_updates` 扩为 `message` 与 `callback_query`。保持已核对的 URL、Webhook 密钥和连接上限，设置 `drop_pending_updates: false`，用 `getWebhookInfo` 核对结果。回滚视图时先恢复只接收 `message`，保留增量表和待处理更新。 [Telegram Webhook 配置](https://core.telegram.org/bots/api#setwebhook) · [Telegram Webhook 回读](https://core.telegram.org/bots/api#getwebhookinfo)
7. 真人视图验收前，用 `gh workflow run worker-isolation-telegram-fixtures.yml --ref main -f action=seed -f cohort=<16位小写字母数字>` 生成指定两名测试用户的合成订阅和回收站记录。流程校验实际 Worker、D1、Telegram 配置摘要和迁移，并只写隔离 D1。真人消息及按钮只在内置浏览器验证。结束后以同一个 `cohort` 和 `action=retire` 删除本组记录，核对输出计数。

域级 Worker 路由核对使用单独的只读凭据。发布任务内使用项目专用凭据核对 Worker 的 Custom Domain、预览、日志、Cron 及实际数据绑定。 [Cloudflare Worker 路由 API](https://developers.cloudflare.com/api/resources/workers/subresources/routes/)

### 数据与切换

隔离容量检查使用当前 `main` 的已部署版本，手动运行 `gh workflow run worker-isolation-capacity.yml --ref main`。托管 runner 生成合成快照，依次验证恰好达到 64 MiB NDJSON 和 16 MiB 分享原文的有效输出、分享原文超 1 字节的拒绝、快照清单超 1 字节的拒绝。正向测试流式核对 Base64 长度和摘要，覆盖串行、并发 2 和 4、慢读及中途取消。发布和容量检查使用同一并发组，测试结束先撤销 D1 能力，再清理对应的私有 R2 对象。清理失败时，工作流保留不含凭据或原始能力令牌的恢复清单。

容量检查的客户端耗时和吞吐来自这组样本。CPU、内存和平台子请求数量通过隔离 Worker 的聚合指标另行核对。旧 SQLite 的正文体积与转换后的 NDJSON 和分享原文分别测量。真实备份的分布、超限项及可恢复性需要通过获准的数据演练验证。 [Workers 限制](https://developers.cloudflare.com/workers/platform/limits/) · [Workers 指标](https://developers.cloudflare.com/analytics/graphql-api/tutorials/querying-workers-metrics/)

1. 先只读核对 Cloudflare 目标账户、Zone、`subs-bot.lilyya.top` 的 DNS、Worker 路由和 Custom Domain 绑定。新资源记录账号、环境及资源 ID，隔离与生产分别使用各自的 Worker、D1、R2 和队列。现有配置冲突须在改动前报告。目标主机名可用且切换获准后，仅增加所需的 Custom Domain 绑定。 [Custom Domains](https://developers.cloudflare.com/workers/configuration/routing/custom-domains/)
2. `Worker CI` 在 GitHub 托管 runner 上安装依赖、检查类型、构建和测试。构建产物标记准确提交与摘要，由授权的部署步骤核对并上传至隔离 Worker。普通 PR CI 使用只读权限和合成数据。部署 Token 通过独立的受控步骤使用。云端 smoke 显式指定隔离环境和提交，核对 `/health` 与提交、已知测试快照的输出和负面用例。分别记录测试、构建、部署和真实运行结果。
3. 对旧 SQLite 执行一致性备份并确认 WAL 已纳入。生成受保护的迁移清单，在隔离环境恢复。校验每类记录数、用户归属、节点数和摘要，以及有效订阅 Token、短码和仍有效的领取记录。分开处理活动订阅、回收站、路径、临时节点、授权覆盖、分享与领取、短链。旧群级数据存在时由维护者确认归属，跨域链接依赖另行核对。
4. 备份须同时保存 D1 元数据和清单引用的 R2 对象。保存 D1 导出或恢复书签、R2 清单及摘要，并在项目专用隔离环境演练还原。Workers Paid 的 D1 Time Travel 可用于最近 30 天的原地恢复，会覆盖目标 D1；它不能还原 R2。恢复前冻结写入并确认 D1 与 R2 指向同一备份代。 [D1 Time Travel](https://developers.cloudflare.com/d1/reference/time-travel/)
5. 生产切换前冻结旧写入、完成最后一次同步、验证旧链接和授权，再切换 Telegram Webhook 或流量。保留待处理更新，先处理旧轮询目前配置 `drop_pending_updates=True` 的回滚风险。验收失败时先停止新写入，核对是否需要回放迁移后写入，再恢复已审核的旧入口和 Telegram 模式。仅回滚 Worker 版本无法回滚 D1 或 R2。 [Telegram `setWebhook` / `deleteWebhook`](https://core.telegram.org/bots/api#setwebhook) · [Worker 版本与部署](https://developers.cloudflare.com/workers/versions-and-deployments/)

## 限额、成本和凭据

- Workers Paid 的 Worker 内存为每 isolate 128 MB，由同一 isolate 中的并发请求共享。HTTP CPU 默认 30 秒，可配置至 5 分钟，每次调用默认最多 10,000 个子请求，R2 和 D1 绑定请求也计入。D1 单个字符串、BLOB 或数据行上限 2,000,000 字节，Paid 单库上限 10 GB。Queues 单条消息上限 128 KB。 [Workers 限制](https://developers.cloudflare.com/workers/platform/limits/) · [D1 限制](https://developers.cloudflare.com/d1/platform/limits/) · [Queues 限制](https://developers.cloudflare.com/queues/platform/limits/)
- 一个有 `N` 个数据块的快照，每遍读取包含一次清单读取和 `N` 次数据块读取。完整 `GET` 执行 `2 × (N + 1)` 次 R2 Class B 读取，并重复校验和解码。`HEAD` 只进行预检。隔离环境的正确性 smoke 完成后，仍需以接近快照与导出上限的样本，在代表性的并发量、慢客户端和中途取消条件下测量首字节与完整响应耗时、吞吐、CPU、内存超限计数及实际 R2 子请求数。用实测操作数与请求分布估算成本，再决定是否调整块大小或请求限额。 [R2 Class B 定价](https://developers.cloudflare.com/r2/pricing/#class-b-operations)
- 成本按实测请求数与 CPU、D1 读写行数、R2 容量及对象读写、队列投递与重试计算。若启用 Container，再核对实例运行时间、内存和磁盘配额、活动 CPU、区域出网及关联 Durable Objects 用量。隔离验收以按需启动和可睡眠为前提。显著新增费用或需要常驻时先提交估算和影响。 [Workers 定价](https://developers.cloudflare.com/workers/platform/pricing/) · [R2 定价](https://developers.cloudflare.com/r2/pricing/) · [Queues 定价](https://developers.cloudflare.com/queues/platform/pricing/) · [Containers 定价](https://developers.cloudflare.com/containers/platform/pricing/)
- 资源管理分开使用只读核查、派生 Token 创建和项目部署权限。新 Token 按目标账户、所需操作和有效期收窄。平台权限无法限定到单个资源时，执行步骤须核对项目专用资源 ID。应用通过绑定和 Secrets 使用运行所需权限。高权限管理凭据留在受控管理位置。 [Cloudflare API Token](https://developers.cloudflare.com/fundamentals/api/get-started/create-token/) · [Workers Secrets](https://developers.cloudflare.com/workers/configuration/secrets/)
- Worker、反代及其他链路避免记录能力路径、查询参数、Telegram 更新、订阅内容、鉴权头或上游异常正文。Cloudflare 自动 invocation 日志可能包含带凭据的 URL，发布前禁用或验证脱敏，并核对追踪、异常和外部转发的字段。允许的运行信号限于路由类别、状态、计数、耗时和内部操作 ID。私密数据和密钥不得出现在公共缓存、Git、构建产物或测试日志。 [Workers Logs](https://developers.cloudflare.com/workers/observability/logs/workers-logs/)
