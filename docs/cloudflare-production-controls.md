# 首次生产生命周期控制

这些工具只实现受保护的操作流程，不授予生产操作权限。正式执行前填写本页清单，在 GitHub 配置单独受保护的 `subs-bot-production` 和 `subs-bot-production-provider` environment，并取得准确目标与逐步操作的批准。测试环境不作为生产身份的默认值。

## 配置契约

`SUBS_BOT_TARGET_JSON` 由 `worker/tools/production_target.py` 严格解析。未知字段、缺字段、占位符、未知同名资源及不一致身份均拒绝。生产目标固定：

| 字段 | 要求 |
| --- | --- |
| `schemaVersion`, `environment` | `1`, `production` |
| `accountId`, `zoneId`, `namespace` | `9431815bdb8beb2272f6668e06b7d3be`, `07c83547944da720e03b31a406fdcd55`, `lilyya` |
| `workerName`, `d1Name`, `bucketName` | `subs-bot-cf-prod-01` |
| `backupBucketName` | `subs-bot-cf-prod-backup-01` |
| `hostname` | `subs-bot.lilyya.top` |
| `workerId`, `workerCreatedOn`, `d1Id`, `d1CreatedAt`, `bucketCreatedAt`, `backupBucketCreatedAt` | 独立读回的不可变 ID／创建时间；只有创建草稿允许这些值为 null |
| `botId`, `botUsername`, `generation` | 已通过 getMe 的新正式 Bot，ID 为小于 2^52 的正整数；授权世代为 1 至 2^53−1 的整数 |
| `admins`, `members`, `defaultAccess` | 每组至多 100 个、按 JSON 字符串字典序排序并去重的正式 ID；ID 为正整数且小于 2^52，至少一个管理员，两组互不重叠；`defaultAccess=deny` |
| `groups` | `[]` 或一个明确 `{chatId,chatType}`；目前单一群卡目的地，超限拒绝；预检实际 Bot 成员／发送权限 |
| `features` | 必须显式填写下述所有布尔开关，不推断默认启用 |
| `provider` | 关闭 URL 能力时可为 null；启用时填写独立验证的完整 ProviderFetch 契约，见 [依赖说明](cloudflare-production-provider.md) |
| `webhook` | `{allowedUpdates:[...],maxConnections:...}`；至少 message/callback_query；inlineSearch 开启时包含 inline_query；连接数 1–40 |
| `keyDigests` | aggregate/privateShare/webhook/shortlink 的 SHA-256；外部短链关闭时 shortlink 可为 null |

全部开关：`inlineSearch`, `providerUrlImport`, `providerUrlDocuments`, `mixedDocuments`, `providerRefresh`, `providerBatch`, `subscriptionShorts`, `externalShortlinks`, `groupShareCards`, `githubSearch`, `apiStatus`。首发 `apiStatus=false`。文档导入依赖 URL 导入，混合文档依赖 URL 文档。生产 ProviderFetch 使用独立 `subs-bot-provider-fetch-prod-01`，不自动接受 dev 身份。

正式 Bot 必须是独立的新身份。生产草稿和已登记目标同时拒绝测试用户名 `test_cfsubs_bot`（不区分大小写）及已核验的稳定测试 Bot ID `9293938370`；改名不能把同一个测试 Bot 变成正式身份。`getMe` 仍须独立核对正式配置的 ID 和用户名，缺失配置不会采用测试值。

固定资源／Bot／授权世代的 `targetSha256` 与完整 `configurationSha256` 分开。开关、依赖、Webhook 参数或 Secret 摘要变化必须重新批准配置；不能沿用旧批准。普通发布保持 aggregate/privateShare 签名密钥连续性，不提供隐式换钥或测试密钥复制。

`SUBS_BOT_CONTROL_SECRETS` 只通过受保护 environment 注入，含 `botToken`, `webhookSecret`, `aggregateKey`, `privateShareKey`, `shortlinkToken`。两个签名密钥必须分别是独立 32 字节密钥的规范 43 字符 Base64URL；Webhook Secret 使用 32–256 字符安全集合；短链启用时必须提供原有完整业务 Token。原始 Secret 不进入目标 JSON、CI 日志、候选或数据备份。

### 可填写的正式草稿模板

以下占位符会被严格拒绝，不能直接 dispatch。所有角色和开关必须由正式批准清单选择；这个关闭可选功能的草稿不表示已经选定首发功能。六个资源 pin 仅在创建草稿中为 null；创建后只从私有 journal 和独立读回填写，不能采用未知同名资源。未启用的外部短链 Token 和摘要都保持 null。

`SUBS_BOT_TARGET_JSON`：

```json
{
  "schemaVersion": 1,
  "environment": "production",
  "accountId": "9431815bdb8beb2272f6668e06b7d3be",
  "zoneId": "07c83547944da720e03b31a406fdcd55",
  "namespace": "lilyya",
  "workerName": "subs-bot-cf-prod-01",
  "workerId": null,
  "workerCreatedOn": null,
  "d1Name": "subs-bot-cf-prod-01",
  "d1Id": null,
  "d1CreatedAt": null,
  "bucketName": "subs-bot-cf-prod-01",
  "bucketCreatedAt": null,
  "backupBucketName": "subs-bot-cf-prod-backup-01",
  "backupBucketCreatedAt": null,
  "hostname": "subs-bot.lilyya.top",
  "botId": "REPLACE_WITH_FORMAL_BOT_ID",
  "botUsername": "REPLACE_WITH_FORMAL_BOT_USERNAME",
  "generation": 1,
  "admins": ["REPLACE_WITH_FORMAL_ADMIN_ID"],
  "members": [],
  "groups": [],
  "defaultAccess": "deny",
  "features": {
    "inlineSearch": false,
    "providerUrlImport": false,
    "providerUrlDocuments": false,
    "mixedDocuments": false,
    "providerRefresh": false,
    "providerBatch": false,
    "subscriptionShorts": false,
    "externalShortlinks": false,
    "groupShareCards": false,
    "githubSearch": false,
    "apiStatus": false
  },
  "provider": null,
  "webhook": {"allowedUpdates": ["message", "callback_query"], "maxConnections": 2},
  "keyDigests": {
    "aggregate": "REPLACE_WITH_INDEPENDENT_AGGREGATE_KEY_SHA256",
    "privateShare": "REPLACE_WITH_INDEPENDENT_PRIVATE_SHARE_KEY_SHA256",
    "webhook": "REPLACE_WITH_WEBHOOK_SECRET_SHA256",
    "shortlink": null
  }
}
```

`SUBS_BOT_CONTROL_SECRETS` 仅在安全注入渠道填写以下形状。生成新的独立生产签名密钥，再将其 SHA-256 填入上面的非 Secret 契约；不复制任何测试密钥。

```json
{
  "botToken": "REPLACE_WITH_FORMAL_BOT_TOKEN",
  "webhookSecret": "REPLACE_WITH_INDEPENDENT_WEBHOOK_SECRET",
  "aggregateKey": "REPLACE_WITH_INDEPENDENT_32_BYTE_BASE64URL_KEY",
  "privateShareKey": "REPLACE_WITH_ANOTHER_INDEPENDENT_32_BYTE_BASE64URL_KEY",
  "shortlinkToken": null
}
```

`SUBS_BOT_APPROVAL_JSON` 的初始化示例；后续每个 action 都重新绑定完整配置与独立前态。此模板不提供批准：

```json
{
  "schemaVersion": 1,
  "environment": "production",
  "targetSha256": "REPLACE_WITH_EXACT_TARGET_SHA256",
  "configurationSha256": "REPLACE_WITH_EXACT_CONFIGURATION_SHA256",
  "revision": "REPLACE_WITH_REVIEWED_APPLICATION_MAIN_SHA",
  "controlRevision": "REPLACE_WITH_CURRENT_CONTROL_MAIN_SHA",
  "action": "initialize",
  "stateSha256": "REPLACE_WITH_INDEPENDENT_RESOURCE_PREDECESSOR_SHA256",
  "authorization": "approve initialize for subs-bot-cf-prod-01"
}
```

## 凭据与批准

| Secret | 所需权限／用途 |
| --- | --- |
| `SUBS_BOT_CF_DATA_TOKEN` | 指定账户 D1 查询／创建及 R2 私有备份／恢复；生产资源预检还需账户只读身份。工具限制具体目标路径，不修改其他数据 |
| `SUBS_BOT_CF_WORKER_TOKEN` | 指定 Worker 版本、发布和 Cron；生产 Zone 只读核对；仅获批域名步骤才使用必要路由／域名权限 |
| `SUBS_BOT_CF_DEPENDENCY_READ_TOKEN` | ProviderFetch 实际 Worker／Container／Workflow 只读盘点；依赖开启而缺失时拒绝 |
| `SUBS_BOT_PROVISION_ANCHOR_JSON` | 已独立登记的私有项目证据桶 `{accountId,bucketName,bucketCreatedAt}`，保存创建前意图和每一步结果；不能只依赖 runner 临时文件 |
| `SUBS_BOT_APPROVAL_JSON` | 本次精确操作批准，见下文；不提供默认批准 |

平台不支持细分的权限应限制到唯一账户、使用短期凭据，并由工具的固定资源 allowlist、受保护 environment 和不取消的并发锁共同约束。需要新权限时先明确范围，不能借短链业务 Token、其他项目凭据或 `/ai` Key 代替。

批准 JSON 必须包含 `schemaVersion=1`, `environment`, `targetSha256`, `configurationSha256`, `revision`, `controlRevision`, `action`, `stateSha256`, `authorization`。`revision` 是被验证应用产物的准确提交；`controlRevision` 是当前控制工具 main 提交；`authorization` 精确为 `approve <action> for subs-bot-cf-prod-01`。创建使用草稿身份，初始化使用资源前态摘要；pause、webhook 和 activate 分别使用专门 plan-pause、plan-webhook 和 plan-activate 的批准前态，其他操作按其说明使用独立 inspect 或 plan-deploy 前态。恢复另绑定完整恢复契约。旧批准、旧前态、其他目标或配置不符均停止。

## 操作顺序

所有命令都 dispatch 到 GitHub 托管 runner；不在个人电脑安装、构建或运行工具。以下命令只有填写安全配置并批准相应操作后才执行：

```sh
gh workflow run worker-production-control.yml --ref main \
  -f target_environment=production -f action=preflight \
  -f source_run_id=EXACT_SUCCESSFUL_MAIN_WORKER_CI
```

同一工作流的 `action` 按下表逐步选择，写操作同时提供独立前态 `state_sha256` 和受保护的精确批准：

| 操作 | 前提与行为 |
| --- | --- |
| availability | 创建草稿、已有私有 journal anchor；完整检查同名资源不存在 |
| provision | 创建前持久意图，每步固定 ID／时间；未知结果停止；不部署模块、不启动消费者 |
| provision-inspect / provision-reconcile | 读回持久创建现场；按精确资源种类、摘要和意图时间窗明确固定丢失响应的结果；不按名称直接采用 |
| preflight | 核对实际账户／Zone、固定资源、R2 私有性、Bot 和群权限；输出初始化可批准前态 |
| initialize | 准确完整迁移，只写正式权限白名单；业务表为空；默认无时区行即 UTC；closed/frozen |
| deploy | 准确 main CI 模块和迁移，精确绑定／配置读回；保持 closed/frozen；设置恢复 Cron 但冻结状态不执行工作 |
| plan-deploy | 已存在版本时先固定 `active_run_id` 及原正式配置／安全 Secret，独立核对当前源；新开关和依赖配置需新的完整配置批准 |
| reconcile-deploy | 发布结果不明后先独立读回，只有已部署准确模块、固定配置和冻结现场才能完成版本控制记录 |
| domain | 精确域名、Zone、DNS 无冲突才绑定；HTTPS／健康提交读回；生产 workers.dev 和预览保持关闭 |
| plan-webhook | 只读核对 Bot、闭合控制和 Webhook；输出稳定 `webhook.settingsSha256` 和包含它的批准 `stateSha256`，不调用 setWebhook |
| webhook | 仅接受 plan-webhook 的两份摘要；重验配置／版本／完整控制行、Bot、HTTPS 域名和稳定设置后写入；drop_pending_updates=false，读回 URL／类别／连接参数及无自定义证书 |
| plan-activate | closed/frozen 且已排空；指定 `baseline_checkpoint_id`、`baseline_manifest_sha256`，完整读回私有 G0 SQL／R2／CI 闭包并与当前数据、版本和配置核对；输出包含该基线的批准前态 |
| activate | 使用相同基线 pin 和 plan-activate 前态重新完整核对，精确批准、版本、配置、Webhook、域名和未知结果检查全部满足后，直接从 frozen 原子开启；中间不得 thaw 或写入 |
| plan-pause | 输出完整现场观察；独立 `approvalState` 绑定 pause、目标／配置、准确版本、完整 control 行和迁移数，输出本次 pause 批准所需的 `stateSha256` |
| pause | 仅接受 plan-pause 的批准前态，不能用普通 inspect 摘要；正常已受理工作的计数／终态变化不使暂停批准失效，目标／配置／版本／控制行变化仍拒绝。同事务 CAS 关闭 admission，不要求 work=0，也不会把 frozen 后台意外解冻 |
| drain | 完整分类状态只读检查；未排空则失败；明确失败／外部不确定结果单列，不删除记录 |
| classify-interruption | 暂停后明确分类已结束或超过执行上限与隔离宽限的调用，保留 uncertain；不确认、不重发相关更新 |
| freeze / thaw | freeze 需已关闭 admission 且无可继续执行工作；thaw 只恢复已受理后台处理，仍保持 admission 关闭 |

常规 inspect／pause／drain 可以显式选择已通过 CI 的 main 祖先应用产物，控制工具自身始终运行当前准确 main。新初始化／部署要求当前 main 产物。不能用新提交的绿色状态替代旧线上模块的来源证明。

常规现场检查、暂停、排空及封存只要求主应用的版本、完整配置和实际绑定准确，不因 ProviderFetch 正在正常处理或故障而阻止关闭 admission。启用依赖的部署在上传前、暂存后和发布后完整读回 Provider 代码／镜像／资源／调用者；最终 plan-activate 与 activate 也要求依赖停止状态和完整证明。实际绑定错误仍会阻止暂停，须保留现场并使用准确配置处理，不能以忽略绑定检查来关闭工作。

暂停顺序为 `plan-pause → 批准该摘要 → pause → inspect → drain → freeze`。生产流程不会自动更换批准；重新规划只发生在新的明确批准下。freeze／activate 的工作与未知结果限制继续生效。专用演练工作流的 `stabilize` 仅绑定独立登记的准确演练源，执行 pause、等待已受理工作、freeze，不接触 Webhook、不删除数据、不分类或重发未知结果。演练自动重新批准最多三次，而且只处理已确认 SQL 尚未开始的 `StalePredecessorError`；SQL CAS 失败、传输未知或确认失败均停止并保留私有 intent。每次 intent 和确认使用唯一序号。

演练在 Webhook 操作中断后，先用准确 `webhook_checkpoint`／`webhook_snapshot_sha256` 执行 `recover-webhook`，独立确认原 URL／参数和空对象认证探针 HTTP 400，不能把 Telegram API 设置读回等同于 Secret 已生效。重新 exercise 可显式成对提供 `baseline_checkpoint_id`／`baseline_manifest_sha256` 复用完整私有 G0；工具仍完整读回 SQL／R2／代码并与当前 frozen 状态核对，激活规划和执行再各自重验。缺项、格式错误或任何漂移都在触碰 Webhook 前停止，不自动重新导出或采用其他基线。未提供时保留新建基线的流程。公网探针统一使用项目读回请求头、保持 TLS／目标／Secret／状态和容量检查，不自动重发业务 POST；报告分别保留净化主因和清理失败。

Actions 产物过期时，可用 `source_checkpoint_id` 和独立保存的 `source_manifest_sha256` 代替 `source_run_id`。工具从私有 R2 核对原始 CI ZIP、来源证明、完整迁移和源配置，不查询已过期的 Actions 产物；旧源仅可用于检查、暂停等运维，新部署仍要求准确当前 main。升级时可用 `active_checkpoint_id`／`active_manifest_sha256` 代替 `active_run_id`，旧完整配置从受摘要保护的私有资料读取，Secret 仍单独安全注入。字段必须成对填写。源代码归档可读不代表备份通过；最终激活还会强制验证全部 SQL 分片、R2 对象、归属元数据及当前 D1 数据，任何损坏、新写入或控制 epoch 变化都停止并要求重新封存基线。

暂停覆盖所有现存业务入口：Webhook 是唯一可写公开 HTTP；其他公开路径仅 GET/HEAD；目前没有 queue handler。运行中 Webhook 与 Cron 每次 D1 操作均受事务 fence，R2／外部发送的执行期由持久 invocation 覆盖。重复 `(bot_id,update_id)` 先核对载荷摘要；处理完成后才持久确认；冲突、未完成或不确定更新不能重新执行业务。未受理更新在 Telegram 保留。业务时效规则仍有效，忽略／拒绝结果也有持久 disposition，不用初始化时间隐藏积压。

Webhook 配置顺序为 `plan-webhook → 明确批准其 stateSha256 → webhook`；同时将规划输出的 `webhook.settingsSha256` 填入 `webhook_sha256`。普通 inspect 摘要或原始 getWebhookInfo 全量摘要不能替代该规划。稳定前态绑定 URL、无自定义证书、连接数和更新类别；待处理数量、投递错误与当前 IP 仅作为净化观察，因此正常投递变化不使批准失效。正式前 URL 只允许空或准确正式目标；通用 rehearsal 也不默认接受 dev URL，只有专用 Drill 从登记的原实例上下文显式提供原 dev URL。未知 URL、证书、额外设置或畸形字段在写入前拒绝。新请求不设置自定义证书或固定 IP。Telegram 的 reported `ip_address` 仅说明当前使用的地址，不能据此判断是否曾设置固定 IP；工具只核对合法公网格式并记录摘要，不宣称证明其来源，也不将地址轮转加入稳定批准摘要。[Telegram Webhook 字段定义](https://core.telegram.org/bots/api#getwebhookinfo)

写入或结果读回不明时保持 admission 关闭，保存失败并先重新执行只读 `plan-webhook` 核对实际设置；工具不自动重发 setWebhook。规划读回不能证明 Telegram 未公开的 Secret 值，不能把结果不明标为成功或沿用旧批准盲目重试；需要新的明确批准和独立认证证据后再决定下一步。

## 专用主应用 Provider 绑定演练

`worker-production-lifecycle-rehearsal.yml` 的 `provider-binding` 仅接受已登记的 `subs-bot-cf-control-drill-01`，不操作原 dev 数据或 Provider 部署。先取得完整、未绑定的专用 Provider 私有归档与独立摘要，并通知操作者准备好既有管理员浏览器会话；操作者明确 ready 后才 dispatch。输入 `source_run_id` 为当前准确 main Worker CI，`active_run_id` 为当前专用应用准确源 CI，`registration_sha256` 保持原登记值。另必填 `provider_run_id`、`provider_run_attempt`、`provider_manifest_sha256`，`human_window_seconds` 选 60–540 秒，`provider_ready_ack` 精确为 `IAB ready for subs-bot-cf-control-drill-01 refresh`。不提供旧基线 pin；配置变化后先封存并核对新的 G0。

流程通过正式 Controller 的 plan-deploy／deploy 保留身份、密钥和数据，仅开启 URL 导入和刷新；严格读回唯一调用者绑定后，执行正常 G0／Webhook／激活流程。合成 URL 导入必须保存完整三个节点并精确导出原 URI。出现 `provider-refresh-window-open` 后，管理员在测试 Bot 私聊找到本次带 run 标记的订阅，打开详情并点击真实刷新按钮；工具只接受该管理员、该订阅、同一来源与真实票据的成功请求，核对 generation 增加一次、三个节点、确认发送及精确导出。重复发送 URL 不算刷新。报告需再与浏览器独立观察交叉核对，窗口打开本身不等于真人通过。

随后先关闭、排空、冻结并独立恢复原 Webhook／认证，再以真实 Controller 发布原 Provider=null／关闭功能的完整配置，核对依赖无调用者。专用数据与原登记保持，后续 inspect 的 active_run_id 应指向这次发布所用的准确 main CI；displayTimezone 仅投影本 Bot 的时区与设置来源，无行明确为默认 UTC。

整体通过还要求 off 后再次独立检查 closed/frozen、所有 work 为零、无未知终态，并通过既有 prepare／capture／verify-backup 和完整基线读回封存当前配置、准确 CI、全部受支持数据及对象闭包。这不创建恢复资源或再触碰 Webhook。报告以 `onActivationBaseline` 保留启用前基线，`latestOffBaseline` 记录新增导入／刷新后的新快照；两者使用不同 checkpoint、journal 和私有阶段键，不以旧 G0 或候选 ZIP 代替新写入保全。任何备份或独立读回失败都会停止整体通过，并保留已经恢复的 off 现场与两份资料。

依赖读取 Secret `SUBS_BOT_CF_DEPENDENCY_READ_TOKEN` 只在此 action 注入，所需权限组为 Workers Scripts Read 与 Workers Containers Read。平台只能按账户授予这些读权限；工具再限制到已验证的 Provider 当前／历史准确 ID 与实际盘点所得对象，GET-only，拒绝其他项目、写操作、D1、R2、Zone 和 Registry。使用短期凭据并核对到期时间，不复制 Provider 运行 Secret。

每个完整 Provider 配置与应用 main 组合只允许一个私有持久 on-intent。部署结果未知时不能重跑此 action；从该 intent 取出完整 source／desired 配置和准确源，使用正式 plan-deploy／reconcile-deploy 路径独立核对发布，再以新的明确批准决定后续。若关闭配置的部署未知也保留两份契约和 intent；不能用原 Provider=null 登记的检查失败来声称恢复成功，不能盲目重新部署或恢复 Webhook。所有 G0、业务记录、票据和私有部分结果保留。

## 集中的正式配置与批准清单

- 正式 Bot 创建责任、已确认 ID／用户名、正式 Token 和独立 Webhook Secret。
- 正式管理员、成员、默认拒绝策略、初始授权世代、群范围及实际 Bot 权限。
- 生产固定资源 ID／创建时间、私有 journal anchor、备份保留期和恢复独立目标命名。
- 最小权限的生产凭据、安全注入、environment 审批负责人；不继承测试授权、测试签名密钥或默认 dev 依赖。同一 Telegram 账号若被选择为正式主体，也必须重新显式填写正式角色并批准。
- 每个功能明确开关；正式 ProviderFetch 的准确版本／镜像／资源／停止后 smoke 证明；内部短链继续 `shortlink-new` / `ShortlinkService` / Service Binding / Bearer 业务 Token。
- 准确候选 main、CI run/attempt、模块／ZIP／迁移摘要、独立读回、私有持久归档及适用恢复基线。
- `subs-bot.lilyya.top`、Webhook allowed_updates/max_connections、明确保留 pending updates。
- 逐项批准创建、初始化、部署闭合、基线封存、域名、Webhook、最终激活、限定验收及观察／保留期。
- `/ai` 保持关闭；真实有效 Key、目标和额度的成功验收属于以后启用该功能的独立条件。

发生新写入后，按 [故障恢复说明](cloudflare-production-recovery.md) 先保全 G1，再恢复 G0 到独立、私有、无消费者目标。没有完整自动增量回放；不提供覆盖现场或自动切消费者的捷径。
