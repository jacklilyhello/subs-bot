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

批准 JSON 必须包含 `schemaVersion=1`, `environment`, `targetSha256`, `configurationSha256`, `revision`, `controlRevision`, `action`, `stateSha256`, `authorization`。`revision` 是被验证应用产物的准确提交；`controlRevision` 是当前控制工具 main 提交；`authorization` 精确为 `approve <action> for subs-bot-cf-prod-01`。创建使用草稿身份，初始化使用资源前态摘要；pause、webhook、activate 和 reconcile-deploy 分别使用专门 plan-pause、plan-webhook、plan-activate 和 plan-reconcile-deploy 的批准前态，其他操作按其说明使用独立 inspect 或 plan-deploy 前态。恢复另绑定完整恢复契约。旧批准、旧前态、其他目标或配置不符均停止。

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
| plan-reconcile-deploy | 只读核对已部署准确模块、配置、依赖和排空冻结现场；将完整状态及 Cron 前态 `reconcileCron` 一起绑定到本次 `stateSha256` |
| reconcile-deploy | 仅接受 plan-reconcile-deploy 的摘要与 `reconcile-deploy` 批准；协调准确控制版本和 policy，或在已确认 successor 上按明确批准补齐空 Cron；不重新上传或切流量 |
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

### 发布中断后的协调

上传或流量切换一旦开始，后续错误以 `deployment-reconciliation-required`、固定 phase 和 `uncertain=true` 保留。`upload`、`staged-readback`、`traffic`、`active-readback`、`reconcile` 区分中断边界；版本／deployment 摘要只帮助关联证据，不表示该操作未执行。生产控制工作流另保存 `subs-bot-production-deployment-events-<run>-<attempt>` artifact，其中 `production-control-deployment-events.ndjson` 记录已确认 ID 和阶段。缺失事件或结果报告不能代替实际读回，事件本身也不等于完整验收。

正常发布在一次流量 POST 返回准确 deployment ID 后，只对完整、已验证的原版本允许最多三次 GET 观察，间隔 1 秒、3 秒；准确新 version/deployment 必须通过原有完整绑定及依赖检查。第三个发布、原版本的模块／绑定漂移、未知读回或验证失败立即停止，不重发上传或流量 POST。保留原批准、source／desired 配置、CI ZIP 和不可变 intent，再独立确认实际发布边界。

协调顺序是 `plan-reconcile-deploy → 明确批准其 stateSha256 → reconcile-deploy`。目标 JSON 和 Secret 必须对应已经独立确认的已部署配置；`source_run_id` 固定该应用的准确 CI，而 `--ref main` 始终选择当前控制代码。应用提交可以是已审查的 main 祖先，不能为协调而改成新构建。以下占位符必须替换；示例不授予生产批准：

```sh
gh workflow run worker-production-control.yml --ref main \
  -f target_environment=production -f action=plan-reconcile-deploy \
  -f source_run_id=EXACT_DEPLOYED_APPLICATION_CI_RUN
```

独立核对计划后，在受保护 environment 安全配置新的 `SUBS_BOT_APPROVAL_JSON`，其 `action=reconcile-deploy`、应用 `revision`、当前工具 `controlRevision`、完整配置及前态摘要必须一致，再执行：

```sh
gh workflow run worker-production-control.yml --ref main \
  -f target_environment=production -f action=reconcile-deploy \
  -f source_run_id=EXACT_DEPLOYED_APPLICATION_CI_RUN \
  -f state_sha256=EXACT_PLAN_RECONCILE_DEPLOY_STATE_SHA256
```

规划只接受 Cron `[]` 或唯一的 `* * * * *`；仅允许平台的 `created_on`／`modified_on` 元数据，整个读回前态随计划批准。计划另绑定 `reconcilePolicyRevision` 和 `reconcileMode`，要求 policy 与当前 control revision 一致。其他 Cron、未知字段或规划后的漂移均拒绝。需要更新版本的 `revision-reconcile` 模式把完整 control 前态和旧 `telegram_general_policy.release_revision` 一起原子断言，再更新版本及 epoch，并读回准确 Cron。不能把 policy 更新零行当作协调成功。

正式 CLI 发现当前 control、policy 和准确已部署应用均为 desired revision 时，规划使用 `already-coherent`，无需额外提供原前态。批准后只确认当前完整 control／epoch 保持不变；Cron 已准确时无写入，明确批准空 Cron 时仅补写准确计划并读回，不再执行 SQL 或增加 epoch。这只证明当前配置一致，不证明某次历史 SQL 或发布步骤曾经成功。显式 on-intent 续接仍使用原不可变前态，不能借此模式放宽原 epoch 到唯一 successor 的约束。

在持有原不可变前态的明确续接中，已协调 successor 仅允许原 epoch 加一、准确新 revision、policy 和完整活动发布均一致：Cron 已准确时只读返回，不写 SQL、不增加 epoch；若 Cron 明确为空，只有本次计划已绑定并批准该空状态，才允许一次 PUT 写入准确 Cron 并重新读回，仍不重放 SQL。写入／确认不明时保留 uncertain；其他状态停止，不能借此补写未知计划或重新部署。正式生产的每一步仍须单独批准。

常规现场检查、暂停、排空及封存只要求主应用的版本、完整配置和实际绑定准确，不因 ProviderFetch 正在正常处理或故障而阻止关闭 admission。启用依赖的部署在上传前、暂存后和发布后完整读回 Provider 代码／镜像／资源／调用者；最终 plan-activate 与 activate 也要求依赖停止状态和完整证明。实际绑定错误仍会阻止暂停，须保留现场并使用准确配置处理，不能以忽略绑定检查来关闭工作。

暂停顺序为 `plan-pause → 批准该摘要 → pause → inspect → drain → freeze`。生产流程不会自动更换批准；重新规划只发生在新的明确批准下。freeze／activate 的工作与未知结果限制继续生效。专用演练工作流的 `stabilize` 仅绑定独立登记的准确演练源，执行 pause、等待已受理工作、freeze，不接触 Webhook、不删除数据、不分类或重发未知结果。演练自动重新批准最多三次，而且只处理已确认 SQL 尚未开始的 `StalePredecessorError`；SQL CAS 失败、传输未知或确认失败均停止并保留私有 intent。每次 intent 和确认使用唯一序号。

演练在 Webhook 操作中断后，先用准确 `webhook_checkpoint`／`webhook_snapshot_sha256` 执行 `recover-webhook`，独立确认原 URL／参数和空对象认证探针 HTTP 400，不能把 Telegram API 设置读回等同于 Secret 已生效。重新 exercise 可显式成对提供 `baseline_checkpoint_id`／`baseline_manifest_sha256` 复用完整私有 G0；工具仍完整读回 SQL／R2／代码并与当前 frozen 状态核对，激活规划和执行再各自重验。缺项、格式错误或任何漂移都在触碰 Webhook 前停止，不自动重新导出或采用其他基线。未提供时保留新建基线的流程。公网探针统一使用项目读回请求头、保持 TLS／目标／Secret／状态和容量检查，不自动重发业务 POST；报告分别保留净化主因和清理失败。

Actions 产物过期时，可用 `source_checkpoint_id` 和独立保存的 `source_manifest_sha256` 代替 `source_run_id`。工具从私有 R2 核对原始 CI ZIP、来源证明、完整迁移和源配置，不查询已过期的 Actions 产物；旧源仅可用于检查、暂停等运维，新部署仍要求准确当前 main。升级时可用 `active_checkpoint_id`／`active_manifest_sha256` 代替 `active_run_id`，旧完整配置从受摘要保护的私有资料读取，Secret 仍单独安全注入。字段必须成对填写。源代码归档可读不代表备份通过；最终激活还会强制验证全部 SQL 分片、R2 对象、归属元数据及当前 D1 数据，任何损坏、新写入或控制 epoch 变化都停止并要求重新封存基线。

暂停覆盖所有现存业务入口：Webhook 是唯一可写公开 HTTP；其他公开路径仅 GET/HEAD；目前没有 queue handler。运行中 Webhook 与 Cron 每次 D1 操作均受事务 fence，R2／外部发送的执行期由持久 invocation 覆盖。重复 `(bot_id,update_id)` 先核对载荷摘要；处理完成后才持久确认；冲突、未完成或不确定更新不能重新执行业务。未受理更新在 Telegram 保留。业务时效规则仍有效，忽略／拒绝结果也有持久 disposition，不用初始化时间隐藏积压。

Webhook 配置顺序为 `plan-webhook → 明确批准其 stateSha256 → webhook`；同时将规划输出的 `webhook.settingsSha256` 填入 `webhook_sha256`。普通 inspect 摘要或原始 getWebhookInfo 全量摘要不能替代该规划。稳定前态绑定 URL、无自定义证书、连接数和更新类别；待处理数量、投递错误与当前 IP 仅作为净化观察，因此正常投递变化不使批准失效。正式前 URL 只允许空或准确正式目标；通用 rehearsal 也不默认接受 dev URL，只有专用 Drill 从登记的原实例上下文显式提供原 dev URL。未知 URL、证书、额外设置或畸形字段在写入前拒绝。新请求不设置自定义证书或固定 IP。Telegram 的 reported `ip_address` 仅说明当前使用的地址，不能据此判断是否曾设置固定 IP；工具只核对合法公网格式并记录摘要，不宣称证明其来源，也不将地址轮转加入稳定批准摘要。[Telegram Webhook 字段定义](https://core.telegram.org/bots/api#getwebhookinfo)

写入或结果读回不明时保持 admission 关闭，保存失败并先重新执行只读 `plan-webhook` 核对实际设置；工具不自动重发 setWebhook。规划读回不能证明 Telegram 未公开的 Secret 值，不能把结果不明标为成功或沿用旧批准盲目重试；需要新的明确批准和独立认证证据后再决定下一步。

## 专用主应用 Provider 绑定演练

Provider 持久来源的独立 Worker 演练入口使用受信 main dispatcher `worker-provider-reviewed-operation.yml`，默认关闭，接受已审准确 PR head、项目隔离目标及独立登记的当前／previous 原始归档。最终 main 的准确 CI 原件可在合并后由 `worker-provider-isolated-source.yml` 封存，并由 `worker-provider-isolated-source-readback.yml` 独立读回、登记；随后可使用同一受保护演练 DAG 的 main-self 模式。该模式必须在各隔离 Environment 显式设置 `SUBS_BOT_PROVIDER_MAIN_SELF_POLICY_JSON`，其 `version=1`、`enabled=true`，`environment` 为该环境的准确名称、`mainSha` 为当前 main；独立核实仓库层不存在同名变量，以免回退。各环境的 `SUBS_BOT_PROVIDER_REVIEWED_HEAD_SHA` 也须固定同一提交，验证输入设置 `pr` 为 `main`、`headSha` 为该提交。两环境的 fresh job 各自于使用凭据前核对自身配置；实际写入之前的 DAG 须已通过两侧 gate，不能将其理解为跨环境原子锁。完成后关闭该模式。此模式仅用于登记的隔离目标，历史记录以 `reviewedPr=main` 明确区分，不伪造 PR 或改写旧证据。

先独立完成隔离镜像发布及全量读回，再分别审批并执行 `prepare-image`、`stage`、`activate`、`smoke`；镜像准备完成证明必须先经私有归档独立读回并登记，才能执行 stage。每次都重新核对准确来源、前态、旧版本终态和无 caller，先单次写入意图、独立读回，再发起对应请求；相应凭据使用隔离资源的短期最小权限。写前观察不能充当外部并发的原子锁，必须确保隔离目标没有其他写者。

私有来源归档保留原始 CI ZIP（含 Worker 模块与 OCI 镜像归档），并按独立固定摘要重新核验目标和原件；它不把归档存在本身当作可信来源。校验仍依赖 GitHub 的原 CI run／attempt、工作流与 main 祖先元数据，以及对应原提交的 requirements 原文；这些信息不可读时安全停止，不能重建旧版或改写来源。正式及隔离来源库存各以 32 次封存为当前上限，当前版本与 previous 合计最多 9 代；来源、镜像和 Worker 操作各自的 controller 允许列表最多 16 个版本。达到边界前须实施经审查的分页或分段扩容，不删除历史证据。演练中模拟 Actions 产物不可用应明确标为模拟，不代表产物真实过期。

首次正式来源封存可使用单独登记的 `isolated-source` 归档作为原 CI ZIP 的运输来源：在正式归档 Environment 的 `SUBS_BOT_PROVIDER_SOURCE_ORIGIN_JSON` 中固定其 kind、run／attempt、manifest／目标／桶及独立读回 ledger 记录摘要，同时单独配置该项目来源桶的只读凭据、桶身份和完整隔离来源 ledger／controller；来源读取步骤不持正式桶写凭据。工具复验原封存和独立读回 run、原 CI 元数据、ZIP 及 Worker／OCI 全部摘要，要求原 build 与正式目标中的 build 完全一致；正式目标、调用方、桶和批准仍独立核对。来源 pin 被记录在正式 plan、intent 和 manifest，且不会把隔离目标当作正式授权。未配置 origin 时仍使用原 Actions 产物；配置不完整或任何来源不符即停止，不回退下载或写入。即使 ZIP 持久保存，原 GitHub run／attempt 元数据或原 requirements 不可验证时仍不能继续。

来源 pin 的字段为 `version`、`kind`、`runId`、`runAttempt`、`manifestSha256`、`targetSha256`、`bucketSha256` 和 `ledgerRecordSha256`；版本固定为 1、kind 为 `isolated-source`、attempt 为 `1`。桶摘要针对登记的完整来源桶配置，ledger 摘要针对原封存对应的完整独立读回登记记录，均按工具的 canonical JSON 计算。原桶配置、ledger 和 controller 分别由 `SUBS_BOT_PROVIDER_SOURCE_ORIGIN_ARCHIVE_TARGET_JSON`、`SUBS_BOT_PROVIDER_SOURCE_ORIGIN_LEDGER_JSON`、`SUBS_BOT_PROVIDER_SOURCE_ORIGIN_CONTROLLERS_JSON` 提供；`SUBS_BOT_PROVIDER_SOURCE_ORIGIN_R2_READ_JSON` 是仅来源桶的只读映射，`SUBS_BOT_PROVIDER_SOURCE_ORIGIN_METADATA_READ_TOKEN` 用于核对桶身份。正式桶写凭据仅用于后续获批准的封存步骤。配置前须独立核对 Environment 身份和同名 repository secret 不产生意外回退。

每步完成后独立读回 Provider 状态及私有意图／密文证据，审核后登记 ledger 并安全注入两个目标环境的加密下一配置和准确审批摘要，再进入下一步。密文 artifact 只用于短时交接，不能当作长期私有归档。响应已收到而后续失败时，流程尝试单次追加加密观察并独立读回；若进程死亡或写入结果不明，保留原 intent 和全部现场，不推断成功、不重发。`worker-provider-reviewed-operation-reconcile.yml` 只诊断写入 job 均明确跳过且私有前缀为空的 run；不得用它解除已执行或结果不明的操作。此入口及各项隔离验收以对应准确提交的实际检查和独立证据为准，不代表正式资源获得授权。

该隔离操作 ledger 和只读对账列表各以上限 32 条为界；达到边界前须完成经审查的分页或分段扩容，不能删除旧意图、证据或登记记录以继续写入。新增限制只约束这个演练 journal，不改变历史版本链的独立上限。

Provider 隔离交接使用一次性的临时 age 私钥；全部已取得的响应密文都须与严格白名单的 response-only 原件关联封存到私有 R2，并经独立解密和读回后，才能按本轮凭据期限清除临时身份。原件不含 API／Bot Token 或签名密钥；配置 Secret 仍不放入数据备份。若证据无法验证或仍有未决密文，保留现场并报告，不得声称已完成清理或结果成功。

中断后仅当 `stage` 的准确 version ID 或 `activate` 的准确 deployment ID 已保全且可独立核实，才可使用默认关闭的隔离 `worker-provider-reviewed-recovery.yml` 先做只读对账：复核原 run/attempt、持久 intent、响应原件、完整来源链、全部版本及部署历史、caller 和 previous 终态。单独批准准确 plan 后再重新观察，单次追加不可变 resolution 并由新 runner 独立读回；经审核登记该 resolution 后，才可使用它生成的密封 next-target 审批后续动作。原 run 仍为失败／未知，不改旧 intent 或重发原写；响应 ID 缺失、现场漂移、额外版本／部署或结果歧义仍须停止并告警。

隔离 Environment 的 `SUBS_BOT_PROVIDER_MUTATION_RECONCILED_JSON` 必须显式登记；仅在私有前缀及完整工作流历史均确认无记录时初始化为空对象，之后只能登记独立读回的精确 resolution，不能删改历史。读回 runner 分别使用受保护的两个 Environment 公钥密封完整合并账本，只输出账本及密文摘要；登记前须重新核验目标 Environment 的身份、公钥和密文摘要，两端登记相同账本。此步骤不代表原失败 run 成功。部署记录的单页盘点必须少于 100 条；达到边界时停止并先实施有界分页支持，不删历史来通过检查。

`worker-production-lifecycle-rehearsal.yml` 的 `provider-binding` 仅接受已登记的 `subs-bot-cf-control-drill-01`，不操作原 dev 数据或 Provider 部署。先取得完整、未绑定的专用 Provider 私有归档与独立摘要，并通知操作者准备好既有管理员浏览器会话；操作者明确 ready 后才 dispatch。输入 `source_run_id` 为当前准确 main Worker CI，`active_run_id` 为当前专用应用准确源 CI，`registration_sha256` 保持原登记值。另必填 `provider_run_id`、`provider_run_attempt`、`provider_manifest_sha256`，`human_window_seconds` 选 60–540 秒，`provider_ready_ack` 精确为 `IAB ready for subs-bot-cf-control-drill-01 refresh`。不提供旧基线 pin；配置变化后先封存并核对新的 G0。

流程通过正式 Controller 的 plan-deploy／deploy 保留身份、密钥和数据，仅开启 URL 导入和刷新；严格读回唯一调用者绑定后，执行正常 G0／Webhook／激活流程。合成 URL 导入必须保存完整三个节点并精确导出原 URI。出现 `provider-refresh-window-open` 后，管理员在测试 Bot 私聊找到本次带 run 标记的订阅，打开详情并点击真实刷新按钮；工具只接受该管理员、该订阅、同一来源与真实票据的成功请求，核对 generation 增加一次、三个节点、确认发送及精确导出。重复发送 URL 不算刷新。报告需再与浏览器独立观察交叉核对，窗口打开本身不等于真人通过。

随后先关闭、排空、冻结并独立恢复原 Webhook／认证，再以真实 Controller 发布原 Provider=null／关闭功能的完整配置，核对依赖无调用者。专用数据与原登记保持，后续 inspect 的 active_run_id 应指向这次发布所用的准确 main CI；displayTimezone 仅投影本 Bot 的时区与设置来源，无行明确为默认 UTC。

整体通过还要求 off 后再次独立检查 closed/frozen、所有 work 为零、无未知终态，并通过既有 prepare／capture／verify-backup 和完整基线读回封存当前配置、准确 CI、全部受支持数据及对象闭包。这不创建恢复资源或再触碰 Webhook。报告以 `onActivationBaseline` 保留启用前基线，`latestOffBaseline` 记录新增导入／刷新后的新快照；两者使用不同 checkpoint、journal 和私有阶段键，不以旧 G0 或候选 ZIP 代替新写入保全。任何备份或独立读回失败都会停止整体通过，并保留已经恢复的 off 现场与两份资料。

依赖读取 Secret `SUBS_BOT_CF_DEPENDENCY_READ_TOKEN` 只在 `provider-binding`、下述 `provider-binding-resume` 和 `provider-binding-reconcile` 注入，所需权限组为 Workers Scripts Read 与 Workers Containers Read。Workers Scripts Read 可使用 account-owned granular token 限定准确 Worker 资源；Containers Read 本轮仅核实到账号级产品权限，必须单独评估并批准其范围。工具按已验证的 Provider 当前／历史准确 ID 与实际盘点所得对象限制 GET，不把工具白名单当作平台级资源隔离。使用短期凭据并核对到期时间，不复制 Provider 运行 Secret。

每个完整 Provider 配置与应用提交组合只允许一个私有持久 on-intent。部署结果未知时不能重跑 `provider-binding`，也不能删除标记以重发。若关闭配置的部署未知，同样保留两份契约和 intent；下述 on 续接不代替未知 off 的处置，不能用原 Provider=null 登记的检查失败声称已经恢复，也不能盲目重新部署或恢复 Webhook。所有 G0、业务记录、票据和私有部分结果保留。

### 明确续接已经部署的 on 配置

`worker-production-lifecycle-rehearsal.yml` 的 `provider-binding-resume` 调用 `worker/tools/production_application_provider_resume.py`，只用于原 on-intent 已存在、实际已部署准确 desired 版本的专用演练目标。先独立读回原始 intent 字节摘要及活动 version/deployment ID；不能仅凭名称、latest 或缺失的确认文件采用资源。新的 dispatch 必须为 attempt 1，继续使用相同登记、完整 Provider 归档和明确的管理员浏览器 ready 合同，不填写旧基线 pin。

`provider_binding_resume_json` 精确包含以下五个字符串字段；未知字段或占位符均拒绝：

```json
{
  "runId": "ORIGINAL_BINDING_RUN_ID",
  "runAttempt": "ORIGINAL_BINDING_RUN_ATTEMPT",
  "intentSha256": "INDEPENDENT_ORIGINAL_RAW_INTENT_SHA256",
  "versionId": "INDEPENDENT_ACTIVE_DESIRED_VERSION_UUID",
  "deploymentId": "INDEPENDENT_ACTIVE_DESIRED_DEPLOYMENT_UUID"
}
```

模块从原共享 admission 以及原 run 专用 on-intent 两处读回，要求字节相同、摘要及原 run/attempt 完全一致，再核对 source／desired 目标、不可变资源、完整配置、两份 CI proof 和 Provider 证据。应用固定为原 `desiredProof` 的准确提交、run/attempt/artifact/ZIP；即使当前控制工具 main 已前进，也不能重建或替换这个应用源。原 source proof 则独立验证部署前版本。`source_run_id` 与 `active_run_id` 在此次续接中都填写原 desired 应用 CI，原来的部署前 CI 从 intent 读取，不再将其填为 `active_run_id`。

```sh
gh workflow run worker-production-lifecycle-rehearsal.yml --ref main \
  -f action=provider-binding-resume \
  -f source_run_id=FROZEN_ORIGINAL_DESIRED_APPLICATION_CI_RUN \
  -f active_run_id=FROZEN_ORIGINAL_DESIRED_APPLICATION_CI_RUN \
  -f registration_sha256=EXACT_EXISTING_REGISTRATION_SHA256 \
  -f provider_run_id=EXACT_COMPLETE_PROVIDER_ARCHIVE_RUN \
  -f provider_run_attempt=EXACT_PROVIDER_ARCHIVE_ATTEMPT \
  -f provider_manifest_sha256=INDEPENDENT_COMPLETE_PROVIDER_MANIFEST_SHA256 \
  -f human_window_seconds=540 \
  -f provider_ready_ack='IAB ready for subs-bot-cf-control-drill-01 refresh' \
  -f provider_binding_resume_json='{"runId":"ORIGINAL_BINDING_RUN_ID","runAttempt":"ORIGINAL_BINDING_RUN_ATTEMPT","intentSha256":"INDEPENDENT_ORIGINAL_RAW_INTENT_SHA256","versionId":"INDEPENDENT_ACTIVE_DESIRED_VERSION_UUID","deploymentId":"INDEPENDENT_ACTIVE_DESIRED_DEPLOYMENT_UUID"}'
```

准确目标、配置、模块、绑定、依赖及原控制前态全部核验后，续接通过正式 Controller 的规划／批准／协调方法完成控制记录，不上传新版本、不再切换 on 流量。完整活动 snapshot 贯穿重新读取；第三个发布、未知终态、其他 epoch 或配置漂移均拒绝。已经协调的准确 successor 遵守前述只读或明确空 Cron 修补规则，不能靠重新 dispatch 重放已发生的 SQL 或业务。

协调成功后仍须真实执行完整后续流程：封存新的 on G0、配置并读回保留 pending 的 Webhook、激活、合成三节点 URL 导入与精确导出，并在 `provider-refresh-window-open` 由管理员点击本次真实票据完成刷新。接着关闭／排空／冻结、恢复原 Webhook 与认证、发布准确 off 配置并确认无 Provider caller，最后封存不同 checkpoint 的 `latestOffBaseline`，包含本轮新增写入和原始 CI 闭包。协调本身、窗口打开或旧 G0 通过均不能代替这些结果；真人验收还须浏览器证据独立对应。

需要分段完成控制协调时，可使用同一工作流的 `action=provider-binding-reconcile`。沿用上述准确 `provider_binding_resume_json`、登记、Provider 归档及冻结应用 CI 输入，仅将 `human_window_seconds=0`；不要求 `provider_ready_ack` 或真人消息锚点。该入口使用相同原 intent、正式协调方法和独立读回，重验共享 admission 未改变，并持久保存 `provider-binding-on-reconciled` 后保持准确 on 配置、原 desired 应用源及 closed/frozen 状态。它不上传版本、不切换 on 流量、不请求公开订阅源、不执行 exercise、Webhook 操作、导入、真人刷新、off 发布或最新备份，也不触发 Webhook 清理。

该分段报告为 `status=reconciled-closed-only`、`humanAcceptance=false`，不报告 `passed`；配置摘要对应实际 on 配置，`ciProof` 对应冻结的 desired 源，control 仍须是原前态的唯一准确 successor。`providerBusinessAcceptance` 中 URL 导入、真人刷新、off 发布和 latest-off 备份均标为 `not-run`。之后重新明确批准完整 `provider-binding-resume`，在准备好真人会话的 60–540 秒窗口内，从同一准确 successor 继续；已确认的协调不再写 SQL 或增加 epoch，后续全部验收仍须实际完成。

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
