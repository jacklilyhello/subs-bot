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
| `botId`, `botUsername`, `generation` | 已通过 getMe 的新正式 Bot；明确的正整数授权世代 |
| `admins`, `members`, `defaultAccess` | 升序、去重的正式 ID 数组；至少一个管理员；互不重叠；`defaultAccess=deny` |
| `groups` | `[]` 或一个明确 `{chatId,chatType}`；目前单一群卡目的地，超限拒绝；预检实际 Bot 成员／发送权限 |
| `features` | 必须显式填写下述所有布尔开关，不推断默认启用 |
| `provider` | 关闭 URL 能力时可为 null；启用时填写独立验证的完整 ProviderFetch 契约，见 [依赖说明](cloudflare-production-provider.md) |
| `webhook` | `{allowedUpdates:[...],maxConnections:...}`；至少 message/callback_query；inlineSearch 开启时包含 inline_query；连接数 1–40 |
| `keyDigests` | aggregate/privateShare/webhook/shortlink 的 SHA-256；外部短链关闭时 shortlink 可为 null |

全部开关：`inlineSearch`, `providerUrlImport`, `providerUrlDocuments`, `mixedDocuments`, `providerRefresh`, `providerBatch`, `subscriptionShorts`, `externalShortlinks`, `groupShareCards`, `githubSearch`, `apiStatus`。首发 `apiStatus=false`。文档导入依赖 URL 导入，混合文档依赖 URL 文档。生产 ProviderFetch 使用独立 `subs-bot-provider-fetch-prod-01`，不自动接受 dev 身份。

固定资源／Bot／授权世代的 `targetSha256` 与完整 `configurationSha256` 分开。开关、依赖、Webhook 参数或 Secret 摘要变化必须重新批准配置；不能沿用旧批准。普通发布保持 aggregate/privateShare 签名密钥连续性，不提供隐式换钥或测试密钥复制。

`SUBS_BOT_CONTROL_SECRETS` 只通过受保护 environment 注入，含 `botToken`, `webhookSecret`, `aggregateKey`, `privateShareKey`, `shortlinkToken`。两个签名密钥必须分别是独立 32 字节密钥的规范 43 字符 Base64URL；Webhook Secret 使用 32–256 字符安全集合；短链启用时必须提供原有完整业务 Token。原始 Secret 不进入目标 JSON、CI 日志、候选或数据备份。

## 凭据与批准

| Secret | 所需权限／用途 |
| --- | --- |
| `SUBS_BOT_CF_DATA_TOKEN` | 指定账户 D1 查询／创建及 R2 私有备份／恢复；生产资源预检还需账户只读身份。工具限制具体目标路径，不修改其他数据 |
| `SUBS_BOT_CF_WORKER_TOKEN` | 指定 Worker 版本、发布和 Cron；生产 Zone 只读核对；仅获批域名步骤才使用必要路由／域名权限 |
| `SUBS_BOT_CF_DEPENDENCY_READ_TOKEN` | ProviderFetch 实际 Worker／Container／Workflow 只读盘点；依赖开启而缺失时拒绝 |
| `SUBS_BOT_PROVISION_ANCHOR_JSON` | 已独立登记的私有项目证据桶 `{accountId,bucketName,bucketCreatedAt}`，保存创建前意图和每一步结果；不能只依赖 runner 临时文件 |
| `SUBS_BOT_APPROVAL_JSON` | 本次精确操作批准，见下文；不提供默认批准 |

平台不支持细分的权限应限制到唯一账户、使用短期凭据，并由工具的固定资源 allowlist、受保护 environment 和不取消的并发锁共同约束。需要新权限时先明确范围，不能借短链业务 Token、其他项目凭据或 `/ai` Key 代替。

批准 JSON 必须包含 `schemaVersion=1`, `environment`, `targetSha256`, `configurationSha256`, `revision`, `controlRevision`, `action`, `stateSha256`, `authorization`。`revision` 是被验证应用产物的准确提交；`controlRevision` 是当前控制工具 main 提交；`authorization` 精确为 `approve <action> for subs-bot-cf-prod-01`。创建使用草稿身份，初始化使用资源前态摘要；其他操作使用独立 inspect 的前态摘要。恢复另绑定完整恢复契约。旧批准、旧前态、其他目标或配置不符均停止。

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
| webhook | 重新核对 getMe/getWebhookInfo 前态，明确 drop_pending_updates=false，读回 URL／类别／连接参数 |
| activate | 精确批准、版本、配置、Webhook、域名、排空和未知结果检查全部满足才开启 |
| pause | 同事务关闭业务 admission；不会把 frozen 后台意外解冻；已受理工作继续完成 |
| drain | 完整分类状态只读检查；未排空则失败；明确失败／外部不确定结果单列，不删除记录 |
| classify-interruption | 暂停后明确分类已结束或超过执行上限与隔离宽限的调用，保留 uncertain；不确认、不重发相关更新 |
| freeze / thaw | freeze 需已关闭 admission 且无可继续执行工作；thaw 只恢复已受理后台处理，仍保持 admission 关闭 |

常规 inspect／pause／drain 可以显式选择已通过 CI 的 main 祖先应用产物，控制工具自身始终运行当前准确 main。新初始化／部署要求当前 main 产物。不能用新提交的绿色状态替代旧线上模块的来源证明。

暂停覆盖所有现存业务入口：Webhook 是唯一可写公开 HTTP；其他公开路径仅 GET/HEAD；目前没有 queue handler。运行中 Webhook 与 Cron 每次 D1 操作均受事务 fence，R2／外部发送的执行期由持久 invocation 覆盖。重复 `(bot_id,update_id)` 先核对载荷摘要；处理完成后才持久确认；冲突、未完成或不确定更新不能重新执行业务。未受理更新在 Telegram 保留。业务时效规则仍有效，忽略／拒绝结果也有持久 disposition，不用初始化时间隐藏积压。

## 集中的正式配置与批准清单

- 正式 Bot 创建责任、已确认 ID／用户名、正式 Token 和独立 Webhook Secret。
- 正式管理员、成员、默认拒绝策略、初始授权世代、群范围及实际 Bot 权限。
- 生产固定资源 ID／创建时间、私有 journal anchor、备份保留期和恢复独立目标命名。
- 最小权限的生产凭据、安全注入、environment 审批负责人；不得填入测试主体、测试签名密钥或默认 dev 依赖。
- 每个功能明确开关；正式 ProviderFetch 的准确版本／镜像／资源／停止后 smoke 证明；内部短链继续 `shortlink-new` / `ShortlinkService` / Service Binding / Bearer 业务 Token。
- 准确候选 main、CI run/attempt、模块／ZIP／迁移摘要、独立读回、私有持久归档及适用恢复基线。
- `subs-bot.lilyya.top`、Webhook allowed_updates/max_connections、明确保留 pending updates。
- 逐项批准创建、初始化、部署闭合、基线封存、域名、Webhook、最终激活、限定验收及观察／保留期。
- `/ai` 保持关闭；真实有效 Key、目标和额度的成功验收属于以后启用该功能的独立条件。

发生新写入后，按 [故障恢复说明](cloudflare-production-recovery.md) 先保全 G1，再恢复 G0 到独立、私有、无消费者目标。没有完整自动增量回放；不提供覆盖现场或自动切消费者的捷径。
