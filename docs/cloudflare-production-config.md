# 首次上线 GitHub 配置清单

在仓库 **Settings → Environments** 中按准确名称创建需要的 Environment，限制到 `main`，为正式资源写入配置指定审查人和部署保护。机密通过 Environment Secret 注入。减少同名的仓库级 Secret，避免工作流意外使用作用域更宽的默认值。下列键仅在对应的上线动作获准后配置或使用。

## `subs-bot-production`

| Secret | 何时填写 | 用途 |
| --- | --- | --- |
| `SUBS_BOT_TARGET_JSON` | 首发 | 账户、Zone、正式 Bot ID/用户名、域名、资源、角色／群范围、功能开关、配置世代和密钥摘要。在创建阶段填写草稿；随后使用实际登记的 ID 和创建时间。参见[目标字段](cloudflare-production-controls.md)。 |
| `SUBS_BOT_CONTROL_SECRETS` | 首发 | JSON 字段 `botToken`、`webhookSecret`、`aggregateKey`、`privateShareKey`、`shortlinkToken`。维护者安全提供 Bot Token，生成独立的 Webhook、聚合和私密分享密钥。短链未启用时填写 JSON null。 |
| `SUBS_BOT_APPROVAL_JSON` | 首发，每个写动作分别填写 | 依据准确计划、前态、目标及控制提交审查生成的批准。一次批准只准许该动作。 |
| `SUBS_BOT_PROVISION_ANCHOR_JSON` | 创建前 | 已批准的私有 provision 日志桶身份，字段 `accountId`、`bucketName`、`bucketCreatedAt`。日志桶独立于本次创建的业务桶和备份桶。 |
| `SUBS_BOT_CF_DATA_TOKEN` | 首发写步骤 | 生命周期 D1 写及必要的数据资源操作。获准 provision 的凭据还需相应创建、发现及登记权限。G0 捕获用该键下的 D1 导出凭据。按步骤收窄并轮换权限。 |
| `SUBS_BOT_CF_WORKER_TOKEN` | 首发写步骤 | 生命周期 Worker 创建、部署、绑定和核验所需权限。备份应用步骤也通过这个键读 Worker；实际备份阶段按工作流所需范围配置。 |
| `SUBS_BOT_CF_DATA_READ_TOKEN` | 首发 G0 读取及独立读回 | 恢复工作流只读 D1。 |
| `SUBS_BOT_CF_WORKER_READ_TOKEN` | 首发 G0 及恢复 | 恢复工作流独立观察 Worker 版本、配置和消费者绑定。 |
| `SUBS_BOT_CF_R2_METADATA_READ_TOKEN` | 首发归档／备份 | 只读核验 R2 桶身份、私有性及配置。 |
| `SUBS_BOT_SCOPED_R2_READ_JSON` | 首发归档／备份 | 按准确桶名提供单桶对象读凭据，覆盖业务桶和备份桶。 |
| `SUBS_BOT_SCOPED_R2_WRITE_JSON` | 首发备份写步骤 | 备份桶的单桶对象读写凭据，向允许的私有键追加内容和持久控制记录。 |
| `SUBS_BOT_RECOVERY_JSON` | 首发 G0；事故或独立恢复另填 | 明确 checkpoint、目的和专用恢复目标；首次用 `purpose=baseline`，事故 G1 用独立 ID 和 `purpose=incident`。恢复旧 checkpoint 时还须固定 session、来源 manifest 和已保全 G1。参见[恢复契约](cloudflare-production-recovery.md)。 |
| `SUBS_BOT_BACKUP_PREPARE_APPROVAL_JSON`、`SUBS_BOT_BACKUP_CAPTURE_APPROVAL_JSON` | 应用工作流手动 `capture` 时 | 分别绑定单步应用备份中恢复引擎的 prepare 与 capture。首次通过 recovery 工作流执行 G0 时，用各动作自己的 `SUBS_BOT_APPROVAL_JSON`。 |
| `SUBS_BOT_CF_DEPENDENCY_READ_TOKEN` | 启用 Provider | 只读核验应用目标所引用的 Provider 版本和调用依赖。 |
| `SUBS_BOT_ACTIVE_TARGET_JSON`、`SUBS_BOT_ACTIVE_CONTROL_SECRETS` | 后续版本或配置切换 | 当前活跃部署的完整配置和安全配置，与新目标分开；使用私有归档源时按生命周期说明提供原配置和对应 Secret。 |
| `SUBS_BOT_CF_R2_CREATE_TOKEN` | 获准创建独立恢复桶 | 仅注入 `create-objects`。创建完成后另配该桶对象凭据。 |
| `SUBS_BOT_SCOPED_R2_EXTRA_READ_JSON`、`SUBS_BOT_SCOPED_R2_EXTRA_WRITE_JSON` | 存在新增独立恢复桶时 | 附加单桶凭据，原 map 和附加 map 不得有重复桶名。 |
| `SUBS_BOT_CF_BACKUP_MONITOR_READ_TOKEN` | 启用日常只读容量监控 | 单独的 D1 只读凭据。 |
| `SUBS_BOT_BACKUP_MONITOR_CONTROLLERS_JSON` | 启用日常只读容量监控 | 用准确工作流、控制版本及历史 pin 管理旧监控来源。 |

首次 G0 还需下节的共享 Secret。创建 R2 桶的 API 权限、只读 metadata 和按单桶隔离的对象权限各自独立；在 Cloudflare 中核对实际权限。客户端的目标约束不改变平台能力。对象 map 格式见[单桶 R2 凭据](cloudflare-scoped-r2.md)。

启用外部短链时，在 `SUBS_BOT_TARGET_JSON` 固定 `features.externalShortlinks` 与匹配的 `keyDigests.shortlink`，在 `SUBS_BOT_CONTROL_SECRETS` 提供 `shortlinkToken`。应用部署从同一配置产生绑定 `SHORTLINK`（`shortlink-new`／`ShortlinkService`）及运行时 secret `SHORTLINK_BUSINESS_TOKEN`；该运行时名不是 GitHub 需要新增的键。内部短链由 `features.subscriptionShorts` 控制。展示默认 UTC，保留管理员修改权限，`/ai` 首发关闭，无需填写 AI 凭据。

## 两个 Environment 共用的备份 Secret

将同一受审内容分别配置到 `subs-bot-production` 和 `subs-bot-production-backup-coordinator`。

| Secret | 何时填写 | 来源及用途 |
| --- | --- | --- |
| `SUBS_BOT_BACKUP_POLICY_JSON` | 首发初始化与 G0 | 运维填写 `version`、`warningPercent`、`pauseLimitSeconds`、`overdueHours`、`windowStartUtc`、`windowMinutes`、`frequencyHours`、可选 `maximumPauseSeconds`。日常建议见[备份运维说明](cloudflare-production-recovery.md)。 |
| `SUBS_BOT_BACKUP_SCHEDULE_SCOPE_GENESIS_SHA256` | 首发，创建后迁移前 | 工具 `plan-schedule-anchor` 输出 `scopeGenesisSha256`，绑定项目共享作用域。 |
| `SUBS_BOT_BACKUP_COORDINATOR_GENESIS_SHA256` | 首发，创建后迁移前 | 同一工具输出 `targetCoordinatorGenesisSha256`，也可由 `plan-initialize` 独立核对。 |
| `SUBS_BOT_BACKUP_GENESIS_SHA256` | 首发，应用备份锚初始化前 | 同一工具输出 `applicationGenesisSha256`，用应用工作流 `plan-initialize-anchor` 与部署后现场核对。 |
| `SUBS_BOT_PRODUCTION_BACKUP_SCHEDULE_REVIEW_JSON`、`SUBS_BOT_PRODUCTION_BACKUP_SCHEDULE_REVIEW_SHA256` | 首发，即使周期关闭 | `plan-controller-review` 给出准确控制提交的源码／工作流树记录、canonical JSON 摘要。维护者审查后配置，两处都保留仍参与历史链验证的已审提交。 |
| `SUBS_BOT_BACKUP_READER_LOG_POLICY_JSON`、`SUBS_BOT_BACKUP_READER_LOG_POLICY_SHA256` | 首发，即使周期关闭 | 维护者按实际 GitHub job 日志保留期填写 `version`、`retentionDays`、`warningDays`、`stopBeforeDays` 及 canonical 摘要。日志过期前必须保全并处置历史链。 |
| `SUBS_BOT_PRODUCTION_BACKUP_SCHEDULE_AUTHORITY_JSON`、`SUBS_BOT_PRODUCTION_BACKUP_SCHEDULE_AUTHORITY_SHA256` | 仅批准启用周期后 | 经独立审查的限期授权合同及 canonical 摘要。绑定控制 SHA、来源 SHA、来源 checkpoint/manifest、三个锚、目标及配置、允许动作、维护窗口和次数。工具验证合同，不代签。字段约束见 [authority_document](../worker/tools/production_backup_schedule.py)。 |

工具给出的 SHA 最终由维护者独立核对并注入受保护配置。计算 JSON 的 pin 时与工具使用相同 UTF-8、排序、压缩的 canonical JSON，摘要覆盖完整内容；不要以人类可读的格式化副本计算 pin。

## `subs-bot-production-backup-coordinator` 额外 Secret

| Secret | 何时填写 | 用途 |
| --- | --- | --- |
| `SUBS_BOT_TARGET_JSON` | 首发 | provision 后确认的正式目标，与应用 Environment 一致。 |
| `SUBS_BOT_CF_R2_METADATA_READ_TOKEN`、`SUBS_BOT_SCOPED_R2_READ_JSON` | 首发 | 只读核对私有桶及备份状态。引导需读取备份、业务和 provision 日志桶。既有单桶读 map 可用 `SUBS_BOT_SCOPED_R2_EXTRA_READ_JSON` 补齐引导所需的桶。 |
| `SUBS_BOT_SCOPED_R2_WRITE_JSON` | 首发获准初始化；也用于已批准的协调写入 | 仅给项目私有备份桶的对象写权限。独立终态作业使用该对象权限追加见证。 |
| `SUBS_BOT_CF_BACKUP_MONITOR_READ_TOKEN`、`SUBS_BOT_CF_WORKER_READ_TOKEN` | 首发引导 | 分别独立读取空 D1 与未部署 Worker；D1 只读 token 也供周期预检使用。 |
| `SUBS_BOT_PROVISION_ANCHOR_JSON` | 首发引导 | 原 provision 私有日志锚身份，与应用 Environment 此键一致。 |
| `SUBS_BOT_BACKUP_SCOPE_BOOTSTRAP_REGISTRATION_SHA256` | 首发引导 | provision 工具产生的 `registrationSha256`，以独立确认的私有登记为准。 |
| `SUBS_BOT_BACKUP_SCOPE_BOOTSTRAP_REVIEW_JSON`、`SUBS_BOT_BACKUP_SCOPE_BOOTSTRAP_REVIEW_SHA256` | 首发引导 | 首次只读 `plan-schedule-anchor` 提供待审的原 run 清单及摘要，独立审核后固定，参见[步骤](cloudflare-production-recovery.md#首次建立备份状态)。 |
| `SUBS_BOT_BACKUP_SCOPE_BOOTSTRAP_PLAN_SHA256` | 首发引导写入前 | 固定再次执行只读计划输出的 `planSha256`；调用 `initialize-schedule-anchor` 时还要传同一个批准摘要。 |

## Variables

缺省关闭项仅在相应生产策略批准或独立动作获准后设置为 `true`。已有保护等待、临时暂停和写入审核均适用于正式操作；只有能满足维护窗口的保护配置才适合启用无人值守调度。

| 设置位置 | Variable | 何时填写及用途 |
| --- | --- | --- |
| 仓库 | `SUBS_BOT_PRODUCTION_BACKUP_SCHEDULE_DISPATCH_ENABLED` | 周期获批后，允许 15 分钟触发器进入协调器。首发默认关闭。 |
| 仓库 | `SUBS_BOT_PRODUCTION_BACKUP_MONITOR_DISPATCH_ENABLED` | 只读监控获批后，允许 app 与协调器的 cron 进入其 Environment。首发默认关闭。 |
| `subs-bot-production-backup-coordinator` | `SUBS_BOT_PRODUCTION_BACKUP_COORDINATOR_ENABLED` | 首发共享／目标锚初始化或获准协调写入期间启用。周期也需要此项。 |
| `subs-bot-production` | `SUBS_BOT_PRODUCTION_BACKUP_WRITES_ENABLED` | 首发获准的应用锚初始化、显式应用备份写步骤或周期子任务需要。默认关闭。 |
| 两个备份 Environment | `SUBS_BOT_PRODUCTION_BACKUP_SCHEDULE_ENABLED` | 周期获批后在两处填写，同时核验各自的限期授权。首发默认关闭。 |
| `subs-bot-production-backup-coordinator` | `SUBS_BOT_PRODUCTION_BACKUP_COORDINATOR_MONITOR_ENABLED` | 确认协调器只读监控的策略后启用。 |
| `subs-bot-production` | `SUBS_BOT_PRODUCTION_BACKUP_MONITOR_ENABLED` | 确认应用容量、失败和过旧监控的策略后启用。 |
| `subs-bot-production` | `SUBS_BOT_PRODUCTION_CAPACITY_INTERVAL_MINUTES`、`SUBS_BOT_PRODUCTION_BACKUP_NOTIFICATION_FILTER` | 启用监控时可配采样间隔（15、30 或 60 分钟）及 GitHub 告警分类路由（默认 `*`）。没有外部通知凭据键。 |
| 两个备份 Environment | `SUBS_BOT_PRODUCTION_BACKUP_SOURCE_CHECKPOINT_ID`、`SUBS_BOT_PRODUCTION_BACKUP_SOURCE_MANIFEST_SHA256` | cron 无输入时填写独立确认的持久来源 ID 和摘要。手动调用可用同名语义的 dispatch 输入，见工作流。 |
| `subs-bot-production` | `SUBS_BOT_PRODUCTION_BACKUP_SOURCE_RUN_ID`、`SUBS_BOT_PRODUCTION_BACKUP_SOURCE_RUN_ATTEMPT` | 手动应用备份可用原 CI 来源变量或直接传输入。保护性计划应固定实际 run 和 attempt。 |

## 可选 Provider 配置

首发只有获批开通正式 Provider 才使用下列 Environment。应用目标和依赖读 Token 仍在 `subs-bot-production`。用于 Provider 的 CI、镜像身份、`archive_refs`、目标前态与批准都是显式工作流输入和契约；运行时配置、Registry 短期凭据与 GH 的默认 `github.token` 不需要新建同名 Secret。详见[Provider 生产控制](cloudflare-production-provider.md)。

| Environment | Secret | 用途 |
| --- | --- | --- |
| `subs-bot-production-provider` | `SUBS_BOT_PROVIDER_CONTROL_TARGET_JSON` | 正式 Provider 及 caller 的固定身份和动作批准契约。 |
| `subs-bot-production-provider` | `SUBS_BOT_CF_PROVIDER_WORKER_TOKEN`、`SUBS_BOT_CF_PROVIDER_CONTAINER_TOKEN` | Worker 控制与 Containers／Registry 来源核验，限定实际使用产品与账户。 |
| `subs-bot-production-provider`、`subs-bot-production-provider-archive` | `SUBS_BOT_PROVIDER_ARCHIVE_BUCKET_JSON`、`SUBS_BOT_CF_PROVIDER_ARCHIVE_READ_TOKEN`、`SUBS_BOT_CF_R2_METADATA_READ_TOKEN`、`SUBS_BOT_SCOPED_R2_READ_JSON` | 使用私有持久来源时，固定正式私有桶、只读身份与准确桶对象映射。 |
| `subs-bot-production-provider`、`subs-bot-production-provider-archive` | `SUBS_BOT_PROVIDER_SOURCE_LEDGER_JSON`、`SUBS_BOT_PROVIDER_SOURCE_CONTROLLERS_JSON`、`SUBS_BOT_PROVIDER_SOURCE_RESOLUTIONS_JSON` | 独立读回登记、已审准确控制提交、已审失败对账记录；按工作流契约显式初始化空账本。 |
| `subs-bot-production-provider-archive` | `SUBS_BOT_PROVIDER_CONTROL_TARGET_JSON`、`SUBS_BOT_CF_PROVIDER_ARCHIVE_WRITE_TOKEN`、`SUBS_BOT_SCOPED_R2_WRITE_JSON` | 获准封存时配置正式目标与专用单桶对象写凭据。只读核验独立执行。 |
| `subs-bot-production-provider-archive` | `SUBS_BOT_PROVIDER_SOURCE_ORIGIN_JSON`、`SUBS_BOT_PROVIDER_SOURCE_ORIGIN_ARCHIVE_TARGET_JSON`、`SUBS_BOT_PROVIDER_SOURCE_ORIGIN_CONTROLLERS_JSON`、`SUBS_BOT_PROVIDER_SOURCE_ORIGIN_LEDGER_JSON`、`SUBS_BOT_PROVIDER_SOURCE_ORIGIN_METADATA_READ_TOKEN`、`SUBS_BOT_PROVIDER_SOURCE_ORIGIN_R2_READ_JSON` | 仅在获准从独立已验证的隔离来源封存正式候选时填写，固定原桶、账本、控制版本和只读能力。 |

## 批准前需确定的事项

- 正式 Bot 的所有者、用户名与 ID，凭据保管和注入责任，正式管理员、成员默认策略及允许群范围。
- 是否首发启用 Provider、外部短链和群入口，相关费用与预算。周期备份、只读监控、独立告警接收方、可接受维护窗口和保留期各自批准。
- 固定审查人与上线窗口。另行批准项目日志锚及正式资源创建、部署、G0、域名绑定、Webhook、启用接收、正式环境验收和后续恢复写入。
- 准确合并 SHA 的 CI、隔离部署和独立读回均匹配后才运行 `worker-production-candidate.yml`。打包器无需正式 Environment Secret。批准私有保全和独立读回，保留已有各代候选、恢复资料和独立保护的密钥。
