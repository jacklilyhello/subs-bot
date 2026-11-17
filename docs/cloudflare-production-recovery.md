# 生产身份备份与独立恢复

`worker/tools/production_recovery.py` 和 `production_recovery_cli.py` 是独立的生产控制实现，使用与部署控制相同的 `production_target.py` 配置契约。`worker-production-recovery.yml` 在 GitHub 托管 runner 执行。生产与明确登记的 rehearsal 运行相同的代码；不修改历史隔离恢复脚本的账户、资源或源版本保护，也不自动采用已有 dev 目标。

工具完成备份和独立目标恢复，不授权切换正式消费者。首次上线仍须填写真实正式配置并另行批准，不能通过选择 workflow 的 `production` 选项取得生产授权。

## 运行前配置

受保护的环境需要 `SUBS_BOT_TARGET_JSON`、`SUBS_BOT_CONTROL_SECRETS`、`SUBS_BOT_CF_DATA_TOKEN`、`SUBS_BOT_CF_WORKER_TOKEN`，与生产生命周期控制相同。额外配置 `SUBS_BOT_RECOVERY_JSON`。每个变更还需准确的 `SUBS_BOT_APPROVAL_JSON`。

数据凭据只需本项目账户的 D1 创建/原生导出/原生导入及 R2 读写能力。代码对数据请求另设严格路径与只读源约束；不提供源业务 SQL 写入、DELETE、reset、Time Travel 恢复或 Worker 部署路径。消费者发现使用 Worker 只读能力，检查全账户脚本及服务环境绑定；不能完整读取时停止。R2 条件写入以现有受保护 Token 身份派生 S3 签名，不把凭据放入上传对象。

常规基线配置示例，以下 ID 仅为格式占位符：

```json
{
  "version": 1,
  "checkpointId": "11111111111111111111111111111111",
  "databaseName": "subs-bot-cf-restore-baseline-example",
  "objectsName": "subs-bot-cf-restore-baseline-example",
  "purpose": "baseline"
}
```

`checkpointId` 为本次唯一的 32 位小写十六进制标识。恢复 D1/R2 名必须是本项目新的 `subs-bot-restore-*` 或 `subs-bot-cf-restore-*` 名，不能等于源 Worker、D1、对象桶或备份桶名。它们在 `prepare` 时必须不存在；常规备份无需创建这些恢复目标。

每次 mutation 的 approval action 为 `recovery-<action>:<SHA-256(canonical 完整恢复配置)>`，其余 approval 字段严格关联环境、固定目标身份 `targetSha256` 和完整当前配置 `configurationSha256`。`revision` 固定为被恢复 G0 的源 CI 提交，`controlRevision` 为当前 main 控制工具提交，`stateSha256` 绑定当前现场／G1 的准确前态，不能互换。开关、Provider、密钥摘要及 Webhook 配置属于配置摘要，不改变固定资源身份；每次更改仍须单独批准并重新核验准确部署。不能把另一个 checkpoint、另一份 G1 或另一组目标的批准用于本次操作。可用生命周期 `inspect` 或本工作流 `inspect` 的 `sourceStateSha256` 取得准确前态。

## 同一状态的 D1/R2 备份

1. 用生命周期 `plan-pause` 取得准确批准前态，明确批准该摘要后执行 `pause` 关闭新增 admission，再 `inspect → drain`。普通 inspect 摘要不能替代 plan-pause；保留已经持久受理的后台任务完成，查看完整分类 work 和 terminal 计数。
2. 仅在尚可执行的工作为零时 freeze。中断租约必须按受保护分类流程处理，保留不确定终态，不删记录或重发消息。未知外部结果不是成功完成，也不能据此自动激活消费者。
3. 用准确源 CI run/attempt 调用 `prepare`。工具核对固定源资源、版本、模块、配置、完整迁移及冻结 epoch，在固定私有备份桶建立追加式意图链。
4. 调用 `capture`。工具原生导出 D1，受限私有 scratch 重建完整 schema/外键/数据，捕获所有 D1 引用的 R2 对象、字节和 ownership metadata。导出后和对象捕获后分别比较完整源数据摘要，并再次读回对象及元数据；源发生变化就停止，不发布完整 manifest。
5. 调用 `verify-backup` 独立读回。封存包含 SQL 分片、引用对象闭包、完整批准配置及其摘要、原始可信 CI ZIP/来源证明；manifest 最后写入。配置包含角色/范围及密钥摘要，实际 Secret 不进入备份；私有配置原件不会进入公开报告。公开报告仅保留 run、身份摘要、数据/对象摘要及数量。

原始 CI ZIP 同样保存在私有 checkpoint 中。Actions 产物到期后可通过 `source_manifest_sha256` 从私有 R2 加载并重新核验准确源代码，无需重新构建旧版本或改写原证明。当前现场 CI 与冻结恢复源 CI 分开选择；恢复旧数据不意味着允许部署旧代码。

## 基线独立恢复

源保持与基线相同的冻结控制和完整数据时，可顺序调用：

```text
create-database
create-objects
restore-objects
start-import
verify-restore
```

创建前先写入每个资源的持久意图。创建后固定实际 ID、名称、创建时间和私有性。未知同名资源不会被自动采用。恢复只写独立目标：D1 必须新建且为空，R2 采用 `If-None-Match: *` 条件写入，冲突内容或元数据不同就停止。完整 Worker 绑定发现必须证明目标没有消费者。

`verify-restore` 比较完整 schema、迁移账本、每表 typed-cell 摘要、数量、序列、外键、完整性、授权/归属/撤销记录及全部引用对象。随后在无出网托管运行时重放已证明等于远端 D1 的数据与实际恢复对象，使用准确模块和目标 origin；以合成凭据检查真实生产暂停门和适用链接的 GET/HEAD。没有真实 Bot 凭据、Webhook、对外目标 Worker 或消费者。

HTTP 报告明确区分成功导出、精确已知 422 内容拒绝及未覆盖项。哈希能力链接、无效或结构化内容、超出响应界限的内容不能冒充成功导出。完整授权与撤销数据对账不等同于每种哈希能力均已做实时外部链接探测。

## 新写入后的 G1 与恢复会话

G0 之后发生任何新增、修改、删除、授权、领取、撤销、短链或外部回复，旧基线不能直接恢复切换。先保留现场，以新的 checkpoint、`purpose: "incident"` 完整封存当前冻结状态 G1。G1 与 G0 都不删除。

恢复 G0 到另一组新目标时，建立独立会话配置：

```json
{
  "version": 1,
  "checkpointId": "11111111111111111111111111111111",
  "sessionId": "22222222222222222222222222222222",
  "sourceManifestSha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "databaseName": "subs-bot-cf-restore-incident-example",
  "objectsName": "subs-bot-cf-restore-incident-example",
  "purpose": "recovery",
  "preservedG1": {
    "checkpointId": "33333333333333333333333333333333",
    "manifestSha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  }
}
```

上例所有摘要和 ID 均是格式占位符，必须替换成独立读回的真实值。执行 `prepare-restore` 后，再执行创建目标、恢复对象、原生导入、完整对账步骤。新的 session 有独立 journal 和资源所有权，G0 的原始 manifest/对象/代码及旧恢复目标保持原状。

工具完整读回 G1 SQL/对象/元数据与代码，并要求当前现场的完整数据、对象和冻结身份仍与 G1 相同。缺失 G1、摘要错误或封存后又发生写入均拒绝继续。恢复后的独立目标只证明 G0 可以重建；它不含 G0 到 G1 的自动增量回放。消费者切换仍需明确的数据处置决定及另行批准。不能保全新写入时保持暂停，不能承诺无损回退。

仅回退代码时保留当前 D1/R2，先证明准确候选兼容当前完整 schema、配置、密钥、授权、回执和撤销语义；不兼容或平台拒绝旧版本时使用经审查的兼容前向发布。回退 Worker 不回退数据库，D1 Time Travel 不恢复 R2。

## 失败、中断与重复执行

| 情况 | 安全处理 |
| --- | --- |
| 创建资源丢响应 | 保留 `started/unknown` 意图；只读查候选，独立核对身份 SHA 和创建时间窗后用 `pin-resource`；不重复 create、不采用未知资源 |
| 导出开始后丢书签 | 保留 unknown，等待平台取消并核对正常查询恢复；不自动重启导出 |
| 已知导出书签超时 | 用原 checkpoint 和 `poll-export` 接续同一导出；有界轮询到期不会报告完成 |
| 对象写入丢响应 | 重新读同一键的完整字节和元数据；相同才可确认，不同或未知即停止 |
| init/ingest 丢响应 | 只用已知书签轮询或只读完整对账；不重复 init/ingest、不清库 |
| journal 写入不明 | 同一调用停止后续 mutation；下次独立读完整 hash chain，冲突、缺代或未确认值阻止继续 |
| 重复已确认调用 | 从持久 pin、内容摘要和完整远端状态确认；不会重复产生未知的创建或导入操作 |
| 恢复目标有 Worker 绑定或公开 R2 | 停止恢复，保留原数据和目标；不会修改其他 Worker 来消除阻塞 |

专用演练若在 G0 独立恢复阶段中断，可在同一个 `recovery` action 显式填写 `recovery_resume_json`，复用已创建的原 D1/R2 和原 hash-chain journal，而不是重新 capture 或 create。以下仅为格式占位符，所有值均须来自独立私有读回：

```json
{"version":1,"checkpointId":"11111111111111111111111111111111","manifestSha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","journalSha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
```

同时填写原登记 `registration_sha256` 和准确当前线上源的 `active_run_id`；工具代码仍运行当前 main。续接先完整核对最新 journal 摘要、封存 manifest/代码/SQL/对象、原目标 ID／创建时间／私有性、当前源冻结状态及完整数据，以及全账户 Worker／服务环境的无消费者证明。服务环境必须是准确身份的完整 API wrapper，包含默认环境；未知包装、默认环境缺失、分页或超限均拒绝。全部只读前置检查通过后才 claim 原 journal，从 `verify-backup → restore-objects → start-import → verify-restore` 接续；已确认对象仍读回字节与元数据，未知导入仅按原书签或完整状态对账处理。旧 latest-journal pin 在链推进后立即失效，不能重复使用。

该演练续接仅用于当前源仍等于原 G0 的阶段，不自动跳过之后的 G1／新写入，亦不复用不明的 G1 会话。源发生变化时停止，按前述 G1 和独立恢复会话流程处理。原失败证据保留，只有新流程的完整数据／对象和无出网 HTTP 验证都通过后才能报告恢复通过。失败报告只包含固定 action／消费者读取阶段、数值 HTTP 状态及不确定标记，不包含其他项目配置、响应体、URL 或凭据。

## 容量与限制

| 项目 | 当前硬界限 |
| --- | --- |
| 原生 SQL 导出 | 32 MiB |
| 完整 D1 数据 | 20,000 行；支持 NULL/TEXT/INTEGER/REAL，INTEGER 限于 JavaScript 安全整数范围 ±(2^53−1)，BLOB 拒绝；单元格至多 2,000,000 UTF-8 字节，每行 canonical typed 编码至多 8,000,000 字节 |
| 引用 R2 闭包 | 至多 512 对象、总计 256 MiB、单对象 512 KiB；私密分享更严格遵守业务内容界限 |
| 私有 manifest | 256 KiB |
| 原始 CI ZIP | 16 MiB，最多 32 个 512 KiB 分片 |
| 控制 journal | 至多 4,096 代，单代 32 KiB |
| 消费者发现 | 单页 Worker 脚本/服务各少于 1,000；每服务环境少于 32；未知分页或截断状态直接失败 |
| 原生导出/导入轮询 | 每次循环期限 120 秒，不包含已在途请求的 HTTP timeout；保留已知书签供下次接续 |

所有界限采用超限拒绝，不截断数据。工具备份完整 D1 与 D1 引用的 R2 闭包，不声称复制任意无引用孤儿对象或 Worker Secret。Secret 由受保护配置另行保管。任务超时可能留下已确认分片或独立目标；这些资料不会被自动删除。源码/配置/密钥不兼容、非支持 schema/元数据或无法完整读取资源时停止，不能用部分摘要宣布恢复成功。

## 隔离日常备份控制草案（尚未启用）

仓库包含待验收的日常备份、私有事务锚、独立监控和中断检查实现，入口默认关闭；尚未完成精确提交的托管测试、隔离故障演练、独立读回、代码审查以及实际 R2 条件写和分页响应核对前，不应视为已经验收。隔离 Environment 的 `SUBS_BOT_REHEARSAL_BACKUP_WRITES_ENABLED` 只控制隔离备份写入及事务锚协调；独立的 `SUBS_BOT_REHEARSAL_BACKUP_WATCHDOG_ENABLED` 控制看护，使停止发起新备份不会同时关闭未决事务看护。日常定时触发还需单独设置 `SUBS_BOT_REHEARSAL_DAILY_BACKUP_ENABLED`，监控定时触发使用 `SUBS_BOT_REHEARSAL_BACKUP_MONITOR_ENABLED`。这些开关均须显式设置为 `true`，默认不启用。

生产 Environment 的 `SUBS_BOT_PRODUCTION_BACKUP_WRITES_ENABLED` 默认关闭，仅允许在另行批准正式运维策略后启用。它只允许进入已选的单步受保护入口，不生成授权：每次仍须精确目标、动作、来源和前态的独立批准，且禁止重跑 mutation attempt。生产 schedule 仅可运行只读监控，不能自动启动生产备份。

草案默认每日 01:00 UTC 备份，80% 容量预警、300 秒暂停告警门限；百分比和门限可配置。暂停门限是触发检查和报警的时间，并非对 Cloudflare 在途请求或 runner 中断的硬时限保证。预检统计迁移链中的所有表和数据库引用对象闭包；活跃现场的读数不是一致快照，SQL 导出大小须冻结后才能准确验证，行数超限时对象未检查会明确标记。最终仍须完整封存与独立读回，容量或读回未知均不能报告成功。30 天为待批准建议，不自动删除 G0、G1、未结案证据或任何备份。

20,000 是全部受支持表的行数总和，不是用户数；例如 Telegram 收件/发件、生产更新处置、调用及 Provider 处理记录也占用容量，日常消息可使其增长。当前恢复链不适合无界增长：接近上限时必须在尚能完整备份的窗口内安排经审查的分片备份与恢复能力扩容，验证后才能提高运行边界；不能以删除处理记录、跳过表或截断对象代替扩容。预检超限时不应开始暂停，并应保留最后一次成功备份、发出告警和安排扩容；冻结后才发现 SQL 过大或其他无法预检的限制时，按事务状态核对是否可以安全恢复接收。现阶段没有已验证的自动扩容或数据清理方案。

隔离计划只允许固定 rehearsal 身份。原已关闭冻结的源完成后仍保持关闭冻结；仅在事务前确认 open/run 的源，才可在满足控制与依赖前置条件后恢复。已受理任务在排空时保留；不确定的外部结果或未确认写入须停止并告警，不重发。看护流程不会把缺失 recovery journal 或不明导出当作已停止。真实测试 Bot 的 webhook 与既有设置需在单独的受控验证窗口内恢复；每日后台计划不能擅自切换或占用它们。

事务锚采用独立配置的 genesis 摘要、目标专用私有指针及不可变历史；指针缺失、历史断链、分页无法证明完整或存在未确认未来代时停止。当前历史盘点最多 10,000 个对象，接近该界限必须先执行经审查的外部锚及轮换方案；该轮换尚未实现。部分初始化或无法证实的并发候选不得通过删除历史解决。手动 `backup-anchor-reconcile-plan` 和 `backup-anchor-reconcile` 仅针对有确认证据的已完成事务 release，写入入口受隔离开关及精确批准保护；原 run 已结束、journal 终态和当前配置/控制必须重新核验，计划 SHA 不替代这些检查。

生产 checkpoint 的 `plan-initialize-anchor` 会只读给出按目标身份计算的 genesis 摘要；首次初始化前须独立固定该摘要并逐动作批准。新 begin 在 acquire 前先独占封存实际 writer、来源、批准摘要、准确控制前态和 anchor 前驱。若原 writer 已结束、完整 journal 确认为空、该 intent 与当前源码和现场均精确匹配，`plan-abort-unstarted` 可生成只读计划，`abort-unstarted` 经独立批准与单次恢复 intent 后终结此会话；唯一可核对的 future acquire 候选也可按摘要显式协调。任何恢复 intent 响应不明或重试、缺失 intent 的旧现场、跨控制版本、日志分叉或在途写入均保持 unknown，不能凭对象暂时缺失重放。`plan-anchor-reconcile` / `anchor-reconcile` 仍只处理原 resume intent 所属 run 已完成、完整 journal 已确认 resumed 且终态精确匹配的 release，不把失败备份改称成功。生产 mutation 默认关闭，并要求上面所述的单步精确批准。

在完整事务 journal 证明尚无 capture 或 poll intent、原 freeze run 已完成且该 checkpoint 的 recovery journal 不存在时，`plan-resume-failed` 可针对确认属于本次维护的 frozen 状态生成受限恢复计划；已完成 fingerprint 时还要重新核对完整冻结数据。恢复动作仍需精确审批，重验依赖和无未知外部结果后才执行一次 CAS。若 recovery journal 存在、导出状态未知、日志缺失或存在未确认写入，则停留并告警；该路径不替代新激活所需的完整基线。此草案不自动授权或保证暂停硬时限。

`capacity-near`、`capacity-over`、`readback-failure` 和 `process-kill` 仅是手动隔离 dispatch 的合成故障模式：它们分别模拟阈值、独立读回失败和 runner 进程中断，不表示真实数据达到阈值或真实 R2 对象被损坏。托管 fixture、Cloudflare 实际验收和生产配置是独立结论，不能以其中任何单项代替整体验收。

另有待接入可信 main gate 的 `capacity-fixture` 候选入口：只针对独立登记、与现有业务 D1 不同的专用 D1 和私有桶，验证准确迁移链，逐次追加合成 finished invocation，测量全库达到 16,000、20,000 和 20,001 行时的真实预检；超限复用日常备份的同一暂停前拒绝条件。每次 schema 或 seed 写入前记录独占私有 intent，意外或未知结果不重发，也不清理数据；每个边界需在追加下一批前用独立 run 复读相同数据与原 run 证据。该入口的实际资源创建、可信 gate、平台侧最小权限和 Cloudflare 执行仍需独立完成。无 Worker 绑定 witness 是有时效的独立观察，不是禁止新绑定的实时平台锁；验收时须独立复读并排除并发绑定。只测行数不能宣称真实对象数量和字节上限已验证。

候选的托管隔离验收拟使用受信 main 的 `worker-backup-reviewed-head.yml`，由专用 `subs-bot-backup-head-isolation` Environment 另行固定已审查候选 SHA；入口默认关闭。可信 main guard 在注入凭据前后核对同仓库 PR、当前 main 祖先、受保护 pin 和两个独立 checkout。候选代码将 GitHub dispatcher main SHA 与 candidate controller SHA 分开记录，不改写 GitHub 提供的 `GITHUB_*`。每次 watchdog 必须核对相同候选、原 run 的可信 dispatcher 和 journal；不能用新 head 推断旧写入的结果。专用环境只提供本项目隔离 D1/R2 所需凭据、Worker 只读凭据和用户授权的测试 Bot 配置；确切权限及有效期须在启用前独立核实。closed/frozen 演练不修改 webhook；open 状态恢复接收仍需独立的短期受控 webhook 窗口和最终恢复证据。
