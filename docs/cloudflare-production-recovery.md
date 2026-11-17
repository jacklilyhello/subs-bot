# 生产身份备份与独立恢复

`worker/tools/production_recovery.py` 和 `production_recovery_cli.py` 是独立的生产控制实现，使用与部署控制相同的 `production_target.py` 配置契约。`worker-production-recovery.yml` 在 GitHub 托管 runner 执行。生产与明确登记的 rehearsal 运行相同的代码；不修改历史隔离恢复脚本的账户、资源或源版本保护，也不自动采用已有 dev 目标。

恢复 Environment 必须分别配置 `SUBS_BOT_CF_DATA_READ_TOKEN`、`SUBS_BOT_CF_DATA_TOKEN`（D1 写）、`SUBS_BOT_CF_WORKER_READ_TOKEN`、`SUBS_BOT_CF_R2_METADATA_READ_TOKEN` 及按准确桶登记的 `SUBS_BOT_SCOPED_R2_READ_JSON`／`SUBS_BOT_SCOPED_R2_WRITE_JSON`。仅创建数据库、导出及导入步骤得到 D1 写凭据；Worker 始终只读，`inspect`／`verify-backup` 不注入对象写凭据。其余恢复步骤仍可能追加私有 journal，不能因为 D1 只读就称整个步骤没有写入。缺失的只读配置不回退到写凭据。

`create-objects` 另需经批准的 `SUBS_BOT_CF_R2_CREATE_TOKEN`，仅向该步骤注入；D1、对象 S3 或 metadata read 凭据不能替代创建权限。隔离 native 恢复的两个建桶动作使用相同规则。创建新目标仍受原始 intent、精确名称、独立身份读回和无消费者检查约束；新桶在任何对象读写前必须加入对应的准确桶 S3 凭据配置。该配置项不构成创建资源或扩大平台权限的授权。

已登记 control-drill 的真实恢复可在同一个工作流显式选择 `environment=rehearsal`，提供 `rehearsal_registration_sha256`，并把准确恢复 contract 配入该隔离 Environment 的 `SUBS_BOT_RECOVERY_JSON`。这一路径从原私有登记加载唯一演练目标，复用现有隔离 Bot／签名配置，使用相同恢复引擎及全部源、前态、日志和独立目标检查；没有重新构建或修改旧源。自动生成的动作批准仅适用于既有 `subs-bot-cf-control-drill-01`，不能用于 production。选择此模式时不接收另一份 `SUBS_BOT_TARGET_JSON`、`SUBS_BOT_CONTROL_SECRETS` 或批准 Secret。未提供登记摘要时沿用原明确目标／外部批准模式；不存在默认 dev 回退。新资源创建仍需本次准确目标的外部授权。

输入的登记摘要必须同时等于受保护 Environment 的 `SUBS_BOT_REHEARSAL_REGISTRATION_SHA256`；调用者自给摘要不足以替换登记。源现场仍与正常 baseline 完全一致时，可以沿该 baseline 已 captured 的原 journal 接续创建独立目标及恢复。创建前也会重核完整源库和全部引用对象／metadata；现场已变化即停止。若存在后续写入，必须另行封存 G1，再使用独立 recovery session，不能伪造 G1 或把旧 baseline 覆盖回源。

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
| CI 归档解包及 Worker | 解包累计至多 64 MiB；Worker 模块至多 1,152 KiB；归档成员还须符合各自的大小及路径检查 |
| 控制 journal | 至多 4,096 代，单代 32 KiB |
| 消费者发现 | 单页 Worker 脚本/服务各少于 1,000；每服务环境少于 32；未知分页或截断状态直接失败 |
| 原生导出/导入轮询 | 每次循环期限 120 秒，不包含已在途请求的 HTTP timeout；保留已知书签供下次接续 |

所有界限采用超限拒绝，不截断数据。工具备份完整 D1 与 D1 引用的 R2 闭包，不声称复制任意无引用孤儿对象或 Worker Secret。Secret 由受保护配置另行保管。任务超时可能留下已确认分片或独立目标；这些资料不会被自动删除。源码/配置/密钥不兼容、非支持 schema/元数据或无法完整读取资源时停止，不能用部分摘要宣布恢复成功。

## 隔离日常备份控制草案（尚未启用）

仓库包含待验收的日常备份、私有事务锚、独立监控和中断检查实现，入口默认关闭；尚未完成精确提交的托管测试、隔离故障演练、独立读回、代码审查以及实际 R2 条件写和分页响应核对前，不应视为已经验收。隔离 Environment 的 `SUBS_BOT_REHEARSAL_BACKUP_WRITES_ENABLED` 只控制隔离备份写入及事务锚协调；独立的 `SUBS_BOT_REHEARSAL_BACKUP_WATCHDOG_ENABLED` 控制看护，使停止发起新备份不会同时关闭未决事务看护。日常定时触发还需单独设置 `SUBS_BOT_REHEARSAL_DAILY_BACKUP_ENABLED`，监控定时触发使用 `SUBS_BOT_REHEARSAL_BACKUP_MONITOR_ENABLED`。这些开关均须显式设置为 `true`，默认不启用。

生产 Environment 的 `SUBS_BOT_PRODUCTION_BACKUP_WRITES_ENABLED` 默认关闭，仅允许在另行批准正式运维策略后启用。它只允许进入已选的单步受保护入口，不生成授权：每次仍须精确目标、动作、来源和前态的独立批准，且禁止重跑 mutation attempt。生产 schedule 仅可运行只读监控，不能自动启动生产备份。

草案默认每日 01:00 UTC 备份，80% 容量预警、300 秒暂停告警门限；百分比和门限可配置。独立的 `maximumPauseSeconds` 默认 1,800 秒（可配置 300–21,600 秒，且不小于报警门限）；超时后不得启动新的冻结或捕获，按精确已知状态执行受限恢复。任何门限都不是对 Cloudflare 在途请求或 runner 中断的硬时限保证。预检统计迁移链中的所有表和数据库引用对象闭包；活跃现场的读数不是一致快照，SQL 导出大小须冻结后才能准确验证，行数超限时对象未检查会明确标记。最终仍须完整封存与独立读回，容量或读回未知均不能报告成功。30 天为待批准建议，不自动删除 G0、G1、未结案证据或任何备份。

20,000 是全部受支持表的行数总和，不是用户数；例如 Telegram 收件/发件、生产更新处置、调用及 Provider 处理记录也占用容量，日常消息可使其增长。当前恢复链不适合无界增长：接近上限时必须在尚能完整备份的窗口内安排经审查的分片备份与恢复能力扩容，验证后才能提高运行边界；不能以删除处理记录、跳过表或截断对象代替扩容。预检超限时不应开始暂停，并应保留最后一次成功备份、发出告警和安排扩容；冻结后才发现 SQL 过大或其他无法预检的限制时，按事务状态核对是否可以安全恢复接收。现阶段没有已验证的自动扩容或数据清理方案。

隔离计划只允许固定 rehearsal 身份。原已关闭冻结的源完成后仍保持关闭冻结；仅在事务前确认 open/run 的源，才可在满足控制与依赖前置条件后恢复。已受理任务在排空时保留；不确定的外部结果或未确认写入须停止并告警，不重发。看护流程不会把缺失 recovery journal 或不明导出当作已停止。真实测试 Bot 的 webhook 与既有设置需在单独的受控验证窗口内恢复；每日后台计划不能擅自切换或占用它们。

事务锚采用独立配置的 genesis 摘要、目标专用私有指针及不可变历史；指针缺失、历史断链、分页无法证明完整或存在未确认未来代时停止。当前历史盘点最多 10,000 个对象，接近该界限必须先执行经审查的外部锚及轮换方案；该轮换尚未实现。部分初始化或无法证实的并发候选不得通过删除历史解决。手动 `backup-anchor-reconcile-plan` 和 `backup-anchor-reconcile` 仅针对有确认证据的已完成事务 release，写入入口受隔离开关及精确批准保护；原 run 已结束、journal 终态和当前配置/控制必须重新核验，计划 SHA 不替代这些检查。

生产 checkpoint 的 `plan-initialize-anchor` 会只读给出按目标身份计算的 genesis 摘要；首次初始化前须独立固定该摘要并逐动作批准。新 begin 在 acquire 前先独占封存实际 writer、来源、批准摘要、准确控制前态和 anchor 前驱。若原 writer 已结束、完整 journal 确认为空、该 intent 与当前源码和现场均精确匹配，`plan-abort-unstarted` 可生成只读计划，`abort-unstarted` 经独立批准与单次恢复 intent 后终结此会话；唯一可核对的 future acquire 候选也可按摘要显式协调。任何恢复 intent 响应不明或重试、缺失 intent 的旧现场、跨控制版本、日志分叉或在途写入均保持 unknown，不能凭对象暂时缺失重放。`plan-anchor-reconcile` / `anchor-reconcile` 仍只处理原 resume intent 所属 run 已完成、完整 journal 已确认 resumed 且终态精确匹配的 release，不把失败备份改称成功。生产 mutation 默认关闭，并要求上面所述的单步精确批准。

在完整事务 journal 证明尚无 capture 或 poll intent、原 freeze run 已完成且该 checkpoint 的 recovery journal 不存在时，`plan-resume-failed` 可针对确认属于本次维护的 frozen 状态生成受限恢复计划；已完成 fingerprint 时还要重新核对完整冻结数据。恢复动作仍需精确审批，重验依赖和无未知外部结果后才执行一次 CAS。若 recovery journal 存在、导出状态未知、日志缺失或存在未确认写入，则停留并告警；该路径不替代新激活所需的完整基线。此草案不自动授权或保证暂停硬时限。

`capacity-near`、`capacity-over`、`readback-failure` 和 `process-kill` 仅是手动隔离 dispatch 的合成故障模式：它们分别模拟阈值、独立读回失败和 runner 进程中断，不表示真实数据达到阈值或真实 R2 对象被损坏。托管 fixture、Cloudflare 实际验收和生产配置是独立结论，不能以其中任何单项代替整体验收。

另有待接入可信 main gate 的 `capacity-fixture` 候选入口：只针对独立登记、与现有业务 D1 不同的专用 D1 和私有桶，验证准确迁移链，逐次追加合成 finished invocation，测量全库达到 16,000、20,000 和 20,001 行时的真实预检；超限复用日常备份的同一暂停前拒绝条件。每次 schema 或 seed 写入前记录独占私有 intent，意外或未知结果不重发，也不清理数据；每个边界需在追加下一批前用独立 run 复读相同数据与原 run 证据。该入口的实际资源创建、可信 gate、平台侧最小权限和 Cloudflare 执行仍需独立完成。无 Worker 绑定 witness 是有时效的独立观察，不是禁止新绑定的实时平台锁；验收时须独立复读并排除并发绑定。只测行数不能宣称真实对象数量和字节上限已验证。

读取令牌权限探针使用另一独立登记且无 Worker 绑定的 D1，可信 main 先按 probe D1 ID 独占记录不可重用 intent；候选只携带 D1 Read 凭据，对该 D1 仅尝试一次固定 CREATE。只有前置只读查询成功、写请求明确返回 HTTP 403 且复读确认表不存在，才可报告请求被拒；成功或其他未知结果保留现场，不重新发送。另一个 fresh trusted runner 再用只读凭据检查同一 D1、私有 intent 和表不存在。受限 token 的平台策略还须独立检查，probe 的结果不能外推为其他 token 或其他账户的权限保证。

候选的托管隔离验收拟使用受信 main 的 `worker-backup-reviewed-head.yml`，由专用 `subs-bot-backup-head-isolation` Environment 另行固定已审查候选 SHA；入口默认关闭。可信 main guard 在注入凭据前后核对同仓库 PR、当前 main 祖先、受保护 pin 和两个独立 checkout。候选代码将 GitHub dispatcher main SHA 与 candidate controller SHA 分开记录，不改写 GitHub 提供的 `GITHUB_*`。每次 watchdog 必须核对相同候选、原 run 的可信 dispatcher 和 journal；不能用新 head 推断旧写入的结果。专用环境只提供本项目隔离 D1/R2 所需凭据、Worker 只读凭据和用户授权的测试 Bot 配置；确切权限及有效期须在启用前独立核实。closed/frozen 演练不修改 webhook；open 状态恢复接收仍需独立的短期受控 webhook 窗口和最终恢复证据。

### 增长与运行边界

完整库的 20,000 行上限包含迁移账本、控制和调用记录、Telegram 收件与回复、订阅及其他全部表，不是用户数。生产 Cron 固定每分钟触发；只要 `workers=run`，每次成功进入 scheduled 路径都会持久新增一条 invocation，即使 admission 已关闭也是如此。若实际每分钟恰好成功触发一次，名义增长约为每小时 60 行、每天 1,440 行、15 分钟 15 行；漏触发、重试和重叠会改变实际数量，不能作为严格下界或上界。一次首次受理的 Telegram 更新至少会新增 invocation 与 update disposition；不同命令还可能新增 inbox、outbox、订阅、任务、分享等多表记录及引用 R2 对象。重复投递、业务量、对象大小和增长速度必须分别观测，不能由用户数推算。

默认 80% 行数告警对应 16,000 行，距 20,000 行只有 4,000 行。如果没有其他增长且告警即时出现，仅按上述名义 Cron 速率计算约剩 66 小时 40 分；实际业务增加、调度重试和发现/处理延迟会缩短这个时间。每日 01:00 UTC 备份和默认 48 小时无成功备份告警都不足以充当容量响应期限：假设 16,000 行阈值刚过就错过一次日常备份，单按名义 Cron 一天还会新增约 1,440 行；48 小时则约 2,880 行，尚未计入业务增长。日常备份前会再次执行 preflight；独立只读监控默认每 15 分钟扫描各表与引用对象，也可配置为 30 或 60 分钟。活跃采样不是一致性快照：扫描中发现变化、对象缺失、读取错误或无法完成时告警 unknown，不等同于完成备份。15 分钟 watchdog 处理未决维护，300 秒暂停告警可能在下一次轮询（约 15 分钟）及 GitHub 排队后才出现；不能保证容量扫描、告警送达或人工响应恰在 15 分钟内完成。上述数字仅是条件明确的规划示例，不保证平台调度或人工响应时限。

上线前按真实观察窗口记录全库行数、引用对象数和字节数，核算最高观测增长率、采样延迟和至少一个响应窗口的余量；未完成运维策略和费用/停机审批前，生产周期任务保持关闭。接近任一上限、增长速率不明或剩余余量不足以覆盖下一次观测及处置时，运维应立即检查最新容量、最后完整备份及未决事务，在余量仍足够时按已批准的控制步骤关闭新增接收并保留 Telegram 待处理更新；允许已受理工作完成或明确分类，再排空并冻结，独立读回控制和数据状态后封存完整现场。单独关闭 admission 并不能停止 scheduled invocation 增长，必须把排空与冻结期间新增的调用记录纳入余量，并独立确认冻结后 Worker 状态；如果预估不足以安全排空、存在未知外部结果或控制写入结果不明，停止后续写操作、保全现场并升级处置，不重发。冻结后再次完整测量并核对可恢复的 G0/G1；任何阶段 SQL 导出、manifest、源码或单对象超限均可能阻断完整备份，不能从行数正常推断备份可成功。

达到或超过边界时，现有限制仍然生效：不得忽略表、截断、删除业务/处理记录或把部分备份称为成功。保留现场和全部 G0/G1/未结案证据，暂停新增写入；只有在经审查的容量处理完成、对完整数据及引用对象执行真实独立目标恢复和对账、并获得相应运维批准后，才能按新边界恢复接收。不能把合成阈值测试或单次备份读回当作扩大恢复上限的证明；也不声称自动增量回放或无损覆盖回退。

15 分钟采样会执行全部表的 D1 计数、迁移/控制核验以及引用对象的列表与内容读取；在 512 个对象、256 MiB 上限附近，每日最多约 96 次扫描、49,152 次对象内容读取和 24 GiB 引用对象读取，另有列表、元数据及源代码读取。实际请求数与耗时取决于数据和失败重试；启用前应按账户费率评估，必要时配置 30/60 分钟并相应扩大容量余量。平台延迟或扫描超过调度间隔时应告警并停止将旧状态当作最新容量。

只读监控提供 GitHub 失败检查、annotation、摘要以及保留 7 天的 JSON artifact；任务输出 `status`、`alerts_json`、`report_sha256`、`notification_relevant` 供同一 workflow 的受控步骤接入。外部接收器可按受信的 workflow run ID 下载 artifact、核对摘要并根据 alert 分类路由；它必须自行处理重复或缺失 run，不能把未取得 artifact 当作健康。隔离和生产环境分别可用 `SUBS_BOT_REHEARSAL_BACKUP_NOTIFICATION_FILTER` 与 `SUBS_BOT_PRODUCTION_BACKUP_NOTIFICATION_FILTER` 配置逗号分隔的通知类别，默认 `*`；过滤仅决定路由标记，不移除原告警或改变失败检查。监控 unknown 和无效过滤配置始终标记相关。此接口不发送外部消息，本轮没有配置通知端点或实际投递；已授权的测试 Bot 和管理员并不意味着此处已接入 Telegram。生产监控仍默认关闭，启用及接收器归属须另行批准。

容量采样只使用 D1 Read 与私有 R2 对象/metadata 只读凭据；代码也拒绝非只读 D1 SQL 与 R2 写操作。平台对 D1 Read 令牌的实际负向写入拒绝必须在独立专用 probe D1 实测，不能仅凭权限名称或本工具自身的 SQL 限制声称已验证；probe 未通过前应保留该权限边界的未验收状态。
