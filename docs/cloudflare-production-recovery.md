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
