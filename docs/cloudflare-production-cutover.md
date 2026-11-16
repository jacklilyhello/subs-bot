# Cloudflare 首次生产上线执行方案

用户于 **2026-11-16** 确认本项目从未投入生产，没有旧生产实例、SQLite/WAL、正式用户数据、旧生产链接或旧消费者；正式 Bot 尚未创建。因此旧数据迁移、最终旧库快照和旧消费者/处理水位交接均为 **N/A（不适用：用户确认无历史生产）**，不再追加旧服务开发。该分类不同于 Passed 或 Not run；历史验收、失败和候选中的 `Not run` 原样保留，由独立说明记录本次首次上线的 N/A 项。

本文件对应已实现的受保护生产配置、创建、初始化、部署、暂停、排空、备份、恢复和激活控制。它是取得正式配置和逐项批准后的执行说明，不表示生产已经上线。工具的准确提交、云端检查和实际隔离演练结果记录在 PR 证据中；候选包、隔离恢复和真人测试均不授予生产操作权限。

## 上线目标与前置条件

| 项目 | 具体安排 | 执行前必须固定 |
| --- | --- | --- |
| 正式 Bot | 新建专用正式 Bot，测试 Bot 继续独立保留 | 维护者创建或另行明确授权创建后，核对 `getMe` 的 ID/用户名，安全注入凭据 |
| 账户/Zone | 账户 `9431815bdb8beb2272f6668e06b7d3be`；Zone `07c83547944da720e03b31a406fdcd55` | 独立读回归属，批准不扩展到其他账户或 Zone |
| 正式 Worker | 拟建项目专用 `subs-bot-cf-prod-01` | 名称可用性、唯一资源身份、准确版本/模块摘要和创建记录 |
| 正式数据 | 拟建 D1、私有 R2 各名为 `subs-bot-cf-prod-01`；私有备份桶 `subs-bot-cf-prod-backup-01` | 尚未创建；先核对名称可用性，创建后独立固定各 ID/时间、迁移清单、初始化白名单和保留策略 |
| 正式域名 | 预留 `subs-bot.lilyya.top` | Zone、DNS/路由/Custom Domain 无冲突，唯一绑定目标 |
| 初始权限 | 只初始化明确批准的正式管理员、成员/默认策略和群范围 | 正式账号/群 ID、授权世代和拒绝规则清单摘要 |
| 展示时区 | 默认 UTC；管理员私聊可设置有效地区时区并持久保存 | 正式初始设置，不改为默认新加坡时区 |
| 生产控制 | 独立受保护的生产部署、暂停、排空和恢复步骤 | 准确工具提交、生产身份、前态摘要保护及隔离验证证据 |

正式 Bot 和初始正式账号尚未确定。测试管理员 `8813701954`、成员 `8653767757`、群 `-5114255828` 不自动成为正式配置。正式库不复制测试订阅、授权覆盖、回执、短码、分享、临时节点、恢复演练数据或测试签名密钥。现有测试环境和原记录保持原样。

生产操作使用 [生命周期控制](cloudflare-production-controls.md)、[ProviderFetch 控制](cloudflare-production-provider.md) 和 [备份／故障恢复控制](cloudflare-production-recovery.md)。`worker-isolation-*` 继续保护原隔离资源，不通过替换其资源名称来操作生产。正式身份、明确配置、必要凭据或本次操作批准缺失时，工具拒绝执行，保持接收关闭；不会回退到测试身份。所有安装、构建、自动化测试、恢复和运行验证仍只在 GitHub 托管 runner 或 Cloudflare 执行。

## 审批所需证据与局部限制

批准清单必须关联准确 main SHA、Worker/Python CI run/attempt、原 ZIP/模块摘要、完整迁移、隔离部署和独立版本/绑定/配置读回；同时提供私有持久候选归档、来源 CI/部署证明及 D1/R2 一致恢复 checkpoint。工具控制版本与冻结恢复源版本分别记录。恢复演练结果放在 PR 独立证据中，不预填本文件为 Passed。

新候选通过 `worker-production-candidate.yml` 的显式 `release_intent=first-release` 生成。该模式将不存在的旧生产 SQLite/WAL 迁移和旧消费者交接标为 N/A，不把这些项目算作 Passed，也不继续要求提供不存在的旧库。打包器本身不执行实时核验：正式配置、生产新库初始化、新工具的实际隔离路径、独立读回及正式激活仍保留独立 Not run 条目，实际结果按准确云端 run/attempt 在 PR 记录。manifest 继续为 version 1、`productionReady=false`、`productionAuthorization=not-granted`。旧候选和私有 R2 原始归档不改写。

| 覆盖项 | 首次上线的处理 |
| --- | --- |
| 帮助、菜单、UTC、管理员时区 | 复用仍对应候选运行代码的有效证据；正式初始化后核对角色及持久设置 |
| 授权新增主体、撤权及数据隔离 | 分别保留合成和既有两账号真人覆盖，不能把合成主体写成额外真人账号通过 |
| 内部短链 | 保留已有真实 Service Binding、稳定签发、故障回退和撤销证据；具体角色/格式按独立记录，未覆盖部分单列 |
| `/ai` 有效 Key 成功探测 | 无获准凭据时保持 **Not run**，不借用其他项目 Key；该能力首发关闭，不作为其他功能首次上线的全局阻塞项。真实有效 Key 的成功验收是 `/ai` 正式启用前的独立前置项，须固定目标、凭据权限和额度，通过后再批准启用，不能跳过 |
| 旧生产数据和消费者交接 | **N/A：维护者确认没有旧生产**；不索取不存在的旧库或补做旧轮询交接 |

短链仅使用 `shortlink-new` / `ShortlinkService` 的现有内部业务接口和 Service Binding，以获准合成目标验证；不改其部署、域名、权限或其他业务数据，不改走公开网络。`/ai` 的局部缺口不改写已有短链实测结论。公开证据只含适当的名称、提交、运行指针、摘要和计数，不含 Secret、能力链接、用户清单或原始内容。

## 获准后的首次上线顺序

每一步独立读回通过后才进入下一步；正式接收在最终激活前保持关闭。

1. **创建并确认正式 Bot。** 由维护者创建或另行明确授权代为创建；安全注入受保护生产配置，核对 `getMe` 和唯一消费者安排。不得复用测试 Bot、启动轮询探测或向未经批准的正式账号发消息。固定正式管理员、默认访问策略及群范围。
2. **只读核对目标。** 固定账户/Zone、资源名称和域名状态。发现同名资源、未知 Webhook、意外消费者或其他项目资源时停止核对，不覆盖采用。
3. **创建独立生产资源。** 在生命周期工作流先执行 `availability`，以草稿身份及准确前态批准 `provision`。创建前的每资源意图和实际 ID／时间写入已登记的私有 journal anchor；只创建批准清单中的 Worker、D1 和私有 R2。新资源不带业务模块或消费者。若结果不明，用 `provision-inspect` 独立读回，再以准确种类、身份摘要和意图时间窗执行 `provision-reconcile`；不能重复创建或采用未知同名资源。
4. **初始化新 schema 和正式权限。** 固定所有实际资源 ID／时间后，执行 `preflight`，核对账户／Zone、Bot／群权限、私有性及准确初始化前态，再批准 `initialize`。应用候选的完整准确迁移，只写批准的正式权限白名单，业务表为空，持久控制为 `closed/frozen`。默认没有时区设置行即 UTC，管理员仍可在私聊持久修改。发现未经正式批准的测试身份、测试夹具或非白名单记录即停止；同一真人账号成为正式主体也须重新明确批准正式角色，不隐式继承测试权限。没有从隔离数据恢复目标复制业务数据的步骤。
5. **部署准确候选，保持暂停。** 若启用 URL 导入／刷新，先按 ProviderFetch 说明完成正式专用依赖的原 OCI 发布、版本、Container／Workflow、真实 smoke 与独立 verify，并固定应用 caller；不能自动使用 dev 服务。生命周期 `deploy` 仅使用已审查的准确 CI 字节，读回 100% 版本、模块、完整绑定／配置和迁移，保持 `closed/frozen`。仅启用批准功能，`/ai` 首发关闭，未批准群范围关闭。后续配置／开关更新用 `plan-deploy` 固定当前线上产物和新配置前态，不沿用初次批准。
6. **封存上线前基线。** 独立 `inspect` 核对实际配置、结构和分类状态，以恢复工作流 `prepare → capture → verify-backup` 保存初始化 G0。资料包含 D1、R2 引用闭包、完整配置及摘要、原始准确 CI ZIP 和来源证明；不包含原始 Secret。已有隔离恢复证据不等于允许覆盖生产 D1。
7. **绑定正式域名。** 生命周期 `domain` 仅在准确 Zone、DNS／Custom Domain 无冲突时将 `subs-bot.lilyya.top` 绑定到唯一目标，读回 HTTPS、健康提交及响应安全策略。生产 workers.dev／预览保持关闭，Telegram 接收仍关闭。
8. **设置唯一正式 Webhook。** 先执行 `plan-webhook`，批准其 `stateSha256`，并将 `webhook.settingsSha256` 填入 `webhook_sha256` 后再执行 `webhook`。前 URL 只允许空或准确正式目标，未知 URL／自定义证书拒绝；工具重新核对 `getMe`，设置准确 URL、Secret、allowed_updates 和 max_connections，显式 `drop_pending_updates: false`，并独立读回。没有旧消费者需要停止。若出现意外积压，先分类其来源、授权和有效期，不用清队列、高 offset 或 `cutoverAt=now` 隐去更新；首次批准策略与主体生效下界为 1，业务时效拒绝／忽略也须持久记录。结果不明只读核对，不启动第二消费者试探。
9. **最终激活。** 先以 G0 的 `baseline_checkpoint_id`、`baseline_manifest_sha256` 执行 `plan-activate`；工具完整读回 SQL／R2／原始 CI 闭包并与当前 frozen 现场核对。以包含该基线的前态单独批准 `activate`，再次核对后直接从 frozen 原子开启，不先 thaw。任何新写入、epoch、版本或配置变化均需重新封存并批准。准确资源、身份／配置、Webhook、域名、分类排空及未知结果检查也必须通过。Webhook 是当前唯一可写公开 HTTP，其他公开路径仅 GET/HEAD，目前没有 queue handler；Cron 使用同一持久 invocation 与 D1 fence。持久受理／disposition 后才确认，重复 `(bot_id, update_id)` 核对载荷摘要并复用完成结果，处理中或外部结果不确定的更新不能重执行业务。封存首次 receipt／任务水位。
10. **限定验收并结束窗口。** 使用生产授权中指定的账号/群验证必要角色权限、导入/读取/导出、后台任务及撤销；新增夹具可识别，结束恢复修改的设置并退役本次夹具。固定准确版本、观察时间、错误/任务/不确定发送计数和新 checkpoint。原测试 Bot 的真人授权不能自动扩大到正式 Bot。

### 工作流与实际操作参数

下列命令仅说明获准后的托管 dispatch，不在本机执行应用工具，也不是本轮生产操作授权。先在受保护 Environment 填写契约／安全 Secret 和精确 `SUBS_BOT_APPROVAL_JSON`；每次写入使用独立前态，不能把下列占位符直接提交。

```sh
gh workflow run worker-production-control.yml --ref main \
  -f target_environment=production -f action=preflight \
  -f source_run_id=EXACT_SUCCESSFUL_MAIN_WORKER_CI
```

同一工作流后续调用以 `-f action=initialize`、`deploy`、`domain`、`webhook`、`plan-activate`、`activate` 逐步执行，并为 mutation 提供 `-f state_sha256=EXACT_INDEPENDENT_PREDECESSOR`；Webhook 另传 `-f webhook_sha256=EXACT_GETWEBHOOKINFO_DIGEST`；plan-activate／activate 另传准确 `-f baseline_checkpoint_id=SEALED_G0_ID -f baseline_manifest_sha256=INDEPENDENT_G0_DIGEST`。批准绑定固定 `targetSha256`、完整 `configurationSha256`、应用 `revision`、当前工具 `controlRevision`、action 和前态。Actions 资料过期后的私有归档参数与全部正式字段、Secret 名见 [生命周期说明](cloudflare-production-controls.md)。

```sh
gh workflow run worker-production-recovery.yml --ref main \
  -f environment=production -f action=prepare \
  -f source_run_id=EXACT_FROZEN_SOURCE_MAIN_CI -f source_run_attempt=EXACT_ATTEMPT \
  -f state_sha256=EXACT_INDEPENDENT_PREDECESSOR
```

恢复工作流另外需要明确 `SUBS_BOT_RECOVERY_JSON`。常规备份接续 `capture`、`verify-backup`；独立恢复按说明选择 `create-database`、`create-objects`、`restore-objects`、`start-import`、`verify-restore`。现场已有新写入时必须先封存 G1，再用独立 session 的 `prepare-restore`，不复用空库初始化操作覆盖现场。

## 接收新写入后的失败恢复

使用生命周期 `plan-pause → 明确批准其 stateSha256 → pause → inspect → drain` 关闭新增 admission 并固定已受理水位。pause 的批准绑定目标、配置、版本、完整控制行和迁移数，保留完整工作观察，但允许已受理工作的正常计数／终态变化；普通 inspect 摘要不能代替 plan-pause。`pause` 不会意外解冻已经冻结的后台。保留已受理工作完成所需的依赖，分类核对 outbox、文档／暂存、提供方单条／文档／批量及未来回复、私密创建、群卡、内联、快照租约、搜索和探测。有效租约或未来生产者仍存在时不宣称排空。异常中断调用只能通过单独批准的 `classify-interruption`，在明确结束或超过执行上限与隔离宽限后保留为 uncertain；不把外部效果判成成功，也不重发更新。已终止失败和外部不确定结果单列保留，不删记录来取得零计数。随后仅在没有可继续执行工作时批准 `freeze`，再封存现场。未知结果仍会阻止自动重新激活；暂停期间 Telegram 待处理更新继续保留。

仅恢复代码时保留当前数据，使用已验证兼容当前完整 schema、授权、回执/租约、能力/撤销语义及依赖配置的准确版本，核对模块和绑定后才恢复接收。历史版本曾成功运行不证明未来兼容；平台拒绝旧 Secret 版本时，不强制绕过检查。

必须恢复数据时，先封存暂停后的现状 G1：D1、R2 引用闭包、收件/回复/任务、配置和资源身份。将历史基线 G0 恢复到新的私有无消费者目标，完整对账后另行申请切换。G0 后的新增、修改、删除、授权、领取、撤销、短链及外部回复都需从 G1 核对和保留。当前没有已验收的完整增量回放能力；无法保留新写入时保持暂停，由维护者明确决定数据处置。恢复失败保留 G0、G1 和独立目标，不覆盖重建原生产库。

本项目没有可接回的旧生产 SQLite 服务。启动旧轮询不是恢复步骤；D1 Time Travel 不能恢复 R2，回退 Worker 也不回退数据库内容。

## 停止条件与最终批准清单

正式身份/目标/权限不符、出现意外消费者、版本或摘要不匹配、初始化混入测试数据、R2 公开、关键数据/权限/撤销验收失败、排空不成立、mutation 结果不明或恢复无法保留新写入时，停止下一项写操作并保留 checkpoint，只做独立读回。需要新增权限、费用或数据处置决定时也停止。

最终请求必须附准确候选/恢复证据和目标清单，逐项批准：

1. 正式 Bot 的创建责任及已确认身份，初始正式账号/默认访问策略和群范围，凭据安全注入方式。
2. 唯一生产 Worker、D1/R2 和必要依赖的创建与初始化；不复制测试数据。
3. 准确版本、Secret/绑定、功能开关、UTC/时区权限，以及已具备的生产暂停/恢复工具。
4. `subs-bot.lilyya.top` 绑定、准确正式 Webhook（保留待处理更新）与通用生产入口激活。
5. 正式验收范围、观察期和备份保留期；`/ai` 首发关闭，真实有效 Key 成功验收后再单独批准其启用。

最终等待项是明确的正式配置和逐项生产批准。缺失正式 Bot、固定资源身份、权限／群范围、独立安全凭据或准确批准时，工具保持拒绝生产操作；不能把方案审批当成直接激活。授权不包含删除隔离环境、变更短链服务或自行接受数据损失。
