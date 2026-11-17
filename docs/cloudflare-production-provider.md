# 首次上线 ProviderFetch 依赖控制

`worker/tools/production_provider.py` 和 `worker-production-provider.yml` 为生产及专用隔离演练执行同一条代码路径。它们不修改旧隔离工具的常量或证据。正式服务固定为 `subs-bot-provider-fetch-prod-01`；演练服务固定为 `subs-bot-provider-fetch-control-drill-01`。账户固定为项目账户；不接受未知同名 Worker，不采用 `subs-bot-provider-fetch-dev-01` 作为正式依赖。

## 受保护配置

工作流的 `production` 选择使用独立 GitHub Environment `subs-bot-production-provider`；`rehearsal` 使用现有 `subs-bot-provider-isolation`。正式 Environment 应限制为 `main` 并设置维护者审批。正式配置和凭据不从隔离 Environment 复制或回退。

环境 Secret `SUBS_BOT_PROVIDER_CONTROL_TARGET_JSON` 是以下完整契约（无默认值）：

```json
{
  "version": 1,
  "environment": "production",
  "accountId": "9431815bdb8beb2272f6668e06b7d3be",
  "service": "subs-bot-provider-fetch-prod-01",
  "workersDevOrigin": "https://subs-bot-provider-fetch-prod-01.lilyya.workers.dev",
  "worker": null,
  "build": {
    "revision": "REPLACE_WITH_REVIEWED_40_HEX_MAIN_SHA",
    "runId": "REPLACE_WITH_PROVIDER_CI_RUN",
    "runAttempt": "REPLACE_WITH_CI_ATTEMPT",
    "artifactId": "REPLACE_WITH_ARTIFACT_ID",
    "archiveSha256": "REPLACE_WITH_ARCHIVE_SHA256",
    "compatibilityDate": "2026-11-06",
    "workerSha256": "REPLACE_WITH_MODULE_SHA256",
    "ociArchiveSha256": "REPLACE_WITH_OCI_ARCHIVE_SHA256",
    "ociManifestSha256": "REPLACE_WITH_OCI_MANIFEST_SHA256",
    "ociConfigSha256": "REPLACE_WITH_OCI_CONFIG_SHA256"
  },
  "versionId": null,
  "activation": null,
  "container": null,
  "workflow": null,
  "smoke": {
    "healthUrl": "https://subs-bot.lilyya.top/health",
    "healthRevision": "REPLACE_WITH_APPROVED_HEALTH_40_HEX_SHA",
    "healthSha256": "REPLACE_WITH_EXACT_HEALTH_BODY_SHA256",
    "healthBytes": 1
  },
  "caller": null
}
```

示例含占位符，校验必然拒绝，不能直接运行。`healthBytes` 必须是独立读回实际 `/health` 原始响应字节数，范围 1–512；摘要核对精确响应字节。正式 Worker 尚未绑定域名时可指定明确批准且已读回的项目专用健康夹具，不能自动使用 dev 地址。合成健康验证不等于真实第三方订阅成功验收。

`worker` 在创建并独立读回后固定为 `{"workerId":"<32 hex>","workerCreatedOn":"<exact timestamp>"}`。其后依次固定 `versionId`、`activation={deploymentId,namespaceId}`、`container={applicationId,createdAt}`、`workflow={workflowId,createdOn,versionId}`。所有字段来自对应资源的独立 API 读回；不得用不明创建结果猜测身份。`caller` 首次绑定前为 null；批准应用绑定后固定为正式应用的准确 `{id,name}`，其中正式名称只能是 `subs-bot-cf-prod-01`。

`SUBS_BOT_CF_PROVIDER_WORKER_TOKEN` 至少需要项目账户的 Workers Scripts Read/Write 和所需 Workflows 管理权限。`SUBS_BOT_CF_PROVIDER_CONTAINER_TOKEN` 需要该账户的 Containers Read/Write，用于精确镜像仓库、准备镜像及专用应用。平台的 registry credential 签发属于账户权限，工具将仓库限定为上述单个服务，并只请求 15 分钟 pull 或 pull/push 凭据；不能把此平台限制描述为脚本级 Token 权限。Secrets 仅注入受保护操作步骤，不进入 artifact。只读依赖核验可使用包含 Workers、Workflows、Containers 读取权限的独立凭据；不需要 registry push 或写权限。

## 执行顺序与结果读回

1. 在获准创建生产资源后，由 GitHub 托管 Provider Fetch CI 构建准确 main。`prepare_provider_artifact.py` 核对 workflow、run/attempt、GitHub 原 ZIP 摘要、Worker 字节、OCI 所有 manifest/config/layer 摘要、非 root 进程与镜像环境。历史 `fetch-v1` manifest 的 dev 服务标签是冻结构建格式；生产部署使用同一准确字节和另行批准的运行时身份，不能据此自动绑定已有 dev 服务。
2. 为每个 mutation 计算 `SHA256(canonical({"operation":"<operation>","target":<完整契约>}))`；canonical 使用 `json.dumps(...,sort_keys=True,separators=(",",":"),ensure_ascii=True)` 的 ASCII 字节。将其作为 `approval_sha256`，选择准确环境和操作。工作流再次核对 hosted runner、当前 main 控制工具的准确 SHA、目标环境、源 CI 与全部契约。已冻结 source revision 可以是当前 main 的准确已审查祖先，必须通过 GitHub compare 核对、准确源 CI run/attempt 和原 archive digest；控制工具升级不改写源 pin。重跑 attempt>1 不允许 mutation。
3. `publish` 只向目标服务的项目 OCI 仓库发布原始镜像，核对 revision tag、manifest 和 config。已存在同 tag 的不同 digest 拒绝；同 digest 可只读核验。`create` 只在准确名称不存在时创建私有空 shell，并核对名称、immutable ID、创建时间、ownership tag、无版本与无域名/队列/其他调用方。
4. 独立固定 Worker pin 后执行 `verify`。`stage` 准备准确 digest 镜像，只上传一次准确模块及 `PROVIDER_TARGET_JSON={environment,accountId,service}`；不部署。读回 Beta 模块字节和绑定、legacy container 声明、版本和兼容设置。新版本用可选 `previous` 保存完整上一代契约，最多九代；每代准确 CI archive 都独立重验。Worker 版本集合必须恰好等于链中明确固定的版本集合；未知版本不能被采用或替换，旧版本不删除。
5. 固定准确 `versionId` 后执行 `activate`，再独立读回并固定 deployment/SQLite namespace。随后分别执行 `provision-container`、`provision-workflow` 并固定准确 identity。创建之前必须完整有界证明没有同名应用、未知 actors/instances 或既有 Workflow。
6. `smoke` 仅由无自动重试的专用 `ProviderReleaseSmoke` Workflow 调用同一 Container/`ProviderFetch` 控制代码，读取明确健康夹具并比对原始摘要和模块版本；同时验证 IPv4 loopback、IPv6 loopback、metadata 地址均拒绝。固定唯一实例 `provider-release-<revision>`，持久 admission 标记阻止再次执行；失败不能被替换为通过。最后独立核对 image、actor、stopped 状态、无 active instance 和 workers.dev 拒绝。
7. 新 dispatch `verify` 独立读回身份、版本、模块、绑定、container、Workflow 和 smoke。主应用通过 `verify_provider_dependency(api,target.provider)` 再读一次完整已固定依赖，默认要求非空 caller pin 且 name/id 双读 `references.workers` 恰好为该调用方，返回 `PROVIDER_FETCH` 的 service、entrypoint、revision、image digest、callerState 和 proof digest。首次部署前仅在主应用已固定准确身份并证明冻结时显式传 `allow_unbound_caller=True`，允许空 references 或同一个精确 caller；任何其他 caller 均拒绝。部署后和独立 inspect 使用默认严格已绑定检查。专用 provider 演练没有应用调用方，显式使用 prebind 检查并记录 `callerState=unbound`，不声称已完成应用绑定。

所有产物均保留准确 run/attempt 和完整配置摘要，上传的 `production-provider-evidence.json` 不含 Token、能力链接或订阅原始内容。正式发布资料仍应由项目候选封存流程保存至私有 R2，不能仅依赖有保留期限的 Actions artifact。

首次正式 Provider 尚为空，应在正式配置和操作获准后，用新的准确 main 运行 [Provider Fetch CI](../.github/workflows/worker-provider-fetch-ci.yml)，待全部检查成功并独立核对 run/attempt、head SHA 和原始产物摘要，再填入[生产控制工作流](../.github/workflows/worker-production-provider.yml)。隔离候选、历史 dev 服务标签和已有 dev 身份均不自动成为正式源或正式目标。

## 故障、容量与限制

任何写结果不明、响应错误、读回身份或摘要不符，都以失败退出。mutation 不做自动重试，也不删除资源或已存 admission 标记来制造成功。新开 `verify` dispatch 只读观察；将观察状态独立核对后再更新契约。一个执行进程最多一次 Worker/Container/Workflow 创建、上传或部署；镜像准备仅在平台明确返回 pending 时继续轮询同一个 digest。registry 可能已经保留准确镜像，应读回确认，不覆盖不同 tag。

发布、升级及 `previous` 链的归档来源读取已提供控制路径，但**尚未完成正式候选封存及隔离维护验收**，不得将其视为生产就绪。每代仍须固定原 CI revision、run/attempt、artifact ID、ZIP、Worker 和 OCI 摘要；归档只提供原始字节，不替代目标批准或来源证明。控制端逐代检查当前 main 的祖先关系、GitHub 上原 CI attempt 的成功元数据、目标身份、完整 ZIP 和 OCI，缺少任一项即在操作前拒绝。历史 requirements 按固定提交从 GitHub 读取并核对 Git blob 摘要；若原 CI run 或提交文件不再可核验，仍须停止。目前最多保留九代链，CI 工作流原 artifact 保留期为 14 天。

生产控制工作流及隔离演练工作流的 `archive_refs` 为空时保留原 CI 来源路径；非空时传 JSON 数组，每代一项，字段严格为 `kind`、`runId`、`runAttempt`、`manifestSha256`、`targetSha256`。`manifestSha256` 必须是归档时独立记录的 R2 manifest 摘要，`targetSha256` 必须是当时独立记录的完整归档目标摘要；不可从待验证对象中现算后作为信任依据。隔离来源的 `kind` 为 `complete` 或 `partial`；partial 仅保留原始字节和失败现场，绝不代表演练成功。正式来源必须使用 `production`，禁止引用隔离桶或隔离 target。不能凭文件名、同名 Worker 或归档存在推断授权。

控制 job 通过专用最小权限只读归档凭据，在独立步骤直接读取 R2 并核验桶身份、私有状态、生命周期和固定 manifest；不将原件或完整目标上传至公开仓库 artifact。随后控制步骤重新核验目标、原 CI 元数据、ZIP、模块和 OCI，Provider 写凭据不注入归档读取步骤。配置需在对应受保护 Provider Environment 单独提供 `SUBS_BOT_CF_PROVIDER_ARCHIVE_READ_TOKEN` 和隔离桶身份 `SUBS_BOT_PROVIDER_ARCHIVE_TARGET_JSON`；正式环境需提供 `SUBS_BOT_PROVIDER_ARCHIVE_BUCKET_JSON`。不得复制高权限凭据替代只读 token。非空 `archive_refs` 必须覆盖当前及整个 previous 链。隔离演练的归档来源目前强制拒绝，因为旧演练的 intent 和 source artifact 通道会暴露完整目标及原件；在这些证据改用私密通道前不能启用，也不能声称完成隔离验收。

正式来源封存提供 [plan/seal 工作流](../.github/workflows/worker-production-provider-source.yml)：在 `subs-bot-production-provider-archive` 配置经过独立核对的完整 Provider target、正式桶身份、专用只读和写入 token。正式桶身份格式为 `{"version":1,"accountId":"<项目账户ID>","namespace":"lilyya","bucket":"subs-bot-cf-prod-backup-01","createdOn":"<已核对的创建时间>"}`；桶必须已获批创建且保持私有，不能使用隔离桶作为回退。本轮不会创建、配置或运行正式资源。

受保护配置须显式设置 `SUBS_BOT_PROVIDER_SOURCE_LEDGER_JSON` 为经独立登记的历史映射（首次为空对象 `{}`，缺失并非空），以及 `SUBS_BOT_PROVIDER_SOURCE_CONTROLLERS_JSON` 为允许的已审查准确控制提交数组。历史每项映射的字段为 `intentSha256`、`manifestSha256`、原 seal `runId`、`controllerRevision`。每次 seal 前完整读取私有 intent、manifest 和 ZIP，并与独立 ledger 及已审查控制提交的 workflow 历史逐项比对；未知历史、缺失或不一致一律停止。新封存尚未独立读回并安全登记到 ledger 时，后续 seal 会停止，读回工具不自动更新 ledger。

先用从未使用的十进制 operation ID、准确 CI run 执行 `plan`；plan 只读且返回绑定准确控制提交、完整目标、原 CI pins、桶身份、完整历史盘点和空前态的 `approvalSha256`。独立审查后在新 dispatch 的 `seal` 提交相同 ID 和精确批准摘要。seal 在同一受保护 job 核验原 CI、原 ZIP 及完整 OCI，不上传原件；写入前核对有界历史，拒绝已用 ID 和任何之前未成功的 seal，然后先向 R2 写入并读回不可变 `started-unknown` intent，再单次封存 chunks 和 manifest。未知写入不得重试；任一先前 seal 失败、取消或状态不明时，后续全部 seal 都会拒绝，直到形成另行审查的独立对账方案。必须保留该工作流 run 记录，历史被删除或不可完整查询时不能据此认定安全。原件封存后用新的 [独立读回工作流](../.github/workflows/worker-production-provider-source-readback.yml) 输入 operation ID（作为 `archive_run_id`）、attempt `1` 和独立记录的 manifest/target 摘要完成 R2-only 核验。该流程仍需代码审查和云端隔离验证，封存不代表 Provider 的生产发布验收。

[失败只读检查](../.github/workflows/worker-production-provider-source-reconcile.yml) 可在新 dispatch 固定失败 run 和 operation ID，独立读取 GitHub job 与完整 R2 目录。仅当原 seal 步骤明确 skipped 且前缀为空时报告该步骤未执行；步骤已运行时，空前缀不能证明写入未发生。若已有完整原件，提供独立记录的 manifest/target 摘要可复验 CI、ZIP、OCI 并报告“失败 run 的完整原件已观察到”，不将失败 run 改成成功。部分 intent、缺块或不明状态保留并继续阻断。检查只输出证据摘要，不写 R2、不批准重试、不自动解除阻断；后续恢复必须另行制定并批准。

当前完整盘点最多 32 份历史 source archive，plan 返回数量和上限；达到上限时在写入前拒绝，不删除旧档。扩容须先审查并实现可分页、分段登记和完整性验证，保留现有全部 pins。这个历史容量界限与单条 previous 链最多九代是两项不同限制。

尚未绑定任何应用 caller 的 Provider 可以通过明确 `previous` 链修复/升级。操作前再次核对 Beta `references.workers=[]`，上一代资源身份、已完成 smoke 和 stopped/无 active instance；保留既有资源和版本。已绑定应用的 Provider 不能使用这个无 caller 升级路径：必须先制定并批准主应用冻结、排空及依赖更新计划，不能从一次空闲样本推断 caller 已暂停。主应用缺少正式依赖 pin 或依赖不符时仍拒绝激活 URL 导入/刷新。

资源盘点具有硬界限：固定发布链/Worker/Workflow 版本与 smoke 实例最多九代、deployment 盘点最多 100、DO namespace 盘点最多 1,000、Container application 盘点最多 500、目标 actor/Container instance 最多一个；分页或超限拒绝，不截断后报告通过。OCI archive 最大 256 MiB、Worker 模块最大 1 MiB、fetch 响应最大 10 MiB。单例使用 `lite`，请求结束先发送 `SIGTERM`，有界等待 `monitor()` 正常退出并确认 `running=false`、`inspect()=null`；异常或超时尝试强制清理后仍失败，正常验收继续要求管理 API 的 `stopped` 状态。控制工具不默认创建 API-status Container。`/ai` 首发保持关闭，真实有效 Key 成功探测继续是该功能单独启用条件。

URL 请求使用共享的 120 秒启动总预算，覆盖 `start`、必须等到设置完成的 inactivity-timeout ACK、readiness 和 image inspection；单次 fetch 28 秒、正常关闭 10 秒、失败清理最多再 10 秒。主应用仅由 Cron 消费长 URL RPC，RPC 上限 180 秒、lease headroom 210 秒、lease 240 秒，均小于 Cron 15 分钟执行窗口。Webhook/HTTP 受理保持持久入队和快速回执。上述预算不保证 Cloudflare 任意冷启动都能完成；超限仍失败并保全现场，不能跳过 ACK、重发旧 one-shot 或把后台结果不明改为成功。

发布 Workflow 的四次 fetch 阶段上限 300 秒、单次 named RPC 阶段 210 秒，控制器最多观察 600 秒；专用应用绑定演练等待排空最多 300 秒。新的失败诊断区分 `inactivity-set` 等固定 primary phase、timeout/operation 和有界 elapsed time，并与 shutdown 子阶段分开记录。API-status V2 的 `dispatchBeforeMs` 最多提前 30 秒及实际提交前硬检查保持不变，不随 URL 启动预算扩大真实 Key 的提交窗口。

可信 GitHub 元数据读取只对 GET 做最多三次尝试，单次网络超时 20 秒、累计退避最多 4 秒。只允许传输失败、500/502/503/504、具有有效小型 Retry-After 或 `remaining=0` 小型 reset 的 429，以及明确 `remaining=0` 且 reset 在剩余等待预算内的 403 重读；普通 403、身份不符、无效 JSON 和超限响应立即失败。缺少明确等待信号的 429、较长 Retry-After 或 reset 也立即失败，不触发短促盲重试或长时间等待。安全诊断只写 stderr 的固定读取类别、阶段和有界数值，不写请求 URL、响应正文、原始 header 或 Token，也不破坏 stdout 的 JSON 原件。失败的操作 intent 仍需封存并独立读回；只有明确 `executed=false / failed-before-dispatch` 才能说明该操作尚未写入，不能据一次 HTTP 错误推断其他操作结果或改用个人凭据绕过配额。

## 新工具的隔离演练与持久证明

`worker-production-provider-rehearsal.yml` 的 `rehearse` 路径通过同一个 `production_provider` 控制实现，使用专用 `subs-bot-provider-fetch-control-drill-01`，不修改原 dev 服务。必须提供准确 Provider CI run、明确批准的项目 `/health` URL 与独立读回 revision，并输入 `rehearse production ProviderFetch controls for subs-bot-provider-fetch-control-drill-01`。自动流程覆盖 create、原 OCI 发布、stage、activate、Container/Workflow 初始化、真实 Cloudflare smoke 和独立 verify。

每个操作通过受保护的 `provider-control-step` 复合 Action 执行：只读预检 → 写入 `started-unknown` intent → 官方 artifact 上传 → 以 GitHub API 核对该 artifact 的准确 main/run/attempt/operation 与摘要 → 执行一次 mutation → 无论结果如何保留结果 checkpoint。intent 包含完整配置摘要、源 CI/模块/OCI pins、操作 approval 摘要与前态摘要；创建前还核对准确名称不存在。artifact 上传失败或回读身份不符时，不允许 dispatch。源原 ZIP、OCI、module 和初始 pins 也在首个资源操作之前上传。

单个原子 `provider-rehearsal-checkpoint.json` 包含完整 target 和 journal，是恢复时的权威记录；两个拆分 JSON 是便于审查的派生文件。收到创建/上传响应后，首先记录白名单资源 ID/时间为 `response-only`，之后才进行完整读回并提交 confirmed pin。后续失败保留这些观察，不把它们自动提升为已验证资源，也不保存上游响应正文或异常文本。状态分别为 `started-unknown`、`confirmed`、`failed-before-dispatch`、`unconfirmed` 和 `skipped`。同一 intent 不可重复 dispatch；未确认 intent 阻止后续操作和完整 proof。

发生 runner 丢失或中断时，已上传的 source/intent/result artifacts 仍可独立取得。源 job 的失败结果保持失败，`always()` 后继 job 将所有可用原件追加封存至私有 R2；平台整体取消导致后继 job 未启动时，可用 `preserve-partial` 加原 run/attempt 再封存。工具核对原 workflow、仓库、main 祖先提交、准确 attempt 和完整有界 artifact inventory，拒绝采用其他任务产物。partial 使用独立 `partial-manifest.json`，固定 `completion=not-complete`；保存成功仅表示现场原件存储完成，不是业务验证通过。`verify-partial` 只从 R2 独立重读这些原件，不能把 partial 转为 complete。

独立核对已确认 pins 与所有 response-only 观察后，才将准确 target 存入 `SUBS_BOT_PROVIDER_REHEARSAL_TARGET_JSON`。`source_mode=registered` 会保留其中冻结源和准确 CI run，在新的 main 控制工具下继续未完成流程，不强迫升级尚未完成的目标。`source_mode=current` 是明确选择新源，只允许先证明原依赖已完整验证、私有、停止且无调用方后升级。发现未知同名资源/版本或结果不明时仍停止，不从单纯名称或失败回执推断成功。

可用 `fault=after-create-response` 或 `after-stage-response` 做明确的托管确定性中断演练，默认 `none`。它只允许首次私有发布、尚未激活消费者、无 previous/caller 的目标；先把真实 API 响应的白名单 ID/时间记为 response-only，再主动失败。原 job 始终失败，partial 仍为 not-complete。该证据应标为“确定性托管中断”，不能称为真实网络故障。

接续流程可直接执行：

1. 用上述 fault 运行 `rehearse`；保存失败 run/attempt、partial manifest SHA 和输出的 `latestCheckpoint.responseIdentity.sha256`。
2. 另开 `verify-partial`，填原 run/attempt 和 manifest SHA；它仅从私有 R2 读回全部原件。仍不能声明业务 complete。
3. 运行 `reconcile-partial`，提供同一原 run/attempt、manifest SHA 及准确 `response_identity_sha256`。工具从已验证 R2 重建原 CI ZIP，核对原摘要、模块与 OCI 闭包；再使用已有项目部署凭据的读取能力，按响应 immutable ID/版本 ID 独立读取名称/创建时间/私有归属、确认无 deployment/消费者，并在 stage 场景读回准确模块、绑定、镜像及版本元数据。专用 transport 强制仅 GET，不按名称猜测 ID，不写 Cloudflare，也不调用 Container/registry mutation。
4. 只有上述核对全部成功，才产生 `provider-reconciled-target.json` 和 `confirmed-identity-only` 回执；该状态仍为 not-complete。将这一准确 target 安全登记到 `subs-bot-provider-isolation` 的 `SUBS_BOT_PROVIDER_REHEARSAL_TARGET_JSON`，保留原 source CI run。
5. 用 `source_mode=registered`、原准确 CI run 和 `fault=none` 再运行 `rehearse`。已验证阶段跳过，未完成阶段继续；完整 named RPC、停止状态和最终独立读回全部成功后才生成 complete proof。可先从 create 的确认点继续并选择 stage fault，再重复同样的只读核对流程，覆盖两个真实响应后中断点。

当前自动只读注册仅覆盖明确的首次 create/stage、无消费者响应；其他不明状态保留现场并拒绝自动注册。原始 mutation 永不自动重试，重复 reconcile 也不能跳过实时身份和未激活状态检查。

### 已执行 smoke 后的受保护前向修复

容器请求结束时先发送 `SIGTERM`，在同一个 10 秒期限内等待 `monitor()` 正常退出并核对 `running=false`、`inspect()=null`；状态读取可在剩余期限内短暂重复，两个条件均不放宽。镜像将 aiohttp 的 shutdown timeout 显式限制为 2 秒，使服务关闭预算小于控制器总期限；预算对齐本身不证明任何既往失败的根因。异常或超时后会尝试 `destroy()` 清理，但仍返回失败。新的失败结果只记录固定 `stop.phase/reason/primaryStage`、有界退出码和清理结果，不记录异常文本；primaryStage 为空也不能代替业务或 RPC 成功证明。正常验收继续要求管理 API 的精确实例为 `stopped`，不会把 `failed` 改名为正常停止。

若旧版本曾强制结束容器，必须保留原失败 run、private partial、旧 Workflow 实例和 Durable Object one-shot 标记。仅当旧实例已完整成功执行固定健康摘要、私网拒绝及 named RPC，且同一精确 image/actor 的 inventory 和 detail 均为 `failed/137`、时间属于旧执行、全部 active 实例为空、两次读回一致、资源没有应用 caller，才可生成单独的 `failed-terminal-preserved / not-complete` 证据。该证据不代表旧版本验收通过，也不能授权重触旧 smoke。另一个独立失败分支仅接受同样固定源、Workflow 和实例、`complete/success` 但业务输出严格为旧格式 `{ok:false,stage:"stop"}` 或新格式附带闭合白名单 `stop` 诊断的结果，并继续要求同一精确 image/actor 的 `failed/137`、无 active、双读一致和无 caller。它单独绑定失败输出摘要并明确 `namedRpcVerified=false`，不能宣称健康、地址策略或 RPC 已通过。

用 `action=reconcile-terminal` 填原 run/attempt、经独立 R2-only 读回的 partial manifest SHA 和 smoke response identity SHA。流程先在 R2 环境验证原始源代码及 intent/response 归属；复用既有 Workflow 而跳过 provision 的 registered 接续，还必须读回该次 activate 的原始不可变 intent、准确源与操作批准、确认后目标及保留的 namespace/Workflow 身份，不接受一条 skipped 记录代替证明。再通过不可变 artifact 将无凭据目标交给 Provider 环境，使用各自既有凭据只读验证终态；最后另一个 R2 环境 job 封存四份小型原件。凭据不跨环境搬运，任一步失败均不产生前向批准。记录返回的 terminal manifest SHA，再以 `action=verify-terminal` 和该 reconcile run/attempt/SHA 从私有 R2 独立读回；状态始终为 not-complete。

只有上述读回成功，才把该 run 的 `subs-bot-provider-forward-terminal-<run>-<attempt>` artifact 中原样的 `provider-reconciled-target.json` 登记为现有 rehearsal/control target 配置，把 `provider-forward-terminal.json` 登记到同一 `subs-bot-provider-isolation` 环境的 `SUBS_BOT_PROVIDER_FORWARD_TERMINAL_JSON`。通过文件 stdin 设置 Secret，不在终端打印配置。

随后明确选择 `source_mode=forward`、新的 current main Provider CI 和 `fault=none`，仍需输入既定专用资源确认。新配置的 `previous` 保留完整旧版本及不可变资源 pins，`forwardRecovery` 绑定原 partial、响应、旧 target 和终态摘要；每次暂存、激活及新 smoke 前都核对旧终态及无 caller 条件。新 revision、新版本和新 Workflow 实例执行完整验收，旧实例与标记保留。最终只有新版本真正 `stopped`、完整 proof 封存和独立 `verify-archive` 成功才能声明完成。通用 `verify`、`stopped` 与依赖验收不会采用 failed-terminal 例外。

后继 job 在原 `subs-bot-isolation` Environment 中，将完成证明、完整 target、journal、源原 ZIP、源 module、OCI archive 和 manifest 封存到既有私有 R2 的 `maintenance/production-provider/<run>/<attempt>/`。每块最大 16 MiB，最多 128 块、总量 600 MiB；超限在 manifest 封存前拒绝。S3 条件写只创建新对象，逐块及完整文件摘要读回后才写最终 manifest；不删除任何原记录。

partial 保存至同一 attempt 的独立 manifest，最多 128 个原始文件、2 GiB 逻辑字节；去重后最多 128 个块/600 MiB。单个 checkpoint 最大 256 KiB、journal 最多 80 个事件；超限停止，不截断。每个版本的原始 target、journal、响应观察和源文件均有独立摘要，重复字节只保留一份物理块。partial 与完整 proof 的读回类型和完成状态分开输出；原始失败不会被存储 job 的成功覆盖。

另开 `verify-archive` dispatch，提供原 run/attempt 与独立记录的 manifest digest，只从私有 R2 读取七个完整文件的全部块并核对计数、字节和摘要，不读取源 Actions artifact。该读回与真实 Cloudflare smoke 是不同证据；工作流结果不预填为 Passed，实际 run/attempt 与失败必须记录在 PR 证据中。

短链仍使用既有 `shortlink-new` / `ShortlinkService` 和 Bearer 业务 Token 的内部 Service Binding；本工具不触碰短链的部署、域名、权限或业务数据。

### 已上传 forward 版本的只读接续

上传 API 返回准确 candidate 后，仅当完整版本盘点恰好包含全部旧版本且唯一缺少该 candidate 时，上传控制路径才会在最多三次 GET 内等待可见性，间隔为 1、3 秒；不会重复上传。未知额外版本、重复 ID、缺失旧版本、分页不完整或 HTTP 错误立即失败。通用 `verify` 的严格版本集合检查不采用此等待例外。

若 forward 暂存已返回 candidate、后续读回仍失败，先保存原 run/attempt、private partial manifest SHA、response identity SHA，并独立运行 `verify-partial`。随后显式选择 `action=reconcile-forward-stage`，填相同原件 pins：工具重验原 CI ZIP/模块/OCI 闭包，按响应指定的既有 candidate 双读完整模块、绑定、版本集合、旧激活/Container/Workflow、无 caller 以及已保全旧 `failed/137` 终态。它不上传、部署或触发 smoke，也不放宽首次 create/stage 的无消费者注册门。

成功仅输出 `confirmed-identity-only / not-complete`，两个小型原件通过准确 run 的不可变 artifact 在既有环境间传递后封存至私有 R2。记录 manifest SHA，再以 `action=verify-forward-stage`、该 reconcile run/attempt/SHA 独立从 R2 读回。只有全部核对成功，才将 `subs-bot-provider-forward-stage-<run>-<attempt>` artifact 的原样 `provider-reconciled-target.json` 安全 stdin 登记到既有 rehearsal/control target 配置。然后使用 `source_mode=registered`、该 target 原冻结 CI run 和 `fault=none` 继续；已固定版本不再上传，旧 smoke 实例及 one-shot 标记保持保全。新版本仍须完成正常停止、完整归档和独立读回验收。
