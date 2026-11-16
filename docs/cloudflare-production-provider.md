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

## 故障、容量与限制

任何写结果不明、响应错误、读回身份或摘要不符，都以失败退出。mutation 不做自动重试，也不删除资源或已存 admission 标记来制造成功。新开 `verify` dispatch 只读观察；将观察状态独立核对后再更新契约。一个执行进程最多一次 Worker/Container/Workflow 创建、上传或部署；镜像准备仅在平台明确返回 pending 时继续轮询同一个 digest。registry 可能已经保留准确镜像，应读回确认，不覆盖不同 tag。

尚未绑定任何应用 caller 的 Provider 可以通过明确 `previous` 链修复/升级。操作前再次核对 Beta `references.workers=[]`，上一代资源身份、已完成 smoke 和 stopped/无 active instance；保留既有资源和版本。已绑定应用的 Provider 不能使用这个无 caller 升级路径：必须先制定并批准主应用冻结、排空及依赖更新计划，不能从一次空闲样本推断 caller 已暂停。主应用缺少正式依赖 pin 或依赖不符时仍拒绝激活 URL 导入/刷新。

资源盘点具有硬界限：固定发布链/Worker/Workflow 版本与 smoke 实例最多九代、deployment 盘点最多 100、DO namespace 盘点最多 1,000、Container application 盘点最多 500、目标 actor/Container instance 最多一个；分页或超限拒绝，不截断后报告通过。OCI archive 最大 256 MiB、Worker 模块最大 1 MiB、fetch 响应最大 10 MiB。单例使用 `lite`，请求结束必须销毁并确认停止；控制工具不默认创建 API-status Container。`/ai` 首发保持关闭，真实有效 Key 成功探测继续是该功能单独启用条件。

## 新工具的隔离演练与持久证明

`worker-production-provider-rehearsal.yml` 的 `rehearse` 路径通过同一个 `production_provider` 控制实现，使用专用 `subs-bot-provider-fetch-control-drill-01`，不修改原 dev 服务。必须提供准确 Provider CI run、明确批准的项目 `/health` URL 与独立读回 revision，并输入 `rehearse production ProviderFetch controls for subs-bot-provider-fetch-control-drill-01`。自动流程覆盖 create、原 OCI 发布、stage、activate、Container/Workflow 初始化、真实 Cloudflare smoke 和独立 verify。每步将准确完整目标与步骤摘要保存到 runner checkpoint；中断后不自动采用同名资源或重做不明 mutation，可从保留 checkpoint 独立核对并将批准的 target 存入专用 `SUBS_BOT_PROVIDER_REHEARSAL_TARGET_JSON` 后继续。

后继 job 在原 `subs-bot-isolation` Environment 中，将完成证明、完整 target、journal、源原 ZIP、源 module、OCI archive 和 manifest 封存到既有私有 R2 的 `maintenance/production-provider/<run>/<attempt>/`。每块最大 16 MiB，最多 128 块、总量 600 MiB；超限在 manifest 封存前拒绝。S3 条件写只创建新对象，逐块及完整文件摘要读回后才写最终 manifest；不删除任何原记录。

另开 `verify-archive` dispatch，提供原 run/attempt 与独立记录的 manifest digest，只从私有 R2 读取七个完整文件的全部块并核对计数、字节和摘要，不读取源 Actions artifact。该读回与真实 Cloudflare smoke 是不同证据；工作流结果不预填为 Passed，实际 run/attempt 与失败必须记录在 PR 证据中。

短链仍使用既有 `shortlink-new` / `ShortlinkService` 和 Bearer 业务 Token 的内部 Service Binding；本工具不触碰短链的部署、域名、权限或业务数据。
