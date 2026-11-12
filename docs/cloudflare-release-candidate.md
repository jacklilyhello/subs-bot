# Cloudflare 发布候选与恢复

此流程准备可审查的生产候选。生产 Bot、Webhook、正式域名、旧消费者及真实数据切换必须另行获准。隔离窗口使用现有测试 Bot、两位已授权账号和一个测试群，不扩大 Telegram 测试范围。

## 完整通用路径的隔离窗口

`worker-isolation-general-window.yml` 和 `general_isolation_window.py` 使用独立的 `full-v1` 持久 profile。它与既有的只读演练分开；只读演练不会获得完整能力，完整窗口也不能由只读工作流管理。`0052` 只增加控制表。

1. 对最新 main 的成功 Worker CI 产物完成常规隔离部署，先核对准确提交、模块、绑定、迁移及健康结果。
2. 用 `action=inspect` 和该 `source_run_id` 取得 `activeSha256`、`stateSha256`、原收件水位及分类工作计数。
3. 用准确的两个摘要执行 `close`，确认串为 `close full general window for subs-bot-cf-dev-01`。所有新消息、回调、文档和内联查询暂停接收。已持久化请求继续由原模式的 Cron 处理。关闭前已在运行的 webhook 调用也必须在 D1 事务内通过原 epoch 条件才能继续。
4. `inspect` 读回分类计数。只在所有计数为零后，使用最新摘要、同一成功 Worker CI 和 `open full general window for subs-bot-cf-dev-01` 执行 `open`。同一事务建立固定管理员、成员及测试群的新授权世代，记录切换时刻，并打开通用入口。
5. 该窗口直接调用通用 webhook 和 Cron 实现。提供方导入、刷新、批量任务、内联、群卡和订阅短链仍各自遵守当前已部署的显式开关及依赖就绪检查。`full-v1` 表示使用完整通用路由，不表示尚未实现的命令已可用。仅对本轮合成条目进行写入测试。
6. 完成两角色、群聊、权限、失败恢复和撤销验收后，再执行 `close`。保留当前部署、绑定和 Cron，等待已受理任务完成。使用最新摘要和 `drain full general window for subs-bot-cf-dev-01` 执行 `drain`；它只确认分类计数全部归零，不取消任务。
7. 使用 `restore full general window for subs-bot-cf-dev-01` 执行 `restore`。在同一事务再次核对排空、停用临时通用授权世代、关闭窗口并恢复原隔离路由。保留业务数据、原隔离授权、通用主体历史和 Telegram 回执。摘要不符、活跃发送租约或后台工作未落定时停止恢复并保留现场。群卡的已终止状态另列证据，不通过重发或删除历史强行排空。

每次写操作都提交最新 `inspect` 的准确前态摘要。传输结果不明时只读核对原操作结果，不重发原前态的写请求。归档到期后，仍可使用最初记录的准确 `activeSha256` 在当前 main 执行 `inspect`、`close`、`drain` 和 `restore`，恢复不依赖旧归档。`open` 始终要求准确且仍可验证的当前 CI 产物和健康部署。

分类排空覆盖普通及旧通用 outbox、文档任务和暂存、提供方单条/文档/批量任务及尚未形成 outbox 的结果、私密创建、群卡发送和仍可执行的过期编辑、内联发送、快照租约、搜索及探测。群卡应使用合成数据的短有效期。活跃租约、待发送群卡及仍可编辑的已发送群卡继续阻止恢复。

群卡终态记录在 `terminalCards`，与阻塞排空的 `work` 分开：`terminalUnknown` 是租约已结束、首次发送结果仍未知的记录；`terminalEditFailure` 是编辑已终止的已发送记录，现有 schema 无法进一步区分明确失败与不确定的编辑结果；`terminalDeliveryFailure` 是首次发送已失败的记录。它们不表示成功，不自动重发，也不删除或改写历史。`drain` 和 `restore` 保留这些计数及 `terminalCardPolicy: retained-without-automatic-retry`，在没有仍可继续工作的任务时允许恢复，无需无限等待已终止的编辑。后续审查仍可核对原回执及原消息。

## 隔离调用方的短链故障演练

`worker-isolation-shortlink-fault-drill.yml` 只改变 `subs-bot-cf-dev-01` 的版本和部署。短链生产服务、域名、WAF、Access 和业务 Token 权限不变。先完成通用窗口的 `close`、`drain`、`restore`，再执行该演练；演练中不要启动其他隔离工作流或修改两个账号的授权。

`action=drill` 填写当前 main 的成功 `worker_ci_run_id`、匹配普通隔离部署的 `deploy_run_id`/`deploy_run_attempt`、未用过的 16 位十六进制 `cohort`，确认串为 `drill shortlink fallback for subs-bot-cf-dev-01`。工具核对准确产物、部署、完整迁移、配置、固定账号及空闲队列，先上传原保护凭据的恢复版本 R，再上传故障版本 C。C 仅替换调用方业务 Token、其摘要及派生发布标记，仍使用真实命名 Service Binding。签名恢复 checkpoint 归档成功后才激活 C。其无效 Token 语法有效，以确保经过实际 RPC；普通发布因凭据摘要不同而拒绝覆盖该状态。

从恢复归档取得 C 的版本 ID，并独立读回确认其 100% 生效后，在内置浏览器用两个固定账号分别发送 `/short https://example.com/subs-bot-normal-short/<cohort>/admin` 和 `/short https://example.org/subs-bot-normal-short/<cohort>/member`。工具最多等待约五分钟，核对真实私聊回执、本地码归属及派生、外链尝试终态和本地 GET/HEAD 跳转。浏览器另行确认回退提示及本地链接，不能把机器读回当成真人验收。数据库未保存 RPC HTTP 状态，报告不宣称直接观测到 401。

主步骤的 `finally` 和工作流的独立 `always()` 步骤均恢复已验证的正常配置。Secret 变化可能使 Cloudflare 拒绝部署较旧的 R；恢复时从签名固定的 R 读取唯一模块，核对摘要和全部绑定，再用原保护凭据向前上传新的正常版本并核验一致后激活，不使用 `force`。若 runner 被强制终止或恢复未独立确认，使用同一工作流 `action=restore`，填写原 `checkpoint_run_id`、准确 `checkpoint_run_attempt`，确认串为 `restore shortlink fallback for subs-bot-cf-dev-01`。该操作接受失败、取消及未完成运行的签名恢复归档；不要求原 CI 归档仍存在或历史提交仍是 main。任何恢复写入均要求当前仍是签名固定的 C，且模块、配置、资源和绑定完全一致；遇到其他部署停止写入。若中断后已是与签名原版本完全一致的正常版本，只做稳定性和健康读回，不覆盖或重新部署。恢复归档保留七天，执行者应在演练期间下载保留该无凭据 checkpoint。恢复后还须用新挑战的正常 `/short` 独立确认业务 RPC，并撤销本轮两个账号各自的合成本地码；不删除外层短链。

## 审查用候选清单

`worker-production-candidate.yml` 在 GitHub 托管 runner 生成只供审查的包。它只使用 `github.token` 的 `actions: read` 和 `contents: read`，不接收 Cloudflare 或 Telegram 凭据、不调用 Cloudflare、不改部署、数据、域名、Webhook 或旧消费者。

填写当前 main 的成功 `source_run_id`、准确 `source_run_attempt`、使用同一 CI 归档的成功普通隔离 `deploy_run_id` 及 `deploy_run_attempt`。工具核对仓库、workflow、main SHA、成功状态、准确尝试、CI 归档 SHA-256、包内模块及完整迁移。它只从该部署 job 的有界日志中提取严格允许的 CI proof、版本/开关 JSON 和迁移计数，并确认 CI proof 与选定归档完全相同。原始日志及签名下载 URL 不进入产物或输出。缺失、重复、冲突或过期证据使生成失败，不能用其他提交或只看绿色运行来替代。

可用 `expected_flags_json` 提交要核对的布尔开关，例如 `{"inlineSearchEnabled":true}`。`expected_binding_names_json` 只接受绑定名称数组，不接受值或凭据。输出中的绑定名称、命名入口及开关是基于已验证源码和历史部署记录的审查预期；它们不构成当前 Cloudflare 配置读回。`data_source_kind` 只接受未提供数据或合成夹具描述，`data_source_sha256` 仅记录可选合成夹具摘要，不读取或导入该数据。

生成的 `subs-bot-production-candidate-…` 归档含 `candidate.json`、`candidate.sha256` 和 `review.md`。机器清单固定 `productionReady: false`、`productionMutationPerformed: false`。只将准确 CI 和匹配的历史部署 workflow 证据记为 Passed；当前版本/绑定/迁移读回、真实 SQLite 演练、实时合成用例和 Telegram 真人验收均明确为 Not run，需独立核验。成功生成审查包不授予或替代生产切换授权。

候选清单由获准的托管流程生成，保存在部署产物或 PR 附属证据中。实际读回及验收证据须另行附上，未核验项目保留 Not run。清单至少包含以下项目；不能填写尚未观察到的成功结果。

| 项目 | 必须固定的内容 |
| --- | --- |
| 来源 | 完整 Git SHA、成功 CI 的 run/attempt、原归档 SHA-256、模块 SHA-256、兼容日期 |
| 数据结构 | 完整迁移顺序与摘要、实际登记数量、schema 与外键读回结果 |
| 运行配置 | Bot 和授权世代的摘要、依赖命名入口和版本/镜像摘要、所有功能开关、展示时区；不含 Secret 值 |
| 隔离证据 | 部署与版本 ID、健康提交、full-v1 开关及排空证据、角色和群聊用例的实际结果 |
| 数据候选 | 获准来源、最终一致 SQLite 备份摘要、WAL 处理方法、逐域数量和归属对账、R2 内容闭包及旧链接连续性 |
| 生产操作计划 | 拟变更的唯一 Worker、D1/R2、Webhook 和域名；暂停、最终同步、交接水位、恢复步骤和明确停机条件 |
| 结果分类 | 每个用例分别标记 Passed、Failed、Not run，并区分合成覆盖与真人覆盖 |

旧数据来源未获准或最终一致性备份、归属对账未完成时，该候选保持未验收状态。空库和弃用旧链接不能作为默认选项。合成原生恢复证明恢复工具链，不能替代真实数据承接验收。

## Cloudflare 新写入后的恢复边界

版本恢复优先保留当前 D1/R2 数据，只回退到经过验证且能读写当前增量 schema、回执和能力记录的 Worker。回退前关闭新接收、保留当前 Cron 和依赖、排空已受理工作并核对回退能力底线。不能仅因某个旧版本曾运行成功就使用它。

若必须恢复数据，先关闭新写入并封存当前 Cloudflare 状态。使用 Cloudflare 侧一致 D1 导出和完整 R2 内容闭包，在独立未绑定目标恢复并对账，再按另行批准的恢复计划切换。恢复的候选不能自行处理 Telegram 更新。D1 Time Travel 是覆盖原目标的独立操作，不等同于完整 R2 恢复。

旧 SQLite 服务不包含迁移后 Cloudflare 新写入。当前没有宣称或授权 Cloudflare 到旧 SQLite 的完整增量回放，不能把启动旧服务当作无损回滚。需要回到 SQLite 时，必须先实现并验收回放、归属与能力连续性，或取得关于停写和数据处理的明确决定。

正式 Telegram 交接须保留待处理更新，停止旧消费者后固定最后处理水位、最终数据快照和新入口起点。不得使用清除待处理更新的默认值来掩盖交接缺口。正式切换失败后也先停止新写入和核对已接受更新，不能同时运行两套消费者写不同数据库。
