# Cloudflare 迁移

迁移目标是让 subs-bot 的 Telegram 处理、订阅与分享数据、导出和后台任务都运行在 Cloudflare。Telegram、GitHub、订阅提供方和已配置的可信短链服务仍是业务接口。完成切换后，服务无需维护者管理 VPS、轮询进程或外部数据库。

## 隔离环境与 HTTP 接口

隔离 Worker 使用本项目专用 `workers.dev` 主机名、D1 元数据、私有 R2 快照和合成数据。Telegram 收件、回复和文档处理使用同一隔离环境。

| 路径 | 隔离 Worker 的行为 |
| --- | --- |
| `GET` 或 `HEAD /health` | 返回部署的 40 位 Git commit SHA，供部署验收核对 |
| `GET` 或 `HEAD /sub/{token}/{format}` | 读取当前已发布快照，支持 `base64`、`v2ray`、`mixed`、`singbox`、`sing-box`、`clash`、`surge`、`qx`、`quantumult` 和 `quantumultx`。省略格式时使用 `clash` |
| `GET` 或 `HEAD /agg/{code}/{format}` | 导出全量或指定订阅，使用同一套格式 |
| `GET` 或 `HEAD /s/{code}` | 对有效聚合码返回同源相对重定向 |
| `POST /telegram/webhook` | 校验隔离 Bot 的 Webhook 密钥，接收受限消息及回调 |

能力链接视同凭据。成功与失败响应均使用 `Cache-Control: no-store, private`、`Referrer-Policy: no-referrer` 和 `X-Content-Type-Options: nosniff`。`HEAD` 执行同样的预检并返回相同状态，响应体为空。未知能力链接返回 `404`，未支持的导出格式返回 `406`，内容无法完整转换或超过格式限制时返回 `422`。若预检时发现已引用的快照不可用或校验失败，返回 `503`。旧服务将未知格式回退到 Clash，迁移前须核对已发链接所用格式。

`GET` 在预检时验证已选定的快照并计算编码长度。通过后再读取同一个不可变快照，按原有块顺序编码，通过 `FixedLengthStream` 发送。两遍读取各自最多同时预读四个块，下游消费一块后再补下一块。若第二遍读取在成功响应头发出后失败，响应流会中止，客户端应把读取错误或未读满声明长度视为失败。响应流取消后停止补读，已发出的存储请求可能仍会完成。 [Workers FixedLengthStream](https://developers.cloudflare.com/workers/runtime-apis/streams/transformstream/#fixedlengthstream) · [Workers Content-Length](https://developers.cloudflare.com/workers/runtime-apis/response/#set-the-content-length-header)

结构化导出支持 Shadowsocks、VMess、VLESS、Trojan、Hysteria 2、TUIC v5 和 AnyTLS。生成 URI 时，服务器地址需要使用 IP 或 ASCII 主机名，包括已明确编码的 Punycode。Python 的 IDNA 转换与 Worker 的 URL 转换可能将同一个 Unicode 主机名解析为不同目的地。已有分享 URI 通过校验后按原字节导出。 [Python IDNA](https://docs.python.org/3/library/codecs.html#encodings.idna) · [URL 标准](https://url.spec.whatwg.org/#concept-domain-to-ascii)

Sing-box 返回含选择器、直连项和代理出站的 JSON。支持 Shadowsocks、VMess、VLESS、Trojan、Hysteria 1 和 2、TUIC、AnyTLS、SOCKS 和 HTTP(S) 的已支持选项。HTTP(S) 使用结构化节点，VMess 的分享 URI 使用 Base64 JSON。引用其他出站或本地文件、执行外部插件、未支持的旧式协议，以及无法保持语义的 Hysteria 2 URI 证书钉扎和 ECH，都会使该订阅的 Sing-box 导出返回 `422`。Sing-box JSON 独立限制为 16 MiB 和 25,000 个代理出站。每个原始节点名的 JSON 编码最多 1 KiB，所有原始节点名合计最多 2 MiB。GitHub 托管 runner 使用校验过 SHA-256 的 Sing-box 1.14.4 检查实际 Worker 响应。 [Sing-box 1.14.4](https://github.com/SagerNet/sing-box/releases/tag/v1.14.4) · [Sing-box 出站](https://sing-box.sagernet.org/configuration/outbound/)

Hysteria 1 分享 URI 的 `peer` 映射到 TLS SNI，上传和下载速率必须达到客户端最小值。Hysteria 2 的 Gecko 包大小沿用客户端默认值与 2,048 字节上限。Hysteria 1 和 2 客户端加载配置时会逐项展开跳跃端口。Worker 在每个出站限制 65,535 项，每份配置限制 1,048,576 项。端口范围的首尾均计入，重复和重叠项分别计数。这是客户端内存保护限额。 [Hysteria 1 URI](https://v1.hysteria.network/docs/uri-scheme/) · [Sing-box 1.14.4 所用端口展开代码](https://github.com/SagerNet/sing-quic/blob/7e0a5869a5f4/hysteria/client.go#L111-L139) · [Hysteria 2 Gecko 与端口展开](https://github.com/SagerNet/sing-quic/blob/7e0a5869a5f4/hysteria2/client.go#L115-L140)

Clash 返回 `text/yaml`，保留旧版的节点选择、自动选择和匹配规则。节点名碰到内建名称、分组名称或其他节点时自动分配后缀，原有不冲突的名称保持原样。支持 Shadowsocks、VMess、VLESS、Trojan、Hysteria 1 和 2、TUIC v5、AnyTLS、SOCKS5 和 HTTP(S) 的可转换设置。支持经过校验的 Hysteria 2 内联 ECH，无法保持语义的 URI 证书钉扎、作用域 IPv6、未支持的协议或本地文件与其他出站依赖返回 `422`。Clash 配置最多 16 MiB 和 25,000 个代理，原始节点名上限与 Sing-box 相同，并使用相同的 Hysteria 跳跃端口计数上限。托管 CI 用校验过 SHA-256 的 Mihomo 1.19.33 读取实际 Worker 响应。 [Mihomo 1.19.33](https://github.com/MetaCubeX/mihomo/releases/tag/v1.19.33) · [Mihomo Hysteria 2](https://wiki.metacubex.one/en/config/proxies/hysteria2/)

Surge 保留 `[Proxy]`、`[Proxy Group]` 和 `FINAL,Proxy`，支持 Shadowsocks、VMess、Trojan、Hysteria 2、TUIC v5、AnyTLS、SOCKS5 和 HTTP(S) 的可转换设置。Quantumult X 的三个别名返回相同的原生节点资源行，支持 Shadowsocks、VMess、VLESS、Trojan、AnyTLS、SOCKS5 和 HTTP(S)。两个格式都要求每个节点能完整转换。旧版 Surge 生成的 VLESS 声明会返回 `422`。Quantumult X 的已有 URI 先解析再转换。未支持的 URI 或不能等价保留的加密、混淆、证书和传输设置同样返回 `422`。名称和字段内有歧义的分隔符或换行也会拒绝，Surge 中支持厂商语法允许的带引号逗号值。每种输出最多 16 MiB、25,000 个节点和每行 64 KiB，Surge 的选择分组也受单行限制。托管 CI 对照厂商语法和旧版可无损案例，核对实际 Worker 响应的字节。Surge 的配置校验命令随 macOS 应用发布，Quantumult X 提供原生资源示例。两个客户端的实际导入未纳入该 CI。 [Surge 策略](https://manual.nssurge.com/policies/overview.html) · [Surge CLI](https://manual.nssurge.com/tools/cli.html) · [Quantumult X 原生节点示例](https://github.com/crossutility/Quantumult-X/blob/master/server-complete.snippet)

聚合能力链接通过 `GET` 或 `HEAD /agg/{code}/{format}` 使用同一套导出格式。`/s/{code}` 仅对有效的聚合码返回同源相对重定向。全量链接按订阅 ID 读取所有者的活动已发布快照，再读取同一 Bot 和所有者的临时节点。筛选链接按记录顺序读取已选订阅，暂时移除回收中的订阅，恢复后可继续使用原 ID。订阅到期时间仍为上游元数据。

`0009` 只存聚合码的摘要。一次 D1 批处理固定成员、快照指针和临时节点。Worker 核对并固定 R2 清单后，复用同一组来源进行两遍导出。每个聚合最多 128 份订阅，快照与临时数据共用 64 MiB、100,000 个节点和 256 个 R2 块的预算。各格式的输出上限仍适用。旧链接导入、其他短链、订阅拉取和生产域名分阶段接入。

`0014` 允许已授权用户在私聊使用 `/export` 签发或重显个人全量链接，使用 `/export revoke` 撤销当前链接。链接基于独立密钥、随机 nonce、安装来源、Bot 和所有者派生，D1 保存摘要及派生元数据。私聊发送前再次核对授权版本和链接代数。重显保留链接，撤销后的新签发使用新链接。响应显示固定隔离来源的 Clash 链接。其他格式仍由 HTTP 入口逐项验证，Base64 链接需要先确认内容可导出。

`0017` 为私聊 `/o 关键词` 签发独立的筛选链接，空关键词匹配所有活动订阅。匹配名称与原始 URL 拼成的文本，使用 CPython 3.11 的 Unicode 14 小写转换，包括 Final_Sigma 上下文规则。数据由 GitHub runner 生成并逐码位核验。匹配后固定订阅 ID 顺序，保留当时尚未发布的命中成员，后续读取它们的最新快照。筛选链接仅包含所选订阅，上游刷新由独立阶段接入。查询文本仅存在于本次请求内存。完整所有者 ID 与生命周期版本向量在最终 D1 事务中核对，创建、重命名、回收或恢复造成的变化会要求重试。

每次筛选最多扫描 512 条元数据、8 MiB UTF-8 文本和五秒，每页 16 条。比较向量最多 1 MiB，关键词最多 256 个码位和 1024 字节，匹配结果最多 128 条。超限时整次筛选返回明确的超限结果。每个 Bot 和所有者最多保留 32 条活动筛选链接。签发使用现有密钥及独立 HMAC 域，重复消息复用原回执，新的查询保留旧链接。私聊发送前再次核对授权版本、成员生命周期与快照代数。发送前失效的链接会撤销并释放配额，确认失败的回复由有界定时清理回收，发送结果不确定时保留能力。

每条链接回复带有十分钟有效、一次使用的撤销按钮。上限提示会为当前活动筛选链接提供新的撤销按钮，使旧消息按钮过期后仍能回收配额。按钮固定 Bot、所有者、私聊、已发送的原消息和发送尝试，撤销后 HTTP 入口立即拒绝该能力码。`/o revoke` 仍按普通关键词搜索。隔离部署、两账号真实 Telegram 验收和旧能力码导入分别记录。

`0010` 在同一次 D1 读取中固定订阅所有者的路径规则，两遍导出复用该结果。规则对节点名称、服务器、原始 `share` 字段拼成的文本执行 Unicode 14 完整大小写折叠与子串匹配。最长折叠关键词优先，同长按规则 ID 排序。命中时给显示名称追加 ` → 备注`，已存分享 URI 的 Base64 输出字节保持原样，临时节点绕过规则。每个所有者最多读取 64 条规则，关键词和备注各最多 128 个 Unicode 码位。每遍最多消耗 64 Mi 个 UTF-16 工作单位，累计原始匹配文本和每次搜索的折叠文本长度。超出读取预算返回 `422`，无效的持久化规则返回 `503`。旧规则的数据迁移分阶段接入。 [CPython 3.11 Unicode 数据](https://docs.python.org/3.11/library/unicodedata.html)

`0013` 支持在 Bot 私聊中使用 `/path` 查看、`/path 关键词 备注` 或 `/path 关键词=备注` 设置、`/path delete 编号` 删除和 `/path clear` 清空。列表每页最多六条，通过回复中的 `/path list 编号` 继续。更新同一个原始关键词保留规则编号。消息鉴权、修改、去重回执和回复意图在同一 D1 事务中确认，规则文本只存于规则表。已经应用较新修改、超过 15 分钟、比数据库时钟快 30 秒以上，或早于或等于成员最近一次授权变更时间的修改请求会提示重发。群聊中的命令不会返回关键词、备注或能力链接。 [Telegram sendMessage](https://core.telegram.org/bots/api#sendmessage) · [D1 事务批处理](https://developers.cloudflare.com/d1/worker-api/d1-database/#batch)

## 组件边界

- **TypeScript Worker** 处理 HTTP、Telegram Webhook、权限与任务编排，通过平台绑定访问 D1、R2 和未来的 Queues。现有 Python 逻辑及回归样例是迁移对照。Python Workers 使用 Pyodide，依赖与文件系统行为与目前的 CPython 服务不同。单独移植轮询、进程内锁和本地 SQLite 仍需重新设计数据和事件生命周期。 [Python Workers 标准库](https://developers.cloudflare.com/workers/languages/python/stdlib/) · [Python 依赖支持](https://developers.cloudflare.com/workers/languages/python/packages/)
- **D1** 保存用户归属、授权、订阅元数据、能力链接、操作状态和当前快照指针。列表与权限检查只读取必要列。授权与领取使用数据库约束和有条件写入，关键读从主库获取。 [D1 Binding API](https://developers.cloudflare.com/d1/worker-api/d1-database/) · [D1 读取一致性](https://developers.cloudflare.com/d1/best-practices/read-replication/)
- **私有 R2** 存储体积较大的节点快照和受控备份。对象通过 Worker 绑定读取。禁用公开访问和边缘缓存。 [R2 一致性](https://developers.cloudflare.com/r2/reference/consistency/) · [R2 限制](https://developers.cloudflare.com/r2/platform/limits/)
- **Cron** 恢复待发 Telegram 回复、回收交互票据、处理文档任务及其废弃候选。提供方任务接入时，D1 记录任务状态与租约。若引入 Queues，只投递任务 ID，并验证重复投递和补发。 [Queues 投递语义](https://developers.cloudflare.com/queues/reference/delivery-guarantees/) · [Cron Triggers](https://developers.cloudflare.com/workers/configuration/cron-triggers/)

### 快照发布和恢复

1. 按订阅 ID 和随机快照 ID 写入一组不可变 NDJSON 对象，再写清单。清单按顺序记录每块的字节数、节点数和 SHA-256。
2. 所有对象写入成功后，使用订阅 ID、用户归属和上一代编号对 D1 进行条件更新，同时发布新快照 ID、清单摘要、节点计数和元数据。并发请求中只有一个写入能更新同一代。R2 写入失败或条件不匹配时，旧指针仍有效。
3. 读取时先核对 D1 中的清单摘要，再按顺序读取和校验各块。快照上限为 64 MiB、256 块、100,000 个节点。单块和单条记录分别最多 512 KiB，清单最多 64 KiB。Base64 导出的 16 MiB 分享文本上限包含行分隔符，Sing-box 按实际 JSON 字节数计量。部署后用真实分布和并发验证这些上限适用。
4. 已发布旧版本和发布结果不明的候选对象先保留。确认发布失败时，可清理本次新写入且尚未发布的对象。启用历史版本回收前，必须确认对象未被活动订阅、回收站、回滚版本或备份引用，并超过约定的恢复期。桶生命周期规则只适用于可证明安全的备份或临时对象前缀。 [R2 生命周期](https://developers.cloudflare.com/r2/buckets/object-lifecycles/)

## 功能对照与验收清单

以旧服务实际注册的命令、文本、按钮和 HTTP 路由为准。下表将已接入的隔离入口和可单独验收的后续工作分开。发布时分别核对托管 CI、确切提交的隔离部署、真实资源读回及用户操作。真人操作限获准的两名测试者在内置浏览器使用隔离 Bot 和指定测试群。 [旧 Bot 入口](../bot.py) · [隔离 Worker 入口](../worker/src/index.ts)

| 旧入口与行为 | 隔离 Worker 与独立验收项 |
| --- | --- |
| `/start`、`/help`、中文回复菜单、`/auth` 列表及增删，支持输入 ID 或回复目标用户。 | 已接入基础欢迎、帮助和私聊管理员授权。核对两账号和测试群的权限隔离、撤权及重投。中文菜单、生产管理员及白名单配置、历史授权覆盖另行核对。 |
| `/list`、`/expire`、回收站菜单、翻页和跳页。 | `/list`、未来 14 天内到期的 `/expire` 及新增的 `/recycle` 已支持按所有者翻页。核对边界日期、旧票据、跨用户回调和重命名、确认删除、30 天内恢复。菜单、任意页跳转和详情入口分开接入。 |
| 数字或列表按钮打开详情，浏览节点和流量，单条重命名、刷新、删除、格式链接、短链和节点文件。`/s` 按名称及原始 URL 搜索，`/d` 批量删除匹配项。`/renumber` 只返回当前订阅计数。 | 已有生命周期操作、元数据和快照读取。详情及节点浏览、搜索、批量回收预览和确认、私聊签发各格式链接及原始 URI 附件分别验收。展示编号由列表计算。原始 URL、节点及能力链接限定在私聊。 |
| 粘贴节点加入临时列表，`/temp` 查看原文，`/temp clear` 清空。 | 已接入私聊原始 URI 和 Base64 批量导入、计数和清空。核对顺序、重复、整批拒绝及迟到清空。私聊查看或导出原文另行验收。 |
| 上传 `.txt`、`.log`、`.yaml`、`.yml`、`.json`，识别节点或订阅 URL，同名文件更新旧导入。 | 已接入私聊节点文档及同名上传替换。验收同一账号保留订阅 ID 和令牌、另一账号同名文件独立、失败保留旧快照。URL 列表和混合文档随提供方导入接入。 |
| 发送一个或多个 HTTP(S) URL 或 `名称\|URL`，重复 URL 刷新，按上游标题自动命名。单条刷新、详情或导出的按需刷新、更新所有的确认和进度、有效及失败报告、保留或回收失败项。 | 私有抓取入口、订阅元数据和快照发布为基础。先验收实际提供方出网、URL 导入、单条刷新和流量、到期、标题，再验收可恢复的批量刷新、报告和失败项回收。 |
| `/export` 动态全量聚合含自己的临时节点，`/o` 按名称和原始 URL 筛选并固定订阅顺序，所选聚合只包含订阅。 | 已接入全量和筛选聚合的 HTTP 读取、私聊 `/export` 及 `/o` 签发和撤销。验收 Unicode 匹配、稳定重显、冻结成员、配额回收、并发修改、撤销后的新读取、两账号归属和顺序。旧聚合码迁移单独接入。 |
| `/short` 显示帮助，`短链 URL`、`short URL` 及详情按钮签发短链。`/s/{code}` 按已保存目标跳转，可选外部服务包装同一受控本地链接。 | 当前 `/s/{code}` 支持聚合同源重定向。单订阅格式短链、任意 HTTP(S) 目标及可信外部服务回退单独验收。 |
| `/path` 和菜单维护路径对应，支持添加、删除和清空，受限文本入口接受 `关键词=备注`。 | HTTP 导出已应用所有者路径规则，临时节点保留原名。私聊 `/path` 已接入显式添加、删除、清空和分页。验收两账号隔离与迟到操作，菜单、独立自由文本和旧规则导入分别接入。 |
| `@Bot [关键词]` 搜索并发送订阅及临时节点，`/i` 切换默认、流量、到期和名称排序。`Share` 支持自定义内容或匹配订阅、指定接收人、份数和有效期；选中反馈用于更新原卡。 | 私密领取已接入私聊 `/start claim_<code>`，核对过期、指定用户、并发、重复领取及撤权后的领取权限。私密创建、内联搜索和排序、卡片编辑分开验收；分享卡片只显示通用信息，正文在私聊交付。 |
| `/g` 查 GitHub 仓库和公开代码，代码无结果时查询 grep.app，必要时提供 GitHub 网页搜索入口。`/ai` 接受 API 地址和 Key，探测 OpenAI 兼容端点的状态和延迟。 | 两项各自接入和验收。GitHub 凭据只发送至 GitHub。`/ai` 按固定范围验证用户提供的地址，禁用重定向，保护 Key 和上游响应。 |
| `/health`、单订阅、聚合和短链 HTTP 路由。旧服务默认使用 Clash，支持 Base64、Sing-box、Surge 和 QX 系列。 | 按本页 HTTP 表验收格式、别名、顺序、字节、失败状态及旧能力链接。托管配置校验、真实隔离 HTTP 响应和客户端导入分别记录。 |
| 旧服务使用长轮询，启动时清理过期分享和旧回收记录，刷新由用户操作触发。 | 已接入 Webhook 和 Telegram 恢复 Cron。订阅批处理和生产数据回收另行验收，回收前核对备份、活动指针及回滚引用。 |

回收操作在同一 D1 事务内将订阅元数据移出活动表。旧 Worker 在回滚时也无法用活动查询读取已回收订阅。恢复保留原 ID、能力令牌、快照指针及到期和流量信息，便于继续使用原链接和 R2 对象。回收站显示和恢复均以 D1 时间为准，保留 30 天的操作窗口。超出窗口的元数据和 R2 对象留待受控清理。已开始的导出可以继续读取原快照，后续请求需要重新查询活动表。

重命名、回收和恢复增加订阅生命周期版本。发布快照时同时检查节点代数与生命周期版本，避免延迟任务跨过回收和恢复边界覆盖当前快照。回滚只切换已验证的 Worker 版本，保留增量表，后续重新部署仍使用完整的迁移历史。

### Telegram 收件、发件与权限验收

- 隔离入口 `/telegram/webhook` 处理上表已接入的命令、消息和回调。指定测试 Bot 的两个用户可以操作各自的订阅，群内入口限指定测试群。管理员在自己的私聊管理另一名测试用户的授权。
- Webhook 仅接收指定路径上的 HTTPS POST，以恒定时间比较核对 `X-Telegram-Bot-Api-Secret-Token`，限制请求大小及允许的 update 类型。用 `(bot_id, update_id)` 唯一键持久记录更新。提交后返回 `2xx`，已持久化的重复更新也返回 `2xx`。暂时无法持久化时返回可重试错误。接受乱序更新，去重保留期覆盖重投窗口。 [Telegram `Update`](https://core.telegram.org/bots/api#update) · [Telegram `setWebhook`](https://core.telegram.org/bots/api#setwebhook)
- 收件记录只保留归属、消息 ID 和已识别的命令。授权变更和回复意图与收件记录在同一 D1 事务提交。同一用户和聊天的回复按入库顺序处理。发送前复核授权，已经发起的外部请求无法撤回。只有明确的 Telegram 限流拒绝可在到期前重试。超时和无法确认的发送标记为 `uncertain`，保留以供核对。 [D1 事务批处理](https://developers.cloudflare.com/d1/worker-api/d1-database/#batch) · [Telegram `ResponseParameters`](https://core.telegram.org/bots/api#responseparameters)
- 只读视图每页至多八条，按订阅 ID、到期时间或删除时间翻页。按钮只传随机值，D1 仅存摘要，绑定原发起人、聊天、话题、已确认发送的消息和尝试号，十分钟内只能消费一次。回调去重、按钮消费和下一页回复同批提交。回滚至支持回执标记的版本时，普通命令继续处理，视图回执留待新版处理。 [Telegram `CallbackQuery`](https://core.telegram.org/bots/api#callbackquery)
- 同一用户的私聊和群聊读取相同的个人数据。重命名和翻页绑定用户、聊天与话题。受保护的写入以 D1 里的当前授权和对象版本为条件。生产授权迁移需要核对管理员、初始白名单及显式允许和拒绝覆盖。
- 私密领取保留现有的分享能力语义。`0005` 按 Bot 存储分享码摘要，使用独立的私有 R2 对象保存最多 64 KiB 的私密正文。`0007` 将指定账号在普通私聊发出的 `/start claim_<code>` 记为持久领取意图，回执只存码的摘要。这个入口沿用单次领取授权，普通订阅操作仍检查白名单。领取前核对正文长度、摘要和 UTF-8，D1 在同一事务复核到期、指定用户及剩余份数，同时将回复切换到发送中。份数以 `(share_id, actor_id)` 唯一领取记录计数，已领取的用户在有效期内可再次查看。
- 私聊短正文以纯文本送达，超过消息长度或含有不适合直接显示的控制字符时使用一个固定文件名的 UTF-8 附件。发送结果不明时保留回执和领取记录，避免自动重复发送。内联创建和更新群内分享卡片另行接入。 [Telegram `sendMessage`](https://core.telegram.org/bots/api#sendmessage) · [Telegram `sendDocument`](https://core.telegram.org/bots/api#senddocument)
- 验收须覆盖 Telegram 返回成功后写回失败，核对同一发件租约的状态与实际送达。 [Telegram `sendMessage`](https://core.telegram.org/bots/api#sendmessage)
- 重命名等待只接受同一用户在同一聊天与话题中回复已经确认送达的 Bot 提示。删除要求点击独立确认按钮。写入时复核所有者、授权、版本和操作票据，在同一 D1 事务完成变更和回复记录。回收站恢复保留订阅 ID、能力链接和已发布快照。
- 临时节点先支持私聊粘贴节点链接或 Base64 列表。导入保留原始 URI、顺序及重复项。格式错误或暂不支持的节点按数量报告，并整批保留原状态。`0008` 将不超过 256 KiB 的有界数据批次、当前授权与回复意图放在同一 D1 事务。每个用户最多 5,000 个节点和 4 MiB。群聊不会接收临时节点正文。`/temp` 查看个人计数，`/temp clear` 清除当前清空操作之前的条目，较新的导入不会被迟到的清空误删。临时文件、URL 及聚合交互另行接入。
- 已授权用户可以在私聊上传 TXT、LOG、YAML 或 JSON 文件导入命名订阅。纯文本支持原始节点和 Base64。每个文件上限 10 MiB 和 500 个节点，超过限制或含无法支持的节点时整批拒绝。订阅提供方 URL 的识别和刷新由独立出网阶段接入。
- `0011` 的私聊任务在 webhook 内持久入库，由 Cron 每轮最多领取一件。`0012` 在写入 R2 前记录候选快照，按所有者、文件名、较新消息、授权版本、租约和订阅版本复核发布。成功时在同一 D1 事务中更新快照指针并写入完成回执。同名导入保留现有 ID 和访问令牌。失败保留上一份有效快照，文件 ID 及文件名在任务终止时清除。只有已超出 Cron 最长执行窗口且活动表和回收站均未引用的候选可回收。

### 私聊聚合签发验收

`worker-isolation-telegram-aggregate-smoke.yml` 只在受保护的 `main` 与 `subs-bot-isolation` 环境运行，和部署共用锁。它核对实际活动版本、精确 D1/R2 归属、Telegram 配置摘要、聚合密钥摘要和 `0014` 校验和。`prepare` 为两个指定账号各保留一份不同的合成 Shadowsocks 快照；已有同名、同来源但身份不同的记录、其他活动订阅、临时节点、路径规则或正在处理的文件任务都会阻止操作。

真人命令全部从指定的 IAB 账号发送，工具不调用 Bot API，也不创建 Telegram 回执。先让两个账号分别私聊发送 `/export` 两次，再运行 `capture-initial`；成员发送 `/export revoke` 后运行 `verify-member-revoked`；成员重新发送一次 `/export` 后运行 `verify-rotated`；最后两个账号都撤销，再运行带完整确认语句的 `retire`。每一步提供上一成功步骤的 `source_run_id`，并核对同一提交、工作流、run attempt 和产物摘要。`prepare` 另将实际活动 Worker 的版本 UUID、模块 SHA-256、兼容日期和提交固定为独立的 `releasePin`；所有捕获和验证步骤要求完全相同，即使 `BUILD_REVISION` 未变，替换版本或模块也会拒绝。该固定值不参与合成 Token 或对象身份派生。

每次检查固定内容的 Clash/Base64 GET 与 HEAD、私有缓存响应头和 `/s/` 同源相对跳转，确认重复签发稳定、旧码撤销后返回 `404`、成员轮换得到新码且管理员码不变。检查点保存能力摘要与规范的 16 字节派生 nonce、密钥版本，以及合成快照的安全数字/UUID 身份与对象摘要；nonce 是非能力恢复元数据，只有另行保护的 HMAC 密钥才能推导 bearer。检查点不保存真实账号 ID、密钥、订阅 Token、原始能力链接或节点正文，日志只报告计数、状态和摘要。

合成订阅 Token 使用独立域的 HMAC 派生，R2 键使用独立派生的 UUIDv8；重试中只采纳完全一致的保留记录与对象，PUT 带 `If-None-Match: *`。发布中断可用同一 cohort 重新 `prepare`，不覆盖已发布或异内容对象。退休先确认两个托管槽已撤销且没有临时节点，以精确快照指针比较并删除两个合成 D1 行，再删除四个固定 R2 键；API 结果不明时先读回，部分对象删除可从上一 `rotated` 检查点重试。只有清理允许在后续已核对的 `main` 发布上继续：资源、配置、密钥及原始派生身份仍须相同，原 `releasePin` 保留，并在最终检查点另记实际清理发布 `retiredAtReleasePin`，不将它计为原验收的延续。实际收件、发件、签发槽和撤销链接作为重放/顺序墓碑保留。此工具是隔离验收准备，只有托管运行结果与真人 IAB 操作共同完成后才能视为实际验收。

### 私聊所选订阅验收

`worker-isolation-telegram-selected-smoke.yml` 使用同一个受保护的 `main`、隔离环境和发布锁。四轮都要求当前提交、活动 Worker 版本和模块摘要一致，并核对两位测试账号、Bot、群聊、聚合密钥和已应用的 `0017` 摘要。每一轮等上一轮成功后再操作，`source_run_id` 指向上一轮的成功运行。工作流只接收浏览器中实际回复所含能力码的 SHA-256，检查点也只保存摘要、回执指纹和合成快照标识。

1. 用未使用的 16 位小写十六进制 `cohort` 执行 `prepare`。它在两位指定账号下暂存四份合成快照。两个管理员订阅分别由名称和来源匹配，第三份用 `STRASSE` 作不匹配对照。成员拥有独立的同关键词订阅。
2. 管理员在 IAB 私聊粘贴一行 `ss://YWVzLTI1Ni1nY206Zml4dHVyZQ@203.0.113.40:8388#CFSEL-<cohort>-temp-node`，等待确认。管理员在指定群聊发送 `/help@test_cfsubs_bot`，确认收到控制回复，再发送 `/o@test_cfsubs_bot <cohort>-STRAẞE-Aς`，观察群聊未发出链接。两位账号各在私聊发送一次 `/o <cohort>-STRAẞE-Aς`。只对各自回复 URL 中 `/agg/` 后的 22 字符能力码计算 SHA-256。将 `admin-first`、`member-first` 两个摘要交给 `capture-first-and-extend`。这一轮核对收发回执和 Clash、Base64 字节，加入一份新匹配订阅，再检查两个原链接的字节保持一致。
3. 管理员在私聊用相同关键词再发一次 `/o`，记录 `admin-second` 摘要，并在第一条链接的原消息上点击一次「撤销此链接」。等待撤销回复后执行 `capture-independence`，只提交新链接摘要。工作流核对首条链接的 `404`、第二条的新增成员，以及成员链接仍可用。
4. 在 IAB 分别点击第二条管理员链接和成员链接各自原消息上的「撤销此链接」。管理员再执行 `/temp clear`。等回复后执行 `retire`，确认字段填 `retire <cohort>`。它先核对三条链接已撤销和清空回执，然后按已核对的行和对象身份删除五条合成订阅及十个 R2 对象。收件、发件、撤销记录和临时节点清空标记保留。

撤销按钮有效期为 10 分钟。收到回复后按上述顺序尽快完成验证。票据已过期或剩余时间不足时，停止本轮，保留现有检查点和合成数据。工具读取群聊控制回执和范围内的签发记录。群聊中未显示链接的观察在 IAB 完成。R2 写入使用发布锁串行执行，逐项比对对象归属、预期字节和写后读回。

### 刷新与出网验收

- 刷新任务保存订阅、发起人、期望版本、尝试次数和错误类别。租约带过期时间及递增凭据，过期消费者的写入由条件检查拒绝。队列消息重复投递时复用同一任务。重试按错误类别退避并遵守提供方限速，耗尽后进入死信或可审计的失败状态。用 Cron 补发已入库但未成功入队的任务。拉取或解析失败只记录错误状态，上一份有效快照继续服务。 [Queues 重试与死信](https://developers.cloudflare.com/queues/configuration/batching-retries/)
- 任意用户 URL 开放前，验证 HTTP(S) URL、允许端口和重定向策略。每一跳重新解析 A/AAAA，拒绝私有、环回、保留及混合公网和私网结果，并确保实际连接到通过检查的 IP，同时保持原 Host、TLS SNI 和证书校验。带凭据的请求禁止将凭据转发至新来源。延续现有解压后 10 MiB 上限，并对上传、重定向次数、总耗时、节点数和 YAML 深度或别名设置限额。
- 抓取组件使用项目专用 Cloudflare Container、固定 DNS 地址的 Python 传输及有界私有 RPC。业务 Worker 的服务绑定、导入和刷新任务需要通过隔离集成验收，确认实际连接、TLS 和 Cloudflare 代理的提供方兼容性。持久数据继续写入 D1 和 R2。 [私有抓取组件](../worker/provider_fetch/README.md) · [Containers 出网](https://developers.cloudflare.com/containers/configuration/outbound-traffic/)
- 测试包括实际提供方的鉴权、重定向、编码、流量头、IPv4/IPv6、阻断行为与限速。输出只记录分类结果和耗时。覆盖 DNS 重绑定、跨来源重定向、压缩超限和异常 YAML，并核对失败不会改变旧快照。真实联调使用获准的测试订阅和会话。

## 部署、数据迁移和回滚

### 隔离环境发布

1. 在 GitHub 建立仅允许 `main` 的 `subs-bot-isolation` Environment。将核对过的资源标识保存为此环境的 Secret `SUBS_BOT_CF_ISOLATION_TARGET_JSON`，包含 `accountId`、`workerId`、`workerCreatedOn`、`d1Id`、`d1CreatedAt`、`r2CreatedOn` 和 `namespace`。把数据和 Worker 部署凭据分别保存在此环境的 `SUBS_BOT_CF_BOOTSTRAP_TOKEN`、`SUBS_BOT_CF_DEPLOY_TOKEN`。普通 PR CI 和构建产物不使用这些凭据。 [GitHub Environment 保护规则](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments)
2. 查找当前 `main` 的成功 `Worker CI` 运行。若该提交只改动旧 Python 服务，先手动对 `main` 运行 `Worker CI` 生成同一 SHA 的产物。以该运行 ID 启动 `gh workflow run worker-isolation-deploy.yml --ref main -f source_run_id=<run-id>`。
3. 发布流程重新核对运行、提交、ZIP 摘要、包内文件清单及独立摘要，验证已登记的资源身份。D1 只接管结构完全一致且已清理合成数据的 `0001` 基线，使用 `subs_bot_schema_migrations` 记录已核对的摘要。后续通过同一流程应用增量建表和建索引。涉及现有数据或表结构变更时单独审查迁移和恢复步骤。 [D1 迁移](https://developers.cloudflare.com/d1/reference/migrations/)
4. Worker 的候选版本通过内容与绑定回读后才启用。记录实际版本、部署及 `/health` 中的提交。遇到不明确的写入结果，先读取实际状态；Worker 回滚仅恢复此前验证的版本，D1 和 R2 状态独立处理。 [Cloudflare Worker 回滚](https://developers.cloudflare.com/workers/versions-and-deployments/rollbacks/)
5. 含 `0002_telegram.sql` 的隔离版本从同一 Environment 的 `SUBS_BOT_TELEGRAM_TEST_CONFIG` 注入加密配置。配置包含已核对的测试 Bot、两个账号、测试群和 Webhook 密钥。Worker 就绪后配置每分钟 Cron，用于恢复持久回复。测试 Bot 的 Webhook 首次设置前，核对 Bot 身份和现有 Webhook；仅在目标是该隔离地址时接收 `message` 更新并保留待处理更新。真实账号的消息验收在内置浏览器执行。 [Workers Cron](https://developers.cloudflare.com/workers/configuration/cron-triggers/) · [Telegram Webhook](https://core.telegram.org/bots/api#setwebhook)
6. 发布含 `0004_telegram_views.sql` 的版本前，先确认已发布并记录支持回执标记的回滚版本。激活新版并核对实际版本后，只为同一隔离测试 Bot 将 `allowed_updates` 扩为 `message` 与 `callback_query`。保持已核对的 URL、Webhook 密钥和连接上限，设置 `drop_pending_updates: false`，用 `getWebhookInfo` 核对结果。回滚视图时先恢复只接收 `message`，保留增量表和待处理更新。 [Telegram Webhook 配置](https://core.telegram.org/bots/api#setwebhook) · [Telegram Webhook 回读](https://core.telegram.org/bots/api#getwebhookinfo)
7. 真人视图验收前，用 `gh workflow run worker-isolation-telegram-fixtures.yml --ref main -f action=seed -f cohort=<16位小写字母数字>` 生成指定两名测试用户的合成订阅和回收站记录。流程校验实际 Worker、D1、Telegram 配置摘要和迁移，并只写隔离 D1。真人消息及按钮只在内置浏览器验证。结束后以同一个 `cohort` 和 `action=retire` 删除本组记录，核对输出计数。
8. 订阅操作验收使用同一工作流，增加 `-f purpose=lifecycle`。专用批次只允许匹配的两个账号及预定义合成来源，测试重命名使用原名后接 `-renamed`。退役流程核对归属、名称、版本、删除状态和未发布快照条件，核对不一致时整批保留。
9. 私密领取验收使用 `worker-isolation-telegram-claims.yml`，通过 `action`、`cohort` 和 `digests` 手动运行。生成四个随机合成分享码，仅将 `targeted`、`race`、`expired` 和 `document` 对应的 SHA-256 摘要提交给工作流。测试人员在指定 Telegram Web 私聊中使用原码。用相同摘要映射退役，核对合成分享、领取与私有 R2 对象均已清除，保留收件和发送回执。
10. 发布含 `0014` 的版本前，在同一受控 Environment 配置 `SUBS_BOT_TELEGRAM_AGGREGATE_KEY`。它是独立随机 32 字节的无填充 Base64URL 编码，注入 Worker 的加密绑定 `TELEGRAM_AGGREGATE_KEY`。发布与回读比较其摘要，重复发布保留原密钥。密钥轮换须单独审查，原始密钥及能力链接始终留在受控凭据和私聊范围内。

域级 Worker 路由核对使用单独的只读凭据。发布任务内使用项目专用凭据核对 Worker 的 Custom Domain、预览、日志、Cron 及实际数据绑定。 [Cloudflare Worker 路由 API](https://developers.cloudflare.com/api/resources/workers/subresources/routes/)

### 数据与切换

隔离容量检查使用当前 `main` 的已部署版本，手动运行 `gh workflow run worker-isolation-capacity.yml --ref main`。托管 runner 生成合成快照，依次验证恰好达到 64 MiB NDJSON 和 16 MiB 分享原文的有效输出、分享原文超 1 字节的拒绝、快照清单超 1 字节的拒绝。正向测试流式核对 Base64 长度和摘要，覆盖串行、并发 2 和 4、慢读及中途取消。发布和容量检查使用同一并发组，测试结束先撤销 D1 能力，再清理对应的私有 R2 对象。清理失败时，工作流保留不含凭据或原始能力令牌的恢复清单。

运行 `gh workflow run worker-isolation-capacity.yml --ref main -f profile=structured-smoke` 可单独检查混合 Base64 导出。该模式在同一个隔离环境暂存两份小快照，用旧版 Python 序列化器的结果校验混合导出的长度和摘要，并检查不支持的结构化节点返回固定的 422 响应。两份快照都检查 GET 和 HEAD，前后各检查一次运行版本。该模式的恢复清单对应 `capacity_resources.py cleanup` 的 `--profile structured-smoke` 参数。

同一工作流的 `profile=singbox-smoke` 针对 `/sing-box` 检查两份专用快照。成功响应必须声明精确字节数，规范化 JSON 摘要与 Python 对照一致。包含外部出站依赖的快照须返回固定的 422。该模式使用同名清理参数。

`profile=clash-smoke` 检查旧能力路径和 `/clash` 两种入口。两者的 GET 字节必须一致，HEAD 均为空。探针对照固定代理、分组、规则和凭据，验证不支持的依赖返回 422。它使用同名清理参数。

`profile=text-export-smoke` 暂存四份合成快照，检查 `/surge`、`/qx`、`/quantumult` 和 `/quantumultx`。成功的 GET 必须声明准确长度，原始 UTF-8 响应的摘要须与固定样本相同。HEAD 均为空，不兼容的协议组合返回固定的 `422`。探针共发送 18 次请求，包括前后两次版本检查。它使用同名清理参数。原生客户端导入和代理连接另行验证。

`profile=aggregate-smoke` 还验证路径规则。探针为专用合成所有者暂存规则，核对单份、全量、指定顺序聚合以及另一所有者的 Sing-box GET 和 HEAD。配置必须保留连接参数并按预期应用 Unicode 折叠、最长关键词和同长规则顺序。临时节点保留原名，聚合 Base64 原始输出字节保持一致。清理事务先核对并移除合成聚合码、规则和临时数据，再由原流程撤销合成订阅并清理 R2。工作流只报告状态、字节数和摘要。

隔离文档验收使用 `worker-isolation-telegram-documents.yml`。选择未使用的 16 位小写十六进制 `cohort` 并先运行 `prepare`。两名获准测试者分别在浏览器中私聊同一个隔离 Bot，上传名为 `tgdoc-<cohort>.txt` 的纯文本文件。每行以 `ss://YWVzLTI1Ni1nY206Zml4dHVyZQ@203.0.113.10:8388#tgdoc-<cohort>-` 开头，成员首版以 `member-first` 结尾，管理员首版以 `admin-first` 结尾。填写成功的 `prepare` 运行 ID 执行 `capture-created`，确认两份首版都已核对后再继续。

成员用相同文件名上传两行替换内容，分别以 `member-second-1` 和 `member-second-2` 结尾，再上传一个同名、只有普通文本的无效文件。以 `capture-created` 运行 ID 执行 `verify-replaced`。该步骤核对成员的稳定订阅 ID、能力令牌摘要和新版本、管理员的原版本、合成导出的 GET 和 HEAD，以及成功回执。能从浏览器确认无效文件的准确消息 ID 时，可填入 `negative_message_id` 核对对应终态，否则保留浏览器观察和未发生额外发布的证据。

关闭本组上传后选择 `retire`，提供成功的 `verify-replaced` 运行 ID，并在确认字段填写 `retire <cohort>`。若在替换前结束，也可使用 `capture-created` 的检查点。清理先在 D1 中核对并撤销本组两个订阅指针，再删除并核对检查点记录的私有 R2 对象。实际 Telegram 的终态回执继续保留，以防重投重新创建订阅。检查点只包含本组合成对象标识、计数和摘要。验收工作流通过 Cloudflare 核对状态，实际上传和可见回复在浏览器中确认。

容量检查的客户端耗时和吞吐来自这组样本。CPU、内存和平台子请求数量通过隔离 Worker 的聚合指标另行核对。旧 SQLite 的正文体积与转换后的 NDJSON 和分享原文分别测量。真实备份的分布、超限项及可恢复性需要通过获准的数据演练验证。 [Workers 限制](https://developers.cloudflare.com/workers/platform/limits/) · [Workers 指标](https://developers.cloudflare.com/analytics/graphql-api/tutorials/querying-workers-metrics/)

旧库容量盘点在获准的托管环境运行 `python3 -B worker/tools/legacy_inventory.py <封存备份>`。输入须是单独完成、关闭、使用 UTF-8 和 DELETE 日志模式的 SQLite 备份。备份准备在原库之外进行，盘点本身以只读事务运行。报告只包含活动订阅与回收站的聚合计数、原始字节、紧凑 UTF-8 NDJSON 字节、块数、大小限制和旧转换器分享原文估算。无法读取或解析的记录有独立计数。退出码 `0` 表示报告完整，仍需检查超限和无效项。退出码 `2` 表示无法核对备份。容量报告不判定归属映射、旧链接兼容、分享权限或实际 Worker 性能。 [SQLite 增量读取](https://sqlite.org/c3ref/blob_open.html) · [SQLite URI](https://sqlite.org/uri.html)

### 真实数据与生产切换门槛

1. 先只读核对 Cloudflare 目标账户、Zone、`subs-bot.lilyya.top` 的 DNS、Worker 路由和 Custom Domain 绑定。新资源记录账号、环境及资源 ID，隔离与生产分别使用各自的 Worker、D1、R2 和队列。现有配置冲突须在改动前报告。目标主机名可用且切换获准后，仅增加所需的 Custom Domain 绑定。 [Custom Domains](https://developers.cloudflare.com/workers/configuration/routing/custom-domains/)
2. `Worker CI` 在 GitHub 托管 runner 上安装依赖、检查类型、构建和测试。构建产物标记准确提交与摘要，由授权的部署步骤核对并上传至隔离 Worker。普通 PR CI 使用只读权限和合成数据。部署 Token 通过独立的受控步骤使用。云端 smoke 显式指定隔离环境和提交，核对 `/health` 与提交、已知测试快照的输出和负面用例。分别记录测试、构建、部署和真实运行结果。
3. 确认获准的数据来源和使用范围后，对旧 SQLite 执行包含 WAL 的一致性备份。先在项目专用隔离目标做恢复和容量盘点。对账活动订阅、回收站、路径规则、临时节点、授权覆盖、分享及领取、短链的数量和归属。核对节点摘要、有效订阅令牌、旧短码、仍有效的领取状态和跨域链接依赖。旧群级数据须由维护者确认归属。
4. 合成备份演练验证恢复路径。真实数据验收需保存同一代 D1 导出或恢复书签、R2 清单及摘要，并在独立目标重建实际引用。核对清单、对象摘要、外键、导出和两个账号的权限。Workers Paid 的 D1 Time Travel 可用于最近 30 天的原地恢复，会覆盖目标 D1。R2 对象使用对应的独立备份。 [D1 Time Travel](https://developers.cloudflare.com/d1/reference/time-travel/)
5. 在功能清单中记录代表性提供方、客户端及双账号的实测结果，并核对容量、失败恢复和旧链接连续性。确认生产切换范围、窗口及回滚方案并取得授权后，冻结旧写入，完成最后一次同步，再切换 Telegram Webhook 或域名流量。保留待处理更新，先处理旧轮询配置 `drop_pending_updates=True` 的回滚风险。验收失败时停止新写入，核对迁移后写入如何回放，再分别恢复 Worker 版本、数据和 Telegram 模式。 [Telegram `setWebhook` / `deleteWebhook`](https://core.telegram.org/bots/api#setwebhook) · [Worker 版本与部署](https://developers.cloudflare.com/workers/versions-and-deployments/)

## 限额、成本和凭据

- Workers Paid 的 Worker 内存为每 isolate 128 MB，由同一 isolate 中的并发请求共享。HTTP CPU 默认 30 秒，可配置至 5 分钟，每次调用默认最多 10,000 个子请求，R2 和 D1 绑定请求也计入。D1 单个字符串、BLOB 或数据行上限 2,000,000 字节，Paid 单库上限 10 GB。Queues 单条消息上限 128 KB。 [Workers 限制](https://developers.cloudflare.com/workers/platform/limits/) · [D1 限制](https://developers.cloudflare.com/d1/platform/limits/) · [Queues 限制](https://developers.cloudflare.com/queues/platform/limits/)
- 一个有 `N` 个数据块的快照，每遍读取包含一次清单读取和 `N` 次数据块读取。完整 `GET` 执行 `2 × (N + 1)` 次 R2 Class B 读取，并重复校验和解码。`HEAD` 只进行预检。隔离环境的正确性 smoke 完成后，仍需以接近快照与导出上限的样本，在代表性的并发量、慢客户端和中途取消条件下测量首字节与完整响应耗时、吞吐、CPU、内存超限计数及实际 R2 子请求数。用实测操作数与请求分布估算成本，再决定是否调整块大小或请求限额。 [R2 Class B 定价](https://developers.cloudflare.com/r2/pricing/#class-b-operations)
- 成本按实测请求数与 CPU、D1 读写行数、R2 容量及对象读写、队列投递与重试计算。若启用 Container，再核对实例运行时间、内存和磁盘配额、活动 CPU、区域出网及关联 Durable Objects 用量。隔离验收以按需启动和可睡眠为前提。显著新增费用或需要常驻时先提交估算和影响。 [Workers 定价](https://developers.cloudflare.com/workers/platform/pricing/) · [R2 定价](https://developers.cloudflare.com/r2/pricing/) · [Queues 定价](https://developers.cloudflare.com/queues/platform/pricing/) · [Containers 定价](https://developers.cloudflare.com/containers/platform/pricing/)
- 资源管理分开使用只读核查、派生 Token 创建和项目部署权限。新 Token 按目标账户、所需操作和有效期收窄。平台权限无法限定到单个资源时，执行步骤须核对项目专用资源 ID。应用通过绑定和 Secrets 使用运行所需权限。高权限管理凭据留在受控管理位置。 [Cloudflare API Token](https://developers.cloudflare.com/fundamentals/api/get-started/create-token/) · [Workers Secrets](https://developers.cloudflare.com/workers/configuration/secrets/)
- Worker、反代及其他链路避免记录能力路径、查询参数、Telegram 更新、订阅内容、鉴权头或上游异常正文。Cloudflare 自动 invocation 日志可能包含带凭据的 URL，发布前禁用或验证脱敏，并核对追踪、异常和外部转发的字段。允许的运行信号限于路由类别、状态、计数、耗时和内部操作 ID。私密数据和密钥不得出现在公共缓存、Git、构建产物或测试日志。 [Workers Logs](https://developers.cloudflare.com/workers/observability/logs/workers-logs/)
