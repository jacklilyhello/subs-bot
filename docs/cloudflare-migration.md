# Cloudflare 迁移

迁移目标是让 subs-bot 的 Telegram 处理、订阅与分享数据、导出和后台任务都运行在 Cloudflare。Telegram、GitHub、订阅提供方和已配置的可信短链服务仍是业务接口。完成切换后，服务无需维护者管理 VPS、轮询进程或外部数据库。

## 隔离环境与 HTTP 接口

隔离 Worker 使用本项目专用 `workers.dev` 主机名、D1 元数据、私有 R2 快照和合成数据。Telegram 收件、回复和文档处理使用同一隔离环境。

| 路径 | 隔离 Worker 的行为 |
| --- | --- |
| `GET` 或 `HEAD /health` | 返回部署的 40 位 Git commit SHA，供部署验收核对 |
| `GET` 或 `HEAD /sub/{token}/{format}` | 读取当前已发布快照，支持 `base64`、`v2ray`、`mixed`、`singbox`、`sing-box`、`clash`、`surge`、`qx`、`quantumult` 和 `quantumultx`。省略格式时使用 `clash` |
| `GET` 或 `HEAD /agg/{code}/{format}` | 导出全量或指定订阅，使用同一套格式 |
| `GET` 或 `HEAD /s/{code}` | 对有效聚合码返回同源相对重定向，对普通短码跳转到已验证的外部 HTTP(S) 地址 |
| `POST /telegram/webhook` | 校验隔离 Bot 的 Webhook 密钥，接收受限消息及回调 |

能力链接视同凭据。成功与失败响应均使用 `Cache-Control: no-store, private`、`Referrer-Policy: no-referrer` 和 `X-Content-Type-Options: nosniff`。`HEAD` 执行同样的预检并返回相同状态，响应体为空。未知能力链接返回 `404`，未支持的导出格式返回 `406`，内容无法完整转换或超过格式限制时返回 `422`。若预检时发现已引用的快照不可用或校验失败，返回 `503`。旧服务将未知格式回退到 Clash，迁移前须核对已发链接所用格式。

`GET` 在预检时验证已选定的快照并计算编码长度。通过后再读取同一个不可变快照，按原有块顺序编码，通过 `FixedLengthStream` 发送。两遍读取各自最多同时预读四个块，下游消费一块后再补下一块。若第二遍读取在成功响应头发出后失败，响应流会中止，客户端应把读取错误或未读满声明长度视为失败。响应流取消后停止补读，已发出的存储请求可能仍会完成。 [Workers FixedLengthStream](https://developers.cloudflare.com/workers/runtime-apis/streams/transformstream/#fixedlengthstream) · [Workers Content-Length](https://developers.cloudflare.com/workers/runtime-apis/response/#set-the-content-length-header)

结构化导出支持 Shadowsocks、VMess、VLESS、Trojan、Hysteria 2、TUIC v5 和 AnyTLS。生成 URI 时，服务器地址需要使用 IP 或 ASCII 主机名，包括已明确编码的 Punycode。Python 的 IDNA 转换与 Worker 的 URL 转换可能将同一个 Unicode 主机名解析为不同目的地。已有分享 URI 通过校验后按原字节导出。 [Python IDNA](https://docs.python.org/3/library/codecs.html#encodings.idna) · [URL 标准](https://url.spec.whatwg.org/#concept-domain-to-ascii)

Sing-box 返回含选择器、直连项和代理出站的 JSON。支持 Shadowsocks、VMess、VLESS、Trojan、Hysteria 1 和 2、TUIC、AnyTLS、SOCKS 和 HTTP(S) 的已支持选项。HTTP(S) 使用结构化节点，VMess 的分享 URI 使用 Base64 JSON。引用其他出站或本地文件、执行外部插件、未支持的旧式协议，以及无法保持语义的 Hysteria 2 URI 证书钉扎和 ECH，都会使该订阅的 Sing-box 导出返回 `422`。Sing-box JSON 独立限制为 16 MiB 和 25,000 个代理出站。每个原始节点名的 JSON 编码最多 1 KiB，所有原始节点名合计最多 2 MiB。GitHub 托管 runner 使用校验过 SHA-256 的 Sing-box 1.14.4 检查实际 Worker 响应。 [Sing-box 1.14.4](https://github.com/SagerNet/sing-box/releases/tag/v1.14.4) · [Sing-box 出站](https://sing-box.sagernet.org/configuration/outbound/)

Hysteria 1 分享 URI 的 `peer` 映射到 TLS SNI，上传和下载速率必须达到客户端最小值。Hysteria 2 的 Gecko 包大小沿用客户端默认值与 2,048 字节上限。Hysteria 1 和 2 客户端加载配置时会逐项展开跳跃端口。Worker 在每个出站限制 65,535 项，每份配置限制 1,048,576 项。端口范围的首尾均计入，重复和重叠项分别计数。这是客户端内存保护限额。 [Hysteria 1 URI](https://v1.hysteria.network/docs/uri-scheme/) · [Sing-box 1.14.4 所用端口展开代码](https://github.com/SagerNet/sing-quic/blob/7e0a5869a5f4/hysteria/client.go#L111-L139) · [Hysteria 2 Gecko 与端口展开](https://github.com/SagerNet/sing-quic/blob/7e0a5869a5f4/hysteria2/client.go#L115-L140)

Clash 返回 `text/yaml`，保留旧版的节点选择、自动选择和匹配规则。节点名碰到内建名称、分组名称或其他节点时自动分配后缀，原有不冲突的名称保持原样。支持 Shadowsocks、VMess、VLESS、Trojan、Hysteria 1 和 2、TUIC v5、AnyTLS、SOCKS5 和 HTTP(S) 的可转换设置。支持经过校验的 Hysteria 2 内联 ECH，无法保持语义的 URI 证书钉扎、作用域 IPv6、未支持的协议或本地文件与其他出站依赖返回 `422`。Clash 配置最多 16 MiB 和 25,000 个代理，原始节点名上限与 Sing-box 相同，并使用相同的 Hysteria 跳跃端口计数上限。托管 CI 用校验过 SHA-256 的 Mihomo 1.19.33 读取实际 Worker 响应。 [Mihomo 1.19.33](https://github.com/MetaCubeX/mihomo/releases/tag/v1.19.33) · [Mihomo Hysteria 2](https://wiki.metacubex.one/en/config/proxies/hysteria2/)

原生 VMess 的 `auto` 在启用 TLS 时有两种含义。Mihomo 仍按客户端架构选择 AES-128-GCM 或 ChaCha20-Poly1305，Sing-box 则使用 `zero`。Worker 将原生 Sing-box 的 TLS `auto`（包括空字符串或省略 `security` 字段）转换成 Clash 的显式 `zero`。将 TLS `auto` 的原生 Clash 节点转为 Sing-box 会使整份导出返回 `422`，因为选定任何单一算法都会丢失按架构选择的行为。旧版 Python 仍会输出这类 Clash 节点的 Sing-box 配置，比较结果可能因此不同。 [Mihomo 1.19.33 出站](https://github.com/MetaCubeX/mihomo/blob/v1.19.33/adapter/outbound/vmess.go#L448-L458) · [Mihomo 自动选密](https://github.com/MetaCubeX/sing-vmess/blob/v0.2.5/protocol.go#L128-L133) · [Sing-box 1.14.4 出站](https://github.com/SagerNet/sing-box/blob/v1.14.4/protocol/vmess/outbound.go#L94-L101)

结构化 VMess 的 Clash H2 与 Sing-box HTTP 跨格式转换要求双方能保留所支持的 TLS H2 请求字段。支持仅 TCP、显式 AES-128-GCM 或 ChaCha20-Poly1305、AEAD Alter ID 0、常规 TLS、默认或单独 `h2` 的 ALPN，以及双方按原样发送的绝对路径和主机列表。Sing-box 输入需要显式限定 `network` 为 TCP，因为省略时同时启用 TCP 和 UDP。Clash 转 Sing-box 会写入 `Accept-Encoding: identity`。反向要求 Sing-box 使用有效的 `PUT` 和单一 `identity` 请求头设置。超出该范围时，目标格式返回 `422`，原生配置仍按各自格式的校验规则导出。托管 CI 使用两种固定版本客户端，在仅开放回环的网络环境中校验合成 TCP 往返。 [Mihomo H2 请求](https://github.com/MetaCubeX/mihomo/blob/v1.19.33/transport/vmess/h2.go#L28-L60) · [Sing-box HTTP 请求](https://github.com/SagerNet/sing-box/blob/v1.14.4/transport/v2rayhttp/client.go#L39-L95)

Surge 保留 `[Proxy]`、`[Proxy Group]` 和 `FINAL,Proxy`，支持 Shadowsocks、VMess、Trojan、Hysteria 2、TUIC v5、AnyTLS、SOCKS5 和 HTTP(S) 的可转换设置。Quantumult X 的三个别名返回相同的原生节点资源行，支持 Shadowsocks、VMess、VLESS、Trojan、AnyTLS、SOCKS5 和 HTTP(S)。两个格式都要求每个节点能完整转换。旧版 Surge 生成的 VLESS 声明会返回 `422`。Quantumult X 的已有 URI 先解析再转换。未支持的 URI 或不能等价保留的加密、混淆、证书和传输设置同样返回 `422`。名称和字段内有歧义的分隔符或换行也会拒绝，Surge 中支持厂商语法允许的带引号逗号值。每种输出最多 16 MiB、25,000 个节点和每行 64 KiB，Surge 的选择分组也受单行限制。托管 CI 对照厂商语法和旧版可无损案例，核对实际 Worker 响应的字节。Surge 的配置校验命令随 macOS 应用发布，Quantumult X 提供原生资源示例。两个客户端的实际导入未纳入该 CI。 [Surge 策略](https://manual.nssurge.com/policies/overview.html) · [Surge CLI](https://manual.nssurge.com/tools/cli.html) · [Quantumult X 原生节点示例](https://github.com/crossutility/Quantumult-X/blob/master/server-complete.snippet)

聚合能力链接通过 `GET` 或 `HEAD /agg/{code}/{format}` 使用同一套导出格式。有效聚合码继续通过 `/s/{code}` 返回同源相对重定向。全量链接按订阅 ID 读取所有者的活动已发布快照，再读取同一 Bot 和所有者的临时节点。筛选链接按记录顺序读取已选订阅，暂时移除回收中的订阅，恢复后可继续使用原 ID。订阅到期时间仍为上游元数据。

`0009` 只存聚合码的摘要。一次 D1 批处理固定成员、快照指针和临时节点。Worker 核对并固定 R2 清单后，复用同一组来源进行两遍导出。每个聚合最多 128 份订阅，快照与临时数据共用 64 MiB、100,000 个节点和 256 个 R2 块的预算。各格式的输出上限仍适用。旧链接导入、订阅拉取和生产域名分阶段接入。

普通短链在私聊通过 `短链 URL`、`short URL` 或 `/short URL` 签发，`/short` 显示帮助，`/short revoke <短码或本地短链>` 撤销自己的链接。每位用户最多有 128 条活动普通短链。目标限 2 KiB，拒绝带 URL 用户名或密码、控制字符、反斜杠、已知本地主机名和本地或受限 IP 字面量的地址。项目域名也禁止作为普通目标。Worker 仅检查 URL 和返回重定向，地址的 DNS 解析由客户端执行。 [URL 标准](https://url.spec.whatwg.org/) · [IANA IPv4 地址注册表](https://www.iana.org/assignments/iana-ipv4-special-registry) · [IANA IPv6 地址注册表](https://www.iana.org/assignments/iana-ipv6-special-registry)

`0019` 在受限 D1 链接行保存规范化目标和短码摘要。确定未送达的重试使用原短码，撤销清除目标并保留摘要。新普通短码和聚合短码使用不同末位，查找同时核对两个表。同一摘要若有两条归属记录，即使其中一条已撤销，普通和聚合路径都返回 `404`。已核对的 12 位旧普通短码可沿用相同路径，旧数据导入另行执行。

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
| 数字或列表按钮打开详情，浏览节点和流量，单条重命名、刷新、删除、格式链接、短链和节点文件。`/s` 按名称及原始 URL 搜索，`/d` 批量删除匹配项。`/renumber` 只返回当前订阅计数。 | 已有生命周期操作、元数据和快照读取。`0022` 在私聊详情中接入每页 15 条的节点浏览，只展示序号、协议和名称。翻页固定到原快照，返回详情可打开同一订阅的当前版本。`0024` 增加私聊 `/d 关键词或订阅链接`，最多预览 16 条匹配项，使用十分钟内一次性按钮确认。任一目标变更时整批停止，已回收订阅可在 30 天内恢复。`0030` 为私聊详情增加原始 URI 附件。详情、搜索、各格式链接及原始 URI 附件分别验收。展示编号由列表计算。原始 URL、节点及能力链接限定在私聊。 |
| 粘贴节点加入临时列表，`/temp` 查看原文，`/temp clear` 清空。 | 私聊核对导入、计数、原文、TXT 附件和清空。验收包含顺序、重复、整批拒绝、迟到清空和清空后的旧请求。 |
| 上传 `.txt`、`.log`、`.yaml`、`.yml`、`.json`，识别节点或订阅 URL，同名文件更新旧导入。 | 已接入私聊节点文档及同名上传替换。验收同一账号保留订阅 ID 和令牌、另一账号同名文件独立、失败保留旧快照。URL 列表和混合文档随提供方导入接入。 |
| 发送一个或多个 HTTP(S) URL 或 `名称\|URL`，重复 URL 刷新，按上游标题自动命名。单条刷新、详情或导出的按需刷新、更新所有的确认和进度、有效及失败报告、保留或回收失败项。 | 私有抓取入口、订阅元数据和快照发布为基础。先验收实际提供方出网、URL 导入、单条刷新和流量、到期、标题，再验收可恢复的批量刷新、报告和失败项回收。 |
| `/export` 动态全量聚合含自己的临时节点，`/o` 按名称和原始 URL 筛选并固定订阅顺序，所选聚合只包含订阅。 | 已接入全量和筛选聚合的 HTTP 读取、私聊 `/export` 及 `/o` 签发和撤销。验收 Unicode 匹配、稳定重显、冻结成员、配额回收、并发修改、撤销后的新读取、两账号归属和顺序。旧聚合码迁移单独接入。 |
| `/short` 显示帮助，`短链 URL`、`short URL` 及详情按钮签发短链。`/s/{code}` 按已保存目标跳转，可选外部服务包装同一受控本地链接。 | 私聊签发和撤销普通 HTTP(S) 短链，兼容聚合重定向。验收旧短码、归属、撤销、缓存与命名空间冲突。单订阅详情入口和可信外部服务另行接入。 |
| `/path` 和菜单维护路径对应，支持添加、删除和清空，受限文本入口接受 `关键词=备注`。 | HTTP 导出已应用所有者路径规则，临时节点保留原名。私聊 `/path` 已接入显式添加、删除、清空和分页。验收两账号隔离与迟到操作，菜单、独立自由文本和旧规则导入分别接入。 |
| `@Bot [关键词]` 搜索并发送订阅及临时节点，`/i` 切换默认、流量、到期和名称排序。`Share` 支持自定义内容或匹配订阅、指定接收人、份数和有效期；选中反馈用于更新原卡。 | 私密创建和领取已接入私聊 `/share`、`/start claim_<code>`。隔离工作流核对实际双账号回执、正文、过期、指定用户、并发与重复领取。`0020` 持久保存私聊 `/i` 排序。`0025` 增加默认关闭的私聊内联订阅搜索，仅处理能确认为当前用户与同一 Bot 私聊的 `sender`。临时节点、选择后的专用操作和群内分享卡片另行接入。Telegram 内联查询只提供聊天类型，无法核对指定群 ID。 [Telegram InlineQuery](https://core.telegram.org/bots/api#inlinequery) |
| `/g` 查 GitHub 仓库和公开代码，代码无结果时查询 grep.app，必要时提供 GitHub 网页搜索入口。 | `0027` 接入指定账号的私聊公开仓库搜索和固定 GitHub 网页代码搜索按钮。服务端代码搜索和 Grep 集成分别验收。 [GitHub 搜索 API](https://docs.github.com/en/rest/search/search) · [Grep 条款](https://grep.app/terms) |
| `/ai` 接受 API 地址和 Key，探测 OpenAI 兼容端点的状态和延迟。 | 按固定范围验证用户提供的地址，禁用重定向，保护 Key 和上游响应，另行接入和验收。 |
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
- 私聊 `/share [x份数] [id领取人ID] [s分钟] -- 正文` 接入 `0016` 的私密创建。份数默认 1、上限 100，时长默认 10 分钟、上限 10,080 分钟。指定领取人限当前隔离策略的两个账号。命令参数最多 4,096 个 UTF-16 单位，分隔符后的正文保留原空格和换行。此入口在私聊签发领取链接。群内通用分享卡片另行接入。
- 私聊内联搜索需要单独启用 Worker 的 `TELEGRAM_INLINE_SEARCH` 和 Telegram 的内联更新。每位获准用户再通过自己的 Bot 私聊发送 `/inline on` 授权 15 分钟，可用 `/inline off` 关闭。结果按 `/i` 的模式排列，只显示脱敏名称。每次最多返回 50 条。扫描预算为两秒，最多处理 512 条订阅，名称和来源共计最多 8 MiB。超出扫描预算时返回空结果。每位用户每分钟最多接纳 12 次查询，同一时刻只处理一个。Telegram 缓存时间为零。D1 只记录查询 ID 摘要、关联授权、排序版本和结果状态，保留约 25 小时用于去重。发送中断后请重新输入关键词。当前配置留在关闭状态。 [Telegram Inline Bots](https://core.telegram.org/bots/inline) · [Telegram answerInlineQuery](https://core.telegram.org/bots/api#answerinlinequery)
- 创建需单独的 `TELEGRAM_PRIVATE_SHARE_CREATION_KEY`，使用规范 Base64URL 编码的 32 字节密钥及稳定安装标识 `subs-bot-cf-dev-01`。它与聚合密钥分离。运行时每轮核对 `0016` 的精确迁移登记，再启用对应收件、发件和恢复分支。缺少密钥时普通回复继续独立发送。清理只需 schema 就绪，不依赖该密钥。受保护发布在任何迁移前核对当前密钥摘要，拒绝意外替换或删除。通用只读验收仅核对绑定元数据。
- 正文在 R2 写入前先登记回执与内容摘要，再以条件 PUT 写入私有对象。未确认正文持久化时 webhook 返回可重试错误。Cron 每轮恢复一份已有正文的候选。发送领取链接前，在同一 D1 更新中同时核对精确发件租约及创建模块返回的私聊、发布、到期和授权版本条件。链接只发给创建者，正文由独立私聊领取。发送结果不明时保留原回执和不确定状态。遗弃候选沿用有归属校验与宽限期的清理，并保留墓碑重新观察迟到对象。托管测试只使用合成更新和 Bot HTTP double，实际双账号验收仍从指定 IAB 执行。
- 验收须覆盖 Telegram 返回成功后写回失败，核对同一发件租约的状态与实际送达。 [Telegram `sendMessage`](https://core.telegram.org/bots/api#sendmessage)
- 重命名等待只接受同一用户在同一聊天与话题中回复已经确认送达的 Bot 提示。删除要求点击独立确认按钮。写入时复核所有者、授权、版本和操作票据，在同一 D1 事务完成变更和回复记录。回收站恢复保留订阅 ID、能力链接和已发布快照。
- 临时节点支持私聊粘贴节点链接或 Base64 列表。导入保留原始 URI、顺序及重复项。格式错误或暂不支持的节点按数量报告，并整批保留原状态。`0008` 将不超过 256 KiB 的有界数据批次、当前授权与回复意图放在同一 D1 事务。每个用户最多 5,000 个节点和 4 MiB。`/temp summary` 只查看个人计数。`/temp clear` 清除当前清空操作之前的条目，较新的导入不会被迟到的清空误删。
- 私聊 `/temp` 查看计数和受理时已有的原始 URI。短回复使用无链接预览的纯文本，较长回复用单个 UTF-8 `temporary-nodes.txt` 附件，顺序与重复项保持原样。回复前重新核对当前授权、清空边界和批次身份。确定未送达的限流重试仍读取原有批次，送达不明时保留回执以防自动重发。新回执只存状态、数量及权限和清空版本。 [Telegram `sendMessage`](https://core.telegram.org/bots/api#sendmessage) · [Telegram `sendDocument`](https://core.telegram.org/bots/api#senddocument)
- 已授权用户可以在私聊上传 TXT、LOG、YAML 或 JSON 文件导入命名订阅。纯文本支持原始节点和 Base64。每个文件上限 10 MiB 和 500 个节点，超过限制或含无法支持的节点时整批拒绝。订阅提供方 URL 的识别和刷新由独立出网阶段接入。
- `0011` 的私聊任务在 webhook 内持久入库，由 Cron 每轮最多领取一件。`0012` 在写入 R2 前记录候选快照，按所有者、文件名、较新消息、授权版本、租约和订阅版本复核发布。成功时在同一 D1 事务中更新快照指针并写入完成回执。同名导入保留现有 ID 和访问令牌。失败保留上一份有效快照，文件 ID 及文件名在任务终止时清除。只有已超出 Cron 最长执行窗口且活动表和回收站均未引用的候选可回收。

### 私聊 GitHub 搜索

现有隔离 Telegram 策略与 `0027` 的准确迁移登记共同启用 `/g 关键词`。命令向 GitHub 发送最多 120 个字符和 256 字节的关键词及受支持限定词。每个账号每 15 秒最多发起一次查找，每次固定向 GitHub 发出一条匿名仓库搜索请求，限时 5 秒，关闭重定向。按星标显示至多五个已验证的公开仓库。代码搜索按钮打开固定 GitHub 网页，由用户自己的 GitHub 会话访问。 [GitHub 仓库搜索](https://docs.github.com/en/rest/search/search#search-repositories) · [GitHub 网页代码搜索](https://docs.github.com/en/search-github/github-code-search/using-github-code-search)

查找期间只保留去重回执、短租约和授权版本。关键词只在当前调用中使用。查找结束后保存回复所需的仓库名称及星标，并在定时恢复中清理已送达、已失效或超过回复窗口的结果。中断的查找由 Cron 提供固定网页入口，已接收的其他命令可继续发送。发送前复核当前授权，明确限流后可重试，结果不明时保留回执。托管测试使用合成的 GitHub 和 Bot 响应。真人验收另用两名指定账号和测试 Bot 各执行一次公开关键词查询，并在已批准群确认同一命令不会产生查找。

### 订阅搜索、详情和格式链接

`/s 关键词` 按当前用户的活动订阅搜索名称和来源，沿用旧版的 Unicode 小写子串匹配。每页最多显示 8 项，搜索限于 512 条订阅及 8 MiB 元数据。群聊只显示用户自己的匹配名称和编号。普通私聊可通过搜索结果、`/list`、`/expire` 的详情按钮，或直接发送活动列表顺序编号查看详情。详情显示流量、到期、节点数量及最多 8 个已校验的节点名称。来源 URL、节点凭据和刷新错误原文不进入回复。

`0018` 只持久化查询结果中的订阅 ID 和顺序、操作范围及回执。按钮以 10 分钟单次票据绑定 Bot、用户、聊天、话题、原回复和发送尝试。Clash、Sing-box、Base64、Surge 和 QX 使用原有订阅 Token 的固定同源格式链接，发送前重新检查授权及活动快照版本。Base64 和 Sing-box 共用 HTTP 导出的预检，其他格式在现有 HTTP 导出路由验证兼容性。未发布的订阅显示当前状态，待后续刷新或文件导入发布后可重新查看。链接发出后仍遵循现有 HTTP 能力链接规则，移入回收站时返回 `404`。

#### 私聊批量回收验收

`worker-isolation-telegram-fixtures.yml` 的 `bulk-trash` 仅在受保护的 `main` 与指定隔离环境运行，和部署共用锁。工具核对活动 Worker 的精确版本及模块摘要、D1/R2 归属、Telegram 策略、聚合密钥摘要与 `0024` 迁移。验收期间保留同一活动版本，避免这两位账号并行执行其他命令。

1. 使用从未使用的 16 位小写字母或数字 `cohort` 执行 `seed`。工具确认两个指定账号没有其他活动订阅或未完成的相关任务，再为管理员建立 16 条、成员建立 1 条合成订阅。管理员的最后一条仅匹配来源 URL，其他条目匹配名称。所有订阅均未发布节点快照。
2. 两位账号分别在 IAB 私聊发送一次 `/d CFB-<cohort>`，确认管理员预览 16 条、成员只预览自己的 1 条。可在指定群用带 Bot 用户名的命令观察没有预览。管理员在十分钟内点击原预览的确认按钮，等待 16 条移入回收站的回复。成员不点击确认按钮。
3. 用成功的 `seed` 运行号作为 `source_run_id` 执行 `verify`。工作流核对实际发送的两个私聊预览、对应的对象集合，以及绑定管理员原消息与发送尝试的确认回复。D1 必须显示 16 条合成管理员订阅均已按同一确认进入回收站，成员行未变更。群聊未显示预览由 IAB 单独观察。
4. 等成员未使用的按钮自然到期，再用成功的 `verify` 运行号及其完整提交 SHA 执行 `retire`。确认字段填 `retire <cohort>`。工具要求发件已落定，在同一 D1 事务内复核并删除精确的合成订阅及其版本记录。Telegram 收件、发件和批量回收回执保留。工具不调用 Telegram API，也不创建 R2 对象。

如果操作中断，可用 `seed` 的成功运行号和完整 `source_revision` 执行相同的 `retire`。恢复仅接受合成行全部未变更，或管理员 16 条均有已送达的精确确认且成员未变更。未使用的按钮仍须先到期。部分回收、未知记录、发送未落定或身份不符会停止清理。后续已部署的 `main` 可以清理历史检查点，但须核对同一资源、策略和密钥，保留原发布固定值并另记清理发布。签名检查点仅保存合成数字标识、摘要和回执水位。恢复不计作真实验收完成。

### 私密创建的隔离验收

`worker-isolation-private-share-command-smoke.yml` 在受保护的 `main` 运行，与部署共用锁。`prepare` 只读记录 D1 基线、活动 Worker 部署和模块、资源归属、Telegram 配置与私密创建密钥摘要。选择新的 16 位小写十六进制 `cohort`，使用准备完成时固定的两个测试账号、Bot 和群。每条合成正文第一行是 `Private share acceptance <cohort>/<case> · 合成`，第二行是 `Second line.`，末尾没有换行。用一个 Telegram 消息发送完整命令和正文。

| 案例 | IAB 操作与预期 |
| --- | --- |
| `expired` | 管理员先私聊发送 `/share x1 s1 -- <正文>`。普通成员在回复显示的 UTC 到期秒之后发送领取载荷，看到过期提示。 |
| `targeted` | 管理员私聊发送 `/share x1 id<普通成员ID> s10 -- <正文>`。管理员先看到指定领取人拒绝，普通成员再领取两次，两次收到同样正文，D1 只有一条领取记录。 |
| `race` | 普通成员私聊发送 `/share x1 s10 -- <正文>`。两个账号在各自的 IAB 私聊中协调发送同一领取载荷。两次 Telegram 消息日期相差最多五秒，只有一方收到正文，另一方看到份数已领完。 |
| `group` | 管理员在指定群发送 `/share@<测试Bot> x1 s1 -- <正文>`，随后发送 `/help@<测试Bot>`。第一条不回复也不留回执，第二条收到正常帮助。 |

在 IAB 内核对 Bot 显示的 `t.me` 域名、用户名和 `claim_…` 载荷。只在指定私聊的输入框发送 `/start claim_…`，避免点击可能唤起 Telegram 客户端的链接。浏览器负责观察正文、失败原因和真实提交，托管测试另外覆盖重叠的 D1 领取事务。

`verify` 使用成功的 `prepare` 运行号。其 `observations` 接收 `codeHashes`（三个私聊案例的原码 SHA-256 摘要）、`raceWinner`（`admin` 或 `member`）、`groupShareMessageId` 与 `groupControlMessageId`。普通群的消息编号按账号分配。工作流保留管理员在 IAB 看到的两个编号，核对水位之后同一 Bot 和群仅有一条已发送的管理员帮助回执，并确认未保存群内合成正文。超级群使用共享的消息编号，继续逐条核对。 [Telegram 消息编号规则](https://core.telegram.org/api/updates)

工作流核对三个已发送创建回执、六个已发送领取回执、两条领取记录、三个私有 R2 对象的原始字节和归属元数据。默认要求准备阶段的活动部署完全相同。若当前已部署的 `main` 是原发布的后继，并且 Worker 模块摘要、兼容日期、隔离资源、Telegram 策略、密钥及必需迁移都相同，可提交 `confirm_verify=verify <cohort> on equivalent release` 重用原观察。流程重新读取历史 Worker 版本，并保留准备和验证两个版本标识。原码、正文、Telegram 账号 ID 和密钥留在各自的授权边界。

`retire` 使用成功的 `verify` 运行号。等到三个分享自然到期并经过预留清理宽限期后，再提交 `confirm_retire=retire <cohort>`。从后来已部署的 `main` 清理时，使用 `retire <cohort> on current release`，仍核对相同资源、策略、密钥摘要和迁移，检查点保留原发布版本。事务只清除已核验的合成创建记录、领取计数和分享记录，保留真实收件、发件和领取意图回执。确认 D1 不再引用对应对象后，逐个清理精确的私有 R2 键。中断后从同一验证检查点重试。未核验的案例保留原记录和对应正文，等待后续单独核对。

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

撤销按钮有效期为 10 分钟。收到回复后按上述顺序尽快完成验证。工具读取群聊控制回执和范围内的签发记录，群聊中未显示链接的观察在 IAB 完成。R2 写入使用发布锁串行执行，逐项比对对象归属、预期字节和写后读回。

票据过期或验证无法继续时，暂停本组操作。若已粘贴临时节点，先在 IAB 用管理员私聊执行 `/temp clear` 并等回复。以最近一轮成功的常规检查点执行 `prepare-abort`，核对已落定的真实回执、链接成员、四份原快照及可能存在的第五份。部署已变更时，额外提供原运行的完整 `source_revision`。再以成功的恢复检查点执行 `abort-retire`，确认字段填 `abort <cohort>`。恢复在同一个 D1 批次撤销核对过的链接并删除精确匹配的合成订阅，随后验证链接拒绝访问并回收已发布快照的固定 R2 对象。未完成发布的第五份可能仍有延迟写入，保留其已核对的 R2 前缀并单独报告。恢复保留真实 Telegram 回执、链接墓碑和原发布摘要，另记恢复时的发布，不计作实际 `/o` 验收完成。

### 刷新与出网验收

- 刷新任务保存订阅、发起人、期望版本、尝试次数和错误类别。租约带过期时间及递增凭据，过期消费者的写入由条件检查拒绝。队列消息重复投递时复用同一任务。重试按错误类别退避并遵守提供方限速，耗尽后进入死信或可审计的失败状态。用 Cron 补发已入库但未成功入队的任务。拉取或解析失败只记录错误状态，上一份有效快照继续服务。 [Queues 重试与死信](https://developers.cloudflare.com/queues/configuration/batching-retries/)
- 任意用户 URL 开放前，验证 HTTP(S) URL、允许端口和重定向策略。每一跳重新解析 A/AAAA，拒绝私有、环回、保留及混合公网和私网结果，并确保实际连接到通过检查的 IP，同时保持原 Host、TLS SNI 和证书校验。带凭据的请求禁止将凭据转发至新来源。延续现有解压后 10 MiB 上限，并对上传、重定向次数、总耗时、节点数和 YAML 深度或别名设置限额。
- 抓取组件使用项目专用 Cloudflare Container、固定 DNS 地址的 Python 传输及有界私有 RPC。Cron 只有在私有服务绑定、预期版本和镜像摘要都配置后，才会领取已有任务。RPC 在启动 Container 前核对版本和镜像。托管 CI 使用合成 RPC 验证已构建 Worker 的 D1、R2 与 HTTP 流程。服务绑定启用和真实提供方的 TLS 与兼容性单独验收。 [私有抓取组件](../worker/provider_fetch/README.md) · [Containers 出网](https://developers.cloudflare.com/containers/configuration/outbound-traffic/)
- 私聊单条导入要求显式开启 `TELEGRAM_PROVIDER_URL_IMPORT=1`，并确认已配置固定抓取绑定和迁移。仅两位隔离账号可提交一条独立 HTTP(S) 链接或 `名称|链接`。群聊、多行内容及回复改名沿用各自的处理路径。每次 Cron 最多领取一项 Telegram 提供方任务和一项普通提供方任务。等待抓取期间，同一私聊可以继续接收其他回复。固定结果只发回原私聊，并与已进入发送流程的回复串行。入队任务的发送期限为完成时间与任务过期时间中较早的一项再加 15 分钟，未入队的拒绝回复从收件起算。关闭入口只停止接收新 URL，固定抓取绑定和迁移就绪时，Cron 继续处理已入队的任务和回执。
- 单条刷新有独立的运行时开关 `TELEGRAM_PROVIDER_REFRESH=1`，当前受保护发布流程默认不配置。未来启用需单独核对固定抓取绑定及 `0028` 迁移，并为开关加入保护发布、版本回读和回滚核对。私聊远程订阅详情的“刷新订阅”按钮有效期为 10 分钟，仅原账号可以在已确认发送的原消息上使用一次。入队时核对出票角色、当前授权、来源摘要、订阅代次及生命周期。关闭新刷新入口后继续处理已有任务和回执。静态文件订阅继续显示原有详情，刷新失败保留当前快照和流量信息。批量刷新另行接入和验收。
- 解析拒绝、抓取失败或租约过期时保留上一份快照和流量信息。成功发布在同一个 D1 批次核对所有者、原始 URL、代次、生命周期和租约，再更新快照、有效流量与到期元数据，并完成任务。候选 R2 路径使用本次租约 UUID。确认 CAS 未提交时回收本次候选，结果不明时读回精确任务及包含摘要的快照指针，并保留不能确认的候选。后续清理需在写 R2 前持久记录候选并确认活动区、回收站和备份均未引用，现有任务记录丢失租约后不能凭 R2 前缀自动推定归属。
- 测试包括实际提供方的鉴权、重定向、编码、流量头、IPv4/IPv6、阻断行为与限速。输出只记录分类结果和耗时。覆盖 DNS 重绑定、跨来源重定向、压缩超限和异常 YAML，并核对失败不会改变旧快照。真实联调使用获准的测试订阅和会话。

## 部署、数据迁移和回滚

### 隔离环境发布

1. 在 GitHub 建立仅允许 `main` 的 `subs-bot-isolation` Environment。将核对过的资源标识保存为此环境的 Secret `SUBS_BOT_CF_ISOLATION_TARGET_JSON`，包含 `accountId`、`workerId`、`workerCreatedOn`、`d1Id`、`d1CreatedAt`、`r2CreatedOn` 和 `namespace`。把数据和 Worker 部署凭据分别保存在此环境的 `SUBS_BOT_CF_BOOTSTRAP_TOKEN`、`SUBS_BOT_CF_DEPLOY_TOKEN`。普通 PR CI 和构建产物不使用这些凭据。 [GitHub Environment 保护规则](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments)
2. 查找当前 `main` 的成功 `Worker CI` 运行。若该提交只改动旧 Python 服务，先手动对 `main` 运行 `Worker CI` 生成同一 SHA 的产物。以该运行 ID 启动 `gh workflow run worker-isolation-deploy.yml --ref main -f source_run_id=<run-id>`。
3. 发布流程重新核对运行、提交、ZIP 摘要、包内文件清单及独立摘要，验证已登记的资源身份。D1 只接管结构完全一致且已清理合成数据的 `0001` 基线，使用 `subs_bot_schema_migrations` 记录已核对的摘要。后续通过同一流程应用增量建表和建索引。涉及现有数据或表结构变更时单独审查迁移和恢复步骤。 [D1 迁移](https://developers.cloudflare.com/d1/reference/migrations/)
4. Worker 的候选版本通过内容与绑定回读后才启用。记录实际版本、部署及 `/health` 中的提交。遇到不明确的写入结果，先读取实际状态；Worker 回滚仅恢复此前验证的版本，D1 和 R2 状态独立处理。 [Cloudflare Worker 回滚](https://developers.cloudflare.com/workers/versions-and-deployments/rollbacks/)
5. 含 `0002_telegram.sql` 的隔离版本从同一 Environment 的 `SUBS_BOT_TELEGRAM_TEST_CONFIG` 注入加密配置。配置包含已核对的测试 Bot、两个账号、测试群和 Webhook 密钥。普通隔离发布在迁移和上传前核对已部署的完整配置摘要，首次绑定后变更或轮换须经过单独的受控发布。Worker 就绪后配置每分钟 Cron，用于恢复持久回复。测试 Bot 的 Webhook 首次设置前，核对 Bot 身份和现有 Webhook；仅在目标是该隔离地址时接收 `message` 更新并保留待处理更新。真实账号的消息验收在内置浏览器执行。 [Workers Cron](https://developers.cloudflare.com/workers/configuration/cron-triggers/) · [Telegram Webhook](https://core.telegram.org/bots/api#setwebhook)
6. 发布含 `0004_telegram_views.sql` 的版本前，先确认已发布并记录支持回执标记的回滚版本。激活新版并核对实际版本后，只为同一隔离测试 Bot 将 `allowed_updates` 扩为 `message` 与 `callback_query`。保持已核对的 URL、Webhook 密钥和连接上限，设置 `drop_pending_updates: false`，用 `getWebhookInfo` 核对结果。回滚视图时先恢复只接收 `message`，保留增量表和待处理更新。 [Telegram Webhook 配置](https://core.telegram.org/bots/api#setwebhook) · [Telegram Webhook 回读](https://core.telegram.org/bots/api#getwebhookinfo)
7. 真人视图验收前，用 `gh workflow run worker-isolation-telegram-fixtures.yml --ref main -f action=seed -f cohort=<16位小写字母数字>` 生成指定两名测试用户的合成订阅和回收站记录。流程校验实际 Worker、D1、Telegram 配置摘要和迁移，并只写隔离 D1。真人消息及按钮只在内置浏览器验证。结束后以同一个 `cohort` 和 `action=retire` 删除本组记录，核对输出计数。
8. 订阅操作验收使用同一工作流，增加 `-f purpose=lifecycle`。专用批次只允许匹配的两个账号及预定义合成来源，测试重命名使用原名后接 `-renamed`。退役流程核对归属、名称、版本、删除状态和未发布快照条件，核对不一致时整批保留。
9. 私密领取验收使用 `worker-isolation-telegram-claims.yml`，通过 `action`、`cohort` 和 `digests` 手动运行。生成四个随机合成分享码，仅将 `targeted`、`race`、`expired` 和 `document` 对应的 SHA-256 摘要提交给工作流。测试人员在指定 Telegram Web 私聊中使用原码。用相同摘要映射退役，核对合成分享、领取与私有 R2 对象均已清除，保留收件和发送回执。
10. 发布含 `0014` 的版本前，在同一受控 Environment 配置 `SUBS_BOT_TELEGRAM_AGGREGATE_KEY`。它是独立随机 32 字节的无填充 Base64URL 编码，注入 Worker 的加密绑定 `TELEGRAM_AGGREGATE_KEY`。发布与回读比较其摘要，重复发布保留原密钥。密钥轮换须单独审查，原始密钥及能力链接始终留在受控凭据和私聊范围内。

域级 Worker 路由核对使用单独的只读凭据。发布任务内使用项目专用凭据核对 Worker 的 Custom Domain、预览、日志、Cron 及实际数据绑定。 [Cloudflare Worker 路由 API](https://developers.cloudflare.com/api/resources/workers/subresources/routes/)

#### 隔离私聊内联搜索

先用当前 `main` 的已核对 Worker CI 产物正常发布，确认活动版本没有 `TELEGRAM_INLINE_SEARCH` 绑定且 D1 已记录 `0025`。发布参数 `inline_search` 默认为 `preserve`，沿用活动版本的设置。首次部署和仍关闭的版本均省略该绑定。启用时只接受 Worker 的版本级 `plain_text` 绑定，值为 `1`。

启用前由用户单独为已核对的隔离测试 Bot 确认 BotFather 的 `/setinline`。无需开启所选内联结果反馈。在受保护的 `main` 运行 `worker-isolation-telegram-inline-webhook.yml`，先用 `inspect` 核对 Bot 身份、内联模式、隔离 Worker、加密配置摘要与现有 Webhook。现有接收范围须为 `message`、`callback_query`，或已包含 `inline_query` 的精确集合。连接上限须为 4，且使用默认 TLS 验证。

只有原 DNS 设置记录仍适用时，使用 `append` 并填写 `append inline_query for @test_cfsubs_bot using verified DNS webhook`。工具将原已核对的 Worker 版本中的配置摘要与当前活动配置逐字节摘要匹配，然后在原集合中追加 `inline_query`，保持相同 URL、密钥和连接上限，并传入 `drop_pending_updates: false`。Webhook 回读的 IP 只是当前投递地址，原设置记录证明 DNS 模式。原配置来源无法核实时使用 `inspect`。已订阅时只读核对。写入响应不确定时只做有界回读，以同一作用域和精确接收集合确认结果。工作流仅输出状态、计数和提交。 [Telegram 内联设置](https://core.telegram.org/bots/inline) · [Webhook 配置](https://core.telegram.org/bots/api#setwebhook) · [Webhook 回读](https://core.telegram.org/bots/api#getwebhookinfo)

确认上述范围后，在受保护的同一发布工作流指定 `inline_search=enable` 和 `inline_search_confirmation=enable inline search for subs-bot-cf-dev-01`。使用当前活动关闭版本对应的同一 `main` 提交和 Worker CI 产物。发布保留已核对的 Telegram 配置、数据绑定、密钥和提供方配置，且在启用前确认该 Bot 没有仍有效的内联同意。记录发布输出中的活动部署、版本及 `inlineSearchEnabled`，并核对完整模块和绑定回读。`/health` 只用于核对提交。

实际验收在内置浏览器中使用两名获准账号与同一测试 Bot 的私聊。各自执行 `/inline on` 后，使用同一合成查询验证只显示自己的订阅名称。在指定测试群查看同一查询无结果。测试结束在各自私聊执行 `/inline off`。紧急停止输入时由用户先将 Webhook 接收范围恢复到已核对的原集合，保留待处理更新。随后可用 `inline_search=disable` 和 `inline_search_confirmation=disable inline search for subs-bot-cf-dev-01` 发布关闭版本。以活动版本回读确认关闭。回滚保留增量 D1 表和既有记录。重新启用前确认旧同意均已关闭或自然到期。 [Telegram 私聊内联类型](https://core.telegram.org/constructor/inlineQueryPeerTypeSameBotPM) · [Worker 回滚](https://developers.cloudflare.com/workers/versions-and-deployments/rollbacks/)

#### 隔离提供方绑定

默认发布不配置提供方绑定。首次启用通常为同一个 `main` 提交构建应用和提供方。完成私有提供方的隔离激活和停机证明，并单独核对域级路由未指向提供方。将下列精确结构保存到 `subs-bot-isolation` Environment 的受保护配置 `SUBS_BOT_CF_PROVIDER_BINDING_JSON`，并在 GitHub 证明产物到期前运行首次绑定。资源标识和完整配置只存于受控配置。

- `version` 为整数 `2`。
- `proof` 包含 `revision`、`runId`、`runAttempt`、`artifactId`、`archiveSha256`。`revision` 是生成证明的受保护工作流提交，也是首次绑定的应用提交。运行和产物编号为十进制字符串，摘要为原始 ZIP 字节的 SHA-256。
- `proofDocument` 为该 ZIP 中 `provider-binding-proof.json` 的完整 JSON 对象。保留证明的所有字段和值，包括证明文档自己的 `version`。同提交证明为 `1`，受控历史提供方延续证明为 `2`。
- `worker` 包含 `workerId`、`workerCreatedOn`。
- `activation` 包含 `versionId`、`deploymentId`、`namespaceId`。

首次绑定在 D1 迁移前核对 GitHub 受保护激活运行、精确 ZIP 摘要、规范化证明内容以及应用与提供方的同账户归属。之后保留原始配置。应用当前活动版本的不可变注解和绑定记录必须与配置的证明摘要及资源身份完全一致。满足此条件时，后续应用发布可以使用新的 `main` 提交，原 GitHub 产物过期或不可用时仍可继续。每次发布仍回读提供方的活动版本、模块、镜像、SQLite 命名空间和私有设置。应用绑定目标为 `subs-bot-provider-fetch-dev-01` 的 `ProviderFetch` 入口，并向该入口校验所需的提供方修订和镜像摘要。

历史延续仅接受已固定的 `c0a73ce` 提供方版本。证明的 `providerBuild.revision` 保留该提供方提交，`activation.revision` 必须等于已核对的证明工作流和应用产物提交。首次绑定要求当前未绑定应用仍运行已核对的 `c0a73ce` 版本，并独立核对该历史提交是当前 `main` 的祖先。绑定后的 RPC 继续校验原提供方提交和 OCI 镜像摘要。

写入应用版本后回读绑定，激活后再次核对提供方。校验失败时仅按既有守卫恢复先前的应用版本。绑定配置变化、提供方漂移或尝试移除绑定会阻止常规发布，轮换须单独审查。回滚至未绑定版本后，重新绑定仍须取得符合首次绑定要求的 GitHub 证明。 [服务绑定](https://developers.cloudflare.com/workers/runtime-apis/bindings/service-bindings/rpc/#named-entrypoints) · [提供方激活与证明](../worker/provider_fetch/README.md)

#### 隔离私聊远程订阅导入

提供方绑定就绪后，先以默认发布参数发布当前 `main` 的已核对产物，确认活动版本已绑定同一个提供方、保留隔离 Telegram 配置和 Cron，并且没有 `TELEGRAM_PROVIDER_URL_IMPORT` 绑定。D1 必须已应用确切的 `0021`、`0023` 迁移。启用时继续使用同一提交和同一产物，在受保护的 `worker-isolation-deploy.yml` 指定 `provider_url_import=enable` 及 `provider_url_import_confirmation=enable provider URL import for subs-bot-cf-dev-01`。以发布结果中的 `providerUrlImportEnabled` 和活动版本绑定回读确认状态。

两名获准测试者分别在内置浏览器中通过隔离 Bot 私聊提交单条 HTTP(S) 订阅链接，可使用 `名称 | URL` 指定名称。群组、未获准的账号和多行消息均不会创建远程导入任务。发布参数默认为 `preserve`。停止接收新链接时使用 `provider_url_import=disable` 及 `provider_url_import_confirmation=disable provider URL import for subs-bot-cf-dev-01`。关闭后 Cron 继续处理已接受的任务和回执。启用校验失败时，已有回滚守卫可恢复使用同一应用产物的关闭版本。 [Worker 回滚](https://developers.cloudflare.com/workers/versions-and-deployments/rollbacks/)

#### 隔离私聊远程订阅刷新

先保留默认参数发布当前 `main` 的已核对产物，使已绑定提供方的隔离 Worker 在刷新关闭时运行包含刷新队列恢复的版本。D1 必须已应用确切的 `0018`、`0021`、`0023` 和 `0028` 迁移。使用同一产物，在受保护的 `worker-isolation-deploy.yml` 指定 `provider_refresh=enable` 和 `provider_refresh_confirmation=enable provider refresh for subs-bot-cf-dev-01`。通过发布结果 `providerRefreshEnabled` 和活动版本的 `TELEGRAM_PROVIDER_REFRESH=1` 绑定核对。

刷新入口独立于 URL 导入。关闭入口时指定 `provider_refresh=disable` 和 `provider_refresh_confirmation=disable provider refresh for subs-bot-cf-dev-01`。Cron 继续处理已接受的任务和回执，并清理过期的刷新按钮。已发出的按钮会按原期限过期，期间重新启用时仍受所有权和订阅版本校验约束。

### 数据与切换

隔离容量检查使用当前 `main` 的已部署版本，手动运行 `gh workflow run worker-isolation-capacity.yml --ref main`。托管 runner 生成合成快照，依次验证恰好达到 64 MiB NDJSON 和 16 MiB 分享原文的有效输出、分享原文超 1 字节的拒绝、快照清单超 1 字节的拒绝。正向测试流式核对 Base64 长度和摘要，覆盖串行、并发 2 和 4、慢读及中途取消。发布和容量检查使用同一并发组，测试结束先撤销 D1 能力，再清理对应的私有 R2 对象。清理失败时，工作流保留不含凭据或原始能力令牌的恢复清单。

上传结果未确认时，在产物过期前私下保留原运行的恢复清单。仅使用原清单和对应的隔离资源继续核对清理。待确认对象仍读不到时保留记录，直到核实其内容并确认删除。重新运行容量检查会使用新的合成数据。

运行 `gh workflow run worker-isolation-capacity.yml --ref main -f profile=structured-smoke` 可单独检查混合 Base64 导出。该模式在同一个隔离环境暂存两份小快照，用旧版 Python 序列化器的结果校验混合导出的长度和摘要，并检查不支持的结构化节点返回固定的 422 响应。两份快照都检查 GET 和 HEAD，前后各检查一次运行版本。该模式的恢复清单对应 `capacity_resources.py cleanup` 的 `--profile structured-smoke` 参数。

同一工作流的 `profile=singbox-smoke` 针对 `/sing-box` 检查两份专用快照。成功响应必须声明精确字节数，规范化 JSON 摘要与 Python 对照一致。包含外部出站依赖的快照须返回固定的 422。该模式使用同名清理参数。

`profile=clash-smoke` 检查旧能力路径和 `/clash` 两种入口。两者的 GET 字节必须一致，HEAD 均为空。探针对照固定代理、分组、规则和凭据，验证不支持的依赖返回 422。它使用同名清理参数。

`profile=text-export-smoke` 暂存四份合成快照，检查 `/surge`、`/qx`、`/quantumult` 和 `/quantumultx`。成功的 GET 必须声明准确长度，原始 UTF-8 响应的摘要须与固定样本相同。HEAD 均为空，不兼容的协议组合返回固定的 `422`。探针共发送 18 次请求，包括前后两次版本检查。它使用同名清理参数。原生客户端导入和代理连接另行验证。

`profile=aggregate-smoke` 还验证路径规则。探针为专用合成所有者暂存规则，核对单份、全量、指定顺序聚合以及另一所有者的 Sing-box GET 和 HEAD。配置必须保留连接参数并按预期应用 Unicode 折叠、最长关键词和同长规则顺序。临时节点保留原名，聚合 Base64 原始输出字节保持一致。清理事务先核对并移除合成聚合码、规则和临时数据，再由原流程撤销合成订阅并清理 R2。工作流只报告状态、字节数和摘要。

隔离文档验收使用 `worker-isolation-telegram-documents.yml`。选择未使用的 16 位小写十六进制 `cohort` 并先运行 `prepare`。两名获准测试者分别在浏览器中私聊同一个隔离 Bot，上传名为 `tgdoc-<cohort>.txt` 的纯文本文件。每行以 `ss://YWVzLTI1Ni1nY206Zml4dHVyZQ@203.0.113.10:8388#tgdoc-<cohort>-` 开头，成员首版以 `member-first` 结尾，管理员首版以 `admin-first` 结尾。填写成功的 `prepare` 运行 ID 执行 `capture-created`，确认两份首版都已核对后再继续。

成员用相同文件名上传两行替换内容，分别以 `member-second-1` 和 `member-second-2` 结尾，再上传一个同名、只有普通文本的无效文件。以 `capture-created` 运行 ID 执行 `verify-replaced`。该步骤核对成员的稳定订阅 ID、能力令牌摘要和新版本、管理员的原版本、合成导出的 GET 和 HEAD，以及成功回执。能从浏览器确认无效文件的准确消息 ID 时，可填入 `negative_message_id` 核对对应终态，否则保留浏览器观察和未发生额外发布的证据。

关闭本组上传后选择 `retire`，提供成功的 `verify-replaced` 运行 ID，并在确认字段填写 `retire <cohort>`。若在替换前结束，也可使用 `capture-created` 的检查点。清理先在 D1 中核对并撤销本组两个订阅指针，再删除并核对检查点记录的私有 R2 对象。实际 Telegram 的终态回执继续保留，以防重投重新创建订阅。检查点只包含本组合成对象标识、计数和摘要。验收工作流通过 Cloudflare 核对状态，实际上传和可见回复在浏览器中确认。

同一工作流的 `profile=node-pages` 使用独立的合成文件名 `tgdoc-nodes-<cohort>.txt`。先执行 `prepare`，然后用下面的配方在新的私有临时目录中生成两份同名文件。将示例 `COHORT` 换成这次 `prepare` 的值。配方只写入使用保留测试地址的合成文本。

```sh
COHORT=0123456789abcdef python3 - <<'PY'
import os
from pathlib import Path
import re
from tempfile import mkdtemp

cohort = os.environ["COHORT"]
if re.fullmatch(r"[0-9a-f]{16}", cohort) is None:
    raise SystemExit("Expected a 16-character lowercase hexadecimal cohort")
root = Path(mkdtemp(prefix="subs-bot-node-pages-"))
name = "tgdoc-nodes-" + cohort
prefix = "ss://YWVzLTI1Ni1nY206Zml4dHVyZQ@203.0.113.10:8388#" + name
for role, count in (("admin", 32), ("member", 2)):
    folder = root / role
    folder.mkdir(mode=0o700)
    content = "".join(f"{prefix}-{role}-{index:02d}\n" for index in range(1, count + 1))
    fd = os.open(folder / (name + ".txt"), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as file:
        file.write(content.encode("ascii"))
print(root)
PY
```

两名获准测试者只在指定内置浏览器的隔离 Bot 私聊中上传各自目录中的文件。用文件名搜索各自的订阅，打开详情和节点浏览。管理员核对按原顺序显示的 15、15、2 个节点以及上一页和下一页按钮。成员核对自己的一页两个节点。随后以 `prepare` 运行 ID 执行 `capture-created`，由工作流核对同一固定版本下两份快照的有序节点、协议和 Base64 GET、HEAD。停止浏览后，以 `capture-created` 运行 ID 和 `retire <cohort>` 执行 `retire`。退役要求相关详情与节点回复已结束，且只撤销已核对的两个订阅和四个 R2 对象。文档、详情和节点浏览回执保留。该模式的流程止于这三步。

应用 `0030` 后，已有快照的私聊订阅详情可一次性导出 `Base64.txt`。文件沿用旧版命名，内容为按节点顺序排列的原始 URI，采用 UTF-8、LF 分隔且末尾无换行。每份文件限 5,000 个节点及 4 MiB，快照清单声明的 NDJSON 总量限 16 MiB，R2 内容预检与文件组装的时间预算为 5 秒。点击时记录快照和路径规则摘要，发送前核对原消息、授权、快照、生命周期及路径规则。Telegram 明确要求限速重试时会重新核对；发送结果不明时保留回执以避免重复发送。

暂时无法确认附件表时，普通命令和订阅详情仍可用，详情暂停签发附件按钮。若同一私聊已开始发送附件，后续回复会等该租约结束。

容量检查的客户端耗时和吞吐来自这组样本。CPU、内存和平台子请求数量通过隔离 Worker 的聚合指标另行核对。旧 SQLite 的正文体积与转换后的 NDJSON 和分享原文分别测量。真实备份的分布、超限项及可恢复性需要通过获准的数据演练验证。 [Workers 限制](https://developers.cloudflare.com/workers/platform/limits/) · [Workers 指标](https://developers.cloudflare.com/analytics/graphql-api/tutorials/querying-workers-metrics/)

旧库容量盘点在获准的托管环境运行 `python3 -B worker/tools/legacy_inventory.py <封存备份>`。输入须是单独完成、关闭、使用 UTF-8 和 DELETE 日志模式的 SQLite 备份。备份准备在原库之外进行，盘点本身以只读事务运行。报告只包含活动订阅与回收站的聚合计数、原始字节、紧凑 UTF-8 NDJSON 字节、块数、大小限制和旧转换器分享原文估算。无法读取或解析的记录有独立计数。退出码 `0` 表示报告完整，仍需检查超限和无效项。退出码 `2` 表示无法核对备份。容量报告不判定归属映射、旧链接兼容、分享权限或实际 Worker 性能。 [SQLite 增量读取](https://sqlite.org/c3ref/blob_open.html) · [SQLite URI](https://sqlite.org/uri.html)

### 旧授权覆盖盘点

普通 Worker CI 只运行合成夹具。真实备份盘点须在单独获准的受保护托管运行中，使用核对过的源码提交和仅供当前账号访问的临时目录。将已经关闭、无 SQLite 伴随文件的 UTF-8、DELETE 日志模式备份放入私有目录，从受信备份交接记录取得独立的 SHA-256。备份须为当前账号拥有的普通文件，使用 `0600` 或 `0400` 权限，最大 2 GiB。备份和输出的直接上级均须私有，输出目录须尚未存在。路径各级由当前账号或 root 所有，允许带 sticky 位的共享临时目录。使用无符号链接的实体路径，并在关闭命令跟踪后执行 `python3 -B worker/tools/legacy_authorization_inventory.py BACKUP OUTPUT EXPECTED_SOURCE_SHA256`。程序在不可变只读事务前后核对路径标识、备份文件状态及 SHA-256。 [SQLite URI](https://sqlite.org/uri.html)

私有 `auth-overrides.ndjson` 按数值用户 ID 升序保存 `userId`、`allowed`、`createdAt` 和 `updatedAt`。`userId` 使用正有符号 64 位整数的十进制字符串，`allowed` 保留整数 `0` 或 `1`，时间保留有序的正 Unix 秒整数，且不超过 `2^53−1`。最多 20,000 行。缺表与空表分别记录。`manifest.json` 绑定源备份摘要、行数、允许与拒绝的计数、文件长度和文件摘要，`manifest.sha256` 最后写入。只有退出码 `0` 且三个文件的清单闭包和摘要均匹配时才接收盘点包。退出码 `2` 表示无法确认。标准输出仅显示固定完成消息。真实备份和盘点包只在批准的私有交接渠道流转，禁止进入 PR、日志、普通 Actions 产物或缓存。

旧表只保存当前覆盖及时间。实际授权还依赖原管理员配置、允许列表和公开模式，须另行核对。此盘点不写入 Worker、D1 或 Telegram 回执。现有候选仍会拒绝未处理的非空授权覆盖。

### 普通短链双账号验收

受保护的 `worker-isolation-telegram-short-links-smoke.yml` 对同一活动版本执行 `prepare`、`issued` 和 `retired`。使用同一个 `cohort` 和 Worker CI 运行 ID。后两步引用前一步的成功运行。两名获准用户只在指定内置浏览器私聊分别签发 `https://example.com/subs-bot-normal-short/<cohort>/admin` 和 `https://example.org/subs-bot-normal-short/<cohort>/member`。管理员先尝试撤销普通用户的测试短码，随后各自撤销自己的短链。提交的浏览器证据只包含三项摘要。

验收任务只读取已固定的资源和回执，并对隔离 Worker 的 GET 和 HEAD 检查状态、重定向目标和私有缓存响应头。探针在项目域名收到响应后结束。撤销后保留两条墓碑，原链接返回 `404`。外部 URL 的连接由使用者的客户端处理。

### 旧单订阅短链

`0029` 为旧版 12 位短码提供独立的兼容表。记录保存短码摘要、Bot、所有者、订阅 ID、原订阅令牌摘要、格式和时间。兼容表存在时，其中的摘要始终占用短码，和普通或聚合短码冲突的访问一律返回 `404`。 [D1 数据库批处理](https://developers.cloudflare.com/d1/worker-api/d1-database/#batch)

首次启用前，以默认参数发布并回读同一提交和 Worker 产物的关闭版本。隔离发布工作流 `worker-isolation-deploy.yml` 的 `legacy_subscription_shorts` 默认为 `preserve`，初始不配置 `LEGACY_SUBSCRIPTION_SHORTS`。启用需指定 `legacy_subscription_shorts=enable` 和 `legacy_subscription_shorts_confirmation=enable legacy subscription shorts for subs-bot-cf-dev-01`。发布核对 `0029` 迁移、兼容表和主键索引，并回读 `legacySubscriptionShortsEnabled`。关闭使用 `disable` 和 `disable legacy subscription shorts for subs-bot-cf-dev-01`。关闭公开跳转时继续保留摘要占用和同一 Bot 下的所有者撤销。

启用后，`/s/{code}` 只会跳到当前站点上仍由原所有者持有、令牌摘要一致的订阅。支持原格式按钮及现有 Base64、Sing-box、QX 别名，也保留省略格式的形式。目标移入回收站时返回 `404`，恢复同一订阅与令牌后可再次跳转。私聊 `/short revoke 短码` 可在公开跳转关闭时撤销自己的记录。撤销清除目标字段并保留摘要占用。旧库转换、真实旧域名和外部短链包装另行验收。

### 隔离合成旧订阅候选应用

在受保护的 `main` 运行 `worker-isolation-legacy-candidate.yml`。所有步骤使用同一组全长 32 位小写十六进制 `cohort`、同一次成功的 Worker CI `source_run_id` 和同一已核对的隔离 Worker。开始前确认本轮可在产物保留期内完成，并保持 `main` 和隔离部署稳定。此流程从 CI 的固定合成候选包恢复，目标 D1 和 R2 的名称包含完整 `cohort`。只在源私有 R2 写入本组操作记录。

默认的 `synthetic-legacy` 沿用版本 1 合成包。路径规则演练显式选择 `synthetic-legacy-path`，全程保持同一选项。该选项使用单独的版本 2 产物、目标资源名称及操作记录前缀。固定样例核对映射归属、精确规则文字及编号顺序，并保留已删除规则的编号上界。最终读回输出规则数量、编号上界和数据摘要。候选保持未绑定状态。

选择 `synthetic-legacy-empty` 演练版本 3。它使用独立的产物、D1、R2 和操作记录前缀。预检从固定合成样例重建源 SQLite 与转换包并核对摘要，再验证两个活动订阅、两个回收站订阅、路径规则、原始令牌对应的两个空导出标记、0026 迁移、编号序列及四个 R2 对象。构建与预检须使用能产生同一 SQLite 文件的托管工具链，摘要不符时停止。恢复读回包含标记数量与表摘要。目标保持未绑定，空导出 HTTP 行为另行验收。

选择 `synthetic-legacy-private-shares` 可原生恢复 `legacy-private-shares-v1` 的固定合成候选。Worker CI 只打包预置样例。预检在取得 Cloudflare 凭据前从固定旧 SQLite 样例重新构建，逐文件比对 SQL、清单、封印与正文。按下方相同步骤在本组专用 D1 和私有 R2 恢复，目标保持未绑定。最终读回应为三个分享、三条历史领取、分享编号上界 3 和三个正文对象，含指定领取人、已到期记录及恰在到期秒的领取。旧内联标识仅计数。核对完整结构、逐表摘要、对象字节和元数据，检查点只上传计数及摘要。旧 Bot 链接和内联卡片连续性另行验收。

选择 `synthetic-legacy-typed-shorts` 演练版本 4。预检先重建同一份固定 SQLite、订阅转换包和短链盘点，再核对短链、0029 迁移和 SQL 重放。该模式使用独立的候选 D1、私有 R2 和操作记录前缀。预期恢复四条单订阅短链，活动和回收站各两条，并保留四条路径规则、两个空导出标记和四个快照对象。最终证据包含短链表数量和摘要。目标保持未绑定，旧链接 HTTP 行为另行验收。

1. 依次运行 `verify`、`prepare`、`create-restore-db`、`create-restore-bucket`，每步核对结果后再继续。创建响应不明时先运行只读 `verify`，根据创建意图、时间和实际资源身份独立确认归属，再用 `pin-resource` 提交 `resource` 和 `identity_sha256`。无法确认归属时保留该资源，停止本组后续写入。
2. 运行 `restore-objects` 核对专用私有 R2 的对象闭包，再运行 `start-import` 向已核对且仍为空的专用 D1 导入。若已有确认的轮询书签，可用同一 `start-import` 继续轮询。响应不明时保留目标和私有操作记录，通过 `verify-restore` 核对完整结果。导入请求未确认、上传链接或产物已失效，或固定版本已变更时，禁止重发首次导入、重置或删除原目标。保留现场核查，后续演练使用新的 `cohort` 和专用资源。 [D1 原生导入](https://developers.cloudflare.com/api/resources/d1/subresources/database/methods/import/)
3. 用 `verify-restore` 验证完整 `PRAGMA quick_check`、外键、结构、迁移记录、编号序列、逐表摘要和 R2 对象。检查失败即保留目标和证据。此结果覆盖合成候选恢复，旧链接、真实数据和 HTTP 导出分别验收。 [D1 完整性检查](https://developers.cloudflare.com/d1/sql-api/sql-statements/#pragma-quick_check)

### 隔离环境原生备份与恢复演练

`Rehearse isolated native D1 and R2 restore` 只在受保护的 `main` 环境运行。输入同一组随机 32 位小写十六进制 `cohort` 和当前提交成功的 Worker CI 运行 ID。逐项完成后再开始下一项：

1. `verify` 只读核对当前 Worker、D1、R2 与候选名称。`prepare` 在源私有 R2 的保留前缀建立追加式操作记录。依次运行 `create-backup-bucket`、`create-restore-db`、`create-restore-bucket`，各自只发起一次创建，并核对账号、名称、创建时间及适用的资源 ID。已有同名资源不会被采用。创建未确认时先只读核对；只有独立证据能确认该候选确属该次创建，才以 `pin-resource` 提供资源类别及候选身份摘要继续。
2. 先结束隔离验收并回收测试能力，待队列、回复、临时交互和待清理对象安定后，安排安静窗口并暂停人工命令与部署，再运行 `capture`。如需验证私密分享的 R2 归属元数据，可保留已验证且自然到期的合成分享及正文，封存后再清理源夹具。Cloudflare 原生导出期间源 D1 **暂时不能查询**；原有 Cron 保留，触发可能暂时失败。只用已记录书签的 `poll-export` 继续查询导出状态，再用 `capture` 保存导出。首次请求响应丢失且没有确认书签时，先等 Cloudflare 自动取消并核对源查询恢复；不要重发首次请求。导出包由原生 SQL、SQL 指向的完整 R2 内容及清单组成。 [D1 原生导出](https://developers.cloudflare.com/api/resources/d1/subresources/database/methods/export/)
3. `restore-objects` 在未绑定应用的专用 R2 重建引用内容，`start-import` 再向仍为空的专用 D1 导入已核对的同一份 SQL。已上传文件可能使 D1 `init` 直接开始导入；导入状态不明时，只用确认的书签继续轮询，或核对目标完整摘要。不要重发 `init`、`ingest` 或清空目标。`verify-restore` 核对完整 schema、迁移记录、序列、外键、逐表内容摘要及 R2 引用和字节。源 D1 永不导入或原地恢复，目标不绑定 Worker，也不会处理 Telegram 更新。 [D1 原生导入](https://developers.cloudflare.com/api/resources/d1/subresources/database/methods/import/)

受保护工作流与隔离部署使用同一并发组。仅此流程可写该演练前缀；每次追加核对上一条记录及本次写入，不依赖管理 REST API 未承诺的条件写入。不要同时从 Dashboard 或其他工具修改相关资源。遇到分叉、未确认写入、源版本变更或目标数据不匹配时保留记录和专用资源，不执行覆盖、删除或重置。SQL、源/目标私有身份、签名 URL、令牌、内容与对象键只留在私有 R2 或 runner 临时目录；Actions 证据只上传摘要和计数。

此演练限定 32 MiB SQL、20,000 行及最多 512 个引用对象（合计 256 MiB）。清单保存 D1 指向的应用对象、标准 HTTP 元数据及经发布回执核对的私密分享 `purpose` 和 `receipt`。恢复使用现有隔离数据 Token 派生的 R2 S3 凭据，向已核对的目标对象发起条件写入，并回读字节和元数据。遇到未知元数据或 SSE-C 会停止。桶的无引用对象和 Worker 密钥不在范围内。托管合成测试、Cloudflare 原生恢复、旧 SQLite 归属转换和生产切换分别验收。 [R2 S3 条件写入](https://developers.cloudflare.com/r2/api/s3/api/) · [R2 Token 凭据](https://developers.cloudflare.com/r2/api/tokens/)

### 旧订阅候选恢复包

在获准的托管 runner 上，将完整封存的旧订阅转换包与核对过来源及摘要的 Worker 产物交给 `worker/tools/legacy_restore_package.py CONVERTER_DIR WORKER_ARTIFACT_DIR OUTPUT_DIR CONVERTER_MANIFEST_SHA WORKER_MANIFEST_SHA REVISION APPLIED_AT`。输入目录须仅供当前账号访问，输出目录须尚未存在。时间参数为候选迁移记录使用的 Unix 秒。程序使用完整增量结构构建独立候选数据库，并重新执行生成的 SQL，核对结构、外键、数据指纹、活动和回收站归属、编号序列及 R2 引用。

候选包含原生导入所用的 `restore.sql`、逐行归属记录、精确对象和最后写入的 `manifest.sha256`。保留原始能力令牌和来源，目录及文件按私有数据管理。路径规则和历史编号都为空时沿用版本 1。版本 2 另将旧 `path_maps` 归入 `path_rules`，保留原编号、顺序、关键字、备注以及已删除规则占用过的编号上界。旧群归属使用已核准的映射。归并到同一用户的不同旧归属，其关键字若在去除首尾空白和折叠大小写后重合，则阻止封存。该检查使用与 Worker 相同的 Unicode 14 规则，托管转换使用 CPython 3.11。无效文本和每位用户超过 64 条也会阻止封存。真实备份仍需盘点其他数据域，未处理的数据域有内容时同样会阻止封存。实际云端导入、未发布订阅的 HTTP 行为、旧链接连续性和各格式兼容性分别验收。

增量迁移 `0026` 为旧空订阅提供单独的 HTTP 导出标记。`/sub` 仅在活动记录的编号、归属及原始令牌摘要均匹配，且仍无已发布快照时返回相应格式的空配置。回收期间返回 404，恢复后按原标记导出。失败刷新保留空配置，首次成功刷新改用正常快照。新建的未发布订阅仍返回 404。此迁移只创建空表，版本 1 和版本 2 候选包继续沿用原有封存规则。标记通过单独验证的封存候选流程填充。

在原命令末尾显式附加 `legacy-empty-v3 SOURCE_SQLITE_SHA OWNER_MAP_SHA` 可构建版本 3。新增参数分别固定已封存 SQLite 与已核准归属映射的 SHA-256，Worker 产物必须包含摘要吻合的 0026 迁移。已验证的旧空节点数组按目标订阅编号、归属与原令牌摘要写入标记表，包含活动和回收站记录。回收站的标记在同一订阅恢复后才可用于导出。SQL 重放核对完整标记集及迁移记录，清单另记活动和回收站标记数、迁移和表摘要。包的验证范围限于候选数据，原生导入和空导出 HTTP 行为需分别验收。

### 隔离旧空订阅 HTTP 验收

在当前 `main` 的确切产物已发布且迁移 `0026` 已核对后，运行 `gh workflow run worker-isolation-legacy-empty-smoke.yml --ref main -f action=verify -f cohort=<16位小写十六进制>`。流程只在既有隔离 D1 准备一个带精确标记的空订阅和一个无标记的对照。依次检查默认路径、各格式别名的 GET 与 HEAD、响应类型、空内容、私有缓存策略及无标记 404，然后按同一批次的精确身份退役两条记录和标记。响应中使用的合成能力令牌不出现在日志中。

若流程中断，可在确认当前隔离版本后，以同一批次执行 `action=retire` 并在 `confirm_retire` 填写 `retire <cohort>`。遇到所有者、版本、指针或标记不符时保留记录并停止。此流程验证实际 Worker HTTP 和 D1 读取，与 V3 独立原生恢复的对象完整性核对分别记录。

隔离版本已启用 `LEGACY_SUBSCRIPTION_SHORTS` 后，在相同工作流命令附加 `-f profile=typed-shorts`，使用新的随机 16 位小写十六进制批次。流程核对当前 Worker 版本和 `0029` 表，在既有隔离 D1 写入一个合成的旧空订阅。通过 GET 和 HEAD 核对默认、Surge 与 `mixed` 的相对跳转和目标内容，以及错误归属、令牌摘要不符、已撤销、普通和聚合短码冲突的 404。将订阅移入回收站、恢复并复验后，在一个批次中清理该订阅、标记和短码，再核对 404。流程不写入 R2，也不调用 Telegram。

如需恢复清理，使用相同 `profile=typed-shorts`、同一 `cohort` 和上述 `retire` 参数。流程只清理身份、摘要和生命周期均匹配的完整合成批次。写入状态不明时保留批次标识，先核对运行，再按相同批次恢复，不重复提交原写入。短码与订阅令牌不进入日志或产物。同一 Bot 真实所有者通过 Telegram 撤销短码另行验收。

### 旧私密分享与领取盘点

真实盘点在单独获准的受保护托管运行中使用核对过的源码提交。将关闭的 UTF-8、DELETE 日志模式备份放入仅供当前账号访问的目录，确认普通文件归当前账号所有、没有其他硬链接或 SQLite 伴随文件。准备尚未存在的私有输出目录路径。关闭命令跟踪，运行 `python3 -B worker/tools/legacy_private_share_inventory.py BACKUP OUTPUT EXPECTED_SOURCE_SHA256 LEGACY_BOT_ID LEGACY_BOT_USERNAME`。源 SHA-256 须取自独立的备份交接记录。旧 Bot 的正十进制 ID 和小写用户名须取自单独核对过的身份记录，用户名省略 `@`。程序在不可变只读事务前后核对同一文件及 SHA-256。 [SQLite URI](https://sqlite.org/uri.html)

清单绑定源摘要、旧 Bot 身份、表与可选内联消息 ID 列是否存在、记录数以及三个数据文件的字节数和摘要。`shares.ndjson` 按旧分享码的 SHA-256 排序，保存发送者、可选接收者、份数和有效期。`claims.ndjson` 按原领取记录编号排序，保存领取者和原时间。ID 使用十进制字符串。每条分享记录标记原始正文在 `payloads.bin` 中的偏移、长度和 SHA-256。程序验证领取者唯一性、关联分享、指定用户、时间范围和已领取份数，并保留已过期记录。旧内联消息 ID 只作为私有来源证据。

最多保留 20,000 条分享、20,000 条领取、单份正文 64 KiB、正文合计 64 MiB 及分享索引 32 MiB。超限或有不一致时整包失败。只有退出码 `0`、最后写入的 `manifest.sha256` 与清单相符，且清单和三个数据文件的闭包完整时才接收。能力字段只保存摘要。正文按原字节保存，可能已含敏感文字、URL 或旧分享码。整个包只在获准的私有渠道流转，禁止进入 PR、日志、普通 Actions 产物或缓存。普通 CI 只使用合成样本。该盘点不导入 Worker 或变更 Telegram 权限，旧链接连续性另行验收。

### 旧私密分享候选恢复包

在获准的托管 runner 上，运行 `worker/tools/legacy_private_share_candidate.py INVENTORY_DIR WORKER_ARTIFACT_DIR OUTPUT_DIR INVENTORY_MANIFEST_SHA WORKER_MANIFEST_SHA REVISION APPLIED_AT SOURCE_SQLITE_SHA LEGACY_BOT_ID LEGACY_BOT_USERNAME`。使用已核对的封存清单、原 SQLite 摘要和旧 Bot 身份作为独立输入。输出目录须尚未存在，封存盘点目录、Worker 产物目录和输出父目录仅供当前账号访问。

`legacy-private-shares-v1` 仅填充准确的 0005 分享和领取表。封存程序逐行复核领取人与指定对象、份数和原时间，保留已到期记录的原到期秒，并逐对象核对原 UTF-8 正文的字节和摘要。私有正文存于 `objects/private-shares/`。内联消息标识留在封存盘点中，候选仅记录其数量。SQL 重放核对完整结构、外键、编号序列和对象闭包。每包最多 512 个正文对象，每个最多 64 KiB，SQL 重放上限为 4 MiB，所有数据库行仍受原生恢复上限约束。候选保持未绑定，旧 Bot 链接与内联卡片连续性需另行验收。

### 旧单订阅短链盘点

在获准的受保护托管运行中，对同一份封存 SQLite 使用 `python3 -B worker/tools/legacy_typed_short_inventory.py BACKUP OUTPUT SOURCE_SHA256 OWNER_MAP_JSON OWNER_MAP_SHA256 OLD_HTTPS_ORIGIN LEGACY_BOT_ID`。备份和新输出目录的父目录须仅供当前账号访问。独立核对源文件摘要、规范化归属映射摘要、原 Bot ID 和旧 HTTPS 来源。旧来源使用小写域名，省略端口和尾部斜线。

工具只接收旧来源上可唯一解析的单订阅目标，先核对短链发行者与订阅原归属，再应用归属映射。保存原活动或回收站编号、归属、格式、创建时间及短码和订阅令牌摘要。聚合、外部、递归、归属不一致或多重匹配会阻止整包封存。首版限制为两万条短链、两万个订阅身份、2 GiB 源库和 8 MiB 清单数据。只在获准的私有渠道流转最后写入封印的目录。后续候选封装需要再次核对目标编号、归属及令牌摘要，实际旧链接路由另行验收。

对同一份封存旧库生成订阅转换包及短链盘点，再在 `legacy_restore_package.py` 原有七个参数后附加 `legacy-typed-short-v4 SOURCE_SQLITE_SHA OWNER_MAP_SHA TYPED_SHORT_INVENTORY TYPED_SHORT_MANIFEST_SHA OLD_ORIGIN_SHA LEGACY_BOT_ID`。版本 4 保留版本 3 的空导出标记和可选路径规则。旧库有短链时，订阅转换命令会以退出码 2 保留封存包。此处只接受唯一的 `unhandled:short_links` 阻止项，其数量必须与已核对的盘点一致。封装逐条核对原表与编号、目标编号、映射后归属及令牌摘要，保留原格式、创建时间和旧 Bot 归属。清单与重放 SQL 固定 0026、0029 迁移和短链表摘要。短链记录只含摘要与类型，候选仍为未应用、未绑定的私有包。实际原生恢复及旧短链 HTTP 行为另行验收。

### 旧混合短链只读盘点

在同一份封存旧库上运行 `python3 -B worker/tools/legacy_short_namespace_inventory.py BACKUP OUTPUT SOURCE_SHA256 OWNER_MAP_JSON OWNER_MAP_SHA256 OLD_HTTPS_ORIGIN LEGACY_BOT_ID`。输出目录须尚未存在，目录和文件仅供当前账号访问。清单为每条合法短码记录摘要、类型或阻止原因。外部 URL、旧短码和订阅令牌的原文留在封存源库。

筛选聚合保留旧列表的顺序和重复项，按旧活动订阅的独立编号高水位记录实际匹配位置。归属在映射前核对，回收站同号记录不会补入。可能因归属合并扩大范围的旧全量聚合标记为阻止。该盘点只封存范围和分类。启用前还须独立验证外部跳转等价性、旧聚合成员生命周期、空结果与临时节点行为。

### 旧外部短链离线比较

托管 CI 使用合成 SQLite 和本次构建的 Worker，比较旧版 `aiohttp.web.HTTPFound` 与 Worker `/s/` 的 `Location` 字节。比较阶段在仅开放回环接口的网络命名空间中运行，关闭核心转储。Worker 通过内存中的单行短链记录走实际 `GET` 和 `HEAD` 路径，响应只返回固定判定。外部地址原文从封存 SQLite 经匿名管道传入内存，封存报告只保存短码摘要和判定。主机后的斜线或转义差异也会单独记录。 [aiohttp 重定向](https://docs.aiohttp.org/en/stable/_modules/aiohttp/web_exceptions.html) · [Miniflare 模块测试](https://developers.cloudflare.com/workers/testing/miniflare/writing-tests/)

离线工具入口为 `python3 -B worker/tools/legacy_short_redirect_oracle.py PRIVATE_CONFIG_JSON`。配置仅供当前账号访问，包含路径 `backup`、`inventory`、`bundle`、`output` 和 `ownerMap`，以及 `sourceSha256`、`inventorySha256`、`workerManifestSha256`、`ownerMapSha256`、`oldOrigin`、`legacyBotId`、`revision`、`pythonVersion` 和 `yarlVersion`。工具核对构建版本、源库和盘点摘要，并重建盘点验证闭合；输出目录须尚未存在。

当前证据限于合成样例，使用旧代码指定的 aiohttp 3.11.18 和测试用 yarl 1.20.0。真实比较须先独立确认旧部署的 Python、aiohttp 和 yarl 版本，并使用相同运行时及经独立核验的 Worker 构建。报告保持离线封存，进入真实候选与激活前另行核对旧链接、目标环境和恢复证据。

### 真实数据与生产切换门槛

1. 先只读核对 Cloudflare 目标账户、Zone、`subs-bot.lilyya.top` 的 DNS、Worker 路由和 Custom Domain 绑定。新资源记录账号、环境及资源 ID，隔离与生产分别使用各自的 Worker、D1、R2 和队列。现有配置冲突须在改动前报告。目标主机名可用且切换获准后，仅增加所需的 Custom Domain 绑定。 [Custom Domains](https://developers.cloudflare.com/workers/configuration/routing/custom-domains/)
2. `Worker CI` 在 GitHub 托管 runner 上安装依赖、检查类型、构建和测试。构建产物标记准确提交与摘要，由授权的部署步骤核对并上传至隔离 Worker。普通 PR CI 使用只读权限和合成数据。部署 Token 通过独立的受控步骤使用。云端 smoke 显式指定隔离环境和提交，核对 `/health` 与提交、已知测试快照的输出和负面用例。分别记录测试、构建、部署和真实运行结果。
3. 确认获准的数据来源和使用范围后，对旧 SQLite 执行包含 WAL 的一致性备份。先在项目专用隔离目标做恢复和容量盘点。对账活动订阅、回收站、路径规则、临时节点、授权覆盖、分享及领取、短链的数量和归属。核对节点摘要、有效订阅令牌、旧短码、仍有效的领取状态和跨域链接依赖。旧群级数据须由维护者确认归属。
4. 隔离合成演练和原生恢复用于验证恢复路径。真实数据验收须用获准的数据和独立目标，核对清单、对象摘要、外键、导出和两个账号的权限。Workers Paid 的 D1 Time Travel 可用于最近 30 天的原地恢复，会覆盖目标 D1；R2 对象另行恢复。 [D1 Time Travel](https://developers.cloudflare.com/d1/reference/time-travel/)
5. 在功能清单中记录代表性提供方、客户端及双账号的实测结果，并核对容量、失败恢复和旧链接连续性。确认生产切换范围、窗口及回滚方案并取得授权后，冻结旧写入，完成最后一次同步，再切换 Telegram Webhook 或域名流量。保留待处理更新，先处理旧轮询配置 `drop_pending_updates=True` 的回滚风险。验收失败时停止新写入，核对迁移后写入如何回放，再分别恢复 Worker 版本、数据和 Telegram 模式。 [Telegram `setWebhook` / `deleteWebhook`](https://core.telegram.org/bots/api#setwebhook) · [Worker 版本与部署](https://developers.cloudflare.com/workers/versions-and-deployments/)

## 限额、成本和凭据

- Workers Paid 的 Worker 内存为每 isolate 128 MB，由同一 isolate 中的并发请求共享。HTTP CPU 默认 30 秒，可配置至 5 分钟，每次调用默认最多 10,000 个子请求，R2 和 D1 绑定请求也计入。D1 单个字符串、BLOB 或数据行上限 2,000,000 字节，Paid 单库上限 10 GB。Queues 单条消息上限 128 KB。 [Workers 限制](https://developers.cloudflare.com/workers/platform/limits/) · [D1 限制](https://developers.cloudflare.com/d1/platform/limits/) · [Queues 限制](https://developers.cloudflare.com/queues/platform/limits/)
- 一个有 `N` 个数据块的快照，每遍读取包含一次清单读取和 `N` 次数据块读取。完整 `GET` 执行 `2 × (N + 1)` 次 R2 Class B 读取，并重复校验和解码。`HEAD` 只进行预检。隔离环境的正确性 smoke 完成后，仍需以接近快照与导出上限的样本，在代表性的并发量、慢客户端和中途取消条件下测量首字节与完整响应耗时、吞吐、CPU、内存超限计数及实际 R2 子请求数。用实测操作数与请求分布估算成本，再决定是否调整块大小或请求限额。 [R2 Class B 定价](https://developers.cloudflare.com/r2/pricing/#class-b-operations)
- 成本按实测请求数与 CPU、D1 读写行数、R2 容量及对象读写、队列投递与重试计算。若启用 Container，再核对实例运行时间、内存和磁盘配额、活动 CPU、区域出网及关联 Durable Objects 用量。隔离验收以按需启动和可睡眠为前提。显著新增费用或需要常驻时先提交估算和影响。 [Workers 定价](https://developers.cloudflare.com/workers/platform/pricing/) · [R2 定价](https://developers.cloudflare.com/r2/pricing/) · [Queues 定价](https://developers.cloudflare.com/queues/platform/pricing/) · [Containers 定价](https://developers.cloudflare.com/containers/platform/pricing/)
- 资源管理分开使用只读核查、派生 Token 创建和项目部署权限。新 Token 按目标账户、所需操作和有效期收窄。平台权限无法限定到单个资源时，执行步骤须核对项目专用资源 ID。应用通过绑定和 Secrets 使用运行所需权限。高权限管理凭据留在受控管理位置。 [Cloudflare API Token](https://developers.cloudflare.com/fundamentals/api/get-started/create-token/) · [Workers Secrets](https://developers.cloudflare.com/workers/configuration/secrets/)
- Worker、反代及其他链路避免记录能力路径、查询参数、Telegram 更新、订阅内容、鉴权头或上游异常正文。Cloudflare 自动 invocation 日志可能包含带凭据的 URL，发布前禁用或验证脱敏，并核对追踪、异常和外部转发的字段。允许的运行信号限于路由类别、状态、计数、耗时和内部操作 ID。私密数据和密钥不得出现在公共缓存、Git、构建产物或测试日志。 [Workers Logs](https://developers.cloudflare.com/workers/observability/logs/workers-logs/)
