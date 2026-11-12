/** One capability directory drives help, reply keyboards and chat-scoped Bot commands. */
export type TelegramCommandFeatures = {
  management?: boolean; subscriptionRead?: boolean; temp?: boolean; tempRawDefault?: boolean; path?: boolean;
  aggregate?: boolean; selected?: boolean; batchRefresh?: boolean; batchStatus?: boolean; short?: boolean; share?: boolean;
  inline?: boolean; inlineOff?: boolean; inlineTemp?: boolean; inlineSort?: boolean; bulkTrash?: boolean; github?: boolean;
  apiStatus?: boolean; browsing?: boolean; authorization?: boolean; authorizationScope?: "registered" | "fixed"; authorizationMemberId?: string; displayTimezone?: boolean; documentImport?: boolean; providerImport?: boolean;
};
export type TelegramCommandContext = {
  privateChat: boolean; role: "admin" | "member"; features: TelegramCommandFeatures;
};
type Entry = { syntax: string; description: string };

export function telegramCommandEntries({ privateChat, role, features: f }: TelegramCommandContext): Entry[] {
  const entries: Entry[] = [{ syntax: "/help", description: "发送帮助" }, { syntax: "/list", description: "查看你的订阅" }];
  const add = (syntax: string, description: string) => entries.push({ syntax, description });
  if (f.management) {
    add("/expire", "查看临期");
    add("/recycle", "查看回收站");
  }
  if (f.subscriptionRead) add("/s 关键词", "搜索订阅");
  if (!privateChat) return entries;
  add("/start", "打开主菜单");
  if (f.temp) {
    add("/temp", f.tempRawDefault ? "查看临时节点" : "查看临时节点数量");
    add("/temp summary", "查看临时节点数量");
    if (!f.tempRawDefault) add("/temp raw", "查看临时节点");
    add("/temp clear", "清空临时节点");
  }
  if (f.path) {
    add("/path", "查看路径规则");
    add("/path list [编号]", "分页查看路径规则");
    add("/path 关键词 备注", "保存路径规则");
    add("/path delete 编号", "删除路径规则");
    add("/path clear", "清空路径规则");
  }
  if (f.aggregate) {
    add("/export", "导出全部订阅");
    add("/export revoke", "撤销全部订阅链接");
  }
  if (f.selected) add("/o [关键词]", "导出所选订阅");
  if (f.short) {
    add("/short URL", "生成短链");
    add("/short revoke 短码或本地短链", "撤销自己的短链");
  }
  if (f.share) {
    add("/share [x份数] [id领取人ID] [s分钟] -- 正文", "创建私密分享");
    add("/share sub 订阅ID [x份数] [id领取人ID] [s分钟]", "分享自己的订阅");
  }
  if (f.batchRefresh) add("/updateall", "预览批量刷新");
  if (f.batchRefresh || f.batchStatus) add("/updateall status", "查看批量任务历史");
  if (f.bulkTrash) add("/d 关键词", "预览匹配订阅的删除操作");
  if (f.github) add("/g 关键词", "搜索 GitHub 公开代码");
  if (f.apiStatus) {
    add("/ai", "测试 API 地址和 Key");
    add("/cancel", "回复 API 提示时取消");
  }
  if (f.inline) {
    add("/inline on", "开启私聊内联搜索（15 分钟）");
    if (f.inlineTemp) add("/inline temp on", "开启临时节点内联搜索（15 分钟）");
  }
  if (f.inline || f.inlineOff) add("/inline off", "关闭内联搜索");
  if (f.inlineSort) {
    add("/i", "查看内联排序");
    for (const mode of ["默认", "流量", "到期", "名称"]) add(`/i ${mode}`, "设置内联排序");
  }
  if (role === "admin" && f.authorization) {
    const fixed = f.authorizationScope === "fixed" && /^[1-9][0-9]{0,15}$/u.test(f.authorizationMemberId ?? "");
    const target = fixed ? f.authorizationMemberId! : "已登记用户ID";
    add("/auth list", "查看授权");
    add(`/auth add ${target}`, fixed ? "授权固定测试用户" : "授权已登记用户");
    add(`/auth remove ${target}`, fixed ? "撤权固定测试用户" : "撤权已登记用户");
  }
  if (role === "admin" && f.displayTimezone) {
    add("/settings", "查看机器人设置");
    add("/timezone", "查看展示时区");
    add("/timezone IANA时区", "设置展示时区");
    add("/timezone UTC", "恢复默认时区");
  }
  return entries;
}

export function renderTelegramHelp(context: TelegramCommandContext): string {
  const lines = telegramCommandEntries(context).map(({ syntax, description }) => `${syntax} ${description}`);
  if (!context.privateChat) lines.push("订阅详情、导出、节点和设置请回到机器人私聊。");
  else {
    if (context.features.browsing) lines.push("发送列表编号打开自己的订阅详情；详情按钮可浏览或导出节点。");
    if (context.features.subscriptionRead) lines.push("在搜索结果中点击详情按钮查看订阅。");
    if (context.features.providerImport) lines.push("直接发送订阅 URL 可添加订阅。");
    if (context.features.documentImport) lines.push("上传 .txt、.log、.yaml、.yml 或 .json 文件可导入节点。");
    if (context.features.inline) lines.push("开启后在机器人自己的私聊输入 @机器人用户名 关键词。");
  }
  return lines.join("\n");
}

export function telegramBotCommands(context: TelegramCommandContext): { command: string; description: string }[] {
  const seen = new Set<string>();
  return telegramCommandEntries(context).flatMap(({ syntax, description }) => {
    const command = syntax.slice(1).split(" ", 1)[0];
    if (seen.has(command)) return [];
    seen.add(command);
    return [{ command, description }];
  });
}

/** Explicit protected deployment synchronization; normal help delivery makes no extra Bot API call. */
export async function syncTelegramCommandMenu(
  botToken: string, chatId: string, context: TelegramCommandContext, request: typeof fetch = fetch,
): Promise<boolean> {
  if (!/^-?[1-9][0-9]{0,15}$/u.test(chatId) || !Number.isSafeInteger(Number(chatId)) || Number(chatId) === 0) return false;
  try {
    const response = await request(`https://api.telegram.org/bot${botToken}/setMyCommands`, {
      method: "POST", redirect: "manual", signal: AbortSignal.timeout(1_500),
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ commands: telegramBotCommands(context), scope: { type: "chat", chat_id: chatId }, language_code: "" }),
    });
    if (!response.ok) { await response.body?.cancel(); return false; }
    const body: unknown = await response.json();
    return body !== null && typeof body === "object" && "ok" in body && body.ok === true && "result" in body && body.result === true;
  } catch { return false; }
}
