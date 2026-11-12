import type { TelegramCommandFeatures } from "./command-catalog.ts";
const MENU = [
  [{ action: "list", labels: ["📦 订阅列表", "📋 订阅列表", "订阅列表"] },
    { action: "expiry", labels: ["🟠 临期列表", "⏳ 临期列表", "临期列表"] }],
  [{ action: "aggregate", labels: ["📤 导出链接", "📦 导出", "导出", "导出链接"] },
    { action: "batchRefresh", labels: ["🔄 更新所有", "更新所有"] }],
  [{ action: "recycle", labels: ["♻️ 撤销删除", "撤销删除"] },
    { action: "renumber", labels: ["🔢 重置编号", "重置编号"] }],
  [{ action: "path", labels: ["🧭 路径对应", "路径对应"] },
    { action: "help", labels: ["❓ 帮助菜单", "帮助菜单", "帮助"] }],
] as const;

export type TelegramMainMenuFeatures = TelegramCommandFeatures & { aggregate: boolean; batchRefresh: boolean };

export function telegramMainMenuAction(text: string) {
  if (text.length > 64) return null;
  const label = text.trim();
  for (const row of MENU) {
    for (const { action, labels } of row) {
      if (labels.some((candidate) => candidate === label)) return action;
    }
  }
  return null;
}

export function telegramMainMenuKeyboard(features: TelegramMainMenuFeatures): { text: string }[][] {
  return MENU.map((row) => row
    .filter(({ action }) => (action !== "aggregate" || features.aggregate) && (action !== "batchRefresh" || features.batchRefresh)
      && (!["expiry", "recycle", "renumber"].includes(action) || features.management !== false) && (action !== "path" || features.path !== false))
    .map(({ labels }) => ({ text: labels[0] }))).filter((row) => row.length > 0);
}
