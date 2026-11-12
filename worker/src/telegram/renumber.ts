/** Display numbers already follow the actor's current ordered inventory; no IDs are rewritten. */
export const TELEGRAM_RENUMBER_MARKER = "renumber:v1";
export const GENERAL_RENUMBER_MARKER = "general-renumber:v1";

export async function renderTelegramRenumber(db: D1Database, actorId: string): Promise<string> {
  const count = await db.prepare("SELECT count(*) AS total FROM subscriptions WHERE owner_id=?")
    .bind(actorId).first<number>("total");
  if (count === null || !Number.isSafeInteger(count) || count < 0) {
    throw new Error("Telegram display numbering count could not be confirmed.");
  }
  return `已重置编号，当前 ${count} 条订阅。`;
}
