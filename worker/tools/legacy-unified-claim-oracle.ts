/** Verify restored private claims through the emitted Worker with a loopback-only Bot double. */

import { createHash } from "node:crypto";
import type { Miniflare } from "miniflare";

const policy = {
  botId: "74111", botUsername: "synthetic_unified_bot", adminId: "74112", memberId: "74113",
  groupId: "-10074116", botToken: `74111:${"s".repeat(35)}`, webhookSecret: "synthetic-v10-claim-webhook-secret",
};
const fixtureCode = (number: number) => Buffer.from([0, 0, 0, 0, 0, 0, 0, number]).toString("base64url");
const targetCode = fixtureCode(6);
const expiredCode = fixtureCode(13);
const targetExpiry = 2_100_000_000;
const expiredAt = 1_700_000_030;
const targetPayload = Buffer.from("\ufeff  合成私密正文\r\n\0  \n", "utf8");
const failure = "The restored private claim could not be confirmed.";
const cases = [
  { id: 101, actor: policy.memberId, code: targetCode, method: "sendDocument",
    text: "私密分享\n来自：合成发送者\n领取进度：1/2" },
  { id: 102, actor: policy.adminId, code: targetCode, method: "sendMessage",
    text: "私密分享领取失败。\n此分享指定了其他领取人。" },
  { id: 103, actor: policy.memberId, code: expiredCode, method: "sendMessage",
    text: "私密分享领取失败。\n分享已过期。" },
] as const;
const digest = (code: string) => createHash("sha256").update(code).digest("hex");
const sentId = (update: number) => 1000 + update;

function requireClaim(condition: unknown): asserts condition {
  if (!condition) throw new Error(failure);
}

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function replyTo(value: unknown): number {
  requireClaim(record(value) && Object.keys(value).length === 2 && value.allow_sending_without_reply === true
    && typeof value.message_id === "number" && Number.isSafeInteger(value.message_id));
  return value.message_id;
}

export function makeUnifiedClaimOracle() {
  const observed = new Set<number>();
  let unexpected = false;
  async function outboundService(request: Request): Promise<Response> {
    try {
      const api = `https://api.telegram.org/bot${policy.botToken}/`;
      const method = request.url === api + "sendDocument" ? "sendDocument"
        : request.url === api + "sendMessage" ? "sendMessage" : null;
      requireClaim(method !== null && request.method === "POST");
      let id: number, chat: unknown, text: unknown;
      if (method === "sendDocument") {
        const form = await request.formData();
        const file = form.get("document");
        const parameters = form.get("reply_parameters");
        requireClaim([...form.keys()].length === 4 && typeof parameters === "string" && file !== null && typeof file !== "string"
          && file.name === "private-share.txt" && /^text\/plain(?:;\s*charset=utf-8)?$/iu.test(file.type)
          && file.size === targetPayload.length && Buffer.from(await file.arrayBuffer()).equals(targetPayload));
        id = replyTo(JSON.parse(parameters));
        chat = form.get("chat_id");
        const caption = form.get("caption");
        text = typeof caption === "string" ? caption.replace(/\r\n/gu, "\n") : caption;
      } else {
        const body: unknown = await request.json();
        requireClaim(record(body) && Object.keys(body).length === 4 && record(body.link_preview_options)
          && body.link_preview_options.is_disabled === true);
        id = replyTo(body.reply_parameters);
        chat = body.chat_id;
        text = body.text;
      }
      const expected = cases.find((item) => item.id === id);
      requireClaim(expected && method === expected.method && chat === expected.actor && text === expected.text && !observed.has(id));
      observed.add(id);
      return Response.json({ ok: true, result: { message_id: sentId(id), chat: { id: Number(chat) } } });
    } catch {
      unexpected = true;
      throw new Error(failure);
    }
  }

  async function verify(runtime: Miniflare, origin: string): Promise<number> {
    const db = await runtime.getD1Database("DB");
    const date = await db.prepare("SELECT unixepoch() AS now").first<number>("now");
    requireClaim(typeof date === "number" && Number.isSafeInteger(date) && date > expiredAt && date < targetExpiry);
    const verifyOriginalClaim = async () => {
      const rows = await db.prepare(`SELECT share.bot_id,share.code_sha256,share.target_user_id,share.expire_at,share.max_claims,
          claim.actor_id,claim.claimed_at FROM private_share_claims AS claim
        JOIN private_shares AS share ON share.id=claim.share_id LIMIT 2`).all();
      requireClaim(rows.success && rows.results.length === 1);
      const row = rows.results[0];
      requireClaim(row.bot_id === policy.botId && row.code_sha256 === digest(targetCode) && row.max_claims === 2
        && row.target_user_id === policy.memberId && row.actor_id === policy.memberId
        && row.expire_at === targetExpiry && row.claimed_at === targetExpiry);
    };
    await verifyOriginalClaim();

    const post = ({ id, actor, code }: (typeof cases)[number]) => runtime.dispatchFetch(origin + "/telegram/webhook", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Telegram-Bot-Api-Secret-Token": policy.webhookSecret },
      body: JSON.stringify({ update_id: id, message: {
        message_id: id, date, text: `/start claim_${code}`, from: { id: Number(actor), is_bot: false },
        chat: { id: Number(actor), type: "private" }, entities: [{ type: "bot_command", offset: 0, length: 6 }],
      } }),
    });
    for (const item of cases) {
      requireClaim((await Promise.all([post(item), post(item)])).every((response) => response.status === 200));
      let settled = false;
      for (let attempt = 0; attempt < 50 && !settled; attempt++) {
        const receipt = await db.prepare(`SELECT inbox.actor_id,inbox.chat_id,inbox.chat_type,inbox.receipt_nonce,
            claim.code_sha256,outbox.state,outbox.attempts,outbox.sent_message_id
          FROM telegram_inbox AS inbox JOIN telegram_private_claim AS claim USING (receipt_id)
          JOIN telegram_outbox AS outbox USING (receipt_id)
          WHERE inbox.bot_id=? AND inbox.update_id=?`).bind(policy.botId, item.id).first();
        requireClaim(!unexpected && receipt && ["pending", "leased", "sending", "sent"].includes(String(receipt.state)));
        settled = receipt.state === "sent";
        if (settled) {
          requireClaim(receipt.actor_id === item.actor && receipt.chat_id === item.actor && receipt.chat_type === "private"
            && receipt.receipt_nonce === "claim:v1" && receipt.code_sha256 === digest(item.code)
            && receipt.attempts === 1 && receipt.sent_message_id === sentId(item.id) && observed.has(item.id));
        } else {
          await new Promise((resolve) => setTimeout(resolve, 100));
        }
      }
      requireClaim(settled);
    }
    requireClaim((await post(cases[0])).status === 200);
    const totals = await db.prepare(`SELECT (SELECT count(*) FROM telegram_inbox) AS inbox,
      (SELECT count(*) FROM telegram_private_claim) AS claim, (SELECT count(*) FROM telegram_outbox) AS outbox`).first();
    requireClaim(!unexpected && observed.size === cases.length && totals?.inbox === cases.length
      && totals.claim === cases.length && totals.outbox === cases.length);
    await verifyOriginalClaim();
    return observed.size;
  }

  return { policy, outboundService, verify };
}
