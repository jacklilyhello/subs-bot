import { readPrivateTelegramCommand, readTelegramUpdate } from "./protocol.ts";
import { renderTelegramView } from "./views.ts";

// This slice has no serving entrypoint, deployment binding, or runtime DDL.
// The hosted adapter supplies a trusted pin for one reconstructed dormant candidate.
export interface GeneralAuthReplayPin {
  botId: string;
  botUsername: string;
  webhookSecret: string;
  sourceSha256: string;
  targetSha256: string;
  previewSha256: string;
  workerManifestSha256: string;
  candidateManifestSha256: string;
  releaseRevision: string;
  generation: number;
  cutoverAt: number;
}

interface ReplayReceipt {
  updateId: number;
  actorId: string;
  chatId: string;
  messageId: number;
  messageDate: number;
  role: "admin" | "member";
  command: "help" | "list";
}

export interface GeneralAuthReplayMessage {
  chat_id: string;
  text: string;
  reply_parameters: { message_id: number };
  link_preview_options: { is_disabled: true };
}

export const GENERAL_AUTH_LEGACY_ROLE = `CASE WHEN principal.is_admin=1 THEN 'admin'
  WHEN principal.override_allowed=1 THEN 'member'
  WHEN principal.override_allowed IS NULL AND principal.is_allowlisted=1 THEN 'member' END`;
const INSTALLATION = `general_auth_replay_fence AS fence
  JOIN general_auth_installation AS installation USING (bot_id)
  JOIN general_auth_principals AS principal USING (bot_id)`;
const PIN = `fence.bot_id=? AND installation.unlisted_default='denied'
  AND installation.source_sha256=? AND installation.target_sha256=? AND installation.preview_manifest_sha256=?
  AND fence.worker_manifest_sha256=? AND fence.candidate_manifest_sha256=? AND fence.release_revision=?
  AND fence.generation=? AND fence.cutover_at=?`;
const TTL = 600;

function pinBindings(pin: GeneralAuthReplayPin): readonly (string | number)[] {
  return [pin.botId, pin.sourceSha256, pin.targetSha256, pin.previewSha256, pin.workerManifestSha256,
    pin.candidateManifestSha256, pin.releaseRevision, pin.generation, pin.cutoverAt];
}

export async function acceptGeneralAuthReplay(db: D1Database, pin: GeneralAuthReplayPin, request: Request): Promise<number> {
  if (request.method !== "POST") return 405;
  if (new URL(request.url).protocol !== "https:") return 404;
  const decoded = await readTelegramUpdate(request, pin.webhookSecret);
  if (decoded.status !== 200) return decoded.status;
  const event = readPrivateTelegramCommand(decoded.update, pin.botUsername);
  if (!event || event.actorId === pin.botId || event.remainder.trim() !== "" || (event.name !== "help" && event.name !== "list")) {
    return 204;
  }
  const row = await db.prepare(`
    INSERT INTO general_auth_replay_receipts
      (bot_id,update_id,generation,actor_id,chat_id,message_id,message_date,role,command,received_at)
    SELECT fence.bot_id,?,fence.generation,principal.user_id,principal.user_id,?,?,${GENERAL_AUTH_LEGACY_ROLE},?,unixepoch()
    FROM ${INSTALLATION}
    WHERE ${PIN} AND principal.user_id=? AND (${GENERAL_AUTH_LEGACY_ROLE}) IS NOT NULL
      AND ?>MAX(fence.cutover_at,unixepoch()-${TTL}) AND ?<=unixepoch()+60
    ON CONFLICT (bot_id,update_id) DO NOTHING RETURNING update_id
  `).bind(decoded.updateId, event.messageId, event.messageDate, event.name, ...pinBindings(pin), event.actorId,
    event.messageDate, event.messageDate).first();
  return row === null ? 204 : 200;
}

const CURRENT = `receipt.bot_id=fence.bot_id AND receipt.generation=fence.generation
  AND receipt.actor_id=principal.user_id AND receipt.chat_id=receipt.actor_id AND receipt.role=(${GENERAL_AUTH_LEGACY_ROLE})
  AND receipt.message_date>fence.cutover_at AND receipt.received_at+${TTL}>unixepoch()`;

export async function drainGeneralAuthReplay(
  db: D1Database, pin: GeneralAuthReplayPin, send: (message: GeneralAuthReplayMessage) => Promise<boolean>,
): Promise<"empty" | "sent" | "uncertain"> {
  const receipt = await db.prepare(`
    SELECT receipt.update_id AS updateId,receipt.actor_id AS actorId,receipt.chat_id AS chatId,
      receipt.message_id AS messageId,receipt.message_date AS messageDate,receipt.role,receipt.command
    FROM ${INSTALLATION} JOIN general_auth_replay_receipts AS receipt ON receipt.bot_id=fence.bot_id
    WHERE ${PIN} AND ${CURRENT} AND receipt.state='pending' ORDER BY receipt.receipt_id LIMIT 1
  `).bind(...pinBindings(pin)).first<ReplayReceipt>();
  if (receipt === null) return "empty";
  const text = receipt.command === "list"
    ? (await renderTelegramView(db, receipt.actorId, { kind: "list", afterId: null, afterEpoch: null })).text
    : "可用命令\n/help 帮助\n/list 查看你的订阅";
  const scope = [pin.botId, receipt.updateId, pin.generation, receipt.actorId, receipt.chatId,
    receipt.messageId, receipt.messageDate, receipt.role, receipt.command] as const;
  const exact = `bot_id=? AND update_id=? AND generation=? AND actor_id=? AND chat_id=? AND message_id=?
    AND message_date=? AND role=? AND command=?`;
  const sending = await db.prepare(`
    UPDATE general_auth_replay_receipts AS receipt SET state='sending'
    WHERE state='pending' AND ${exact} AND EXISTS (SELECT 1 FROM ${INSTALLATION} WHERE ${PIN} AND ${CURRENT})
    RETURNING update_id
  `).bind(...scope, ...pinBindings(pin)).first();
  if (sending === null) return "empty";
  let state: "sent" | "uncertain" = "uncertain";
  try {
    if (await send({ chat_id: receipt.chatId, text, reply_parameters: { message_id: receipt.messageId },
      link_preview_options: { is_disabled: true } })) state = "sent";
  } catch {
    // A transport error may follow a send. This receipt never returns to pending.
  }
  const settled = await db.prepare(`UPDATE general_auth_replay_receipts SET state=?
    WHERE state='sending' AND ${exact} RETURNING update_id`).bind(state, ...scope).first();
  return settled === null ? "uncertain" : state;
}
