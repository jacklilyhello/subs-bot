import { sendGeneralTelegramPrivateReply } from "./delivery.ts";
import { GENERAL_LATEST_ACTOR_SQL, GENERAL_POLICY_ACTORS_SQL, GENERAL_POLICY_PIN_SQL, GENERAL_REPLY_TTL,
  generalOrdinaryReplyEligibilitySql, generalPolicyBindings } from "./general-receipt.ts";
import { readGeneralGroupCommand, readGeneralPrivateMenuCommand, readTelegramBotCredentials, readTelegramUpdate,
  type TelegramBotCredentials, type TelegramEventScope, type TelegramGroupShareDestination } from "./protocol.ts";
import type { GeneralReadLaneScope } from "./general-read-lane.ts";
import { renderTelegramView } from "./views.ts";
import { renderTelegramHelp, type TelegramCommandFeatures } from "./command-catalog.ts";

export interface GeneralTelegramPin extends TelegramBotCredentials {
  generation: number;
  cutoverAt: number;
  activationSha256: string;
  releaseRevision: string;
  sharedOutbox: boolean;
  privateManagement: boolean;
  privateBrowsing?: boolean;
  privateFormats: boolean;
  privateTemp: boolean;
  privateDocument: boolean;
  privateProvider: boolean;
  providerDocumentReplies?: boolean;
  privateClaims: boolean;
  privateShareCreation: boolean;
  privateAggregate: boolean;
  privateSelected: boolean;
  privateShort: boolean;
  subscriptionShorts?: "issue" | "drain";
  privateAuthorization?: boolean;
  privateInline?: boolean;
  privateGitHub?: boolean;
  privateApiStatus?: boolean;
  providerBatch?: boolean;
  displayTimezone?: boolean;
  commandFeatures?: TelegramCommandFeatures;
  groupShare?: TelegramGroupShareDestination;
  rehearsal?: GeneralReadLaneScope;
  isolationWindow?: { profile: "full-v1"; adminId: string; memberId: string };
}

interface Lease {
  id: number;
  actorId: string;
  actorRevision: number;
  messageId: number;
  messageDate: number;
  command: "help" | "list";
  leaseId: string;
}

const LEASE_SECONDS = 15;
const CURRENT = `${generalOrdinaryReplyEligibilitySql("receipt")} AND EXISTS (
  SELECT 1 FROM ${GENERAL_POLICY_ACTORS_SQL} WHERE ${GENERAL_POLICY_PIN_SQL} AND policy.active=1
    AND receipt.bot_id=policy.bot_id AND receipt.generation=policy.generation
    AND actor.actor_id=receipt.actor_id AND actor.revision=receipt.actor_revision AND ${GENERAL_LATEST_ACTOR_SQL}
    AND receipt.message_date>MAX(policy.cutover_at,actor.effective_at))`;
const EXACT_LEASE = `receipt_id=? AND bot_id=? AND generation=? AND actor_id=? AND actor_revision=?
  AND message_id=? AND message_date=? AND command=? AND lease_id=?`;

export function parseGeneralTelegramPin(input: unknown, releaseRevision: unknown): GeneralTelegramPin | null {
  if (typeof input !== "string" || input.length > 4096 || typeof releaseRevision !== "string"
    || !/^[0-9a-f]{40}(?![\s\S])/u.test(releaseRevision)) return null;
  try {
    const value = JSON.parse(input) as Record<string, unknown> | null;
    if (value === null || typeof value !== "object" || Array.isArray(value)) return null;
    const sharedOutbox = Object.hasOwn(value, "outbox");
    const privateShort = value.outbox === "shared-private-management-formats-temp-node-document-provider-claims-share-aggregate-selected-short";
    const privateSelected = value.outbox === "shared-private-management-formats-temp-node-document-provider-claims-share-aggregate-selected" || privateShort;
    const privateAggregate = value.outbox === "shared-private-management-formats-temp-node-document-provider-claims-share-aggregate" || privateSelected;
    const privateShareCreation = value.outbox === "shared-private-management-formats-temp-node-document-provider-claims-share" || privateAggregate;
    const privateClaims = value.outbox === "shared-private-management-formats-temp-node-document-provider-claims" || privateShareCreation;
    const privateProvider = value.outbox === "shared-private-management-formats-temp-node-document-provider" || privateClaims;
    const privateDocument = value.outbox === "shared-private-management-formats-temp-node-document" || privateProvider;
    const cumulative = value.outbox === "shared-private-management-formats-temp" || privateDocument;
    const privateFormats = value.outbox === "shared-private-management-formats" || cumulative;
    const privateTemp = value.outbox === "shared-private-temp" || cumulative;
    const privateManagement = value.outbox === "shared-private-management" || privateFormats || privateTemp;
    const browsingConfigured = Object.hasOwn(value, "subscriptionBrowsing");
    const privateBrowsing = value.subscriptionBrowsing === true;
    const authorizationConfigured = Object.hasOwn(value, "authManagement");
    const privateAuthorization = value.authManagement === true;
    const inlineConfigured = Object.hasOwn(value, "inlineSearch");
    const privateInline = value.inlineSearch === true;
    const githubConfigured = Object.hasOwn(value, "githubSearch");
    const privateGitHub = value.githubSearch === true;
    const apiConfigured = Object.hasOwn(value, "apiStatus");
    const privateApiStatus = value.apiStatus === true;
    const batchConfigured = Object.hasOwn(value, "providerBatch");
    const providerBatch = value.providerBatch === true;
    const groupConfigured = Object.hasOwn(value, "groupShare");
    const typedConfigured = Object.hasOwn(value, "subscriptionShorts");
    const subscriptionShorts = value.subscriptionShorts;
    let groupShare: TelegramGroupShareDestination | undefined;
    if (groupConfigured) {
      if (!privateShareCreation || value.groupShare === null || typeof value.groupShare !== "object"
        || Array.isArray(value.groupShare) || Object.keys(value.groupShare).length !== 2) return null;
      const { chatId, chatType } = value.groupShare as Record<string, unknown>;
      if (typeof chatId !== "string" || !/^-[1-9][0-9]{0,15}(?![\s\S])/u.test(chatId)
        || -Number(chatId) >= 2 ** 52 || (chatType !== "group" && chatType !== "supergroup")) return null;
      groupShare = { chatId, chatType };
    }
    if (Object.keys(value).length !== 7 + Number(sharedOutbox) + Number(authorizationConfigured) + Number(inlineConfigured)
        + Number(groupConfigured) + Number(typedConfigured) + Number(batchConfigured) + Number(githubConfigured) + Number(apiConfigured) + Number(browsingConfigured)
      || (sharedOutbox && value.outbox !== "shared" && !privateManagement)
      || (authorizationConfigured && (!privateManagement || !privateAuthorization))
      || (inlineConfigured && (!privateManagement || !privateInline))
      || (githubConfigured && (!privateManagement || !privateGitHub))
      || (apiConfigured && (!privateManagement || !privateApiStatus))
      || (browsingConfigured && (!privateManagement || !privateBrowsing))
      || (batchConfigured && (!privateProvider || !providerBatch))
      || (typedConfigured && (!privateShort || (subscriptionShorts !== "issue" && subscriptionShorts !== "drain")))) return null;
    const credentials = readTelegramBotCredentials(value);
    const { generation, cutoverAt, activationSha256 } = value;
    if (!credentials || Number(credentials.botId) >= 2 ** 52 || typeof generation !== "number"
      || !Number.isSafeInteger(generation) || generation < 1 || typeof cutoverAt !== "number"
      || !Number.isSafeInteger(cutoverAt) || cutoverAt < 1 || typeof activationSha256 !== "string"
      || !/^[0-9a-f]{64}(?![\s\S])/u.test(activationSha256)) return null;
    return { ...credentials, generation, cutoverAt, activationSha256, releaseRevision, sharedOutbox, privateManagement,
      privateFormats, privateTemp, privateDocument, privateProvider, privateClaims, privateShareCreation, privateAggregate, privateSelected,
      privateShort, privateAuthorization, privateInline, ...(privateBrowsing ? { privateBrowsing } : {}), ...(privateGitHub ? { privateGitHub } : {}), ...(privateApiStatus ? { privateApiStatus } : {}), ...(providerBatch ? { providerBatch } : {}), ...(groupShare ? { groupShare } : {}),
      ...(subscriptionShorts === "issue" || subscriptionShorts === "drain" ? { subscriptionShorts } : {}) };
  } catch {
    return null;
  }
}

function leaseBindings(pin: GeneralTelegramPin, lease: Lease) {
  return [lease.id, pin.botId, pin.generation, lease.actorId, lease.actorRevision,
    lease.messageId, lease.messageDate, lease.command, lease.leaseId];
}

export type GeneralReadCommand = "start" | "help" | "list";

export type GeneralReadEvent = TelegramEventScope & {
  command: GeneralReadCommand; viewKind: "list" | "expiry" | "recycle" | null; renumber?: true;
};

export function generalReadEvent(
  pin: Pick<GeneralTelegramPin, "botUsername" | "botId" | "privateManagement">,
  update: Record<string, unknown>, updateId: number, shared = false,
): GeneralReadEvent | null {
  const event = readGeneralPrivateMenuCommand(update, pin.botUsername);
  if (event && event.actorId !== pin.botId && event.remainder.trim() === "") {
    const { actorId, messageId, messageDate, name } = event;
    if (shared && pin.privateManagement && name === "renumber") return {
      updateId, actorId, chatId: actorId, chatType: "private", threadId: null, messageId, messageDate,
      command: "help", viewKind: null, renumber: true,
    };
    if (name === "help" || name === "list" || name === "start" || (shared && pin.privateManagement && ["start", "expire", "recycle"].includes(name))) {
      return { updateId, actorId, chatId: actorId, chatType: "private", threadId: null, messageId, messageDate,
        command: name === "start" ? (shared ? "start" : "help") : name === "help" ? "help" : "list",
        viewKind: name === "start" || name === "help" ? null : name === "expire" ? "expiry" : name as "list" | "recycle" };
    }
  }
  const group = shared ? readGeneralGroupCommand(update, pin.botUsername) : null;
  if (!group || group.actorId === pin.botId || group.name === "s") return null;
  if (["expire", "recycle", "renumber"].includes(group.name) && !pin.privateManagement) return null;
  const { name, remainder: _remainder, ...scope } = group;
  if (name === "renumber") return { ...scope, updateId, command: "help", viewKind: null, renumber: true };
  return { ...scope, updateId, command: name === "start" ? "start" : name === "help" ? "help" : "list",
    viewKind: name === "start" || name === "help" ? null : name === "expire" ? "expiry" : name as "list" | "recycle" };
}

async function readGeneralReadCommand(pin: GeneralTelegramPin, request: Request): Promise<
  (GeneralReadEvent & { status: 200 }) | { status: 204 | 400 | 401 | 413 | 415 }
> {
  const decoded = await readTelegramUpdate(request, pin.webhookSecret);
  if (decoded.status !== 200) return decoded;
  const event = generalReadEvent(pin, decoded.update, decoded.updateId);
  return event ? { ...event, status: 200 } : { status: 204 };
}

export async function renderGeneralReadReply(db: D1Database, actorId: string, command: GeneralReadCommand): Promise<string> {
  return command === "list"
    ? (await renderTelegramView(db, actorId, { kind: "list", afterId: null, afterEpoch: null })).text
    : renderTelegramHelp({ privateChat: true, role: "member", features: {} });
}

export async function acceptGeneralTelegramCommand(db: D1Database, pin: GeneralTelegramPin, request: Request): Promise<number> {
  const event = await readGeneralReadCommand(pin, request);
  if (event.status !== 200) return event.status;
  const accepted = await db.prepare(`INSERT INTO telegram_general_replies
    (bot_id,generation,actor_id,actor_revision,update_id,message_id,message_date,command)
    SELECT policy.bot_id,policy.generation,actor.actor_id,actor.revision,?,?,?,?
    FROM ${GENERAL_POLICY_ACTORS_SQL}
    WHERE ${GENERAL_POLICY_PIN_SQL} AND policy.active=1 AND actor.actor_id=? AND ${GENERAL_LATEST_ACTOR_SQL}
      AND ?>MAX(policy.cutover_at,actor.effective_at,unixepoch()-${GENERAL_REPLY_TTL}) AND ?<=unixepoch()+60
      AND NOT EXISTS (SELECT 1 FROM telegram_inbox WHERE bot_id=policy.bot_id AND update_id=?)
      AND NOT EXISTS (SELECT 1 FROM telegram_general_replies AS queued
        WHERE queued.bot_id=actor.bot_id AND queued.generation=actor.generation
          AND queued.actor_id=actor.actor_id AND queued.actor_revision=actor.revision
          AND queued.state IN ('pending','leased','sending') AND queued.received_at+${GENERAL_REPLY_TTL}>unixepoch()
        LIMIT 1 OFFSET 3)
    ON CONFLICT (bot_id,update_id) DO NOTHING RETURNING receipt_id`)
    .bind(event.updateId, event.messageId, event.messageDate, event.command, ...generalPolicyBindings(pin),
      event.actorId, event.messageDate, event.messageDate, event.updateId).first();
  return accepted ? 200 : 204;
}

export async function claimGeneralTelegramReply(db: D1Database, pin: GeneralTelegramPin): Promise<Lease | null> {
  return db.prepare(`UPDATE telegram_general_replies SET state='leased',lease_id=?,lease_until=unixepoch()+${LEASE_SECONDS}
    WHERE receipt_id=(SELECT receipt.receipt_id FROM telegram_general_replies AS receipt
      WHERE receipt.bot_id=? AND receipt.generation=? AND ${CURRENT}
        AND (receipt.state='pending' OR (receipt.state='leased' AND receipt.lease_until<=unixepoch()))
        AND NOT EXISTS (SELECT 1 FROM telegram_general_replies AS earlier
          WHERE earlier.bot_id=receipt.bot_id AND earlier.actor_id=receipt.actor_id AND earlier.receipt_id<receipt.receipt_id
            AND earlier.state IN ('pending','leased','sending')
            AND ((earlier.state='sending' AND earlier.lease_until>unixepoch()) OR (
              earlier.state IN ('pending','leased') AND earlier.generation=receipt.generation
              AND earlier.actor_revision=receipt.actor_revision AND earlier.received_at+${GENERAL_REPLY_TTL}>unixepoch())))
      ORDER BY receipt.receipt_id LIMIT 1)
    RETURNING receipt_id AS id,actor_id AS actorId,actor_revision AS actorRevision,message_id AS messageId,
      message_date AS messageDate,command,lease_id AS leaseId`)
    .bind(crypto.randomUUID(), pin.botId, pin.generation, ...generalPolicyBindings(pin)).first<Lease>();
}

export async function beginGeneralTelegramReply(db: D1Database, pin: GeneralTelegramPin, lease: Lease): Promise<boolean> {
  const row = await db.prepare(`UPDATE telegram_general_replies AS receipt
    SET state='sending',lease_until=unixepoch()+${LEASE_SECONDS}
    WHERE state='leased' AND lease_until>unixepoch() AND ${EXACT_LEASE} AND ${CURRENT} RETURNING receipt_id`)
    .bind(...leaseBindings(pin, lease), ...generalPolicyBindings(pin)).first();
  return row !== null;
}

export async function drainGeneralTelegramReply(db: D1Database, pin: GeneralTelegramPin): Promise<boolean> {
  const lease = await claimGeneralTelegramReply(db, pin);
  if (!lease) return false;
  const text = await renderGeneralReadReply(db, lease.actorId, lease.command);
  if (!await beginGeneralTelegramReply(db, pin, lease)) return false;
  const outcome = await sendGeneralTelegramPrivateReply(pin.botToken, lease.actorId, lease.messageId, text);
  const state = outcome.kind === "retry" ? "failed" : outcome.kind;
  await db.prepare(`UPDATE telegram_general_replies SET state=?,lease_id=NULL,lease_until=NULL
    WHERE state='sending' AND ${EXACT_LEASE}`).bind(state, ...leaseBindings(pin, lease)).run();
  return true;
}

export async function recoverGeneralTelegramReplies(db: D1Database, pin: GeneralTelegramPin): Promise<void> {
  await db.prepare(`UPDATE telegram_general_replies
    SET state=CASE WHEN state='sending' THEN 'uncertain' ELSE 'discarded' END,lease_id=NULL,lease_until=NULL
    WHERE receipt_id IN (SELECT receipt.receipt_id FROM telegram_general_replies AS receipt
      WHERE receipt.bot_id=? AND ((receipt.state='sending' AND receipt.lease_until<=unixepoch())
        OR (receipt.state IN ('pending','leased') AND NOT (${CURRENT})))
      ORDER BY receipt.receipt_id LIMIT 16)
    AND EXISTS (SELECT 1 FROM telegram_general_policy AS policy WHERE ${GENERAL_POLICY_PIN_SQL})`)
    .bind(pin.botId, ...generalPolicyBindings(pin), ...generalPolicyBindings(pin)).run();
  for (let i = 0; i < 4 && await drainGeneralTelegramReply(db, pin); i++) {
    // Bound scheduled work while allowing the next pending receipt to advance.
  }
}
