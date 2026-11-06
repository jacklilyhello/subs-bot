import { checkOwnerId, validInteger } from "./storage.ts";

export const MAX_PRIVATE_SHARE_BYTES = 64 * 1024;
const MAX_SENDER_NAME_BYTES = 256;
const MAX_CLAIMS = 100;
const MAX_DURATION_MINUTES = 7 * 24 * 60;
const SHARE_CODE = /^(?:[A-Za-z0-9_-]{11}|[A-Za-z0-9_-]{22})(?![\s\S])/u;
const PAYLOAD_ID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}(?![\s\S])/u;
const SHA256 = /^[a-f0-9]{64}(?![\s\S])/u;
const encoder = new TextEncoder();

export interface PrivateShareInput {
  botId: string;
  senderId: string;
  senderName: string;
  content: string;
  maxClaims: number;
  targetUserId: string | null;
  durationMinutes: number;
}

export interface PrivateShareClaimInput {
  botId: string;
  actorId: string;
  code: string;
}

type DeniedKind = "expired" | "target" | "exhausted";

export type PrivateShareClaimResult =
  | { kind: "claimed" | "repeated"; content: string; senderName: string; claimCount: number; maxClaims: number; expireAt: number }
  | { kind: "unavailable" | DeniedKind };

interface ShareRow {
  id: number;
  senderName: string;
  payloadId: string;
  payloadSha256: string;
  payloadBytes: number;
  maxClaims: number;
  expireAt: number;
  active: number;
  targetAllowed: number;
  alreadyClaimed: number;
  claimCount: number;
}

function checkedText(text: unknown, limit: number): Uint8Array<ArrayBuffer> {
  if (typeof text !== "string" || text.length === 0 || text.length > limit || /[\ud800-\udfff]/u.test(text)) {
    throw new RangeError("Invalid private share text.");
  }
  const bytes = encoder.encode(text);
  if (bytes.length > limit) throw new RangeError("Private share text exceeds its size limit.");
  return bytes;
}

function digestHex(digest: ArrayBuffer): string {
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function payloadKey(id: string): string {
  return `private-shares/${id}.txt`;
}

export async function createPrivateShare(
  db: D1Database,
  bucket: R2Bucket,
  { botId, senderId, senderName, content, maxClaims, targetUserId, durationMinutes }: PrivateShareInput,
): Promise<{ code: string; expireAt: number }> {
  checkOwnerId(botId);
  checkOwnerId(senderId);
  if (targetUserId !== null) checkOwnerId(targetUserId);
  if (!validInteger(maxClaims, 1, MAX_CLAIMS) || !validInteger(durationMinutes, 1, MAX_DURATION_MINUTES)) {
    throw new RangeError("Invalid private share limits.");
  }
  checkedText(senderName, MAX_SENDER_NAME_BYTES);
  if (senderName.includes("\0")) throw new RangeError("Invalid private share sender name.");
  const bytes = checkedText(content, MAX_PRIVATE_SHARE_BYTES);

  try {
    const random = crypto.getRandomValues(new Uint8Array(16));
    const code = btoa(String.fromCharCode(...random)).replace(/\+/gu, "-").replace(/\//gu, "_").replace(/=+$/u, "");
    const payloadId = crypto.randomUUID();
    const key = payloadKey(payloadId);
    const [codeDigest, payloadDigest] = await Promise.all([
      crypto.subtle.digest("SHA-256", encoder.encode(code)), crypto.subtle.digest("SHA-256", bytes),
    ]);
    const object = await bucket.put(key, bytes, { onlyIf: { etagDoesNotMatch: "*" }, sha256: payloadDigest });
    if (!object) throw new Error("Private share payload could not be created.");

    const result = await db.prepare(`
      INSERT INTO private_shares
        (bot_id, code_sha256, sender_id, sender_name, payload_id, payload_sha256, payload_bytes,
          max_claims, target_user_id, expire_at, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, unixepoch() + ?, unixepoch())
      ON CONFLICT (bot_id, code_sha256) DO NOTHING
      RETURNING expire_at AS expireAt
    `).bind(botId, digestHex(codeDigest), senderId, senderName, payloadId, digestHex(payloadDigest), bytes.length,
      maxClaims, targetUserId, durationMinutes * 60).all<{ expireAt: number }>();
    if (result.success && result.meta.changes === 1 && result.results.length === 1
      && validInteger(result.results[0].expireAt, 1)) {
      return { code, expireAt: result.results[0].expireAt };
    }
    // A lost D1 response may hide a commit. Only a confirmed conflict makes this candidate disposable.
    if (result.success && result.meta.changes === 0 && result.results.length === 0) {
      await bucket.delete(key).catch(() => {});
    }
  } catch {
    // Suppress backend errors that may contain private data.
  }
  throw new Error("Private share could not be created.");
}

function denial(row: ShareRow): DeniedKind | null {
  if (row.active !== 1) return "expired";
  if (row.targetAllowed !== 1) return "target";
  if (row.alreadyClaimed !== 1 && row.claimCount >= row.maxClaims) return "exhausted";
  return null;
}

async function readVerifiedPayload(bucket: R2Bucket, row: ShareRow): Promise<string | null> {
  if (!PAYLOAD_ID.test(row.payloadId) || !SHA256.test(row.payloadSha256)
    || !validInteger(row.payloadBytes, 1, MAX_PRIVATE_SHARE_BYTES)) return null;
  try {
    const object = await bucket.get(payloadKey(row.payloadId));
    if (!object) return null;
    if (object.size !== row.payloadBytes) {
      await object.body.cancel().catch(() => {});
      return null;
    }
    const bytes = new Uint8Array(row.payloadBytes);
    const reader = object.body.getReader();
    let offset = 0;
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        if (value.length > bytes.length - offset) {
          await reader.cancel().catch(() => {});
          return null;
        }
        bytes.set(value, offset);
        offset += value.length;
      }
    } finally {
      reader.releaseLock();
    }
    if (offset !== bytes.length || digestHex(await crypto.subtle.digest("SHA-256", bytes)) !== row.payloadSha256) {
      return null;
    }
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    return null;
  }
}

export async function claimPrivateShare(
  db: D1Database,
  bucket: R2Bucket,
  { botId, actorId, code }: PrivateShareClaimInput,
): Promise<PrivateShareClaimResult> {
  if (typeof code !== "string" || !SHARE_CODE.test(code)) return { kind: "unavailable" };
  try {
    checkOwnerId(botId);
    checkOwnerId(actorId);
  } catch {
    return { kind: "unavailable" };
  }

  try {
    const codeHash = digestHex(await crypto.subtle.digest("SHA-256", encoder.encode(code)));
    const lookup = db.prepare(`
      SELECT share.id, share.sender_name AS senderName, share.payload_id AS payloadId,
        share.payload_sha256 AS payloadSha256, share.payload_bytes AS payloadBytes,
        share.max_claims AS maxClaims, share.expire_at AS expireAt, share.expire_at >= unixepoch() AS active,
        (share.target_user_id IS NULL OR share.target_user_id = ?) AS targetAllowed,
        EXISTS (SELECT 1 FROM private_share_claims WHERE share_id = share.id AND actor_id = ?) AS alreadyClaimed,
        (SELECT count(*) FROM private_share_claims WHERE share_id = share.id) AS claimCount
      FROM private_shares AS share WHERE share.bot_id = ? AND share.code_sha256 = ?
    `).bind(actorId, actorId, botId, codeHash);
    const candidate = await lookup.first<ShareRow>();
    if (!candidate) return { kind: "unavailable" };
    const denied = denial(candidate);
    if (denied) return { kind: denied };

    const content = await readVerifiedPayload(bucket, candidate);
    if (content === null) return { kind: "unavailable" };

    // The verified pointer, access, cutoff, remaining count and unique actor are checked on the write.
    const [write, read] = await db.batch<ShareRow>([
      db.prepare(`
        INSERT INTO private_share_claims (share_id, actor_id, claimed_at)
        SELECT share.id, ?, unixepoch() FROM private_shares AS share
        WHERE share.id = ? AND share.bot_id = ? AND share.code_sha256 = ?
          AND share.payload_id = ? AND share.payload_sha256 = ? AND share.payload_bytes = ?
          AND share.expire_at >= unixepoch() AND (share.target_user_id IS NULL OR share.target_user_id = ?)
          AND (SELECT count(*) FROM private_share_claims WHERE share_id = share.id) < share.max_claims
        ON CONFLICT (share_id, actor_id) DO NOTHING
      `).bind(actorId, candidate.id, botId, codeHash, candidate.payloadId, candidate.payloadSha256,
        candidate.payloadBytes, actorId),
      lookup,
    ]);
    if (!write?.success || !read?.success || read.results.length > 1
      || !validInteger(write.meta.changes, 0, 1)) throw new Error("Private share claim batch failed.");
    const confirmed = read.results[0];
    if (!confirmed || confirmed.id !== candidate.id || confirmed.payloadId !== candidate.payloadId
      || confirmed.payloadSha256 !== candidate.payloadSha256 || confirmed.payloadBytes !== candidate.payloadBytes) {
      if (write.meta.changes === 0) return { kind: "unavailable" };
      throw new Error("Private share claim batch failed.");
    }
    const inserted = write.meta.changes === 1;
    if (!inserted) {
      const nowDenied = denial(confirmed);
      if (nowDenied) return { kind: nowDenied };
    }
    if (confirmed.alreadyClaimed !== 1 || confirmed.targetAllowed !== 1
      || !validInteger(confirmed.claimCount, 1, confirmed.maxClaims)) throw new Error("Private share claim batch failed.");
    // The successful insertion established eligibility even if the clock ticked before the readback.
    return { kind: inserted ? "claimed" : "repeated", content, senderName: confirmed.senderName,
      claimCount: confirmed.claimCount, maxClaims: confirmed.maxClaims, expireAt: confirmed.expireAt };
  } catch {
    throw new Error("Private share claim could not be confirmed.");
  }
}
