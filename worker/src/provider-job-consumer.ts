import {
  PROVIDER_MAX_BODY_BYTES, PROVIDER_MAX_METADATA_BYTES, PROVIDER_METADATA_FIELDS, PROVIDER_REVISION, PROVIDER_SHA256,
  type ProviderFetcher, type ProviderFetchResult, type ProviderPin,
} from "./provider-fetch-contract.ts";
import {
  claimProviderJob, isProviderJobCurrent, retireStaleProviderJob, settleProviderJob,
  type ProviderFailureOutcome, type ProviderJobLease, type ProviderTelegramPolicy,
} from "./provider-jobs.ts";
import { providerSnapshotJournalReady, publishProviderSnapshot, stageProviderSnapshot } from "./provider-snapshot-journal.ts";
import { initialProviderTitle } from "./provider-initial-title.ts";
import { digestHex, type SnapshotMetadataUpdate, type StagedNodeSnapshot } from "./storage.ts";
import { parseSubscriptionDocument } from "./subscription-document.ts";

const RPC_TIMEOUT_MS = 72_000;
const LEASE_HEADROOM_MS = 90_000;
const encoder = new TextEncoder();
const timedOut = Symbol("Provider RPC timeout");

type ConsumerOutcome = "disabled" | "idle" | "saved" | "retry" | "done" | "stale" | "uncertain";

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function keysAre(value: Record<string, unknown>, required: readonly string[], optional?: string): boolean {
  const allowed = optional === undefined ? required : [...required, optional];
  return required.every((key) => Object.hasOwn(value, key)) && Object.keys(value).every((key) => allowed.includes(key));
}

async function callProvider(provider: ProviderFetcher, lease: ProviderJobLease, pin: ProviderPin): Promise<unknown> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      provider.fetchSubscription({ url: lease.sourceUrl, ...pin }),
      new Promise<typeof timedOut>((resolve) => { timer = setTimeout(() => resolve(timedOut), RPC_TIMEOUT_MS); }),
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

const rejected: ProviderFailureOutcome = { kind: "failed", reason: "fetch-rejected" };
const invalidDocument: ProviderFailureOutcome = { kind: "failed", reason: "invalid-document" };

function fetchFailure(value: unknown): ProviderFailureOutcome {
  if (!record(value) || value.ok !== false || typeof value.retryable !== "boolean" ||
      !keysAre(value, ["ok", "code", "retryable"], "upstreamStatus")) return rejected;
  const code = value.code;
  if (code === "http-status") {
    const status = value.upstreamStatus;
    if (typeof status !== "number" || !Number.isInteger(status) || status < 100 || status > 599 || status === 200) return rejected;
    return value.retryable && (status === 408 || status === 429 || status >= 500)
      ? { kind: "retry", reason: "upstream-retryable" } : rejected;
  }
  if (Object.hasOwn(value, "upstreamStatus") || !value.retryable) return rejected;
  if (code === "busy" || code === "timeout" || code === "dns-failed" || code === "unavailable") return { kind: "retry", reason: code };
  return rejected;
}

type FetchSuccess = Extract<ProviderFetchResult, { ok: true }>;

function validBody(value: Record<string, unknown>): value is Record<string, unknown> & FetchSuccess {
  if (!keysAre(value, ["ok", "body", "bodySha256"], "metadata") || value.ok !== true ||
      !(value.body instanceof ArrayBuffer) || value.body.byteLength > PROVIDER_MAX_BODY_BYTES ||
      typeof value.bodySha256 !== "string" || !PROVIDER_SHA256.test(value.bodySha256)) return false;
  if (!Object.hasOwn(value, "metadata")) return true;
  if (!record(value.metadata)) return false;
  for (const [key, entry] of Object.entries(value.metadata)) {
    if (!PROVIDER_METADATA_FIELDS.some((allowed) => allowed === key) || typeof entry !== "string" ||
        entry.length > PROVIDER_MAX_METADATA_BYTES || /[\u0000-\u001f\u007f-\u009f\ud800-\udfff]/u.test(entry)) return false;
  }
  return encoder.encode(JSON.stringify(value.metadata)).byteLength <= PROVIDER_MAX_METADATA_BYTES;
}

function decimal(value: string | undefined): number | undefined {
  if (value === undefined || !/^(?:0|[1-9][0-9]{0,18})(?:\.[0-9]{1,9})?$/u.test(value)) return undefined;
  const number = Number(value);
  return Number.isFinite(number) && number <= Number.MAX_SAFE_INTEGER ? number : undefined;
}

/** Traffic and expiry are display metadata. Missing or invalid values preserve known values. */
function subscriptionMetadata(userinfo: string | undefined): SnapshotMetadataUpdate {
  const fields = new Map<string, string>();
  for (const part of (userinfo ?? "").split(";")) {
    const split = part.indexOf("=");
    if (split < 0) continue;
    const key = part.slice(0, split).trim();
    if (!["upload", "download", "total", "expire"].includes(key)) continue;
    if (fields.has(key)) return {};
    fields.set(key, part.slice(split + 1).trim());
  }
  const upload = decimal(fields.get("upload") ?? "0");
  const download = decimal(fields.get("download") ?? "0");
  const total = decimal(fields.get("total"));
  const expire = decimal(fields.get("expire"));
  const metadata: SnapshotMetadataUpdate = {};
  if (upload !== undefined && download !== undefined && total !== undefined && total > 0 && upload + download <= Number.MAX_SAFE_INTEGER) {
    metadata.trafficUsed = (upload + download) / 1024 ** 3;
    metadata.trafficTotal = total / 1024 ** 3;
  }
  if (expire !== undefined && expire >= 1) metadata.expireAt = Math.floor(expire);
  return metadata;
}

/** Run at most one lease from the selected queue and use the named binding for its source URL. */
export async function runOneProviderJob(
  db: D1Database, bucket: R2Bucket, provider: ProviderFetcher | undefined, pin: ProviderPin, policy?: ProviderTelegramPolicy,
  includeBatch = false,
): Promise<ConsumerOutcome> {
  if (!provider || typeof pin.providerRevision !== "string" || !PROVIDER_REVISION.test(pin.providerRevision) ||
      typeof pin.imageSha256 !== "string" || !PROVIDER_SHA256.test(pin.imageSha256) ||
      !await providerSnapshotJournalReady(db)) return "disabled";
  const lease = await claimProviderJob(db, policy, includeBatch);
  if (lease === null) return "idle";
  if (lease.scope !== "generic" && !await isProviderJobCurrent(db, lease)) {
    await retireStaleProviderJob(db, lease);
    return "stale";
  }
  if (lease.leaseUntil * 1000 - Date.now() < LEASE_HEADROOM_MS) {
    return settleProviderJob(db, lease, { kind: "retry", reason: "timeout" });
  }
  let fetched: unknown;
  try {
    fetched = await callProvider(provider, lease, pin);
  } catch {
    return settleProviderJob(db, lease, { kind: "retry", reason: "unavailable" });
  }
  if (fetched === timedOut) return settleProviderJob(db, lease, { kind: "retry", reason: "timeout" });
  if (!record(fetched) || fetched.ok !== true) return settleProviderJob(db, lease, fetchFailure(fetched));
  if (!validBody(fetched) || digestHex(await crypto.subtle.digest("SHA-256", fetched.body)) !== fetched.bodySha256) {
    return settleProviderJob(db, lease, rejected);
  }

  const parsed = parseSubscriptionDocument(new Uint8Array(fetched.body));
  if (parsed.kind !== "parsed" || parsed.nodes.length === 0 || parsed.rejected.malformed || parsed.rejected.unsupported) {
    return settleProviderJob(db, lease, invalidDocument);
  }
  if (!await isProviderJobCurrent(db, lease)) {
    await retireStaleProviderJob(db, lease);
    return "stale";
  }
  let staged: StagedNodeSnapshot | null;
  try {
    staged = await stageProviderSnapshot(db, bucket, lease, parsed.nodes);
  } catch {
    return settleProviderJob(db, lease, { kind: "retry", reason: "storage-failed" });
  }
  const initialTitle = lease.scope !== "generic" && lease.kind === "url-import"
    && lease.expectedGeneration === 0 && lease.expectedLifecycleRevision === 0
    ? initialProviderTitle(fetched.metadata, lease.sourceUrl) : undefined;
  const outcome = staged
    ? await publishProviderSnapshot(db, lease, staged, subscriptionMetadata(fetched.metadata?.["subscription-userinfo"]), initialTitle)
    : "stale";
  if (outcome === "stale") await retireStaleProviderJob(db, lease);
  return outcome;
}
