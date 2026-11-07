import type { TelegramPolicy } from "./protocol.ts";

const BOT_API = "https://api.telegram.org";
const MAX_METADATA_BYTES = 16 * 1024;
const MAX_TIMEOUT_MS = 20_000;
const BOT_TOKEN = /^[1-9][0-9]{0,18}:[A-Za-z0-9_-]{1,128}(?![\s\S])/u;
const FILE_ID = /^[!-~]{1,512}(?![\s\S])/u;
const PATH_COMPONENT = /^[A-Za-z0-9._-]{1,128}(?![\s\S])/u;

export const MAX_TELEGRAM_DOCUMENT_BYTES = 10 * 1024 * 1024;

type PermanentReason = "invalid-request" | "invalid-response" | "rejected" | "too-large" | "size-mismatch";
type RetryReason = "timeout" | "rate-limited" | "unavailable";
type Deadline = { signal: AbortSignal; expiresAt: number };

export type TelegramDocumentResult =
  | { kind: "downloaded"; bytes: Uint8Array<ArrayBuffer> }
  | { kind: "permanent"; reason: PermanentReason }
  | { kind: "retryable"; reason: RetryReason };

class InvalidDocumentResponse extends Error {
  readonly reason: PermanentReason;

  constructor(reason: PermanentReason) {
    super("Telegram document response failed validation.");
    this.reason = reason;
  }
}

function record(value: unknown): Record<string, unknown> | undefined {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? value as Record<string, unknown> : undefined;
}

function validSize(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function safeFilePath(value: unknown): value is string {
  return typeof value === "string" && value.length <= 1024 && value.split("/").every((part) =>
    PATH_COMPONENT.test(part) && part !== "." && part !== "..");
}

function discard(response: Response): void {
  void response.body?.cancel().catch(() => {});
}

function expired({ signal, expiresAt }: Deadline): boolean {
  return signal.aborted || Date.now() >= expiresAt;
}

function requireTime(deadline: Deadline): void {
  if (expired(deadline)) throw new Error("Telegram document deadline elapsed.");
}

function statusFailure(
  response: Response,
  deadline: Deadline,
): Exclude<TelegramDocumentResult, { kind: "downloaded" }> | undefined {
  if (expired(deadline)) {
    discard(response);
    return { kind: "retryable", reason: "timeout" };
  }
  if (!response.redirected && response.status === 200) return undefined;
  discard(response);
  if (response.redirected) return { kind: "permanent", reason: "invalid-response" };
  if (response.status === 429) return { kind: "retryable", reason: "rate-limited" };
  if (response.status === 408 || response.status >= 500) return { kind: "retryable", reason: "unavailable" };
  return { kind: "permanent", reason: response.status >= 400 ? "rejected" : "invalid-response" };
}

function responseLength(response: Response): number | undefined {
  const encoding = response.headers.get("Content-Encoding");
  const length = response.headers.get("Content-Length");
  if (encoding !== null && encoding.toLowerCase() !== "identity") {
    throw new InvalidDocumentResponse("invalid-response");
  }
  if (length === null) return undefined;
  if (!/^[0-9]{1,16}(?![\s\S])/u.test(length) || !validSize(Number(length))) {
    throw new InvalidDocumentResponse("invalid-response");
  }
  return Number(length);
}

async function readBody(
  response: Response,
  deadline: Deadline,
  maximum: number,
  oversized: "invalid-response" | "too-large",
  expected?: number,
): Promise<Uint8Array<ArrayBuffer>> {
  const { signal } = deadline;
  const reader = response.body?.getReader();
  const cancel = () => { void reader?.cancel().catch(() => {}); };
  let complete = false;
  signal.addEventListener("abort", cancel, { once: true });
  try {
    requireTime(deadline);
    const declared = responseLength(response);
    if (declared !== undefined && declared > maximum) throw new InvalidDocumentResponse(oversized);
    if (expected !== undefined && declared !== undefined && declared !== expected) {
      throw new InvalidDocumentResponse("size-mismatch");
    }
    const exact = expected ?? declared;
    let bytes = new Uint8Array(exact ?? Math.min(maximum, 64 * 1024));
    let size = 0;
    if (reader) {
      for (;;) {
        const part = await reader.read();
        requireTime(deadline);
        if (part.done) break;
        const end = size + part.value.byteLength;
        if (end > maximum) throw new InvalidDocumentResponse(oversized);
        if (exact !== undefined && end > exact) throw new InvalidDocumentResponse("size-mismatch");
        if (end > bytes.byteLength) {
          const expanded = new Uint8Array(Math.min(maximum, Math.max(end, bytes.byteLength * 2)));
          expanded.set(bytes);
          bytes = expanded;
        }
        bytes.set(part.value, size);
        size = end;
      }
    }
    if (exact !== undefined && size !== exact) throw new InvalidDocumentResponse("size-mismatch");
    complete = true;
    return bytes.subarray(0, size);
  } finally {
    signal.removeEventListener("abort", cancel);
    if (!complete) cancel();
    reader?.releaseLock();
  }
}

function fileMetadata(bytes: Uint8Array<ArrayBuffer>): Record<string, unknown> | undefined {
  try {
    const payload = record(JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes)) as unknown);
    if (payload?.ok === true) return record(payload.result);
  } catch {
    // Decoding errors can include the upstream body.
  }
  return undefined;
}

/** Resolve and download one admitted Bot API document within a single time budget. */
export async function downloadTelegramDocument(
  policy: Pick<TelegramPolicy, "botId" | "botToken">,
  { fileId, expectedSize }: { fileId: string; expectedSize?: number },
  { request = fetch, timeoutMs = MAX_TIMEOUT_MS }: { request?: typeof fetch; timeoutMs?: number } = {},
): Promise<TelegramDocumentResult> {
  const { botId, botToken } = policy;
  if (typeof botToken !== "string" || typeof botId !== "string" || !BOT_TOKEN.test(botToken) ||
      !botToken.startsWith(`${botId}:`) || typeof fileId !== "string" || !FILE_ID.test(fileId) ||
      (expectedSize !== undefined && !validSize(expectedSize)) ||
      !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > MAX_TIMEOUT_MS) {
    return { kind: "permanent", reason: "invalid-request" };
  }
  if (expectedSize !== undefined && expectedSize > MAX_TELEGRAM_DOCUMENT_BYTES) {
    return { kind: "permanent", reason: "too-large" };
  }

  const deadline = { expiresAt: Date.now() + timeoutMs, signal: AbortSignal.timeout(timeoutMs) };
  const common = { cache: "no-store", redirect: "manual", signal: deadline.signal } as const;
  try {
    const metadataResponse = await request(`${BOT_API}/bot${botToken}/getFile`, {
      ...common, method: "POST", headers: {
        "Content-Type": "application/json", "Accept": "application/json", "Accept-Encoding": "identity",
      }, body: JSON.stringify({ file_id: fileId }),
    });
    const metadataFailure = statusFailure(metadataResponse, deadline);
    if (metadataFailure) return metadataFailure;
    const metadata = fileMetadata(await readBody(metadataResponse, deadline, MAX_METADATA_BYTES, "invalid-response"));
    requireTime(deadline);
    const path = metadata?.file_path;
    const size = metadata?.file_size;
    if (!safeFilePath(path) || (size !== undefined && !validSize(size))) {
      return { kind: "permanent", reason: "invalid-response" };
    }
    if (size !== undefined && size > MAX_TELEGRAM_DOCUMENT_BYTES) return { kind: "permanent", reason: "too-large" };
    if (size !== undefined && expectedSize !== undefined && size !== expectedSize) {
      return { kind: "permanent", reason: "size-mismatch" };
    }

    const fileResponse = await request(`${BOT_API}/file/bot${botToken}/${path}`, {
      ...common, method: "GET", headers: { "Accept-Encoding": "identity" },
    });
    const fileFailure = statusFailure(fileResponse, deadline);
    if (fileFailure) return fileFailure;
    const bytes = await readBody(fileResponse, deadline, MAX_TELEGRAM_DOCUMENT_BYTES, "too-large", expectedSize ?? size);
    requireTime(deadline);
    return { kind: "downloaded", bytes };
  } catch (error) {
    if (expired(deadline)) return { kind: "retryable", reason: "timeout" };
    if (error instanceof InvalidDocumentResponse) return { kind: "permanent", reason: error.reason };
    return { kind: "retryable", reason: "unavailable" };
  }
}
