export const SERVICE = "subs-bot-provider-fetch-dev-01";
export const SINGLETON = "provider-fetch-v1";
export const REVISION = /^[0-9a-f]{40}(?![\s\S])/u;
const IMAGE = /^registry\.cloudflare\.com\/[0-9a-f]{32}\/subs-bot-provider-fetch-dev-01@sha256:[0-9a-f]{64}(?![\s\S])/u;
const IDLE_MS = 30_000;
const START_MS = 30_000;
const FETCH_MS = 28_000;
const STOP_MS = 10_000;
const PORT = 8080;
const ORIGIN = "http://container";
const BLOCKED = ["http://127.0.0.1/", "http://[::1]/", "http://169.254.169.254/"];
const MAX_URL_BYTES = 8192;
const MAX_REQUEST_BYTES = 12 * 1024;
const MAX_BODY_BYTES = 10 * 1024 * 1024;
const MAX_METADATA_BYTES = 3072;
const SHA256 = /^[a-f0-9]{64}(?![\s\S])/u;
const encoder = new TextEncoder();
const metadataKeys = ["content-type", "content-disposition", "profile-title", "subscription-userinfo"] as const;
const failureStatuses = {
  "invalid-request": [400, 413], "invalid-url": [422], "blocked-address": [422], "busy": [429],
  "invalid-auth": [502], "dns-failed": [502], "tls-failed": [502], "unavailable": [502, 503],
  "timeout": [504], "invalid-redirect": [502], "redirect-limit": [502], "http-status": [502],
  "body-too-large": [502], "invalid-body": [502],
} as const;

export interface ProviderFetchInput { url: string }
type ProviderMetadata = Partial<Record<typeof metadataKeys[number], string>>;
type FailureCode = keyof typeof failureStatuses;
type ProviderFailure = { ok: false; code: FailureCode; retryable: boolean; upstreamStatus?: number };
export type ProviderFetchResult =
  | { ok: true; body: ArrayBuffer; bodySha256: string; metadata?: ProviderMetadata }
  | ProviderFailure;

export function providerFailure(code: FailureCode, upstreamStatus?: number): ProviderFailure {
  const retryable = code === "busy" || code === "timeout" || code === "dns-failed" || code === "unavailable"
    || (upstreamStatus !== undefined && (upstreamStatus === 408 || upstreamStatus === 429 || upstreamStatus >= 500));
  return { ok: false, code, retryable, ...(upstreamStatus === undefined ? {} : { upstreamStatus }) };
}

export function providerPayload(input: unknown): string | null {
  if (!isRecord(input) || Object.keys(input).length !== 1 || !Object.hasOwn(input, "url")) return null;
  const { url } = input;
  if (typeof url !== "string" || url.length > MAX_URL_BYTES || !/^https?:\/\//iu.test(url)
      || /[\s\\\u0000-\u001f\u007f-\u009f\ud800-\udfff]/u.test(url) || /%(?![a-f0-9]{2})/iu.test(url)
      || encoder.encode(url).byteLength > MAX_URL_BYTES) return null;
  const payload = JSON.stringify({ url });
  return encoder.encode(payload).byteLength <= MAX_REQUEST_BYTES ? payload : null;
}

type ProbeStage = "configuration" | "start" | "readiness" | "image" | "edge" | "address-policy" | "stop";

export class ProviderProbeError extends Error {
  readonly stage: ProbeStage;

  constructor(stage: ProbeStage) {
    super(`Provider container smoke failed during ${stage}.`);
    this.stage = stage;
  }
}

function requireResult(value: unknown, message: string): asserts value {
  if (!value) throw new Error(message);
}

function within<T>(promise: Promise<T>, signal: AbortSignal): Promise<T> {
  return new Promise((resolve, reject) => {
    const abort = () => reject(new Error("Provider operation timed out."));
    if (signal.aborted) abort();
    else signal.addEventListener("abort", abort, { once: true });
    void promise.then(resolve, reject).finally(() => signal.removeEventListener("abort", abort));
  });
}

async function smallBody(response: Response, limit: number, signal: AbortSignal): Promise<Uint8Array<ArrayBuffer>> {
  const length = response.headers.get("Content-Length");
  const reader = response.body?.getReader();
  const bytes = new Uint8Array(limit);
  let size = 0;
  let finished = false;
  try {
    requireResult(length === null || (/^[0-9]+$/u.test(length) && Number(length) <= limit), "Provider response size differs.");
    if (reader) {
      for (;;) {
        const part = await within(reader.read(), signal);
        if (part.done) break;
        requireResult(part.value.byteLength <= limit - size, "Provider response size differs.");
        bytes.set(part.value, size);
        size += part.value.byteLength;
      }
    }
    requireResult(length === null || Number(length) === size, "Provider response length differs.");
    finished = true;
    return bytes.subarray(0, size);
  } finally {
    if (reader && !finished) void reader.cancel().catch(() => {});
    reader?.releaseLock();
  }
}

function json(bytes: Uint8Array<ArrayBuffer>): unknown {
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes));
  } catch {
    throw new Error("Provider response was invalid.");
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function privateResponse(response: Response, status: number, media: string): boolean {
  return response.status === status && response.headers.get("Cache-Control") === "private, no-store"
    && response.headers.get("Referrer-Policy") === "no-referrer"
    && response.headers.get("X-Content-Type-Options") === "nosniff"
    && response.headers.get("Content-Type")?.split(";")[0] === media;
}

function cleanResponse(response: Response): boolean {
  return response.headers.get("Content-Encoding") === null && response.headers.get("Location") === null
    && response.headers.get("Set-Cookie") === null;
}

async function ready(port: Fetcher, revision: string, deadline: number): Promise<void> {
  while (Date.now() < deadline) {
    const signal = AbortSignal.timeout(Math.min(1500, Math.max(1, deadline - Date.now())));
    let response;
    try {
      response = await within(port.fetch(ORIGIN + "/ready", { redirect: "manual", signal }), signal);
    } catch {
      // The TCP port can be unavailable while the image starts.
    }
    if (response?.status === 200) {
      const value = json(await smallBody(response, 256, signal));
      requireResult(privateResponse(response, 200, "application/json") && cleanResponse(response) && isRecord(value)
        && Object.keys(value).length === 2 && value.ok === true && value.revision === revision,
      "Provider container readiness revision differs.");
      return;
    }
    void response?.body?.cancel().catch(() => {});
    const remaining = deadline - Date.now();
    if (remaining > 0) await new Promise<void>((resolve) => setTimeout(resolve, Math.min(250, remaining)));
  }
  throw new Error("Provider container did not become ready.");
}

function post(port: Fetcher, path: "/v1/edge-proof" | "/v1/fetch", body: string, signal: AbortSignal) {
  return within(port.fetch(ORIGIN + path, {
    method: "POST", headers: { "Content-Type": "application/json" }, body, redirect: "manual", signal,
  }), signal);
}

async function withPinnedContainer<T>(
  container: Container, revision: string, use: (port: Fetcher, image: string) => Promise<T>,
): Promise<T> {
  let stage: ProbeStage = "configuration";
  let started = false;
  try {
    const image = container.images.provider;
    requireResult(REVISION.test(revision) && typeof image === "string" && IMAGE.test(image) && !container.running,
      "The provider container image or stopped state differs.");
    const deadline = Date.now() + START_MS;
    const startup = AbortSignal.timeout(START_MS);
    stage = "start";
    container.start({ image, instance: "lite", enableInternet: true });
    started = true;
    await within(container.setInactivityTimeout(IDLE_MS), startup);
    stage = "readiness";
    const port = container.getTcpPort(PORT);
    await ready(port, revision, deadline);
    stage = "image";
    requireResult((await within(container.inspect(), startup))?.image === image, "The running provider image differs.");
    return await use(port, image);
  } catch (error) {
    throw error instanceof ProviderProbeError ? error : new ProviderProbeError(stage);
  } finally {
    if (started) {
      try {
        await within(container.destroy(), AbortSignal.timeout(STOP_MS));
        requireResult(!container.running, "The provider container stop could not be confirmed.");
      } catch {
        throw new ProviderProbeError("stop");
      }
    }
  }
}

async function sha256(bytes: Uint8Array<ArrayBuffer>): Promise<string> {
  const hash = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(hash), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function providerMetadata(header: string | null): ProviderMetadata | undefined {
  if (header === null) return undefined;
  const invalid = "Provider metadata differs.";
  requireResult(header.length <= 4 * Math.ceil(MAX_METADATA_BYTES / 3) && header.length % 4 === 0
    && /^[A-Za-z0-9_-]+={0,2}(?![\s\S])/u.test(header), invalid);
  const base64 = header.replaceAll("-", "+").replaceAll("_", "/");
  const text = atob(base64);
  requireResult(text.length <= MAX_METADATA_BYTES && btoa(text) === base64 && !/[^\x00-\x7f]/u.test(text), invalid);
  const value: unknown = JSON.parse(text);
  requireResult(isRecord(value) && Object.keys(value).every((key) => metadataKeys.some((allowed) => key === allowed))
    && Object.values(value).every((entry) => typeof entry === "string" && entry.length <= MAX_METADATA_BYTES
      && encoder.encode(entry).byteLength <= MAX_METADATA_BYTES && !/[\u0000-\u001f\u007f-\u009f\ud800-\udfff]/u.test(entry)), invalid);
  // The pinned Python endpoint sends compact ASCII JSON. This check also
  // rejects duplicate keys before they could be hidden by JSON.parse.
  const canonical = JSON.stringify(value).replace(/[\u0080-\uffff]/g,
    (char) => "\\u" + char.charCodeAt(0).toString(16).padStart(4, "0"));
  requireResult(text === canonical, invalid);
  return Object.keys(value).length === 0 ? undefined : value as ProviderMetadata;
}

async function fetchPort(port: Fetcher, payload: string): Promise<ProviderFetchResult> {
  const signal = AbortSignal.timeout(FETCH_MS);
  let response: Response;
  try {
    response = await post(port, "/v1/fetch", payload, signal);
  } catch {
    return providerFailure(signal.aborted ? "timeout" : "unavailable");
  }
  try {
    requireResult(cleanResponse(response), "Provider response headers differ.");
    if (response.status !== 200) {
      requireResult(privateResponse(response, response.status, "application/json"), "Provider error response differs.");
      const error = json(await smallBody(response, 256, signal));
      requireResult(isRecord(error) && typeof error.error === "string" && Object.hasOwn(failureStatuses, error.error),
        "Provider error category differs.");
      const code = error.error as FailureCode;
      requireResult((failureStatuses[code] as readonly number[]).includes(response.status), "Provider error status differs.");
      const upstream = error.upstreamStatus;
      requireResult(code === "http-status"
        ? Object.keys(error).length === 2 && typeof upstream === "number" && Number.isInteger(upstream)
          && upstream >= 100 && upstream <= 599 && upstream !== 200
        : Object.keys(error).length === 1, "Provider error fields differ.");
      return providerFailure(code, code === "http-status" ? upstream as number : undefined);
    }
    const length = response.headers.get("Content-Length");
    const hash = response.headers.get("X-Provider-Body-Sha256");
    requireResult(privateResponse(response, 200, "application/octet-stream") && length !== null
      && /^(?:0|[1-9][0-9]{0,7})(?![\s\S])/u.test(length) && Number(length) <= MAX_BODY_BYTES
      && hash !== null && SHA256.test(hash), "Provider response size or digest header differs.");
    const metadata = providerMetadata(response.headers.get("X-Provider-Metadata"));
    const bytes = await smallBody(response, Number(length), signal);
    requireResult(await within(sha256(bytes), signal) === hash, "Provider body digest differs.");
    return { ok: true, body: bytes.buffer, bodySha256: hash, ...(metadata === undefined ? {} : { metadata }) };
  } catch {
    if (!response.bodyUsed) void response.body?.cancel().catch(() => {});
    return providerFailure(signal.aborted ? "timeout" : "invalid-body");
  }
}

export async function fetchPinnedProvider(container: Container, revision: string, payload: string): Promise<ProviderFetchResult> {
  try {
    return await withPinnedContainer(container, revision, (port) => fetchPort(port, payload));
  } catch {
    return providerFailure("unavailable");
  }
}

export async function exercise(container: Container, revision: string, isolatedRevision: string) {
  return withPinnedContainer(container, revision, async (port, image) => {
    let stage: ProbeStage = "edge";
    try {
      const signal = AbortSignal.timeout(FETCH_MS);
      const positive = await post(port, "/v1/edge-proof", "{}", signal);
      const bytes = await smallBody(positive, 512, signal);
      const families = positive.headers.get("X-Provider-Approved-Families");
      requireResult(privateResponse(positive, 200, "application/octet-stream") && (families === "4" || families === "6" || families === "4,6"),
        "The fixed provider edge request failed.");
      const value = json(bytes);
      const hash = await within(sha256(bytes), signal);
      requireResult(positive.headers.get("X-Provider-Body-Sha256") === hash && isRecord(value) && Object.keys(value).length === 3
        && value.ok === true && value.service === "subs-bot" && value.revision === isolatedRevision,
      "The fixed provider edge response differed.");
      stage = "address-policy";
      for (const url of BLOCKED) {
        const signal = AbortSignal.timeout(FETCH_MS);
        const response = await post(port, "/v1/fetch", JSON.stringify({ url }), signal);
        const result = json(await smallBody(response, 128, signal));
        requireResult(privateResponse(response, 422, "application/json") && isRecord(result)
          && Object.keys(result).length === 1 && result.error === "blocked-address", "The private address policy proof failed.");
      }
      return { ok: true, revision, isolatedRevision, imageSha256: image.split("@sha256:")[1], edgeStatus: 200,
        approvedDnsFamilies: families.split(",").map(Number), bodyBytes: bytes.byteLength, bodySha256: hash,
        blockedPrivateTargets: BLOCKED.length, stopped: true };
    } catch {
      throw new ProviderProbeError(stage);
    }
  });
}
