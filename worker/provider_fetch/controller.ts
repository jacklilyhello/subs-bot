import {
  PROVIDER_API_STATUS_MAX_ELAPSED_MS as API_STATUS_MAX_ELAPSED_MS,
  PROVIDER_MAX_BODY_BYTES as MAX_BODY_BYTES, PROVIDER_MAX_METADATA_BYTES as MAX_METADATA_BYTES,
  PROVIDER_METADATA_FIELDS as metadataKeys, PROVIDER_REVISION as REVISION, PROVIDER_SHA256 as SHA256,
  type ProviderApiStatusFailureCode, type ProviderApiStatusInput, type ProviderApiStatusResult, type ProviderApiStatusV2Input,
  type ProviderFailureCode, type ProviderFetchInput, type ProviderFetchResult, type ProviderMetadata,
} from "../src/provider-fetch-contract.ts";

export const SERVICE = "subs-bot-provider-fetch-dev-01";
export const SINGLETON = "provider-fetch-v1";
export { REVISION };
const IMAGE = /^registry\.cloudflare\.com\/[0-9a-f]{32}\/subs-bot-provider-fetch-dev-01@sha256:[0-9a-f]{64}(?![\s\S])/u;
const IDLE_MS = 30_000;
const START_MS = 30_000;
const FETCH_MS = 28_000;
const API_STATUS_MS = 20_000;
const API_STATUS_V2_MAX_AHEAD_MS = 30_000;
const API_STATUS_V2_DISPATCH_MARGIN_MS = 1_000;
const STOP_MS = 10_000;
const PORT = 8080;
const ORIGIN = "http://container";
const BLOCKED = ["http://127.0.0.1/", "http://[::1]/", "http://169.254.169.254/"];
const MAX_URL_BYTES = 8192;
const MAX_REQUEST_BYTES = 12 * 1024;
const API_AUTHORITY = /^(?:\[[^\[\]]+\]|[^:\[\]]+)(?::[0-9]{1,5})?$/u;
const encoder = new TextEncoder();
const failureStatuses = {
  "invalid-request": [400, 413], "invalid-url": [422], "blocked-address": [422], "busy": [429],
  "invalid-auth": [502], "dns-failed": [502], "tls-failed": [502], "unavailable": [502, 503],
  "timeout": [504], "invalid-redirect": [502], "redirect-limit": [502], "http-status": [502],
  "body-too-large": [502], "invalid-body": [502],
} as const satisfies Record<ProviderFailureCode, readonly number[]>;
const apiStatusFailureStatuses = {
  "invalid-request": failureStatuses["invalid-request"],
  "invalid-url": failureStatuses["invalid-url"],
  "invalid-auth": failureStatuses["invalid-auth"],
  "blocked-address": failureStatuses["blocked-address"],
  "busy": failureStatuses.busy,
  "dns-failed": failureStatuses["dns-failed"],
  "tls-failed": failureStatuses["tls-failed"],
  "unavailable": failureStatuses.unavailable,
  "timeout": failureStatuses.timeout,
} as const satisfies Record<Exclude<ProviderApiStatusFailureCode, "invalid-body">, readonly number[]>;

type FailureCode = ProviderFailureCode;
type ProviderFailure = Extract<ProviderFetchResult, { ok: false }>;

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

export function providerRequest(input: unknown): ProviderFetchInput | null {
  if (!isRecord(input) || Object.keys(input).length !== 3 || !Object.hasOwn(input, "url")
      || !Object.hasOwn(input, "providerRevision") || !Object.hasOwn(input, "imageSha256")) return null;
  const { url, providerRevision, imageSha256 } = input;
  if (typeof url !== "string" || providerPayload({ url }) === null
      || typeof providerRevision !== "string" || !REVISION.test(providerRevision)
      || typeof imageSha256 !== "string" || !SHA256.test(imageSha256)) return null;
  return { url, providerRevision, imageSha256 };
}

export function providerApiStatusRequest(input: unknown): ProviderApiStatusInput | null {
  if (!isRecord(input) || Object.keys(input).length !== 4
    || !["url", "key", "providerRevision", "imageSha256"].every((field) => Object.hasOwn(input, field))) return null;
  const { url, key, providerRevision, imageSha256 } = input;
  const pinned = providerRequest({ url, providerRevision, imageSha256 });
  if (!pinned || typeof key !== "string" || !/^[!-~]{1,512}(?![\s\S])/u.test(key)) return null;
  const endpoint = /^https:\/\/([^/?#]+)(\/[^?#]*)(?![\s\S])/iu.exec(pinned.url);
  if (!endpoint || /[@%]/u.test(endpoint[1]) || !API_AUTHORITY.test(endpoint[1])
    || !(endpoint[2].endsWith("/models") || endpoint[2].endsWith("/chat/completions"))) return null;
  try {
    // The Container independently validates DNS, public addresses and the socket.
    if (new URL(pinned.url).port !== "") return null;
  } catch {
    return null;
  }
  return encoder.encode(JSON.stringify({ url: pinned.url, key })).byteLength <= MAX_REQUEST_BYTES ? { ...pinned, key } : null;
}

export function providerApiStatusV2Request(input: unknown): ProviderApiStatusV2Input | null {
  if (!isRecord(input) || Object.keys(input).length !== 5
    || !["url", "key", "providerRevision", "imageSha256", "dispatchBeforeMs"].every((field) => Object.hasOwn(input, field))) return null;
  const { url, key, providerRevision, imageSha256, dispatchBeforeMs } = input;
  if (typeof dispatchBeforeMs !== "number" || !Number.isSafeInteger(dispatchBeforeMs) || dispatchBeforeMs < 1
    || dispatchBeforeMs > Date.now() + API_STATUS_V2_MAX_AHEAD_MS) return null;
  const request = providerApiStatusRequest({ url, key, providerRevision, imageSha256 });
  return request && encoder.encode(JSON.stringify({ url, key, dispatchBeforeMs })).byteLength <= MAX_REQUEST_BYTES
    ? { ...request, dispatchBeforeMs } : null;
}

export function providerApiStatusV2Expired(dispatchBeforeMs: number): boolean {
  return Date.now() >= dispatchBeforeMs - API_STATUS_V2_DISPATCH_MARGIN_MS;
}

export function apiStatusFailure(code: ProviderApiStatusFailureCode): Extract<ProviderApiStatusResult, { ok: false }> {
  return { ok: false, code };
}

function apiStatusSuccess(status: unknown, elapsedMs: unknown): Extract<ProviderApiStatusResult, { ok: true }> | null {
  if (typeof status !== "number" || !Number.isInteger(status) || status < 100 || status > 599
    || typeof elapsedMs !== "number" || !Number.isInteger(elapsedMs) || elapsedMs < 0 || elapsedMs > API_STATUS_MAX_ELAPSED_MS) return null;
  return { ok: true, status, elapsedMs };
}

export function providerApiStatusResult(value: unknown): ProviderApiStatusResult {
  if (isRecord(value)) {
    const fields = Object.keys(value).length;
    if (value.ok === true && fields === 3 && Object.hasOwn(value, "ok") && Object.hasOwn(value, "status")
      && Object.hasOwn(value, "elapsedMs")) return apiStatusSuccess(value.status, value.elapsedMs) ?? apiStatusFailure("invalid-body");
    if (value.ok === false && fields === 2 && Object.hasOwn(value, "ok") && Object.hasOwn(value, "code")
      && typeof value.code === "string" && (value.code === "invalid-body" || Object.hasOwn(apiStatusFailureStatuses, value.code))) {
      return apiStatusFailure(value.code as ProviderApiStatusFailureCode);
    }
  }
  return apiStatusFailure("invalid-body");
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

function json(bytes: Uint8Array<ArrayBuffer>, exact = false): unknown {
  try {
    const text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
    const value: unknown = JSON.parse(text);
    // This protocol has only fixed ASCII names, integer values and closed error codes.
    if (exact && text.replace(/[ \t\r\n]/gu, "") !== JSON.stringify(value)) throw new Error();
    return value;
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

function post(port: Fetcher, path: "/v1/edge-proof" | "/v1/fetch" | "/v1/api-status" | "/v2/api-status", body: string, signal: AbortSignal) {
  return within(port.fetch(ORIGIN + path, {
    method: "POST", headers: { "Content-Type": "application/json" }, body, redirect: "manual", signal,
  }), signal);
}

async function withPinnedContainer<T>(
  container: Container, revision: string, use: (port: Fetcher, image: string) => Promise<T>, expectedImageSha256?: string,
  startupDeadline?: number,
): Promise<T> {
  let stage: ProbeStage = "configuration";
  let started = false;
  try {
    const image = container.images.provider;
    requireResult(REVISION.test(revision) && typeof image === "string" && IMAGE.test(image) && !container.running,
      "The provider container image or stopped state differs.");
    requireResult(expectedImageSha256 === undefined || image.endsWith(`@sha256:${expectedImageSha256}`),
      "The provider container image does not match the caller's pin.");
    const now = Date.now();
    const deadline = Math.min(now + START_MS, startupDeadline ?? Infinity);
    requireResult(deadline > now, "The provider startup deadline elapsed.");
    const startup = AbortSignal.timeout(deadline - now);
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

export async function fetchPinnedProvider(container: Container, revision: string, payload: string, imageSha256: string): Promise<ProviderFetchResult> {
  try {
    if (typeof imageSha256 !== "string" || !SHA256.test(imageSha256)) return providerFailure("invalid-request");
    return await withPinnedContainer(container, revision, (port) => fetchPort(port, payload), imageSha256);
  } catch {
    return providerFailure("unavailable");
  }
}

async function apiStatusPort(port: Fetcher, url: string, key: string, dispatchBeforeMs?: number): Promise<ProviderApiStatusResult> {
  const timeout = dispatchBeforeMs === undefined ? API_STATUS_MS
    : Math.min(API_STATUS_MS, dispatchBeforeMs - API_STATUS_V2_DISPATCH_MARGIN_MS - Date.now());
  if (timeout <= 0) return apiStatusFailure("timeout");
  const signal = AbortSignal.timeout(timeout);
  let response: Response;
  try {
    // A request carrying a key is submitted once, even if the outcome is unknown.
    const path = dispatchBeforeMs === undefined ? "/v1/api-status" : "/v2/api-status";
    const body = JSON.stringify({ url, key, dispatchBeforeMs });
    if (dispatchBeforeMs !== undefined && providerApiStatusV2Expired(dispatchBeforeMs)) return apiStatusFailure("timeout");
    response = await post(port, path, body, signal);
  } catch {
    return apiStatusFailure(signal.aborted ? "timeout" : "unavailable");
  }
  try {
    requireResult(privateResponse(response, response.status, "application/json") && cleanResponse(response),
      "Provider API status response headers differ.");
    const value = json(await smallBody(response, 256, signal), true);
    requireResult(isRecord(value), "Provider API status response is invalid.");
    const fields = Object.keys(value).length;
    if (response.status === 200 && fields === 2 && Object.hasOwn(value, "status") && Object.hasOwn(value, "elapsedMs")) {
      const result = apiStatusSuccess(value.status, value.elapsedMs);
      if (result) return result;
    } else if (response.status !== 200 && fields === 1 && Object.hasOwn(value, "error")
      && typeof value.error === "string" && Object.hasOwn(apiStatusFailureStatuses, value.error)) {
      const code = value.error as keyof typeof apiStatusFailureStatuses;
      if ((apiStatusFailureStatuses[code] as readonly number[]).includes(response.status)) return apiStatusFailure(code);
    }
    return apiStatusFailure("invalid-body");
  } catch {
    if (!response.bodyUsed) void response.body?.cancel().catch(() => {});
    return apiStatusFailure(signal.aborted ? "timeout" : "invalid-body");
  }
}

export async function probePinnedProviderApiStatus(container: Container, input: ProviderApiStatusInput): Promise<ProviderApiStatusResult> {
  try {
    const request = providerApiStatusRequest(input);
    if (!request) return apiStatusFailure("invalid-request");
    return await withPinnedContainer(container, request.providerRevision, (port) => apiStatusPort(port, request.url, request.key),
      request.imageSha256);
  } catch {
    return apiStatusFailure("unavailable");
  }
}

export async function probePinnedProviderApiStatusV2(container: Container, input: ProviderApiStatusV2Input): Promise<ProviderApiStatusResult> {
  const request = providerApiStatusV2Request(input);
  if (!request) return apiStatusFailure("invalid-request");
  const { url, key, providerRevision, imageSha256, dispatchBeforeMs } = request;
  if (providerApiStatusV2Expired(dispatchBeforeMs)) return apiStatusFailure("timeout");
  try {
    return await withPinnedContainer(container, providerRevision, (port) => apiStatusPort(port, url, key, dispatchBeforeMs),
      imageSha256, dispatchBeforeMs - API_STATUS_V2_DISPATCH_MARGIN_MS);
  } catch {
    return apiStatusFailure(providerApiStatusV2Expired(dispatchBeforeMs) ? "timeout" : "unavailable");
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
