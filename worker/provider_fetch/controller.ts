export const SERVICE = "subs-bot-provider-fetch-dev-01";
export const SINGLETON = "provider-fetch-v1";
export const REVISION = /^[0-9a-f]{40}(?![\s\S])/u;
const IMAGE = /^registry\.cloudflare\.com\/[0-9a-f]{32}\/subs-bot-provider-fetch-dev-01@sha256:[0-9a-f]{64}(?![\s\S])/u;
const IDLE_MS = 30_000;
const START_MS = 30_000;
const PORT = 8080;
const ORIGIN = "http://container";
const BLOCKED = ["http://127.0.0.1/", "http://[::1]/", "http://169.254.169.254/"];

type ProbeStage = "configuration" | "start" | "readiness" | "image" | "edge" | "address-policy" | "stop";

export class ProviderProbeError extends Error {
  constructor(readonly stage: ProbeStage) {
    super(`Provider container smoke failed during ${stage}.`);
  }
}

function requireResult(value: unknown, message: string): asserts value {
  if (!value) throw new Error(message);
}

async function smallBody(response: Response, limit: number): Promise<Uint8Array<ArrayBuffer>> {
  const length = response.headers.get("Content-Length");
  const reader = response.body?.getReader();
  const bytes = new Uint8Array(limit);
  let size = 0;
  let finished = false;
  try {
    requireResult(length === null || (/^[0-9]+$/u.test(length) && Number(length) <= limit), "Provider response size differs.");
    if (reader) {
      for (;;) {
        const part = await reader.read();
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
    if (reader && !finished) await reader.cancel().catch(() => {});
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

async function ready(port: Fetcher, revision: string): Promise<void> {
  const deadline = Date.now() + START_MS;
  while (Date.now() < deadline) {
    let response;
    try {
      response = await port.fetch(ORIGIN + "/ready", {
        redirect: "manual", signal: AbortSignal.timeout(Math.min(1500, Math.max(1, deadline - Date.now()))),
      });
    } catch {
      // The TCP port can be unavailable while the image starts.
    }
    if (response?.status === 200) {
      const value = json(await smallBody(response, 256));
      requireResult(privateResponse(response, 200, "application/json") && isRecord(value)
        && Object.keys(value).length === 2 && value.ok === true && value.revision === revision,
      "Provider container readiness revision differs.");
      return;
    }
    await response?.body?.cancel().catch(() => {});
    if (Date.now() < deadline) await new Promise<void>((resolve) => setTimeout(resolve, 250));
  }
  throw new Error("Provider container did not become ready.");
}

function post(port: Fetcher, path: "/v1/edge-proof" | "/v1/fetch", payload: { url: string } | Record<string, never>) {
  return port.fetch(ORIGIN + path, {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload),
    redirect: "manual", signal: AbortSignal.timeout(28_000),
  });
}

export async function exercise(container: Container, revision: string, isolatedRevision: string) {
  let stage: ProbeStage = "configuration";
  let started = false;
  try {
    const image = container.images.provider;
    requireResult(typeof image === "string" && IMAGE.test(image) && !container.running,
      "The provider container image or stopped state differs.");
    stage = "start";
    container.start({ image, instance: "lite", enableInternet: true });
    started = true;
    await container.setInactivityTimeout(IDLE_MS);
    stage = "readiness";
    const port = container.getTcpPort(PORT);
    await ready(port, revision);
    stage = "image";
    requireResult((await container.inspect())?.image === image, "The running provider image differs.");
    stage = "edge";
    const positive = await post(port, "/v1/edge-proof", {});
    const bytes = await smallBody(positive, 512);
    const families = positive.headers.get("X-Provider-Approved-Families");
    requireResult(privateResponse(positive, 200, "application/octet-stream") && (families === "4" || families === "6" || families === "4,6"),
      "The fixed provider edge request failed.");
    const value = json(bytes);
    const hash = await crypto.subtle.digest("SHA-256", bytes);
    const sha256 = Array.from(new Uint8Array(hash), (byte) => byte.toString(16).padStart(2, "0")).join("");
    requireResult(positive.headers.get("X-Provider-Body-Sha256") === sha256 && isRecord(value) && Object.keys(value).length === 3
      && value.ok === true && value.service === "subs-bot" && value.revision === isolatedRevision,
    "The fixed provider edge response differed.");
    stage = "address-policy";
    for (const url of BLOCKED) {
      const response = await post(port, "/v1/fetch", { url });
      const result = json(await smallBody(response, 128));
      requireResult(privateResponse(response, 422, "application/json") && isRecord(result)
        && Object.keys(result).length === 1 && result.error === "blocked-address",
      "The private address policy proof failed.");
    }
    return { ok: true, revision, isolatedRevision, imageSha256: image.split("@sha256:")[1], edgeStatus: 200,
      approvedDnsFamilies: families.split(",").map(Number), bodyBytes: bytes.byteLength, bodySha256: sha256,
      blockedPrivateTargets: BLOCKED.length, stopped: true };
  } catch {
    throw new ProviderProbeError(stage);
  } finally {
    if (started) {
      try {
        await container.destroy();
        requireResult(!container.running, "The provider container stop could not be confirmed.");
      } catch {
        throw new ProviderProbeError("stop");
      }
    }
  }
}
