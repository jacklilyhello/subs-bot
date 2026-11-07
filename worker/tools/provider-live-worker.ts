/** Run one private transport replay through the emitted Worker. The caller discards process output. */

import { createHash, randomBytes } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { Miniflare } from "miniflare";

import { ClashContentError, serializeClashProxy } from "../src/clash-export.ts";
import { enqueueProviderUrlImport, providerHost } from "../src/provider-jobs.ts";
import { serializeSingBoxOutbound, SingBoxContentError } from "../src/singbox-export.ts";
import {
  getOwnedSubscription, getSubscriptionSnapshot, planSnapshotRead, readPlannedSnapshotNodes, type NodeRecord,
} from "../src/storage.ts";
import { isValidStoredShare } from "../src/stored-share.ts";
import { serializeStructuredShare } from "../src/structured-share.ts";
import { parseSubscriptionDocument } from "../src/subscription-document.ts";
import { parseTextProxy, TextExportError } from "../src/text-export.ts";

const OWNER = "91001";
const PROVIDER_REVISION = "a".repeat(40);
const IMAGE_SHA256 = "b".repeat(64);
const MAX_BODY = 10 * 1024 * 1024;
const MAX_CONFIG = 16 * 1024 * 1024;
const FORMATS = {
  base64: ["base64", "mixed", "v2ray"],
  clash: ["", "clash"],
  singbox: ["singbox", "sing-box"],
  surge: ["surge"],
  qx: ["qx", "quantumult", "quantumultx"],
};
type Format = keyof typeof FORMATS;
type Counts = Record<string, number>;
const FORMAT_NAMES = Object.keys(FORMATS) as Format[];
const FAMILIES = new Set(["ss", "vmess", "vless", "trojan", "hysteria", "hysteria2", "tuic", "anytls", "socks", "http"]);
const PROVIDER = `
  import { WorkerEntrypoint } from "cloudflare:workers";
  export class ProviderFetch extends WorkerEntrypoint {
    async fetchSubscription(input) {
      if (Object.keys(input).length !== 3 || input.url !== this.env.SOURCE ||
          input.providerRevision !== this.env.REVISION || input.imageSha256 !== this.env.IMAGE) {
        throw new Error("Provider replay identity differs.");
      }
      const saved = await this.env.RESPONSE.get("response");
      if (!saved) throw new Error("Provider replay body is missing.");
      return {ok:true, body:await saved.arrayBuffer(), bodySha256:this.env.BODY_SHA256,
        ...(this.env.METADATA === "null" ? {} : {metadata:JSON.parse(this.env.METADATA)})};
    }
  }
  export default {fetch(){return new Response(null,{status:404})}};
`;

function requireCheck(value: unknown): asserts value {
  if (!value) throw new Error("Private Worker replay could not be verified.");
}

function sha256(value: Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

function family(node: NodeRecord): string {
  const type = node.type;
  if (type === "shadowsocks") return "ss";
  if (type === "hy2") return "hysteria2";
  if (type === "socks5") return "socks";
  if (type === "https") return "http";
  return typeof type === "string" && FAMILIES.has(type) ? type : "other";
}

function admissible(format: Format, node: NodeRecord): boolean {
  if (format === "base64") {
    const stored = node.share;
    return stored === undefined || stored === null || stored === ""
      ? serializeStructuredShare(node) !== null : isValidStoredShare(stored);
  }
  try {
    if (format === "clash") serializeClashProxy(node);
    else if (format === "singbox") serializeSingBoxOutbound(node);
    else parseTextProxy(node, format);
    return true;
  } catch (error) {
    if (error instanceof ClashContentError || error instanceof SingBoxContentError || error instanceof TextExportError) return false;
    throw error;
  }
}

function object(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function rejectedTraits(node: NodeRecord): string[] {
  const traits: string[] = [];
  if (node["client-fingerprint"] === "randomized") traits.push("randomized-fingerprint");
  if (node["packet-encoding"] === "none" || node.packet_encoding === "none") traits.push("packet-encoding-none");
  if (object(node.tls)) traits.push("nested-tls");
  const ws = node["ws-opts"];
  if (object(ws) && object(ws.headers) && Object.values(ws.headers).some(Array.isArray)) traits.push("ws-header-array");
  return traits;
}

function increment(counts: Counts, name: string): void {
  counts[name] = (counts[name] ?? 0) + 1;
}

function diagnosticCounter() {
  const protocols: Counts = {};
  const formats = Object.fromEntries(FORMAT_NAMES.map((format) => [format, {
    admitted: {} as Counts, rejected: {} as Counts, rejectedTraits: {} as Counts,
  }]));
  return {
    value: { protocols, formats },
    add(node: NodeRecord) {
      const protocol = family(node);
      increment(protocols, protocol);
      const traits = rejectedTraits(node);
      for (const format of FORMAT_NAMES) {
        const result = formats[format];
        if (admissible(format, node)) increment(result.admitted, protocol);
        else {
          increment(result.rejected, protocol);
          for (const trait of traits) increment(result.rejectedTraits, trait);
        }
      }
    },
  };
}

async function readBody(response: Response, limit: number): Promise<Buffer> {
  const reader = response.body?.getReader();
  requireCheck(reader);
  const pieces: Uint8Array[] = [];
  let length = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      length += value.byteLength;
      requireCheck(length <= limit);
      pieces.push(value);
    }
  } finally {
    await reader.cancel().catch(() => {});
  }
  return Buffer.concat(pieces, length);
}

async function readExports(runtime: Miniflare, token: string, output: string) {
  const formats = {};
  for (const [format, aliases] of Object.entries(FORMATS)) {
    const limit = format === "base64" ? 4 * Math.ceil(MAX_CONFIG / 3) : MAX_CONFIG;
    let primary: { status: number; bytes: number; sha: string | null } | undefined;
    for (const alias of aliases) {
      const url = `https://fixture.invalid/sub/${token}${alias ? "/" + alias : ""}`;
      const headers = { "Accept-Encoding": "identity" };
      const head = await runtime.dispatchFetch(url, { method: "HEAD", headers });
      const response = await runtime.dispatchFetch(url, { headers });
      requireCheck(head.status === response.status && head.body === null &&
        [head, response].every((result) => result.headers.get("Cache-Control") === "private, no-store" &&
          result.headers.get("Referrer-Policy") === "no-referrer"));
      requireCheck(response.status === 200 || response.status === 422);
      const body = await readBody(response, response.ok ? limit : 128);
      if (!response.ok) requireCheck(body.toString() === "Subscription content cannot be exported.");
      const length = response.headers.get("Content-Length");
      requireCheck(length === null || Number(length) === body.length);
      const result = { status: response.status, bytes: body.length, sha: response.ok ? sha256(body) : null };
      if (primary) {
        requireCheck(primary.status === result.status && primary.bytes === result.bytes && primary.sha === result.sha);
      } else {
        primary = result;
        if (response.ok) await writeFile(join(output, `${format}.body`), body, { flag: "wx", mode: 0o600 });
      }
    }
    requireCheck(primary);
    Object.assign(formats, { [format]: { status: primary.status, bytes: primary.status === 200 ? primary.bytes : 0 } });
  }
  return formats;
}

async function run(bundle: string, bodyFile: string, output: string, controls: string) {
  const { source, rpcMetadata, bodySha256, decodedBytes } = JSON.parse(controls);
  requireCheck(typeof source === "string" && typeof bodySha256 === "string" && Number.isInteger(decodedBytes) &&
    decodedBytes >= 0 && decodedBytes <= MAX_BODY);
  const body = await readFile(bodyFile);
  requireCheck(body.length === decodedBytes && sha256(body) === bodySha256);
  const parsed = parseSubscriptionDocument(body);
  const document = {
    kind: parsed.kind, format: parsed.format, envelope: parsed.envelope,
    nodes: parsed.nodes.length, malformed: parsed.rejected.malformed, unsupported: parsed.rejected.unsupported,
    ignored: parsed.ignored, ...(parsed.kind === "limit" ? { limit: parsed.limit } : {}),
  };
  if (!providerHost(source)) return { document, job: "source-rejected" };

  const manifest = JSON.parse(await readFile(join(bundle, "isolation.json"), "utf8"));
  const script = await readFile(join(bundle, "index.js"), "utf8");
  const noNetwork = () => { throw new Error("Private replay attempted network access."); };
  const runtime = new Miniflare({ workers: [
    { name: "app", modules: true, script, compatibilityDate: manifest.compatibilityDate,
      d1Databases: { DB: "private-replay" }, r2Buckets: ["NODES"], outboundService: noNetwork,
      serviceBindings: { PROVIDER_FETCH: { name: "provider", entrypoint: "ProviderFetch" } },
      bindings: { BUILD_REVISION: manifest.revision, PROVIDER_REVISION, PROVIDER_IMAGE_SHA256: IMAGE_SHA256 } },
    { name: "provider", modules: true, script: PROVIDER, compatibilityDate: manifest.compatibilityDate,
      r2Buckets: ["RESPONSE"], outboundService: noNetwork,
      bindings: { SOURCE: source, REVISION: PROVIDER_REVISION, IMAGE: IMAGE_SHA256,
        BODY_SHA256: bodySha256, METADATA: JSON.stringify(rpcMetadata ?? null) } },
  ] });
  try {
    const db = await runtime.getD1Database("DB", "app");
    const bucket = await runtime.getR2Bucket("NODES", "app");
    const replay = await runtime.getR2Bucket("RESPONSE", "provider");
    await replay.put("response", new Uint8Array(body).buffer);
    for (const migration of manifest.migrations) {
      const sql = await readFile(join(bundle, migration.name), "utf8");
      await db.batch(sql.trim().split(/;\s*/u).filter(Boolean).map((statement) => db.prepare(statement)));
    }
    const job = await enqueueProviderUrlImport(db, { ownerId: OWNER, sourceUrl: source,
      requestKey: randomBytes(32).toString("hex"), name: "Private replay" });
    requireCheck(job.kind === "queued");
    const before = await getOwnedSubscription(db, OWNER, job.subscriptionId);
    requireCheck(before?.sourceUrl === source && before.generation === 0);
    const app = await runtime.getWorker("app");
    requireCheck((await app.scheduled({ cron: "* * * * *" })).outcome === "ok");
    const row = await db.prepare(`SELECT state, result_code AS result, failure_code AS failure, attempts
      FROM subscription_provider_jobs WHERE job_id=?`).bind(job.jobId)
      .first<{ state: string; result: string | null; failure: string | null; attempts: number }>();
    requireCheck(row?.attempts === 1);
    const owned = await getOwnedSubscription(db, OWNER, job.subscriptionId);
    requireCheck(owned?.sourceUrl === source && owned.token === before.token);
    if (row.state === "done" && (row.result === "invalid-document" || row.result === "fetch-rejected")) {
      requireCheck(owned.generation === 0);
      return { document, job: row.result };
    }
    requireCheck(row.state === "done" && row.result === "saved" && row.failure === null && owned.generation === 1);
    const snapshot = await getSubscriptionSnapshot(db, owned.token);
    requireCheck(snapshot?.nodeCount === owned.nodeCount);
    const plan = await planSnapshotRead(bucket, snapshot);
    const diagnostics = diagnosticCounter();
    let count = 0;
    for await (const node of readPlannedSnapshotNodes(bucket, plan)) {
      diagnostics.add(node);
      count += 1;
    }
    requireCheck(count === document.nodes && count === snapshot.nodeCount);
    const stored = await bucket.list();
    const keys = new Set([plan.prefix + "manifest.json", ...plan.chunks.map((_, index) => `${plan.prefix}${index}.ndjson`)]);
    requireCheck(!stored.truncated && stored.objects.length === keys.size && stored.objects.every(({ key }) => keys.has(key)));
    return {
      document, job: "saved", chunks: plan.chunks.length, ndjsonBytes: plan.chunks.reduce((sum, chunk) => sum + chunk.bytes, 0),
      metadata: { trafficUsed: owned.trafficUsed, trafficTotal: owned.trafficTotal, expireAt: owned.expireAt },
      diagnostics: diagnostics.value,
      formats: await readExports(runtime, owned.token, output),
    };
  } finally {
    await runtime.dispose();
  }
}

try {
  const [bundle, bodyFile, output, controls] = process.argv.slice(2);
  requireCheck(bundle && bodyFile && output && controls);
  const result = await run(bundle, bodyFile, output, await readFile(controls, "utf8"));
  await writeFile(join(output, "worker.json"), JSON.stringify(result), { flag: "wx", mode: 0o600 });
} catch {
  process.exitCode = 2;
}
