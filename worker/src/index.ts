import { AggregateLimitError, getAggregateNodeSource, hasAggregateLink } from "./aggregate.ts";
import { normalShortLinksReady, resolveShortLocation } from "./short-links.ts";
import { SnapshotIntegrityError, type ExportNodeSource, type NodeRecord } from "./storage.ts";
import { getSubscriptionNodeSource, PathRuleContentError } from "./path-rules.ts";
import { isValidStoredShare } from "./stored-share.ts";
import { serializeStructuredShare } from "./structured-share.ts";
import { ClashContentError } from "./clash-export.ts";
import { clashChunks, planClash } from "./clash-response.ts";
import { SingBoxContentError } from "./singbox-export.ts";
import { planSingBox, singBoxChunks } from "./singbox-response.ts";
import { TextExportError } from "./text-export.ts";
import { planTextExport, textExportChunks } from "./text-export-response.ts";
import { acceptTelegramAggregate, parseTelegramAggregateKey } from "./telegram/aggregate-actions.ts";
import { acceptTelegramSelected, reapTelegramSelected } from "./telegram/selected-export.ts";
import { answerTelegramCallback, drainTelegramReplies } from "./telegram/delivery.ts";
import { runTelegramDocumentIntake } from "./telegram/document-intake.ts";
import { acceptTelegramDocumentJob } from "./telegram/document-jobs.ts";
import { reconcileTelegramDocumentJobReplies, retireTelegramDocumentStage } from "./telegram/document-persistence.ts";
import { acceptTelegramLifecycle, reapTelegramLifecycle } from "./telegram/lifecycle-actions.ts";
import { acceptTelegramPath } from "./telegram/path-management.ts";
import { acceptTelegramPrivateClaim } from "./telegram/private-claims.ts";
import {
  acceptTelegramPrivateShareCreation, parseTelegramPrivateShareArgs,
  recoverTelegramPrivateShareCreation, retireAbandonedTelegramPrivateShareCreation,
} from "./telegram/private-share-creation.ts";
import { telegramPrivateShareRuntime } from "./telegram/private-share-runtime.ts";
import { decodeTelegramRequest, parseTelegramPolicy } from "./telegram/protocol.ts";
import { acceptTelegramCommand } from "./telegram/store.ts";
import { acceptTelegramTemp } from "./telegram/temp-import.ts";
import { acceptTelegramView, reapTelegramViewTickets } from "./telegram/views.ts";
import { acceptTelegramShortLink, reapFailedTelegramShortLinks } from "./telegram/short-link-actions.ts";

export interface Env {
  DB: D1Database;
  NODES: R2Bucket;
  BUILD_REVISION?: string;
  TELEGRAM_ISOLATION_CONFIG?: string;
  TELEGRAM_AGGREGATE_KEY?: string;
  TELEGRAM_PRIVATE_SHARE_CREATION_KEY?: string;
}

const MAX_SHARE_BYTES = 16 * 1024 * 1024;
// Every complete chunk ends on a Base64 group boundary.
const SHARE_CHUNK_BYTES = 24 * 1024;
const QX_KINDS = new Set(["qx", "quantumult", "quantumultx"]);
const EXPORT_KINDS = new Set(["base64", "v2ray", "mixed", "singbox", "sing-box", "clash", "surge", ...QX_KINDS]);
const SUBSCRIPTION_PATH = /^\/sub\/([A-Za-z0-9_-]{16,128})(?:\/([A-Za-z0-9-]{1,32}))?$/;
const AGGREGATE_PATH = /^\/agg\/([A-Za-z0-9_-]{12}|[A-Za-z0-9_-]{22})\/([A-Za-z0-9-]{1,32})$/;
const SHORT_PATH = /^\/s\/([A-Za-z0-9_-]{12}|[A-Za-z0-9_-]{22})$/;
const HEADERS = {
  "Cache-Control": "private, no-store",
  "Referrer-Policy": "no-referrer",
  "X-Content-Type-Options": "nosniff",
};

function plain(text: string, status: number, head: boolean, headers?: HeadersInit): Response {
  const responseHeaders = new Headers(headers);
  for (const [name, value] of Object.entries(HEADERS)) responseHeaders.set(name, value);
  responseHeaders.set("Content-Type", "text/plain; charset=utf-8");
  return new Response(head ? null : text, { status, headers: responseHeaders });
}

class ExportContentError extends Error {}

function shareLine(node: NodeRecord): string {
  const stored = node.share;
  if (stored === undefined || stored === null || stored === "") {
    const generated = serializeStructuredShare(node);
    if (generated !== null) return generated;
  } else if (isValidStoredShare(stored)) {
    return stored;
  }
  throw new ExportContentError();
}

async function* shareBytes(
  source: ExportNodeSource, signal?: AbortSignal,
): AsyncGenerator<Uint8Array> {
  const encoder = new TextEncoder();
  let total = 0;
  let count = 0;

  for await (const node of source.read(signal)) {
    count += 1;
    const share = shareLine(node);
    const line = encoder.encode(total === 0 ? share : `\n${share}`);
    total += line.length;
    if (total > MAX_SHARE_BYTES) throw new ExportContentError();
    yield line;
  }
  if (!signal?.aborted && count !== source.nodeCount) throw new SnapshotIntegrityError();
}

async function* base64Chunks(
  source: ExportNodeSource, signal: AbortSignal,
): AsyncGenerator<Uint8Array> {
  const encoder = new TextEncoder();
  const chunk = new Uint8Array(SHARE_CHUNK_BYTES);
  let offset = 0;

  for await (const line of shareBytes(source, signal)) {
    for (let start = 0; start < line.length;) {
      const length = Math.min(line.length - start, chunk.length - offset);
      chunk.set(line.subarray(start, start + length), offset);
      start += length;
      offset += length;
      if (offset === chunk.length) {
        yield encoder.encode(btoa(String.fromCharCode(...chunk)));
        offset = 0;
      }
    }
  }
  if (offset !== 0) yield encoder.encode(btoa(String.fromCharCode(...chunk.subarray(0, offset))));
}

function fixedLengthBody(
  generate: (signal: AbortSignal) => AsyncGenerator<Uint8Array>, byteLength: number,
): ReadableStream {
  const abort = new AbortController();
  const chunks = generate(abort.signal);
  const source = new ReadableStream<Uint8Array>({
    async pull(controller) {
      try {
        const chunk = await chunks.next();
        if (abort.signal.aborted) return;
        if (chunk.done) controller.close();
        else controller.enqueue(chunk.value);
      } catch {
        if (!abort.signal.aborted) controller.error(new Error("Subscription stream failed."));
      }
    },
    async cancel() {
      abort.abort();
      await chunks.return(undefined).catch(() => {});
    },
  }, { highWaterMark: 0 });
  const { readable, writable } = new FixedLengthStream(byteLength);
  // A source error aborts the response body. Client cancellation also stops the source.
  void source.pipeTo(writable).catch(() => {});
  return readable;
}

async function telegramWebhook(request: Request, env: Env, ctx?: ExecutionContext): Promise<Response> {
  if (request.method !== "POST") {
    return plain("Method not allowed.", 405, request.method === "HEAD", { Allow: "POST" });
  }
  if (new URL(request.url).protocol !== "https:") return plain("Not found.", 404, false);
  const policy = parseTelegramPolicy(env.TELEGRAM_ISOLATION_CONFIG);
  if (!policy) return plain("Service unavailable.", 503, false);

  try {
    const decoded = await decodeTelegramRequest(request, policy);
    if (decoded.status !== 200) return new Response(null, { status: decoded.status, headers: HEADERS });
    const aggregateKey = await parseTelegramAggregateKey(env.TELEGRAM_AGGREGATE_KEY);
    const privateShare = await telegramPrivateShareRuntime(env.DB, env.TELEGRAM_PRIVATE_SHARE_CREATION_KEY);
    const shortLinks = await normalShortLinksReady(env.DB);
    const drain = () => ctx?.waitUntil(drainTelegramReplies(env.DB, env.NODES, policy, 4, 20_000, fetch, aggregateKey, privateShare,
      shortLinks).catch(() => undefined));
    if (decoded.command) {
      await acceptTelegramCommand(env.DB, policy, decoded.command);
      drain();
    } else if (decoded.view) {
      const outcome = await acceptTelegramView(env.DB, policy, decoded.view);
      if (decoded.view.kind === "callback") {
        ctx?.waitUntil(answerTelegramCallback(policy, decoded.view.callbackId));
      }
      if (outcome === "accepted" || decoded.view.kind !== "callback") {
        drain();
      }
    } else if (decoded.lifecycle) {
      const outcome = await acceptTelegramLifecycle(env.DB, policy, decoded.lifecycle);
      if (decoded.lifecycle.kind === "lifecycle-callback") {
        ctx?.waitUntil(answerTelegramCallback(policy, decoded.lifecycle.callbackId));
      }
      if (outcome === "accepted") {
        drain();
      }
    } else if (decoded.privateClaim) {
      const outcome = await acceptTelegramPrivateClaim(env.DB, policy, decoded.privateClaim);
      if (outcome === "accepted") {
        drain();
      }
    } else if (decoded.temp) {
      const outcome = await acceptTelegramTemp(env.DB, policy, decoded.temp);
      if (outcome === "accepted") {
        drain();
      }
    } else if (decoded.selected) {
      if (!aggregateKey) return new Response(null, { status: 204, headers: HEADERS });
      const outcome = await acceptTelegramSelected(env.DB, policy, decoded.selected, aggregateKey);
      if (decoded.selected.kind === "selected-revoke") ctx?.waitUntil(answerTelegramCallback(policy, decoded.selected.callbackId));
      if (outcome === "accepted") drain();
    } else if (decoded.aggregate) {
      if (!aggregateKey) return new Response(null, { status: 204, headers: HEADERS });
      if (await acceptTelegramAggregate(env.DB, policy, decoded.aggregate, aggregateKey) === "accepted") drain();
    } else if (decoded.path) {
      const outcome = await acceptTelegramPath(env.DB, policy, decoded.path);
      if (outcome === "accepted") {
        drain();
      }
    } else if (decoded.document) {
      await acceptTelegramDocumentJob(env.DB, policy, decoded.document);
    } else if (decoded.shortLink) {
      if (!shortLinks) return new Response(null, { status: 204, headers: HEADERS });
      if (await acceptTelegramShortLink(env.DB, policy, decoded.shortLink, aggregateKey) === "accepted") drain();
    } else if (decoded.privateShareCreation) {
      if (!privateShare.context) return new Response(null, { status: 204, headers: HEADERS });
      const input = decoded.privateShareCreation;
      const draft = parseTelegramPrivateShareArgs(input.args);
      if (!draft || (draft.targetUserId !== null && draft.targetUserId !== policy.adminId && draft.targetUserId !== policy.memberId)) {
        await acceptTelegramCommand(env.DB, policy, { ...input, command: "help" });
        drain();
      } else if (await acceptTelegramPrivateShareCreation(env.DB, env.NODES, policy, { ...input, ...draft }, privateShare.context) === "published") {
        drain();
      }
    }
    return new Response(null, { status: decoded.status, headers: HEADERS });
  } catch {
    // Telegram can retry delivery if durable admission could not be confirmed.
    return plain("Service unavailable.", 503, false);
  }
}

async function fetchRequest(request: Request, env: Env, ctx?: ExecutionContext): Promise<Response> {
  const path = new URL(request.url).pathname;
  if (path === "/telegram/webhook") return telegramWebhook(request, env, ctx);
  const subscription = SUBSCRIPTION_PATH.exec(path);
  const aggregate = AGGREGATE_PATH.exec(path);
  const short = SHORT_PATH.exec(path);
  const matchedExport = subscription ?? aggregate;
  const head = request.method === "HEAD";
  if (path !== "/health" && !matchedExport && !short) return plain("Not found.", 404, head);
  if (request.method !== "GET" && !head) return plain("Method not allowed.", 405, false, { Allow: "GET, HEAD" });

  if (path === "/health") {
    const revision = env.BUILD_REVISION;
    if (typeof revision !== "string" || revision.length !== 40 || !/^[0-9a-f]+$/.test(revision)) {
      return plain("Service unavailable.", 503, head);
    }
    const body = head ? null : JSON.stringify({ ok: true, service: "subs-bot", revision });
    return new Response(body, { headers: { ...HEADERS, "Content-Type": "application/json" } });
  }

  if (short) {
    try {
      const location = await normalShortLinksReady(env.DB) ? await resolveShortLocation(env.DB, short[1])
        : await hasAggregateLink(env.DB, short[1]) ? `/agg/${short[1]}/clash` : null;
      return location ? new Response(null, { status: 302, headers: { ...HEADERS, Location: location } })
        : plain("Not found.", 404, head);
    } catch {
      return plain("Subscription temporarily unavailable.", 503, head);
    }
  }
  if (!matchedExport) return plain("Not found.", 404, head);
  const [, token, kind = "clash"] = matchedExport;
  const format = kind.toLowerCase();
  if (!EXPORT_KINDS.has(format)) return plain("Export format unavailable.", 406, head);

  try {
    const source = aggregate ? await getAggregateNodeSource(env.DB, env.NODES, token, await normalShortLinksReady(env.DB))
      : await getSubscriptionNodeSource(env.DB, env.NODES, token);
    if (!source) return plain("Not found.", 404, head);
    if (format === "clash") {
      const plan = await planClash(source);
      return new Response(
        head ? null : fixedLengthBody((signal) => clashChunks(source, plan, signal), plan.bytes),
        { headers: { ...HEADERS, "Content-Type": "text/yaml; charset=utf-8" } },
      );
    }
    if (format === "singbox" || format === "sing-box") {
      const plan = await planSingBox(source);
      return new Response(
        head ? null : fixedLengthBody((signal) => singBoxChunks(source, plan, signal), plan.bytes),
        { headers: { ...HEADERS, "Content-Type": "application/json" } },
      );
    }
    if (format === "surge" || QX_KINDS.has(format)) {
      const textFormat = format === "surge" ? "surge" : "qx";
      const plan = await planTextExport(source, textFormat);
      return new Response(head ? null : fixedLengthBody(
        (signal) => textExportChunks(source, textFormat, plan, signal), plan.bytes,
      ), { headers: { ...HEADERS, "Content-Type": "text/plain; charset=utf-8" } });
    }
    // Measure and verify the source before returning success, without retaining its content.
    let shareLength = 0;
    for await (const line of shareBytes(source)) shareLength += line.byteLength;
    if (shareLength === 0) return plain("Subscription temporarily unavailable.", 503, head);
    const body = head ? null : fixedLengthBody(
      (signal) => base64Chunks(source, signal), 4 * Math.ceil(shareLength / 3),
    );
    return new Response(body, {
      headers: { ...HEADERS, "Content-Type": "text/plain; charset=utf-8" },
    });
  } catch (error) {
    if (error instanceof AggregateLimitError || error instanceof ExportContentError || error instanceof SingBoxContentError
        || error instanceof ClashContentError || error instanceof TextExportError || error instanceof PathRuleContentError) {
      return plain("Subscription content cannot be exported.", 422, head);
    }
    return plain("Subscription temporarily unavailable.", 503, head);
  }
}

async function recoverTelegramWork(_controller: ScheduledController, env: Env): Promise<void> {
  const policy = parseTelegramPolicy(env.TELEGRAM_ISOLATION_CONFIG);
  if (!policy) return;
  const aggregateKey = await parseTelegramAggregateKey(env.TELEGRAM_AGGREGATE_KEY);
  const privateShare = await telegramPrivateShareRuntime(env.DB, env.TELEGRAM_PRIVATE_SHARE_CREATION_KEY);
  const shortLinks = await normalShortLinksReady(env.DB);
  const replies = async () => {
    await drainTelegramReplies(env.DB, env.NODES, policy, 10, 45_000, fetch, aggregateKey, privateShare, shortLinks);
    await reapTelegramViewTickets(env.DB);
    await reapTelegramLifecycle(env.DB);
    if (aggregateKey) await reapTelegramSelected(env.DB);
    if (shortLinks) await reapFailedTelegramShortLinks(env.DB, policy.botId);
  };
  const documents = async () => {
    let claimed = false;
    try {
      claimed = await runTelegramDocumentIntake(env.DB, env.NODES, policy);
    } finally {
      const reconciled = await reconcileTelegramDocumentJobReplies(env.DB, policy);
      if (claimed || reconciled > 0) await drainTelegramReplies(env.DB, env.NODES, policy, 4, 15_000, fetch, aggregateKey, privateShare, shortLinks);
    }
  };
  const creations = async () => {
    if (privateShare.context && await recoverTelegramPrivateShareCreation(env.DB, env.NODES, policy, privateShare.context) === "published") {
      await drainTelegramReplies(env.DB, env.NODES, policy, 4, 15_000, fetch, aggregateKey, privateShare, shortLinks);
    }
  };
  const results = await Promise.allSettled([replies(), documents(), creations(), retireTelegramDocumentStage(env.DB, env.NODES, policy),
    privateShare.schemaReady ? retireAbandonedTelegramPrivateShareCreation(env.DB, env.NODES, policy) : Promise.resolve()]);
  if (results.some(({ status }) => status === "rejected")) {
    throw new Error("Telegram scheduled recovery could not finish.");
  }
}

export default { fetch: fetchRequest, scheduled: recoverTelegramWork } satisfies ExportedHandler<Env>;
