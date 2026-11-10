import { AggregateLimitError, getAggregateNodeSource } from "./aggregate.ts";
import { normalShortLinksReady, readShortLinkNamespaces, resolveShortLocation } from "./short-links.ts";
import { parsePublicOrigin, type PublicOrigin } from "./public-origin.ts";
import { getSubscriptionNodeSource, PathRuleContentError } from "./path-rules.ts";
import { legacyEmptyExportResponse, legacyEmptyExportState } from "./legacy-empty-export.ts";
import { base64Chunks, ExportContentError, planBase64 } from "./base64-response.ts";
import { ClashContentError } from "./clash-export.ts";
import { clashChunks, planClash } from "./clash-response.ts";
import { SingBoxContentError } from "./singbox-export.ts";
import { planSingBox, singBoxChunks } from "./singbox-response.ts";
import { TextExportError } from "./text-export.ts";
import { planTextExport, textExportChunks } from "./text-export-response.ts";
import { PROVIDER_REVISION, PROVIDER_SHA256, type ProviderApiStatusV2Prober, type ProviderFetcher, type ProviderPin } from "./provider-fetch-contract.ts";
import { runOneProviderJob } from "./provider-job-consumer.ts";
import { providerSnapshotJournalReady } from "./provider-snapshot-journal.ts";
import { acceptTelegramAggregate, parseTelegramAggregateKey } from "./telegram/aggregate-actions.ts";
import { acceptTelegramSelected, reapTelegramSelected } from "./telegram/selected-export.ts";
import { answerTelegramCallback, drainTelegramReplies, sendTelegramGroupShareCard, sendTelegramInlineAnswer } from "./telegram/delivery.ts";
import { runTelegramDocumentIntake, telegramMixedDocumentReady } from "./telegram/document-intake.ts";
import { acceptTelegramDocumentJob } from "./telegram/document-jobs.ts";
import { reconcileTelegramDocumentJobReplies, retireTelegramDocumentStage } from "./telegram/document-persistence.ts";
import { acceptTelegramLifecycle, reapTelegramLifecycle } from "./telegram/lifecycle-actions.ts";
import { acceptTelegramGitHubSearch, recoverTelegramGitHubSearch, runTelegramGitHubSearch, telegramGitHubSearchReady } from "./telegram/github-search.ts";
import { scopeGitHubSearchProof, writeGitHubSearchProof } from "./telegram/github-search-proof.ts";
import { acceptGeneralTelegramCommand, drainGeneralTelegramReply, parseGeneralTelegramPin,
  recoverGeneralTelegramReplies } from "./telegram/general-auth-runtime.ts";
import { acceptTelegramGroupShare, telegramGroupShareReady } from "./telegram/group-share-actions.ts";
import { drainTelegramGroupShareCards } from "./telegram/group-share-delivery.ts";
import { acceptTelegramBulkTrash, telegramBulkTrashReady } from "./telegram/bulk-trash.ts";
import { acceptTelegramInlineSort, telegramInlineSortReady } from "./telegram/inline-sort.ts";
import { acceptTelegramInlineConsent, telegramInlineSearchReady } from "./telegram/inline-search-consent.ts";
import { answerTelegramInlineSearch, reapTelegramInlineSearch } from "./telegram/inline-search.ts";
import { acceptTelegramPath } from "./telegram/path-management.ts";
import { acceptTelegramPrivateClaim, legacyInlineClaimUrl } from "./telegram/private-claims.ts";
import {
  acceptTelegramPrivateShareCreation, acceptTelegramSubscriptionShare, parseTelegramPrivateShareArgs,
  parseTelegramSubscriptionShareArgs, recoverTelegramPrivateShareCreation, retireAbandonedTelegramPrivateShareCreation,
} from "./telegram/private-share-creation.ts";
import { telegramPrivateShareRuntime } from "./telegram/private-share-runtime.ts";
import { decodeTelegramRequest, parseTelegramPolicy, type TelegramPolicy } from "./telegram/protocol.ts";
import { acceptTelegramProviderRequest } from "./telegram/provider-admission.ts";
import { promoteTelegramProviderDocument, settleTelegramProviderDocuments, telegramProviderDocumentReady } from "./telegram/provider-document.ts";
import { reconcileTelegramProviderDocumentReplies } from "./telegram/provider-document-replies.ts";
import {
  acceptTelegramApiStatusPrompt, acceptTelegramApiStatusReply, reconcileTelegramApiStatus, runTelegramApiStatus, telegramApiStatusReady,
} from "./telegram/api-status.ts";
import { reconcileTelegramProviderBatches, telegramProviderBatchReady } from "./telegram/provider-batch.ts";
import {
  acceptTelegramProviderBatchControl, reapTelegramProviderBatchTickets, reconcileTelegramProviderBatchReplies,
  telegramProviderBatchControlsReady,
} from "./telegram/provider-batch-controls.ts";
import { parseTelegramProviderText, reconcileTelegramProviderReplies, telegramProviderRepliesReady } from "./telegram/provider-replies.ts";
import { reapTelegramProviderRefreshTickets, telegramProviderRefreshReady } from "./telegram/provider-refresh.ts";
import { acceptTelegramCommand } from "./telegram/store.ts";
import { acceptTelegramTemp } from "./telegram/temp-import.ts";
import { acceptTelegramView, reapTelegramViewTickets } from "./telegram/views.ts";
import { acceptTelegramShortLink, reapFailedTelegramShortLinks } from "./telegram/short-link-actions.ts";
import { acceptTelegramSubscriptionRead, reapTelegramSubscriptionReadTickets, telegramSubscriptionReadReady } from "./telegram/subscription-read.ts";
import { acceptTelegramPageJump, telegramPageJumpEpoch } from "./telegram/page-jump.ts";
import { acceptTelegramSubscriptionNodePage, reapTelegramSubscriptionNodeTickets, telegramSubscriptionNodePagesReady } from "./telegram/subscription-node-pages.ts";
import { acceptTelegramSubscriptionRawFile, reapTelegramRawFileTickets,
  telegramSubscriptionRawFileReady } from "./telegram/subscription-raw-file.ts";

export interface Env {
  DB: D1Database;
  NODES: R2Bucket;
  BUILD_REVISION?: string;
  PUBLIC_ORIGIN?: string;
  TELEGRAM_ISOLATION_CONFIG?: string;
  TELEGRAM_GENERAL_CONFIG?: string;
  TELEGRAM_CONFIG_SHA256?: string;
  TELEGRAM_AGGREGATE_KEY?: string;
  TELEGRAM_PRIVATE_SHARE_CREATION_KEY?: string;
  TELEGRAM_GROUP_SHARE_CARDS?: string;
  TELEGRAM_PAGE_JUMP?: string;
  TELEGRAM_INLINE_SEARCH?: string;
  PROVIDER_FETCH?: ProviderFetcher;
  PROVIDER_REVISION?: string;
  PROVIDER_IMAGE_SHA256?: string;
  TELEGRAM_PROVIDER_URL_IMPORT?: string;
  TELEGRAM_PROVIDER_URL_DOCUMENTS?: string;
  TELEGRAM_MIXED_DOCUMENTS?: string;
  TELEGRAM_PROVIDER_REFRESH?: string;
  LEGACY_SUBSCRIPTION_SHORTS?: string;
  TELEGRAM_PROVIDER_BATCH_REFRESH?: string;
  TELEGRAM_API_STATUS?: string;
  PROVIDER_API_STATUS?: ProviderApiStatusV2Prober;
  PROVIDER_API_STATUS_REVISION?: string;
  PROVIDER_API_STATUS_IMAGE_SHA256?: string;
}

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

function providerPin(env: Env): ProviderPin {
  return { providerRevision: env.PROVIDER_REVISION ?? "", imageSha256: env.PROVIDER_IMAGE_SHA256 ?? "" };
}

function apiStatusProvider(env: Env): { binding: ProviderApiStatusV2Prober; pin: ProviderPin } | null {
  const { PROVIDER_API_STATUS: binding, PROVIDER_API_STATUS_REVISION: providerRevision,
    PROVIDER_API_STATUS_IMAGE_SHA256: imageSha256 } = env;
  if (env.TELEGRAM_API_STATUS !== "1" || typeof binding?.probeApiStatusV2 !== "function"
    || typeof providerRevision !== "string" || !PROVIDER_REVISION.test(providerRevision)
    || typeof imageSha256 !== "string" || !PROVIDER_SHA256.test(imageSha256)) return null;
  return { binding, pin: { providerRevision, imageSha256 } };
}

async function telegramProviderQueueReady(env: Env, pin = providerPin(env)): Promise<boolean> {
  return typeof env.PROVIDER_FETCH?.fetchSubscription === "function"
    && typeof pin.providerRevision === "string" && PROVIDER_REVISION.test(pin.providerRevision)
    && typeof pin.imageSha256 === "string" && PROVIDER_SHA256.test(pin.imageSha256)
    && await telegramProviderRepliesReady(env.DB).catch(() => false);
}

async function providerBatchReadiness(env: Env) {
  const [queue, controls] = await Promise.all([
    telegramProviderBatchReady(env.DB).catch(() => "unavailable" as const),
    telegramProviderBatchControlsReady(env.DB).catch(() => "unavailable" as const),
  ]);
  return {
    queue: queue === false && (controls === true || env.TELEGRAM_PROVIDER_BATCH_REFRESH === "1") ? "unavailable" as const : queue,
    controls: controls === true && queue !== true ? "unavailable" as const : controls,
  };
}

function telegramGitHubSearchProbe(db: D1Database): () => Promise<boolean> {
  let readiness: Promise<boolean> | undefined;
  return () => readiness ??= telegramGitHubSearchReady(db);
}

function drainGroupShareCards(db: D1Database, policy: TelegramPolicy): Promise<void> {
  return drainTelegramGroupShareCards(db, policy, (actorId, method, body) => sendTelegramGroupShareCard(policy, actorId, method, body));
}

async function telegramWebhook(request: Request, env: Env, publicOrigin: PublicOrigin, ctx?: ExecutionContext): Promise<Response> {
  if (request.method !== "POST") {
    return plain("Method not allowed.", 405, request.method === "HEAD", { Allow: "POST" });
  }
  if (new URL(request.url).protocol !== "https:") return plain("Not found.", 404, false);
  if (env.TELEGRAM_ISOLATION_CONFIG === undefined && env.TELEGRAM_GENERAL_CONFIG !== undefined) {
    const general = parseGeneralTelegramPin(env.TELEGRAM_GENERAL_CONFIG, env.BUILD_REVISION);
    if (!general) return plain("Service unavailable.", 503, false);
    try {
      const status = await acceptGeneralTelegramCommand(env.DB, general, request);
      if (status === 200) {
        const delivery = drainGeneralTelegramReply(env.DB, general);
        if (ctx) ctx.waitUntil(delivery.catch(() => undefined));
        else await delivery;
      }
      return new Response(null, { status, headers: HEADERS });
    } catch {
      return plain("Service unavailable.", 503, false);
    }
  }
  const policy = parseTelegramPolicy(env.TELEGRAM_ISOLATION_CONFIG);
  if (!policy) return plain("Service unavailable.", 503, false);

  try {
    const inlineSearchEnabled = env.TELEGRAM_INLINE_SEARCH === "1";
    const decoded = await decodeTelegramRequest(request, policy, inlineSearchEnabled);
    if (decoded.status !== 200) return new Response(null, { status: decoded.status, headers: HEADERS });
    if (decoded.legacyInlineClaim) {
      const { legacyInlineClaim } = decoded;
      const url = await legacyInlineClaimUrl(env.DB, policy, legacyInlineClaim);
      ctx?.waitUntil(answerTelegramCallback(policy, legacyInlineClaim.callbackId, url ? { url } : "此旧卡片暂不可用。"));
      return new Response(null, { status: 204, headers: HEADERS });
    }
    const pageJumpEpoch = telegramPageJumpEpoch(env.TELEGRAM_PAGE_JUMP);
    if (decoded.inlineQuery) {
      if (await telegramInlineSearchReady(env.DB)) await answerTelegramInlineSearch(env.DB, policy, decoded.inlineQuery, sendTelegramInlineAnswer);
      return new Response(null, { status: 204, headers: HEADERS });
    }
    const aggregateKey = await parseTelegramAggregateKey(env.TELEGRAM_AGGREGATE_KEY);
    const privateShare = await telegramPrivateShareRuntime(env.DB, env.TELEGRAM_PRIVATE_SHARE_CREATION_KEY,
      env.TELEGRAM_GROUP_SHARE_CARDS === "1");
    const shortLinkNamespaces = await readShortLinkNamespaces(env.DB);
    const shortLinks = shortLinkNamespaces.normal;
    const subscriptionRead = await telegramSubscriptionReadReady(env.DB);
    const inlineSort = await telegramInlineSortReady(env.DB);
    const subscriptionNodes = subscriptionRead && await telegramSubscriptionNodePagesReady(env.DB);
    const subscriptionRawFile = subscriptionRead && await telegramSubscriptionRawFileReady(env.DB).catch(() => "unavailable" as const);
    const apiStatus = await telegramApiStatusReady(env.DB).catch(() => "unavailable" as const);
    const statusProvider = apiStatusProvider(env);
    const providerQueueReady = await telegramProviderQueueReady(env);
    const providerBatch = await providerBatchReadiness(env);
    const providerIntakeReady = providerQueueReady && await providerSnapshotJournalReady(env.DB);
    const providerBatchAdmission = providerIntakeReady && env.TELEGRAM_PROVIDER_BATCH_REFRESH === "1";
    const providerDocument = await telegramProviderDocumentReady(env.DB).catch(() => "unavailable" as const);
    const providerPolicy = providerDocument === true ? { ...policy, includeDocuments: true as const } : policy;
    const inlineConsent = inlineSearchEnabled && await telegramInlineSearchReady(env.DB);
    const bulkTrash = await telegramBulkTrashReady(env.DB);
    const githubSearch = telegramGitHubSearchProbe(env.DB);
    const providerRefresh = env.TELEGRAM_PROVIDER_REFRESH === "1" && providerIntakeReady && subscriptionRead
      && await telegramProviderRefreshReady(env.DB).catch(() => false);
    const drainReplies = async (budget = 20_000) => drainTelegramReplies(env.DB, env.NODES, policy, 4, budget, fetch, aggregateKey, privateShare,
      subscriptionRead, shortLinks, inlineSort, subscriptionNodes, providerQueueReady, bulkTrash, inlineConsent,
      await githubSearch().catch(() => "unavailable" as const), providerRefresh, subscriptionRawFile, providerBatch.controls, apiStatus,
      statusProvider !== null, providerDocument, providerBatchAdmission, pageJumpEpoch, publicOrigin);
    const drain = () => ctx?.waitUntil(drainReplies().catch(() => undefined));
    if (decoded.apiStatus) {
      if (!statusProvider || apiStatus !== true) return new Response(null, { status: 204, headers: HEADERS });
      if (decoded.apiStatus.kind === "prompt") {
        if (await acceptTelegramApiStatusPrompt(env.DB, policy, decoded.apiStatus)) drain();
      } else {
        const accepted = await acceptTelegramApiStatusReply(env.DB, policy, decoded.apiStatus);
        if (accepted) ctx?.waitUntil((async () => {
          const deadline = Date.now() + 28_000;
          try {
            await runTelegramApiStatus(env.DB, policy, statusProvider.binding, statusProvider.pin, accepted);
          } finally {
            const ready = await reconcileTelegramApiStatus(env.DB, policy);
            const remaining = deadline - Date.now();
            if (ready && remaining > 2000) await drainReplies(remaining);
          }
        })().catch(() => undefined));
      }
    } else if (decoded.command) {
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
    } else if (decoded.pageJump) {
      if (pageJumpEpoch === null) return new Response(null, { status: 204, headers: HEADERS });
      const accepted = await acceptTelegramPageJump(env.DB, policy, decoded.pageJump, pageJumpEpoch);
      if (decoded.pageJump.kind === "open") ctx?.waitUntil(answerTelegramCallback(policy, decoded.pageJump.callbackId));
      if (accepted) drain();
    } else if (decoded.lifecycle) {
      const outcome = await acceptTelegramLifecycle(env.DB, policy, decoded.lifecycle);
      if (decoded.lifecycle.kind === "lifecycle-callback") {
        ctx?.waitUntil(answerTelegramCallback(policy, decoded.lifecycle.callbackId));
      }
      if (outcome === "accepted") {
        drain();
      }
    } else if (decoded.groupShare) {
      const event = decoded.groupShare;
      const ready = privateShare.context && (event.kind !== "publish" || privateShare.groupCardsEnabled)
        && await telegramGroupShareReady(env.DB);
      const accepted = ready && await acceptTelegramGroupShare(env.DB, policy, event) === "accepted";
      if (event.kind === "handoff") {
        if (accepted) drain();
      } else {
        const text = !accepted ? "此卡片暂不可用。" : event.kind === "publish" ? "已提交到指定群。" : "已选中。请打开机器人私聊领取。";
        ctx?.waitUntil(answerTelegramCallback(policy, event.callbackId, text));
        if (accepted && event.kind === "publish") ctx?.waitUntil(drainGroupShareCards(env.DB, policy).catch(() => undefined));
      }
    } else if (decoded.privateClaim) {
      const outcome = await acceptTelegramPrivateClaim(env.DB, policy, decoded.privateClaim);
      if (outcome === "accepted") {
        drain();
      }
    } else if (decoded.temp) {
      const candidate = env.TELEGRAM_PROVIDER_URL_IMPORT === "1" && providerQueueReady && decoded.temp.kind === "temp-text"
        ? parseTelegramProviderText(decoded.temp.text) : null;
      if (candidate) {
        if (!providerIntakeReady || providerBatch.queue === "unavailable" || providerDocument === "unavailable") {
          return new Response(null, { status: 503, headers: HEADERS });
        }
        const outcome = await acceptTelegramProviderRequest(env.DB, providerPolicy, { ...decoded.temp, ...candidate, kind: "url-import" }, providerBatch.queue);
        if (outcome.kind !== "queued" && outcome.kind !== "ignored") {
          await reconcileTelegramProviderReplies(env.DB, policy);
          drain();
        }
      } else if (await acceptTelegramTemp(env.DB, policy, decoded.temp) === "accepted") {
        drain();
      }
    } else if (decoded.selected) {
      if (!aggregateKey) return new Response(null, { status: 204, headers: HEADERS });
      const outcome = await acceptTelegramSelected(env.DB, policy, decoded.selected, aggregateKey);
      if (decoded.selected.kind === "selected-revoke") ctx?.waitUntil(answerTelegramCallback(policy, decoded.selected.callbackId));
      if (outcome === "accepted") drain();
    } else if (decoded.aggregate) {
      if (!aggregateKey) return new Response(null, { status: 204, headers: HEADERS });
      if (await acceptTelegramAggregate(env.DB, policy, decoded.aggregate, aggregateKey, shortLinkNamespaces.allMarker) === "accepted") drain();
    } else if (decoded.path) {
      const outcome = await acceptTelegramPath(env.DB, policy, decoded.path);
      if (outcome === "accepted") {
        drain();
      }
    } else if (decoded.inlineSort) {
      if (!inlineSort) return new Response(null, { status: 204, headers: HEADERS });
      if (await acceptTelegramInlineSort(env.DB, policy, decoded.inlineSort) === "accepted") drain();
    } else if (decoded.bulkTrash) {
      if (!bulkTrash) return new Response(null, { status: 204, headers: HEADERS });
      const outcome = await acceptTelegramBulkTrash(env.DB, policy, decoded.bulkTrash);
      if (decoded.bulkTrash.kind === "confirm") ctx?.waitUntil(answerTelegramCallback(policy, decoded.bulkTrash.callbackId));
      if (outcome === "accepted") drain();
    } else if (decoded.inlineConsent) {
      if (!inlineConsent) return new Response(null, { status: 204, headers: HEADERS });
      if (await acceptTelegramInlineConsent(env.DB, policy, decoded.inlineConsent) === "accepted") drain();
    } else if (decoded.githubSearch) {
      const receivedAt = Date.now();
      if (!await githubSearch()) return new Response(null, { status: 204, headers: HEADERS });
      const admitted = await acceptTelegramGitHubSearch(env.DB, policy, decoded.githubSearch);
      if (admitted.kind === "ignored") return new Response(null, { status: 204, headers: HEADERS });
      if (admitted.kind === "reply") drain();
      if (admitted.kind === "lookup") {
        const proof = scopeGitHubSearchProof(new URL(request.url).origin, env.BUILD_REVISION, env.TELEGRAM_CONFIG_SHA256,
          admitted.query, policy, decoded.githubSearch, receivedAt);
        const lookup = async () => {
          if (!await runTelegramGitHubSearch(env.DB, policy, admitted, fetch, proof?.observation)) return;
          const delivery = drainReplies();
          if (proof) await Promise.all([delivery, writeGitHubSearchProof(env.NODES, proof, admitted.receiptId)]);
          else await delivery;
        };
        if (ctx) ctx.waitUntil(lookup().catch(() => undefined));
        else await lookup();
      }
    } else if (decoded.document) {
      const optIn = env.TELEGRAM_PROVIDER_URL_DOCUMENTS === "1";
      const mixedOptIn = env.TELEGRAM_MIXED_DOCUMENTS === "1";
      if (optIn && (providerDocument !== true || !providerIntakeReady || providerBatch.queue === "unavailable")) {
        return new Response(null, { status: 503, headers: HEADERS });
      }
      if (mixedOptIn && (!optIn || !await telegramMixedDocumentReady(env.DB))) {
        return new Response(null, { status: 503, headers: HEADERS });
      }
      await acceptTelegramDocumentJob(env.DB, policy, decoded.document, optIn, mixedOptIn);
    } else if (decoded.shortLink) {
      if (!shortLinks) return new Response(null, { status: 204, headers: HEADERS });
      if (await acceptTelegramShortLink(env.DB, policy, decoded.shortLink, aggregateKey, shortLinkNamespaces) === "accepted") drain();
    } else if (decoded.subscriptionRead) {
      if (!subscriptionRead) return new Response(null, { status: 204, headers: HEADERS });
      const outcome = await acceptTelegramSubscriptionRead(env.DB, policy, decoded.subscriptionRead, subscriptionNodes);
      if (decoded.subscriptionRead.kind === "callback") {
        ctx?.waitUntil(answerTelegramCallback(policy, decoded.subscriptionRead.callbackId));
      }
      if (outcome === "accepted") drain();
    } else if (decoded.subscriptionNodes) {
      if (!subscriptionNodes) return new Response(null, { status: 204, headers: HEADERS });
      const outcome = await acceptTelegramSubscriptionNodePage(env.DB, policy, decoded.subscriptionNodes);
      ctx?.waitUntil(answerTelegramCallback(policy, decoded.subscriptionNodes.callbackId));
      if (outcome === "accepted") drain();
    } else if (decoded.providerRefresh) {
      if (!providerRefresh) return new Response(null, { status: 204, headers: HEADERS });
      if (providerBatch.queue === "unavailable" || providerDocument === "unavailable") {
        return new Response(null, { status: 503, headers: HEADERS });
      }
      const outcome = await acceptTelegramProviderRequest(env.DB, providerPolicy, { ...decoded.providerRefresh, kind: "refresh-ticket" }, providerBatch.queue);
      ctx?.waitUntil(answerTelegramCallback(policy, decoded.providerRefresh.callbackId));
      if (outcome.kind !== "queued" && outcome.kind !== "ignored") {
        await reconcileTelegramProviderReplies(env.DB, policy);
        drain();
      }
    } else if (decoded.subscriptionRawFile) {
      if (subscriptionRawFile !== true) return new Response(null, { status: 204, headers: HEADERS });
      const outcome = await acceptTelegramSubscriptionRawFile(env.DB, policy, decoded.subscriptionRawFile);
      ctx?.waitUntil(answerTelegramCallback(policy, decoded.subscriptionRawFile.callbackId));
      if (outcome === "accepted") drain();
    } else if (decoded.providerBatch) {
      if (providerBatch.controls === "unavailable") return new Response(null, { status: 503, headers: HEADERS });
      if (!providerBatch.controls) return new Response(null, { status: 204, headers: HEADERS });
      const event = decoded.providerBatch;
      if (!providerBatchAdmission && event.kind !== "status") return new Response(null, { status: 204, headers: HEADERS });
      const outcome = await acceptTelegramProviderBatchControl(env.DB, policy, event, providerBatchAdmission);
      if (!providerBatchAdmission && outcome === "ignored") return new Response(null, { status: 204, headers: HEADERS });
      if (event.kind === "confirm" && providerBatchAdmission) ctx?.waitUntil(answerTelegramCallback(policy, event.callbackId));
      if (outcome === "accepted") drain();
    } else if (decoded.privateShareCreation) {
      if (!privateShare.context) return new Response(null, { status: 204, headers: HEADERS });
      const input = decoded.privateShareCreation;
      if (/^\s*sub(?:\s|$)/iu.test(input.args)) {
        const selection = parseTelegramSubscriptionShareArgs(input.args);
        const targetAllowed = selection?.targetUserId === null || selection?.targetUserId === policy.adminId
          || selection?.targetUserId === policy.memberId;
        const outcome = selection && targetAllowed ? await acceptTelegramSubscriptionShare(env.DB, env.NODES, policy,
          { ...input, ...selection }, privateShare.context, publicOrigin) : "unavailable";
        if (outcome === "unavailable") {
          await acceptTelegramCommand(env.DB, policy, { ...input, command: "help" }, "subscription-share-unavailable");
        }
        if (outcome === "unavailable" || outcome === "published") drain();
      } else {
        const draft = parseTelegramPrivateShareArgs(input.args);
        if (!draft || (draft.targetUserId !== null && draft.targetUserId !== policy.adminId && draft.targetUserId !== policy.memberId)) {
          await acceptTelegramCommand(env.DB, policy, { ...input, command: "help" });
          drain();
        } else if (await acceptTelegramPrivateShareCreation(env.DB, env.NODES, policy, { ...input, ...draft }, privateShare.context) === "published") {
          drain();
        }
      }
    }
    return new Response(null, { status: decoded.status, headers: HEADERS });
  } catch {
    // Telegram can retry delivery if durable admission could not be confirmed.
    return plain("Service unavailable.", 503, false);
  }
}

async function fetchRequest(request: Request, env: Env, ctx?: ExecutionContext): Promise<Response> {
  const publicOrigin = parsePublicOrigin(env.PUBLIC_ORIGIN);
  const head = request.method === "HEAD";
  if (publicOrigin === null) return plain("Service unavailable.", 503, head);
  const path = new URL(request.url).pathname;
  if (path === "/telegram/webhook") return telegramWebhook(request, env, publicOrigin, ctx);
  const subscription = SUBSCRIPTION_PATH.exec(path);
  const aggregate = AGGREGATE_PATH.exec(path);
  const short = SHORT_PATH.exec(path);
  const matchedExport = subscription ?? aggregate;
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
      const location = await resolveShortLocation(env.DB, short[1], env.LEGACY_SUBSCRIPTION_SHORTS === "1");
      return location ? new Response(null, { status: 302, headers: { ...HEADERS, Location: location } })
        : plain("Not found.", 404, head);
    } catch {
      return plain("Subscription temporarily unavailable.", 503, head);
    }
  }
  if (!matchedExport) return plain("Not found.", 404, head);
  const [, token, kind = "clash"] = matchedExport;
  const requestedFormat = kind.toLowerCase();
  const knownFormat = EXPORT_KINDS.has(requestedFormat);
  if (!knownFormat && (!aggregate || token.length !== 12)) return plain("Export format unavailable.", 406, head);
  let legacyAggregate = false;

  try {
    const aggregateSource = aggregate ? await getAggregateNodeSource(env.DB, env.NODES, token, !knownFormat) : null;
    legacyAggregate = aggregateSource?.legacyAggregate === true;
    if (!knownFormat && !legacyAggregate) return plain("Export format unavailable.", 406, head);
    const format = knownFormat ? requestedFormat : "clash";
    let source = aggregate ? aggregateSource : await getSubscriptionNodeSource(env.DB, env.NODES, token);
    if (legacyAggregate && source?.nodeCount === 0) return legacyEmptyExportResponse(format, head, HEADERS, true);
    if (subscription && !source) {
      const state = await legacyEmptyExportState(env.DB, token);
      if (state === "empty") return legacyEmptyExportResponse(format, head, HEADERS);
      // A refresh may have published between the initial lookup and the legacy check.
      if (state === "published") source = await getSubscriptionNodeSource(env.DB, env.NODES, token);
    }
    if (!source) return plain("Not found.", 404, head);
    const exportHeaders = (media: string, bytes: number) => {
      const headers: Record<string, string> = { ...HEADERS, "Content-Type": media };
      if (legacyAggregate && head && bytes > 0) headers["Content-Length"] = String(bytes);
      return headers;
    };
    if (format === "clash") {
      const plan = await planClash(source);
      return new Response(
        head ? null : fixedLengthBody((signal) => clashChunks(source, plan, signal), plan.bytes),
        { headers: exportHeaders("text/yaml; charset=utf-8", plan.bytes) },
      );
    }
    if (format === "singbox" || format === "sing-box") {
      const plan = await planSingBox(source);
      return new Response(
        head ? null : fixedLengthBody((signal) => singBoxChunks(source, plan, signal), plan.bytes),
        { headers: exportHeaders(legacyAggregate ? "application/json; charset=utf-8" : "application/json", plan.bytes) },
      );
    }
    if (format === "surge" || QX_KINDS.has(format)) {
      const textFormat = format === "surge" ? "surge" : "qx";
      const plan = await planTextExport(source, textFormat);
      return new Response(head ? null : fixedLengthBody(
        (signal) => textExportChunks(source, textFormat, plan, signal), plan.bytes,
      ), { headers: exportHeaders("text/plain; charset=utf-8", plan.bytes) });
    }
    // Measure and verify the source before returning success, without retaining its content.
    const length = await planBase64(source);
    const body = head ? null : fixedLengthBody((signal) => base64Chunks(source, signal), length);
    return new Response(body, { headers: exportHeaders("text/plain; charset=utf-8", length) });
  } catch (error) {
    if (!knownFormat && !legacyAggregate) return plain("Export format unavailable.", 406, head);
    if (error instanceof AggregateLimitError || error instanceof ExportContentError || error instanceof SingBoxContentError
        || error instanceof ClashContentError || error instanceof TextExportError || error instanceof PathRuleContentError) {
      return plain("Subscription content cannot be exported.", 422, head);
    }
    return plain("Subscription temporarily unavailable.", 503, head);
  }
}

async function recoverTelegramWork(
  env: Env, policy: TelegramPolicy, pin: ProviderPin, providerQueueReady: boolean, publicOrigin: PublicOrigin,
): Promise<void> {
  const aggregateKey = await parseTelegramAggregateKey(env.TELEGRAM_AGGREGATE_KEY);
  const privateShare = await telegramPrivateShareRuntime(env.DB, env.TELEGRAM_PRIVATE_SHARE_CREATION_KEY,
    env.TELEGRAM_GROUP_SHARE_CARDS === "1");
  const shortLinks = await normalShortLinksReady(env.DB);
  const subscriptionRead = await telegramSubscriptionReadReady(env.DB);
  const inlineSort = await telegramInlineSortReady(env.DB);
  const subscriptionNodes = subscriptionRead && await telegramSubscriptionNodePagesReady(env.DB);
  const subscriptionRawFile = subscriptionRead && await telegramSubscriptionRawFileReady(env.DB).catch(() => "unavailable" as const);
  const apiStatus = await telegramApiStatusReady(env.DB).catch(() => "unavailable" as const);
  const providerBatch = await providerBatchReadiness(env);
  const providerIntakeReady = providerQueueReady && await providerSnapshotJournalReady(env.DB);
  const providerBatchAdmission = providerIntakeReady && env.TELEGRAM_PROVIDER_BATCH_REFRESH === "1";
  const providerDocument = await telegramProviderDocumentReady(env.DB).catch(() => "unavailable" as const);
  const providerPolicy = providerDocument === true ? { ...policy, includeDocuments: true as const } : policy;
  const inlineSearchSchema = await telegramInlineSearchReady(env.DB);
  const inlineConsent = inlineSearchSchema && env.TELEGRAM_INLINE_SEARCH === "1";
  const bulkTrash = await telegramBulkTrashReady(env.DB);
  const githubSearch = telegramGitHubSearchProbe(env.DB);
  const providerRefreshSchema = await telegramProviderRefreshReady(env.DB).catch(() => false);
  const providerRefresh = env.TELEGRAM_PROVIDER_REFRESH === "1" && providerIntakeReady && subscriptionRead && providerRefreshSchema;
  const drain = async (limit: number, budget: number) =>
    drainTelegramReplies(env.DB, env.NODES, policy, limit, budget, fetch, aggregateKey, privateShare,
      subscriptionRead, shortLinks, inlineSort, subscriptionNodes, providerQueueReady, bulkTrash, inlineConsent,
      await githubSearch().catch(() => "unavailable" as const), providerRefresh, subscriptionRawFile, providerBatch.controls, apiStatus,
      apiStatusProvider(env) !== null, providerDocument, providerBatchAdmission, telegramPageJumpEpoch(env.TELEGRAM_PAGE_JUMP), publicOrigin);
  const replies = async () => {
    await drain(10, 45_000);
    await reapTelegramViewTickets(env.DB);
    await reapTelegramLifecycle(env.DB);
    if (aggregateKey) await reapTelegramSelected(env.DB);
    if (subscriptionRead) await reapTelegramSubscriptionReadTickets(env.DB);
    if (subscriptionNodes) await reapTelegramSubscriptionNodeTickets(env.DB);
    if (providerRefreshSchema) await reapTelegramProviderRefreshTickets(env.DB);
    if (subscriptionRawFile === true) await reapTelegramRawFileTickets(env.DB);
    if (providerBatch.controls === true) await reapTelegramProviderBatchTickets(env.DB);
    if (shortLinks) await reapFailedTelegramShortLinks(env.DB, policy.botId);
  };
  const documents = async () => {
    if (providerDocument === "unavailable") return;
    const mixedDocument = providerDocument && await telegramMixedDocumentReady(env.DB);
    let claimed = false;
    try {
      claimed = await runTelegramDocumentIntake(env.DB, env.NODES, policy, providerDocument, mixedDocument);
    } finally {
      const reconciled = await reconcileTelegramDocumentJobReplies(env.DB, policy);
      if (claimed || reconciled > 0) {
        await drain(4, 15_000);
      }
    }
  };
  const creations = async () => {
    if (privateShare.context && await recoverTelegramPrivateShareCreation(env.DB, env.NODES, policy, privateShare.context) === "published") {
      await drain(4, 15_000);
    }
  };
  const groupCards = async () => {
    if (privateShare.context && await telegramGroupShareReady(env.DB)) await drainGroupShareCards(env.DB, policy);
  };
  const searches = async () => {
    if (await githubSearch().catch(() => false) && await recoverTelegramGitHubSearch(env.DB, policy) > 0) {
      await drain(4, 15_000);
    }
  };
  const apiStatusReplies = async () => {
    if (apiStatus === true && await reconcileTelegramApiStatus(env.DB, policy) > 0) await drain(4, 15_000);
  };
  const providers = async () => {
    try {
      if (providerIntakeReady && providerBatch.queue !== "unavailable" && providerDocument !== "unavailable") {
        if (providerBatch.queue) await reconcileTelegramProviderBatches(env.DB, policy);
        try {
          if (providerDocument) await promoteTelegramProviderDocument(env.DB, policy, providerBatch.queue);
        } finally {
          await runOneProviderJob(env.DB, env.NODES, env.PROVIDER_FETCH, pin, providerPolicy, providerBatch.queue);
        }
      }
    } finally {
      const results = await Promise.allSettled([
        providerQueueReady ? reconcileTelegramProviderReplies(env.DB, policy) : Promise.resolve(0),
        (async () => {
          if (providerBatch.queue === true) await reconcileTelegramProviderBatches(env.DB, policy, false);
          return providerBatch.controls === true ? reconcileTelegramProviderBatchReplies(env.DB, policy) : 0;
        })(),
        (async () => {
          if (providerDocument !== true) return 0;
          await settleTelegramProviderDocuments(env.DB, policy);
          return reconcileTelegramProviderDocumentReplies(env.DB, policy);
        })(),
      ]);
      if (results.some((result) => result.status === "fulfilled" && result.value > 0)) await drain(4, 15_000);
      if (results.some((result) => result.status === "rejected")) throw new Error("Telegram provider replies could not recover.");
    }
  };
  const results = await Promise.allSettled([replies(), documents(), creations(), groupCards(), searches(), apiStatusReplies(), retireTelegramDocumentStage(env.DB, env.NODES, policy),
    privateShare.schemaReady ? retireAbandonedTelegramPrivateShareCreation(env.DB, env.NODES, policy) : Promise.resolve(),
    providers(), inlineSearchSchema ? reapTelegramInlineSearch(env.DB, policy.botId) : Promise.resolve()]);
  if (results.some(({ status }) => status === "rejected")) {
    throw new Error("Telegram scheduled recovery could not finish.");
  }
}

async function scheduled(_controller: ScheduledController, env: Env): Promise<void> {
  const publicOrigin = parsePublicOrigin(env.PUBLIC_ORIGIN);
  if (publicOrigin === null) return;
  const pin = providerPin(env);
  try {
    const policy = parseTelegramPolicy(env.TELEGRAM_ISOLATION_CONFIG);
    if (policy) await recoverTelegramWork(env, policy, pin, await telegramProviderQueueReady(env, pin), publicOrigin);
    else if (env.TELEGRAM_ISOLATION_CONFIG === undefined) {
      const general = parseGeneralTelegramPin(env.TELEGRAM_GENERAL_CONFIG, env.BUILD_REVISION);
      if (general) await recoverGeneralTelegramReplies(env.DB, general);
    }
  } finally {
    await runOneProviderJob(env.DB, env.NODES, env.PROVIDER_FETCH, pin);
  }
}

export default { fetch: fetchRequest, scheduled } satisfies ExportedHandler<Env>;
