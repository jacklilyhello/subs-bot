import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash, timingSafeEqual } from "node:crypto";
import { readFile } from "node:fs/promises";
import { networkInterfaces } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { build } from "esbuild";
import { Log, LogLevel, Miniflare } from "miniflare";
import { PRODUCTION_PUBLIC_ORIGIN } from "../src/public-origin.ts";
import { createPrivateShare, privateShareCodeDigest } from "../src/private-shares.ts";
import { publishNodeSnapshot } from "../src/storage.ts";
import { parseSubscriptionDocument } from "../src/subscription-document.ts";
import { claimTelegramDocumentJob } from "../src/telegram/document-jobs.ts";
import { persistTelegramDocumentJob, reconcileTelegramDocumentJobReplies, retireTelegramDocumentStage } from "../src/telegram/document-persistence.ts";
import { parseTelegramAggregateKey } from "../src/telegram/aggregate-actions.ts";
import { reapFailedTelegramShortLinks } from "../src/telegram/short-link-actions.ts";
import { GENERAL_AUTH_LEGACY_ROLE, type GeneralAuthReplayMessage, type GeneralAuthReplayPin } from "../src/telegram/general-auth-replay.ts";
import { beginGeneralTelegramReply, claimGeneralTelegramReply, parseGeneralTelegramPin } from "../src/telegram/general-auth-runtime.ts";
import { acceptGeneralSharedTelegramCommand, beginGeneralSharedTelegramReply, claimGeneralSharedTelegramReply,
  recoverGeneralSharedTelegramReplies } from "../src/telegram/general-auth-shared.ts";
import { generalCurrentAuthoritySql, generalCurrentReceiptSql, generalOrdinaryReplyEligibilitySql, generalPolicyBindings,
  generalRecordedOriginSql } from "../src/telegram/general-receipt.ts";
import { acceptTelegramCommand, claimTelegramReply } from "../src/telegram/store.ts";
import { acceptTelegramView } from "../src/telegram/views.ts";
import { assertGeneralReadLane, readGeneralReadLane } from "../src/telegram/general-read-lane.ts";
import { MAX_TEMP_BATCH_NODES, MAX_TEMP_OWNER_NODES } from "../src/telegram/temp-storage.ts";

type Fixture = Omit<GeneralAuthReplayPin, "botUsername" | "webhookSecret" | "generation" | "cutoverAt"> & {
  bundleSha256: string; compatibilityDate: string; statements: string[];
};

function diagnosticError(error: unknown): string {
  for (let depth = 0; depth < 4 && error instanceof Error; depth++, error = error.cause) {
    if (/expression tree is too large|maximum (expression )?depth/iu.test(error.message)) return "expression-depth";
    if (/too many (sql )?variables|wrong number of parameter bindings/iu.test(error.message)) return "bindings";
    if (/no such (table|column)|ambiguous column/iu.test(error.message)) return "schema";
    if (/near .*syntax error/iu.test(error.message)) return "syntax";
    if (/constraint failed/iu.test(error.message)) return "constraint";
  }
  return "unclassified";
}

test("closed general authorization replays a sealed candidate in a separate emitted Worker", { timeout: 60_000 }, async (t) => {
  assert.equal(process.platform, "linux");
  assert.notEqual(process.getuid?.(), 0);
  assert.deepEqual(Object.keys(networkInterfaces()), ["lo"]);
  // Direct admission calls let the test revoke a leased reply before the emitted Worker drains it.
  // Keep the Worker comparison semantics when those calls run in the Node fixture process.
  const oldComparison = Object.getOwnPropertyDescriptor(crypto.subtle, "timingSafeEqual");
  Object.defineProperty(crypto.subtle, "timingSafeEqual", {
    configurable: true,
    value: (received: ArrayBuffer, expected: ArrayBuffer) => {
      assert.equal(received.byteLength, 32);
      assert.equal(expected.byteLength, 32);
      return timingSafeEqual(new Uint8Array(received), new Uint8Array(expected));
    },
  });
  t.after(() => {
    if (oldComparison) Object.defineProperty(crypto.subtle, "timingSafeEqual", oldComparison);
    else Reflect.deleteProperty(crypto.subtle, "timingSafeEqual");
  });
  const { SUBS_BOT_LEGACY_PYTHON, WORKER_TEST_BUNDLE_DIR, WORKER_TEST_REVISION } = process.env;
  assert.ok(SUBS_BOT_LEGACY_PYTHON && WORKER_TEST_BUNDLE_DIR && WORKER_TEST_REVISION);
  const generated = spawnSync(SUBS_BOT_LEGACY_PYTHON, ["-B", fileURLToPath(new URL("./telegram-general-auth-replay-fixture.py", import.meta.url))], {
    env: { PATH: "/usr/bin:/bin", TMPDIR: process.env.TMPDIR, WORKER_TEST_BUNDLE_DIR, WORKER_TEST_REVISION },
    maxBuffer: 512 * 1024, timeout: 15_000,
  });
  if (generated.status !== 0) {
    const diagnostic = /^Synthetic general authorization fixture could not be confirmed \((sandbox|artifact|candidate)\)\.\n$/u
      .exec(generated.stderr?.toString() ?? "");
    assert.fail(`Synthetic replay fixture was not verified (${diagnostic?.[1] ?? "unconfirmed"}).`);
  }
  const { bundleSha256, compatibilityDate, statements, ...fixture } = JSON.parse(generated.stdout.toString()) as Fixture;
  assert.equal(fixture.releaseRevision, WORKER_TEST_REVISION);
  assert.equal(fixture.botId, "105");
  const servingScript = await readFile(join(WORKER_TEST_BUNDLE_DIR, "index.js"));
  assert.equal(createHash("sha256").update(servingScript).digest("hex"), bundleSha256);
  const entry = await build({ entryPoints: [fileURLToPath(new URL("./telegram-general-auth-replay-entry.ts", import.meta.url))],
    bundle: true, format: "esm", platform: "browser", target: "es2022", write: false });
  assert.equal(entry.outputFiles.length, 1);
  const now = Math.floor(Date.now() / 1000);
  const pin: GeneralAuthReplayPin = { ...fixture, botUsername: "GeneralFixtureBot", webhookSecret: "fixture-general-only",
    generation: 1, cutoverAt: now - 20 };
  const isolation = { botId: "151", botUsername: "IsolationFixtureBot", webhookSecret: "fixture-isolation-only",
    botToken: "151:fixture-isolation-token", adminId: "181", memberId: "182", groupId: "-100300" };
  const sent: GeneralAuthReplayMessage[] = [];
  const generalSent: GeneralAuthReplayMessage[] = [];
  const laneSent: GeneralAuthReplayMessage[] = [];
  const sharedSent: (GeneralAuthReplayMessage & { message_thread_id?: number })[] = [];
  const lifecycleSent: (GeneralAuthReplayMessage & { reply_markup?: {
    force_reply?: boolean; inline_keyboard?: { text: string; callback_data: string }[][];
  } })[] = [];
  const lifecycleMessagesById = new Map<number, (typeof lifecycleSent)[number]>();
  const lifecycleAcks = new Set<string>();
  const fixtureDocuments = new Map<string, string>();
  const tempRawDocuments = new Map<number, { actorId: string; caption: string; body: string }>();
  const fileRequests: string[] = [];
  let lifecycleAckCalls = 0;
  let failTransport = false;
  let failGeneralTransport = false;
  const generalToken = `${fixture.botId}:fixture-general-token`;
  const generalConfig = JSON.stringify({ botId: pin.botId, botUsername: pin.botUsername,
    webhookSecret: pin.webhookSecret, botToken: generalToken, generation: pin.generation, cutoverAt: pin.cutoverAt,
    activationSha256: pin.candidateManifestSha256 });
  const generalPin = parseGeneralTelegramPin(generalConfig, fixture.releaseRevision);
  assert.ok(generalPin && !generalPin.sharedOutbox);
  const sharedConfig = JSON.stringify({ ...JSON.parse(generalConfig), outbox: "shared" });
  const sharedPin = parseGeneralTelegramPin(sharedConfig, fixture.releaseRevision);
  assert.ok(sharedPin?.sharedOutbox && !sharedPin.privateManagement);
  const lifecycleConfig = JSON.stringify({ ...JSON.parse(generalConfig), outbox: "shared-private-management" });
  const privatePin = parseGeneralTelegramPin(lifecycleConfig, fixture.releaseRevision);
  assert.ok(privatePin?.sharedOutbox && privatePin.privateManagement && !privatePin.privateFormats && !privatePin.privateTemp);
  const formatsConfig = JSON.stringify({ ...JSON.parse(generalConfig), outbox: "shared-private-management-formats" });
  const formatsPin = parseGeneralTelegramPin(formatsConfig, fixture.releaseRevision);
  assert.ok(formatsPin?.sharedOutbox && formatsPin.privateManagement && formatsPin.privateFormats && !formatsPin.privateTemp);
  const tempConfig = JSON.stringify({ ...JSON.parse(generalConfig), outbox: "shared-private-temp" });
  const tempPin = parseGeneralTelegramPin(tempConfig, fixture.releaseRevision);
  assert.ok(tempPin?.sharedOutbox && tempPin.privateManagement && tempPin.privateTemp && !tempPin.privateFormats && !tempPin.privateDocument);
  const cumulativeConfig = JSON.stringify({ ...JSON.parse(generalConfig), outbox: "shared-private-management-formats-temp" });
  const cumulativePin = parseGeneralTelegramPin(cumulativeConfig, fixture.releaseRevision);
  assert.ok(cumulativePin?.sharedOutbox && cumulativePin.privateManagement && cumulativePin.privateFormats
    && cumulativePin.privateTemp && !cumulativePin.privateDocument);
  const documentConfig = JSON.stringify({ ...JSON.parse(generalConfig), outbox: "shared-private-management-formats-temp-node-document" });
  const documentPin = parseGeneralTelegramPin(documentConfig, fixture.releaseRevision);
  assert.ok(documentPin?.sharedOutbox && documentPin.privateManagement && documentPin.privateFormats
    && documentPin.privateTemp && documentPin.privateDocument && !documentPin.privateProvider);
  const providerConfig = JSON.stringify({ ...JSON.parse(generalConfig),
    outbox: "shared-private-management-formats-temp-node-document-provider" });
  const generalProviderPin = parseGeneralTelegramPin(providerConfig, fixture.releaseRevision);
  assert.ok(generalProviderPin?.privateProvider && generalProviderPin.privateDocument && !generalProviderPin.privateClaims);
  const claimsConfig = JSON.stringify({ ...JSON.parse(generalConfig),
    outbox: "shared-private-management-formats-temp-node-document-provider-claims" });
  const claimsPin = parseGeneralTelegramPin(claimsConfig, fixture.releaseRevision);
  assert.ok(claimsPin?.privateClaims && claimsPin.privateProvider && !claimsPin.privateShareCreation && !claimsPin.privateAggregate);
  const shareConfig = JSON.stringify({ ...JSON.parse(generalConfig),
    outbox: "shared-private-management-formats-temp-node-document-provider-claims-share" });
  const sharePin = parseGeneralTelegramPin(shareConfig, fixture.releaseRevision);
  assert.ok(sharePin?.privateShareCreation && !sharePin.privateAggregate);
  const aggregateConfig = JSON.stringify({ ...JSON.parse(generalConfig),
    outbox: "shared-private-management-formats-temp-node-document-provider-claims-share-aggregate" });
  const aggregatePin = parseGeneralTelegramPin(aggregateConfig, fixture.releaseRevision);
  assert.ok(aggregatePin?.privateAggregate && aggregatePin.privateShareCreation && aggregatePin.privateClaims);
  assert.equal(aggregatePin.privateSelected, false);
  const selectedConfig = JSON.stringify({ ...JSON.parse(generalConfig),
    outbox: "shared-private-management-formats-temp-node-document-provider-claims-share-aggregate-selected" });
  assert.ok(parseGeneralTelegramPin(selectedConfig, fixture.releaseRevision)?.privateSelected);
  const shortConfig = JSON.stringify({ ...JSON.parse(generalConfig),
    outbox: "shared-private-management-formats-temp-node-document-provider-claims-share-aggregate-selected-short" });
  const shortPin = parseGeneralTelegramPin(shortConfig, fixture.releaseRevision);
  assert.ok(shortPin?.privateShort && shortPin.privateSelected && !shortPin.privateAuthorization);
  const typedConfig = (mode: "issue" | "drain") => JSON.stringify({ ...JSON.parse(shortConfig), subscriptionShorts: mode });
  assert.equal(shortPin.subscriptionShorts, undefined);
  assert.equal(parseGeneralTelegramPin(typedConfig("issue"), fixture.releaseRevision)?.subscriptionShorts, "issue");
  assert.equal(parseGeneralTelegramPin(JSON.stringify({ ...JSON.parse(formatsConfig), subscriptionShorts: "issue" }),
    fixture.releaseRevision), null);
  const aggregateKeyRaw = Buffer.alloc(32, 17).toString("base64url");
  const shareKeyRaw = Buffer.alloc(32, 0x61).toString("base64url");
  const authConfig = JSON.stringify({ ...JSON.parse(shortConfig), authManagement: true });
  const inlineConfig = JSON.stringify({ ...JSON.parse(authConfig), inlineSearch: true });
  const inlinePin = parseGeneralTelegramPin(inlineConfig, fixture.releaseRevision);
  assert.ok(inlinePin?.privateInline);
  const inlineAnswers = new Map<string, { titles: string[]; messages: string[] }>();
  const authPin = parseGeneralTelegramPin(authConfig, fixture.releaseRevision);
  assert.ok(authPin?.privateAuthorization && authPin.privateShort && authPin.privateSelected && authPin.privateAggregate
    && authPin.privateShareCreation && authPin.privateClaims);
  assert.equal(parseGeneralTelegramPin(JSON.stringify({ ...JSON.parse(sharedConfig), authManagement: true }),
    fixture.releaseRevision), null);
  const groupShareDestination = { chatId: "-100600", chatType: "supergroup" };
  const groupShareConfig = JSON.stringify({ ...JSON.parse(authConfig), groupShare: groupShareDestination });
  assert.deepEqual(parseGeneralTelegramPin(groupShareConfig, fixture.releaseRevision)?.groupShare, groupShareDestination);
  assert.equal(parseGeneralTelegramPin(JSON.stringify({ ...JSON.parse(shareConfig),
    groupShare: { ...groupShareDestination, threadId: 17 } }), fixture.releaseRevision), null);
  const groupCards: { id: number; method: string; body: (typeof lifecycleSent)[number] }[] = [];
  const claimSends = new Map<number, { actorId: string; text?: string; body?: Buffer }>();
  for (const outbox of ["legacy", "shared-lifecycle", "shared-path", ["shared-private-management"]]) {
    assert.equal(parseGeneralTelegramPin(JSON.stringify({ ...JSON.parse(generalConfig), outbox }),
      fixture.releaseRevision), null);
  }
  const d1Databases = { DB: "sealed-general-auth-replay" };
  const providerRevision = "a".repeat(40), imageSha256 = "b".repeat(64);
  const sourceUrl = "https://provider.fixture.invalid/sub/%2f?fixture=signed%2Bvalue";
  const goodLineUrl = "https://provider.fixture.invalid/multiline/%2f?fixture=signed%7Cline";
  const failedLineUrl = "https://provider.fixture.invalid/multiline/failed?fixture=signed%2Bline";
  const providerShare = "ss://YWVzLTI1Ni1nY206Zml4dHVyZQ@203.0.113.10:8388#general-provider";
  let typedRetry: { messageId: number; attempts: string[] } | null = null;
  const privateTransport = async (request: Request) => {
    const api = `https://api.telegram.org/bot${generalToken}/`;
    const files = `https://api.telegram.org/file/bot${generalToken}/documents/`;
    if (request.url === api + "answerInlineQuery") {
      const answer = await request.json() as { inline_query_id: string; is_personal: boolean; cache_time: number;
        next_offset: string; results: { title: string; input_message_content: { message_text: string } }[] };
      assert.equal(request.method, "POST");
      assert.equal(answer.is_personal, true);
      assert.equal(answer.cache_time, 0);
      assert.equal(answer.next_offset, "");
      assert.equal(inlineAnswers.has(answer.inline_query_id), false, "an inline query can send only once");
      inlineAnswers.set(answer.inline_query_id, { titles: answer.results.map(({ title }) => title),
        messages: answer.results.map(({ input_message_content }) => input_message_content.message_text) });
      return Response.json({ ok: true, result: true });
    }
    if (request.url === api + "getFile") {
      assert.equal(request.method, "POST");
      const { file_id: fileId } = await request.json() as { file_id: string };
      const fixture = fixtureDocuments.get(fileId);
      assert.ok(fixture);
      fileRequests.push(fileId);
      return Response.json({ ok: true, result: { file_path: `documents/${fileId}`, file_size: Buffer.byteLength(fixture) } });
    }
    if (request.url.startsWith(files)) {
      assert.equal(request.method, "GET");
      const fileId = request.url.slice(files.length);
      const fixture = fixtureDocuments.get(fileId);
      assert.ok(fixture);
      fileRequests.push(fileId);
      return new Response(fixture);
    }
    assert.equal(request.method, "POST");
    if (request.url === api + "answerCallbackQuery") {
      lifecycleAckCalls++;
      const ack = await request.json() as { callback_query_id: string };
      assert.ok(/^fixture-7[0-9]{3}$/u.test(ack.callback_query_id) && !lifecycleAcks.has(ack.callback_query_id));
      lifecycleAcks.add(ack.callback_query_id);
      return Response.json({ ok: true, result: true });
    }
    if (request.url === api + "sendDocument") {
      const form = await request.formData();
      const file = form.get("document");
      assert.ok(file && typeof file !== "string" && file.name === "temporary-nodes.txt");
      const { message_id: id } = JSON.parse(String(form.get("reply_parameters"))) as { message_id: number };
      assert.equal(id, 8306);
      assert.ok(!tempRawDocuments.has(id));
      const actorId = String(form.get("chat_id"));
      tempRawDocuments.set(id, { actorId, caption: String(form.get("caption")), body: await file.text() });
      return Response.json({ ok: true, result: { chat: { id: Number(actorId) }, message_id: 19_800 } });
    }
    assert.equal(request.url, api + "sendMessage");
    const message = await request.json() as (typeof lifecycleSent)[number];
    if (typedRetry && message.reply_parameters.message_id === typedRetry.messageId && message.text.includes("/s/")) {
      typedRetry.attempts.push(message.text);
      if (typedRetry.attempts.length === 1) {
        return Response.json({ ok: false, error_code: 429, parameters: { retry_after: 60 } }, { status: 429 });
      }
    }
    lifecycleSent.push(message);
    const messageId = 9400 + lifecycleSent.length;
    lifecycleMessagesById.set(messageId, message);
    return Response.json({ ok: true, result: { chat: { id: Number(message.chat_id) }, message_id: messageId } });
  };
  const runtime = new Miniflare({ log: new Log(LogLevel.NONE), workers: [
    { name: "serving", modules: true, script: servingScript.toString(), compatibilityDate, d1Databases, r2Buckets: ["NODES"],
      bindings: { BUILD_REVISION: fixture.releaseRevision, TELEGRAM_ISOLATION_CONFIG: JSON.stringify(isolation),
        TELEGRAM_GENERAL_CONFIG: generalConfig, REPLAY_PIN: pin },
      outboundService: () => { throw new Error("Unexpected serving transport."); } },
    { name: "rehearsal", modules: true, script: servingScript.toString(), compatibilityDate, d1Databases, r2Buckets: ["NODES"],
      bindings: { BUILD_REVISION: fixture.releaseRevision, TELEGRAM_ISOLATION_CONFIG: JSON.stringify(isolation) },
      outboundService: async (request: Request) => {
        assert.equal(request.url, `https://api.telegram.org/bot${isolation.botToken}/sendMessage`);
        assert.equal(request.method, "POST");
        const message = await request.json() as GeneralAuthReplayMessage;
        laneSent.push(message);
        return Response.json({ ok: true, result: { chat: { id: Number(message.chat_id) }, message_id: 9500 + laneSent.length } });
      } },
    { name: "general", modules: true, script: servingScript.toString(), compatibilityDate, d1Databases, r2Buckets: ["NODES"],
      bindings: { BUILD_REVISION: fixture.releaseRevision, TELEGRAM_GENERAL_CONFIG: generalConfig },
      outboundService: async (request: Request) => {
        assert.equal(request.url, `https://api.telegram.org/bot${generalToken}/sendMessage`);
        assert.equal(request.method, "POST");
        const message = await request.json() as GeneralAuthReplayMessage;
        generalSent.push(message);
        return failGeneralTransport ? new Response(null, { status: 503 }) : Response.json({
          ok: true, result: { chat: { id: Number(message.chat_id) }, message_id: generalSent.length },
        });
      } },
    { name: "shared", modules: true, script: servingScript.toString(), compatibilityDate, d1Databases, r2Buckets: ["NODES"],
      bindings: { BUILD_REVISION: fixture.releaseRevision, TELEGRAM_GENERAL_CONFIG: sharedConfig },
      outboundService: async (request: Request) => {
        assert.equal(request.url, `https://api.telegram.org/bot${generalToken}/sendMessage`);
        assert.equal(request.method, "POST");
        const message = await request.json() as (typeof sharedSent)[number];
        sharedSent.push(message);
        return Response.json({ ok: true, result: { chat: { id: Number(message.chat_id) }, message_id: 9300 + sharedSent.length,
          message_thread_id: message.reply_parameters.message_id === 7204 ? 45 : message.message_thread_id } });
      } },
    { name: "lifecycle", modules: true, script: servingScript.toString(), compatibilityDate, d1Databases, r2Buckets: ["NODES"],
      bindings: { BUILD_REVISION: fixture.releaseRevision, TELEGRAM_GENERAL_CONFIG: lifecycleConfig },
      outboundService: privateTransport },
    { name: "formats", modules: true, script: servingScript.toString(), compatibilityDate, d1Databases, r2Buckets: ["NODES"],
      bindings: { BUILD_REVISION: fixture.releaseRevision, TELEGRAM_GENERAL_CONFIG: documentConfig, PUBLIC_ORIGIN: PRODUCTION_PUBLIC_ORIGIN },
      outboundService: privateTransport },
    ...[true, false].map((enabled) => ({ name: enabled ? "general-inline" : "general-inline-paused", modules: true,
      script: servingScript.toString(), compatibilityDate, d1Databases, r2Buckets: ["NODES"], outboundService: privateTransport,
      bindings: { BUILD_REVISION: fixture.releaseRevision, TELEGRAM_GENERAL_CONFIG: inlineConfig,
        TELEGRAM_AGGREGATE_KEY: aggregateKeyRaw, TELEGRAM_PRIVATE_SHARE_CREATION_KEY: shareKeyRaw,
        ...(enabled ? { TELEGRAM_INLINE_SEARCH: "1" } : {}) } })),
    { name: "auth", modules: true, script: servingScript.toString(), compatibilityDate, d1Databases, r2Buckets: ["NODES"],
      bindings: { BUILD_REVISION: fixture.releaseRevision, TELEGRAM_GENERAL_CONFIG: authConfig,
        TELEGRAM_AGGREGATE_KEY: aggregateKeyRaw, TELEGRAM_PRIVATE_SHARE_CREATION_KEY: shareKeyRaw }, outboundService: privateTransport },
    ...[true, false].map((withKey) => ({ name: withKey ? "aggregate" : "aggregate-no-key", modules: true,
      script: servingScript.toString(), compatibilityDate, d1Databases, r2Buckets: ["NODES"], outboundService: privateTransport,
      bindings: { BUILD_REVISION: fixture.releaseRevision, TELEGRAM_GENERAL_CONFIG: aggregateConfig, PUBLIC_ORIGIN: PRODUCTION_PUBLIC_ORIGIN,
        ...(withKey ? { TELEGRAM_AGGREGATE_KEY: aggregateKeyRaw } : { TELEGRAM_PRIVATE_SHARE_CREATION_KEY: shareKeyRaw }) } })),
    { name: "selected", modules: true, script: servingScript.toString(), compatibilityDate, d1Databases, r2Buckets: ["NODES"],
      bindings: { BUILD_REVISION: fixture.releaseRevision, TELEGRAM_GENERAL_CONFIG: selectedConfig,
        PUBLIC_ORIGIN: PRODUCTION_PUBLIC_ORIGIN, TELEGRAM_AGGREGATE_KEY: aggregateKeyRaw }, outboundService: privateTransport },
    { name: "ordinary-short", modules: true, script: servingScript.toString(), compatibilityDate, d1Databases, r2Buckets: ["NODES"],
      bindings: { BUILD_REVISION: fixture.releaseRevision, TELEGRAM_GENERAL_CONFIG: shortConfig,
        PUBLIC_ORIGIN: PRODUCTION_PUBLIC_ORIGIN, TELEGRAM_AGGREGATE_KEY: aggregateKeyRaw }, outboundService: privateTransport },
    ...(["issue", "drain"] as const).map((mode) => ({ name: `typed-short-${mode}`, modules: true, script: servingScript.toString(),
      compatibilityDate, d1Databases, r2Buckets: ["NODES"], outboundService: privateTransport,
      bindings: { BUILD_REVISION: fixture.releaseRevision, TELEGRAM_GENERAL_CONFIG: typedConfig(mode),
        PUBLIC_ORIGIN: PRODUCTION_PUBLIC_ORIGIN, TELEGRAM_AGGREGATE_KEY: aggregateKeyRaw } })),
    ...["provider-open", "provider-paused", "provider-multiline"].map((name) => ({ name, modules: true,
      script: servingScript.toString(), compatibilityDate, d1Databases, r2Buckets: ["NODES"], outboundService: privateTransport,
      serviceBindings: { PROVIDER_FETCH: { name: "provider-rpc", entrypoint: "ProviderFetch" } },
      bindings: { BUILD_REVISION: fixture.releaseRevision, TELEGRAM_GENERAL_CONFIG: providerConfig,
        PROVIDER_REVISION: providerRevision, PROVIDER_IMAGE_SHA256: imageSha256,
        ...(name === "provider-paused" ? {} : { TELEGRAM_PROVIDER_URL_IMPORT: "1", TELEGRAM_PROVIDER_REFRESH: "1" }),
        ...(name === "provider-multiline" ? { TELEGRAM_PROVIDER_URL_DOCUMENTS: "1" } : {}) } })),
    { name: "share-creation", modules: true, script: servingScript.toString(), compatibilityDate, d1Databases, r2Buckets: ["NODES"],
      bindings: { BUILD_REVISION: fixture.releaseRevision, TELEGRAM_GENERAL_CONFIG: shareConfig,
        TELEGRAM_PRIVATE_SHARE_CREATION_KEY: shareKeyRaw, PUBLIC_ORIGIN: PRODUCTION_PUBLIC_ORIGIN },
      outboundService: privateTransport },
    { name: "group-share", modules: true, script: servingScript.toString(), compatibilityDate, d1Databases, r2Buckets: ["NODES"],
      bindings: { BUILD_REVISION: fixture.releaseRevision, TELEGRAM_GENERAL_CONFIG: groupShareConfig,
        TELEGRAM_PRIVATE_SHARE_CREATION_KEY: shareKeyRaw },
      outboundService: async (request: Request) => {
        const method = request.url.split("/").at(-1);
        if (method !== "sendMessage" && method !== "editMessageText") return privateTransport(request);
        const body = await request.clone().json() as (typeof lifecycleSent)[number] & { message_id?: number };
        if (body.chat_id !== groupShareDestination.chatId) return privateTransport(request);
        const id = method === "editMessageText" ? body.message_id! : 9901;
        groupCards.push({ id, method, body });
        return Response.json({ ok: true, result: { message_id: id,
          chat: { id: Number(groupShareDestination.chatId), type: groupShareDestination.chatType } } });
      } },
    { name: "claims", modules: true, script: servingScript.toString(), compatibilityDate, d1Databases, r2Buckets: ["NODES"],
      bindings: { BUILD_REVISION: fixture.releaseRevision, TELEGRAM_GENERAL_CONFIG: claimsConfig },
      outboundService: async (request: Request) => {
        const api = `https://api.telegram.org/bot${generalToken}/`;
        assert.equal(request.method, "POST");
        let actorId: string, replyId: number, text: string | undefined, body: Buffer | undefined;
        if (request.url === api + "sendDocument") {
          const form = await request.formData();
          actorId = String(form.get("chat_id"));
          replyId = JSON.parse(String(form.get("reply_parameters"))).message_id as number;
          const document = form.get("document");
          assert.ok(document && typeof document !== "string" && document.name === "private-share.txt");
          body = Buffer.from(await document.arrayBuffer());
        } else {
          assert.equal(request.url, api + "sendMessage");
          const message = await request.json() as GeneralAuthReplayMessage;
          actorId = message.chat_id;
          replyId = message.reply_parameters.message_id;
          text = message.text;
        }
        assert.ok(!claimSends.has(replyId));
        claimSends.set(replyId, { actorId, text, body });
        return Response.json({ ok: true, result: { chat: { id: Number(actorId) }, message_id: replyId + 3000 } });
      } },
    { name: "provider-rpc", modules: true, compatibilityDate, d1Databases,
      script: `import { WorkerEntrypoint } from 'cloudflare:workers';
        export class ProviderFetch extends WorkerEntrypoint {
          async fetchSubscription(input) {
            if (Object.keys(input).length !== 3 || !${JSON.stringify([sourceUrl, goodLineUrl, failedLineUrl])}.includes(input.url) ||
                input.providerRevision !== ${JSON.stringify(providerRevision)} || input.imageSha256 !== ${JSON.stringify(imageSha256)}) {
              throw new Error('Unexpected synthetic provider request.');
            }
            const fail = await this.env.DB.prepare('UPDATE general_provider_fixture SET calls=calls+1 RETURNING fail').first('fail');
            if (fail === 1 || input.url === ${JSON.stringify(failedLineUrl)}) {
              return {ok:false,code:'http-status',retryable:false,upstreamStatus:403};
            }
            const body = new TextEncoder().encode(${JSON.stringify(providerShare)}).buffer;
            const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', body));
            return {ok:true,body,bodySha256:Array.from(hash, byte => byte.toString(16).padStart(2,'0')).join(''),
              metadata:{'profile-title':'General%20Provider.yaml'}};
          }
        }
        export default {fetch(){throw new Error('Public provider transport was invoked.')}};` },
    { name: "replay", modules: true, script: entry.outputFiles[0].text, compatibilityDate, d1Databases, bindings: { REPLAY_PIN: pin },
      outboundService: async (request: Request) => {
        assert.equal(request.url, "https://transport.fixture.invalid/sendMessage");
        assert.equal(request.method, "POST");
        sent.push(await request.json() as GeneralAuthReplayMessage);
        return new Response(null, { status: failTransport ? 503 : 200 });
      } },
  ] });
  t.after(() => runtime.dispose());
  const db = await runtime.getD1Database("DB", "replay");
  assert.ok(statements.length > 0 && statements.length <= 256);
  for (let index = 0; index < statements.length; index += 64) {
    const slice = statements.slice(index, index + 64);
    const results = await db.batch(slice.map((sql) => db.prepare(sql)));
    assert.equal(results.length, slice.length);
    assert.ok(results.every(({ success }) => success));
  }
  assert.deepEqual((await db.prepare("PRAGMA foreign_key_check").all()).results, []);
  assert.equal(await db.prepare("SELECT count(*) AS n FROM general_auth_principals").first("n"), 5);
  assert.equal(await db.prepare("SELECT count(*) AS n FROM general_auth_groups").first("n"), 2);

  // Deliberately fixture-local. The candidate and serving migrations have no such DDL or activation.
  await db.batch([
    db.prepare(`CREATE TABLE general_auth_replay_fence (
      bot_id TEXT PRIMARY KEY REFERENCES general_auth_installation,worker_manifest_sha256 TEXT NOT NULL,
      candidate_manifest_sha256 TEXT NOT NULL,release_revision TEXT NOT NULL,generation INTEGER NOT NULL,
      cutover_at INTEGER NOT NULL) STRICT`),
    db.prepare(`CREATE TABLE general_auth_replay_receipts (
      receipt_id INTEGER PRIMARY KEY,bot_id TEXT NOT NULL REFERENCES general_auth_replay_fence,
      update_id INTEGER NOT NULL,generation INTEGER NOT NULL,actor_id TEXT NOT NULL,chat_id TEXT NOT NULL CHECK (chat_id=actor_id),
      message_id INTEGER NOT NULL,message_date INTEGER NOT NULL,role TEXT NOT NULL CHECK (role IN ('admin','member')),
      command TEXT NOT NULL CHECK (command IN ('help','list')),received_at INTEGER NOT NULL,
      state TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','sending','sent','uncertain')),
      UNIQUE(bot_id,update_id)) STRICT`),
    ...["101", "102", "103", "104", "106", "107"].map((actor) => db.prepare(`
      INSERT INTO subscriptions (owner_id,name,source_url,token,created_at,updated_at) VALUES (?,?,?,?,?,?)
    `).bind(actor, `Own ${actor} https://display.fixture.invalid/hidden`, "https://source.fixture.invalid/hidden",
      `fixture-token-${actor}-only`, now, now)),
  ]);

  const replay = await runtime.getWorker("replay");
  const serving = await runtime.getWorker("serving");
  const general = await runtime.getWorker("general");
  let sequence = 1000;
  type PostOptions = { updateId?: number; chatId?: number; chatType?: string; date?: number; secret?: string;
    message?: Record<string, unknown>; worker?: typeof replay };
  const post = (actor: number, text: string, options: PostOptions = {}) => (options.worker ?? replay).fetch(
    "https://app.fixture.invalid/telegram/webhook", { method: "POST", headers: { "Content-Type": "application/json",
      "X-Telegram-Bot-Api-Secret-Token": options.secret ?? pin.webhookSecret },
    body: JSON.stringify({ update_id: options.updateId ?? ++sequence, message: {
      from: { id: actor, is_bot: false }, chat: { id: options.chatId ?? actor, type: options.chatType ?? "private" },
      date: options.date ?? now - 5, message_id: options.updateId ?? sequence, text,
      entities: [{ type: "bot_command", offset: 0, length: text.split(" ")[0].length }], ...options.message,
    } }),
  });
  const drain = async () => {
    const response = await replay.fetch("https://app.fixture.invalid/test/drain", { method: "POST" });
    assert.equal(response.status, 200);
    return (await response.json() as { outcome: string }).outcome;
  };
  const generalPost = (actor: number, text: string, options: PostOptions = {}) => post(actor, text, { ...options, worker: general });
  const generalState = (updateId: number) =>
    db.prepare("SELECT state FROM telegram_general_replies WHERE update_id=?").bind(updateId).first<string>("state");
  const waitForGeneral = async (updateId: number, expected: string) => {
    const end = Date.now() + 4000;
    while (await generalState(updateId) !== expected && Date.now() < end) {
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    assert.equal(await generalState(updateId), expected);
  };
  assert.equal((await generalPost(101, "/help")).status, 204);
  await db.batch([
    db.prepare(`INSERT INTO telegram_general_policy (bot_id,generation,release_revision,activation_sha256,cutover_at)
      VALUES (?,?,?,?,?)`).bind(generalPin.botId, generalPin.generation, generalPin.releaseRevision,
      generalPin.activationSha256, generalPin.cutoverAt),
    db.prepare(`INSERT INTO telegram_general_actors (bot_id,generation,actor_id,revision,effective_at,role)
      SELECT principal.bot_id,?,principal.user_id,1,?,COALESCE((${GENERAL_AUTH_LEGACY_ROLE}),'denied')
      FROM general_auth_principals AS principal WHERE principal.bot_id=?`)
      .bind(generalPin.generation, generalPin.cutoverAt, generalPin.botId),
  ]);
  assert.equal((await generalPost(101, "/help")).status, 204, "seeded roles are closed before activation");
  await db.prepare("UPDATE telegram_general_policy SET active=1,cutover_at=cutover_at+1 WHERE bot_id=?").bind(pin.botId).run();
  assert.equal((await generalPost(101, "/help")).status, 204, "a different cutover cannot activate the binding");
  await db.prepare("UPDATE telegram_general_policy SET cutover_at=? WHERE bot_id=?").bind(pin.cutoverAt, pin.botId).run();
  assert.equal((await post(101, "/help", { worker: serving, secret: isolation.webhookSecret })).status, 204,
    "existing isolation policy wins even when the general policy is active");
  assert.equal((await generalPost(102, "/list")).status, 204);
  assert.equal((await generalPost(107, "/list")).status, 204);
  assert.equal((await generalPost(104, "/list", { chatType: "supergroup", chatId: -100100 })).status, 204);
  assert.equal((await generalPost(104, "/list", { date: pin.cutoverAt })).status, 204);
  assert.equal((await generalPost(104, "/auth")).status, 204);
  assert.equal(generalSent.length, 0);
  assert.equal((await generalPost(104, "/list", { updateId: 7001 })).status, 200);
  await waitForGeneral(7001, "sent");
  assert.deepEqual(generalSent[0], { chat_id: "104", text: "你的订阅\n1. Own 104 [链接已省略]",
    reply_parameters: { message_id: 7001 }, link_preview_options: { is_disabled: true } });
  assert.equal((await generalPost(104, "/list", { updateId: 7001 })).status, 204);

  failGeneralTransport = true;
  assert.equal((await generalPost(103, "/help", { updateId: 7002 })).status, 200);
  await waitForGeneral(7002, "uncertain");
  assert.equal((await generalPost(103, "/help", { updateId: 7002 })).status, 204);

  await db.prepare(`INSERT INTO telegram_general_replies
    (bot_id,generation,actor_id,actor_revision,update_id,message_id,message_date,command)
    VALUES (?,?,'104',1,7003,7003,?,'list')`).bind(pin.botId, pin.generation, now - 5).run();
  const lease = await claimGeneralTelegramReply(db, generalPin);
  assert.ok(lease);
  await db.batch([
    db.prepare("INSERT INTO telegram_general_actors VALUES (?,?,'104',2,?,'denied')").bind(pin.botId, pin.generation, now - 4),
    db.prepare("INSERT INTO telegram_general_actors VALUES (?,?,'104',3,?,'member')").bind(pin.botId, pin.generation, now - 3),
  ]);
  assert.equal(await beginGeneralTelegramReply(db, generalPin, lease), false, "same-role regrant cannot inherit an old lease");
  assert.equal((await generalPost(104, "/list", { date: now - 3 })).status, 204, "a grant's exact second stays closed");
  await db.prepare(`INSERT INTO telegram_general_replies
    (bot_id,generation,actor_id,actor_revision,update_id,message_id,message_date,command)
    VALUES (?,?,'104',3,7004,7004,?,'list')`).bind(pin.botId, pin.generation, now - 2).run();
  const interruptedSend = await claimGeneralTelegramReply(db, generalPin);
  assert.ok(interruptedSend);
  assert.equal(await beginGeneralTelegramReply(db, generalPin, interruptedSend), true);
  await db.prepare("UPDATE telegram_general_replies SET lease_until=unixepoch()-1 WHERE update_id=7004").run();
  assert.equal((await general.scheduled({ cron: "* * * * *" })).outcome, "ok");
  assert.equal(await generalState(7003), "discarded");
  assert.equal(await generalState(7004), "uncertain", "expired sending work cannot be delivered twice");
  await db.prepare("UPDATE telegram_general_policy SET generation=generation+1 WHERE bot_id=?").bind(pin.botId).run();
  assert.equal((await generalPost(101, "/help")).status, 204, "a stale configured generation cannot admit");
  assert.equal(generalSent.length, 2);

  assert.equal((await post(101, "/help")).status, 204);
  assert.equal(await drain(), "empty");
  assert.equal((await post(101, "/help", { secret: "wrong" })).status, 401);

  await db.prepare("INSERT INTO general_auth_replay_fence VALUES (?,?,?,?,?,?)")
    .bind(pin.botId, pin.workerManifestSha256, pin.candidateManifestSha256, "0".repeat(40), pin.generation, pin.cutoverAt).run();
  assert.equal((await post(101, "/help")).status, 204);
  await db.prepare("UPDATE general_auth_replay_fence SET release_revision=?").bind(pin.releaseRevision).run();
  await db.prepare("UPDATE general_auth_installation SET target_sha256=?").bind("0".repeat(64)).run();
  assert.equal((await post(101, "/help")).status, 204);
  await db.prepare("UPDATE general_auth_installation SET target_sha256=?").bind(pin.targetSha256).run();
  assert.equal((await post(101, "/help", { worker: serving, secret: isolation.webhookSecret })).status, 204);
  assert.equal((await serving.fetch("https://app.fixture.invalid/test/drain", { method: "POST" })).status, 404);
  assert.equal(await db.prepare("SELECT count(*) AS n FROM telegram_inbox").first("n"), 0);

  const denied: Array<[number, string, PostOptions]> = [
    [102, "/list", {}], [107, "/help", {}], [105, "/help", {}], [104, "/list", { chatId: 103 }],
    [104, "/list", { chatId: -100100, chatType: "supergroup" }],
    [104, "/list", { chatId: -100999, chatType: "group" }], [104, "/help", { message: { message_thread_id: 9 } }],
    [104, "/help", { message: { sender_chat: { id: -100100 } } }], [104, "/help", { date: pin.cutoverAt }],
    [104, "/help@DifferentBot", {}], [104, "/list 103", {}], [104, "/auth", {}], [104, "/start", {}],
  ];
  for (const [actor, command, options] of denied) assert.equal((await post(actor, command, options)).status, 204);
  assert.equal(await drain(), "empty");

  assert.equal((await post(101, "/help", { updateId: 100 })).status, 200);
  assert.equal((await post(101, "/help", { updateId: 100 })).status, 204);
  assert.deepEqual((await Promise.all([drain(), drain()])).sort(), ["empty", "sent"]);
  assert.deepEqual(sent, [{ chat_id: "101", text: "可用命令\n/help 帮助\n/list 查看你的订阅",
    reply_parameters: { message_id: 100 }, link_preview_options: { is_disabled: true } }]);
  for (const actor of [106, 103, 104]) {
    assert.equal((await post(actor, "/list@GeneralFixtureBot")).status, 200);
    assert.equal(await drain(), "sent");
    assert.deepEqual(sent.at(-1), { chat_id: String(actor), text: `你的订阅\n1. Own ${actor} [链接已省略]`, reply_parameters: { message_id: sequence },
      link_preview_options: { is_disabled: true } });
  }

  failTransport = true;
  assert.equal((await post(103, "/help", { updateId: 101 })).status, 200);
  assert.equal(await drain(), "uncertain");
  assert.equal((await post(103, "/help", { updateId: 101 })).status, 204);
  assert.equal(await drain(), "empty");
  assert.equal(await db.prepare("SELECT state FROM general_auth_replay_receipts WHERE update_id=101").first("state"), "uncertain");

  assert.equal((await post(104, "/list")).status, 200);
  await db.prepare("UPDATE general_auth_principals SET is_admin=1 WHERE bot_id=? AND user_id='104'").bind(pin.botId).run();
  assert.equal(await drain(), "empty");
  assert.equal((await post(106, "/list")).status, 200);
  await db.prepare("UPDATE general_auth_replay_fence SET generation=generation+1").run();
  assert.equal(await drain(), "empty");
  assert.equal((await post(106, "/list")).status, 204);
  assert.equal(sent.length, 5);
  assert.equal(await db.prepare("SELECT count(*) AS n FROM telegram_outbox").first("n"), 0);

  const shared = await runtime.getWorker("shared");
  const sharedPost = (actor: number, text: string, options: PostOptions = {}) =>
    post(actor, text, { date: now - 2, ...options, worker: shared });
  await db.prepare("UPDATE telegram_general_policy SET generation=? WHERE bot_id=?").bind(pin.generation, pin.botId).run();
  const migration = await db.prepare("SELECT sha256 FROM subs_bot_schema_migrations WHERE position=46").first<string>("sha256");
  assert.ok(migration);
  await db.prepare("UPDATE subs_bot_schema_migrations SET sha256=? WHERE position=46").bind("0".repeat(64)).run();
  assert.equal((await sharedPost(101, "/help")).status, 204, "wrong shared schema pin keeps admission closed");
  await db.prepare("UPDATE subs_bot_schema_migrations SET sha256=? WHERE position=46").bind(migration).run();

  await db.prepare(`INSERT INTO telegram_general_replies
    (bot_id,generation,actor_id,actor_revision,update_id,message_id,message_date,command)
    VALUES (?,?,'101',1,7100,7100,?,'help')`).bind(pin.botId, pin.generation, now - 2).run();
  assert.equal((await sharedPost(104, "/list")).status, 204, "an open 0044 queue keeps the new family closed");
  await db.prepare("UPDATE telegram_general_replies SET state='discarded' WHERE update_id=7100").run();
  assert.equal((await sharedPost(104, "/list", { updateId: 7001 })).status, 204, "old-family receipt remains a tombstone");
  assert.equal((await sharedPost(102, "/list")).status, 204);
  assert.equal((await sharedPost(104, "/list", { chatId: -100100, chatType: "group" })).status, 204);

  assert.deepEqual((await Promise.all([sharedPost(104, "/list", { updateId: 7101 }),
    sharedPost(104, "/list", { updateId: 7101 })])).map(({ status }) => status).sort(), [200, 204]);
  const findReply = (id: number) => db.prepare(`SELECT inbox.receipt_nonce AS marker,reply.state,reply.sent_message_id AS messageId,
    origin.generation,origin.actor_revision AS actorRevision,page.kind
    FROM telegram_inbox AS inbox JOIN telegram_outbox AS reply USING (receipt_id)
    JOIN telegram_general_receipt AS origin USING (receipt_id) LEFT JOIN telegram_view AS page USING (receipt_id)
    WHERE inbox.bot_id=? AND inbox.update_id=?`).bind(pin.botId, id).first();
  const sharedEnd = Date.now() + 4000;
  while ((await findReply(7101))?.state !== "sent" && Date.now() < sharedEnd) {
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  assert.deepEqual(await findReply(7101), { marker: "general-read:v1", state: "sent", messageId: 9301,
    generation: pin.generation, actorRevision: 3, kind: "list" });
  assert.deepEqual(sharedSent, [{ chat_id: "104", text: "你的订阅\n1. Own 104 [链接已省略]",
    reply_parameters: { message_id: 7101 }, link_preview_options: { is_disabled: true } }]);
  assert.equal((await generalPost(104, "/list", { updateId: 7101, date: now - 2 })).status, 204,
    "seven-key compatibility path also respects a shared receipt");

  assert.equal((await sharedPost(101, "/help", { updateId: 7104 })).status, 200);
  const helpEnd = Date.now() + 4000;
  while ((await findReply(7104))?.state !== "sent" && Date.now() < helpEnd) {
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  assert.deepEqual(await findReply(7104), { marker: "general-read:v1", state: "sent", messageId: 9302,
    generation: pin.generation, actorRevision: 1, kind: null });
  assert.deepEqual(sharedSent[1], { chat_id: "101", text: "可用命令\n/help 帮助\n/list 查看你的订阅",
    reply_parameters: { message_id: 7104 }, link_preview_options: { is_disabled: true } });

  const receiptFacts = (updateId: number, proof = sharedPin) => {
    const pins = generalPolicyBindings(proof);
    return db.prepare(`SELECT (${generalRecordedOriginSql("inbox")}) AS recorded,
      (${generalCurrentAuthoritySql("inbox")}) AS currentAuthority,
      (${generalOrdinaryReplyEligibilitySql("inbox")}) AS fresh,
      (${generalCurrentReceiptSql("inbox")}) AS deliverable
      FROM telegram_inbox AS inbox WHERE inbox.bot_id=? AND inbox.update_id=? AND inbox.receipt_nonce='general-read:v1'`)
      .bind(...pins, ...pins, ...pins, pin.botId, updateId).first();
  };
  assert.deepEqual(await receiptFacts(7101), { recorded: 1, currentAuthority: 1, fresh: 1, deliverable: 1 });
  assert.deepEqual(await receiptFacts(7101, { ...sharedPin, activationSha256: "0".repeat(64) }),
    { recorded: 0, currentAuthority: 0, fresh: 1, deliverable: 0 });

  const seedInbox = (id: number, marker: string | null) => db.prepare(`INSERT INTO telegram_inbox
    (bot_id,update_id,actor_id,chat_id,chat_type,message_id,message_date,command,receipt_nonce)
    VALUES (?,?,'104','104','private',?,?,'help',?) RETURNING receipt_id`)
    .bind(pin.botId, id, id, now - 2, marker).first<number>("receipt_id");
  const generalReceipt = await seedInbox(7102, "general-read:v1");
  const ordinaryReceipt = await seedInbox(7103, null);
  assert.ok(generalReceipt && ordinaryReceipt);
  await db.batch([
    db.prepare("INSERT INTO telegram_general_receipt VALUES (?,?,3,'member',?,?,?)")
      .bind(generalReceipt, pin.generation, sharedPin.releaseRevision, sharedPin.activationSha256, sharedPin.cutoverAt),
    db.prepare("INSERT INTO telegram_outbox (receipt_id) VALUES (?),(?)").bind(generalReceipt, ordinaryReceipt),
  ]);
  assert.equal((await claimTelegramReply(db, pin.botId))?.receiptId, ordinaryReceipt,
    "the isolation queue neither claims the new family nor lets it block ordinary FIFO");
  const sharedLease = await claimGeneralSharedTelegramReply(db, sharedPin);
  assert.equal(sharedLease?.receiptId, generalReceipt);
  assert.ok(sharedLease);
  await db.prepare("UPDATE telegram_inbox SET received_at=unixepoch()-600 WHERE receipt_id=?").bind(generalReceipt).run();
  assert.deepEqual(await receiptFacts(7102), { recorded: 1, currentAuthority: 1, fresh: 0, deliverable: 0 });
  assert.equal(await beginGeneralSharedTelegramReply(db, sharedPin, sharedLease), false, "the ordinary clock still closes at 600 seconds");
  await db.prepare("UPDATE telegram_inbox SET received_at=unixepoch() WHERE receipt_id=?").bind(generalReceipt).run();
  const changedPin = { ...sharedPin, activationSha256: "b".repeat(64) };
  await db.prepare("UPDATE telegram_general_policy SET activation_sha256=? WHERE bot_id=?")
    .bind(changedPin.activationSha256, pin.botId).run();
  assert.equal(await beginGeneralSharedTelegramReply(db, changedPin, sharedLease), false, "same generation cannot inherit an old activation");
  await db.prepare("UPDATE telegram_general_policy SET activation_sha256=? WHERE bot_id=?")
    .bind(sharedPin.activationSha256, pin.botId).run();
  await db.prepare("INSERT INTO telegram_general_actors VALUES (?,?,'104',4,?,'denied')")
    .bind(pin.botId, pin.generation, now - 2).run();
  assert.deepEqual(await receiptFacts(7102), { recorded: 1, currentAuthority: 0, fresh: 1, deliverable: 0 });
  assert.equal(await beginGeneralSharedTelegramReply(db, sharedPin, sharedLease), false);
  assert.equal((await shared.scheduled({ cron: "* * * * *" })).outcome, "ok");
  assert.equal((await findReply(7102))?.state, "failed");
  assert.equal(sharedSent.length, 2);

  const groupId = "-100100";
  const groupEvent: PostOptions = { chatId: Number(groupId), chatType: "supergroup", date: now,
    message: { is_topic_message: true, message_thread_id: 44, reply_to_message: { message_id: 44 } } };
  const addressed = "/list@GeneralFixtureBot";
  const groupPost = (actor: number, text: string, options: PostOptions = {}) => sharedPost(actor, text, { ...groupEvent, ...options });
  assert.equal((await groupPost(101, addressed)).status, 204, "an imported dormant group grants no runtime access");
  const grantGroup = () => db.prepare("INSERT INTO telegram_general_groups VALUES (?,?,?,'supergroup')")
    .bind(pin.botId, pin.generation, groupId).run();
  await grantGroup();
  await db.prepare("UPDATE subs_bot_schema_migrations SET sha256=? WHERE position=47").bind("0".repeat(64)).run();
  assert.equal((await groupPost(101, addressed)).status, 204, "wrong 0047 pin leaves the group path closed");
  assert.equal((await sharedPost(101, "/help", { updateId: 7200 })).status, 200);
  const privateEnd = Date.now() + 4000;
  while ((await findReply(7200))?.state !== "sent" && Date.now() < privateEnd) {
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  assert.equal((await findReply(7200))?.state, "sent");
  await db.prepare("UPDATE subs_bot_schema_migrations SET sha256=? WHERE position=47")
    .bind("442b9f1e52ad961aac41ee9416760863984646a96570bd22f26474d329ee626e").run();

  for (const rejected of [
    groupPost(102, addressed), groupPost(101, "/list"), groupPost(101, "/list@DifferentBot"),
    groupPost(101, addressed, { chatId: -100200 }), groupPost(101, addressed, { chatType: "group" }),
    groupPost(101, addressed, { message: { message_thread_id: 44 } }),
    groupPost(101, "/help@GeneralFixtureBot"), groupPost(101, addressed, { date: pin.cutoverAt }),
  ]) assert.equal((await rejected).status, 204);
  await db.prepare("INSERT INTO telegram_general_actors VALUES (?,?,'104',5,?,'member')")
    .bind(pin.botId, pin.generation, now - 1).run();
  for (const [id, actor, state] of [[7201, 101, "sent"], [7202, 104, "sent"], [7204, 101, "uncertain"]] as const) {
    assert.equal((await groupPost(actor, addressed, { updateId: id })).status, 200);
    assert.equal((await groupPost(actor, addressed, { updateId: id })).status, 204);
    const end = Date.now() + 4000;
    while ((await findReply(id))?.state !== state && Date.now() < end) await new Promise((resolve) => setTimeout(resolve, 10));
    assert.equal((await findReply(id))?.state, state);
    assert.deepEqual(sharedSent.find(({ reply_parameters }) => reply_parameters.message_id === id), {
      chat_id: groupId, text: `你的订阅\n1. Own ${actor} [链接已省略]`, message_thread_id: 44,
      reply_parameters: { message_id: id, allow_sending_without_reply: false }, link_preview_options: { is_disabled: true },
    });
  }

  const groupReceipt = await db.prepare(`INSERT INTO telegram_inbox
    (bot_id,update_id,actor_id,chat_id,chat_type,message_id,message_date,thread_id,command,receipt_nonce)
    VALUES (?,7203,'101',?,'supergroup',7203,?,44,'list','general-group-read:v1') RETURNING receipt_id`)
    .bind(pin.botId, groupId, now).first<number>("receipt_id");
  assert.ok(groupReceipt);
  await db.batch([
    db.prepare("INSERT INTO telegram_general_receipt VALUES (?,?,1,'admin',?,?,?)")
      .bind(groupReceipt, pin.generation, sharedPin.releaseRevision, sharedPin.activationSha256, sharedPin.cutoverAt),
    db.prepare("INSERT INTO telegram_view (receipt_id,kind) VALUES (?,'list')").bind(groupReceipt),
    db.prepare("INSERT INTO telegram_outbox (receipt_id) VALUES (?)").bind(groupReceipt),
  ]);
  const groupLease = await claimGeneralSharedTelegramReply(db, sharedPin);
  assert.equal(groupLease?.receiptId, groupReceipt);
  assert.ok(groupLease);
  assert.equal(await beginGeneralSharedTelegramReply(db, sharedPin, { ...groupLease, threadId: 45 }), false);
  await db.prepare("DELETE FROM telegram_general_groups WHERE bot_id=? AND generation=? AND chat_id=?")
    .bind(pin.botId, pin.generation, groupId).run();
  assert.equal(await beginGeneralSharedTelegramReply(db, sharedPin, groupLease), false);
  assert.equal((await shared.scheduled({ cron: "* * * * *" })).outcome, "ok");
  assert.deepEqual(await findReply(7203), { marker: "general-group-read:v1", state: "failed", messageId: null,
    generation: pin.generation, actorRevision: 1, kind: "list" });
  assert.equal(sharedSent.length, 6);

  const lifecycle = await runtime.getWorker("lifecycle");
  const lifecyclePost = (id: number, actor: number, text: string, message?: Record<string, unknown>) =>
    post(actor, text, { updateId: id, date: now, worker: lifecycle, message });
  const awaitLifecycle = async (id: number) => {
    const end = Date.now() + 4000;
    let row = await findReply(id);
    while (row?.state !== "sent" && Date.now() < end) {
      await new Promise((resolve) => setTimeout(resolve, 10));
      row = await findReply(id);
    }
    assert.equal(row?.state, "sent");
    const messageId = row?.messageId;
    assert.ok(typeof messageId === "number");
    const message = lifecycleMessagesById.get(messageId);
    assert.ok(message);
    return { message, messageId };
  };
  const button = (message: (typeof lifecycleSent)[number], label: string) => {
    const ticket = message.reply_markup?.inline_keyboard?.flat().find(({ text }) => text.includes(label))?.callback_data;
    assert.ok(ticket && /^sba1_[A-Za-z0-9_-]{22}$/u.test(ticket));
    return ticket;
  };
  const origin = (id: number, chatId: number, chatType = "private", botId = Number(pin.botId)) => ({
    message_id: id, date: now, chat: { id: chatId, type: chatType }, from: { id: botId, is_bot: true },
  });
  const callback = (id: number, actor: number, source: ReturnType<typeof origin>, ticket: string, worker = lifecycle) => worker.fetch(
    "https://app.fixture.invalid/telegram/webhook", { method: "POST",
      headers: { "Content-Type": "application/json", "X-Telegram-Bot-Api-Secret-Token": pin.webhookSecret },
      body: JSON.stringify({ update_id: id, callback_query: {
        id: `fixture-${id}`, from: { id: actor, is_bot: false }, message: source, data: ticket,
      } }),
    });
  const owned = () => db.prepare("SELECT id,token,name FROM subscriptions WHERE owner_id='101'").first<{ id: number; token: string; name: string }>();
  const initial = await owned();
  assert.ok(initial);
  assert.equal((await sharedPost(101, "/recycle")).status, 204, "the read-only config cannot enter lifecycle");
  assert.equal((await lifecyclePost(7301, 101, "/list")).status, 200);
  const listed = await awaitLifecycle(7301);
  const rename = button(listed.message, "重命名");
  assert.equal((await callback(7310, 104, origin(listed.messageId, 104), rename)).status, 204);
  assert.equal((await callback(7311, 101, origin(listed.messageId, -100100, "supergroup"), rename)).status, 204);
  assert.equal((await callback(7312, 101, origin(listed.messageId, 101, "private", 123), rename)).status, 204);
  assert.equal((await callback(7302, 101, origin(listed.messageId, 101), rename)).status, 200);
  assert.equal((await callback(7302, 101, origin(listed.messageId, 101), rename)).status, 204);
  const prompt = await awaitLifecycle(7302);
  assert.equal(prompt.message.reply_parameters.message_id, listed.messageId);
  assert.deepEqual(prompt.message.reply_markup, { force_reply: true });
  assert.equal((await lifecyclePost(7303, 101, "Renamed lifecycle fixture", { message_id: 20_001,
    reply_to_message: origin(prompt.messageId, 101), entities: [] })).status, 200);
  assert.equal((await awaitLifecycle(7303)).message.text, "订阅名称已更新。");
  assert.deepEqual(await owned(), { ...initial, name: "Renamed lifecycle fixture" });

  assert.equal((await lifecyclePost(7304, 101, "/list")).status, 200);
  const renamed = await awaitLifecycle(7304);
  assert.equal((await callback(7305, 101, origin(renamed.messageId, 101), button(renamed.message, "删除"))).status, 200);
  const confirm = await awaitLifecycle(7305);
  assert.equal((await callback(7306, 101, origin(confirm.messageId, 101), button(confirm.message, "确认移入回收站"))).status, 200);
  await awaitLifecycle(7306);
  assert.equal(await owned(), null);
  assert.equal(await db.prepare("SELECT token FROM subscription_trash WHERE id=? AND owner_id='101'")
    .bind(initial.id).first("token"), initial.token);

  assert.equal((await lifecyclePost(7307, 101, "/recycle")).status, 200);
  const recycle = await awaitLifecycle(7307);
  assert.equal((await callback(7308, 101, origin(recycle.messageId, 101), button(recycle.message, "恢复"))).status, 200);
  assert.equal((await awaitLifecycle(7308)).message.text, "已恢复订阅。");
  assert.deepEqual(await owned(), { ...initial, name: "Renamed lifecycle fixture" });
  assert.equal(await db.prepare("SELECT revision FROM subscription_lifecycle WHERE subscription_id=?").bind(initial.id).first("revision"), 3);
  assert.equal(await db.prepare("SELECT count(*) AS n FROM subscription_trash WHERE id=?").bind(initial.id).first("n"), 0);

  assert.equal((await lifecyclePost(7309, 104, "/list")).status, 200);
  const memberList = await awaitLifecycle(7309);
  await db.prepare("INSERT INTO telegram_general_actors VALUES (?,?,'104',6,?,'denied')")
    .bind(pin.botId, pin.generation, now).run();
  assert.equal((await callback(7313, 104, origin(memberList.messageId, 104), button(memberList.message, "删除"))).status, 204);
  assert.equal(await db.prepare("SELECT count(*) AS n FROM subscriptions WHERE owner_id='104'").first("n"), 1);
  assert.equal(lifecycleSent.length, 9);
  const ackDeadline = Date.now() + 1000;
  while (lifecycleAcks.size < 4 && Date.now() < ackDeadline) await new Promise((resolve) => setTimeout(resolve, 10));
  assert.deepEqual([...lifecycleAcks].sort(), ["fixture-7302", "fixture-7305", "fixture-7306", "fixture-7308"]);
  assert.equal(lifecycleAckCalls, 4);

  const detailTicket = (message: (typeof lifecycleSent)[number]) => {
    const ticket = message.reply_markup?.inline_keyboard?.flat()[0]?.callback_data;
    assert.ok(ticket && /^sbr1_[A-Za-z0-9_-]{22}$/u.test(ticket));
    return ticket;
  };
  assert.equal((await sharedPost(101, "/s Renamed")).status, 204);
  await grantGroup();
  assert.equal((await post(101, "/s@GeneralFixtureBot Renamed", { ...groupEvent, worker: lifecycle })).status, 204);
  assert.equal((await lifecyclePost(7320, 101, "/s Renamed")).status, 200);
  const searched = await awaitLifecycle(7320);
  assert.match(searched.message.text, /Renamed lifecycle fixture/u);
  const firstTicket = detailTicket(searched.message);
  const frozen = await db.prepare(`SELECT search.matches FROM telegram_subscription_read AS search
    JOIN telegram_inbox AS inbox USING (receipt_id) WHERE inbox.bot_id=? AND inbox.update_id=7320`)
    .bind(pin.botId).first<string>("matches");
  assert.deepEqual(JSON.parse(frozen!), [[initial.id, 1, 3]]);
  assert.equal((await callback(7321, 103, origin(searched.messageId, 103), firstTicket)).status, 204);
  await db.batch([
    db.prepare("UPDATE subscriptions SET name='Renamed current fixture' WHERE id=? AND owner_id='101'").bind(initial.id),
    db.prepare("UPDATE subscription_lifecycle SET revision=4 WHERE subscription_id=? AND revision=3").bind(initial.id),
  ]);
  assert.equal((await callback(7322, 101, origin(searched.messageId, 101), firstTicket)).status, 204, "a stale detail ticket stays closed");
  assert.equal((await lifecyclePost(7323, 101, "/s source.fixture.invalid")).status, 200);
  const sourceSearch = await awaitLifecycle(7323);
  assert.equal(sourceSearch.message.text, "没有匹配订阅。");
  assert.equal(sourceSearch.message.reply_markup, undefined);

  assert.equal((await lifecyclePost(7324, 101, "/s Renamed")).status, 200);
  const freshSearch = await awaitLifecycle(7324);
  const freshTicket = detailTicket(freshSearch.message);
  assert.equal((await callback(7325, 101, origin(freshSearch.messageId, 101), freshTicket)).status, 200);
  assert.equal((await callback(7325, 101, origin(freshSearch.messageId, 101), freshTicket)).status, 204);
  const detail = await awaitLifecycle(7325);
  assert.match(detail.message.text, /配置名称：Renamed current fixture/u);
  assert.match(detail.message.text, /节点数量：0/u);
  assert.equal(detail.message.reply_markup, undefined);
  assert.doesNotMatch(detail.message.text, /https?:|\/sub\/|fixture-token|source\.fixture/u);
  assert.equal(await db.prepare("SELECT count(*) AS n FROM telegram_provider_jobs").first("n"), 0);
  assert.equal(await db.prepare("SELECT count(*) AS n FROM telegram_subscription_read_ticket WHERE kind='format'").first("n"), 0);

  assert.equal((await lifecyclePost(7326, 103, "/s Own")).status, 200);
  const previousGrant = await awaitLifecycle(7326);
  await db.batch([
    db.prepare("INSERT INTO telegram_general_actors VALUES (?,?,'103',2,?,'denied')").bind(pin.botId, pin.generation, now),
    db.prepare("INSERT INTO telegram_general_actors VALUES (?,?,'103',3,?,'member')").bind(pin.botId, pin.generation, now + 1),
  ]);
  assert.equal((await callback(7327, 103, { ...origin(previousGrant.messageId, 103), date: now + 2 },
    detailTicket(previousGrant.message))).status, 204, "a fresh callback date cannot carry an old grant into a new revision");

  const pathStart = lifecycleSent.length;
  const pathSent = () => lifecycleSent.slice(pathStart);
  const pathPost = (actor: number, command: string, options: PostOptions = {}) =>
    post(actor, command, { date: now + 2, ...options, worker: lifecycle });
  const awaitPath = async (updateId: number) => {
    const end = Date.now() + 4000;
    while ((await findReply(updateId))?.state !== "sent" && Date.now() < end) {
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    const reply = await findReply(updateId);
    assert.ok(reply);
    assert.equal(reply.state, "sent");
    assert.equal(reply.marker, "general-path:v1");
  };
  assert.equal((await sharedPost(101, "/path same-key Disabled")).status, 204);
  assert.equal((await pathPost(102, "/path same-key Denied")).status, 204);
  assert.equal((await pathPost(101, "/path same-key Old", { date: pin.cutoverAt })).status, 204);
  assert.equal((await pathPost(101, "/path@GeneralFixtureBot same-key Group", groupEvent)).status, 204);
  const pathMigration = await db.prepare("SELECT sha256 FROM subs_bot_schema_migrations WHERE position=13").first<string>("sha256");
  assert.ok(pathMigration);
  await db.prepare("UPDATE subs_bot_schema_migrations SET sha256=? WHERE position=13").bind("0".repeat(64)).run();
  assert.equal((await pathPost(101, "/path same-key Invalid pin")).status, 204);
  await db.prepare("UPDATE subs_bot_schema_migrations SET sha256=? WHERE position=13").bind(pathMigration).run();
  assert.equal(pathSent().length, 0);

  assert.equal((await pathPost(101, "/path same-key Admin only", { updateId: 7341 })).status, 200);
  await awaitPath(7341);
  assert.equal((await pathPost(101, "/path same-key Duplicate", { updateId: 7341 })).status, 204);
  assert.equal((await pathPost(103, "/path same-key Member only", { updateId: 7342 })).status, 200);
  await awaitPath(7342);
  assert.equal((await pathPost(103, "/path", { updateId: 7343 })).status, 200);
  await awaitPath(7343);
  assert.equal(pathSent().length, 3);
  assert.equal(pathSent()[2].chat_id, "103");
  assert.match(pathSent()[2].text, /^你的路径规则\n#\d+ same-key → Member only$/u);

  assert.equal((await pathPost(101, "/path clear", { updateId: 7344, date: now + 1 })).status, 200);
  await awaitPath(7344);
  assert.equal(pathSent()[3].text, "此路径命令已过期或已有更新的操作，请重发。");
  assert.deepEqual((await db.prepare("SELECT owner_id,remark FROM path_rules WHERE keyword='same-key' ORDER BY owner_id").all()).results,
    [{ owner_id: "101", remark: "Admin only" }, { owner_id: "103", remark: "Member only" }]);
  assert.equal((await pathPost(101, "/path clear", { updateId: 7345, date: now + 3 })).status, 200);
  await awaitPath(7345);
  assert.equal(pathSent()[4].chat_id, "101");
  assert.equal(pathSent()[4].text, "已清空 1 条路径规则。");
  assert.deepEqual((await db.prepare("SELECT owner_id,remark FROM path_rules WHERE keyword='same-key'").all()).results,
    [{ owner_id: "103", remark: "Member only" }]);

  const pendingPaths: number[] = [];
  for (const id of [7346, 7347, 7348, 7349]) {
    const receiptId = await db.prepare(`INSERT INTO telegram_inbox
      (bot_id,update_id,actor_id,chat_id,chat_type,message_id,message_date,command,receipt_nonce)
      VALUES (?,?,'103','103','private',?,?,'help','general-path:v1') RETURNING receipt_id`)
      .bind(pin.botId, id, id, now + 2).first<number>("receipt_id");
    assert.ok(receiptId);
    pendingPaths.push(receiptId);
    await db.batch([
      db.prepare("INSERT INTO telegram_general_receipt VALUES (?,?,3,'member',?,?,?)")
        .bind(receiptId, pin.generation, privatePin.releaseRevision, privatePin.activationSha256, privatePin.cutoverAt),
      db.prepare("INSERT INTO telegram_path_reply (receipt_id,kind) VALUES (?,'list')").bind(receiptId),
      db.prepare("INSERT INTO telegram_outbox (receipt_id) VALUES (?)").bind(receiptId),
    ]);
  }
  assert.equal((await pathPost(103, "/list")).status, 204, "path replies consume the common admission quota");
  assert.equal((await pathPost(103, "/s Own")).status, 204);
  const pathLease = await claimGeneralSharedTelegramReply(db, privatePin);
  assert.equal(pathLease?.receiptId, pendingPaths[0]);
  assert.ok(pathLease);
  await db.prepare("INSERT INTO telegram_general_actors VALUES (?,?,'103',4,?,'denied')")
    .bind(pin.botId, pin.generation, now + 2).run();
  assert.equal(await beginGeneralSharedTelegramReply(db, privatePin, pathLease), false);
  assert.equal((await lifecycle.scheduled({ cron: "* * * * *" })).outcome, "ok");
  assert.equal((await findReply(7346))?.state, "failed");
  assert.equal(pathSent().length, 5);

  const formats = await runtime.getWorker("formats");
  const bucket = await runtime.getR2Bucket("NODES", "formats");
  const fixtureShare = "ss://YWVzLTI1Ni1nY206Zml4dHVyZQ@203.0.113.10:8388#fixture";
  assert.equal(await publishNodeSnapshot(db, bucket, { id: initial.id, ownerId: "101", expectedGeneration: 0,
    expectedLifecycleRevision: 4 }, [{ type: "temp", name: "fixture", share: fixtureShare }]), true);
  const formatDetail = async (firstId: number, worker = formats) => {
    assert.equal((await post(101, "/s Renamed", { updateId: firstId, date: now, worker })).status, 200);
    const search = await awaitLifecycle(firstId);
    assert.equal((await callback(firstId + 1, 101, origin(search.messageId, 101), detailTicket(search.message), worker)).status, 200);
    return awaitLifecycle(firstId + 1);
  };
  const disabledDetail = await formatDetail(7370, lifecycle);
  assert.equal(disabledDetail.message.reply_markup, undefined);
  const enabledDetail = await formatDetail(7372);
  assert.match(enabledDetail.message.text, /节点数量：1/u);
  assert.doesNotMatch(enabledDetail.message.text, /https?:|fixture-token|source\.fixture/u);
  const choices = enabledDetail.message.reply_markup?.inline_keyboard?.flat();
  assert.deepEqual(choices?.map(({ text }) => text), ["Clash Meta", "Sing-box", "Base64", "Surge", "QX"]);
  const formatTicket = (label: string) => {
    const ticket = choices?.find(({ text }) => text === label)?.callback_data;
    assert.ok(ticket && /^sbr1_[A-Za-z0-9_-]{22}$/u.test(ticket));
    return ticket;
  };
  const base64 = formatTicket("Base64");
  assert.equal((await callback(7374, 101, origin(enabledDetail.messageId, 101), base64)).status, 204, "old private mode stays closed");
  assert.equal((await callback(7375, 101, origin(enabledDetail.messageId, -100100, "supergroup"), base64, formats)).status, 204);
  await db.prepare("INSERT INTO telegram_general_actors VALUES (?,?,'104',7,?,'member')")
    .bind(pin.botId, pin.generation, now + 1).run();
  assert.equal((await callback(7376, 104, { ...origin(enabledDetail.messageId, 104), date: now + 2 }, base64, formats)).status, 204);
  assert.equal((await callback(7377, 101, origin(disabledDetail.messageId, 101), base64, formats)).status, 204);
  assert.equal((await callback(7378, 101, origin(enabledDetail.messageId, 101), base64, formats)).status, 200);
  const exported = await awaitLifecycle(7378);
  assert.deepEqual(exported.message, { chat_id: "101", text: `Base64\n${PRODUCTION_PUBLIC_ORIGIN}/sub/${initial.token}/base64`,
    reply_parameters: { message_id: enabledDetail.messageId }, link_preview_options: { is_disabled: true } });
  const served = await formats.fetch(`https://app.fixture.invalid/sub/${initial.token}/base64`);
  assert.equal(served.status, 200);
  assert.equal(await served.text(), Buffer.from(fixtureShare).toString("base64"));
  assert.equal((await callback(7378, 101, origin(enabledDetail.messageId, 101), base64, formats)).status, 204);
  assert.equal((await callback(7379, 101, origin(enabledDetail.messageId, 101), base64, formats)).status, 204);
  await db.prepare("UPDATE subscription_lifecycle SET revision=5 WHERE subscription_id=? AND revision=4").bind(initial.id).run();
  assert.equal((await callback(7380, 101, origin(enabledDetail.messageId, 101), formatTicket("Clash Meta"), formats)).status, 204);
  assert.equal(await findReply(7380), null);
  assert.equal(await db.prepare("SELECT count(*) AS n FROM telegram_provider_jobs").first("n"), 0);

  const firstShare = "hy2://first.example.invalid#synthetic-temp-first";
  const secondShare = "ssr://synthetic-temp-opaque#synthetic-temp-second";
  const tempPost = (id: number, actor: number, text: string, options: PostOptions = {}) => post(actor, text, {
    worker: formats, updateId: id, date: now + 4, ...options,
    message: text.startsWith("/") ? options.message : { entities: [], ...options.message },
  });
  await db.batch([
    db.prepare("INSERT INTO telegram_general_actors VALUES (?,?,'104',8,?,'member')")
      .bind(pin.botId, pin.generation, now + 3),
    db.prepare("INSERT INTO legacy_temp_installations VALUES (?,?,?)").bind(pin.botId, "d".repeat(64), now + 3),
  ]);
  const legacy = JSON.stringify([{ name: "Fixture baseline", type: "temp", share: firstShare }]);
  await db.prepare("INSERT INTO legacy_temp_batches VALUES (?,'104',1,1,?,1,?,?)")
    .bind(pin.botId, legacy, Buffer.byteLength(legacy), createHash("sha256").update(legacy).digest("hex")).run();
  assert.equal((await sharedPost(101, "/temp summary")).status, 204);
  assert.equal((await tempPost(7400, 101, "/temp clear", { date: now + 3 })).status, 204,
    "the restored baseline cutoff is strict even for an administrator");
  assert.equal((await tempPost(7401, 102, firstShare)).status, 204);
  assert.equal((await tempPost(7402, 101, firstShare, groupEvent)).status, 204);
  assert.equal((await tempPost(7403, 101, firstShare, { message: { reply_to_message: origin(10, 101) } })).status, 204);
  assert.equal((await tempPost(7404, 101, "ordinary fixture text")).status, 204);
  assert.equal((await tempPost(7405, 101, "https://provider.fixture.invalid/ordinary")).status, 204);
  const tempMigration = await db.prepare("SELECT sha256 FROM subs_bot_schema_migrations WHERE position=8").first<string>("sha256");
  assert.ok(tempMigration);
  await db.prepare("UPDATE subs_bot_schema_migrations SET sha256=? WHERE position=8").bind("0".repeat(64)).run();
  assert.equal((await tempPost(7406, 101, firstShare)).status, 204);
  await db.prepare("UPDATE subs_bot_schema_migrations SET sha256=? WHERE position=8").bind(tempMigration).run();
  assert.equal(await db.prepare("SELECT count(*) AS n FROM telegram_temp_reply").first("n"), 0);

  assert.equal((await tempPost(7410, 101, firstShare)).status, 200);
  const administrator = await awaitLifecycle(7410);
  assert.equal(administrator.message.text, "已加入临时列表 1 条节点，当前共有 1 条。");
  assert.equal((await tempPost(7410, 101, secondShare)).status, 204);
  const tempBase64 = Buffer.from(secondShare, "utf8").toString("base64");
  assert.equal((await tempPost(7411, 104, tempBase64)).status, 200);
  assert.equal((await awaitLifecycle(7411)).message.text, "已加入临时列表 1 条节点，当前共有 2 条。");
  assert.deepEqual(await db.prepare(`SELECT inbox.receipt_nonce AS marker,authority.actor_role AS role,
    authority.actor_revision AS revision,reply.kind AS kind
    FROM telegram_inbox AS inbox JOIN telegram_general_receipt AS authority USING (receipt_id)
    JOIN telegram_temp_reply AS reply USING (receipt_id) JOIN telegram_temp_batch AS batch USING (receipt_id)
    WHERE inbox.bot_id=? AND inbox.update_id=7411 AND batch.bot_id=inbox.bot_id AND batch.actor_id=inbox.actor_id`)
    .bind(pin.botId).first(), { marker: "general-temp:v1", role: "member", revision: 8, kind: "added" });

  assert.equal((await tempPost(7412, 104, "/temp")).status, 200);
  const summary = await awaitLifecycle(7412);
  assert.equal(summary.message.text, "临时列表共有 2 条节点。发送 /temp clear 清空。");
  assert.equal(summary.message.reply_markup, undefined);
  assert.equal((await tempPost(7413, 104, firstShare + "\nhy2://")).status, 200);
  assert.match((await awaitLifecycle(7413)).message.text, /^本批未写入。/u);
  assert.equal((await tempPost(7415, 104, firstShare, { date: now + 5 })).status, 200);
  await awaitLifecycle(7415);
  const totals = () => db.prepare(`SELECT actor_id AS owner,count(*) AS batches FROM telegram_temp_batch
    WHERE bot_id=? GROUP BY actor_id ORDER BY actor_id`).bind(pin.botId).all();
  await db.prepare(`CREATE TRIGGER fixture_general_temp_intake_abort BEFORE INSERT ON telegram_outbox
    WHEN EXISTS (SELECT 1 FROM telegram_inbox WHERE receipt_id=NEW.receipt_id AND bot_id='105' AND update_id=7414)
    BEGIN SELECT RAISE(IGNORE); END`).run();
  try {
    assert.equal((await tempPost(7414, 104, "/temp clear")).status, 503);
    assert.deepEqual((await totals()).results, [{ owner: "101", batches: 1 }, { owner: "104", batches: 2 }]);
    assert.equal(await db.prepare("SELECT count(*) AS n FROM legacy_temp_batches").first("n"), 1);
    assert.equal(await db.prepare("SELECT count(*) AS n FROM telegram_temp_clear_fence").first("n"), 0);
    assert.equal(await findReply(7414), null);
  } finally {
    await db.prepare("DROP TRIGGER fixture_general_temp_intake_abort").run();
  }
  assert.equal((await tempPost(7414, 104, "/temp clear")).status, 200);
  assert.equal((await awaitLifecycle(7414)).message.text, "已移除 2 条临时节点，当前共有 1 条。");
  assert.equal((await tempPost(7414, 104, "/temp clear")).status, 204);
  assert.deepEqual((await totals()).results, [{ owner: "101", batches: 1 }, { owner: "104", batches: 1 }]);
  assert.equal(await db.prepare("SELECT count(*) AS n FROM legacy_temp_batches").first("n"), 0);
  assert.equal((await tempPost(7416, 104, firstShare, { message: { message_id: 7413 } })).status, 200);
  assert.match((await awaitLifecycle(7416)).message.text, /^该操作早于最近一次清空/u);
  assert.doesNotMatch(JSON.stringify(lifecycleSent.filter(({ reply_parameters }) => reply_parameters.message_id >= 7410)),
    /(?:hy2|ssr):|synthetic-temp-/u);

  const queuedSummary = new Request("https://app.fixture.invalid/telegram/webhook", {
    method: "POST", headers: { "Content-Type": "application/json", "X-Telegram-Bot-Api-Secret-Token": pin.webhookSecret },
    body: JSON.stringify({ update_id: 7417, message: {
      from: { id: 104, is_bot: false }, chat: { id: 104, type: "private" }, date: now + 5, message_id: 7417,
      text: "/temp summary", entities: [{ type: "bot_command", offset: 0, length: 5 }],
    } }),
  });
  assert.equal(await acceptGeneralSharedTelegramCommand(db, formatsPin, queuedSummary.clone()), 204);
  assert.equal(await acceptGeneralSharedTelegramCommand(db, cumulativePin, queuedSummary), 200);
  const tempLease = await claimGeneralSharedTelegramReply(db, cumulativePin);
  assert.equal(tempLease?.updateId, 7417);
  assert.ok(tempLease);
  await db.prepare("INSERT INTO telegram_general_actors VALUES (?,?,'104',9,?,'denied')")
    .bind(pin.botId, pin.generation, now + 6).run();
  assert.equal(await beginGeneralSharedTelegramReply(db, cumulativePin, tempLease), false);
  const firstDocumentCron = await formats.scheduled({ cron: "* * * * *" });
  if (firstDocumentCron.outcome !== "ok") {
    // Reproduce only storage phases after the emitted check failed. This fixture
    // has no queued documents yet and the shared probe stops before delivery.
    let backendClass = "unclassified";
    const probeDb = (beforeBatch?: () => void) => ({
      prepare: db.prepare.bind(db),
      async batch(statements: D1PreparedStatement[]) {
        beforeBatch?.();
        try { return await db.batch(statements); } catch (error) {
          backendClass = diagnosticError(error);
          throw error;
        }
      },
    }) as D1Database;
    const stopBeforeClaim = new Error("Synthetic recovery reached the delivery boundary.");
    let sharedBatches = 0;
    const noDelivery = probeDb(() => {
      // The first batch reaps lifecycle tickets, the second would claim a reply.
      if (++sharedBatches > 1) throw stopBeforeClaim;
    });
    const stages = {
      "document-claim": () => claimTelegramDocumentJob(probeDb(), documentPin),
      "document-replies": () => reconcileTelegramDocumentJobReplies(probeDb(), documentPin),
      "document-stage": () => retireTelegramDocumentStage(probeDb(), bucket, documentPin),
      "shared-reaper": () => recoverGeneralSharedTelegramReplies(noDelivery, documentPin, bucket, PRODUCTION_PUBLIC_ORIGIN),
      "shared-claim": () => claimGeneralSharedTelegramReply(probeDb(), documentPin),
    };
    const results = [];
    for (const [stage, probe] of Object.entries(stages)) {
      backendClass = "unclassified";
      try { await probe(); results.push(`${stage}=ok`); } catch (error) {
        const direct = diagnosticError(error);
        results.push(`${stage}=${error === stopBeforeClaim ? "ok" : direct === "unclassified" ? backendClass : direct}`);
      }
    }
    assert.fail(`Emitted general Cron failed (${results.join(", ")}).`);
  }
  assert.equal(firstDocumentCron.outcome, "ok");
  assert.equal((await findReply(7417))?.state, "failed");
  assert.equal((await tempPost(7418, 104, "/temp clear", { date: now + 7 })).status, 204);
  assert.deepEqual((await totals()).results, [{ owner: "101", batches: 1 }, { owner: "104", batches: 1 }]);

  const quotaRows = JSON.stringify(Array.from({ length: MAX_TEMP_BATCH_NODES }, () =>
    ({ name: "Fixture quota", type: "temp", share: firstShare })));
  const quotaSha = createHash("sha256").update(quotaRows).digest("hex");
  const quotaSteps = [];
  for (let start = 1; start <= MAX_TEMP_OWNER_NODES; start += MAX_TEMP_BATCH_NODES) {
    quotaSteps.push(db.prepare("INSERT INTO legacy_temp_batches VALUES (?,'106',?,?,?,?,?,?)")
      .bind(pin.botId, start, start + MAX_TEMP_BATCH_NODES - 1, quotaRows, MAX_TEMP_BATCH_NODES,
        Buffer.byteLength(quotaRows), quotaSha));
  }
  assert.ok((await db.batch(quotaSteps)).every(({ success }) => success));
  assert.equal((await tempPost(7419, 106, firstShare)).status, 200);
  assert.match((await awaitLifecycle(7419)).message.text, new RegExp(`达到数量或大小限制.*${MAX_TEMP_OWNER_NODES}`, "u"));
  assert.equal(await db.prepare("SELECT count(*) AS n FROM telegram_temp_batch WHERE bot_id=? AND actor_id='106'")
    .bind(pin.botId).first("n"), 0);

  const documentWebhookUrl = "https://app.fixture.invalid/telegram/webhook";
  const documentRequest = (updateId: number, actor: number, fileId: string, options: PostOptions = {}): RequestInit =>
    ({ method: "POST",
      headers: { "Content-Type": "application/json", "X-Telegram-Bot-Api-Secret-Token": pin.webhookSecret },
      body: JSON.stringify({ update_id: updateId, message: {
        from: { id: actor, is_bot: false }, chat: { id: options.chatId ?? actor, type: options.chatType ?? "private" },
        message_id: updateId, date: options.date ?? now + 8,
        document: { file_id: fileId, file_name: "Fixture node upload.txt", file_size: Buffer.byteLength(fixtureDocuments.get(fileId)!) },
      } }),
    });
  const submitDocument = (id: number, actor: number, file: string, options: PostOptions = {}) =>
    formats.fetch(documentWebhookUrl, documentRequest(id, actor, file, options));
  const documentRow = (id: number) => db.prepare(`SELECT inbox.receipt_nonce AS marker,job.state,job.result_code AS outcome,
    job.file_id IS NULL AS scrubbed,origin.actor_revision AS revision
    FROM telegram_document_jobs AS job JOIN telegram_inbox AS inbox USING (receipt_id)
    JOIN telegram_general_receipt AS origin USING (receipt_id) WHERE inbox.bot_id=? AND inbox.update_id=?`)
    .bind(pin.botId, id).first();
  const uploaded = () => db.prepare(`SELECT owner_id AS owner,generation,token FROM subscriptions
    WHERE name='Fixture node upload' AND source_url='uploaded://telegram-document' ORDER BY owner_id`).all<{ owner: string; generation: number; token: string }>();
  fixtureDocuments.set("fixture-doc-admin", firstShare);
  fixtureDocuments.set("fixture-doc-member", secondShare);
  fixtureDocuments.set("fixture-doc-mixed", firstShare + "\nhttps://provider.fixture.invalid/private");
  fixtureDocuments.set("fixture-doc-revoked", firstShare);
  await db.prepare("INSERT INTO telegram_general_actors VALUES (?,?,'104',10,?,'member')")
    .bind(pin.botId, pin.generation, now + 7).run();
  assert.equal(await acceptGeneralSharedTelegramCommand(db, cumulativePin,
    new Request(documentWebhookUrl, documentRequest(7500, 101, "fixture-doc-admin"))), 204);
  assert.equal((await submitDocument(7501, 102, "fixture-doc-admin")).status, 204);
  assert.equal((await submitDocument(7502, 101, "fixture-doc-admin", groupEvent)).status, 204);
  assert.equal((await submitDocument(7510, 101, "fixture-doc-admin")).status, 200);
  assert.equal((await submitDocument(7510, 101, "fixture-doc-admin")).status, 204);
  assert.equal((await submitDocument(7511, 104, "fixture-doc-member")).status, 200);
  assert.equal((await documentRow(7510))?.state, "pending");
  assert.equal(await findReply(7510), null);
  assert.deepEqual(fileRequests, [], "webhook admission cannot download files");

  for (const [id, actor] of [[7510, 101], [7511, 104]] as const) {
    assert.equal((await formats.scheduled({ cron: "* * * * *" })).outcome, "ok");
    if (await findReply(id) === null) {
      const failed = await documentRow(id);
      const requestCount = fileRequests.filter((file) => file === (actor === 101 ? "fixture-doc-admin" : "fixture-doc-member")).length;
      let cause = "unclassified";
      let phase = "none";
      if (failed?.state === "pending" && requestCount === 2) {
        // Reproduce the storage path only in this disposable fixture. Never send or download again.
        await db.prepare(`UPDATE telegram_document_jobs SET due_at=unixepoch()
          WHERE receipt_id=(SELECT receipt_id FROM telegram_inbox WHERE bot_id=? AND update_id=?)
          AND state='pending'`).bind(pin.botId, id).run();
        const lease = await claimTelegramDocumentJob(db, documentPin);
        assert.ok(lease && lease.actorId === String(actor));
        const parsed = parseSubscriptionDocument(new TextEncoder().encode(actor === 101 ? firstShare : secondShare));
        assert.equal(parsed.kind, "parsed");
        const storageDb = {
          prepare: db.prepare.bind(db),
          async batch(statements: D1PreparedStatement[]) {
            phase = phase === "none" ? "reserve" : "publish";
            try { return await db.batch(statements); } catch (error) {
              cause = diagnosticError(error);
              throw error;
            }
          },
        } as D1Database;
        try {
          const result = await persistTelegramDocumentJob(storageDb, bucket, documentPin, lease, parsed.nodes,
            { parsed: parsed.nodes.length });
          cause = result;
        } catch (error) {
          if (cause === "unclassified") cause = diagnosticError(error);
        }
      }
      assert.fail(`Synthetic document reply missing (state=${failed?.state}, outcome=${failed?.outcome}, fetches=${requestCount}, ${phase}=${cause}).`);
    }
    const saved = await awaitLifecycle(id);
    assert.equal(saved.message.chat_id, String(actor));
    assert.equal(saved.message.text, "文件已导入，共 1 个节点。");
    assert.deepEqual(await documentRow(id), { marker: "general-document-job:v1", state: "done",
      outcome: "saved", scrubbed: 1, revision: actor === 101 ? 1 : 10 });
  }
  assert.deepEqual(fileRequests, ["fixture-doc-admin", "fixture-doc-admin", "fixture-doc-member", "fixture-doc-member"]);
  const original = (await uploaded()).results;
  assert.deepEqual(original.map(({ owner, generation }) => ({ owner, generation })),
    [{ owner: "101", generation: 1 }, { owner: "104", generation: 1 }]);
  for (const [index, share] of [firstShare, secondShare].entries()) {
    const response = await formats.fetch(`https://app.fixture.invalid/sub/${original[index].token}/base64`);
    assert.equal(response.status, 200);
    assert.equal(Buffer.from(await response.text(), "base64").toString("utf8"), share);
  }

  assert.equal((await submitDocument(7512, 104, "fixture-doc-mixed", { date: now + 9 })).status, 200);
  assert.equal((await formats.scheduled({ cron: "* * * * *" })).outcome, "ok");
  assert.equal((await awaitLifecycle(7512)).message.text, "文件未导入。请检查文件类型、大小和节点格式。已有订阅保持原样。");
  assert.deepEqual((await uploaded()).results, original);
  assert.equal(await db.prepare("SELECT count(*) AS n FROM telegram_provider_documents").first("n"), 0);
  assert.equal(await db.prepare("SELECT count(*) AS n FROM telegram_provider_jobs").first("n"), 0);

  assert.equal((await submitDocument(7513, 104, "fixture-doc-revoked", { date: now + 9 })).status, 200);
  await db.prepare("INSERT INTO telegram_general_actors VALUES (?,?,'104',11,?,'denied')")
    .bind(pin.botId, pin.generation, now + 10).run();
  assert.equal((await formats.scheduled({ cron: "* * * * *" })).outcome, "ok");
  assert.deepEqual(await documentRow(7513), { marker: "general-document-job:v1", state: "done",
    outcome: "access-changed", scrubbed: 1, revision: 10 });
  assert.equal((await findReply(7513))?.state, "failed");
  assert.equal(fileRequests.includes("fixture-doc-revoked"), false);
  assert.deepEqual((await uploaded()).results, original);

  const abandonedSnapshot = "33333333-3333-4333-8333-333333333333";
  const memberSubscriptionId = await db.prepare("SELECT id FROM subscriptions WHERE owner_id='104' AND token=?")
    .bind(original[1].token).first<number>("id");
  assert.ok(memberSubscriptionId);
  const abandonedObject = `subscriptions/${memberSubscriptionId}/${abandonedSnapshot}/0.ndjson`;
  await db.prepare(`INSERT INTO telegram_document_stages (snapshot_id,receipt_id,subscription_id,lease_id,cleanup_after)
    SELECT ?,receipt_id,?,'44444444-4444-4444-8444-444444444444',unixepoch()-1
    FROM telegram_inbox WHERE bot_id=? AND update_id=7513`).bind(abandonedSnapshot, memberSubscriptionId, pin.botId).run();
  await bucket.put(abandonedObject, "synthetic retired document object");
  assert.equal((await formats.scheduled({ cron: "* * * * *" })).outcome, "ok");
  assert.equal(await bucket.head(abandonedObject), null);
  assert.equal(await db.prepare("SELECT snapshot_id FROM telegram_document_stages WHERE snapshot_id=?")
    .bind(abandonedSnapshot).first(), null);
  assert.deepEqual((await uploaded()).results, original);

  await db.batch([db.prepare("CREATE TABLE general_provider_fixture (calls INTEGER,fail INTEGER) STRICT"),
    db.prepare("INSERT INTO general_provider_fixture VALUES (0,0)")]);
  const providerOpen = await runtime.getWorker("provider-open");
  const providerPaused = await runtime.getWorker("provider-paused");
  const providerPost = (id: number, text: string, options: PostOptions = {}) => post(101, text, {
    worker: providerOpen, updateId: id, date: now + 12, ...options, message: { entities: [], ...options.message },
  });
  const providerCalls = () => db.prepare("SELECT calls FROM general_provider_fixture").first<number>("calls");
  const providerRow = () => db.prepare(`SELECT id,name,token,generation,snapshot_id AS snapshotId FROM subscriptions
    WHERE owner_id='101' AND source_url=?`).bind(sourceUrl).first<{ id: number; name: string; token: string;
      generation: number; snapshotId: string | null }>();
  const providerCron = async () => assert.equal((await providerPaused.scheduled({ cron: "* * * * *" })).outcome, "ok");
  assert.equal((await providerPost(7520, sourceUrl, { worker: providerPaused })).status, 204);
  assert.equal((await providerPost(7521, sourceUrl, groupEvent)).status, 204);
  assert.equal((await providerPost(7522, `${sourceUrl}|synthetic-api-key`)).status, 204);
  assert.equal(await providerRow(), null);
  assert.equal((await providerPost(7523, sourceUrl)).status, 200);
  assert.equal((await providerPost(7523, sourceUrl)).status, 204);
  assert.equal((await providerPost(7526, `Duplicate name | ${sourceUrl}`)).status, 200);
  assert.equal(await db.prepare("SELECT count(*) AS n FROM telegram_provider_jobs WHERE state='pending'").first("n"), 1);
  const shell = await providerRow();
  assert.ok(shell && shell.generation === 0);
  assert.equal(await providerCalls(), 0);
  await db.prepare("UPDATE telegram_inbox SET received_at=unixepoch()-901 WHERE bot_id=? AND update_id=7523").bind(pin.botId).run();
  await providerCron();
  const saved = await awaitLifecycle(7523);
  assert.deepEqual({ actor: saved.message.chat_id, text: saved.message.text }, { actor: "101", text: "远程订阅已导入。发送 /list 查看。" });
  assert.equal((await awaitLifecycle(7526)).message.text, "相同订阅已在处理中。");
  const published = await providerRow();
  assert.ok(published?.snapshotId);
  assert.deepEqual(published, { ...shell, name: "General Provider", generation: 1, snapshotId: published.snapshotId });
  const downloaded = await providerPaused.fetch(`https://app.fixture.invalid/sub/${published.token}/base64`);
  assert.equal(downloaded.status, 200);
  assert.equal(await downloaded.text(), Buffer.from(providerShare).toString("base64"));
  await db.prepare("UPDATE general_provider_fixture SET fail=1").run();
  assert.equal((await providerPost(7524, `User name | ${sourceUrl}`)).status, 200);
  await providerCron();
  assert.equal((await awaitLifecycle(7524)).message.text, "无法获取远程订阅。");
  assert.deepEqual(await providerRow(), published);
  assert.equal((await providerPost(7525, "https://synthetic-user@provider.fixture.invalid/private")).status, 200);
  await providerCron();
  assert.equal((await awaitLifecycle(7525)).message.text, "订阅链接无效。请发送单条 HTTP 或 HTTPS 链接。");
  assert.equal(await providerCalls(), 2);
  assert.equal(await db.prepare(`SELECT count(*) AS n FROM telegram_inbox WHERE receipt_nonce='general-provider-request:v1'`).first("n"), 4);

  const providerDetail = async (searchId: number, detailId: number, keyword: string, worker = providerOpen) => {
    assert.equal((await post(101, `/s ${keyword}`, { worker, updateId: searchId, date: now + 12 })).status, 200);
    const result = await awaitLifecycle(searchId);
    assert.equal((await callback(detailId, 101, { ...origin(result.messageId, 101), date: now + 12 },
      detailTicket(result.message), worker)).status, 200);
    return await awaitLifecycle(detailId);
  };
  const refreshButton = (message: (typeof lifecycleSent)[number]) => message.reply_markup?.inline_keyboard?.flat()
    .find(({ text }) => text === "刷新订阅")?.callback_data;
  assert.equal(refreshButton((await providerDetail(7530, 7531, "General Provider", providerPaused)).message), undefined);
  await db.prepare(`INSERT INTO subscriptions (owner_id,name,source_url,token,created_at,updated_at)
    VALUES ('101','Refresh static fixture','uploaded://refresh-static','refresh-static-fixture-token',?,?)`).bind(now, now).run();
  assert.equal(refreshButton((await providerDetail(7532, 7533, "Refresh static fixture")).message), undefined);

  const ready = await providerDetail(7534, 7535, "General Provider");
  const ticket = refreshButton(ready.message);
  assert.ok(ticket && /^sbpr1_[A-Za-z0-9_-]{21}[AQgw]$/u.test(ticket));
  const source = { ...origin(ready.messageId, 101), date: now + 12 };
  assert.equal((await callback(7536, 101, source, ticket, providerPaused)).status, 204);
  assert.equal((await callback(7537, 103, { ...source, chat: { id: 103, type: "private" } }, ticket, providerOpen)).status, 204);
  assert.equal((await callback(7538, 101, { ...source, message_id: source.message_id + 1 }, ticket, providerOpen)).status, 204);
  assert.equal((await callback(7539, 101, { ...source, chat: { id: -100100, type: "supergroup" } }, ticket, providerOpen)).status, 204);
  await db.prepare("UPDATE subscriptions SET source_url='https://other.fixture.invalid/snapshot' WHERE id=?").bind(published.id).run();
  assert.equal((await callback(7540, 101, source, ticket, providerOpen)).status, 204);
  await db.prepare("UPDATE subscriptions SET source_url=? WHERE id=?").bind(sourceUrl, published.id).run();
  await db.prepare("UPDATE subscriptions SET generation=2 WHERE id=?").bind(published.id).run();
  assert.equal((await callback(7546, 101, source, ticket, providerOpen)).status, 204);
  await db.prepare("UPDATE subscriptions SET generation=1 WHERE id=?").bind(published.id).run();
  const lifecycleRevision = await db.prepare("SELECT revision FROM subscription_lifecycle WHERE subscription_id=?")
    .bind(published.id).first<number>("revision");
  assert.ok(lifecycleRevision === 1, "The automatic title performs a guarded rename.");
  const changeLifecycle = (revision: number) => db.prepare("UPDATE subscription_lifecycle SET revision=? WHERE subscription_id=?")
    .bind(revision, published.id).run();
  assert.equal((await changeLifecycle(lifecycleRevision + 1)).meta.changes, 1);
  try {
    assert.equal((await callback(7547, 101, source, ticket, providerOpen)).status, 204);
  } finally {
    assert.equal((await changeLifecycle(lifecycleRevision)).meta.changes, 1);
  }
  await db.prepare(`CREATE TRIGGER fixture_refresh_consumption_abort BEFORE UPDATE OF used_by_receipt_id
    ON telegram_provider_refresh_tickets BEGIN SELECT RAISE(IGNORE); END`).run();
  try {
    assert.equal((await callback(7548, 101, source, ticket, providerOpen)).status, 503);
    assert.equal(await findReply(7548), null);
    assert.equal(await db.prepare("SELECT count(*) AS n FROM telegram_provider_jobs WHERE kind='refresh'").first("n"), 0);
  } finally {
    await db.prepare("DROP TRIGGER fixture_refresh_consumption_abort").run();
  }
  await db.prepare("UPDATE general_provider_fixture SET fail=0").run();
  assert.equal(await providerCalls(), 2);
  const attempts = await Promise.all([callback(7541, 101, source, ticket, providerOpen), callback(7541, 101, source, ticket, providerOpen)]);
  assert.deepEqual(attempts.map(({ status }) => status).sort(), [200, 204]);
  assert.equal((await callback(7542, 101, source, ticket, providerOpen)).status, 204);
  assert.deepEqual(await db.prepare(`SELECT job.kind,job.state,job.source_sha256=ticket.source_sha256 AS exactSource,
    job.expected_generation=ticket.generation AS exactGeneration,job.expected_lifecycle_revision=ticket.lifecycle_revision AS exactLifecycle
    FROM telegram_provider_refresh_tickets AS ticket JOIN telegram_provider_requests AS request ON request.receipt_id=ticket.used_by_receipt_id
    JOIN telegram_provider_jobs AS job USING(job_id) JOIN telegram_inbox AS inbox ON inbox.receipt_id=request.receipt_id
    WHERE inbox.bot_id=? AND inbox.update_id=7541`).bind(pin.botId).first(), {
    kind: "refresh", state: "pending", exactSource: 1, exactGeneration: 1, exactLifecycle: 1,
  });
  await providerCron(); // Admission is off in this Worker, but the accepted refresh still settles.
  assert.equal((await awaitLifecycle(7541)).message.text, "远程订阅已刷新。发送 /list 查看。");
  const refreshed = await providerRow();
  assert.ok(refreshed?.snapshotId && refreshed.snapshotId !== published.snapshotId);
  assert.deepEqual(refreshed, { ...published, generation: 2, snapshotId: refreshed.snapshotId });

  const next = await providerDetail(7543, 7544, "General Provider");
  const nextTicket = refreshButton(next.message);
  assert.ok(nextTicket);
  const nextOrigin = { ...origin(next.messageId, 101), date: now + 12 };
  await db.prepare("UPDATE general_provider_fixture SET fail=1").run();
  assert.equal((await callback(7545, 101, nextOrigin, nextTicket, providerOpen)).status, 200);
  await providerCron();
  assert.equal((await awaitLifecycle(7545)).message.text, "无法获取远程订阅。");
  assert.deepEqual(await providerRow(), refreshed);
  assert.equal(await providerCalls(), 4);
  assert.doesNotMatch(JSON.stringify(lifecycleSent.filter(({ reply_parameters }) => reply_parameters.message_id >= 7520)),
    /provider\.fixture|signed%2Bvalue|synthetic-user|ss:\/\//u);

  const claimsWorker = await runtime.getWorker("claims");
  const claimBucket = await runtime.getR2Bucket("NODES", "claims");
  await db.prepare("INSERT INTO telegram_general_actors VALUES (?,?,'104',12,?,'member')")
    .bind(pin.botId, pin.generation, now + 15).run();
  const claimPost = (id: number, actor: number, code: string, options: PostOptions = {}) =>
    post(actor, "/start claim_" + code, { worker: claimsWorker, updateId: id, date: now + 16, ...options });
  const awaitClaim = async (id: number) => {
    const end = Date.now() + 4000;
    for (let row = await findReply(id); Date.now() < end; row = await findReply(id)) {
      if (row?.state === "sent") {
        assert.equal(row.marker, "general-private-claim:v1");
        const sent = claimSends.get(id);
        assert.ok(sent);
        return sent;
      }
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    assert.fail("The synthetic private claim did not settle.");
  };
  const shareBody = "\uFEFFSynthetic archived body\r\nwith NUL\0";
  const share = await createPrivateShare(db, claimBucket, { botId: pin.botId, senderId: "101",
    senderName: "Synthetic share sender", content: shareBody, targetUserId: "104", maxClaims: 1, durationMinutes: 5 });
  const legacyCode = "legacyShare";
  const legacyDigest = await privateShareCodeDigest(legacyCode);
  await db.prepare("UPDATE private_shares SET code_sha256=? WHERE bot_id=? AND code_sha256=?")
    .bind(legacyDigest, pin.botId, await privateShareCodeDigest(share.code)).run();
  const countClaims = (digest: string | null) => db.prepare(`SELECT count(*) AS n FROM private_share_claims AS claim
    JOIN private_shares AS share ON share.id=claim.share_id WHERE share.bot_id=? AND share.code_sha256=?`)
    .bind(pin.botId, digest).first<number>("n");
  assert.equal((await claimPost(7560, 104, legacyCode, { worker: providerPaused })).status, 204);
  assert.equal((await claimPost(7561, 102, legacyCode)).status, 204);
  assert.equal((await claimPost(7562, 104, legacyCode, groupEvent)).status, 204);
  assert.equal((await claimPost(7563, 101, legacyCode)).status, 200);
  assert.match((await awaitClaim(7563)).text ?? "", /指定了其他领取人/u);
  assert.equal(await countClaims(legacyDigest), 0);
  assert.equal((await claimPost(7564, 104, legacyCode)).status, 200);
  assert.deepEqual(await awaitClaim(7564), { actorId: "104", text: undefined, body: Buffer.from(shareBody, "utf8") });
  assert.equal((await claimPost(7564, 104, legacyCode)).status, 204);
  assert.equal((await claimPost(7565, 104, legacyCode)).status, 200);
  assert.deepEqual(await awaitClaim(7565), { actorId: "104", text: undefined, body: Buffer.from(shareBody, "utf8") });
  assert.equal(await countClaims(legacyDigest), 1);
  assert.equal(await db.prepare(`SELECT claim.code_sha256 AS digest FROM telegram_private_claim AS claim
    JOIN telegram_inbox AS inbox USING(receipt_id) WHERE inbox.bot_id=? AND inbox.update_id=7564`)
    .bind(pin.botId).first("digest"), legacyDigest);

  const revoked = await createPrivateShare(db, claimBucket, { botId: pin.botId, senderId: "101", senderName: "Fixture",
    content: "Synthetic revoked body", targetUserId: "104", maxClaims: 1, durationMinutes: 5 });
  assert.equal(await acceptGeneralSharedTelegramCommand(db, claimsPin, new Request("https://app.fixture.invalid/telegram/webhook", {
    method: "POST", headers: { "Content-Type": "application/json", "X-Telegram-Bot-Api-Secret-Token": pin.webhookSecret },
    body: JSON.stringify({ update_id: 7566, message: { text: "/start claim_" + revoked.code, message_id: 7566, date: now + 16,
      from: { id: 104, is_bot: false }, chat: { id: 104, type: "private" }, entities: [{ type: "bot_command", offset: 0, length: 6 }] } }),
  })), 200);
  const queuedClaim = await claimGeneralSharedTelegramReply(db, claimsPin);
  assert.equal(queuedClaim?.updateId, 7566);
  await db.prepare("INSERT INTO telegram_general_actors VALUES (?,?,'104',13,?,'denied')")
    .bind(pin.botId, pin.generation, now + 17).run();
  assert.equal((await claimsWorker.scheduled({ cron: "* * * * *" })).outcome, "ok");
  assert.equal((await findReply(7566))?.state, "failed");
  assert.equal(await countClaims(await privateShareCodeDigest(revoked.code)), 0);
  assert.equal(claimSends.has(7566), false);

  const expired = await createPrivateShare(db, claimBucket, { botId: pin.botId, senderId: "101", senderName: "Fixture",
    content: "Synthetic expired body", targetUserId: null, maxClaims: 1, durationMinutes: 5 });
  const expiredDigest = await privateShareCodeDigest(expired.code);
  await db.prepare("UPDATE private_shares SET created_at=unixepoch()-2,expire_at=unixepoch()-1 WHERE bot_id=? AND code_sha256=?")
    .bind(pin.botId, expiredDigest).run();
  assert.equal((await claimPost(7567, 101, expired.code)).status, 200);
  assert.match((await awaitClaim(7567)).text ?? "", /分享已过期/u);
  assert.equal(await countClaims(expiredDigest), 0);

  const shareWorker = await runtime.getWorker("share-creation");
  const shareLink = /https:\/\/t\.me\/GeneralFixtureBot\?start=claim_([A-Za-z0-9_-]{22})/u;
  const shareText = "/share x2 id106 s5 -- Synthetic creation body";
  const sharePost = (updateId: number, actor: number, text: string, options: PostOptions = {}) =>
    post(actor, text, { worker: shareWorker, updateId, date: now + 19, ...options });
  assert.equal((await sharePost(7570, 101, shareText, { worker: claimsWorker })).status, 204);
  assert.equal((await sharePost(7571, 102, shareText)).status, 204);
  assert.equal((await sharePost(7572, 101, shareText, groupEvent)).status, 204);
  assert.equal((await sharePost(7573, 101, "/share x101 -- invalid")).status, 204);
  assert.equal((await sharePost(7574, 101, "/share id104 -- revoked recipient")).status, 204);
  assert.equal((await sharePost(7575, 101, shareText)).status, 200);
  const created = await awaitLifecycle(7575).catch(async () => {
    // Failure-only evidence. Inspect fixed state fields and never retry a send here.
    const facts = await db.prepare(`SELECT creation.state AS creationState, reply.state AS replyState,
      reply.attempts, CASE WHEN reply.due_at <= unixepoch() THEN 1 ELSE 0 END AS due,
      CASE WHEN reply.lease_until > unixepoch() THEN 1 ELSE 0 END AS leaseActive
      FROM telegram_inbox AS inbox
      LEFT JOIN telegram_private_share_creations AS creation USING (receipt_id)
      LEFT JOIN telegram_outbox AS reply USING (receipt_id)
      WHERE inbox.bot_id=? AND inbox.update_id=? AND inbox.receipt_nonce='general-share-create:v1'`)
      .bind(pin.botId, 7575).first<{ creationState: string | null; replyState: string | null;
        attempts: number | null; due: number; leaseActive: number }>();
    const creation = ["reserved", "published", "abandoned"].find((state) => state === facts?.creationState) ?? "absent-or-invalid";
    const reply = ["pending", "leased", "sending", "sent", "failed", "uncertain"]
      .find((state) => state === facts?.replyState) ?? "absent-or-invalid";
    const attempts = [0, 1, 2, 3, 4].find((count) => count === facts?.attempts) ?? "absent-or-invalid";
    assert.fail(`Synthetic share reply missing (creation=${creation}, outbox=${reply}, attempts=${attempts}, `
      + `due=${facts?.due === 1}, leaseActive=${facts?.leaseActive === 1}).`);
  });
  assert.equal(created.message.chat_id, "101");
  assert.equal(created.message.reply_markup, undefined);
  assert.doesNotMatch(created.message.text, /Synthetic creation body/u);
  const issued = shareLink.exec(created.message.text);
  assert.ok(issued);
  const issuedCode = issued[1];
  assert.deepEqual(await db.prepare(`SELECT creation.state,creation.installation,share.target_user_id AS target,
    share.max_claims AS portions,share.expire_at-share.created_at AS ttl,share.code_sha256 AS digest
    FROM telegram_private_share_creations AS creation JOIN telegram_inbox AS inbox USING(receipt_id)
    JOIN private_shares AS share ON share.id=creation.share_id WHERE inbox.bot_id=? AND inbox.update_id=7575
      AND inbox.receipt_nonce='general-share-create:v1'`).bind(pin.botId).first(),
  { state: "published", installation: "general-bot-105", target: "106", portions: 2, ttl: 300,
    digest: await privateShareCodeDigest(issuedCode) });
  assert.equal((await sharePost(7575, 101, shareText)).status, 200, "a confirmed replay reuses the same published receipt");
  assert.equal(lifecycleSent.filter(({ reply_parameters }) => reply_parameters.message_id === 7575).length, 1);
  assert.equal((await claimPost(7576, 106, issuedCode, { date: now + 20 })).status, 200);
  assert.match((await awaitClaim(7576)).text ?? "", /Synthetic creation body/u);

  const subscriptionDetail = (await providerDetail(7568, 7569, "Renamed current fixture", shareWorker)).message;
  assert.ok(subscriptionDetail.text.split("\n").includes(`私密分享此订阅：/share sub ${initial.id}`));
  const subscriptionCommand = `/share sub ${initial.id} x1 id106 s5`;
  assert.equal((await sharePost(7577, 106, subscriptionCommand)).status, 204, "a current actor cannot share another owner's subscription");
  assert.equal(await findReply(7577), null);
  assert.equal((await sharePost(7578, 101, subscriptionCommand)).status, 200);
  const subscriptionShare = (await awaitLifecycle(7578)).message;
  assert.equal(subscriptionShare.chat_id, "101");
  assert.doesNotMatch(subscriptionShare.text, /source\.fixture|\/sub\//u);
  const subscriptionCode = shareLink.exec(subscriptionShare.text)?.[1];
  assert.ok(subscriptionCode);
  assert.equal((await claimPost(7599, 106, subscriptionCode, { date: now + 20 })).status, 200);
  const receivedSubscription = await awaitClaim(7599);
  assert.equal(receivedSubscription.actorId, "106");
  assert.ok(receivedSubscription.text?.endsWith([
    "🏷️ 订阅名称：Renamed current fixture",
    "🌐 原始链接：https://source.fixture.invalid/hidden",
    `⚡ Clash 配置：${PRODUCTION_PUBLIC_ORIGIN}/sub/${initial.token}/clash`,
  ].join("\n")));

  const groupShareWorker = await runtime.getWorker("group-share");
  const decoyGroup = "-100601";
  await db.prepare(`INSERT INTO telegram_general_groups (bot_id,generation,chat_id,chat_type)
    VALUES (?,?,?,'supergroup'),(?,?,?,'supergroup')`)
    .bind(pin.botId, pin.generation, groupShareDestination.chatId, pin.botId, pin.generation, decoyGroup).run();
  const groupSharePost = (updateId: number, actor: number, text: string) =>
    post(actor, text, { worker: groupShareWorker, updateId, date: now + 22 });
  const groupShareBody = "Synthetic body from the confirmed group card";
  assert.equal((await groupSharePost(7660, 101, `/share x1 id106 s5 -- ${groupShareBody}`)).status, 200);
  const groupCreation = await awaitLifecycle(7660);
  const publishCard = groupCreation.message.reply_markup?.inline_keyboard?.[0]?.[0]?.callback_data;
  assert.equal(publishCard, "group-share:publish:v1");
  const creationOrigin = { ...origin(groupCreation.messageId, 101), date: now + 22 };
  assert.equal((await callback(7661, 101, creationOrigin, publishCard!, groupShareWorker)).status, 200);
  assert.equal((await callback(7661, 101, creationOrigin, publishCard!, groupShareWorker)).status, 204);
  const readGroupCard = () => db.prepare(`SELECT card.state,card.message_id AS messageId,card.shown FROM telegram_group_share_cards AS card
    JOIN telegram_inbox AS inbox USING(receipt_id) WHERE inbox.bot_id=? AND inbox.update_id=7660`)
    .bind(pin.botId).first<{ state: string; messageId: number | null; shown: number }>();
  const awaitGroupCard = async (shown: number) => {
    const end = Date.now() + 4000;
    for (let row = await readGroupCard(); Date.now() < end; row = await readGroupCard()) {
      if (row?.state === "sent" && row.shown === shown) {
        assert.equal(row.messageId, 9901);
        return;
      }
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    assert.fail("The synthetic group card did not settle.");
  };
  await awaitGroupCard(0);
  assert.equal(groupCards.length, 1);
  const [publishedGroupCard] = groupCards;
  assert.deepEqual(publishedGroupCard, { id: 9901, method: "sendMessage", body: {
    chat_id: groupShareDestination.chatId, text: "私密分享\n领取进度：0/1", link_preview_options: { is_disabled: true },
    reply_markup: { inline_keyboard: [[{ text: "领取", callback_data: "group-share:pick:v1" }],
      [{ text: "打开 Bot 私聊", url: "https://t.me/GeneralFixtureBot?start=group" }]] },
  } });
  const cardOrigin = { ...origin(publishedGroupCard.id, Number(groupShareDestination.chatId), "supergroup"), date: now + 22 };
  const pick = "group-share:pick:v1";
  assert.equal((await callback(7662, 101, cardOrigin, pick, groupShareWorker)).status, 204);
  assert.equal((await callback(7663, 106, { ...cardOrigin, chat: { id: Number(decoyGroup), type: "supergroup" } },
    pick, groupShareWorker)).status, 204);
  assert.equal((await callback(7664, 106, { ...cardOrigin, message_thread_id: 42 }, pick, groupShareWorker)).status, 204);
  assert.equal((await callback(7665, 106, cardOrigin, pick, groupShareWorker)).status, 200);
  assert.equal((await callback(7665, 106, cardOrigin, pick, groupShareWorker)).status, 204);
  const groupClaimCount = () => db.prepare(`SELECT count(*) AS n FROM private_share_claims AS claim
    JOIN telegram_private_share_creations AS creation ON creation.share_id=claim.share_id
    JOIN telegram_inbox AS inbox USING(receipt_id) WHERE inbox.bot_id=? AND inbox.update_id=7660`)
    .bind(pin.botId).first<number>("n");
  assert.equal(await groupClaimCount(), 0, "the group click does not reserve a private portion");
  for (const id of [7666, 7667]) {
    assert.equal((await groupSharePost(id, 106, "/start group")).status, 200);
    const delivery = (await awaitLifecycle(id)).message;
    assert.equal(delivery.chat_id, "106");
    assert.ok(delivery.text.endsWith(groupShareBody));
    assert.equal((await findReply(id))?.marker, "general-group-claim:v1");
  }
  assert.equal(await groupClaimCount(), 1);
  assert.equal((await groupShareWorker.scheduled({ cron: "* * * * *" })).outcome, "ok");
  await awaitGroupCard(1);
  assert.deepEqual(groupCards.map(({ method, body }) => [method, body.text]), [
    ["sendMessage", "私密分享\n领取进度：0/1"], ["editMessageText", "私密分享\n领取进度：1/1"],
  ]);
  await db.prepare("DELETE FROM telegram_general_groups WHERE bot_id=? AND generation=? AND chat_id=?")
    .bind(pin.botId, pin.generation, groupShareDestination.chatId).run();
  assert.equal((await groupSharePost(7668, 106, "/start group")).status, 204);
  assert.equal(await findReply(7668), null);
  assert.equal(await groupClaimCount(), 1);
  await db.prepare("DELETE FROM telegram_general_groups WHERE bot_id=? AND generation=? AND chat_id=?")
    .bind(pin.botId, pin.generation, decoyGroup).run();

  const aggregateWorker = await runtime.getWorker("aggregate");
  const aggregateNoKey = await runtime.getWorker("aggregate-no-key");
  const aggregateKey = await parseTelegramAggregateKey(aggregateKeyRaw);
  assert.ok(aggregateKey);
  const exportPost = (id: number, actor: number, text = "/export", options: PostOptions = {}) =>
    post(actor, text, { worker: aggregateWorker, updateId: id, date: now + 20, ...options });
  const slot = (actorId: string) => db.prepare(`SELECT revision,code_sha256 AS digest FROM telegram_aggregate_slots
    WHERE bot_id=? AND actor_id=?`).bind(pin.botId, actorId).first<{ revision: number; digest: string | null }>();
  const exportReply = async (id: number, actorId: string) => {
    const { message } = await awaitLifecycle(id);
    assert.equal(message.chat_id, actorId);
    assert.deepEqual(message.link_preview_options, { is_disabled: true });
    assert.equal((await findReply(id))?.marker, "general-aggregate:v1");
    return message.text;
  };
  const aggregateCode = async (id: number, actorId: string) => {
    const text = await exportReply(id, actorId);
    const clash = text.split("\n")[1];
    const url = new URL(clash);
    assert.equal(url.origin, PRODUCTION_PUBLIC_ORIGIN);
    const code = /^\/agg\/([A-Za-z0-9_-]{22})\/clash$/u.exec(url.pathname)?.[1];
    assert.ok(code);
    assert.ok(text.includes(`${PRODUCTION_PUBLIC_ORIGIN}/agg/${code}/base64`));
    assert.equal((await slot(actorId))?.digest, createHash("sha256").update(code).digest("hex"));
    return code;
  };
  const getAggregate = (code: string, format = "base64") => aggregateWorker.fetch(`https://app.fixture.invalid/agg/${code}/${format}`);
  assert.equal((await exportPost(7580, 101, "/export", { worker: claimsWorker })).status, 204);
  assert.equal((await exportPost(7581, 101, "/export", { worker: aggregateNoKey })).status, 204);
  assert.equal((await exportPost(7579, 101, "/share -- Synthetic cross-key control")).status, 204);
  assert.equal((await exportPost(7582, 101, "/export@GeneralFixtureBot", groupEvent)).status, 204);
  assert.equal((await exportPost(7583, 102)).status, 204);
  assert.equal((await exportPost(7584, 101, "/export someone-else")).status, 204);
  assert.equal(await slot("101"), null);
  assert.equal((await exportPost(7585, 101)).status, 200);
  const adminAggregate = await aggregateCode(7585, "101");
  assert.equal((await exportPost(7585, 101)).status, 204);
  assert.equal((await exportPost(7586, 101)).status, 200);
  assert.equal(await aggregateCode(7586, "101"), adminAggregate);

  await db.prepare("INSERT INTO telegram_general_actors VALUES (?,?,'104',14,?,'member')")
    .bind(pin.botId, pin.generation, now + 19).run();
  assert.equal((await exportPost(7587, 104)).status, 200);
  const memberAggregate = await aggregateCode(7587, "104");
  assert.notEqual(adminAggregate, memberAggregate);
  const readAggregate = async (code: string) => {
    const response = await getAggregate(code);
    assert.equal(response.status, 200);
    return Buffer.from(await response.text(), "base64").toString("utf8").split("\n");
  };
  const adminRows = await readAggregate(adminAggregate), memberRows = await readAggregate(memberAggregate);
  assert.ok(adminRows.includes(providerShare) && adminRows.includes(fixtureShare) && !adminRows.includes(secondShare));
  assert.ok(memberRows.includes(secondShare) && !memberRows.includes(providerShare) && !memberRows.includes(fixtureShare));

  const unsupported = await db.prepare(`SELECT id FROM subscriptions WHERE owner_id='101' AND token='refresh-static-fixture-token'`)
    .first<number>("id");
  assert.ok(unsupported);
  assert.equal(await publishNodeSnapshot(db, bucket, { id: unsupported, ownerId: "101", expectedGeneration: 0,
    expectedLifecycleRevision: 0 }, [{ type: "wireguard", name: "Fixture unsupported share" }]), true);
  assert.equal((await exportPost(7588, 101)).status, 200);
  const limited = await exportReply(7588, "101");
  assert.ok(limited.includes(`${PRODUCTION_PUBLIC_ORIGIN}/agg/${adminAggregate}/clash`));
  assert.match(limited, /Base64：订阅内容不支持此格式。/u);
  assert.doesNotMatch(limited, /\/base64/u);
  assert.equal((await getAggregate(adminAggregate)).status, 422);

  assert.equal((await exportPost(7589, 104, "/export revoke")).status, 200);
  assert.equal(await exportReply(7589, "104"), "聚合导出链接已撤销。");
  assert.equal((await getAggregate(memberAggregate)).status, 404);
  assert.equal((await getAggregate(adminAggregate)).status, 422);
  assert.equal((await slot("104"))?.digest, null);
  assert.equal((await exportPost(7590, 101, "/export revoke")).status, 200);
  assert.equal(await exportReply(7590, "101"), "聚合导出链接已撤销。");
  assert.equal((await getAggregate(adminAggregate)).status, 404);
  assert.equal((await exportPost(7592, 101, "/export", { date: now + 19 })).status, 200);
  assert.equal(await exportReply(7592, "101"), "这条聚合操作已失效。");
  assert.equal((await slot("101"))?.digest, null);

  assert.equal(await acceptGeneralSharedTelegramCommand(db, aggregatePin, new Request("https://app.fixture.invalid/telegram/webhook", {
    method: "POST", headers: { "Content-Type": "application/json", "X-Telegram-Bot-Api-Secret-Token": pin.webhookSecret },
    body: JSON.stringify({ update_id: 7591, message: { text: "/export", message_id: 7591, date: now + 21,
      from: { id: 104, is_bot: false }, chat: { id: 104, type: "private" }, entities: [{ type: "bot_command", offset: 0, length: 7 }] } }),
  }), undefined, undefined, undefined, undefined, aggregateKey), 200);
  const queuedAggregate = await claimGeneralSharedTelegramReply(db, aggregatePin);
  assert.ok(queuedAggregate?.updateId === 7591);
  await db.prepare("INSERT INTO telegram_general_actors VALUES (?,?,'104',15,?,'denied')")
    .bind(pin.botId, pin.generation, now + 22).run();
  assert.equal(await beginGeneralSharedTelegramReply(db, aggregatePin, queuedAggregate), false);
  assert.equal((await aggregateWorker.scheduled({ cron: "* * * * *" })).outcome, "ok");
  assert.equal((await findReply(7591))?.state, "failed");
  assert.ok(!lifecycleSent.some(({ reply_parameters }) => reply_parameters.message_id === 7591));

  const inlineWorker = await runtime.getWorker("general-inline");
  const inlinePaused = await runtime.getWorker("general-inline-paused");
  // Use an independent member epoch. The short-link fixture uses actor 104 later.
  const inlineActor = 103;
  const inlineActorRevision = 5;
  await db.prepare("INSERT INTO telegram_general_actors VALUES (?,?,?,?,?,'member')")
    .bind(pin.botId, pin.generation, String(inlineActor), inlineActorRevision, now + 22).run();
  const inlineCommand = (id: number, actor: number, text: string, options: PostOptions = {}) =>
    post(actor, text, { worker: inlineWorker, updateId: id, date: now + 24, ...options });
  const inlineQuery = (id: number, actor: number, query: string, chatType = "sender", worker = inlineWorker) =>
    worker.fetch("https://app.fixture.invalid/telegram/webhook", { method: "POST",
      headers: { "Content-Type": "application/json", "X-Telegram-Bot-Api-Secret-Token": pin.webhookSecret },
      body: JSON.stringify({ update_id: id, inline_query: { id: `synthetic-inline-${id}`,
        from: { id: actor, is_bot: false }, chat_type: chatType, offset: "", query } }),
    });
  assert.equal((await inlineQuery(8850, 101, "Own")).status, 204);
  assert.equal(inlineAnswers.size, 0);
  assert.equal((await inlineCommand(8851, 101, "/inline on", { worker: inlinePaused })).status, 204);
  assert.equal((await inlineCommand(8852, 101, "/inline on", groupEvent)).status, 204);
  assert.equal((await inlineCommand(8853, 101, "/inline on")).status, 200);
  assert.equal((await inlineCommand(8854, inlineActor, "/inline on")).status, 200);
  assert.match((await awaitLifecycle(8853)).message.text, /15 分钟/u);
  assert.match((await awaitLifecycle(8854)).message.text, /15 分钟/u);
  assert.equal((await inlineQuery(8855, 101, "Own", "group")).status, 204);
  assert.equal((await inlineQuery(8856, 102, "Own")).status, 204);
  assert.equal((await inlineQuery(8857, 101, "Own", "sender", inlinePaused)).status, 204);
  assert.equal(inlineAnswers.size, 0);
  assert.equal((await inlineQuery(8858, 101, "Renamed current fixture")).status, 204);
  assert.equal((await inlineQuery(8859, inlineActor, "Own 103")).status, 204);
  assert.equal((await inlineQuery(8858, 101, "Renamed current fixture")).status, 204);
  assert.equal(inlineAnswers.size, 2);
  assert.ok(inlineAnswers.get("synthetic-inline-8858")?.titles.some((title) => title.startsWith("Renamed current fixture")));
  assert.ok(inlineAnswers.get("synthetic-inline-8859")?.titles.some((title) => title.startsWith("Own 103")));
  assert.doesNotMatch(JSON.stringify([...inlineAnswers.values()]), /https?:|fixture-token|source\.fixture/u);
  assert.equal((await inlineCommand(8860, 101, "/inline off", { worker: inlinePaused, date: now + 25 })).status, 200);
  assert.match((await awaitLifecycle(8860)).message.text, /已关闭/u);
  await db.prepare("INSERT INTO telegram_general_actors VALUES (?,?,?,?,?,'denied')")
    .bind(pin.botId, pin.generation, String(inlineActor), inlineActorRevision + 1, now + 25).run();
  assert.equal((await inlineQuery(8861, 101, "Renamed current fixture")).status, 204);
  assert.equal((await inlineQuery(8862, inlineActor, "Own 103")).status, 204);
  assert.equal(inlineAnswers.size, 2, "opt-out and revocation independently fence delivery");
  assert.deepEqual((await db.prepare(`SELECT actor_id AS actor,state,result_count AS n
    FROM telegram_inline_search_receipts WHERE bot_id=? ORDER BY update_id`).bind(pin.botId).all()).results,
    [{ actor: "101", state: "sent", n: 1 }, { actor: "103", state: "sent", n: 1 }]);

  const selectedWorker = await runtime.getWorker("selected");
  const selectedPost = (updateId: number, actor: number, query: string, options: PostOptions = {}) =>
    post(actor, `/o ${query}`, { updateId, worker: selectedWorker, date: now + 24, ...options });
  const firstSelectedShare = fixtureShare + "-selected-first";
  const secondSelectedShare = fixtureShare + "-selected-second";
  const selectedIds: number[] = [];
  for (const [owner, name, source, share] of [
    ["101", "ÉTÉ-COHORT", "uploaded://selected-fixture-first", firstSelectedShare],
    ["104", "ÉTÉ-COHORT", "uploaded://selected-fixture-foreign", fixtureShare + "-foreign"],
    ["101", "Second selected fixture", "uploaded://selected-fixture/été-cohort", secondSelectedShare],
  ] as const) {
    const id = await db.prepare(`INSERT INTO subscriptions(owner_id,name,source_url,token,created_at,updated_at)
      VALUES (?,?,?,?,?,?) RETURNING id`).bind(owner, name, source, crypto.randomUUID().replaceAll("-", ""), now, now).first<number>("id");
    assert.ok(id);
    assert.equal(await publishNodeSnapshot(db, bucket, { id, ownerId: owner, expectedGeneration: 0, expectedLifecycleRevision: 0 },
      [{ type: "temp", name, share }]), true);
    if (owner === "101") selectedIds.push(id);
  }
  const keyword = "été-cohort";
  assert.equal((await selectedPost(7710, 101, keyword, { worker: aggregateWorker })).status, 204);
  assert.equal((await selectedPost(7711, 101, keyword, groupEvent)).status, 204);
  assert.equal((await selectedPost(7712, 104, keyword)).status, 204);
  assert.equal((await selectedPost(7713, 101, keyword)).status, 200);
  const selection = await awaitLifecycle(7713);
  assert.equal(selection.message.chat_id, "101");
  assert.deepEqual(selection.message.link_preview_options, { is_disabled: true });
  const selectedUrl = new URL(selection.message.text.split("\n")[1]);
  assert.equal(selectedUrl.origin, PRODUCTION_PUBLIC_ORIGIN);
  const selectedCode = /^\/agg\/([A-Za-z0-9_-]{22})\/clash$/u.exec(selectedUrl.pathname)?.[1];
  assert.ok(selectedCode);
  assert.equal((await getAggregate(selectedCode, "clash")).status, 200);
  assert.deepEqual(await readAggregate(selectedCode), [firstSelectedShare, secondSelectedShare]);
  const selectedDigest = createHash("sha256").update(selectedCode).digest("hex");
  assert.deepEqual(await db.prepare(`SELECT link.selected_ids AS ids,origin.receipt_nonce AS marker
    FROM aggregate_links AS link JOIN telegram_selected_links AS selected USING(code_sha256)
    JOIN telegram_inbox AS origin ON origin.receipt_id=selected.origin_receipt_id WHERE link.code_sha256=?`)
    .bind(selectedDigest).first(), { ids: JSON.stringify(selectedIds), marker: "general-selected:v1" });
  assert.equal((await selectedPost(7713, 101, keyword)).status, 204);
  const firstSelectedTicket = selection.message.reply_markup?.inline_keyboard?.[0]?.[0]?.callback_data;
  assert.ok(firstSelectedTicket && /^sbo1_[A-Za-z0-9_-]{22}$/u.test(firstSelectedTicket));
  const privateOrigin = { ...origin(selection.messageId, 101), date: now + 25 };
  assert.equal((await callback(7714, 106, { ...privateOrigin, chat: { id: 106, type: "private" } }, firstSelectedTicket, selectedWorker)).status, 204);
  assert.equal((await callback(7715, 101, { ...privateOrigin, message_id: selection.messageId + 1 }, firstSelectedTicket, selectedWorker)).status, 204);
  assert.equal((await selectedPost(7716, 101, "x".repeat(257))).status, 200);
  const limit = await awaitLifecycle(7716);
  const menuTicket = limit.message.reply_markup?.inline_keyboard?.[0]?.[0]?.callback_data;
  assert.ok(menuTicket && menuTicket !== firstSelectedTicket && /^sbo1_[A-Za-z0-9_-]{22}$/u.test(menuTicket));
  const limitOrigin = { ...origin(limit.messageId, 101), date: now + 26 };
  assert.equal((await callback(7717, 101, limitOrigin, menuTicket, selectedWorker)).status, 200);
  const revokedSelection = await awaitLifecycle(7717);
  assert.equal(revokedSelection.message.chat_id, "101");
  assert.equal(revokedSelection.message.text, "所选聚合链接已撤销。");
  assert.equal((await callback(7718, 101, limitOrigin, menuTicket, selectedWorker)).status, 204);
  assert.equal((await getAggregate(selectedCode)).status, 404);

  const ordinaryShortWorker = await runtime.getWorker("ordinary-short");
  const ordinaryShortPost = (updateId: number, actor: number, text: string, options: PostOptions = {}) =>
    post(actor, text, { updateId, worker: ordinaryShortWorker, date: now + 25, ...options });
  const ordinaryShortTarget = "https://example.net/a%20b?mode=synthetic#keep";
  assert.equal((await ordinaryShortPost(7740, 101, "/short", { worker: selectedWorker })).status, 204);
  assert.equal((await ordinaryShortPost(7741, 101, `/short ${ordinaryShortTarget}`, groupEvent)).status, 204);
  assert.equal((await ordinaryShortPost(7742, 104, `/short ${ordinaryShortTarget}`)).status, 204);
  assert.equal((await ordinaryShortPost(7743, 101, "/short")).status, 200);
  assert.match((await awaitLifecycle(7743)).message.text, /\/short https:\/\/example\.com\/xxx/u);
  assert.equal((await ordinaryShortPost(7744, 101, "/short http://synthetic-user@127.0.0.1/private")).status, 200);
  const invalidShortNotice = (await awaitLifecycle(7744)).message.text;
  assert.match(invalidShortNotice, /^短链目标或撤销参数无效。/u);
  assert.doesNotMatch(invalidShortNotice, /synthetic-user|127\.0\.0\.1/u);
  assert.equal((await ordinaryShortPost(7745, 101, `/short ${ordinaryShortTarget}`)).status, 200);
  const ordinaryShortMessage = (await awaitLifecycle(7745)).message;
  assert.equal(ordinaryShortMessage.chat_id, "101");
  assert.deepEqual(ordinaryShortMessage.link_preview_options, { is_disabled: true });
  assert.equal((await findReply(7745))?.marker, "general-short:v1");
  assert.ok(!ordinaryShortMessage.text.includes(ordinaryShortTarget));
  const ordinaryShortUrl = new URL(ordinaryShortMessage.text.split("\n")[1]);
  assert.equal(ordinaryShortUrl.origin, PRODUCTION_PUBLIC_ORIGIN);
  const ordinaryShortCode = /^\/s\/([A-Za-z0-9_-]{21}s)$/u.exec(ordinaryShortUrl.pathname)?.[1];
  assert.ok(ordinaryShortCode);
  const ordinaryShortPath = `https://app.fixture.invalid/s/${ordinaryShortCode}`;
  for (const method of ["GET", "HEAD"]) {
    const response = await ordinaryShortWorker.fetch(ordinaryShortPath, { method, redirect: "manual" });
    assert.equal(response.status, 302);
    assert.equal(response.headers.get("Location"), ordinaryShortTarget);
  }
  assert.equal((await ordinaryShortPost(7745, 101, `/short ${ordinaryShortTarget}`)).status, 204);
  assert.equal((await ordinaryShortPost(7746, 106, `/short revoke ${ordinaryShortCode}`)).status, 200);
  assert.equal((await awaitLifecycle(7746)).message.text, "没有可撤销的短链。");
  assert.equal((await ordinaryShortWorker.fetch(ordinaryShortPath, { redirect: "manual" })).status, 302);
  assert.equal((await ordinaryShortPost(7747, 101, `/short revoke ${ordinaryShortUrl.href}`)).status, 200);
  assert.equal((await awaitLifecycle(7747)).message.text, "短链已撤销。");
  assert.equal((await ordinaryShortWorker.fetch(ordinaryShortPath, { redirect: "manual" })).status, 404);
  assert.equal(await db.prepare("SELECT target_url IS NULL AS scrubbed FROM normal_short_links WHERE code_sha256=?")
    .bind(createHash("sha256").update(ordinaryShortCode).digest("hex")).first("scrubbed"), 1);

  const reservedTypedCode = "A".repeat(21) + "t";
  const reservedTypedDigest = createHash("sha256").update(reservedTypedCode).digest("hex");
  await db.prepare(`INSERT INTO telegram_subscription_short_links
    (code_sha256,origin_receipt_id,bot_id,owner_id,subscription_id,token_sha256,format,nonce,key_version)
    SELECT ?,inbox.receipt_id,inbox.bot_id,inbox.actor_id,?,?,'base64',?,1 FROM telegram_inbox AS inbox
    JOIN telegram_subscription_read AS read USING(receipt_id) WHERE inbox.bot_id=? AND inbox.update_id=7378`)
    .bind(reservedTypedDigest, initial.id, createHash("sha256").update(initial.token).digest("hex"), "A".repeat(22), pin.botId).run();
  assert.equal((await ordinaryShortPost(7748, 101, `/short revoke ${reservedTypedCode}`)).status, 200);
  assert.equal((await awaitLifecycle(7748)).message.text, "没有可撤销的短链。");
  assert.equal(await db.prepare("SELECT revoked_at IS NULL AS active FROM telegram_subscription_short_links WHERE code_sha256=?")
    .bind(reservedTypedDigest).first("active"), 1);
  const typedPath = `https://app.fixture.invalid/s/${reservedTypedCode}`;
  for (const method of ["GET", "HEAD"]) {
    const response = await formats.fetch(typedPath, { method, redirect: "manual" });
    assert.equal(response.status, 302);
    assert.equal(response.headers.get("Location"), `/sub/${initial.token}/base64`);
  }
  const originReceipt = await db.prepare("SELECT receipt_id FROM telegram_inbox WHERE bot_id=? AND update_id=7378")
    .bind(pin.botId).first<number>("receipt_id");
  assert.ok(originReceipt);
  const originalRevision = await db.prepare("SELECT actor_revision FROM telegram_general_receipt WHERE receipt_id=?")
    .bind(originReceipt).first<number>("actor_revision");
  assert.ok(originalRevision);
  const setArchivedGrant = (revision: number) => db.prepare("UPDATE telegram_general_receipt SET actor_revision=? WHERE receipt_id=?")
    .bind(revision, originReceipt).run();
  await setArchivedGrant(9007199254740991);
  assert.equal((await formats.fetch(typedPath, { redirect: "manual" })).status, 404);
  await setArchivedGrant(originalRevision);
  const setTypedReply = (state: "uncertain" | "failed") => db.prepare(`UPDATE telegram_outbox
    SET state=?,lease_id=?,lease_until=NULL,sent_message_id=NULL WHERE receipt_id=?`)
    .bind(state, state === "uncertain" ? "fixture-general-typed-uncertain" : null, originReceipt).run();
  await setTypedReply("uncertain");
  assert.equal((await formats.scheduled({ cron: "* * * * *" })).outcome, "ok");
  assert.equal((await formats.fetch(typedPath, { redirect: "manual" })).status, 302);
  await setTypedReply("failed");
  assert.equal((await formats.fetch(typedPath, { redirect: "manual" })).status, 404);
  assert.equal((await formats.scheduled({ cron: "* * * * *" })).outcome, "ok");
  assert.equal(await db.prepare(`SELECT revoked_at IS NOT NULL AND subscription_id IS NULL AND token_sha256 IS NULL
    AND format IS NULL AND nonce IS NULL AS retired FROM telegram_subscription_short_links WHERE code_sha256=? AND origin_receipt_id=?`)
    .bind(reservedTypedDigest, originReceipt).first("retired"), 1);

  const typedIssue = await runtime.getWorker("typed-short-issue");
  const typedDrain = await runtime.getWorker("typed-short-drain");
  const shortDetail = await formatDetail(7750, typedIssue);
  const shortTicket = shortDetail.message.reply_markup?.inline_keyboard?.flat().find(({ text }) => text === "Clash Meta")?.callback_data;
  assert.ok(shortTicket);
  const retry = { messageId: shortDetail.messageId, attempts: [] as string[] };
  typedRetry = retry;
  const typedSource = origin(shortDetail.messageId, 101);
  assert.equal((await callback(7752, 101, typedSource, shortTicket, typedIssue)).status, 200);
  const pending = () => db.prepare(`SELECT reply.state FROM telegram_outbox AS reply JOIN telegram_inbox AS inbox USING(receipt_id)
    WHERE inbox.bot_id=? AND inbox.update_id=7752 AND reply.attempts=1`).bind(pin.botId).first("state");
  for (const end = Date.now() + 4000; await pending() !== "pending" && Date.now() < end;) {
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  assert.equal(await pending(), "pending");
  assert.equal(retry.attempts.length, 1);
  await db.prepare(`UPDATE telegram_outbox SET due_at=unixepoch() WHERE receipt_id IN (
    SELECT receipt_id FROM telegram_inbox WHERE bot_id=? AND update_id=7752)`).bind(pin.botId).run();
  assert.equal((await typedDrain.scheduled({ cron: "* * * * *" })).outcome, "ok");
  const issuedTyped = (await awaitLifecycle(7752)).message;
  assert.deepEqual(retry.attempts, [issuedTyped.text, issuedTyped.text]);
  typedRetry = null;
  assert.equal(issuedTyped.chat_id, "101");
  assert.deepEqual(issuedTyped.link_preview_options, { is_disabled: true });
  const issuedTypedCode = issuedTyped.text.split("\n")[1]?.split("/").at(-1);
  assert.ok(issuedTypedCode && /^[A-Za-z0-9_-]{21}t$/u.test(issuedTypedCode));
  assert.equal(issuedTyped.text, `Clash Meta\n${PRODUCTION_PUBLIC_ORIGIN}/s/${issuedTypedCode}`);
  const issuedTypedPath = `https://app.fixture.invalid/s/${issuedTypedCode}`;
  assert.equal((await typedDrain.fetch(issuedTypedPath, { method: "HEAD", redirect: "manual" })).headers.get("Location"),
    `/sub/${initial.token}/clash`);
  assert.equal((await callback(7752, 101, typedSource, shortTicket, typedIssue)).status, 204);
  const scopedRevoke = `/short revoke ${PRODUCTION_PUBLIC_ORIGIN}/s/${issuedTypedCode}`;
  assert.equal((await ordinaryShortPost(7753, 106, scopedRevoke, { worker: typedDrain })).status, 200);
  assert.equal((await awaitLifecycle(7753)).message.text, "没有可撤销的短链。");
  assert.equal((await ordinaryShortPost(7754, 101, scopedRevoke, { ...groupEvent, worker: typedDrain })).status, 204);
  assert.equal((await typedDrain.fetch(issuedTypedPath, { redirect: "manual" })).status, 302);
  assert.equal((await ordinaryShortPost(7755, 101, scopedRevoke, { worker: typedDrain })).status, 200);
  assert.equal((await awaitLifecycle(7755)).message.text, "短链已撤销。");
  assert.equal((await typedDrain.fetch(issuedTypedPath, { redirect: "manual" })).status, 404);
  const pausedDetail = await formatDetail(7756, typedDrain);
  const pausedTicket = pausedDetail.message.reply_markup?.inline_keyboard?.flat().find(({ text }) => text === "Clash Meta")?.callback_data;
  assert.ok(pausedTicket);
  assert.equal((await callback(7758, 101, origin(pausedDetail.messageId, 101), pausedTicket, typedDrain)).status, 200);
  assert.equal((await awaitLifecycle(7758)).message.text, `Clash Meta\n${PRODUCTION_PUBLIC_ORIGIN}/sub/${initial.token}/clash`);
  const typedRows = await db.prepare(`SELECT link.code_sha256 AS digest,link.revoked_at IS NOT NULL AS retired
    FROM telegram_subscription_short_links AS link JOIN telegram_inbox AS inbox
      ON inbox.receipt_id=link.origin_receipt_id AND inbox.bot_id=link.bot_id AND inbox.actor_id=link.owner_id
    WHERE inbox.bot_id=? AND inbox.update_id BETWEEN 7750 AND 7758`)
    .bind(pin.botId).all();
  assert.deepEqual(typedRows.results, [{ digest: createHash("sha256").update(issuedTypedCode).digest("hex"), retired: 1 }]);

  await db.prepare("INSERT INTO telegram_general_actors VALUES (?,?,'104',16,?,'member')")
    .bind(pin.botId, pin.generation, now + 23).run();
  assert.equal(await acceptGeneralSharedTelegramCommand(db, shortPin, new Request("https://app.fixture.invalid/telegram/webhook", {
    method: "POST", headers: { "Content-Type": "application/json", "X-Telegram-Bot-Api-Secret-Token": pin.webhookSecret },
    body: JSON.stringify({ update_id: 7749, message: { text: `/short ${ordinaryShortTarget}`, message_id: 7749, date: now + 25,
      from: { id: 104, is_bot: false }, chat: { id: 104, type: "private" }, entities: [{ type: "bot_command", offset: 0, length: 6 }] } }),
  }), undefined, undefined, undefined, undefined, aggregateKey), 200);
  const queuedShort = await claimGeneralSharedTelegramReply(db, shortPin);
  assert.ok(queuedShort?.updateId === 7749);
  await db.prepare("INSERT INTO telegram_general_actors VALUES (?,?,'104',17,?,'denied')")
    .bind(pin.botId, pin.generation, now + 26).run();
  assert.equal(await beginGeneralSharedTelegramReply(db, shortPin, queuedShort), false);
  assert.equal((await db.prepare(`UPDATE telegram_outbox SET state='failed',lease_id=NULL,lease_until=NULL
    WHERE receipt_id=? AND lease_id=? AND state='leased'`).bind(queuedShort.receiptId, queuedShort.leaseId).run()).meta.changes, 1);
  await reapFailedTelegramShortLinks(db, pin.botId);
  const shortCandidateScrubbed = () => db.prepare("SELECT target_url IS NULL AS scrubbed FROM normal_short_links WHERE origin_receipt_id=?")
    .bind(queuedShort.receiptId).first("scrubbed");
  assert.equal(await shortCandidateScrubbed(), 0);
  assert.equal((await ordinaryShortWorker.scheduled({ cron: "* * * * *" })).outcome, "ok");
  assert.equal(await shortCandidateScrubbed(), 1);
  assert.ok(!lifecycleSent.some(({ reply_parameters }) => reply_parameters.message_id === 7749));

  const rehearsal = await runtime.getWorker("rehearsal");
  const lanePost = (actor: number, command: string, options: PostOptions = {}) =>
    post(actor, command, { secret: isolation.webhookSecret, date: now - 3, ...options, worker: rehearsal });
  const laneRow = (updateId: number) => db.prepare(`SELECT inbox.actor_id AS actor, inbox.receipt_nonce AS marker, reply.state
      FROM telegram_inbox AS inbox JOIN telegram_outbox AS reply USING (receipt_id)
      WHERE inbox.bot_id=? AND inbox.update_id=?`).bind(isolation.botId, updateId).first();
  const waitForLane = async (updateId: number) => {
    const end = Date.now() + 4000;
    for (let row = await laneRow(updateId); Date.now() < end; row = await laneRow(updateId)) {
      if (row?.state === "sent") return row;
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    assert.fail("The synthetic read rehearsal reply did not settle.");
  };
  await db.batch([
    db.prepare(`INSERT INTO subscriptions (owner_id,name,source_url,token,created_at,updated_at)
      VALUES (181,'Rehearsal admin only','https://source.fixture.invalid/hidden','rehearsal-admin-token',?,?),
             (182,'Rehearsal member only','https://source.fixture.invalid/hidden','rehearsal-member-token',?,?)`).bind(now, now, now, now),
    db.prepare("INSERT INTO telegram_general_read_lane (bot_id,epoch,mode) VALUES (?,1,'closed')").bind(isolation.botId),
  ]);
  const staleScope = { updateId: 8100, actorId: isolation.adminId, chatId: isolation.adminId,
    chatType: "private" as const, threadId: null, messageId: 8100, messageDate: now - 3 };
  await assert.rejects(acceptTelegramCommand(db, isolation, { ...staleScope, command: "help" }, undefined,
    assertGeneralReadLane(db, isolation.botId, "isolated", null)));
  await assert.rejects(acceptTelegramView(db, isolation, { ...staleScope, kind: "list" },
    assertGeneralReadLane(db, isolation.botId, "isolated", null)));
  assert.equal(await laneRow(8100), null, "a stale admission cannot commit on either isolation anchor");
  assert.equal((await lanePost(181, "/help", { updateId: 8101 })).status, 503);
  assert.equal((await lanePost(182, "/list", { updateId: 8102, date: now - 21 })).status, 503);
  assert.equal((await lanePost(181, "/help", { updateId: 8103, secret: pin.webhookSecret })).status, 401);
  assert.equal(await laneRow(8101), null);
  assert.equal(await laneRow(8102), null);
  assert.equal(laneSent.length, 0);

  await db.batch([
    db.prepare(`INSERT INTO telegram_general_policy (bot_id,generation,release_revision,activation_sha256,cutover_at,active)
      VALUES (?,1,?,?,?,1)`).bind(isolation.botId, fixture.releaseRevision, pin.candidateManifestSha256, now - 20),
    db.prepare("INSERT INTO telegram_general_actors VALUES (?,1,?,1,?,'admin'),(?,1,?,1,?,'member')")
      .bind(isolation.botId, isolation.adminId, now - 20, isolation.botId, isolation.memberId, now - 20),
    db.prepare("UPDATE telegram_general_read_lane SET mode='general',epoch=2,generation=1 WHERE bot_id=?")
      .bind(isolation.botId),
  ]);
  const open = await readGeneralReadLane(db, isolation, fixture.releaseRevision);
  assert.ok(open?.pin?.rehearsal && open.mode === "general");
  assert.deepEqual([open.pin.privateManagement, open.pin.privateFormats, open.pin.privateTemp,
    open.pin.privateDocument, open.pin.privateProvider, open.pin.privateClaims, open.pin.privateShareCreation, open.pin.privateAggregate,
    open.pin.privateSelected, open.pin.privateShort], [false, false, false, false, false, false, false, false, false, false],
    "the rehearsal enables only private reads");
  assert.equal((await lanePost(182, "/list", { updateId: 8102, date: now - 21 })).status, 503,
    "uncommitted pre-cutover delivery is held for the original lane");
  assert.equal((await lanePost(183, "/list", { updateId: 8104 })).status, 204);
  assert.equal(await laneRow(8104), null);
  assert.equal((await lanePost(181, "/help", { updateId: 8105 })).status, 200);
  assert.deepEqual(await waitForLane(8105), { actor: "181", marker: "general-read:v1", state: "sent" });
  assert.equal((await lanePost(182, "/list", { updateId: 8106 })).status, 200);
  assert.deepEqual(await waitForLane(8106), { actor: "182", marker: "general-read:v1", state: "sent" });
  assert.equal((await lanePost(182, "/list", { updateId: 8106 })).status, 204);
  assert.deepEqual(laneSent.map((message) => message.chat_id), ["181", "182"]);
  assert.match(laneSent[1].text, /Rehearsal member only/u);
  assert.doesNotMatch(laneSent[1].text, /Rehearsal admin only|fixture\.invalid|rehearsal-member-token/u);

  const pending = await db.prepare(`INSERT INTO telegram_inbox
    (bot_id,update_id,actor_id,chat_id,chat_type,message_id,message_date,command,receipt_nonce)
    VALUES (?,8107,?,?,'private',8107,?,'help','general-read:v1') RETURNING receipt_id`)
    .bind(isolation.botId, isolation.memberId, isolation.memberId, now - 3).first<number>("receipt_id");
  assert.ok(pending);
  await db.batch([
    db.prepare("INSERT INTO telegram_general_receipt VALUES (?,1,1,'member',?,?,?)")
      .bind(pending, fixture.releaseRevision, pin.candidateManifestSha256, now - 20),
    db.prepare("INSERT INTO telegram_outbox (receipt_id) VALUES (?)").bind(pending),
  ]);
  const laneLease = await claimGeneralSharedTelegramReply(db, open.pin);
  assert.ok(laneLease);
  assert.equal(laneLease.receiptId, pending);
  await db.batch([
    db.prepare("UPDATE telegram_general_read_lane SET mode='closed',epoch=3 WHERE bot_id=?").bind(isolation.botId),
    db.prepare("INSERT INTO telegram_auth VALUES (?,?,0,?,8108)").bind(isolation.botId, isolation.memberId, now - 2),
  ]);
  assert.equal(await beginGeneralSharedTelegramReply(db, open.pin, laneLease), false, "member revocation fences the send");
  const draining = await db.prepare(`INSERT INTO telegram_inbox
    (bot_id,update_id,actor_id,chat_id,chat_type,message_id,message_date,command,receipt_nonce)
    VALUES (?,8110,?,?,'private',8110,?,'help','general-read:v1') RETURNING receipt_id`)
    .bind(isolation.botId, isolation.adminId, isolation.adminId, now - 3).first<number>("receipt_id");
  assert.ok(draining);
  await db.batch([
    db.prepare("INSERT INTO telegram_general_receipt VALUES (?,1,1,'admin',?,?,?)")
      .bind(draining, fixture.releaseRevision, pin.candidateManifestSha256, now - 20),
    db.prepare("INSERT INTO telegram_outbox (receipt_id) VALUES (?)").bind(draining),
  ]);
  assert.equal((await rehearsal.scheduled({ cron: "* * * * *" })).outcome, "ok");
  assert.equal((await laneRow(8107))?.state, "failed");
  assert.equal((await laneRow(8110))?.state, "sent", "closing ingress preserves the current grant for draining");
  assert.equal((await lanePost(181, "/help", { updateId: 8105 })).status, 204, "known committed retries can settle while closed");
  assert.equal((await lanePost(181, "/help", { updateId: 8109 })).status, 503);
  assert.equal(laneSent.length, 3);

  await db.batch([
    db.prepare("UPDATE telegram_general_policy SET active=0 WHERE bot_id=? AND generation=1").bind(isolation.botId),
    db.prepare("UPDATE telegram_general_read_lane SET mode='isolated',epoch=4,generation=NULL WHERE bot_id=?").bind(isolation.botId),
  ]);
  assert.equal((await lanePost(181, "/help", { updateId: 8109 })).status, 200);
  assert.deepEqual(await waitForLane(8109), { actor: "181", marker: null, state: "sent" });
  assert.equal((await lanePost(182, "/list", { updateId: 8102, date: now - 21 })).status, 200);
  assert.equal((await laneRow(8102))?.marker, "view:v1", "the delayed delivery retains its original receipt family");

  const authWorker = await runtime.getWorker("auth");
  const actionDate = Math.floor(Date.now() / 1000);
  await db.prepare("INSERT INTO telegram_general_actors VALUES (?,?,'108',1,?,'member')")
    .bind(authPin.botId, authPin.generation, authPin.cutoverAt).run();
  const authPost = (id: number, actor: number, text: string, options: PostOptions = {}) =>
    post(actor, text, { worker: authWorker, updateId: id, date: actionDate, ...options });
  const directAuth = (id: number, actor: number, text: string, messageId = id) => acceptGeneralSharedTelegramCommand(db, authPin,
    new Request("https://app.fixture.invalid/telegram/webhook", { method: "POST",
      headers: { "Content-Type": "application/json", "X-Telegram-Bot-Api-Secret-Token": authPin.webhookSecret },
      body: JSON.stringify({ update_id: id, message: { text, date: actionDate, message_id: messageId,
        from: { id: actor, is_bot: false }, chat: { id: actor, type: "private" },
        entities: [{ type: "bot_command", offset: 0, length: 5 }] } }) }));
  const authState = () => db.prepare(`SELECT revision,role,effective_at AS effectiveAt FROM telegram_general_actors
    WHERE bot_id=? AND generation=? AND actor_id='108' ORDER BY revision DESC LIMIT 1`)
    .bind(authPin.botId, authPin.generation).first<{ revision: number; role: string; effectiveAt: number }>();

  assert.equal((await authPost(8200, 101, "/auth remove 108", { worker: claimsWorker })).status, 204);
  assert.equal((await authPost(8200, 108, "/auth remove 108")).status, 204);
  assert.equal((await authPost(8200, 101, "/auth remove 108", { chatType: "group", chatId: -100100 })).status, 204);
  assert.equal((await authPost(8200, 101, "/auth remove 108", { date: authPin.cutoverAt })).status, 204);
  await db.prepare("UPDATE subs_bot_schema_migrations SET sha256=? WHERE position=50").bind("0".repeat(64)).run();
  assert.equal((await authPost(8200, 101, "/auth remove 108")).status, 204);
  await db.prepare("UPDATE subs_bot_schema_migrations SET sha256=? WHERE position=50")
    .bind("369be22ccf8c0a30dfb7823e8ac2c402c65e2c404d655af360d7e88806aa0fe0").run();
  assert.equal(await findReply(8200), null);
  await db.prepare("INSERT INTO telegram_general_read_lane (bot_id,epoch,mode) VALUES (?,1,'isolated')").bind(authPin.botId).run();
  assert.equal((await authPost(8200, 101, "/auth remove 108")).status, 204, "a same-Bot rehearsal target is closed to general writes");
  await db.prepare("DELETE FROM telegram_general_read_lane WHERE bot_id=?").bind(authPin.botId).run();

  assert.equal(await directAuth(8202, 106, "/auth add 108", 10), 200, "a no-op grant orders later arrivals");
  assert.equal(await directAuth(8201, 101, "/auth remove 108", 900), 200);
  assert.equal((await authState())?.revision, 1, "the stale same-second revoke cannot win across private chats");
  assert.equal(await directAuth(8203, 101, "/auth remove 108"), 200);
  assert.equal(await directAuth(8203, 101, "/auth remove 108"), 204, "duplicate delivery cannot append another revision");
  assert.equal((await authState())?.role, "denied");
  assert.equal((await authPost(8290, 108, "/list")).status, 204);
  assert.equal(await directAuth(8204, 106, "/auth add 108"), 200);
  const regrant = await authState();
  assert.ok(regrant);
  assert.equal(regrant.revision, 3);
  assert.equal(regrant.role, "member");
  assert.ok(regrant.effectiveAt >= actionDate + 60);
  assert.equal((await authPost(8290, 108, "/list")).status, 204, "an update from before regrant cannot inherit the new role");

  assert.equal((await claimsWorker.scheduled({ cron: "* * * * *" })).outcome, "ok", "paused admission still drains accepted work");
  assert.deepEqual(claimSends.get(8204), { actorId: "106", text: "用户 108：已授权。", body: undefined });
  assert.equal(claimSends.get(8203)?.text, "这次授权操作已被较新的状态取代。");
  assert.equal(claimSends.get(900)?.text, "这次授权操作已被较新的状态取代。");
  assert.equal((await authPost(8210, 101, "/auth remove 108")).status, 200);
  assert.equal((await awaitLifecycle(8210)).message.text, "用户 108：已撤权。");
  assert.equal((await authState())?.revision, 4);
  assert.equal((await authState())?.role, "denied");
  assert.equal((await authPost(8211, 101, "/auth remove 106")).status, 200);
  assert.equal((await awaitLifecycle(8211)).message.text, "只能管理已登记的普通用户。");
  assert.equal((await authPost(8212, 101, "/auth add 109")).status, 200);
  assert.equal((await awaitLifecycle(8212)).message.text, "只能管理已登记的普通用户。");
  assert.equal(await directAuth(8213, 106, "/auth add 108"), 200);
  await db.prepare("INSERT INTO telegram_general_actors VALUES (?,?,'106',2,?,'denied')")
    .bind(authPin.botId, authPin.generation, actionDate).run();
  assert.equal((await authWorker.scheduled({ cron: "* * * * *" })).outcome, "ok");
  assert.equal((await findReply(8213))?.state, "failed", "an old admin grant cannot deliver its queued acknowledgement");
  assert.equal(lifecycleSent.some(({ reply_parameters }) => reply_parameters.message_id === 8213), false);
  for (const id of [8214, 8215, 8216, 8217]) assert.equal(await directAuth(id, 101, "/auth add 108"), 200);
  assert.equal((await authPost(8218, 101, "/auth remove 108")).status, 503, "an authorized command can retry after queue backpressure");
  assert.equal(await findReply(8218), null);
  assert.equal((await authWorker.scheduled({ cron: "* * * * *" })).outcome, "ok");
  assert.equal((await authPost(8218, 101, "/auth remove 108")).status, 200);
  assert.equal((await awaitLifecycle(8218)).message.text, "用户 108：已撤权。");
  assert.equal((await authState())?.revision, 6);

  await db.batch(Array.from({ length: 25 }, (_, offset) => db.prepare(
    "INSERT INTO telegram_general_actors VALUES (?,?,?,1,?,'member')",
  ).bind(authPin.botId, authPin.generation, String(110 + offset), actionDate + 10)));
  const listActionCount = () => db.prepare("SELECT count(*) AS n FROM telegram_general_auth_actions WHERE bot_id=?")
    .bind(authPin.botId).first<number>("n");
  const actionCount = await listActionCount();
  assert.equal((await authPost(8220, 110, "/auth list", { date: actionDate + 11 })).status, 204);
  assert.equal((await authPost(8220, 101, "/auth list", { chatType: "group", chatId: -100100 })).status, 204);
  assert.equal((await authPost(8220, 101, "/auth list 110")).status, 204);
  assert.equal(await findReply(8220), null);
  assert.equal((await authPost(8221, 101, "/auth list")).status, 200);
  const roster = (await awaitLifecycle(8221)).message;
  assert.equal(roster.chat_id, "101");
  const rosterLines = roster.text.split("\n");
  assert.equal(rosterLines.length, 22);
  assert.equal(rosterLines[0], "授权名单（默认拒绝）");
  assert.equal(rosterLines[1], "101：管理员");
  assert.ok(rosterLines.includes("108：已撤权"));
  assert.match(rosterLines[7], /^110：(等待授权生效|已授权)$/u);
  assert.equal(rosterLines.at(-1), "仅显示前 20 位，名单中还有其他用户。");
  assert.doesNotMatch(roster.text, /124：|fixture\.invalid|https?:/u);
  assert.equal((await authPost(8221, 101, "/auth list")).status, 204);
  assert.equal(await listActionCount(), actionCount, "a roster read writes no authorization action or target revision");
  assert.equal((await authState())?.revision, 6);

  assert.equal(await directAuth(8222, 101, "/auth"), 200);
  await db.prepare("INSERT INTO telegram_general_actors VALUES (?,?,'101',2,?,'denied')")
    .bind(authPin.botId, authPin.generation, actionDate).run();
  assert.equal((await authWorker.scheduled({ cron: "* * * * *" })).outcome, "ok");
  assert.equal((await findReply(8222))?.state, "failed");
  assert.equal(lifecycleSent.some(({ reply_parameters }) => reply_parameters.message_id === 8222), false);

  const rawDate = actionDate + 11;
  const rawPost = (id: number, actor: number, text: string, options: PostOptions = {}) =>
    tempPost(id, actor, text, { worker: authWorker, date: rawDate, ...options });
  const legacyRaw = JSON.stringify([{ name: "Synthetic raw baseline", type: "temp", share: firstShare }]);
  await db.prepare("INSERT INTO legacy_temp_batches VALUES (?,'110',2,2,?,1,?,?)")
    .bind(pin.botId, legacyRaw, Buffer.byteLength(legacyRaw), createHash("sha256").update(legacyRaw).digest("hex")).run();
  assert.equal((await rawPost(8300, 110, "/temp raw", { worker: shared })).status, 204);
  assert.equal((await rawPost(8300, 110, "/temp raw", { chatType: "group", chatId: -100100 })).status, 204);
  assert.equal((await rawPost(8301, 110, secondShare)).status, 200);
  await awaitLifecycle(8301);
  assert.equal((await rawPost(8302, 110, "/temp raw")).status, 200);
  assert.equal((await findReply(8302))?.marker, "general-temp-raw:v1:[0,0]");
  const rawReply = (await awaitLifecycle(8302)).message;
  assert.equal(rawReply.chat_id, "110");
  assert.equal(rawReply.text, `临时列表共有 2 条节点。发送 /temp clear 清空。\n\n${firstShare}\n${secondShare}`);
  assert.deepEqual(rawReply.link_preview_options, { is_disabled: true });
  assert.equal((await rawPost(8302, 110, "/temp raw")).status, 204);

  const long = Array.from({ length: 30 }, () => secondShare + "-" + "X".repeat(48));
  for (const id of [8304, 8305]) {
    assert.equal((await rawPost(id, 111, long.join("\n"))).status, 200);
    await awaitLifecycle(id);
  }
  assert.equal((await rawPost(8306, 111, "/temp raw")).status, 200);
  const rawEnd = Date.now() + 4000;
  while ((await findReply(8306))?.state !== "sent" && Date.now() < rawEnd) await new Promise((resolve) => setTimeout(resolve, 10));
  assert.equal((await findReply(8306))?.state, "sent");
  assert.deepEqual(tempRawDocuments.get(8306), { actorId: "111", caption: "临时列表共有 60 条节点。发送 /temp clear 清空。",
    body: [...long, ...long].join("\n") });

  const pendingRaw = (id: number, actor: number) => new Request("https://app.fixture.invalid/telegram/webhook", { method: "POST",
    headers: { "Content-Type": "application/json", "X-Telegram-Bot-Api-Secret-Token": pin.webhookSecret },
    body: JSON.stringify({ update_id: id, message: { text: "/temp raw", message_id: id, date: rawDate,
      from: { id: actor, is_bot: false }, chat: { id: actor, type: "private" }, entities: [{ type: "bot_command", offset: 0, length: 5 }] } }) });
  assert.equal(await acceptGeneralSharedTelegramCommand(db, authPin, pendingRaw(8310, 110)), 200);
  assert.equal((await rawPost(8311, 110, "/temp clear", { date: rawDate + 1 })).status, 200);
  assert.equal((await awaitLifecycle(8310)).message.text, "临时列表或授权已变更，请重新发送 /temp raw。");
  assert.equal((await rawPost(8309, 110, "/temp raw")).status, 204);
  assert.equal(await acceptGeneralSharedTelegramCommand(db, authPin, pendingRaw(8312, 111)), 200);
  await db.prepare("INSERT INTO telegram_general_actors VALUES (?,?,'111',2,?,'denied')")
    .bind(pin.botId, pin.generation, rawDate + 1).run();
  assert.equal((await authWorker.scheduled({ cron: "* * * * *" })).outcome, "ok");
  assert.equal((await findReply(8312))?.state, "failed");
  assert.equal(lifecycleSent.some(({ reply_parameters }) => reply_parameters.message_id === 8312), false);

  const multiline = await runtime.getWorker("provider-multiline");
  const multiText = `First line name | ${goodLineUrl}\n${failedLineUrl}\nIgnored duplicate | ${goodLineUrl}`;
  const multiPost = (id: number, actor: number, text = multiText, options: PostOptions = {}) => post(actor, text, {
    worker: multiline, updateId: id, date: rawDate, ...options, message: { entities: [], ...options.message },
  });
  const lineOutcomes = (updateId: number) => db.prepare(`SELECT line.ordinal,line.result_code AS result
    FROM telegram_provider_document_lines AS line JOIN telegram_inbox AS inbox USING(receipt_id)
    WHERE inbox.bot_id=? AND inbox.update_id=? ORDER BY line.ordinal`).bind(pin.botId, updateId).all();
  await db.prepare("UPDATE general_provider_fixture SET fail=0").run();
  const priorCalls = await providerCalls();
  assert.ok(priorCalls !== null);
  const oldLine = await db.prepare(`INSERT INTO subscriptions (owner_id,name,source_url,token,created_at,updated_at)
    VALUES ('110','Existing subscription',?,'fixture-multiline-retained',unixepoch(),unixepoch()) RETURNING id`)
    .bind(failedLineUrl).first<number>("id");
  assert.ok(oldLine);
  assert.equal(await publishNodeSnapshot(db, bucket, { id: oldLine, ownerId: "110", expectedGeneration: 0,
    expectedLifecycleRevision: 0 }, [{ share: fixtureShare }]), true);
  const retainedSnapshot = () => db.prepare("SELECT generation,snapshot_id AS snapshotId FROM subscriptions WHERE id=? AND owner_id='110'")
    .bind(oldLine).first();
  const oldSnapshot = await retainedSnapshot();
  assert.equal((await multiPost(8400, 110, multiText, { worker: providerOpen })).status, 204);
  assert.equal((await multiPost(8400, 110, multiText, { chatType: "group", chatId: -100100 })).status, 204);
  assert.equal((await multiPost(8400, 110, `${goodLineUrl}|fixture-key\n${failedLineUrl}`)).status, 204);
  assert.equal((await multiPost(8401, 110)).status, 200);
  assert.equal((await multiPost(8401, 110)).status, 204);
  assert.equal((await multiPost(8402, 110)).status, 503);
  assert.equal(await providerCalls(), priorCalls, "admission performs no provider egress");
  assert.deepEqual((await lineOutcomes(8401)).results, [{ ordinal: 0, result: null }, { ordinal: 1, result: null }]);
  await providerCron();
  assert.equal(await findReply(8401), null, "no terminal reply before all lines finish");
  await providerCron();
  const multiReply = (await awaitLifecycle(8401)).message;
  assert.equal(multiReply.chat_id, "110");
  assert.equal(multiReply.text, "订阅链接消息已处理。\n已保存 1 条\n已合并 0 条\n失败 1 条\n超出上限 0 条");
  assert.deepEqual((await lineOutcomes(8401)).results, [{ ordinal: 0, result: "saved" }, { ordinal: 1, result: "fetch-rejected" }]);
  assert.deepEqual(await db.prepare("SELECT name,generation FROM subscriptions WHERE owner_id='110' AND source_url=?")
    .bind(goodLineUrl).first(), { name: "First line name", generation: 1 });
  assert.deepEqual(await retainedSnapshot(), oldSnapshot);
  assert.equal(await providerCalls(), priorCalls + 2);

  assert.equal((await multiPost(8403, 112)).status, 200);
  await db.prepare("INSERT INTO telegram_general_actors VALUES (?,?,'112',2,?,'denied')")
    .bind(pin.botId, pin.generation, rawDate + 1).run();
  await providerCron();
  assert.deepEqual((await lineOutcomes(8403)).results, [{ ordinal: 0, result: "access-changed" }, { ordinal: 1, result: "access-changed" }]);
  assert.equal(await findReply(8403), null);
  assert.equal(await providerCalls(), priorCalls + 2);
});
