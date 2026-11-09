import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { Miniflare } from "miniflare";
import { createSubscription, publishNodeSnapshot } from "../src/storage.ts";
import { trashOwnedSubscription } from "../src/subscriptions.ts";
import { acceptTelegramSubscriptionShare, importTelegramPrivateShareCreationKey } from "../src/telegram/private-share-creation.ts";
import { PRIVATE_SHARE_CREATION_INSTALLATION } from "../src/telegram/private-share-runtime.ts";
import type { TelegramPolicy } from "../src/telegram/protocol.ts";

const policy: TelegramPolicy = {
  botId: "75401", botUsername: "FixtureSubscriptionShareBot", adminId: "75402", memberId: "75403",
  groupId: "-10075404", botToken: "75401:synthetic-token", webhookSecret: "synthetic-subscription-share-secret",
};
const unavailable = "无法分享此订阅。请在私聊打开自己的订阅详情后重试。";
const name = "  合成 & <节点>  ";
const sourceUrl = "HtTpS://provider.example.invalid/sub/%2F?z=fixture%2Bcredential&b=x|y";
const origin = "https://subs-bot-cf-dev-01.lilyya.workers.dev";
const creationKey = Buffer.alloc(32, 0x58).toString("base64url");
const digest = (bytes: Buffer | string) => createHash("sha256").update(bytes).digest("hex");

type WireReply = { chat_id: string; text: string; reply_parameters?: { message_id: number }; link_preview_options: unknown };
type ShareRow = { id: number; payloadId: string; payloadSha256: string; payloadBytes: number; codeSha256: string;
  sender: string; target: string | null; maxClaims: number; duration: number };

test("the emitted Worker shares exactly one owned subscription payload with its designated private recipient", { timeout: 60_000 }, async (t) => {
  const directory = process.env.WORKER_TEST_BUNDLE_DIR;
  assert.ok(directory);
  const manifest = JSON.parse(await readFile(join(directory, "isolation.json"), "utf8")) as {
    compatibilityDate: string; revision: string; bundleSha256: string; migrations: { name: string; sha256: string }[];
  };
  const script = await readFile(join(directory, "index.js"));
  assert.equal(digest(script), manifest.bundleSha256);
  const sent: Array<{ id: number; body: WireReply }> = [];
  const runtime = new Miniflare({ modules: true, script: script.toString("utf8"), compatibilityDate: manifest.compatibilityDate,
    d1Databases: ["DB"], r2Buckets: ["NODES"], bindings: { BUILD_REVISION: manifest.revision,
      TELEGRAM_ISOLATION_CONFIG: JSON.stringify(policy), TELEGRAM_PRIVATE_SHARE_CREATION_KEY: creationKey,
    }, outboundService: async (request: Request) => {
      assert.equal(request.url, `https://api.telegram.org/bot${policy.botToken}/sendMessage`);
      assert.equal(request.method, "POST");
      const body = await request.json() as WireReply;
      assert.ok([policy.adminId, policy.memberId].includes(body.chat_id));
      assert.deepEqual(body.link_preview_options, { is_disabled: true });
      const id = 21_000 + sent.length;
      sent.push({ id, body });
      return Response.json({ ok: true, result: { message_id: id, chat: { id: Number(body.chat_id) } } });
    } });
  t.after(() => runtime.dispose());
  const db = await runtime.getD1Database("DB");
  const bucket = await runtime.getR2Bucket("NODES");
  for (const { name, sha256 } of manifest.migrations) {
    const bytes = await readFile(join(directory, name));
    assert.equal(digest(bytes), sha256);
    await db.batch(bytes.toString("utf8").trim().split(/;\s*/u).filter(Boolean).map((sql) => db.prepare(sql)));
  }
  await db.prepare("CREATE TABLE subs_bot_schema_migrations (position INTEGER, name TEXT PRIMARY KEY, sha256 TEXT, mode TEXT)").run();
  await db.batch(manifest.migrations.map(({ name, sha256 }, index) =>
    db.prepare("INSERT INTO subs_bot_schema_migrations VALUES (?,?,?,'applied')").bind(index + 1, name, sha256)));

  const foreign = await createSubscription(db, { ownerId: policy.memberId, name: "Foreign fixture", sourceUrl: "https://foreign.example.invalid/sub" });
  const own = await createSubscription(db, { ownerId: policy.adminId, name, sourceUrl });
  const trashed = await createSubscription(db, { ownerId: policy.adminId, name: "Trashed fixture", sourceUrl: "https://trash.example.invalid/sub" });
  assert.notEqual(own.id, 1, "The only active subscription is selected by stable ID, independent of list position.");
  assert.equal(await trashOwnedSubscription(db, { id: trashed.id, ownerId: policy.adminId, expectedLifecycleRevision: 0 }), true);
  const date = Number(await db.prepare("SELECT unixepoch() AS now").first("now"));
  const context = await importTelegramPrivateShareCreationKey(creationKey, PRIVATE_SHARE_CREATION_INSTALLATION);
  assert.ok(context);
  let publishedDuringAdmission = false;
  const racingDb = { prepare: (sql: string) => db.prepare(sql), async batch(statements: D1PreparedStatement[]) {
    if (!publishedDuringAdmission) {
      // Change only the generation after the source read and before the reservation transaction.
      assert.equal(await publishNodeSnapshot(db, bucket, { id: own.id, ownerId: policy.adminId,
        expectedGeneration: 0, expectedLifecycleRevision: 0 },
      [{ share: "ss://YWVzLTI1Ni1nY206Zml4dHVyZQ@203.0.113.10:8388#Bundle-share-node" }]), true);
      publishedDuringAdmission = true;
    }
    return db.batch(statements);
  } } as unknown as D1Database;
  assert.equal(await acceptTelegramSubscriptionShare(racingDb, bucket, policy, { updateId: 90, messageId: 90, messageDate: date,
    actorId: policy.adminId, chatId: policy.adminId, chatType: "private", threadId: null, args: `sub ${own.id}`,
    subscriptionId: own.id, maxClaims: 1, targetUserId: policy.memberId, durationMinutes: 3,
  }, context), "unavailable");
  assert.equal(publishedDuringAdmission, true);
  assert.equal(await db.prepare("SELECT receipt_id FROM telegram_inbox WHERE bot_id=? AND update_id=90").bind(policy.botId).first(), null);
  assert.equal((await bucket.list({ prefix: "private-shares/" })).objects.length, 0);

  const clashUrl = `${origin}/sub/${own.token}/clash`;
  const exported = await runtime.dispatchFetch(clashUrl);
  assert.equal(exported.status, 200);
  assert.match(await exported.text(), /Bundle-share-node/u);
  const expectedBody = `🏷️ 订阅名称：${name}\n🌐 原始链接：${sourceUrl}\n⚡ Clash 配置：${clashUrl}`;

  const post = (id: number, actor: string, text: string, chat = actor) => runtime.dispatchFetch("https://fixture.invalid/telegram/webhook", {
    method: "POST", headers: { "Content-Type": "application/json", "X-Telegram-Bot-Api-Secret-Token": policy.webhookSecret },
    body: JSON.stringify({ update_id: id, message: { message_id: id, date, text, from: { id: Number(actor), is_bot: false },
      chat: { id: Number(chat), type: chat.startsWith("-") ? "group" : "private" },
      ...(text.startsWith("/") ? { entities: [{ type: "bot_command", offset: 0, length: text.split(/\s/u, 1)[0].length }] } : {}),
    } }),
  });
  const worker = await runtime.getWorker();
  const tick = async () => assert.equal((await worker.scheduled({ cron: "* * * * *" })).outcome, "ok");
  const waitFor = async (find: () => Promise<WireReply | undefined>) => {
    await tick();
    for (let attempt = 0; attempt < 60; attempt++) {
      const result = await find();
      if (result) return result;
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    assert.fail("Expected a private subscription-share fixture reply.");
  };
  const confirmed = (updateId: number) => waitFor(async () => {
    const id = await db.prepare(`SELECT sent_message_id FROM telegram_outbox JOIN telegram_inbox USING(receipt_id)
      WHERE bot_id=? AND update_id=? AND state='sent'`).bind(policy.botId, updateId).first<number>("sent_message_id");
    return sent.find((reply) => reply.id === id && reply.body.reply_parameters?.message_id === updateId)?.body;
  });
  const tableCount = (table: "private_shares" | "telegram_private_share_creations" | "private_share_claims") =>
    db.prepare(`SELECT count(*) AS n FROM ${table}`).first<number>("n");
  const shares = () => db.prepare(`SELECT id,payload_id AS payloadId,payload_sha256 AS payloadSha256,
      payload_bytes AS payloadBytes,code_sha256 AS codeSha256,sender_id AS sender,target_user_id AS target,
      max_claims AS maxClaims,expire_at-created_at AS duration FROM private_shares ORDER BY id`).all<ShareRow>();

  const command = `/share sub ${own.id} x1 id${policy.memberId} s3`;
  assert.equal((await post(1, policy.adminId, command, policy.groupId)).status, 204);
  assert.equal((await post(2, policy.adminId, command, "-10075405")).status, 204);
  assert.equal((await post(3, "75406", command)).status, 204);
  for (const [id, actor, target] of [[4, policy.memberId, own.id], [5, policy.adminId, foreign.id],
    [6, policy.adminId, trashed.id], [7, policy.adminId, 99_999]] as const) {
    const start = sent.length;
    assert.equal((await post(id, actor, `/share sub ${target}`)).status, 200);
    const reply = await waitFor(async () => sent.slice(start).find(({ body }) => body.chat_id === actor)?.body);
    assert.equal(reply.text, unavailable);
  }
  assert.equal(await tableCount("private_shares"), 0);
  assert.equal(await tableCount("telegram_private_share_creations"), 0);
  assert.equal((await bucket.list({ prefix: "private-shares/" })).objects.length, 0);

  assert.equal((await post(8, policy.adminId, "1")).status, 200);
  const detail = await confirmed(8);
  assert.equal(detail.chat_id, policy.adminId);
  assert.ok(detail.text.split("\n").includes(`私密分享此订阅：/share sub ${own.id}`));
  assert.equal(detail.text.includes(sourceUrl) || detail.text.includes(own.token), false);

  const request = () => post(20, policy.adminId, command);
  assert.deepEqual((await Promise.all([request(), request()])).map(({ status }) => status), [200, 200]);
  const created = await confirmed(20);
  assert.equal(created.chat_id, policy.adminId);
  const code = created.text.match(/\?start=claim_([A-Za-z0-9_-]{22})/u)?.[1];
  assert.ok(code);
  assert.equal(sent.filter(({ body }) => body.reply_parameters?.message_id === 20).length, 1);
  assert.equal(await tableCount("telegram_private_share_creations"), 1);
  const stored = (await shares()).results;
  assert.equal(stored.length, 1);
  const [share] = stored;
  const expectedBytes = Buffer.from(expectedBody);
  assert.deepEqual({ sender: share.sender, target: share.target, maxClaims: share.maxClaims, duration: share.duration },
    { sender: policy.adminId, target: policy.memberId, maxClaims: 1, duration: 180 });
  assert.equal(share.codeSha256, digest(code));
  assert.equal(share.payloadSha256, digest(expectedBytes));
  assert.equal(share.payloadBytes, expectedBytes.length);
  const object = await bucket.get(`private-shares/${share.payloadId}.txt`);
  assert.ok(object);
  assert.deepEqual(Buffer.from(await object.arrayBuffer()), expectedBytes);

  assert.equal((await post(21, policy.adminId, `/start claim_${code}`)).status, 200);
  assert.match((await confirmed(21)).text, /指定了其他领取人/u);
  assert.equal(await tableCount("private_share_claims"), 0);
  for (const id of [22, 23]) {
    assert.equal((await post(id, policy.memberId, `/start claim_${code}`)).status, 200);
    const reply = await confirmed(id);
    assert.equal(reply.chat_id, policy.memberId);
    assert.equal(reply.text.split("\n\n", 2)[1], expectedBody);
    assert.equal(await tableCount("private_share_claims"), 1);
  }
  for (const { body } of sent.filter(({ body }) => ![22, 23].includes(body.reply_parameters?.message_id ?? 0))) {
    for (const sensitive of [sourceUrl, name, clashUrl]) assert.equal(body.text.includes(sensitive), false);
  }

  const literalBody = "  sub 1 remains literal after the delimiter.  ";
  assert.equal((await post(24, policy.adminId, `/share x1 --\n${literalBody}`)).status, 200);
  assert.match((await confirmed(24)).text, /\?start=claim_[A-Za-z0-9_-]{22}/u);
  const after = (await shares()).results;
  assert.equal(after.length, 2);
  assert.equal(after[1].payloadSha256, digest(literalBody));
  assert.equal(await (await bucket.get(`private-shares/${after[1].payloadId}.txt`))!.text(), literalBody);
});
