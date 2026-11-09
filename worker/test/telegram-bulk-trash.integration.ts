import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { Miniflare } from "miniflare";
import { createSubscription, getOwnedSubscription, publishNodeSnapshot } from "../src/storage.ts";
import { listDeletedSubscriptions, renameOwnedSubscription, restoreOwnedSubscription } from "../src/subscriptions.ts";
import { acceptTelegramBulkTrash, confirmTelegramBulkTrashSend, renderTelegramBulkTrash } from "../src/telegram/bulk-trash.ts";
import type { TelegramPolicy } from "../src/telegram/protocol.ts";
import { beginTelegramBulkTrashReply, claimTelegramReply, settleTelegramReply } from "../src/telegram/store.ts";

test("emitted /d previews owned matches and atomically recycles the exact confirmed generation set", { timeout: 90_000 }, async () => {
  const directory = process.env.WORKER_TEST_BUNDLE_DIR;
  assert.ok(directory);
  const manifest = JSON.parse(await readFile(join(directory, "isolation.json"), "utf8"));
  const script = await readFile(join(directory, "index.js"));
  const sha256 = (bytes: Buffer | string) => createHash("sha256").update(bytes).digest("hex");
  assert.equal(sha256(script), manifest.bundleSha256);
  const policy: TelegramPolicy = {
    botId: "78701", botUsername: "Fixture_Trash_Bot", adminId: "78702", memberId: "78703", groupId: "-10078704",
    botToken: "78701:synthetic-token", webhookSecret: "synthetic-bulk-trash-secret",
  };
  type Button = { text: string; callback_data: string };
  type Sent = { id: number; text: string; chat: string; buttons: Button[] };
  const sent: Sent[] = [];
  const runtime = new Miniflare({
    modules: true, script: script.toString("utf8"), compatibilityDate: manifest.compatibilityDate,
    d1Databases: ["DB"], r2Buckets: ["NODES"],
    bindings: { BUILD_REVISION: manifest.revision, TELEGRAM_ISOLATION_CONFIG: JSON.stringify(policy) },
    outboundService: async (request: Request) => {
      assert.equal(request.method, "POST");
      const api = `https://api.telegram.org/bot${policy.botToken}`;
      if (request.url === api + "/answerCallbackQuery") return Response.json({ ok: true, result: true });
      assert.equal(request.url, api + "/sendMessage");
      const body = await request.json() as { chat_id: string; text: string; link_preview_options: unknown;
        reply_markup?: { inline_keyboard: Button[][] } };
      assert.ok(body.chat_id === policy.memberId || body.chat_id === policy.adminId);
      assert.deepEqual(body.link_preview_options, { is_disabled: true });
      assert.doesNotMatch(body.text, /https:\/\/|synthetic-(?:source|name)-secret/u);
      const id = 1000 + sent.length;
      sent.push({ id, text: body.text, chat: body.chat_id, buttons: body.reply_markup?.inline_keyboard.flat() ?? [] });
      return Response.json({ ok: true, result: { message_id: id, chat: { id: Number(body.chat_id) } } });
    },
  });
  try {
    const db = await runtime.getD1Database("DB");
    const bucket = await runtime.getR2Bucket("NODES");
    const migrations = manifest.migrations as { name: string; sha256: string }[];
    const bulk = migrations.find(({ name }) => name === "0024_telegram_bulk_trash.sql");
    const retirement = migrations.find(({ name }) => name === "0038_legacy_selected_aggregates.sql");
    assert.ok(bulk && retirement);
    async function applyMigration(migration: (typeof migrations)[number]) {
      const bytes = await readFile(join(directory!, migration.name));
      assert.equal(sha256(bytes), migration.sha256);
      await db.batch(bytes.toString("utf8").trim().split(/;\s*/u).filter(Boolean).map((sql) => db.prepare(sql)));
    }
    for (const migration of migrations) if (migration !== bulk) await applyMigration(migration);
    const now = await db.prepare("SELECT unixepoch() AS now").first<number>("now");
    assert.ok(now);
    const date = now - 5;
    const post = (update: unknown) => runtime.dispatchFetch("https://fixture.invalid/telegram/webhook", {
      method: "POST", headers: { "Content-Type": "application/json", "X-Telegram-Bot-Api-Secret-Token": policy.webhookSecret },
      body: JSON.stringify(update),
    });
    const chat = (id: string) => ({ id: Number(id), type: id === policy.groupId ? "supergroup" : "private" });
    const command = (id: number, text: string, owner = policy.memberId, chatId = owner) => post({ update_id: id, message: {
      message_id: id, date, text, from: { id: Number(owner), is_bot: false }, chat: chat(chatId),
      entities: [{ type: "bot_command", offset: 0, length: 2 }],
    } });
    const click = (updateId: number, messageId: number, ticket: string, owner = policy.memberId, chatId = owner) =>
      post({ update_id: updateId, callback_query: { id: `fixture-bulk-${updateId}`, data: ticket,
        from: { id: Number(owner), is_bot: false }, message: { message_id: messageId, date,
          from: { id: Number(policy.botId), is_bot: true }, chat: chat(chatId) } } });
    const state = (id: number) => db.prepare(`SELECT state,sent_message_id AS id FROM telegram_inbox
      JOIN telegram_outbox USING(receipt_id) WHERE bot_id=? AND update_id=?`).bind(policy.botId, id)
      .first<{ state: string; id: number | null }>();
    async function reply(id: number) {
      for (let attempt = 0; attempt < 60; attempt++) {
        const row = await state(id);
        const value = row?.state === "sent" && sent.find((item) => item.id === row.id);
        if (value) return value;
        await new Promise((resolve) => setTimeout(resolve, 100));
      }
      assert.fail("Expected private bulk trash reply did not settle.");
    }
    const ticket = ({ buttons }: Sent) => {
      assert.equal(buttons.length, 1);
      assert.equal(buttons[0].text, "确认移入回收站");
      assert.match(buttons[0].callback_data, /^sbd1_[A-Za-z0-9_-]{22}$/u);
      return buttons[0].callback_data;
    };
    const seed = (ownerId: string, name: string, slug: string) => createSubscription(db, {
      ownerId, name, sourceUrl: `https://example.invalid/${slug}`,
    });
    const trash = async (ownerId = policy.memberId) => (await listDeletedSubscriptions(db, ownerId, { limit: 50 })).items;
    const first = await seed(policy.memberId, "Straße-AΣ https://example.invalid/synthetic-name-secret", "first");
    const second = await seed(policy.memberId, "URL match", "straße-aς/synthetic-source-secret");
    const decoy = await seed(policy.memberId, "STRASSE-AΣ decoy", "decoy");
    const foreign = await seed(policy.adminId, "Foreign Straße-AΣ match", "foreign");
    await db.batch([
      db.prepare("CREATE TABLE subs_bot_schema_migrations(position INTEGER PRIMARY KEY,name TEXT,sha256 TEXT,mode TEXT) STRICT"),
      db.prepare("INSERT INTO subs_bot_schema_migrations VALUES (38,?,?,'applied')").bind(retirement.name, retirement.sha256),
      db.prepare("INSERT INTO legacy_selected_members VALUES (?,0),(?,0),(?,0),(?,0)")
        .bind(first.id, second.id, decoy.id, foreign.id),
    ]);
    const watched = async () => (await db.prepare("SELECT retired FROM legacy_selected_members ORDER BY id").all<{ retired: number }>())
      .results.map(({ retired }) => retired);
    const needle = "/d STRAẞE-Aς";
    const uri = "ss://YWVzLTI1Ni1nY206Zml4dHVyZQ@203.0.113.9:8388#Synthetic";
    const publish = (generation: number) => publishNodeSnapshot(db, bucket, { id: second.id, ownerId: policy.memberId,
      expectedGeneration: generation, expectedLifecycleRevision: 0 }, [{ name: "Published", share: uri }]);

    assert.equal((await command(1, needle)).status, 204);
    assert.equal(await state(1), null);
    await applyMigration(bulk);
    assert.equal((await command(2, needle, policy.memberId, policy.groupId)).status, 204);
    assert.equal(await state(2), null);
    assert.equal((await command(3, "/d")).status, 200);
    assert.match((await reply(3)).text, /^用法/u);
    assert.equal((await command(4, "/d unmatched-fixture")).status, 200);
    assert.equal((await reply(4)).text, "没有匹配订阅。");

    assert.equal((await command(5, needle)).status, 200);
    const preview = await reply(5);
    assert.match(preview.text, /以下 2 条订阅/u);
    assert.match(preview.text, /1\. Straße-AΣ \[链接已省略\]\n2\. URL match/u);
    assert.doesNotMatch(preview.text, /Foreign|decoy/u);
    assert.deepEqual(await trash(), []);
    assert.equal((await click(6, preview.id, ticket(preview), policy.adminId)).status, 200);
    assert.equal((await click(7, preview.id, ticket(preview), policy.memberId, policy.groupId)).status, 204);
    assert.equal((await click(8, preview.id + 1, ticket(preview))).status, 200);
    for (const id of [6, 7, 8]) assert.equal(await state(id), null);

    assert.equal(await publish(0), true);
    assert.equal((await click(9, preview.id, ticket(preview))).status, 200);
    assert.match((await reply(9)).text, /本次未移动任何订阅/u);
    assert.deepEqual(await trash(), []);
    assert.deepEqual(await watched(), [0, 0, 0, 0]);
    assert.ok(await getOwnedSubscription(db, policy.memberId, first.id));
    assert.ok(await getOwnedSubscription(db, policy.memberId, second.id));
    assert.equal((await command(10, needle)).status, 200);
    const retryable = await reply(10);
    const code = ticket(retryable);
    await db.prepare(`CREATE TRIGGER ignore_synthetic_second_trash BEFORE INSERT ON subscription_trash
      WHEN new.id=${second.id} BEGIN SELECT RAISE(IGNORE); END`).run();
    try {
      assert.equal((await click(11, retryable.id, code)).status, 503);
      assert.equal(await state(11), null);
      assert.deepEqual(await trash(), []);
      assert.deepEqual(await watched(), [0, 0, 0, 0]);
      for (const item of [first, second]) assert.equal((await getOwnedSubscription(db, policy.memberId, item.id))?.lifecycleRevision, 0);
      assert.deepEqual(await db.prepare("SELECT confirmed_by_receipt_id FROM telegram_bulk_trash WHERE token_sha256=?")
        .bind(sha256(code)).first(), { confirmed_by_receipt_id: null });
    } finally {
      await db.prepare("DROP TRIGGER ignore_synthetic_second_trash").run();
    }
    assert.equal((await click(11, retryable.id, code)).status, 200);
    assert.match((await reply(11)).text, /已将 2 条订阅移入回收站/u);
    assert.deepEqual(await watched(), [1, 1, 0, 0]);
    assert.equal((await click(12, retryable.id, code)).status, 200);
    assert.equal(await state(12), null);
    assert.deepEqual((await trash()).map(({ id, lifecycleRevision }) => [id, lifecycleRevision]).sort((a, b) => a[0] - b[0]),
      [[first.id, 1], [second.id, 1]]);
    assert.ok(await getOwnedSubscription(db, policy.memberId, decoy.id));
    assert.ok(await getOwnedSubscription(db, policy.adminId, foreign.id));
    assert.equal((await runtime.dispatchFetch(`https://fixture.invalid/sub/${second.token}/base64`)).status, 404);
    assert.equal(await restoreOwnedSubscription(db, { id: second.id, ownerId: policy.memberId, expectedLifecycleRevision: 1 }), true);
    assert.deepEqual(await watched(), [1, 1, 0, 0]);
    const recovered = await runtime.dispatchFetch(`https://fixture.invalid/sub/${second.token}/base64`);
    assert.equal(recovered.status, 200);
    assert.equal(await recovered.text(), Buffer.from(uri).toString("base64"));

    assert.equal((await command(13, needle)).status, 200);
    const beforeGrant = await reply(13);
    await db.prepare("INSERT INTO telegram_auth (bot_id,user_id,allowed,message_date,message_id) VALUES (?,?,1,?,1)")
      .bind(policy.botId, policy.memberId, now - 60).run();
    assert.equal((await click(14, beforeGrant.id, ticket(beforeGrant))).status, 200);
    assert.equal(await state(14), null);
    assert.ok(await getOwnedSubscription(db, policy.memberId, second.id));

    const boundaryIds: number[] = [];
    for (let index = 0; index < 17; index++) {
      const row = await seed(policy.adminId, `all-overlap ${index < 16 ? "exact-boundary" : "outside-boundary"} ${index}`, `cap-${index}`);
      boundaryIds.push(row.id);
    }
    await db.prepare("INSERT INTO legacy_selected_members SELECT value,0 FROM json_each(?)").bind(JSON.stringify(boundaryIds)).run();
    assert.equal((await command(15, "/d all-overlap", policy.adminId)).status, 200);
    const limit = await reply(15);
    assert.match(limit.text, /超过 16 条订阅/u);
    assert.deepEqual(limit.buttons, []);
    assert.equal((await command(16, "/d exact-boundary", policy.adminId)).status, 200);
    const max = await reply(16);
    assert.match(max.text, /以下 16 条订阅/u);
    assert.equal((await click(17, max.id, ticket(max), policy.adminId)).status, 200);
    assert.match((await reply(17)).text, /已将 16 条订阅移入回收站/u);
    assert.equal((await trash(policy.adminId)).length, 16);
    assert.deepEqual((await watched()).slice(4), [...Array<number>(16).fill(1), 0]);

    assert.equal(await acceptTelegramBulkTrash(db, policy, { kind: "preview", query: "Foreign", actorId: policy.adminId,
      chatId: policy.adminId, chatType: "private", threadId: null, messageId: 18, messageDate: date, updateId: 18 }), "accepted");
    assert.equal(await claimTelegramReply(db, policy.botId), null);
    const lease = await claimTelegramReply(db, policy.botId, false, false, false, false, false, false, undefined, true);
    assert.ok(lease?.bulkTrash);
    const prepared = await renderTelegramBulkTrash(db, policy, lease);
    assert.ok(prepared?.ticket);
    assert.equal(await beginTelegramBulkTrashReply(db, policy, lease, prepared.guard, prepared.ticket.sha256), true);
    assert.equal(await renameOwnedSubscription(db, { id: foreign.id, ownerId: policy.adminId, expectedLifecycleRevision: 0 }, "Renamed"), true);
    assert.equal(await confirmTelegramBulkTrashSend(db, policy, lease, prepared.guard, prepared.ticket.sha256), false);
    await settleTelegramReply(db, policy, lease, { kind: "failed" });
    assert.equal((await state(18))?.state, "failed");

    assert.equal((await command(19, needle)).status, 200);
    assert.equal((await command(20, "/d Renamed", policy.adminId)).status, 200);
    const oldMember = await reply(19);
    const oldAdmin = await reply(20);
    const roles = await db.prepare(`SELECT actor_role FROM telegram_bulk_trash JOIN telegram_inbox USING(receipt_id)
      WHERE update_id IN (19,20) ORDER BY update_id`).all();
    assert.deepEqual(roles.results, [{ actor_role: "member" }, { actor_role: "admin" }]);
    await db.prepare("UPDATE telegram_auth SET allowed=0,message_date=unixepoch(),message_id=21 WHERE bot_id=? AND user_id=?")
      .bind(policy.botId, policy.memberId).run();
    const changedRoles = { ...policy, adminId: policy.memberId, memberId: policy.adminId };
    for (const [updateId, owner, origin] of [[21, policy.memberId, oldMember], [22, policy.adminId, oldAdmin]] as const) {
      assert.equal(await acceptTelegramBulkTrash(db, changedRoles, { kind: "confirm", ticket: ticket(origin),
        callbackId: `fixture-bulk-role-${updateId}`, updateId, actorId: owner, chatId: owner, chatType: "private",
        threadId: null, messageId: origin.id, messageDate: date }), "ignored");
      assert.equal(await state(updateId), null);
      assert.deepEqual(await db.prepare("SELECT confirmed_by_receipt_id FROM telegram_bulk_trash WHERE token_sha256=?")
        .bind(sha256(ticket(origin))).first(), { confirmed_by_receipt_id: null });
    }
    assert.ok(await getOwnedSubscription(db, policy.memberId, second.id));
    assert.ok(await getOwnedSubscription(db, policy.adminId, foreign.id));

    const actions = await db.prepare("SELECT * FROM telegram_bulk_trash").all();
    assert.doesNotMatch(JSON.stringify(actions.results), /sbd1_|synthetic-(?:source|name)-secret|STRAẞE|URL match|https:\/\//u);
  } finally {
    await runtime.dispose();
  }
});
