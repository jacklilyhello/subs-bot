import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile, readdir } from "node:fs/promises";
import { after, before, test } from "node:test";
import { build } from "esbuild";
import { Miniflare } from "miniflare";
import { fileURLToPath } from "node:url";
import { getAggregateNodeSource, hasAggregateLink } from "../src/aggregate.ts";
import { createSubscription, publishNodeSnapshot } from "../src/storage.ts";
import { renameOwnedSubscription, restoreOwnedSubscription, trashOwnedSubscription } from "../src/subscriptions.ts";
import { parseTelegramAggregateKey, TELEGRAM_AGGREGATE_ORIGIN } from "../src/telegram/aggregate-actions.ts";
import { drainTelegramReplies } from "../src/telegram/delivery.ts";
import { acceptTelegramSelected, MAX_SELECTED_LINKS, prepareSelectedLimitTickets, prepareSelectedRevokeTicket,
  reapTelegramSelected, resolveTelegramSelectedCode, retireUnsentSelectedLink, TELEGRAM_SELECTED_MARKER } from "../src/telegram/selected-export.ts";
import { beginTelegramSelectedLinkReply, claimTelegramReply, reapExpiredTelegramReplies, settleTelegramReply } from "../src/telegram/store.ts";
import type { TelegramPolicy, TelegramSelectedUpdate } from "../src/telegram/protocol.ts";

const migrations = new URL("../migrations/", import.meta.url);
const date = Math.floor(Date.now() / 1000) - 5;
const encodedKey = Buffer.alloc(32, 0x29).toString("base64url");
const share = "ss://YWVzLTI1Ni1nY206Zml4dHVyZS1vbmx5@203.0.113.10:8388";
const runtime = new Miniflare({ modules: true, compatibilityDate: "2026-07-30", d1Databases: ["DB"], r2Buckets: ["NODES"],
  script: "export default { fetch() { return new Response(null); } };" });
let db: D1Database;
let bucket: R2Bucket;
let key: CryptoKey;

async function migrate(database: D1Database) {
  for (const file of (await readdir(migrations)).filter((name) => name.endsWith(".sql")).sort()) {
    const sql = await readFile(new URL(file, migrations), "utf8");
    await database.batch(sql.trim().split(/;\s*/u).filter(Boolean).map((statement) => database.prepare(statement)));
  }
}
before(async () => {
  db = await runtime.getD1Database("DB");
  bucket = await runtime.getR2Bucket("NODES");
  key = (await parseTelegramAggregateKey(encodedKey))!;
  await migrate(db);
});
after(() => runtime.dispose());

function policy(suffix: string): TelegramPolicy {
  return { botId: `930${suffix}`, adminId: `931${suffix}`, memberId: `932${suffix}`, groupId: "-1001234567890",
    botUsername: "SelectedFixtureBot", botToken: `930${suffix}:synthetic-token`, webhookSecret: "synthetic-selected-secret" };
}
function event(config: TelegramPolicy, updateId: number, query = ""): TelegramSelectedUpdate {
  return { updateId, actorId: config.memberId, chatId: config.memberId, chatType: "private", threadId: null,
    messageId: updateId + 10, messageDate: date, kind: "selected", query };
}
async function seed(config: TelegramPolicy, name: string, ready = true, database = db, nodes = bucket) {
  const row = await createSubscription(database, { ownerId: config.memberId, name, sourceUrl: "https://provider.example.invalid/private" });
  if (ready) assert.equal(await publishNodeSnapshot(database, nodes, { id: row.id, ownerId: config.memberId,
    expectedGeneration: 0, expectedLifecycleRevision: 0 }, [{ name, share: `${share}#${encodeURIComponent(name)}` }]), true);
  return row;
}
async function action(config: TelegramPolicy, updateId: number) {
  return db.prepare(`SELECT action.result,action.code_sha256 AS codeSha256,inbox.receipt_nonce AS marker
    FROM telegram_selected_actions AS action JOIN telegram_inbox AS inbox USING(receipt_id)
    WHERE inbox.bot_id=? AND inbox.update_id=?`).bind(config.botId, updateId)
    .first<{ result: string; codeSha256: string | null; marker: string }>();
}
async function issued(config: TelegramPolicy, updateId: number, query = "") {
  assert.equal(await acceptTelegramSelected(db, config, event(config, updateId, query), key), "accepted");
  const lease = await claimTelegramReply(db, config.botId, true);
  assert.ok(lease?.selected);
  const scope = { ...lease, selected: lease.selected };
  const code = await resolveTelegramSelectedCode(db, config, scope, key);
  assert.ok(code);
  const ticket = await prepareSelectedRevokeTicket();
  assert.equal(await beginTelegramSelectedLinkReply(db, config, lease, [{ ...ticket, codeSha256: lease.selected.codeSha256! }]), true);
  assert.equal(await resolveTelegramSelectedCode(db, config, scope, key, true), code);
  await settleTelegramReply(db, config, lease, { kind: "sent", messageId: 700 + updateId });
  return { code, ticket, lease };
}
function revoke(config: TelegramPolicy, updateId: number, token: string, messageId = 701): TelegramSelectedUpdate {
  return { updateId, actorId: config.memberId, chatId: config.memberId, chatType: "private", threadId: null,
    messageId, messageDate: date, kind: "selected-revoke", callbackId: "synthetic-selected-callback", ticket: token };
}

test("selected membership uses lowercase, fixed ordered IDs, and retains empty matched members", async () => {
  const config = policy("01");
  const first = await seed(config, "Straße");
  const empty = await seed(config, "Straße empty", false);
  await seed(config, "STRASSE");
  const { code, lease } = await issued(config, 1, "STRaße");
  assert.deepEqual(await action(config, 1), { result: "issued", codeSha256: createHash("sha256").update(code).digest("hex"),
    marker: TELEGRAM_SELECTED_MARKER });
  const stored = await db.prepare("SELECT selected_ids AS ids FROM aggregate_links WHERE code_sha256=?")
    .bind(lease.selected!.codeSha256).first<string>("ids");
  assert.equal(stored, JSON.stringify([first.id, empty.id]));
  await seed(config, "Straße later");
  assert.equal(await publishNodeSnapshot(db, bucket, { id: empty.id, ownerId: config.memberId, expectedGeneration: 0,
    expectedLifecycleRevision: 0 }, [{ share: share + "#empty-now-ready" }]), true);
  const source = await getAggregateNodeSource(db, bucket, code);
  assert.ok(source);
  const rows = [];
  for await (const node of source.read()) rows.push(node.share);
  assert.deepEqual(rows, [share + "#Stra%C3%9Fe", share + "#empty-now-ready"]);
  const durable = await db.prepare("SELECT * FROM telegram_selected_links WHERE bot_id=?").bind(config.botId).all();
  assert.doesNotMatch(JSON.stringify(durable.results), /STRaße|provider\.example|ss:\/\//u);
});

test("replayed update creates one independent link and never changes a different selected capability", async () => {
  const config = policy("02");
  await seed(config, "replay");
  const first = await issued(config, 1);
  assert.equal(await acceptTelegramSelected(db, config, event(config, 1), key), "ignored");
  const second = await issued(config, 2);
  assert.notEqual(first.code, second.code);
  assert.equal(await hasAggregateLink(db, first.code), true);
  assert.equal(await hasAggregateLink(db, second.code), true);
  assert.equal(await db.prepare("SELECT count(*) AS n FROM telegram_selected_links WHERE bot_id=?")
    .bind(config.botId).first<number>("n"), 2);
});

test("no match, empty cache, malformed query and selection overflow are explicit and never mint partial links", async () => {
  const config = policy("03");
  await seed(config, "empty", false);
  for (const [update, query, result] of [[1, "missing", "nomatch"], [2, "empty", "empty"], [3, "x".repeat(257), "limit"]] as const) {
    assert.equal(await acceptTelegramSelected(db, config, event(config, update, query), key), "accepted");
    assert.equal((await action(config, update))?.result, result);
  }
  for (let index = 0; index < 128; index += 1) {
    await createSubscription(db, { ownerId: config.memberId, name: `another-${index}`, sourceUrl: "https://example.invalid/" });
  }
  assert.equal(await acceptTelegramSelected(db, config, event(config, 4), key), "accepted");
  assert.equal((await action(config, 4))?.result, "limit");
  assert.equal(await db.prepare("SELECT count(*) AS n FROM telegram_selected_links WHERE bot_id=?")
    .bind(config.botId).first<number>("n"), 0);
});

test("entire inventory CAS rejects a concurrent rename of a previously nonmatching row", async () => {
  const config = policy("04");
  await seed(config, "hit");
  const other = await seed(config, "other");
  const changing = {
    prepare: (sql: string) => db.prepare(sql),
    batch: async (statements: D1PreparedStatement[]) => {
      assert.equal(await renameOwnedSubscription(db,
        { id: other.id, ownerId: config.memberId, expectedLifecycleRevision: 0 }, "hit-too"), true);
      return db.batch(statements);
    },
  } as D1Database;
  assert.equal(await acceptTelegramSelected(changing, config, event(config, 1, "hit"), key), "accepted");
  assert.equal((await action(config, 1))?.result, "stale");
  assert.equal(await db.prepare("SELECT count(*) AS n FROM aggregate_links WHERE owner_id=?")
    .bind(config.memberId).first<number>("n"), 0);
});

test("inventory admission rejects create, trash and restore changes across the metadata scan", async () => {
  for (const [suffix, kind] of [["09", "create"], ["10", "trash"], ["11", "restore"]] as const) {
    const config = policy(suffix);
    await seed(config, "hit");
    const other = await seed(config, "other");
    if (kind === "restore") {
      assert.equal(await trashOwnedSubscription(db,
        { id: other.id, ownerId: config.memberId, expectedLifecycleRevision: 0 }), true);
    }
    const changing = {
      prepare: (sql: string) => db.prepare(sql),
      batch: async (statements: D1PreparedStatement[]) => {
        if (kind === "create") await seed(config, "newly-created");
        else if (kind === "trash") {
          assert.equal(await trashOwnedSubscription(db,
            { id: other.id, ownerId: config.memberId, expectedLifecycleRevision: 0 }), true);
        } else {
          assert.equal(await restoreOwnedSubscription(db,
            { id: other.id, ownerId: config.memberId, expectedLifecycleRevision: 1 }), true);
        }
        return db.batch(statements);
      },
    } as D1Database;
    assert.equal(await acceptTelegramSelected(changing, config, event(config, 1, "hit"), key), "accepted");
    assert.equal((await action(config, 1))?.result, "stale");
  }
});

test("owner scan overflow returns limit even if the unfinished scan has no matches", async () => {
  const config = policy("12");
  for (let start = 0; start < 513; start += 64) {
    const statements = [];
    for (let index = start; index < Math.min(start + 64, 513); index += 1) {
      statements.push(db.prepare(`INSERT INTO subscriptions
        (owner_id,name,source_url,token,created_at,updated_at) VALUES (?,'unmatched','https://example.invalid/',?,unixepoch(),unixepoch())
      `).bind(config.memberId, `selected-scan-fixture-${index}`));
    }
    await db.batch(statements);
  }
  assert.equal(await acceptTelegramSelected(db, config, event(config, 1, "missing"), key), "accepted");
  assert.equal((await action(config, 1))?.result, "limit");
  assert.equal(await db.prepare("SELECT count(*) AS n FROM aggregate_links WHERE owner_id=?")
    .bind(config.memberId).first<number>("n"), 0);
});

test("a snapshot generation or authorization epoch change fences the final link send", async () => {
  const config = policy("05");
  const row = await seed(config, "generation");
  assert.equal(await acceptTelegramSelected(db, config, event(config, 1), key), "accepted");
  const lease = await claimTelegramReply(db, config.botId, true);
  assert.ok(lease?.selected);
  const scope = { ...lease, selected: lease.selected };
  const code = await resolveTelegramSelectedCode(db, config, scope, key);
  assert.ok(code);
  assert.equal(await publishNodeSnapshot(db, bucket, { id: row.id, ownerId: config.memberId, expectedGeneration: 1,
    expectedLifecycleRevision: 0 }, [{ share: share + "#new-generation" }]), true);
  assert.equal(await resolveTelegramSelectedCode(db, config, scope, key), null);
  const ticket = { ...await prepareSelectedRevokeTicket(), codeSha256: lease.selected.codeSha256! };
  assert.equal(await beginTelegramSelectedLinkReply(db, config, lease, [ticket]), false);
  assert.equal(await retireUnsentSelectedLink(db, config, lease, "leased"), true);
  assert.equal(await hasAggregateLink(db, code), false);
  assert.equal((await action(config, 1))?.result, "stale");
  await db.prepare("INSERT INTO telegram_auth VALUES (?,?,1,?,100)").bind(config.botId, config.memberId, date).run();
  assert.equal(await acceptTelegramSelected(db, config, event(config, 2), key), "accepted");
  assert.equal((await action(config, 2))?.result, "stale");
});

test("selected quota is reclaimed only by an exact actor/bot/private sent-message revoke ticket", async () => {
  const config = policy("06");
  await seed(config, "quota");
  const first = await issued(config, 1);
  for (let index = 2; index <= MAX_SELECTED_LINKS; index += 1) {
    assert.equal(await acceptTelegramSelected(db, config, event(config, index), key), "accepted");
  }
  assert.equal(await acceptTelegramSelected(db, config, event(config, 50), key), "accepted");
  assert.equal((await action(config, 50))?.result, "limit");
  for (const invalid of [
    { ...revoke(config, 51, first.ticket.token), actorId: config.adminId, chatId: config.adminId },
    { ...revoke(config, 52, first.ticket.token), chatType: "group" as const, chatId: config.groupId },
    revoke(config, 53, first.ticket.token, 999),
  ]) assert.equal(await acceptTelegramSelected(db, config, invalid, key), "ignored");
  assert.equal(await hasAggregateLink(db, first.code), true);
  await db.prepare("UPDATE telegram_selected_revoke_ticket SET expires_at=unixepoch()-1 WHERE token_sha256=?")
    .bind(first.ticket.sha256).run();
  assert.equal(await acceptTelegramSelected(db, config, revoke(config, 54, first.ticket.token), key), "ignored");
  const sent: Array<{ text: string; reply_markup?: { inline_keyboard: Array<Array<{ callback_data: string }>> } }> = [];
  const request: typeof fetch = async (_input, init) => {
    sent.push(JSON.parse(String(init?.body)));
    return Response.json({ ok: true, result: { message_id: 1000 + sent.length, chat: { id: Number(config.memberId) } } });
  };
  await drainTelegramReplies(db, bucket, config, 40, 60_000, request, key);
  const management = sent.at(-1);
  assert.match(management!.text, /上限/u);
  assert.equal(management?.reply_markup?.inline_keyboard.length, MAX_SELECTED_LINKS);
  const freshTicket = management!.reply_markup!.inline_keyboard.at(-1)![0].callback_data;
  assert.equal(await acceptTelegramSelected(db, config, revoke(config, 55, freshTicket, 1000 + sent.length), key), "accepted");
  assert.equal((await action(config, 55))?.result, "revoked");
  assert.equal(await hasAggregateLink(db, first.code), false);
  assert.equal(await acceptTelegramSelected(db, config, revoke(config, 56, freshTicket, 1000 + sent.length), key), "ignored");
  assert.equal(await acceptTelegramSelected(db, config, event(config, 57), key), "accepted");
  assert.equal((await action(config, 57))?.result, "issued");
});

test("a prepared limit revoke list cannot commit sending or partial tickets after a concurrent accepted revoke", async () => {
  const config = policy("14");
  await seed(config, "limit-race");
  const first = await issued(config, 1);
  await issued(config, 2);
  assert.equal(await acceptTelegramSelected(db, config, event(config, 3, "x".repeat(257)), key), "accepted");
  const lease = await claimTelegramReply(db, config.botId, true);
  assert.equal(lease?.selected?.result, "limit");
  assert.ok(lease);
  const prepared = await prepareSelectedLimitTickets(db, config, config.memberId);
  assert.equal(prepared.length, 2);
  assert.equal(await acceptTelegramSelected(db, config, revoke(config, 4, first.ticket.token), key), "accepted");
  assert.equal(await hasAggregateLink(db, first.code), false);

  assert.equal(await beginTelegramSelectedLinkReply(db, config, lease, prepared), false);
  assert.equal(await db.prepare("SELECT state FROM telegram_outbox WHERE receipt_id=?")
    .bind(lease.receiptId).first<string>("state"), "leased");
  assert.equal(await db.prepare("SELECT count(*) AS n FROM telegram_selected_revoke_ticket WHERE origin_receipt_id=?")
    .bind(lease.receiptId).first<number>("n"), 0);

  const fresh = await prepareSelectedLimitTickets(db, config, config.memberId);
  assert.equal(fresh.length, 1);
  assert.equal(await beginTelegramSelectedLinkReply(db, config, lease, fresh), true);
  assert.equal(await beginTelegramSelectedLinkReply(db, config, lease, fresh), false);
  assert.equal(await db.prepare("SELECT count(*) AS n FROM telegram_selected_revoke_ticket WHERE origin_receipt_id=?")
    .bind(lease.receiptId).first<number>("n"), 1);
  await settleTelegramReply(db, config, lease, { kind: "sent", messageId: 703 });
});

test("SQLite failure rolls back the selected receipt and capability, and a bad ticket rolls back begin", async () => {
  const config = policy("07");
  await seed(config, "rollback");
  const broken = {
    prepare: (sql: string) => db.prepare(sql),
    batch: (statements: D1PreparedStatement[]) => db.batch([
      ...statements,
      db.prepare("INSERT INTO telegram_selected_actions(receipt_id,result,auth_message_date,auth_message_id) VALUES (-1,'invalid',0,0)"),
    ]),
  } as D1Database;
  await assert.rejects(acceptTelegramSelected(broken, config, event(config, 1, "rollback"), key),
    /Selected export receipt could not be confirmed/u);
  assert.equal(await action(config, 1), null);
  assert.equal(await db.prepare("SELECT count(*) AS n FROM aggregate_links WHERE owner_id=?")
    .bind(config.memberId).first<number>("n"), 0);
  await acceptTelegramSelected(db, config, event(config, 2), key);
  const lease = await claimTelegramReply(db, config.botId, true);
  assert.ok(lease?.selected);
  await assert.rejects(beginTelegramSelectedLinkReply(db, config, lease,
    [{ token: "unused", sha256: "invalid-digest", codeSha256: lease.selected.codeSha256! }]));
  assert.equal(await db.prepare("SELECT state FROM telegram_outbox WHERE receipt_id=?")
    .bind(lease.receiptId).first<string>("state"), "leased");
});

test("uncertain sends retain their capability while expired unsent receipts release quota", async () => {
  const config = policy("13");
  await seed(config, "recovery");
  await acceptTelegramSelected(db, config, event(config, 1), key);
  const lease = await claimTelegramReply(db, config.botId, true);
  assert.ok(lease?.selected);
  const code = await resolveTelegramSelectedCode(db, config, { ...lease, selected: lease.selected }, key);
  assert.ok(code);
  const ticket = { ...await prepareSelectedRevokeTicket(), codeSha256: lease.selected.codeSha256! };
  assert.equal(await beginTelegramSelectedLinkReply(db, config, lease, [ticket]), true);
  await settleTelegramReply(db, config, lease, { kind: "uncertain" });
  await acceptTelegramSelected(db, config, event(config, 2), key);
  const second = await action(config, 2);
  await db.prepare("UPDATE telegram_inbox SET received_at=unixepoch()-901 WHERE bot_id=? AND update_id=2")
    .bind(config.botId).run();
  await reapExpiredTelegramReplies(db, config.botId, true);
  await reapTelegramSelected(db);
  assert.equal(await hasAggregateLink(db, code), true);
  assert.equal(await db.prepare("SELECT revoked_at IS NOT NULL AS revoked FROM aggregate_links WHERE code_sha256=?")
    .bind(second!.codeSha256).first<number>("revoked"), 1);
  assert.equal(await claimTelegramReply(db, config.botId, true), null);
});

test("the normal webhook issues only private selected subscriptions and serves/revokes their existing HTTP exports", { timeout: 60_000 }, async () => {
  const built = await build({ entryPoints: [fileURLToPath(new URL("../src/index.ts", import.meta.url))], bundle: true,
    format: "esm", platform: "browser", target: "es2022", write: false });
  const config = policy("08");
  const sent: Array<{ text: string; chat_id: string; reply_markup?: { inline_keyboard: Array<Array<{ callback_data: string }>> } }> = [];
  const worker = new Miniflare({
    modules: true, script: built.outputFiles[0].text, compatibilityDate: "2026-07-30", d1Databases: ["DB"], r2Buckets: ["NODES"],
    bindings: { BUILD_REVISION: "a".repeat(40), TELEGRAM_ISOLATION_CONFIG: JSON.stringify(config), TELEGRAM_AGGREGATE_KEY: encodedKey },
    outboundService: async (request: Request) => {
      if (request.url.endsWith("/answerCallbackQuery")) return Response.json({ ok: true, result: true });
      assert.equal(request.url, `https://api.telegram.org/bot${config.botToken}/sendMessage`);
      const body = await request.json() as typeof sent[number];
      assert.equal(body.chat_id, config.memberId);
      sent.push(body);
      return Response.json({ ok: true, result: { message_id: 1000 + sent.length, chat: { id: Number(body.chat_id) } } });
    },
  });
  try {
    const database = await worker.getD1Database("DB");
    const nodes = await worker.getR2Bucket("NODES");
    await migrate(database);
    await seed(config, "Straße", true, database, nodes);
    await seed(config, "STRASSE", true, database, nodes);
    const post = (update_id: number, message: unknown) => worker.dispatchFetch("https://fixture.invalid/telegram/webhook", {
      method: "POST", headers: { "Content-Type": "application/json", "X-Telegram-Bot-Api-Secret-Token": config.webhookSecret },
      body: JSON.stringify({ update_id, message }),
    });
    const message = (text: string, group = false) => ({
      message_id: 11, date, from: { id: Number(config.memberId), is_bot: false },
      chat: { id: Number(group ? config.groupId : config.memberId), type: group ? "group" : "private" }, text,
      entities: [{ type: "bot_command", offset: 0, length: 2 }],
    });
    assert.equal((await post(1, message("/o Straße", true))).status, 204);
    assert.equal((await post(2, message("/o Straße"))).status, 200);
    for (let attempt = 0; attempt < 50 && sent.length === 0; attempt += 1) {
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    assert.equal(sent.length, 1);
    const url = sent[0].text.match(/https:\/\/[^\s]+\/clash/u)?.[0];
    assert.ok(url?.startsWith(TELEGRAM_AGGREGATE_ORIGIN + "/agg/"));
    const response = await worker.dispatchFetch(url.replace(/clash$/u, "base64"));
    assert.equal(response.status, 200);
    assert.equal(await response.text(), Buffer.from(share + "#Stra%C3%9Fe").toString("base64"));
    assert.equal(response.headers.get("Cache-Control"), "private, no-store");
    const ticket = sent[0].reply_markup?.inline_keyboard[0][0].callback_data;
    assert.match(ticket!, /^sbo1_[A-Za-z0-9_-]{22}$/u);
    const callback = {
      id: "synthetic-callback", from: { id: Number(config.memberId), is_bot: false }, data: ticket,
      message: { message_id: 1001, date, from: { id: Number(config.botId), is_bot: true },
        chat: { id: Number(config.memberId), type: "private" } },
    };
    assert.equal((await worker.dispatchFetch("https://fixture.invalid/telegram/webhook", {
      method: "POST", headers: { "Content-Type": "application/json", "X-Telegram-Bot-Api-Secret-Token": config.webhookSecret },
      body: JSON.stringify({ update_id: 3, callback_query: callback }),
    })).status, 200);
    assert.equal((await worker.dispatchFetch(url, { method: "HEAD" })).status, 404);
  } finally {
    await worker.dispose();
  }
});
