import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import { Miniflare } from "miniflare";
import { beginProductionInvocation, fenceProductionDatabase, finishProductionInvocation, readProductionControl,
  productionUpdateDigest, readProductionUpdate, reserveProductionUpdate, settleProductionUpdate,
  PRODUCTION_CONTROL_MIGRATION, PRODUCTION_CONTROL_SHA256, PRODUCTION_UPDATES_MIGRATION,
  PRODUCTION_UPDATES_SHA256 } from "../src/production-control.ts";
import { parseGeneralTelegramPin } from "../src/telegram/general-auth-runtime.ts";

test("production admission transactions close while accepted workers finish and frozen runtimes cannot write", async (t) => {
  const runtime = new Miniflare({ modules: true, script: "export default {fetch(){return new Response(null)}}",
    compatibilityDate: "2026-07-30", d1Databases: ["DB"] });
  t.after(() => runtime.dispose());
  const db = await runtime.getD1Database("DB");
  const sql = await readFile(new URL(`../migrations/${PRODUCTION_CONTROL_MIGRATION}`, import.meta.url), "utf8");
  await db.batch(sql.trim().split(/;\s*/u).filter(Boolean).map((value) => db.prepare(value)));
  await db.prepare("CREATE TABLE subs_bot_schema_migrations(position INTEGER PRIMARY KEY,name TEXT,sha256 TEXT,mode TEXT)").run();
  await db.prepare("INSERT INTO subs_bot_schema_migrations VALUES(55,?,?,'applied')")
    .bind(PRODUCTION_CONTROL_MIGRATION, PRODUCTION_CONTROL_SHA256).run();
  await db.prepare("CREATE TABLE production_fixture(id INTEGER PRIMARY KEY,value TEXT)").run();
  const digest = "a".repeat(64), revision = "b".repeat(40);
  const pin = parseGeneralTelegramPin(JSON.stringify({ botId: "91001", botUsername: "ControlFixtureBot",
    botToken: "91001:synthetic-token", webhookSecret: "synthetic-hook", generation: 1, cutoverAt: 1,
    activationSha256: digest, outbox: "shared-private-management" }), revision);
  assert.ok(pin);
  await assert.rejects(readProductionControl(db, digest, pin));
  await db.prepare("INSERT INTO subs_bot_production_control VALUES(1,?,?,?,1,1,'closed','run')")
    .bind(digest, pin.botId, revision).run();
  const closed = await readProductionControl(db, digest, pin);
  await assert.rejects(beginProductionInvocation(db, closed, "webhook"));
  assert.equal(await db.prepare("SELECT count(*) AS n FROM subs_bot_production_invocations").first("n"), 0);
  for (const [target, otherPin] of [["c".repeat(64), pin], [digest, { ...pin, botId: "91002" }],
    [digest, { ...pin, releaseRevision: "d".repeat(40) }], [digest, { ...pin, generation: 2 }]] as const) {
    await assert.rejects(readProductionControl(db, target, otherPin));
  }
  await db.prepare("UPDATE subs_bot_production_control SET admission='open',epoch=2").run();
  const control = await readProductionControl(db, digest, pin);
  const invocation = await beginProductionInvocation(db, control, "webhook");
  const admission = fenceProductionDatabase(db, invocation);
  const work = fenceProductionDatabase(db, { ...invocation, kind: "scheduled" });
  await admission.prepare("INSERT INTO production_fixture VALUES(1,'durably accepted')").run();
  const stale = admission.prepare("INSERT INTO production_fixture VALUES(2,'must roll back')");
  await db.prepare("UPDATE subs_bot_production_control SET admission='closed',epoch=3").run();
  await assert.rejects(admission.batch([stale, admission.prepare("UPDATE production_fixture SET value='must roll back' WHERE id=1")]));
  assert.deepEqual((await db.prepare("SELECT * FROM production_fixture").all()).results,
    [{ id: 1, value: "durably accepted" }]);
  await work.prepare("UPDATE production_fixture SET value='accepted work completed' WHERE id=1").run();
  assert.equal(await db.prepare("SELECT count(*) AS n FROM subs_bot_production_invocations WHERE state<>'finished'").first("n"), 1);
  await finishProductionInvocation(db, invocation, true);
  await assert.rejects(finishProductionInvocation(db, invocation, true), "a repeated completion is not silently accepted");
  assert.equal(await db.prepare("SELECT state FROM subs_bot_production_invocations").first("state"), "finished");
  const cron = await beginProductionInvocation(db, await readProductionControl(db, digest, pin), "scheduled");
  await db.prepare("UPDATE subs_bot_production_control SET workers='frozen',epoch=4").run();
  await assert.rejects(fenceProductionDatabase(db, cron).prepare("INSERT INTO production_fixture VALUES(3,'frozen')").run());
  await assert.rejects(beginProductionInvocation(db, await readProductionControl(db, digest, pin), "scheduled"));
  await finishProductionInvocation(db, cron, false);
  assert.equal(await db.prepare("SELECT count(*) AS n FROM subs_bot_production_invocations WHERE state='uncertain'").first("n"), 1);
  await db.prepare("UPDATE subs_bot_production_control SET workers='run',epoch=5").run();
  const expired = await beginProductionInvocation(db, await readProductionControl(db, digest, pin), "scheduled");
  await db.prepare("UPDATE subs_bot_production_invocations SET lease_until=unixepoch()-1 WHERE invocation_id=?").bind(expired.id).run();
  await assert.rejects(fenceProductionDatabase(db, expired).prepare("INSERT INTO production_fixture VALUES(4,'expired')").run());
  await finishProductionInvocation(db, expired, true);
  assert.equal(await db.prepare("SELECT count(*) AS n FROM subs_bot_production_invocations WHERE state='uncertain'").first("n"), 2);
  assert.equal(await db.prepare("SELECT count(*) AS n FROM production_fixture").first("n"), 1);
});

test("production update reservations serialize retries, retain ignored dispositions and preserve interrupted work", async (t) => {
  const runtime = new Miniflare({ modules: true, script: "export default {fetch(){return new Response(null)}}",
    compatibilityDate: "2026-07-30", d1Databases: ["DB"] });
  t.after(() => runtime.dispose());
  const db = await runtime.getD1Database("DB");
  await db.prepare("CREATE TABLE subs_bot_schema_migrations(position INTEGER PRIMARY KEY,name TEXT,sha256 TEXT,mode TEXT)").run();
  for (const [position, name, sha] of [[55, PRODUCTION_CONTROL_MIGRATION, PRODUCTION_CONTROL_SHA256],
    [56, PRODUCTION_UPDATES_MIGRATION, PRODUCTION_UPDATES_SHA256]] as const) {
    const sql = await readFile(new URL(`../migrations/${name}`, import.meta.url), "utf8");
    await db.batch(sql.trim().split(/;\s*/u).filter(Boolean).map((value) => db.prepare(value)));
    await db.prepare("INSERT INTO subs_bot_schema_migrations VALUES(?,?,?,'applied')").bind(position, name, sha).run();
  }
  const digest = "a".repeat(64), revision = "b".repeat(40);
  const pin = parseGeneralTelegramPin(JSON.stringify({ botId: "93001", botUsername: "UpdateFixtureBot",
    botToken: "93001:synthetic-token", webhookSecret: "synthetic-hook", generation: 1, cutoverAt: 1,
    activationSha256: digest, outbox: "shared-private-management" }), revision);
  assert.ok(pin);
  await db.prepare("INSERT INTO subs_bot_production_control VALUES(1,?,?,?,1,1,'open','run')")
    .bind(digest, pin.botId, revision).run();
  const control = await readProductionControl(db, digest, pin);
  const update = { update_id: 1, message: { date: 100, text: "/unknown" } };
  const payloadSha = await productionUpdateDigest(update);
  assert.equal(payloadSha, await productionUpdateDigest({ message: { text: "/unknown", date: 100 }, update_id: 1 }));
  assert.notEqual(payloadSha, await productionUpdateDigest({ ...update, update_id: 2 }));
  const first = await beginProductionInvocation(db, control, "webhook");
  const second = await beginProductionInvocation(db, control, "webhook");
  assert.equal(await readProductionUpdate(db, control, 1), null);
  assert.equal(await reserveProductionUpdate(db, first, 1, payloadSha), true);
  assert.equal(await reserveProductionUpdate(db, second, 1, payloadSha), false, "a concurrent delivery cannot own the processing update");
  assert.equal(await reserveProductionUpdate(db, second, 1, "f".repeat(64)), false, "a changed payload cannot replace the original digest");
  await settleProductionUpdate(db, first, 1, payloadSha, 503);
  await finishProductionInvocation(db, first, true);
  assert.equal((await readProductionUpdate(db, control, 1))?.state, "retryable");
  assert.equal(await reserveProductionUpdate(db, second, 1, payloadSha), true);
  await settleProductionUpdate(db, second, 1, payloadSha, 204);
  await finishProductionInvocation(db, second, true);
  const completed = await readProductionUpdate(db, control, 1);
  assert.equal(completed?.state, "completed");
  assert.equal(completed?.httpStatus, 204, "an ignored authenticated update has a durable disposition before acknowledgment");
  assert.equal(completed?.payloadSha256, payloadSha);
  const interrupted = await beginProductionInvocation(db, control, "webhook");
  assert.equal(await reserveProductionUpdate(db, interrupted, 2, "e".repeat(64)), true);
  await finishProductionInvocation(db, interrupted, false);
  const retry = await beginProductionInvocation(db, control, "webhook");
  assert.equal(await reserveProductionUpdate(db, retry, 2, "e".repeat(64)), false, "an interrupted processing update is not automatically overwritten");
  await finishProductionInvocation(db, retry, true);
  assert.equal((await readProductionUpdate(db, control, 2))?.state, "processing");
  assert.equal(await db.prepare("SELECT count(*) AS n FROM subs_bot_production_updates WHERE state='processing'").first("n"), 1);
  // The protected control tool can classify an ended invocation. The runtime
  // must retain that uncertainty and must not acquire ownership for a resend.
  await db.prepare("UPDATE subs_bot_production_updates SET state='uncertain' WHERE update_id=2").run();
  const afterClassification = await beginProductionInvocation(db, control, "webhook");
  assert.equal(await reserveProductionUpdate(db, afterClassification, 2, "e".repeat(64)), false);
  await finishProductionInvocation(db, afterClassification, true);
  assert.equal((await readProductionUpdate(db, control, 2))?.state, "uncertain");
  assert.equal((await readProductionUpdate(db, control, 2))?.httpStatus, null);
  assert.equal(await db.prepare("SELECT count(*) AS n FROM subs_bot_production_updates WHERE state='processing'").first("n"), 0);
  assert.equal(await db.prepare("SELECT count(*) AS n FROM subs_bot_production_updates WHERE state='uncertain'").first("n"), 1);
  const racedPause = await beginProductionInvocation(db, control, "webhook");
  await db.prepare("UPDATE subs_bot_production_control SET admission='closed',epoch=2").run();
  await assert.rejects(reserveProductionUpdate(db, racedPause, 3, "d".repeat(64)));
  await finishProductionInvocation(db, racedPause, true);
  assert.equal(await readProductionUpdate(db, control, 3), null);
});
