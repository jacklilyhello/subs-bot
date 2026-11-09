import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { networkInterfaces } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { Miniflare } from "miniflare";
import { createSubscription, getOwnedSubscription, publishNodeSnapshot } from "../src/storage.ts";
import { restoreOwnedSubscription, trashOwnedSubscription } from "../src/subscriptions.ts";
import type { TelegramPolicy } from "../src/telegram/protocol.ts";
import { acceptTelegramTemp } from "../src/telegram/temp-import.ts";

const owner = "74102";
const other = "74103";
const bot = "74101";
const code = "legacy_all01";
const modern = "modern_fixture_all_001";
const inventory = "a".repeat(64);
const digest = (value: string | Uint8Array) => createHash("sha256").update(value).digest("hex");
const share = (name: string) => `ss://YWVzLTI1Ni1nY206Zml4dHVyZQ@203.0.113.10:8388#${name}`;
const emptyKinds = ["base64", "v2ray", "mixed", "clash", "unknown-format", "singbox", "sing-box",
  "surge", "qx", "quantumult", "quantumultx"] as const;
type Wire = { media: string; bytes: number; sha256: string };
type Reference = { phases: Wire[]; empty: Record<(typeof emptyKinds)[number], Wire> };

test("emitted legacy all links follow Python export order across trash, restore and later adds", { timeout: 90_000 }, async () => {
  const directory = process.env.WORKER_TEST_BUNDLE_DIR;
  const python = process.env.SUBS_BOT_LEGACY_PYTHON;
  assert.ok(directory && python && process.platform === "linux" && process.getuid?.() !== 0);
  assert.deepEqual(Object.keys(networkInterfaces()), ["lo"]);
  const old = spawnSync(python, ["-B", fileURLToPath(new URL("./legacy-dynamic-all-python.py", import.meta.url))], {
    encoding: "utf8", timeout: 30_000, maxBuffer: 8192, env: { HOME: process.env.HOME, TMPDIR: process.env.TMPDIR },
  });
  assert.equal(old.status, 0, "offline Python lifecycle observation");
  const reference = JSON.parse(old.stdout) as Reference;
  assert.equal(reference.phases.length, 6);
  assert.deepEqual(Object.keys(reference.empty).sort(), [...emptyKinds].sort());

  const manifest = JSON.parse(await readFile(join(directory, "isolation.json"), "utf8"));
  const script = await readFile(join(directory, "index.js"));
  assert.equal(digest(script), manifest.bundleSha256);
  assert.equal(manifest.revision, process.env.WORKER_TEST_REVISION);
  const migrations = manifest.migrations as { name: string; sha256: string }[];
  assert.equal(migrations[39]?.name, "0040_legacy_all_aggregates.sql");
  const runtime = new Miniflare({ modules: true, script: script.toString("utf8"), compatibilityDate: manifest.compatibilityDate,
    d1Databases: ["DB"], r2Buckets: ["NODES"], bindings: { BUILD_REVISION: manifest.revision } });
  try {
    const db = await runtime.getD1Database("DB");
    const bucket = await runtime.getR2Bucket("NODES");
    for (const migration of migrations) {
      const bytes = await readFile(join(directory, migration.name));
      assert.equal(digest(bytes), migration.sha256);
      await db.batch(bytes.toString("utf8").trim().split(/;\s*/u).filter(Boolean).map((sql) => db.prepare(sql)));
    }
    await db.prepare(`CREATE TABLE subs_bot_schema_migrations (
      position INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, sha256 TEXT NOT NULL, mode TEXT NOT NULL,
      applied_at INTEGER NOT NULL DEFAULT (unixepoch())
    ) STRICT`).run();
    await db.batch(migrations.map(({ name, sha256 }, index) => db.prepare(
      "INSERT INTO subs_bot_schema_migrations(position,name,sha256,mode) VALUES (?,?,?,'applied')",
    ).bind(index + 1, name, sha256)));

    const request = (resource: string, method = "GET") => runtime.dispatchFetch(`https://legacy-all.fixture.invalid${resource}`, {
      method, redirect: "manual", headers: { "Accept-Encoding": "identity" },
    });
    async function wire(bearer: string, kind: string, expected: Wire) {
      const path = `/agg/${bearer}/${kind}`;
      const response = await request(path);
      assert.equal(response.status, 200, path);
      assert.equal(response.headers.get("Content-Type"), expected.media, path);
      assert.equal(response.headers.get("Cache-Control"), "private, no-store");
      assert.equal(response.headers.get("Referrer-Policy"), "no-referrer");
      const body = new Uint8Array(await response.arrayBuffer());
      assert.equal(body.length, expected.bytes, path);
      assert.equal(digest(body), expected.sha256, path);
      const head = await request(path, "HEAD");
      assert.equal(head.status, 200, path);
      assert.equal(head.headers.get("Content-Type"), expected.media, path);
      if (expected.bytes) assert.equal(head.headers.get("Content-Length"), String(expected.bytes), path);
      assert.equal((await head.arrayBuffer()).byteLength, 0);
    }
    const phase = (index: number) => wire(code, "base64", reference.phases[index]);
    async function seed(name: string, ownerId = owner) {
      const sub = await createSubscription(db, { ownerId, name, sourceUrl: "uploaded://legacy-all-fixture" });
      assert.equal(await publishNodeSnapshot(db, bucket,
        { id: sub.id, ownerId, expectedGeneration: 0, expectedLifecycleRevision: 0 },
        [{ name, type: "ss", server: "203.0.113.10", port: 8388, cipher: "aes-256-gcm", password: "fixture", share: share(name) }]), true);
      return { id: sub.id, ownerId, token: sub.token };
    }
    type Sub = Awaited<ReturnType<typeof seed>>;
    const remove = async (sub: Sub, revision: number) => assert.equal(
      await trashOwnedSubscription(db, { ...sub, expectedLifecycleRevision: revision }), true);
    async function restore(sub: Sub) {
      assert.equal(await restoreOwnedSubscription(db, { ...sub, expectedLifecycleRevision: 1 }), true);
      const restored = await getOwnedSubscription(db, owner, sub.id);
      assert.equal(restored?.token, sub.token);
      assert.equal(restored?.lifecycleRevision, 2);
    }
    const alpha = await seed("alpha");
    const beta = await seed("beta");
    const gamma = await seed("gamma");
    await seed("foreign-sub", other);

    const temp = (actorId: string, id: number, name: string) => {
      const json = JSON.stringify([{ name, share: share(name), type: "temp" }]);
      return db.prepare(`INSERT INTO legacy_temp_batches
        (bot_id,actor_id,first_legacy_id,last_legacy_id,nodes_json,node_count,payload_bytes,payload_sha256)
        VALUES (?,?,?,?,?,1,?,?)`).bind(bot, actorId, id, id, json, Buffer.byteLength(json), digest(json));
    };
    const link = (bearer: string) => db.prepare("INSERT INTO aggregate_links(code_sha256,owner_id,kind,bot_id) VALUES (?,?,'all',?)")
      .bind(digest(bearer), owner, bot);
    await db.batch([
      db.prepare("INSERT INTO legacy_temp_installations(bot_id,inventory_sha256,cutover_epoch) VALUES (?,?,NULL)").bind(bot, inventory),
      temp(owner, 1, "temporary"), temp(other, 2, "foreign-temp"),
      link(code), link(modern),
      db.prepare("INSERT INTO legacy_all_aggregates(code_sha256,bot_id,owner_id,inventory_sha256) VALUES (?,?,?,?)")
        .bind(digest(code), bot, owner, inventory),
    ]);
    assert.equal((await request(`/s/${code}`)).status, 404);
    assert.equal((await request(`/agg/${code}/base64`)).status, 404);
    await db.prepare("UPDATE legacy_temp_installations SET cutover_epoch=unixepoch()-60 WHERE bot_id=?").bind(bot).run();
    await phase(0);
    for (const method of ["GET", "HEAD"]) {
      const redirect = await request(`/s/${code}`, method);
      assert.equal(redirect.status, 302);
      assert.equal(redirect.headers.get("Location"), `/agg/${code}/clash`);
      assert.equal((await request(`/agg/${code}`, method)).status, 404);
    }
    await remove(alpha, 0);
    await remove(beta, 0);
    await phase(1);
    await restore(beta);
    await phase(2);
    await restore(alpha);
    await phase(3);
    const delta = await seed("delta");
    await phase(4);
    await remove(gamma, 0);
    await restore(gamma);
    await phase(5);
    for (const sub of [alpha, beta, delta, gamma]) await remove(sub, sub === delta ? 0 : 2);
    const policy: TelegramPolicy = { botId: bot, memberId: owner, adminId: other, groupId: "-10074104",
      botUsername: "fixture_legacy_all_bot", botToken: bot + ":synthetic-token", webhookSecret: "synthetic-legacy-all" };
    assert.equal(await acceptTelegramTemp(db, policy, { kind: "temp-clear", updateId: 1, messageId: 1,
      messageDate: Math.floor(Date.now() / 1000), chatType: "private", threadId: null, actorId: owner, chatId: owner }), "accepted");
    for (const kind of emptyKinds) await wire(code, kind, reference.empty[kind]);
    assert.equal((await request(`/agg/${modern}/base64`)).status, 404);
    assert.equal((await request(`/agg/${modern}/unknown-format`)).status, 406);
  } finally {
    await runtime.dispose();
  }
});
