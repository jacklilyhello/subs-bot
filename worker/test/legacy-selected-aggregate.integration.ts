import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { Miniflare } from "miniflare";
import { createSubscription, publishNodeSnapshot } from "../src/storage.ts";
import { restoreOwnedSubscription, trashOwnedSubscription } from "../src/subscriptions.ts";

const sha = (value: string | Buffer) => createHash("sha256").update(value).digest("hex");
const code = (value: number) => `legacy_${String(value).padStart(5, "0")}`;
const share = (name: string) => `ss://YWVzLTI1Ni1nY206Zml4dHVyZQ@203.0.113.10:8388#${name}`;
const owner = "87102";
const missingId = 9000;
const absentId = 9001;

test("emitted marked selected exports preserve legacy order, empty framing and permanent retirement", { timeout: 90_000 }, async () => {
  const directory = process.env.WORKER_TEST_BUNDLE_DIR;
  assert.ok(directory);
  const manifest = JSON.parse(await readFile(join(directory, "isolation.json"), "utf8"));
  const script = await readFile(join(directory, "index.js"));
  assert.equal(sha(script), manifest.bundleSha256);
  const runtime = new Miniflare({ modules: true, script: script.toString("utf8"), compatibilityDate: manifest.compatibilityDate,
    d1Databases: ["DB"], r2Buckets: ["NODES"], bindings: { BUILD_REVISION: manifest.revision } });
  try {
    const db = await runtime.getD1Database("DB");
    const bucket = await runtime.getR2Bucket("NODES");
    const migrations = manifest.migrations as { name: string; sha256: string }[];
    const retirement = migrations.find(({ name }) => name === "0038_legacy_selected_aggregates.sql");
    const emptyMigration = migrations.find(({ name }) => name === "0026_legacy_empty_subscription_exports.sql");
    assert.ok(retirement && emptyMigration);
    async function apply(migration: (typeof migrations)[number]) {
      const bytes = await readFile(join(directory!, migration.name));
      assert.equal(sha(bytes), migration.sha256);
      await db.batch(bytes.toString("utf8").trim().split(/;\s*/u).filter(Boolean).map((sql) => db.prepare(sql)));
    }
    for (const migration of migrations.slice(0, migrations.indexOf(retirement))) await apply(migration);

    async function seed(name: string, published = false, ownerId = owner) {
      const sub = await createSubscription(db, { ownerId, name, sourceUrl: "uploaded://legacy-selected-fixture" });
      if (published) assert.equal(await publishNodeSnapshot(db, bucket,
        { id: sub.id, ownerId, expectedGeneration: 0, expectedLifecycleRevision: 0 },
        [{ name, type: "ss", server: "203.0.113.10", port: 8388, cipher: "aes-256-gcm", password: "fixture", share: share(name) }]), true);
      return sub;
    }
    const first = await seed("first", true);
    const second = await seed("second", true);
    const empty = await seed("verified-empty");
    const unpublished = await seed("unpublished");
    const foreign = await seed("foreign", true, "87103");
    const unwatched = await seed("unwatched", true);
    const ordinary = code(1);
    const ordinaryEmpty = code(2);
    const marked = code(3);
    const markedEmpty = code(4);
    const markedForTypeCollision = code(5);
    const normalLength = `new_${"A".repeat(18)}`;
    const path = (bearer: string, format = "base64") => `/agg/${bearer}/${format}`;
    const request = (resource: string, method = "GET") => runtime.dispatchFetch(`https://aggregate.fixture.invalid${resource}`, {
      method, redirect: "manual", headers: { "Accept-Encoding": "identity" },
    });
    async function link(bearer: string, ids: number[], legacy = false) {
      const steps = [db.prepare(`INSERT INTO aggregate_links (code_sha256,owner_id,kind,selected_ids) VALUES (?,?,'selected',?)`)
        .bind(sha(bearer), owner, JSON.stringify(ids))];
      if (legacy) steps.push(db.prepare("INSERT INTO legacy_selected_aggregates VALUES (?)").bind(sha(bearer)));
      await db.batch(steps);
    }
    async function redirect(bearer: string, status: number) {
      for (const method of ["GET", "HEAD"]) {
        const response = await request(`/s/${bearer}`, method);
        assert.equal(response.status, status);
        assert.equal(response.headers.get("Location"), status === 302 ? path(bearer, "clash") : null);
        if (status === 302) assert.equal(await response.text(), "");
      }
    }
    async function exportBytes(bearer: string, kind: string, type: string, body: string) {
      const get = await request(path(bearer, kind));
      assert.equal(get.status, 200);
      assert.equal(get.headers.get("Content-Type"), type);
      assert.equal(get.headers.get("Cache-Control"), "private, no-store");
      assert.equal(get.headers.get("Referrer-Policy"), "no-referrer");
      if (body) assert.equal(get.headers.get("Content-Length"), String(Buffer.byteLength(body)));
      assert.equal(await get.text(), body);
      const head = await request(path(bearer, kind), "HEAD");
      assert.equal(head.status, 200);
      assert.equal(head.headers.get("Content-Type"), type);
      assert.equal(head.headers.get("Content-Length"), body ? String(Buffer.byteLength(body)) : null);
      assert.equal(await head.text(), "");
    }
    const encode = (...names: string[]) => Buffer.from(names.map(share).join("\n")).toString("base64");

    await link(ordinary, [second.id, first.id]);
    await link(ordinaryEmpty, [unpublished.id]);
    await link(normalLength, [second.id, first.id]);
    await redirect(ordinary, 302);
    assert.equal(await (await request(path(ordinary))).text(), encode("second", "first"));
    assert.equal((await request(path(ordinaryEmpty))).status, 404);
    assert.equal((await request(path(ordinary, "unknown-format"))).status, 406);

    await apply(retirement);
    await db.batch([
      db.prepare("CREATE TABLE subs_bot_schema_migrations(position INTEGER PRIMARY KEY,name TEXT,sha256 TEXT,mode TEXT) STRICT"),
      db.prepare("INSERT INTO subs_bot_schema_migrations VALUES (26,?,?,'applied'),(38,?,?,'applied')")
        .bind(emptyMigration.name, emptyMigration.sha256, retirement.name, "0".repeat(64)),
      db.prepare("INSERT INTO legacy_empty_subscription_exports VALUES (?,?,?)").bind(empty.id, owner, sha(empty.token)),
      db.prepare("INSERT INTO legacy_selected_members VALUES (?,0),(?,0),(?,0),(?,0),(?,0),(?,0),(?,1)")
        .bind(first.id, second.id, empty.id, unpublished.id, foreign.id, missingId, absentId),
    ]);
    await link(marked, [second.id, absentId, first.id, second.id, empty.id], true);
    await link(markedEmpty, [absentId, empty.id], true);
    await link(markedForTypeCollision, [absentId], true);
    await redirect(marked, 404);
    assert.equal((await request(path(marked))).status, 404);
    assert.equal(await (await request(path(ordinary))).text(), encode("second", "first"));
    await db.prepare("UPDATE subs_bot_schema_migrations SET sha256=? WHERE position=38").bind(retirement.sha256).run();
    await redirect(marked, 302);
    await redirect(markedEmpty, 302);
    await exportBytes(marked, "base64", "text/plain; charset=utf-8", encode("second", "first", "second"));
    assert.equal((await request(path(normalLength, "unknown-format"))).status, 406);
    assert.equal((await request(path(ordinary, "unknown-format"))).status, 406);
    const clash = await request(path(marked, "clash"));
    const fallback = await request(path(marked, "unknown-format"));
    assert.equal(fallback.status, 200);
    assert.equal(fallback.headers.get("Content-Type"), "text/yaml; charset=utf-8");
    assert.equal(await fallback.text(), await clash.text());

    const emptyClash = `proxies: []
proxy-groups:
- name: 🚀 节点选择
  type: select
  proxies:
  - DIRECT
- name: ♻️ 自动选择
  type: url-test
  proxies:
  - DIRECT
  url: http://www.gstatic.com/generate_204
  interval: 300
rules:
- MATCH,🚀 节点选择
`;
    const emptySingBox = JSON.stringify({ outbounds: [
      { type: "selector", tag: "proxy", outbounds: ["direct"] }, { type: "direct", tag: "direct" },
    ] }, null, 2);
    for (const kind of ["base64", "v2ray", "mixed", "qx", "quantumult", "quantumultx"]) {
      await exportBytes(markedEmpty, kind, "text/plain; charset=utf-8", "");
    }
    for (const kind of ["clash", "unknown-format"]) await exportBytes(markedEmpty, kind, "text/yaml; charset=utf-8", emptyClash);
    for (const kind of ["singbox", "sing-box"]) await exportBytes(markedEmpty, kind, "application/json; charset=utf-8", emptySingBox);
    await exportBytes(markedEmpty, "surge", "text/plain; charset=utf-8", "[Proxy]\n\n[Proxy Group]\nProxy = select, DIRECT\n\n[Rule]\nFINAL,Proxy\n");

    for (const [index, id] of [unpublished.id, foreign.id, missingId, unwatched.id].entries()) {
      const bearer = code(10 + index);
      await link(bearer, [first.id, id], true);
      for (const method of ["GET", "HEAD"]) {
        assert.equal((await request(path(bearer), method)).status, 503);
        assert.equal((await request(path(bearer, "unknown-format"), method)).status, 406);
      }
    }
    const malformed = code(14);
    await link(malformed, [first.id], true);
    await db.prepare("UPDATE aggregate_links SET selected_ids=? WHERE code_sha256=?")
      .bind(JSON.stringify([String(first.id)]), sha(malformed)).run();
    assert.equal((await request(path(malformed))).status, 503);
    await db.prepare("UPDATE legacy_empty_subscription_exports SET token_sha256=? WHERE subscription_id=?")
      .bind("0".repeat(64), empty.id).run();
    assert.equal((await request(path(markedEmpty))).status, 503);
    await db.prepare("UPDATE legacy_empty_subscription_exports SET token_sha256=? WHERE subscription_id=?")
      .bind(sha(empty.token), empty.id).run();
    await db.prepare("UPDATE subs_bot_schema_migrations SET sha256=? WHERE position=26").bind("0".repeat(64)).run();
    assert.equal((await request(path(marked))).status, 503);
    await db.prepare("UPDATE subs_bot_schema_migrations SET sha256=? WHERE position=26").bind(emptyMigration.sha256).run();

    const target = { id: second.id, ownerId: owner, expectedLifecycleRevision: 0 };
    assert.equal(await trashOwnedSubscription(db, target), true);
    await exportBytes(marked, "base64", "text/plain; charset=utf-8", encode("first"));
    assert.equal(await restoreOwnedSubscription(db, { ...target, expectedLifecycleRevision: 1 }), true);
    await exportBytes(marked, "base64", "text/plain; charset=utf-8", encode("first"));
    assert.equal(await (await request(path(normalLength))).text(), encode("second", "first"));

    const firstSnapshot = await db.prepare("SELECT snapshot_id FROM subscriptions WHERE id=?").bind(first.id).first<string>("snapshot_id");
    assert.ok(firstSnapshot);
    await bucket.delete(`subscriptions/${first.id}/${firstSnapshot}/manifest.json`);
    assert.equal((await request(path(marked))).status, 503);

    await db.prepare(`INSERT INTO normal_short_links (code_sha256,code_length,bot_id,owner_id,created_at,revoked_at)
      VALUES (?,12,'87101',?,unixepoch(),unixepoch())`).bind(sha(markedEmpty), owner).run();
    await db.prepare(`INSERT INTO legacy_subscription_short_links
      (code_sha256,bot_id,owner_id,subscription_id,token_sha256,format,created_at)
      VALUES (?,'87101',?,?,?,'base64',unixepoch())`).bind(sha(markedForTypeCollision), owner, empty.id, sha(empty.token)).run();
    await db.prepare("UPDATE aggregate_links SET revoked_at=unixepoch() WHERE code_sha256=?").bind(sha(marked)).run();
    for (const bearer of [marked, markedEmpty, markedForTypeCollision, code(99)]) {
      await redirect(bearer, 404);
      assert.equal((await request(path(bearer))).status, 404);
      assert.equal((await request(path(bearer), "HEAD")).status, 404);
    }
  } finally {
    await runtime.dispose();
  }
});
