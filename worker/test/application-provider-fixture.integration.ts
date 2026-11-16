import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { Miniflare } from "miniflare";

import { runOneProviderJob } from "../src/provider-job-consumer.ts";
import { enqueueProviderUrlImport, enqueueOwnedProviderRefresh } from "../src/provider-jobs.ts";
import { getOwnedSubscription } from "../src/storage.ts";
import { recordTempFixtureMigration } from "./temp-migration-fixture.ts";

const digest = (body: Uint8Array) => createHash("sha256").update(body).digest("hex");

test("the exact CI three-node source survives actual Provider parsing, refresh and emitted Base64 export",
  { timeout: 60_000 }, async (t) => {
    const directory = process.env.WORKER_TEST_BUNDLE_DIR;
    assert.ok(directory);
    const manifest = JSON.parse(await readFile(join(directory, "isolation.json"), "utf8"));
    const script = await readFile(join(directory, "index.js"));
    assert.equal(digest(script), manifest.bundleSha256);
    const snapshot = manifest.snapshots[0];
    assert.equal(snapshot.id, 1);
    assert.equal(snapshot.nodeCount, 3);
    const shares: string[] = [];
    for (const object of snapshot.objects) {
      const body = await readFile(join(directory, object.file));
      assert.equal(body.length, object.bytes);
      assert.equal(digest(body), object.sha256);
      if (object.key.endsWith(".ndjson")) {
        for (const line of body.toString("utf8").trimEnd().split("\n")) shares.push(JSON.parse(line).share);
      }
    }
    assert.equal(shares.length, 3);
    const source = Buffer.from(shares.join("\n")).toString("base64");
    assert.equal(Buffer.byteLength(source), snapshot.bodyBytes);
    assert.equal(digest(Buffer.from(source)), snapshot.bodySha256);
    const runtime = new Miniflare({ modules: true, script: script.toString("utf8"),
      compatibilityDate: manifest.compatibilityDate, bindings: { BUILD_REVISION: manifest.revision },
      d1Databases: ["DB"], r2Buckets: ["NODES"] });
    t.after(() => runtime.dispose());
    const db = await runtime.getD1Database("DB"), bucket = await runtime.getR2Bucket("NODES");
    for (const entry of manifest.migrations) {
      const body = await readFile(join(directory, entry.name));
      assert.equal(digest(body), entry.sha256);
      await db.batch(body.toString("utf8").trim().split(/;\s*/u).filter(Boolean).map((sql) => db.prepare(sql)));
      await recordTempFixtureMigration(db, entry);
    }
    const ownerId = "8813701954", sourceUrl = "https://fixture.example.invalid/sub/source/base64?provider_fixture=100-1";
    const pin = { providerRevision: "a".repeat(40), imageSha256: "b".repeat(64) };
    let calls = 0;
    const provider = { async fetchSubscription(input: unknown) {
      assert.deepEqual(input, { url: sourceUrl, ...pin });
      calls++;
      const body = new TextEncoder().encode(source).buffer;
      return { ok: true as const, body, bodySha256: digest(new Uint8Array(body)) };
    } };
    const admission = await enqueueProviderUrlImport(db, { ownerId, requestKey: "c".repeat(64), sourceUrl });
    assert.equal(admission.kind, "queued");
    assert.ok("subscriptionId" in admission);
    assert.equal(await runOneProviderJob(db, bucket, provider, pin), "saved");
    async function exportExact(generation: number) {
      const subscription = await getOwnedSubscription(db, ownerId, admission.subscriptionId);
      assert.ok(subscription);
      assert.equal(subscription.generation, generation);
      assert.equal(subscription.nodeCount, 3);
      const response = await runtime.dispatchFetch(`https://fixture.example.invalid/sub/${subscription.token}/base64`);
      assert.equal(response.status, 200);
      assert.equal(response.headers.get("Cache-Control"), "private, no-store");
      assert.equal(await response.text(), source, "URI encoding, order and names must remain exact, not merely the count.");
      return subscription;
    }
    const first = await exportExact(1);
    const refresh = await enqueueOwnedProviderRefresh(db, { ownerId, requestKey: "d".repeat(64),
      id: first.id, expectedGeneration: 1, expectedLifecycleRevision: 0 });
    assert.equal(refresh.kind, "queued");
    assert.equal(await runOneProviderJob(db, bucket, provider, pin), "saved");
    await exportExact(2);
    assert.equal(calls, 2);
  });
