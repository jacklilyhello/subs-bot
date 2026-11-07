import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test, type TestContext } from "node:test";
import { fileURLToPath } from "node:url";

import { Miniflare } from "miniflare";
import { parse } from "yaml";

import { enqueueOwnedProviderRefresh, enqueueProviderUrlImport, type ProviderAdmission } from "../src/provider-jobs.ts";
import { getOwnedSubscription } from "../src/storage.ts";

const ownerId = "91001";
const source = "https://provider.example.invalid/signed?z=synthetic%2Fvalue&a=1";
const firstShare = "ss://YWVzLTI1Ni1nY206Zml4dHVyZQ@203.0.113.10:8388#first";
const secondShare = "ss://YWVzLTI1Ni1nY206Zml4dHVyZQ@203.0.113.20:8388#second";
const providerRevision = "a".repeat(40);
const imageSha256 = "b".repeat(64);

function job(admission: ProviderAdmission) {
  assert.equal(admission.kind, "queued");
  assert.ok("jobId" in admission);
  return admission;
}

async function setup(enabled: boolean) {
  const directory = process.env.WORKER_TEST_BUNDLE_DIR;
  assert.ok(directory);
  const manifest = JSON.parse(await readFile(join(directory, "isolation.json"), "utf8"));
  const script = await readFile(join(directory, "index.js"), "utf8");
  const d1Databases = { DB: "provider-consumer-fixture" };
  const runtime = new Miniflare({ workers: [
    { name: "app", modules: true, script, compatibilityDate: manifest.compatibilityDate, d1Databases, r2Buckets: ["NODES"],
      serviceBindings: { PROVIDER_FETCH: { name: "provider", entrypoint: "ProviderFetch" } },
      bindings: { BUILD_REVISION: manifest.revision, ...(enabled ? { PROVIDER_REVISION: providerRevision, PROVIDER_IMAGE_SHA256: imageSha256 } : {}) } },
    { name: "provider", modules: true, compatibilityDate: manifest.compatibilityDate, d1Databases,
      script: `import { WorkerEntrypoint } from 'cloudflare:workers';
        export class ProviderFetch extends WorkerEntrypoint {
          async fetchSubscription(input) {
            if (Object.keys(input).length !== 3 || input.url !== ${JSON.stringify(source)}
              || input.providerRevision !== ${JSON.stringify(providerRevision)} || input.imageSha256 !== ${JSON.stringify(imageSha256)}) {
              throw new Error('Synthetic provider input differs.');
            }
            const mode = await this.env.DB.prepare('UPDATE provider_fixture_state SET calls=calls+1 RETURNING mode').first('mode');
            if (mode === 'retry') return {ok:false,code:'http-status',retryable:true,upstreamStatus:503};
            if (mode === 'stale') await this.env.DB.prepare('INSERT INTO subscription_lifecycle SELECT id,1 FROM subscriptions').run();
            const first = ${JSON.stringify(firstShare)}, second = ${JSON.stringify(secondShare)};
            const text = mode === 'initial' ? first : mode === 'malformed' ? first + '\\nss://broken' : second + '\\n' + first;
            const body = new TextEncoder().encode(text).buffer;
            const hash = await crypto.subtle.digest('SHA-256',body);
            return {ok:true,body,bodySha256:mode === 'corrupt' ? '0'.repeat(64) : Array.from(new Uint8Array(hash),
              byte => byte.toString(16).padStart(2,'0')).join(''),
              ...(mode === 'initial' ? {metadata:{'subscription-userinfo':'upload=1073741824; download=1073741824; total=4294967296; expire=2000000000'}} : {})};
          }
        }
        export default {fetch(){return new Response(null,{status:404})}};` },
  ] });
  try {
    const db = await runtime.getD1Database("DB", "app");
    const bucket = await runtime.getR2Bucket("NODES", "app");
    for (const migration of manifest.migrations) {
      const sql = await readFile(join(directory, migration.name), "utf8");
      await db.batch(sql.trim().split(/;\s*/u).filter(Boolean).map((statement) => db.prepare(statement)));
    }
    await db.batch([
      db.prepare("CREATE TABLE provider_fixture_state(mode TEXT NOT NULL,calls INTEGER NOT NULL)"),
      db.prepare("INSERT INTO provider_fixture_state VALUES ('initial',0)"),
    ]);
    const worker = await runtime.getWorker("app");
    const cron = async () => assert.equal((await worker.scheduled({ cron: "* * * * *" })).outcome, "ok");
    return { runtime, db, bucket, cron };
  } catch (error) {
    await runtime.dispose();
    throw error;
  }
}

test("emitted Worker drains provider import and refresh through named RPC, D1, R2 and HTTP", { timeout: 60_000 }, async (t) => {
  const { runtime, db, bucket, cron } = await setup(true);
  t.after(() => runtime.dispose());
  let sequence = 0;
  const requestKey = () => (++sequence).toString(16).padStart(64, "0");
  const admission = job(await enqueueProviderUrlImport(db, { ownerId, sourceUrl: source, requestKey: requestKey() }));
  const sub = async () => {
    const item = await getOwnedSubscription(db, ownerId, admission.subscriptionId);
    assert.ok(item);
    return item;
  };
  const path = `https://fixture.invalid/sub/${(await sub()).token}/base64`;
  const exportIs = async (text: string) => {
    const response = await runtime.dispatchFetch(path);
    assert.equal(response.status, 200);
    assert.equal(response.headers.get("Cache-Control"), "private, no-store");
    assert.equal(await response.text(), Buffer.from(text).toString("base64"));
  };
  const mode = async (value: string) => db.prepare("UPDATE provider_fixture_state SET mode=?").bind(value).run();
  const refresh = async () => job(await enqueueOwnedProviderRefresh(db, { ownerId, id: admission.subscriptionId, requestKey: requestKey() }));
  const status = async (id: number) => db.prepare(`SELECT state,result_code AS result,failure_code AS failure,attempts FROM subscription_provider_jobs WHERE job_id=?`).bind(id).first();

  assert.equal((await runtime.dispatchFetch(path)).status, 404);
  await cron();
  assert.deepEqual(await status(admission.jobId), { state: "done", result: "saved", failure: null, attempts: 1 });
  const initial = await sub();
  assert.equal(initial.generation, 1);
  assert.equal(initial.trafficUsed, 2);
  assert.equal(initial.trafficTotal, 4);
  assert.equal(initial.expireAt, 2_000_000_000);
  await exportIs(firstShare);

  const retry = await refresh();
  await mode("retry");
  await cron();
  await cron();
  assert.deepEqual(await status(retry.jobId), { state: "pending", result: null, failure: "upstream-retryable", attempts: 1 });
  assert.deepEqual(await sub(), initial);
  await exportIs(firstShare);
  await db.prepare("UPDATE subscription_provider_jobs SET due_at=unixepoch() WHERE job_id=?").bind(retry.jobId).run();
  await mode("refresh");
  await cron();
  assert.deepEqual(await status(retry.jobId), { state: "done", result: "saved", failure: null, attempts: 2 });
  const refreshed = await sub();
  assert.equal(refreshed.generation, 2);
  assert.equal(refreshed.token, initial.token);
  assert.equal(refreshed.trafficTotal, initial.trafficTotal);
  assert.equal(refreshed.expireAt, initial.expireAt);
  await exportIs(`${secondShare}\n${firstShare}`);

  for (const [fixture, expected] of [["malformed", "invalid-document"], ["corrupt", "fetch-rejected"], ["stale", "stale-target"]]) {
    const next = await refresh();
    await mode(fixture);
    await cron();
    assert.equal((await status(next.jobId))?.result, expected);
    assert.equal((await sub()).generation, 2);
    await exportIs(`${secondShare}\n${firstShare}`);
  }
  assert.equal((await bucket.list()).objects.length, 4);
  assert.equal(await db.prepare("SELECT calls FROM provider_fixture_state").first("calls"), 6);
});

test("emitted Worker leaves queued work untouched when the provider pin is missing", { timeout: 60_000 }, async (t) => {
  const { runtime, db, cron } = await setup(false);
  t.after(() => runtime.dispose());
  const queued = job(await enqueueProviderUrlImport(db, { ownerId, sourceUrl: source, requestKey: "c".repeat(64) }));
  await cron();
  assert.deepEqual(await db.prepare("SELECT state,attempts FROM subscription_provider_jobs WHERE job_id=?").bind(queued.jobId).first(),
    { state: "pending", attempts: 0 });
  assert.equal(await db.prepare("SELECT calls FROM provider_fixture_state").first("calls"), 0);
});

async function protectedReplay(t: TestContext, body: Buffer) {
  const bundle = process.env.WORKER_TEST_BUNDLE_DIR;
  assert.ok(bundle);
  const scratch = await mkdtemp(join(tmpdir(), "synthetic-provider-replay-"));
  t.after(() => rm(scratch, { recursive: true, force: true }));
  const input = join(scratch, "sample-01.body");
  const controls = join(scratch, "request.json");
  await writeFile(input, body, { mode: 0o600 });
  await writeFile(controls, JSON.stringify({
    source, decodedBytes: body.length, bodySha256: createHash("sha256").update(body).digest("hex"),
    rpcMetadata: { "subscription-userinfo": "upload=1073741824; download=1073741824; total=4294967296; expire=2000000000" },
  }), { mode: 0o600 });
  const script = fileURLToPath(new URL("../tools/provider-live-worker.ts", import.meta.url));
  const check = spawnSync(process.execPath, [script, bundle, input, scratch, controls], {
    stdio: "ignore", env: { PATH: process.env.PATH, HOME: scratch, TMPDIR: scratch }, timeout: 50_000,
  });
  assert.equal(check.status, 0, "The protected comparator could not complete its synthetic replay.");
  return { scratch, report: JSON.parse(await readFile(join(scratch, "worker.json"), "utf8")) };
}

test("protected comparator replays the exact named provider body through the emitted Worker", { timeout: 60_000 }, async (t) => {
  const body = Buffer.from(firstShare);
  const { report, scratch } = await protectedReplay(t, body);
  assert.equal(report.job, "saved");
  assert.deepEqual(report.document, {
    kind: "parsed", format: "text", envelope: "plain", nodes: 1, malformed: 0, unsupported: 0, ignored: 0,
  });
  assert.deepEqual(report.metadata, { trafficUsed: 2, trafficTotal: 4, expireAt: 2_000_000_000 });
  assert.equal(report.chunks, 1);
  assert.deepEqual(Object.values(report.formats).map((format) => (format as { status: number }).status), [200, 200, 200, 200, 200]);
  assert.deepEqual(report.diagnostics.protocols, { ss: 1 });
  for (const format of Object.values(report.diagnostics.formats)) {
    assert.deepEqual(format, { admitted: { ss: 1 }, rejected: {}, rejectedTraits: {} });
  }
  assert.equal(await readFile(join(scratch, "base64.body"), "ascii"), body.toString("base64"));
});

test("protected comparator distinguishes per-node refusal from a stored document", { timeout: 60_000 }, async (t) => {
  const body = Buffer.from(JSON.stringify({ proxies: [
    { name: "Synthetic SS", type: "ss", server: "203.0.113.10", port: 8388, cipher: "aes-128-gcm", password: "fixture-only" },
    { name: "Synthetic AnyTLS", type: "anytls", server: "203.0.113.11", port: 443,
      password: "fixture-only", "client-fingerprint": "randomized" },
    { name: "Synthetic VMess", type: "vmess", server: "203.0.113.12", port: 443,
      uuid: "12345678-1234-4234-8234-123456789012", cipher: "aes-128-gcm", "packet-encoding": "none" },
  ] }));
  const { report, scratch } = await protectedReplay(t, body);
  assert.equal(report.job, "saved");
  assert.equal(report.document.nodes, 3);
  assert.deepEqual(report.diagnostics.protocols, { ss: 1, anytls: 1, vmess: 1 });
  for (const format of ["base64", "surge", "qx"]) {
    assert.equal(report.formats[format].status, 422);
    assert.deepEqual(report.diagnostics.formats[format], {
      admitted: { ss: 1 }, rejected: { anytls: 1, vmess: 1 },
      rejectedTraits: { "randomized-fingerprint": 1, "packet-encoding-none": 1 },
    });
  }
  assert.equal(report.formats.clash.status, 422);
  assert.equal(report.diagnostics.formats.clash.rejected.vmess, 1);
  assert.equal(report.diagnostics.formats.clash.rejectedTraits["packet-encoding-none"], 1);
  assert.equal(report.formats.singbox.status, 200);
  assert.deepEqual(report.diagnostics.formats.singbox, {
    admitted: { ss: 1, anytls: 1, vmess: 1 }, rejected: {}, rejectedTraits: {},
  });
  const binary = process.env.SINGBOX_TEST_BINARY;
  assert.ok(binary);
  const check = spawnSync(binary, ["check", "-c", join(scratch, "singbox.body")], {
    stdio: "ignore", timeout: 15_000,
  });
  assert.equal(check.status, 0, "The synthetic replay must be accepted by the pinned Sing-box checker.");
});

const hysteria2 = {
  name: "Synthetic Hysteria 2", type: "hysteria2", server: "203.0.113.20", port: 443, password: "fixture-only",
};

test("structured Hysteria 2 cannot disable UDP in a Clash export", { timeout: 60_000 }, async (t) => {
  const body = Buffer.from(JSON.stringify({ proxies: [{ ...hysteria2, udp: false }] }));
  const { report } = await protectedReplay(t, body);
  assert.equal(report.job, "saved");
  assert.equal(report.document.format, "clash");
  assert.equal(report.formats.clash.status, 422);
});

test("structured Hysteria 2 can retain native UDP behavior in a Clash export", { timeout: 60_000 }, async (t) => {
  const body = Buffer.from(JSON.stringify({ proxies: [{ ...hysteria2, udp: true }] }));
  const { report, scratch } = await protectedReplay(t, body);
  assert.equal(report.job, "saved");
  assert.equal(report.document.format, "clash");
  for (const format of ["base64", "surge", "singbox"]) {
    assert.equal(report.formats[format].status, 200);
  }
  assert.equal(report.formats.clash.status, 200, "Redundant Hysteria 2 UDP enablement must remain exportable to Mihomo.");
  const output = await readFile(join(scratch, "clash.body"), "utf8");
  assert.deepEqual(parse(output).proxies, [hysteria2]);
  const config = join(scratch, "synthetic-hysteria2.yaml");
  await writeFile(config, output, { mode: 0o600 });
  const binary = process.env.MIHOMO_TEST_BINARY;
  assert.ok(binary);
  const check = spawnSync(binary, ["-t", "-d", scratch, "-f", config], {
    stdio: "ignore", env: { HOME: scratch }, timeout: 15_000,
  });
  assert.equal(check.status, 0, "The exact synthetic output must be accepted by the pinned Mihomo checker.");
});
