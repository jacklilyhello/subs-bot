import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import { Miniflare } from "miniflare";
import { exercise, fetchPinnedProvider, providerPayload, ProviderProbeError } from "./controller.ts";

const revision = "a".repeat(40);
const isolatedRevision = "b".repeat(40);
const imageDigest = "c".repeat(64);
const image = `registry.cloudflare.com/${"d".repeat(32)}/subs-bot-provider-fetch-dev-01@sha256:${imageDigest}`;
const headers = {
  "Cache-Control": "private, no-store",
  "Referrer-Policy": "no-referrer",
  "X-Content-Type-Options": "nosniff",
};
const body = JSON.stringify({ ok: true, service: "subs-bot", revision: isolatedRevision });
const digest = createHash("sha256").update(body).digest("hex");

function fake({ runningImage = image, failStop = false, corruptEdge = false, providerResponse } = {}) {
  const calls = [];
  const container = {
    images: { provider: image },
    running: false,
    start(options) { calls.push(["start", options]); this.running = true; },
    async setInactivityTimeout(ms) { calls.push(["idle", ms]); },
    async inspect() { return { image: runningImage }; },
    async destroy() {
      calls.push(["destroy"]);
      if (failStop) throw new Error("remote-error-fixture");
      this.running = false;
    },
    getTcpPort(port) {
      assert.equal(port, 8080);
      return { async fetch(url, init) {
        calls.push([url, init.body ? JSON.parse(init.body) : null]);
        assert.equal(init.redirect, "manual");
        if (url === "http://container/ready") return Response.json({ ok: true, revision }, { headers });
        assert.equal(init.method, "POST");
        assert.deepEqual(init.headers, { "Content-Type": "application/json" });
        if (url === "http://container/v1/edge-proof") {
          return new Response(corruptEdge ? "corrupt-fixture" : body, { headers: { ...headers,
            "Content-Type": "application/octet-stream", "X-Provider-Approved-Families": "4,6", "X-Provider-Body-Sha256": digest,
          } });
        }
        assert.equal(url, "http://container/v1/fetch");
        if (providerResponse) return providerResponse(init);
        return Response.json({ error: "blocked-address" }, { headers, status: 422 });
      } };
    },
  };
  return { container, calls };
}

test("starts only the pinned image, checks the fixed cases and destroys the instance", async () => {
  const { container, calls } = fake();
  assert.deepEqual(await exercise(container, revision, isolatedRevision), {
    ok: true, revision, isolatedRevision, imageSha256: imageDigest, edgeStatus: 200,
    approvedDnsFamilies: [4, 6], bodyBytes: Buffer.byteLength(body), bodySha256: digest,
    blockedPrivateTargets: 3, stopped: true,
  });
  assert.deepEqual(calls, [
    ["start", { image, instance: "lite", enableInternet: true }], ["idle", 30_000],
    ["http://container/ready", null], ["http://container/v1/edge-proof", {}],
    ["http://container/v1/fetch", { url: "http://127.0.0.1/" }],
    ["http://container/v1/fetch", { url: "http://[::1]/" }],
    ["http://container/v1/fetch", { url: "http://169.254.169.254/" }], ["destroy"],
  ]);
});

const providerUrl = "https://fixture.example/sub?token=synthetic-private-parameter";
const metadataHeader = (text) => Buffer.from(text).toString("base64").replaceAll("+", "-").replaceAll("/", "_");
const success = (extra = {}, bytes = Buffer.from("synthetic subscription bytes")) => new Response(bytes, {
  headers: { ...headers, "Content-Type": "application/octet-stream", "Content-Length": String(bytes.length),
    "X-Provider-Body-Sha256": createHash("sha256").update(bytes).digest("hex"), ...extra },
});

test("admits only a bounded RPC input and posts the exact URL to the verified private container", async () => {
  for (const input of [null, [], {}, { url: providerUrl, headers: {} }, { url: 100 }, { url: "ftp://fixture.example/" },
    { url: "https://fixture.example/\ud800" }, { url: "https://fixture.example/\nnext" }, { url: "https://fixture.example/%zz" },
    { url: "https://fixture.example/" + "😀".repeat(3000) }, { url: "https://fixture.example/" + '"'.repeat(7000) }]) {
    assert.equal(providerPayload(input), null);
  }
  const payload = providerPayload({ url: providerUrl });
  assert.deepEqual(JSON.parse(payload), { url: providerUrl });
  const { container, calls } = fake({ providerResponse: () => success({
    "X-Provider-Metadata": metadataHeader(String.raw`{"profile-title":"\u6e2f \ud83d\ude00","subscription-userinfo":"upload=1; total=9"}`),
  }) });
  const result = await fetchPinnedProvider(container, revision, payload, imageDigest);
  assert.equal(result.ok, true);
  assert(result.body instanceof ArrayBuffer);
  assert.equal(Buffer.from(result.body).toString(), "synthetic subscription bytes");
  assert.equal(result.bodySha256, createHash("sha256").update(Buffer.from(result.body)).digest("hex"));
  assert.deepEqual(result.metadata, { "profile-title": "港 😀", "subscription-userinfo": "upload=1; total=9" });
  assert.deepEqual(calls.slice(-2), [["http://container/v1/fetch", { url: providerUrl }], ["destroy"]]);

  const empty = fake({ providerResponse: () => success({}, Buffer.alloc(0)) });
  const emptyResult = await fetchPinnedProvider(empty.container, revision, payload, imageDigest);
  assert.equal(emptyResult.ok, true);
  assert.equal(emptyResult.body.byteLength, 0);
  assert(!("metadata" in emptyResult));

  const max = Buffer.alloc(10 * 1024 * 1024, 0x41);
  const full = fake({ providerResponse: () => success({}, max) });
  const fullResult = await fetchPinnedProvider(full.container, revision, payload, imageDigest);
  assert.equal(fullResult.ok, true);
  assert.equal(fullResult.body.byteLength, max.length);
  assert.equal(fullResult.bodySha256, createHash("sha256").update(max).digest("hex"));
});

test("rejects incomplete bodies, invalid hashes, foreign headers and malformed metadata before returning bytes", async () => {
  for (const response of [
    () => success({ "Content-Length": "1" }), () => success({ "Content-Length": "100" }),
    () => success({ "Content-Length": "10485761" }), () => success({ "X-Provider-Body-Sha256": "0".repeat(64) }),
    () => success({ "Content-Encoding": "gzip" }), () => success({ Location: providerUrl }),
    () => success({ "Set-Cookie": "synthetic" }), () => success({ "X-Provider-Metadata": "====" }),
    ...[String.raw`{"profile-title":"a","profile-title":"b"}`, String.raw`{"location":"https://fixture.example/"}`,
      String.raw`{"profile-title":"line\nnext"}`, '{"profile-title":"' + "x".repeat(3072) + '"}']
      .map((text) => () => success({ "X-Provider-Metadata": metadataHeader(text) })),
  ]) {
    const { container, calls } = fake({ providerResponse: response });
    assert.deepEqual(await fetchPinnedProvider(container, revision, providerPayload({ url: providerUrl }), imageDigest),
      { ok: false, code: "invalid-body", retryable: false });
    assert.deepEqual(calls.at(-1), ["destroy"]);
  }
});

test("returns only closed failure fields and verifies the stop before releasing a result", async () => {
  for (const [status, value, expected] of [
    [502, { error: "http-status", upstreamStatus: 429 }, { code: "http-status", retryable: true, upstreamStatus: 429 }],
    [502, { error: "http-status", upstreamStatus: 403 }, { code: "http-status", retryable: false, upstreamStatus: 403 }],
    [502, { error: "http-status", upstreamStatus: 503 }, { code: "http-status", retryable: true, upstreamStatus: 503 }],
    [502, { error: "http-status", upstreamStatus: "429" }, { code: "invalid-body", retryable: false }],
    [502, { error: "http-status", upstreamStatus: 429, url: providerUrl }, { code: "invalid-body", retryable: false }],
    [422, { error: "blocked-address" }, { code: "blocked-address", retryable: false }],
    [429, { error: "busy" }, { code: "busy", retryable: true }],
    [504, { error: "timeout" }, { code: "timeout", retryable: true }],
    [302, { error: "busy" }, { code: "invalid-body", retryable: false }],
  ]) {
    const { container } = fake({ providerResponse: () => Response.json(value, { status, headers }) });
    assert.deepEqual(await fetchPinnedProvider(container, revision, providerPayload({ url: providerUrl }), imageDigest), { ok: false, ...expected });
  }
  for (const options of [{ failStop: true, providerResponse: () => success() }, { runningImage: "foreign" },
    { providerResponse: () => { throw new Error(providerUrl); } }]) {
    const { container, calls } = fake(options);
    assert.deepEqual(await fetchPinnedProvider(container, revision, providerPayload({ url: providerUrl }), imageDigest),
      { ok: false, code: "unavailable", retryable: true });
    assert.deepEqual(calls.at(-1), ["destroy"]);
  }
});

test("bounds a stalled response body and stops the container", async (t) => {
  const timeout = AbortSignal.timeout.bind(AbortSignal);
  t.mock.method(AbortSignal, "timeout", (ms) => {
    if (ms !== 28_000) return timeout(ms);
    const controller = new AbortController();
    setTimeout(() => controller.abort(), 20);
    return controller.signal;
  });
  const { container, calls } = fake({ providerResponse: () => new Response(new ReadableStream({
    pull: () => new Promise(() => {}),
  }), { headers: { ...headers, "Content-Type": "application/octet-stream", "Content-Length": "1",
    "X-Provider-Body-Sha256": "a".repeat(64) } }) });
  assert.deepEqual(await fetchPinnedProvider(container, revision, providerPayload({ url: providerUrl }), imageDigest),
    { ok: false, code: "timeout", retryable: true });
  assert.deepEqual(calls.at(-1), ["destroy"]);
});

test("refuses a foreign or running image and cleans up owned failed probes", async () => {
  const foreign = fake();
  foreign.container.images.provider = image.replace("provider-fetch", "other-service");
  await assert.rejects(exercise(foreign.container, revision, isolatedRevision), { stage: "configuration" });
  assert.deepEqual(foreign.calls, []);
  const active = fake();
  active.container.running = true;
  await assert.rejects(exercise(active.container, revision, isolatedRevision), { stage: "configuration" });
  assert.deepEqual(active.calls, []);
  const wrongPin = fake();
  assert.deepEqual(await fetchPinnedProvider(wrongPin.container, revision, providerPayload({ url: providerUrl }), "e".repeat(64)),
    { ok: false, code: "unavailable", retryable: true });
  assert.deepEqual(wrongPin.calls, []);
  for (const [options, stage] of [[{ runningImage: "foreign" }, "image"], [{ corruptEdge: true }, "edge"], [{ failStop: true }, "stop"]]) {
    const { container, calls } = fake(options);
    await assert.rejects(exercise(container, revision, isolatedRevision), (error) => {
      assert(error instanceof ProviderProbeError);
      assert.equal(error.stage, stage);
      assert(!error.message.includes("remote-error-fixture"));
      return true;
    });
    assert.deepEqual(calls.at(-1), ["destroy"]);
  }
});

test("the emitted Worker rejects all public fetches without any runtime bindings", async () => {
  assert(process.env.PROVIDER_WORKER_BUNDLE);
  const script = await readFile(process.env.PROVIDER_WORKER_BUNDLE, "utf8");
  const runtime = new Miniflare({ modules: true, script, compatibilityDate: "2026-07-30" });
  try {
    for (const [path, method] of [["/", "GET"], ["/ready", "GET"], ["/v1/fetch", "POST"], ["/v1/edge-proof", "POST"]]) {
      const response = await runtime.dispatchFetch("https://provider.example" + path, { method });
      assert.equal(response.status, 404);
      assert.equal(response.headers.get("Cache-Control"), "private, no-store");
      assert.equal(await response.text(), "Not found.");
    }
  } finally {
    await runtime.dispose();
  }
});

test("the emitted named service binding admits a private RPC call and returns structured binary data", async () => {
  assert(process.env.PROVIDER_WORKER_BUNDLE);
  const script = await readFile(process.env.PROVIDER_WORKER_BUNDLE, "utf8");
  const runtime = new Miniflare({ workers: [
    { name: "caller", modules: true, compatibilityDate: "2026-07-30",
      serviceBindings: { PROVIDER: { name: "provider", entrypoint: "ProviderFetch" } },
      script: `export default { async fetch(request, env) {
        const path = new URL(request.url).pathname;
        const url = path === '/invalid' ? 'file:///synthetic' : 'https://fixture.example' + path;
        const input = path === '/unpinned' ? { url } : { url,
          providerRevision: path === '/wrong-revision' ? '${isolatedRevision}' : '${revision}', imageSha256: '${imageDigest}' };
        const result = await env.PROVIDER.fetchSubscription(input);
        return result.ok ? new Response(result.body, { headers: { 'x-verified': result.bodySha256 } }) : Response.json(result);
      } };` },
    { name: "provider", modules: true, compatibilityDate: "2026-07-30", script, bindings: { BUILD_REVISION: revision },
      durableObjects: { PROVIDER_CONTAINER: { className: "FixtureContainer", scriptName: "fixture" } } },
    { name: "fixture", modules: true, compatibilityDate: "2026-07-30",
      script: `import { DurableObject } from 'cloudflare:workers';
      export class FixtureContainer extends DurableObject {
        async fetchSubscription(input) {
          if (input.url === 'https://fixture.example/wrong-revision') return { ok: true, body: new ArrayBuffer(0), bodySha256: '${"a".repeat(64)}' };
          if (input.providerRevision !== '${revision}' || input.imageSha256 !== '${imageDigest}') throw new Error('wrong test pin');
          if (input.url !== 'https://fixture.example/accepted') throw new Error('synthetic private RPC failure');
          return { ok: true, body: new Uint8Array([1, 2, 3]).buffer, bodySha256: '${createHash("sha256").update(Buffer.from([1, 2, 3])).digest("hex")}' };
        }
      }
      export default { fetch() { return new Response(null, { status: 404 }); } };` },
  ] });
  try {
    const accepted = await runtime.dispatchFetch("https://caller.example/accepted");
    assert.deepEqual(new Uint8Array(await accepted.arrayBuffer()), new Uint8Array([1, 2, 3]));
    assert.equal(accepted.headers.get("x-verified"), createHash("sha256").update(Buffer.from([1, 2, 3])).digest("hex"));
    for (const [path, code, retryable] of [["/invalid", "invalid-request", false], ["/unpinned", "invalid-request", false],
      ["/wrong-revision", "unavailable", true], ["/fails", "unavailable", true]]) {
      const result = await runtime.dispatchFetch("https://caller.example" + path);
      assert.deepEqual(await result.json(), { ok: false, code, retryable });
    }
  } finally {
    await runtime.dispose();
  }
});
