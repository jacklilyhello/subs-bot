import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import { Miniflare } from "miniflare";
import {
  exercise, fetchPinnedProvider, probePinnedProviderApiStatus, providerApiStatusRequest, providerPayload, ProviderProbeError,
} from "./controller.ts";

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

function fake({ runningImage = image, failStop = false, corruptEdge = false, providerResponse, apiResponse } = {}) {
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
        if (url === "http://container/v1/api-status" && apiResponse) return apiResponse(init);
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

const apiInput = { url: "https://fixture.example:443/tenant/v1/models", key: "synthetic-api-key",
  providerRevision: revision, imageSha256: imageDigest };
const apiPath = "http://container/v1/api-status";
const apiJson = (value, status = 200, extra = {}) => Response.json(value, { status, headers: { ...headers, ...extra } });

test("API status accepts exact pinned bounded input and posts only URL and key once", async () => {
  const maxURL = "https://fixture.example/" + "a".repeat(8192 - "https://fixture.example//models".length) + "/models";
  assert.deepEqual(providerApiStatusRequest(apiInput), apiInput);
  assert.ok(providerApiStatusRequest({ ...apiInput, url: maxURL, key: "k".repeat(512) }));
  for (const input of [null, [], {}, { ...apiInput, extra: true }, { ...apiInput, providerRevision: revision.toUpperCase() },
    { ...apiInput, imageSha256: imageDigest + "\n" }, { ...apiInput, key: 42 }, { ...apiInput, key: "" },
    { ...apiInput, key: "k".repeat(513) }, { ...apiInput, key: "a b" }, { ...apiInput, key: "x\r\nY:test" },
    ...["http://fixture.example/v1/models", "https://user@fixture.example/v1/models", "https://%66ixture.example/v1/models",
      "https://fixture.example:8443/v1/models", "https://fixture.example:/v1/models", "https://fixture.example/v1/models?",
      "https://fixture.example/v1/models#", "https://fixture.example/v1/models/", "https://fixture.example/v1/MODELS",
      "https://fixture.example/v1/model%73", "https://fixture.example/\ud800/models", "https://fixture.example/\\x/models",
      maxURL.replace("/models", "x/models")].map((url) => ({ ...apiInput, url })),
    { ...apiInput, url: "https://fixture.example/" + '"'.repeat(6000) + "/models", key: '"'.repeat(512) },
  ]) assert.equal(providerApiStatusRequest(input), null);

  const live = fake({ apiResponse: () => new Response('{"status": 302, "elapsedMs": 15000}', {
    headers: { ...headers, "Content-Type": "application/json; charset=utf-8" },
  }) });
  assert.deepEqual(await probePinnedProviderApiStatus(live.container, apiInput), { ok: true, status: 302, elapsedMs: 15_000 });
  assert.deepEqual(live.calls, [
    ["start", { image, instance: "lite", enableInternet: true }], ["idle", 30_000], ["http://container/ready", null],
    [apiPath, { url: apiInput.url, key: apiInput.key }], ["destroy"],
  ]);
  const wrongPin = fake();
  assert.deepEqual(await probePinnedProviderApiStatus(wrongPin.container, { ...apiInput, imageSha256: "e".repeat(64) }),
    { ok: false, code: "unavailable" });
  assert.deepEqual(wrongPin.calls, []);
  const invalid = fake();
  assert.deepEqual(await probePinnedProviderApiStatus(invalid.container, { ...apiInput, url: "http://fixture.example/v1/models" }),
    { ok: false, code: "invalid-request" });
  assert.deepEqual(invalid.calls, []);
  const wrongRunningImage = fake({ runningImage: "foreign" });
  assert.deepEqual(await probePinnedProviderApiStatus(wrongRunningImage.container, apiInput), { ok: false, code: "unavailable" });
  assert.equal(wrongRunningImage.calls.filter(([path]) => path === apiPath).length, 0);
  assert.deepEqual(wrongRunningImage.calls.at(-1), ["destroy"]);
});

test("API status rejects malformed port replies and never replays a key after an ambiguous call", async () => {
  const raw = (body) => new Response(body, { headers: { ...headers, "Content-Type": "application/json" } });
  const status = '{"status":401,"elapsedMs":0}';
  for (const [apiResponse, expected] of [
    [() => apiJson({ status: 401, elapsedMs: 0 }), { ok: true, status: 401, elapsedMs: 0 }],
    [() => raw(status.padEnd(256, " ")), { ok: true, status: 401, elapsedMs: 0 }],
    [() => apiJson({ error: "blocked-address" }, 422), { ok: false, code: "blocked-address" }],
    [() => apiJson({ error: "busy" }, 429), { ok: false, code: "busy" }],
    [() => apiJson({ error: "timeout" }, 504), { ok: false, code: "timeout" }],
    [() => { throw new Error(apiInput.key); }, { ok: false, code: "unavailable" }],
    ...[() => raw(status.padEnd(257, " ")), () => raw('{"status":401,"status":403,"elapsedMs":1}'),
      () => raw(new Uint8Array([0xff])), () => apiJson({ status: 401, elapsedMs: 1, key: apiInput.key }),
      () => apiJson({ status: 99, elapsedMs: 1 }), () => apiJson({ status: 600, elapsedMs: 1 }),
      () => apiJson({ status: 401, elapsedMs: 15_001 }), () => apiJson({ status: 401, elapsedMs: 1.5 }),
      () => apiJson({ status: 401, elapsedMs: -1 }), () => apiJson({ status: 401, elapsedMs: 1 }, 200, { "Content-Length": "2" }),
      () => apiJson({ status: 401, elapsedMs: 1 }, 200, { "Content-Encoding": "gzip" }),
      () => apiJson({ status: 401, elapsedMs: 1 }, 200, { "Set-Cookie": "ignored=1" }),
      () => apiJson({ error: "busy" }, 302, { Location: "https://different.example" }),
      () => apiJson({ error: "busy" }, 502), () => apiJson({ error: "http-status", upstreamStatus: 429 }, 502),
      () => apiJson({ error: apiInput.key }, 502),
    ].map((response) => [response, { ok: false, code: "invalid-body" }]),
  ]) {
    const { container, calls } = fake({ apiResponse });
    assert.deepEqual(await probePinnedProviderApiStatus(container, apiInput), expected);
    assert.equal(calls.filter(([path]) => path === apiPath).length, 1);
    assert.deepEqual(calls.at(-1), ["destroy"]);
  }
  const failStop = fake({ apiResponse: () => apiJson({ status: 200, elapsedMs: 1 }), failStop: true });
  assert.deepEqual(await probePinnedProviderApiStatus(failStop.container, apiInput), { ok: false, code: "unavailable" });
  assert.equal(failStop.calls.filter(([path]) => path === apiPath).length, 1);
});

test("API status body timeout finishes without a second port call", async (t) => {
  const timeout = AbortSignal.timeout.bind(AbortSignal);
  t.mock.method(AbortSignal, "timeout", (ms) => {
    if (ms !== 20_000) return timeout(ms);
    const controller = new AbortController();
    setTimeout(() => controller.abort(), 20);
    return controller.signal;
  });
  const { container, calls } = fake({ apiResponse: () => new Response(new ReadableStream({
    pull: () => new Promise(() => {}),
  }), { headers: { ...headers, "Content-Type": "application/json" } }) });
  assert.deepEqual(await probePinnedProviderApiStatus(container, apiInput), { ok: false, code: "timeout" });
  assert.equal(calls.filter(([path]) => path === apiPath).length, 1);
  assert.deepEqual(calls.at(-1), ["destroy"]);
});

test("the emitted Worker rejects all public fetches without any runtime bindings", async () => {
  assert(process.env.PROVIDER_WORKER_BUNDLE);
  const script = await readFile(process.env.PROVIDER_WORKER_BUNDLE, "utf8");
  const runtime = new Miniflare({ modules: true, script, compatibilityDate: "2026-07-30" });
  try {
    for (const [path, method] of [["/", "GET"], ["/ready", "GET"], ["/v1/fetch", "POST"], ["/v1/edge-proof", "POST"],
      ["/v1/api-status", "POST"]]) {
      const response = await runtime.dispatchFetch("https://provider.example" + path, { method });
      assert.equal(response.status, 404);
      assert.equal(response.headers.get("Cache-Control"), "private, no-store");
      assert.equal(await response.text(), "Not found.");
    }
  } finally {
    await runtime.dispose();
  }
});

test("the emitted subscription RPC, status RPC and Workflow share one private loopback Durable Object", { timeout: 20_000 }, async () => {
  assert(process.env.PROVIDER_WORKER_BUNDLE);
  const script = await readFile(process.env.PROVIDER_WORKER_BUNDLE, "utf8");
  const fixture = `import { DurableObject } from 'cloudflare:workers';
    export { default, ProviderFetch, ProviderSmoke } from "./emitted.mjs";
    export class ProviderContainer extends DurableObject {
      assertSingleton() {
        const id = this.ctx.exports.ProviderContainer.idFromName('provider-fetch-v1');
        if (!this.ctx.id.equals(id) || 'PROVIDER_CONTAINER' in this.env) {
          throw new Error('unexpected fixture namespace');
        }
      }
      async fetchSubscription(input) {
        this.assertSingleton();
        if (input.url === 'https://fixture.example/wrong-revision') return { ok: true, body: new ArrayBuffer(0), bodySha256: '${"a".repeat(64)}' };
        if (input.providerRevision !== '${revision}' || input.imageSha256 !== '${imageDigest}') throw new Error('wrong test pin');
        if (input.url !== 'https://fixture.example/accepted') throw new Error('synthetic private RPC failure');
        await this.ctx.storage.put('accepted', true);
        return { ok: true, body: new Uint8Array([1, 2, 3]).buffer, bodySha256: '${createHash("sha256").update(Buffer.from([1, 2, 3])).digest("hex")}' };
      }
      async probeApiStatus(input) {
        this.assertSingleton();
        if (!(await this.ctx.storage.get('accepted'))) throw new Error('wrong fixture status actor');
        const path = new URL(input.url).pathname;
        if (['/probe-wrong-revision/v1/models', '/probe-extra/v1/models', '/probe-invalid/v1/models'].includes(path)) {
          return { ok: true, status: 200, elapsedMs: 1 };
        }
        if (Object.keys(input).length !== 4 || input.key !== 'synthetic-api-key'
            || input.providerRevision !== '${revision}' || input.imageSha256 !== '${imageDigest}'
            || path === '/probe-fails/v1/models') throw new Error(input.key);
        if (path === '/probe-smuggled/v1/models') return { ok: true, status: 401, elapsedMs: 12, credential: input.key };
        if (path === '/probe-busy/v1/models') return { ok: false, code: 'busy' };
        return { ok: true, status: 401, elapsedMs: 12 };
      }
      async prove(probe) {
        this.assertSingleton();
        if (!(await this.ctx.storage.get('accepted')) || probe.providerRevision !== '${revision}'
            || probe.isolatedRevision !== '${isolatedRevision}') throw new Error('wrong fixture smoke target');
        return { ok: true };
      }
    }`;
  const runtime = new Miniflare({ workers: [
    { name: "caller", modules: true, compatibilityDate: "2026-07-30",
      serviceBindings: { PROVIDER: { name: "provider", entrypoint: "ProviderFetch" } },
      script: `export default { async fetch(request, env) {
        const path = new URL(request.url).pathname;
        if (path.startsWith('/probe-')) {
          const input = {
            url: 'https://fixture.example' + path + '/v1/models',
            key: path === '/probe-invalid' ? 'invalid key' : 'synthetic-api-key',
            providerRevision: path === '/probe-wrong-revision' ? '${isolatedRevision}' : '${revision}',
            imageSha256: path === '/probe-wrong-image' ? '${"e".repeat(64)}' : '${imageDigest}',
          };
          if (path === '/probe-extra') input.headers = {};
          return Response.json(await env.PROVIDER.probeApiStatus(input));
        }
        const url = path === '/invalid' ? 'file:///synthetic' : 'https://fixture.example' + path;
        const input = path === '/unpinned' ? { url } : { url,
          providerRevision: path === '/wrong-revision' ? '${isolatedRevision}' : '${revision}', imageSha256: '${imageDigest}' };
        const result = await env.PROVIDER.fetchSubscription(input);
        return result.ok ? new Response(result.body, { headers: { 'x-verified': result.bodySha256 } }) : Response.json(result);
      } };` },
    { name: "provider", compatibilityDate: "2026-07-30",
      modules: [
        { type: "ESModule", path: "fixture.mjs", contents: fixture },
        { type: "ESModule", path: "emitted.mjs", contents: script },
      ],
      bindings: { BUILD_REVISION: revision },
      additionalUnboundDurableObjects: [{ className: "ProviderContainer", useSQLite: true }],
      workflows: { PROVIDER_SMOKE: { name: "subs-bot-provider-fetch-dev-01-smoke", className: "ProviderSmoke", scriptName: "provider" } } },
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
    for (const [path, expected] of [
      ["/probe-accepted", { ok: true, status: 401, elapsedMs: 12 }],
      ["/probe-invalid", { ok: false, code: "invalid-request" }],
      ["/probe-extra", { ok: false, code: "invalid-request" }],
      ["/probe-wrong-revision", { ok: false, code: "unavailable" }],
      ["/probe-wrong-image", { ok: false, code: "unavailable" }],
      ["/probe-fails", { ok: false, code: "unavailable" }],
      ["/probe-busy", { ok: false, code: "busy" }],
      ["/probe-smuggled", { ok: false, code: "invalid-body" }],
    ]) {
      const response = await runtime.dispatchFetch("https://caller.example" + path);
      assert.deepEqual(await response.json(), expected);
    }
    const { PROVIDER_SMOKE } = await runtime.getBindings("provider");
    const smoke = await PROVIDER_SMOKE.create({ id: `provider-smoke-${revision}`,
      params: { providerRevision: revision, isolatedRevision } });
    let result;
    for (let attempt = 0; attempt < 100; attempt++) {
      result = await smoke.status();
      if (["complete", "errored", "terminated"].includes(result.status)) break;
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    assert.equal(result?.status, "complete");
    assert.deepEqual(result.output, { ok: true });
  } finally {
    await runtime.dispose();
  }
});
