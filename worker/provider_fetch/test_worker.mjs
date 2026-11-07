import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import { Miniflare } from "miniflare";
import { exercise, ProviderProbeError } from "./controller.ts";

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

function fake({ runningImage = image, failStop = false, corruptEdge = false } = {}) {
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

test("refuses a foreign or running image and cleans up owned failed probes", async () => {
  const foreign = fake();
  foreign.container.images.provider = image.replace("provider-fetch", "other-service");
  await assert.rejects(exercise(foreign.container, revision, isolatedRevision), { stage: "configuration" });
  assert.deepEqual(foreign.calls, []);
  const active = fake();
  active.container.running = true;
  await assert.rejects(exercise(active.container, revision, isolatedRevision), { stage: "configuration" });
  assert.deepEqual(active.calls, []);
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
  const runtime = new Miniflare({ modules: true, scriptPath: process.env.PROVIDER_WORKER_BUNDLE, compatibilityDate: "2026-07-30" });
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
