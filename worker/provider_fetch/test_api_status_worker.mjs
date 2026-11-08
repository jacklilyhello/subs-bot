import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import { Miniflare } from "miniflare";
import { API_STATUS_SERVICE, probePinnedProviderApiStatusV2, SERVICE } from "./controller.ts";

const revision = "a".repeat(40);
const imageSha256 = "c".repeat(64);
const input = { url: "https://fixture.example/v1/models", key: "synthetic-api-key", providerRevision: revision, imageSha256 };
const image = (service) => `registry.cloudflare.com/${"d".repeat(32)}/${service}@sha256:${imageSha256}`;
const compatibilityDate = "2026-07-30";
const isolatedRevision = "f".repeat(40);
const smokeName = API_STATUS_SERVICE + "-smoke";

test("the V2 probe requires its own image repository before starting the container", async () => {
  for (const [repository, service, allowed] of [
    [API_STATUS_SERVICE, API_STATUS_SERVICE, true],
    [SERVICE, API_STATUS_SERVICE, false],
    [API_STATUS_SERVICE, undefined, false],
  ]) {
    const calls = [];
    const selected = image(repository);
    const headers = {
      "Cache-Control": "private, no-store", "Referrer-Policy": "no-referrer", "X-Content-Type-Options": "nosniff",
    };
    const container = {
      images: { provider: selected },
      running: false,
      start(options) { calls.push(["start", options.image]); this.running = true; },
      async setInactivityTimeout() {},
      async inspect() { return { image: selected }; },
      async destroy() { calls.push(["stop"]); this.running = false; },
      getTcpPort(port) {
        assert.equal(port, 8080);
        return { async fetch(url, init) {
          if (url === "http://container/ready") return Response.json({ ok: true, revision }, { headers });
          assert.equal(url, "http://container/v2/api-status");
          assert.equal(init.redirect, "manual");
          calls.push(["probe", JSON.parse(init.body)]);
          return Response.json({ status: 401, elapsedMs: 12 }, { headers });
        } };
      },
    };
    const dispatchBeforeMs = Date.now() + 20_000;
    const result = await probePinnedProviderApiStatusV2(container, { ...input, dispatchBeforeMs }, service);
    assert.deepEqual(result, allowed ? { ok: true, status: 401, elapsedMs: 12 } : { ok: false, code: "unavailable" });
    assert.deepEqual(calls, allowed ? [["start", selected], ["probe", { url: input.url, key: input.key, dispatchBeforeMs }], ["stop"]] : []);
  }
});

test("the emitted status Worker exposes only V2 RPC and a fixed default denial", { timeout: 20_000 }, async () => {
  assert(process.env.PROVIDER_WORKER_BUNDLE);
  const script = await readFile(process.env.PROVIDER_WORKER_BUNDLE, "utf8");
  const fixture = `import { DurableObject } from "cloudflare:workers";
    import * as candidate from "./emitted.mjs";
    if (Object.keys(candidate).sort().join(",") !== "ProviderApiStatus,ProviderContainer,ProviderSmoke,default"
        || Object.getOwnPropertyNames(candidate.ProviderContainer.prototype).sort().join(",") !== "constructor,probeApiStatusV2,prove") {
      throw new Error("The emitted API status Worker exposes unexpected exports.");
    }
    export { default, ProviderApiStatus, ProviderSmoke } from "./emitted.mjs";
    export class ProviderContainer extends DurableObject {
      async prove(probe) {
        if (!this.ctx.id.equals(this.ctx.exports.ProviderContainer.idFromName("provider-api-status-v2"))
            || probe.providerRevision !== "${revision}" || probe.isolatedRevision !== "${isolatedRevision}") {
          throw new Error("Unexpected V2 smoke request.");
        }
        await this.ctx.storage.put("smoke", true);
        return { ok: true, imageSha256: "${imageSha256}" };
      }
      async probeApiStatusV2(input) {
        if (!this.ctx.id.equals(this.ctx.exports.ProviderContainer.idFromName("provider-api-status-v2"))
            || Object.keys(input).length !== 5 || input.providerRevision !== "${revision}"
            || input.imageSha256 !== "${imageSha256}"
            || !Number.isSafeInteger(input.dispatchBeforeMs)) throw new Error("Unexpected V2 request.");
        if (input.url === "https://subs-bot-cf-dev-01.lilyya.workers.dev/v1/models") {
          if (input.key !== "synthetic-provider-smoke-key" || !(await this.ctx.storage.get("smoke"))
              || await this.ctx.storage.get("statusSmoke")) throw new Error("Unexpected V2 smoke dispatch.");
          await this.ctx.storage.put("statusSmoke", true);
          return { ok: true, status: 404, elapsedMs: 12 };
        }
        if (input.url !== "https://fixture.example/v1/models" || input.key !== "synthetic-api-key") throw new Error("Unexpected V2 target.");
        const elapsedMs = (await this.ctx.storage.get("calls") ?? 0) + 1;
        await this.ctx.storage.put("calls", elapsedMs);
        return { ok: true, status: 401, elapsedMs };
      }
    }`;
  const runtime = new Miniflare({ workers: [
    { name: "caller", modules: true, compatibilityDate,
      serviceBindings: { STATUS: { name: "provider", entrypoint: "ProviderApiStatus" } },
      script: `export default { async fetch(request, env) {
        const path = new URL(request.url).pathname;
        const input = ${JSON.stringify(input)};
        input.dispatchBeforeMs = Date.now() + (path === "/expired" ? -1 : 20_000);
        if (path === "/revision") input.providerRevision = "e".repeat(40);
        if (path === "/malformed") delete input.dispatchBeforeMs;
        if (path === "/v1" || path === "/fetch") {
          try {
            if (path === "/v1") await env.STATUS.probeApiStatus(input);
            else await env.STATUS.fetchSubscription(input);
            return new Response("Unexpected callable method.", { status: 500 });
          } catch {
            return new Response(null, { status: 404 });
          }
        }
        return Response.json(await env.STATUS.probeApiStatusV2(input));
      } };` },
    { name: "provider", compatibilityDate, bindings: { BUILD_REVISION: revision },
      modules: [
        { type: "ESModule", path: "fixture.mjs", contents: fixture },
        { type: "ESModule", path: "emitted.mjs", contents: script },
      ],
      additionalUnboundDurableObjects: [{ className: "ProviderContainer", useSQLite: true }],
      workflows: { PROVIDER_SMOKE: { name: smokeName, className: "ProviderSmoke", scriptName: "provider" } } },
  ] });
  try {
    for (const [path, expected] of [
      ["/accepted", { ok: true, status: 401, elapsedMs: 1 }],
      ["/expired", { ok: false, code: "timeout" }],
      ["/revision", { ok: false, code: "unavailable" }],
      ["/malformed", { ok: false, code: "invalid-request" }],
      ["/accepted", { ok: true, status: 401, elapsedMs: 2 }],
    ]) {
      const response = await runtime.dispatchFetch("https://caller.example" + path);
      assert.deepEqual(await response.json(), expected);
    }
    for (const path of ["/v1", "/fetch"]) {
      assert.equal((await runtime.dispatchFetch("https://caller.example" + path)).status, 404);
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
    assert.deepEqual(result.output, { ok: true, imageSha256, apiStatus: 404 });
    const provider = await runtime.getWorker("provider");
    for (const [path, method] of [["/", "GET"], ["/ready", "GET"], ["/v1/fetch", "POST"], ["/v2/api-status", "POST"]]) {
      const response = await provider.fetch("https://provider.example" + path, { method });
      assert.equal(response.status, 404);
      assert.equal(response.headers.get("Cache-Control"), "private, no-store");
      assert.equal(await response.text(), "Not found.");
    }
  } finally {
    await runtime.dispose();
  }
});
