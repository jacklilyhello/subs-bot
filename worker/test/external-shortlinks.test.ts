import assert from "node:assert/strict";
import { test } from "node:test";
import { callShortlinkService, localShortlink, wrapAuthorizedLocalShortlink } from "../src/telegram/external-shortlinks.ts";

const origin = "https://subs-bot-cf-dev-01.lilyya.workers.dev";
const local = origin + "/s/" + "a".repeat(22);
const operation = "12345678-1234-4234-a234-123456789012";
const token = "sl_" + "f".repeat(64);

test("RPC sends only the published local short capability and opaque stable idempotency key", async () => {
  const requests: Request[] = [];
  const service = { async createShortlink(request: Request) {
    requests.push(request);
    assert.equal(request.url, "https://link-admin.lily.lat/api/shorten");
    assert.equal(request.method, "POST");
    assert.equal(request.headers.get("authorization"), `Bearer ${token}`);
    assert.equal(request.headers.get("idempotency-key"), operation);
    assert.equal(request.headers.get("content-type"), "application/json");
    assert.deepEqual(await request.json(), { url: local, domain: "gfw.mom" });
    return Response.json({ ok: true, data: { domain: "gfw.mom", slug: "Ab9xQ2mR", short_url: "https://gfw.mom/Ab9xQ2mR" } },
      { status: requests.length === 1 ? 201 : 200, headers: requests.length === 1 ? {} : { "Idempotency-Replayed": "true" } });
  } };
  assert.deepEqual(await callShortlinkService({ service, token }, local, origin, operation), { kind: "created", url: "https://gfw.mom/Ab9xQ2mR" });
  assert.deepEqual(await callShortlinkService({ service, token }, local, origin, operation), { kind: "replayed", url: "https://gfw.mom/Ab9xQ2mR" });
  assert.equal(requests.length, 2);
});

test("no credential, upstream URL, direct export or alternate destination can reach RPC", async () => {
  let calls = 0;
  const service = { async createShortlink() { calls++; throw new Error("must not call"); } };
  for (const url of ["https://provider.example/subscription?secret=x", origin + "/sub/secret/clash", origin + "/agg/secret/clash",
    local + "?secret=x", local + "#fragment", local + "\n", "https://other.example/s/" + "a".repeat(22)]) {
    assert.equal(localShortlink(url, origin), false);
    assert.equal((await callShortlinkService({ service, token }, url, origin, operation)).kind, "fallback");
  }
  assert.equal((await callShortlinkService({ service }, local, origin, operation)).kind, "fallback");
  assert.equal(calls, 0);
  assert.equal(await wrapAuthorizedLocalShortlink({} as D1Database, "1", local, origin, { service, token }, async () => false), null);
  assert.equal(calls, 0);
});

test("authentication, forbidden domains and malformed success are terminal local fallbacks", async () => {
  const cases = [
    () => Response.json({ ok: false, error: { code: "TOKEN_INVALID" } }, { status: 401 }),
    () => Response.json({ ok: false, error: { code: "DOMAIN_FORBIDDEN" } }, { status: 403 }),
    () => Response.json({ ok: true, data: { domain: "gfw.mom", slug: "safe", short_url: "https://evil.example/safe" } }, { status: 201 }),
    () => Response.json({ ok: true, data: { domain: "gfw.mom", slug: "safe", short_url: "https://gfw.mom/safe" } }, { status: 200 }),
    () => new Response("x".repeat(8193), { status: 201, headers: { "content-type": "application/json" } }),
    () => Response.redirect("https://gfw.mom/other"),
  ];
  for (const response of cases) {
    assert.deepEqual(await callShortlinkService({ token, service: { createShortlink: async () => response() } }, local, origin, operation),
      { kind: "fallback", retryAfter: null, terminal: true });
  }
});

test("rate limits retain Retry-After; timeout and RPC exceptions allow only scheduled retry", async () => {
  assert.deepEqual(await callShortlinkService({ token, service: { createShortlink: async () => new Response(null,
    { status: 429, headers: { "Retry-After": "86400" } }) } }, local, origin, operation),
    { kind: "fallback", retryAfter: 86400, terminal: false });
  assert.deepEqual(await callShortlinkService({ token, service: { createShortlink: async () => new Response(null,
    { status: 503, headers: { "Retry-After": "7200" } }) } }, local, origin, operation),
    { kind: "fallback", retryAfter: 7200, terminal: false });
  for (const response of [async () => { throw new Error("synthetic secret must not escape"); },
    async () => new Promise<Response>(() => {})]) {
    assert.deepEqual(await callShortlinkService({ token, service: { createShortlink: response } }, local, origin, operation, 5),
      { kind: "fallback", retryAfter: 1, terminal: false });
  }
});
