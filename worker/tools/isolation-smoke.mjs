import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";

const origin = "https://subs-bot-cf-dev-01.lilyya.workers.dev";
const fixture = JSON.parse(await readFile(process.argv[2], "utf8"));
assert.equal(fixture.revision, process.env.BUILD_REVISION, "Smoke fixture revision mismatch");

async function request(path, method = "GET") {
  const response = await fetch(origin + path, {
    method, redirect: "error", signal: AbortSignal.timeout(30_000),
  });
  const cache = (response.headers.get("cache-control") ?? "").split(",").map((part) => part.trim());
  assert(cache.includes("private") && cache.includes("no-store"), "Response is cacheable");
  assert.equal(response.headers.get("referrer-policy"), "no-referrer");
  return response;
}

const health = await request("/health");
assert.equal(health.status, 200);
const state = await health.json();
assert(state.ok === true && state.service === "subs-bot", "Unexpected health response");
assert(state.revision === fixture.revision, "The deployed Worker revision differs from the tested commit");

for (const [i, snapshot] of fixture.snapshots.entries()) {
  if (i === 1) assert(snapshot.nodeBytes > 2_000_000, "Large fixture must exceed the D1 row limit");
  const path = `/sub/${snapshot.token}/base64`;
  const response = await request(path);
  assert.equal(response.status, 200, "Synthetic snapshot export failed");
  assert.match(response.headers.get("content-type") ?? "", /^text\/plain\b/);
  const hash = createHash("sha256");
  let bytes = 0;
  for await (const chunk of response.body) {
    bytes += chunk.byteLength;
    assert(bytes <= snapshot.bodyBytes, "Export exceeded expected fixture size");
    hash.update(chunk);
  }
  assert.equal(bytes, snapshot.bodyBytes, "Snapshot response length differs");
  assert.equal(hash.digest("hex"), snapshot.bodySha256, "Snapshot response digest differs");
}

const head = await request(`/sub/${fixture.snapshots[0].token}/mixed`, "HEAD");
assert.equal(head.status, 200);
assert.equal(head.body, null);

const missing = await request("/sub/subsbot-synthetic-missing-01/base64");
assert.equal(missing.status, 404);
const unsupported = await request(`/sub/${fixture.snapshots[0].token}/singbox`);
assert.equal(unsupported.status, 406);

console.log("Cloudflare verified: exact revision, small and >2 MB private snapshots, HEAD alias, 404 and 406.");
