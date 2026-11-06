import assert from "node:assert/strict";
import { createHash } from "node:crypto";

export async function verifyIsolation(fixture, revision, fetchRequest) {
  assert.match(revision ?? "", /^[a-f0-9]{40}$/, "Missing full build revision");
  assert.equal(fixture.revision, revision, "Smoke fixture revision mismatch");

  async function request(path, method = "GET") {
    const response = await fetchRequest(path, {
      method, redirect: "error", signal: AbortSignal.timeout(30_000),
      headers: { "Accept-Encoding": "identity" },
    });
    const cache = (response.headers.get("cache-control") ?? "").split(",").map((part) => part.trim());
    assert(cache.includes("private") && cache.includes("no-store"), "Response is cacheable");
    assert.equal(response.headers.get("referrer-policy"), "no-referrer");
    assert.equal(response.headers.get("x-content-type-options"), "nosniff");
    return response;
  }

  const health = await request("/health");
  assert.equal(health.status, 200);
  const state = await health.json();
  assert(state.ok === true && state.service === "subs-bot", "Unexpected health response");
  assert(state.revision === revision, "The running Worker revision differs from the tested commit");

  assert(fixture.snapshots.some((snapshot) => snapshot.nodeBytes > 2_000_000),
    "Large fixture must exceed the D1 row limit");
  for (const snapshot of fixture.snapshots) {
    const response = await request(`/sub/${snapshot.token}/base64`);
    assert.equal(response.status, 200, "Synthetic snapshot export failed");
    assert.match(response.headers.get("content-type") ?? "", /^text\/plain\b/);
    assert.equal(response.headers.get("content-length"), String(snapshot.bodyBytes),
      "The response did not declare the verified export length");
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
  await missing.body?.cancel();
  const singBox = await request(`/sub/${fixture.snapshots[0].token}/singbox`);
  assert.equal(singBox.status, 200, "Synthetic Sing-box export failed");
  assert.equal(singBox.headers.get("content-type"), "application/json");
  const config = await singBox.json();
  assert(Array.isArray(config.outbounds) && config.outbounds.length === fixture.snapshots[0].nodeCount + 2
    && config.outbounds[0]?.type === "selector" && config.outbounds[0]?.tag === "proxy"
    && config.outbounds[1]?.type === "direct" && config.outbounds[1]?.tag === "direct"
    && config.outbounds.slice(2).every((outbound) => outbound?.type === "shadowsocks" && outbound?.server === "203.0.113.10"),
  "Unexpected synthetic Sing-box configuration");
  const unsupported = await request(`/sub/${fixture.snapshots[0].token}/clash`);
  assert.equal(unsupported.status, 406);
  await unsupported.body?.cancel();
}
