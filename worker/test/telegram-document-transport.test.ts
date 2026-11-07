import assert from "node:assert/strict";
import { test } from "node:test";

import { downloadTelegramDocument, MAX_TELEGRAM_DOCUMENT_BYTES } from "../src/telegram/document-transport.ts";

const policy = { botId: "123456789", botToken: `123456789:${"a".repeat(35)}` };
const input = { fileId: "synthetic_file-id" };
const path = "documents/file_0.yaml";
const permanent = (reason: string) => ({ kind: "permanent", reason });
const retryable = (reason: string) => ({ kind: "retryable", reason });

function metadata(filePath = path, fileSize?: number): Response {
  return Response.json({ ok: true, result: { file_path: filePath, file_size: fileSize } });
}

function script(...steps: Array<Response | (() => Response)>): {
  request: typeof fetch;
  calls: Array<{ url: URL; init?: RequestInit }>;
} {
  const calls: Array<{ url: URL; init?: RequestInit }> = [];
  return {
    calls,
    request: async (url, init) => {
      const step = steps[calls.length];
      calls.push({ url: new URL(String(url)), init });
      if (!step) throw new Error("Unexpected synthetic HTTP request.");
      return typeof step === "function" ? step() : step;
    },
  };
}

function chunks(sizes: number[], init?: ResponseInit) {
  let index = 0;
  let canceled = false;
  const body = new ReadableStream<Uint8Array>({
    pull(controller) {
      if (index === sizes.length) controller.close();
      else controller.enqueue(new Uint8Array(sizes[index++]));
    },
    cancel() { canceled = true; },
  }, { highWaterMark: 0 });
  return { response: new Response(body, init), canceled: () => canceled };
}

test("downloads exact bytes using the configured bot, fixed origin, and one signal", async () => {
  const bytes = new TextEncoder().encode("合成节点\n");
  const { request, calls } = script(metadata(path, bytes.byteLength), new Response(bytes, {
    headers: { "Content-Length": String(bytes.byteLength) },
  }));
  assert.deepEqual(await downloadTelegramDocument(policy, { ...input, expectedSize: bytes.byteLength }, { request }),
    { kind: "downloaded", bytes });
  assert.equal(calls.length, 2);
  assert.deepEqual(calls.map(({ url }) => url.origin), ["https://api.telegram.org", "https://api.telegram.org"]);
  assert.deepEqual(calls.map(({ url }) => url.pathname), [`/bot${policy.botToken}/getFile`, `/file/bot${policy.botToken}/${path}`]);
  for (const { url, init } of calls) {
    assert.equal(url.search, "");
    assert.equal(url.hash, "");
    assert.equal(init?.cache, "no-store");
    assert.equal(init?.redirect, "manual");
    assert.equal(new Headers(init?.headers).get("Accept-Encoding"), "identity");
  }
  assert.equal(calls[0].init?.method, "POST");
  assert.deepEqual(JSON.parse(String(calls[0].init?.body)), { file_id: input.fileId });
  assert.equal(calls[1].init?.method, "GET");
  assert.equal(calls[1].init?.body, undefined);
  assert.ok(calls[0].init?.signal);
  assert.equal(calls[0].init?.signal, calls[1].init?.signal);
});

test("rejects invalid inputs before any network request", async () => {
  const { request, calls } = script();
  for (const [candidatePolicy, candidate] of [
    [{ ...policy, botId: "987654321" }, input],
    [{ ...policy, botToken: `${policy.botToken}/getMe` }, input],
    [policy, { fileId: "broken\n" }],
    [policy, { ...input, expectedSize: -1 }],
    [policy, { ...input, expectedSize: 1.25 }],
  ] as const) {
    assert.deepEqual(await downloadTelegramDocument(candidatePolicy, candidate, { request }), permanent("invalid-request"));
  }
  assert.deepEqual(await downloadTelegramDocument(policy, input, { request, timeoutMs: 20_001 }), permanent("invalid-request"));
  assert.deepEqual(await downloadTelegramDocument(policy, { ...input, expectedSize: MAX_TELEGRAM_DOCUMENT_BYTES + 1 },
    { request }), permanent("too-large"));
  assert.equal(calls.length, 0);
});

test("rejects absolute, ambiguous, and traversing paths before issuing a file request", async () => {
  for (const bad of ["https://example.invalid/private", "//example.invalid/private", "/documents/file.txt",
    "documents/../file.txt", "documents/./file.txt", "documents//file.txt", "documents/file.txt/",
    "documents\\file.txt", "documents/%2e%2e/file.txt", "documents/a%2fb.txt", "documents/a.txt?q=1",
    "documents/a.txt#fragment", "documents/a.txt\n", "documents/文件.txt", "a".repeat(129), ""]) {
    const { request, calls } = script(metadata(bad));
    assert.deepEqual(await downloadTelegramDocument(policy, input, { request }), permanent("invalid-response"));
    assert.equal(calls.length, 1);
  }
});

test("bounds and validates getFile metadata before contacting the file endpoint", async () => {
  const oversized = chunks([16 * 1024 + 1]);
  const malformed = [new Response("<html>synthetic</html>"), new Response(new Uint8Array([0xff])),
    Response.json({ ok: true, result: { file_size: 2 } }), Response.json({ ok: false }), metadata(path, -1),
    metadata(path, 2 ** 53), oversized.response];
  for (const response of malformed) {
    const { request, calls } = script(response);
    assert.deepEqual(await downloadTelegramDocument(policy, input, { request }), permanent("invalid-response"));
    assert.equal(calls.length, 1);
  }
  assert.ok(oversized.canceled());
  for (const [size, reason] of [[MAX_TELEGRAM_DOCUMENT_BYTES + 1, "too-large"], [1, "size-mismatch"]] as const) {
    const { request, calls } = script(metadata(path, size));
    assert.deepEqual(await downloadTelegramDocument(policy, { ...input, expectedSize: 2 }, { request }), permanent(reason));
    assert.equal(calls.length, 1);
  }
});

test("accepts the exact file limit and rejects either a larger declaration or an oversized stream", async () => {
  const atLimit = chunks(Array<number>(160).fill(64 * 1024));
  const exact = script(metadata(), atLimit.response);
  const result = await downloadTelegramDocument(policy, input, { request: exact.request });
  assert.equal(result.kind, "downloaded");
  if (result.kind === "downloaded") assert.equal(result.bytes.byteLength, MAX_TELEGRAM_DOCUMENT_BYTES);
  assert.equal(atLimit.canceled(), false);

  for (const body of [chunks([], { headers: { "Content-Length": String(MAX_TELEGRAM_DOCUMENT_BYTES + 1) } }),
    chunks([MAX_TELEGRAM_DOCUMENT_BYTES, 1])]) {
    const { request, calls } = script(metadata(), body.response);
    assert.deepEqual(await downloadTelegramDocument(policy, input, { request }), permanent("too-large"));
    assert.equal(calls.length, 2);
    assert.ok(body.canceled());
  }
});

test("rejects conflicting, truncated, or excessive file lengths and unexpected content coding", async () => {
  for (const [response, expected] of [
    [chunks([], { headers: { "Content-Length": "2" } }).response, permanent("size-mismatch")],
    [chunks([2]).response, permanent("size-mismatch")],
    [chunks([4]).response, permanent("size-mismatch")],
    [chunks([3], { headers: { "Content-Length": "3, 3" } }).response, permanent("invalid-response")],
    [chunks([3], { headers: { "Content-Encoding": "gzip" } }).response, permanent("invalid-response")],
  ] as const) {
    const { request } = script(metadata(), response);
    assert.deepEqual(await downloadTelegramDocument(policy, { ...input, expectedSize: 3 }, { request }), expected);
  }
  const { request } = script(metadata(), chunks([2], { headers: { "Content-Length": "3" } }).response);
  assert.deepEqual(await downloadTelegramDocument(policy, input, { request }), permanent("size-mismatch"));
});

test("classifies failures with fixed outcomes and never follows either redirect", async () => {
  const secret = "synthetic-secret-sentinel";
  for (const [status, expected] of [[302, permanent("invalid-response")], [400, permanent("rejected")],
    [403, permanent("rejected")], [404, permanent("rejected")], [408, retryable("unavailable")],
    [429, retryable("rate-limited")], [503, retryable("unavailable")]] as const) {
    for (const stage of [1, 2]) {
      const body = chunks([1], { status, headers: { Location: `https://example.invalid/${secret}` } });
      const { request, calls } = script(...(stage === 1 ? [body.response] : [metadata(), body.response]));
      assert.deepEqual(await downloadTelegramDocument(policy, input, { request }), expected);
      assert.equal(calls.length, stage);
      assert.ok(body.canceled());
    }
  }
  const fail = () => { throw new Error(`${policy.botToken}/${secret}/${input.fileId}`); };
  for (const steps of [[fail], [metadata(), fail]]) {
    const { request } = script(...steps);
    assert.deepEqual(await downloadTelegramDocument(policy, input, { request }), retryable("unavailable"));
  }
});

test("one deadline aborts a stalled body and cancels its stream", { timeout: 2_000 }, async () => {
  let canceled = false;
  const stalled = new Response(new ReadableStream({ cancel() { canceled = true; } }));
  const { request, calls } = script(metadata(), stalled);
  // Node's AbortSignal timeout alone does not keep the test process alive.
  const keepAlive = setTimeout(() => {}, 1_000);
  try {
    assert.deepEqual(await downloadTelegramDocument(policy, input, { request, timeoutMs: 100 }), retryable("timeout"));
    assert.equal(calls.length, 2);
    assert.equal(calls[0].init?.signal, calls[1].init?.signal);
    assert.ok(calls[1].init?.signal?.aborted);
    assert.ok(canceled);
  } finally {
    clearTimeout(keepAlive);
  }
});
