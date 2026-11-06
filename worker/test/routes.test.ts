import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { after, test } from "node:test";
import worker, { type Env } from "../src/index.ts";

const TOKEN = "synthetic-sub-token-01";
const REVISION = "a".repeat(40);
const SNAPSHOT_ID = "00000000-0000-4000-8000-000000000001";
const PREFIX = `subscriptions/42/${SNAPSHOT_ID}/`;
const LINK = "ss://YWVzLTI1Ni1nY206Zml4dHVyZQ@203.0.113.12:8388#";

// Node lacks the Worker constructor. Check byte-count and cancellation behavior here;
// the emitted Worker integration test checks actual workerd response framing.
class FixedLengthStreamShim {
  readonly readable: ReadableStream<Uint8Array>;
  readonly writable: WritableStream<Uint8Array>;

  constructor(length: number) {
    let written = 0;
    const stream = new TransformStream<Uint8Array, Uint8Array>({
      transform(chunk, controller) {
        written += chunk.byteLength;
        if (written > length) throw new Error("Too many response bytes.");
        controller.enqueue(chunk);
      },
      flush() {
        if (written !== length) throw new Error("Response byte count mismatch.");
      },
    });
    this.readable = stream.readable;
    this.writable = stream.writable;
  }
}

const originalFixedLengthStream = Object.getOwnPropertyDescriptor(globalThis, "FixedLengthStream");
Object.defineProperty(globalThis, "FixedLengthStream", { value: FixedLengthStreamShim, configurable: true });
after(() => {
  if (originalFixedLengthStream) Object.defineProperty(globalThis, "FixedLengthStream", originalFixedLengthStream);
  else Reflect.deleteProperty(globalThis, "FixedLengthStream");
});

function fixture(groups: Array<Array<Record<string, unknown>>>) {
  const objects = new Map<string, Buffer>();
  const hash = (data: Buffer) => createHash("sha256").update(data).digest("hex");
  const chunks = groups.map((nodes, index) => {
    const bytes = Buffer.from(nodes.map((node) => JSON.stringify(node)).join("\n") + "\n");
    objects.set(`${PREFIX}${index}.ndjson`, bytes);
    return { bytes: bytes.length, sha256: hash(bytes), count: nodes.length };
  });
  const manifest = Buffer.from(JSON.stringify({ version: 1, chunks }));
  objects.set(`${PREFIX}manifest.json`, manifest);
  const snapshot = {
    id: 42,
    generation: 1,
    snapshotId: SNAPSHOT_ID,
    manifestSha256: hash(manifest),
    nodeCount: chunks.reduce((total, { count }) => total + count, 0),
  };
  const lookups: string[] = [];
  const reads: string[] = [];
  const DB = {
    prepare() {
      return { bind: (token: string) => ({
        first: async () => {
          lookups.push(token);
          return token === TOKEN ? snapshot : null;
        },
      }) };
    },
  } as unknown as Env["DB"];
  const NODES = {
    async get(key: string) {
      reads.push(key);
      const bytes = objects.get(key);
      return bytes === undefined ? null : {
        size: bytes.byteLength,
        arrayBuffer: async () => Uint8Array.from(bytes).buffer,
        body: { cancel: async () => {} },
      };
    },
  } as unknown as Env["NODES"];
  return { env: { DB, NODES, BUILD_REVISION: REVISION }, objects, lookups, reads };
}

function request(path: string, env: Env, method = "GET") {
  return worker.fetch(new Request(`https://subs-bot.example${path}`, { method }), env);
}

function assertPrivate(response: Response) {
  assert.equal(response.headers.get("cache-control"), "private, no-store");
  assert.equal(response.headers.get("referrer-policy"), "no-referrer");
  assert.equal(response.headers.get("x-content-type-options"), "nosniff");
}

test("health exposes only the exact build revision and rejects invalid configuration", async () => {
  const { env, lookups, reads } = fixture([[{ share: LINK }]]);
  const healthy = await request("/health", env);
  assert.equal(healthy.status, 200);
  assertPrivate(healthy);
  assert.deepEqual(await healthy.json(), { ok: true, service: "subs-bot", revision: REVISION });

  const invalid = await request("/health", { ...env, BUILD_REVISION: "synthetic-invalid-secret" });
  assert.equal(invalid.status, 503);
  assertPrivate(invalid);
  assert.equal(await invalid.text(), "Service unavailable.");
  assert.deepEqual(lookups, []);
  assert.deepEqual(reads, []);
});

test("subscription aliases stream identical Base64 across UTF-8 and R2 chunk boundaries", async () => {
  const first = LINK + "x".repeat(24 * 1024 - LINK.length - 1) + "香港";
  const links = [first, `${LINK}第二条`, `${LINK}third`];
  const { env, reads } = fixture([[{ share: links[0] }], [{ share: links[1] }, { share: links[2] }]]);
  const expected = Buffer.from(links.join("\n")).toString("base64");
  const pass = ["manifest.json", "0.ndjson", "1.ndjson"].map((name) => PREFIX + name);
  for (const kind of ["base64", "mixed", "V2Ray"]) {
    const before = reads.length;
    const response = await request(`/sub/${TOKEN}/${kind}`, env);
    assert.equal(response.status, 200);
    assertPrivate(response);
    assert.equal(response.headers.get("content-type"), "text/plain; charset=utf-8");
    assert.equal(await response.text(), expected);
    assert.deepEqual(reads.slice(before), [...pass, ...pass]);
  }

  const beforeHead = reads.length;
  const head = await request(`/sub/${TOKEN}/base64`, env, "HEAD");
  assert.equal(head.status, 200);
  assertPrivate(head);
  assert.equal(head.body, null);
  assert.deepEqual(reads.slice(beforeHead), pass);
});

test("wrong capabilities and unavailable formats never read private objects", async () => {
  const { env, lookups, reads } = fixture([[{ share: LINK }]]);
  const wrongToken = "other-sub-token-000000";
  const notFound = await request(`/sub/${wrongToken}/base64`, env);
  assert.equal(notFound.status, 404);
  assertPrivate(notFound);
  assert.equal(await notFound.text(), "Not found.");
  assert.equal((await request(`/sub/${TOKEN}/singbox`, env)).status, 406);
  assert.equal((await request(`/sub/${TOKEN}`, env)).status, 406);
  const post = await request(`/sub/${TOKEN}/base64`, env, "POST");
  assert.equal(post.status, 405);
  assert.equal(post.headers.get("allow"), "GET, HEAD");
  assert.deepEqual(lookups, [wrongToken]);
  assert.deepEqual(reads, []);
});

test("malformed links and corrupt or missing snapshots fail without partial credentials", async () => {
  const invalid = fixture([[{ share: LINK }], [{ share: `${LINK}bad\n${LINK}injected` }]]);
  const unsupported = await request(`/sub/${TOKEN}/base64`, invalid.env);
  assert.equal(unsupported.status, 422);
  assertPrivate(unsupported);
  assert.equal(await unsupported.text(), "Subscription content cannot be exported.");

  const corrupt = fixture([[{ share: LINK }], [{ share: LINK }]]);
  const key = `${PREFIX}1.ndjson`;
  const original = corrupt.objects.get(key)!;
  const changed = Buffer.from(original);
  changed[changed.length - 2] = 33;
  corrupt.objects.set(key, changed);
  for (const missing of [false, true]) {
    if (missing) corrupt.objects.delete(key);
    const unavailable = await request(`/sub/${TOKEN}/base64`, corrupt.env);
    assert.equal(unavailable.status, 503);
    assertPrivate(unavailable);
    assert.equal(await unavailable.text(), "Subscription temporarily unavailable.");
  }
});

test("preflights legacy authority and ECH validity for every alias without leaking private content", async () => {
  const hopping = "hysteria2://fixture:pass@[2001:db8::5]:443,8443-8445/?ech=AAT-DQAA#港 😀";
  const stored = fixture([[{ share: LINK }, { share: hopping }]]);
  const response = await request("/sub/" + TOKEN + "/mixed", stored.env);
  assert.equal(response.status, 200);
  assertPrivate(response);
  assert.equal(Buffer.from(await response.text(), "base64").toString("utf8"), LINK + "\n" + hopping);

  const invalidLinks = [
    "hy2://fixture-secret@proxy.example.invalid?ech=%2Ffixture%2Fsecret-path",
    "trojan://proxy.example.invalid:443#fixture-secret",
    "ss://fixture-secret",
  ];
  for (const invalid of invalidLinks) {
    const rejected = fixture([[{ share: LINK }], [{ share: invalid }]]);
    const result = await request("/sub/" + TOKEN + "/v2ray", rejected.env);
    assert.equal(result.status, 422);
    assertPrivate(result);
    assert.equal(await result.text(), "Subscription content cannot be exported.");
    assert.deepEqual(rejected.reads, ["manifest.json", "0.ndjson", "1.ndjson"].map((name) => PREFIX + name));
    const head = await request("/sub/" + TOKEN + "/base64", rejected.env, "HEAD");
    assert.equal(head.status, 422);
    assertPrivate(head);
    assert.equal(head.body, null);
  }
});

test("a second-pass R2 failure errors the body after earlier bytes without exposing backend details", async () => {
  const first = LINK + "x".repeat(24 * 1024);
  const { env } = fixture([[{ share: first }], [{ share: `${LINK}later` }]]);
  const get = env.NODES.get.bind(env.NODES);
  let reads = 0;
  env.NODES.get = async (key: string) => {
    if (key === `${PREFIX}1.ndjson` && ++reads === 2) throw new Error("synthetic backend credential");
    return get(key);
  };

  const response = await request(`/sub/${TOKEN}/base64`, env);
  assert.equal(response.status, 200);
  assertPrivate(response);
  const reader = response.body!.getReader();
  const chunk = await reader.read();
  assert.equal(chunk.done, false);
  assert.equal(Buffer.from(chunk.value!).toString(), Buffer.from(first).subarray(0, 24 * 1024).toString("base64"));
  await assert.rejects(reader.read(), { message: "Subscription stream failed." });
  assert.equal(reads, 2);
});

test("canceling a response stops reads beyond the current lookahead window", async () => {
  const first = LINK + "x".repeat(4 * 24 * 1024);
  const { env, reads } = fixture([
    [{ share: first }], ...Array.from({ length: 4 }, (_, index) => [{ share: `${LINK}later${index}` }]),
  ]);
  const response = await request(`/sub/${TOKEN}/base64`, env);
  assert.equal(response.status, 200);
  const reader = response.body!.getReader();
  assert.equal((await reader.read()).done, false);
  await reader.cancel();
  assert.equal((await reader.read()).done, true);
  const pass = ["manifest.json", "0.ndjson", "1.ndjson", "2.ndjson", "3.ndjson", "4.ndjson"].map((name) => PREFIX + name);
  assert.deepEqual(reads, [...pass, ...pass.slice(0, -1)]);
});
