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
      return { bind: (token: string) => ({ token, first: async () => null }) };
    },
    async batch([{ token }]: { token: string }[]) {
      lookups.push(token);
      return [{ success: true, results: token === TOKEN ? [snapshot] : [] }, { success: true, results: [] }];
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

test("streams structured fallback and preserves a valid stored share in the same snapshot", async () => {
  const structured = { type: "ss", server: "203.0.113.10", port: 8388, name: "港 + 字", cipher: "aes-256-gcm", password: "fixture-only" };
  const stored = "vless://synthetic-client@bücher.example:443#原始标签 😀";
  const generated = "ss://YWVzLTI1Ni1nY206Zml4dHVyZS1vbmx5@203.0.113.10:8388#%E6%B8%AF%20%2B%20%E5%AD%97";
  const { env } = fixture([
    [structured, { ...structured, share: null }],
    [{ ...structured, type: "unknown", share: stored }, { ...structured, share: "" }],
  ]);
  const response = await request(`/sub/${TOKEN}/mixed`, env);
  assert.equal(response.status, 200);
  assertPrivate(response);
  assert.equal(await response.text(), Buffer.from([generated, generated, stored, generated].join("\n")).toString("base64"));
  const head = await request(`/sub/${TOKEN}/v2ray`, env, "HEAD");
  assert.equal(head.status, 200);
  assertPrivate(head);
  assert.equal(head.body, null);

  for (const invalid of [
    { ...structured, share: "ss://malformed-fixture" },
    { ...structured, share: false },
    { ...structured, server: "faß.example" },
    { ...structured, plugin: "v2ray-plugin", plugin_opts: "tls;cert=/path/to/synthetic-fixture" },
  ]) {
    const rejected = fixture([[{ share: stored }], [invalid]]);
    const response = await request(`/sub/${TOKEN}/base64`, rejected.env);
    assert.equal(response.status, 422);
    assertPrivate(response);
    assert.equal(await response.text(), "Subscription content cannot be exported.");
  }
});

test("applies the 16 MiB limit to serialized URI bytes and separators", async () => {
  const maximum = 16 * 1024 * 1024;
  const base = { type: "ss", server: "203.0.113.10", port: 8388, cipher: "aes-256-gcm", password: "fixture-only" };
  const prefixBytes = "ss://YWVzLTI1Ni1nY206Zml4dHVyZS1vbmx5@203.0.113.10:8388#".length;
  const fullName = "字".repeat(170_000);
  const fullShareBytes = prefixBytes + 9 * fullName.length;
  const remaining = maximum - (10 * (fullShareBytes + 1)) - prefixBytes;
  const finalName = "字".repeat(Math.floor(remaining / 9)) + "x".repeat(remaining % 9);
  const groups = Array.from({ length: 10 }, () => [{ ...base, name: fullName }]);
  for (const over of [false, true]) {
    const { env } = fixture([...groups, [{ ...base, name: over ? finalName + "x" : finalName }]]);
    const response = await request(`/sub/${TOKEN}/base64`, env, "HEAD");
    assert.equal(response.status, over ? 422 : 200);
    assertPrivate(response);
    assert.equal(response.body, null);
  }
});

test("wrong capabilities and unavailable formats never read private objects", async () => {
  const { env, lookups, reads } = fixture([[{ share: LINK }]]);
  const wrongToken = "other-sub-token-000000";
  const notFound = await request(`/sub/${wrongToken}/base64`, env);
  assert.equal(notFound.status, 404);
  assertPrivate(notFound);
  assert.equal(await notFound.text(), "Not found.");
  assert.equal((await request("/sub/" + TOKEN + "/unsupported", env)).status, 406);
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

test("preserves allowed Shadowsocks plugins and rejects a legacy plugin concealed by a fragment", async () => {
  const user = "aes-256-gcm:fixture:p@ss@proxy.example.invalid:8388";
  const legacy = (plugin: string) => "ss://" + Buffer.from(
    `${user}/?plugin=${plugin}#@display.example.invalid:8388`,
  ).toString("base64url") + "#港 节点";
  const permitted = legacy("obfs-local%3Bobfs%3Dhttp");
  const permittedSnapshot = fixture([[{ share: LINK }, { share: permitted }]]);
  const response = await request(`/sub/${TOKEN}/mixed`, permittedSnapshot.env);
  assert.equal(response.status, 200);
  assertPrivate(response);
  assert.equal(Buffer.from(await response.text(), "base64").toString("utf8"), LINK + "\n" + permitted);

  for (const denied of [
    legacy("v2ray-plugin%3Btls%3Bcert%3D%2Fpath%2Fsynthetic-cert"),
    "ss://" + Buffer.from("aes-256-gcm:fixture:p@ss/字#?@192.0.2.40:443").toString("base64url"),
  ]) {
    const deniedSnapshot = fixture([[{ share: LINK }], [{ share: denied }]]);
    const get = await request(`/sub/${TOKEN}/v2ray`, deniedSnapshot.env);
    assert.equal(get.status, 422);
    assertPrivate(get);
    assert.equal(await get.text(), "Subscription content cannot be exported.");
    const head = await request(`/sub/${TOKEN}/base64`, deniedSnapshot.env, "HEAD");
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

test("Sing-box aliases preflight exact names and credentials before streaming JSON", async () => {
  const node = { type: "ss", server: "203.0.113.12", port: 8388, cipher: "aes-256-gcm", password: "fixture:港🌐" };
  const { env, reads } = fixture([[{ ...node, name: "proxy" }, { ...node, name: "港" }], [{ ...node, name: "港" }]]);
  const pass = ["manifest.json", "0.ndjson", "1.ndjson"].map((name) => PREFIX + name);
  const primary = "/sub/" + TOKEN + "/singbox";
  const alias = "/sub/" + TOKEN + "/SING-BOX";
  const head = await request(alias, env, "HEAD");
  assert.equal(head.status, 200);
  assert.equal(head.body, null);
  assertPrivate(head);
  assert.deepEqual(reads.splice(0), pass);

  const response = await request(primary, env);
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("content-type"), "application/json");
  assertPrivate(response);
  const body = await response.text();
  const config = JSON.parse(body);
  const tags = ["proxy (2)", "港", "港 (2)"];
  assert.deepEqual(config.outbounds[0], { type: "selector", tag: "proxy", outbounds: tags });
  assert.deepEqual(config.outbounds[1], { type: "direct", tag: "direct" });
  assert.deepEqual(config.outbounds.slice(2).map((outbound: { tag: string }) => outbound.tag), tags);
  assert.deepEqual(config.outbounds.slice(2).map((outbound: { password: string }) => outbound.password),
    Array(3).fill(node.password));
  assert.deepEqual(reads, [...pass, ...pass]);

  const rejected = fixture([[node], [{ share: "hy2://fixture@proxy.example.invalid?ech=AAT-DQAA" }]]);
  for (const method of ["GET", "HEAD"]) {
    const invalid = await request(alias, rejected.env, method);
    assert.equal(invalid.status, 422);
    assertPrivate(invalid);
    if (method === "HEAD") assert.equal(invalid.body, null);
    else assert.equal(await invalid.text(), "Subscription content cannot be exported.");
  }
});

test("Sing-box enforces format-specific name and response budgets during preflight", async () => {
  const node = { type: "ss", server: "203.0.113.12", port: 8388, cipher: "aes-256-gcm", password: "fixture-only" };
  const name = "港".repeat(340) + "xy";
  const path = "/sub/" + TOKEN + "/singbox";
  for (const [label, status] of [[name, 200], [name + "z", 422]] as const) {
    const { env } = fixture([[{ ...node, name: label }]]);
    assert.equal((await request(path, env, "HEAD")).status, status);
  }
  const largeNode = { ...node, password: "x".repeat(500_000) };
  for (const [count, status] of [[33, 200], [34, 422]]) {
    const { env } = fixture(Array.from({ length: count }, (_, index) => [{ ...largeNode, name: "node-" + index }]));
    assert.equal((await request(path, env, "HEAD")).status, status);
  }
});

test("Sing-box aborts a late corrupted body without returning complete JSON", async () => {
  const { env } = fixture([[{ share: LINK }], [{ share: LINK }]]);
  const get = env.NODES.get.bind(env.NODES);
  let reads = 0;
  env.NODES.get = async (key: string) => {
    if (key === PREFIX + "1.ndjson" && ++reads === 2) throw new Error("synthetic backend credential");
    return get(key);
  };
  const response = await request("/sub/" + TOKEN + "/singbox", env);
  assert.equal(response.status, 200);
  const reader = response.body!.getReader();
  assert.equal((await reader.read()).done, false);
  assert.equal((await reader.read()).done, false);
  await assert.rejects(reader.read(), { message: "Subscription stream failed." });
  assert.equal(reads, 2);
});

test("Sing-box caps expanded Hysteria hopping entries across the whole response", async () => {
  const node = { type: "hysteria2", server: "hy2.example.invalid", tls: { enabled: true } };
  const full = Array.from({ length: 16 }, () => ({ ...node, server_ports: ["1:65535"] }));
  // 16 full ranges and 16 entries reach 1,048,576; the next entry is rejected.
  for (const [range, status] of [["443:458", 200], ["443:459", 422]]) {
    const { env } = fixture([[...full, { ...node, server_ports: [range] }]]);
    const response = await request("/sub/" + TOKEN + "/singbox", env, "HEAD");
    assert.equal(response.status, status);
    assert.equal(response.body, null);
  }
});

test("the default and explicit Clash routes stream the same bounded private YAML", async () => {
  const node = { type: "ss", server: "203.0.113.12", port: 8388, cipher: "aes-256-gcm", password: "fixture:港\u0085🌐" };
  const { env, reads } = fixture([[{ ...node, name: "DIRECT" }], [{ ...node, name: "DIRECT (2)" }]]);
  const pass = ["manifest.json", "0.ndjson", "1.ndjson"].map((name) => PREFIX + name);
  const path = "/sub/" + TOKEN;
  const alias = path + "/cLaSh";
  const head = await request(alias, env, "HEAD");
  assert.equal(head.status, 200);
  assert.equal(head.body, null);
  assertPrivate(head);
  assert.deepEqual(reads.splice(0), pass);
  const response = await request(path, env);
  const alternate = await request(alias, env);
  assert.equal(response.status, 200);
  assert.equal(alternate.status, 200);
  assert.equal(response.headers.get("content-type"), "text/yaml; charset=utf-8");
  assertPrivate(response);
  const yaml = await response.text();
  assert.equal(await alternate.text(), yaml);
  assert.match(yaml, /^proxies:\n/u);
  assert(yaml.includes('"name":"DIRECT (3)"') && yaml.includes('"name":"DIRECT (2)"'));
  assert(yaml.includes('"proxies":["DIRECT (3)","DIRECT (2)"]'));
  assert(yaml.includes("fixture:港\\u0085🌐"));
  assert.deepEqual(reads, [...pass, ...pass, ...pass, ...pass]);
});

test("Clash rejects lossy input before success and aborts a failed second snapshot pass", async () => {
  const path = "/sub/" + TOKEN;
  const bad = fixture([[{ share: LINK }], [{ share: "hy2://fixture@hy.example.invalid?pinSHA256=" + "ab".repeat(32) }]]);
  const rejected = await request(path, bad.env);
  assert.equal(rejected.status, 422);
  assert.equal(await rejected.text(), "Subscription content cannot be exported.");
  assertPrivate(rejected);

  const missing = await request("/sub/other-sub-token-000000", bad.env, "HEAD");
  assert.equal(missing.status, 404);
  assert.equal(missing.body, null);

  const { env } = fixture([[{ share: LINK }], [{ share: LINK }]]);
  const get = env.NODES.get.bind(env.NODES);
  let reads = 0;
  env.NODES.get = async (key: string) => {
    if (key === PREFIX + "1.ndjson" && ++reads === 2) throw new Error("synthetic backend credential");
    return get(key);
  };
  const response = await request(path, env);
  assert.equal(response.status, 200);
  const reader = response.body!.getReader();
  assert.equal(new TextDecoder().decode((await reader.read()).value), "proxies:\n");
  assert.equal((await reader.read()).done, false);
  await assert.rejects(reader.read(), { message: "Subscription stream failed." });
  assert.equal(reads, 2);
});

test("Clash limits serialized names and aggregate hopping expansion during preflight", async () => {
  const path = "/sub/" + TOKEN;
  const name = "港".repeat(340) + "xy";
  for (const [label, status] of [[name, 200], [name + "z", 422]] as const) {
    const { env } = fixture([[{ name: label, share: LINK }]]);
    assert.equal((await request(path, env, "HEAD")).status, status);
  }
  const node = { type: "hysteria2", server: "hy2.example.invalid" };
  const full = Array.from({ length: 16 }, () => ({ ...node, ports: "1-65535" }));
  for (const [ports, status] of [["443-458", 200], ["443-459", 422]]) {
    const { env } = fixture([[...full, { ...node, ports }]]);
    assert.equal((await request(path, env, "HEAD")).status, status);
  }
});

test("Surge preserves private group references and QX aliases preserve exact native lines", async () => {
  const node = { type: "ss", server: "203.0.113.12", port: 8388, cipher: "aes-256-gcm", password: "fixture:港🌐" };
  const { env, reads } = fixture([[{ ...node, name: "direct" }], [{ ...node, name: "DIRECT (2)" }]]);
  const pass = ["manifest.json", "0.ndjson", "1.ndjson"].map((name) => PREFIX + name);
  const path = "/sub/" + TOKEN + "/";
  const head = await request(path + "Surge", env, "HEAD");
  assert.equal(head.status, 200);
  assert.equal(head.body, null);
  assertPrivate(head);
  assert.deepEqual(reads.splice(0), pass);
  const surge = await request(path + "Surge", env);
  assert.equal(surge.status, 200);
  assertPrivate(surge);
  assert.equal(await surge.text(), "[Proxy]\n"
    + "direct (3) = ss, 203.0.113.12, 8388, encrypt-method=aes-256-gcm, password=fixture:港🌐\n"
    + "DIRECT (2) = ss, 203.0.113.12, 8388, encrypt-method=aes-256-gcm, password=fixture:港🌐\n\n"
    + "[Proxy Group]\nProxy = select, direct (3), DIRECT (2)\n\n[Rule]\nFINAL,Proxy\n");
  assert.deepEqual(reads.splice(0), [...pass, ...pass]);
  const qx = "shadowsocks=203.0.113.12:8388, method=aes-256-gcm, password=fixture:港🌐, tag=direct (3)\n"
    + "shadowsocks=203.0.113.12:8388, method=aes-256-gcm, password=fixture:港🌐, tag=DIRECT (2)\n";
  for (const suffix of ["qx", "Quantumult", "QUANTUMULTX"]) {
    const result = await request(path + suffix, env);
    assert.equal(result.status, 200);
    assertPrivate(result);
    assert.equal(await result.text(), qx);
  }
  assert.equal((await request(path + "quantumult-x", env)).status, 406);
});

test("text exports refuse a mixed unsupported snapshot and a corrupted or oversized response", async () => {
  const path = "/sub/" + TOKEN + "/";
  for (const format of ["surge", "qx"]) {
    const bad = fixture([[{ share: LINK }], [{ share: "ssr://fixture-secret" }]]);
    const rejected = await request(path + format, bad.env);
    assert.equal(rejected.status, 422);
    assert.equal(await rejected.text(), "Subscription content cannot be exported.");
    assertPrivate(rejected);
    const head = await request(path + format, bad.env, "HEAD");
    assert.equal(head.status, 422);
    assert.equal(head.body, null);
    const broken = fixture([[{ share: LINK }]]);
    broken.objects.delete(PREFIX + "0.ndjson");
    assert.equal((await request(path + format, broken.env)).status, 503);
  }

  const node = { type: "ss", server: "203.0.113.12", port: 8388, cipher: "aes-256-gcm" };
  const prefix = "node = ss, 203.0.113.12, 8388, encrypt-method=aes-256-gcm, password=";
  const size = 64 * 1024 - prefix.length - 1;
  for (const [bytes, status] of [[size, 200], [size + 1, 422]]) {
    const { env } = fixture([[{ ...node, name: "node", password: "x".repeat(bytes) }]]);
    assert.equal((await request(path + "surge", env, "HEAD")).status, status);
  }
  const group = Array.from({ length: 100 }, (_, index) => ({ ...node, name: "x".repeat(700) + index, password: "fixture" }));
  const { env } = fixture([group]);
  assert.equal((await request(path + "surge", env, "HEAD")).status, 422);
  assert.equal((await request(path + "qx", env, "HEAD")).status, 200);
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
