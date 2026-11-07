import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

import { Miniflare } from "miniflare";

import worker from "../src/index.ts";
import { createSubscription, getSubscriptionSnapshot, MAX_CHUNK_BYTES, publishNodeSnapshot, readSnapshotNodes } from "../src/storage.ts";
import { parseNodeText } from "../src/text-import.ts";

const SS = "ss://YWVzLTI1Ni1nY206Zml4dHVyZQ@[2001:db8::5]:8388/?plugin=obfs-local%3Bobfs%3Dhttp#港 节点 😀";
const HOPPING = "hysteria2://user%40fixture:p%3A%2B%2F%25%E7%A7%98@[2001:db8::5]:443,5000-5002/" +
  "?sni=tls.example.invalid&insecure=1&obfs=salamander&obfs-password=fixture%2B%3B%25#%E9%A6%99%E6%B8%AF%20HY2";
const DEFAULT = "hy2://default.example.invalid#Default";
const LEGACY = "hy2://legacy.example.invalid:8443?auth=old%2Bkey&mport=5000-5002#Legacy";
const OPAQUE = "ssr://opaque-legacy-share#Legacy";

const base64 = (value: string) => Buffer.from(value).toString("base64");

function plain(nodes: readonly { share: string }[]): string[] {
  return nodes.map(({ share }) => share);
}

test("preserves exact trimmed shares and duplicate order across text and complete folded Base64", () => {
  const shares = [SS, HOPPING, DEFAULT, LEGACY, OPAQUE, SS];
  const text = " \uFEFF" + shares.join("\r\n") + " \t";
  const unicode = Buffer.from(text, "utf8");
  const folded = base64(text).match(/.{1,23}/gu)?.join("\r\n\t") ?? "";
  for (const [input, format] of [
    [text, "text"],
    [unicode, "text"],
    [folded, "base64"],
    [Buffer.from(text).toString("base64url"), "base64"],
    [base64(text).replace(/=+$/u, ""), "base64"],
  ] as const) {
    const result = parseNodeText(input);
    assert.equal(result.kind, "parsed");
    assert.equal(result.format, format);
    assert.deepEqual(result.rejected, { malformed: 0, unsupported: 0 });
    assert.equal(result.rawOnly, 3);
    assert.deepEqual(plain(result.nodes), shares);
    assert.equal(result.ndjsonBytes, Buffer.byteLength(result.nodes.map((node) => JSON.stringify(node)).join("\n") + "\n"));
    assert.deepEqual(result.nodes[1], {
      name: "香港 HY2", type: "hysteria2", share: HOPPING, server: "2001:db8::5", ports: "443,5000-5002",
      password: "user@fixture:p:+/%秘", sni: "tls.example.invalid", "skip-cert-verify": true,
      obfs: "salamander", "obfs-password": "fixture+;%",
    });
    assert.deepEqual(result.nodes[2], {
      name: "Default", type: "hysteria2", share: DEFAULT, server: "default.example.invalid",
      port: 443, password: "", sni: "", "skip-cert-verify": false,
    });
    assert.equal(result.nodes[3].ports, "5000-5002");
    assert.equal(result.nodes[3].password, "old+key");
  }
});

test("keeps safe scoped IPv6, certificate pin and inline ECH without rewriting the original", () => {
  const pin = "AB:".repeat(31) + "AB";
  const uri = `hy2://same%2Bkey@[fe80::1%25TestZone]:443,8443/?auth=same%2Bkey&pinSHA256=${pin}&%65ch=AAT-DQAA`;
  const result = parseNodeText(uri);
  assert.equal(result.kind, "parsed");
  assert.deepEqual(result.nodes[0], {
    name: "HY2 节点", type: "hysteria2", share: uri, server: "fe80::1%25TestZone", ports: "443,8443",
    password: "same+key", sni: "", "skip-cert-verify": false, fingerprint: "ab".repeat(32),
    "ech-opts": { enable: true, config: "AAT+DQAA" },
  });
});

test("reports malformed and unsupported URI candidates separately from prose, headers, and URLs", () => {
  const malformed = [
    "hy2://", "hy2:/malformed",
    "hy2://proxy.example.invalid:8443,443?mport=5000",
    "hy2://first@proxy.example.invalid?auth=second",
    "hy2://proxy.example.invalid?auth=one&%61uth=one",
    "hy2://proxy.example.invalid?auth=%ff",
    "hy2://proxy.example.invalid?obfs=salamander",
    "hy2://proxy.example.invalid/unsupported/path",
    "hy2://proxy.example.invalid?ech=%2Fpath%2Fsynthetic-fixture",
    "hy2://proxy.example.invalid?pinSHA256=::",
    "hy2://proxy.example.invalid:8443-443",
    "hy2://proxy.example.invalid#Line\u2028separation",
    "ss://aes-256-gcm:synthetic-private-field@proxy.example.invalid:8388/?plugin=%2Fsynthetic%2Fexe",
  ];
  const unsupported = [
    "hysteria2+realm+http://synthetic-private-field@realm.example.invalid/name",
    "hy2://proxy.example.invalid?future=synthetic-private-field",
    "hy2://proxy.example.invalid?obfs=unsupported&obfs-password=synthetic-private-field",
  ];
  const ignored = ["# nodes", "proxies:", "https://provider.example.invalid/synthetic-private-field", "prose containing " + SS];
  const input = [DEFAULT, ...malformed, ...unsupported, ...ignored, SS].join("\n");
  for (const text of [input, base64(input)]) {
    const result = parseNodeText(text);
    assert.equal(result.kind, "parsed");
    assert.deepEqual(result.rejected, { malformed: malformed.length, unsupported: unsupported.length });
    assert.equal(result.ignored, ignored.length);
    assert.deepEqual(plain(result.nodes), [DEFAULT, SS]);
    assert.doesNotMatch(JSON.stringify(result), /synthetic-private-field/u);
  }
  const invalid = parseNodeText(base64("hy2://"));
  assert.equal(invalid.kind, "no-nodes");
  assert.equal(invalid.format, "base64");
  assert.deepEqual(invalid.rejected, { malformed: 1, unsupported: 0 });
});

test("supports independent encoded lines and uses VMess profile labels while keeping raw capabilities", () => {
  const vmess = "vmess://" + base64(JSON.stringify({
    ps: "内层名字 😀", add: "vm.example.invalid", id: "synthetic-id", port: 443, net: "ws",
    path: "/synthetic-path", alpn: "h2,http/1.1",
  }));
  const encoded = base64("@ fixture comment\n" + vmess + "\n" + LEGACY);
  const result = parseNodeText(["# list", encoded, DEFAULT, "bm9kZS1mcmVlLXByb3Nl", OPAQUE].join("\n"));
  assert.equal(result.kind, "parsed");
  assert.equal(result.format, "text");
  assert.equal(result.ignored, 3);
  assert.equal(result.rawOnly, 2);
  assert.deepEqual(plain(result.nodes), [vmess, LEGACY, DEFAULT, OPAQUE]);
  assert.deepEqual(result.nodes[0], { name: "内层名字 😀", type: "vmess", share: vmess });
  const old = "vmess://" + Buffer.from(JSON.stringify({
    ps: "旧名字", add: "vm.example.invalid", id: "synthetic-id", port: "0443",
  }), "utf16le").toString("base64");
  assert.deepEqual(parseNodeText(old).nodes, [{ name: "旧名字", type: "vmess", share: old }]);
  assert.equal(parseNodeText("aHkyOi8v====").rejected.malformed, 0);
});

test("rejects invalid UTF-8 and discards all publishable nodes on every size or count limit", () => {
  const invalidUtf8 = new Uint8Array([0xef, 0xbb, 0xbf, 0xff]);
  assert.equal(parseNodeText(invalidUtf8).kind, "invalid-encoding");
  assert.equal(parseNodeText(DEFAULT + "\ud800").kind, "invalid-encoding");
  const invalidEncoded = Buffer.concat([Buffer.from(DEFAULT), Buffer.from([0xff])]).toString("base64");
  assert.equal(parseNodeText(invalidEncoded).kind, "invalid-encoding");
  const mixedEncoding = parseNodeText(SS + "\n" + invalidEncoded);
  assert.equal(mixedEncoding.kind, "invalid-encoding");
  assert.deepEqual(mixedEncoding.nodes, []);

  const bytes = Buffer.byteLength(SS);
  assert.equal(parseNodeText(SS, { maxInputBytes: bytes }).kind, "parsed");
  const oversizedInput = parseNodeText(SS, { maxInputBytes: bytes - 1 });
  const tooMany = parseNodeText([DEFAULT, LEGACY].join("\n"), { maxNodes: 1 });
  const largeLabel = DEFAULT + "x".repeat(MAX_CHUNK_BYTES / 2);
  const tooLargeForChunk = parseNodeText([SS, largeLabel].join("\n"), { maxInputBytes: MAX_CHUNK_BYTES });
  for (const [result, limit] of [[oversizedInput, "input-bytes"], [tooMany, "nodes"],
    [tooLargeForChunk, "node-bytes"]] as const) {
    assert.equal(result.kind, "limit");
    assert.equal(result.limit, limit);
    assert.deepEqual(result.nodes, []);
    assert.equal(result.ndjsonBytes, 0);
  }
  assert.throws(() => parseNodeText(SS, { maxNodes: 0 }), /Invalid node text import limits/u);
});

test("publishes parsed nodes through D1 and R2 and renders Base64 and safe Sing-box outputs", async () => {
  const miniflare = new Miniflare({
    modules: true,
    script: "export default { fetch() { return new Response(null); } };",
    compatibilityDate: "2026-07-30",
    d1Databases: ["DB"],
    r2Buckets: ["NODES"],
  });
  const fixedLength = Object.getOwnPropertyDescriptor(globalThis, "FixedLengthStream");
  try {
    const db = await miniflare.getD1Database("DB");
    const bucket = await miniflare.getR2Bucket("NODES");
    for (const name of ["0001_subscriptions.sql", "0003_subscription_lifecycle.sql"]) {
      const sql = await readFile(new URL(`../migrations/${name}`, import.meta.url), "utf8");
      await db.batch(sql.trim().split(/;\s*/u).filter(Boolean).map((statement) => db.prepare(statement)));
    }
    const subscription = await createSubscription(db, { ownerId: "76001", name: "Synthetic text import",
      sourceUrl: "uploaded://synthetic-text-import" });
    const shares = [SS, HOPPING, DEFAULT, LEGACY, OPAQUE, SS];
    const imported = parseNodeText(base64(shares.join("\n")));
    assert.equal(imported.kind, "parsed");
    const target = { id: subscription.id, ownerId: subscription.ownerId, expectedGeneration: 0, expectedLifecycleRevision: 0 };
    assert.equal(await publishNodeSnapshot(db, bucket, target, imported.nodes), true);
    const snapshot = await getSubscriptionSnapshot(db, subscription.token);
    assert.ok(snapshot);
    const restored = [];
    for await (const node of readSnapshotNodes(bucket, snapshot)) restored.push(node);
    assert.deepEqual(restored, imported.nodes);
    assert.equal(await publishNodeSnapshot(db, bucket, target, parseNodeText(DEFAULT).nodes), false);

    // Real response framing is covered by the hosted emitted-Worker test.
    class FixedLengthStreamShim extends TransformStream<Uint8Array, Uint8Array> {
      constructor(_length: number) {
        super();
      }
    }
    Object.defineProperty(globalThis, "FixedLengthStream", { value: FixedLengthStreamShim, configurable: true });
    const env = { DB: db, NODES: bucket };
    const base = `https://fixture.invalid/sub/${subscription.token}`;
    const response = await worker.fetch(new Request(base + "/base64"), env);
    assert.equal(response.status, 200);
    assert.equal(await response.text(), base64(shares.join("\n")));

    const unsupported = await worker.fetch(new Request(base + "/singbox"), env);
    assert.equal(unsupported.status, 422);
    assert.doesNotMatch(await unsupported.text(), /opaque-legacy-share|fixture%2B%3B%25/u);

    const supported = parseNodeText(shares.filter((share) => share !== OPAQUE).join("\n"));
    assert.equal(supported.kind, "parsed");
    assert.equal(await publishNodeSnapshot(db, bucket, { ...target, expectedGeneration: 1 }, supported.nodes), true);
    const singbox = await worker.fetch(new Request(base + "/singbox"), env);
    assert.equal(singbox.status, 200);
    const { outbounds } = await singbox.json() as { outbounds: Record<string, unknown>[] };
    assert.deepEqual(outbounds.slice(2).map(({ tag }) => tag), ["港 节点 😀", "香港 HY2", "Default", "Legacy", "港 节点 😀 (2)"]);
    assert.equal(outbounds[2].type, "shadowsocks");
    assert.equal(outbounds[2].plugin_opts, "obfs=http");
    assert.deepEqual(outbounds[3], {
      tag: "香港 HY2", type: "hysteria2", server: "2001:db8::5", server_ports: ["443:443", "5000:5002"],
      tls: { enabled: true, server_name: "tls.example.invalid", insecure: true },
      password: "user@fixture:p:+/%秘", obfs: { type: "salamander", password: "fixture+;%" },
    });
    assert.equal(outbounds[4].server_port, 443);
    assert.deepEqual(outbounds[5].server_ports, ["5000:5002"]);
    assert.equal(outbounds[5].password, "old+key");
  } finally {
    if (fixedLength) Object.defineProperty(globalThis, "FixedLengthStream", fixedLength);
    else Reflect.deleteProperty(globalThis, "FixedLengthStream");
    await miniflare.dispose();
  }
});
