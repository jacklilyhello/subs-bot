import assert from "node:assert/strict";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { Miniflare } from "miniflare";
import { serializeClashProxy } from "../src/clash-export.ts";
import { serializeSingBoxOutbound } from "../src/singbox-export.ts";
import { MAX_CHUNK_BYTES } from "../src/storage.ts";
import { parseStructuredNodeDocument as parse } from "../src/structured-import.ts";

const ss = {
  name: "合成节点 😀", type: "ss", server: "203.0.113.10", port: 8388, cipher: "aes-256-gcm", password: "fixture-only",
};
const ssYaml = "{name: example, type: ss, server: 203.0.113.10, port: 8388, cipher: aes-256-gcm, password: fixture-only}";
const uri = "ss://YWVzLTI1Ni1nY206Zml4dHVyZS1vbmx5@203.0.113.10:8388";

test("imports only Clash proxies and preserves structured credentials and options", () => {
  const data = `\ufeff# Provider fixture
proxies:
  - name: "合成节点 😀"
    type: ss
    server: 203.0.113.10
    port: 8388
    cipher: aes-256-gcm
    password: fixture-only
    plugin: obfs
    plugin-opts: {mode: http, host: fixture.example}
proxy-groups:
  - ${ssYaml}
rules: [MATCH, DIRECT]
notes: |
  ${uri}
`;
  const result = parse(new TextEncoder().encode(data));
  assert.equal(result.kind, "parsed");
  assert.equal(result.format, "clash");
  assert.equal(result.nodes.length, 1);
  const node = result.nodes[0];
  assert.equal(node.share, "");
  assert.equal(node.name, ss.name);
  assert.equal(node.password, ss.password);
  assert.equal((node["plugin-opts"] as Record<string, string>).host, "fixture.example");
  assert.equal(serializeClashProxy(node).proxy.port, 8388);
  assert.equal(result.ndjsonBytes, Buffer.byteLength(JSON.stringify(node)) + 1);
});

test("accepts standalone YAML and JSON lists and supports a strict JSON hint", () => {
  assert.equal(parse(`- ${ssYaml}\n`).kind, "parsed");
  assert.equal(parse(`[${ssYaml}]`, { maxDepth: 2 }).kind, "parsed");
  assert.deepEqual(parse(JSON.stringify([ss]), { syntax: "json" }).nodes, [{ ...ss, share: "" }]);
  assert.deepEqual(parse(JSON.stringify({ proxies: [ss] })).nodes, [{ ...ss, share: "" }]);
  assert.equal(parse(`[${JSON.stringify(ss)},]`, { syntax: "json" }).kind, "malformed");
});

test("imports native Sing-box fields and skips routing-only outbounds", () => {
  const native = { type: "hysteria2", tag: "合成 H2", server: "203.0.113.11", server_ports: ["443:445"],
    hop_interval: "7s", password: "synthetic-only", tls: { enabled: true, server_name: "fixture.example" } };
  const controls = ["direct", "block", "dns", "selector", "urltest"].map((type) => ({ type, tag: type, outbounds: [native.tag] }));
  const result = parse(JSON.stringify({ inbounds: [native], outbounds: [...controls, native], route: { rules: [native] } }), { syntax: "json" });
  assert.equal(result.kind, "parsed");
  assert.equal(result.format, "singbox");
  assert.equal(result.ignored, controls.length);
  assert.equal(result.nodes.length, 1);
  const node = result.nodes[0];
  assert.equal(node.name, native.tag);
  assert.equal(node.tag, undefined);
  assert.deepEqual(node.server_ports, native.server_ports);
  assert.equal(node.share, "");
  const { tag: _, ...expected } = native;
  assert.deepEqual(JSON.parse(serializeSingBoxOutbound(node).json), expected);
});

test("reports malformed and unsupported rows without importing metadata or URI overrides", () => {
  const result = parse(JSON.stringify({ proxies: [
    ss, { ...ss, port: 0 }, { ...ss, type: "fixture-unknown" }, { ...ss, share: uri },
    { ...ss, server: "https://fixture.example" }, null,
  ] }));
  assert.equal(result.kind, "parsed");
  assert.deepEqual(result.nodes, [{ ...ss, share: "" }]);
  assert.deepEqual(result.rejected, { malformed: 3, unsupported: 2 });
  assert.equal(parse(`proxies: {}\nnotes: ${uri}`).kind, "malformed");
  assert.equal(parse(`proxies: []\noutbounds: []`).kind, "malformed");
  assert.equal(parse(`proxies: []\nnotes: |\n  ${uri}`).kind, "no-nodes");
  assert.equal(parse(`proxy-groups:\n  - ${ssYaml}\nnotes: |\n  ${uri}`).kind, "no-nodes");
  assert.equal(parse(uri).kind, "no-nodes");
  assert.equal(parse(JSON.stringify([{ ...ss, type: "fixture-unknown" }])).kind, "unsupported");
  assert.equal(parse(JSON.stringify([{ ...ss, name: "" }])).kind, "malformed");
});

test("rejects aliases, directives, tags, unsafe and decoded duplicate keys before returning any nodes", () => {
  for (const document of [
    `proxies: &nodes [${ssYaml}]`, `template: &example ${ssYaml}\nproxies: [*example]`,
    "proxies: [*missing]", `%YAML 1.1\n---\nproxies: [${ssYaml}]`, `proxies: !!seq [${ssYaml}]`,
  ]) {
    const result = parse(document);
    assert.deepEqual([result.kind, result.nodes], ["unsupported", []]);
  }
  for (const document of [
    `proxies: [${ssYaml}]\nproxies: []`, `proxies: [${ssYaml}]\n---\nproxies: []`,
    `proxies: [${ssYaml}]\nmetadata: {<<: 1}`, `proxies: [${ssYaml}]\nmetadata: {123: 1}`,
    '{"proxies":[{"name":"fixture","n\\u0061me":"duplicate"}]}',
    '{"proxies":[],"metadata":{"\\u005f_proto__":{"fixture-polluted":true}}}',
    `proxies: [${ssYaml}]\nmetadata: {constructor: {prototype: {fixture: true}}}`,
  ]) {
    const result = parse(document);
    assert.equal(result.kind, "malformed");
    assert.deepEqual(result.nodes, []);
    assert(!JSON.stringify(result).includes("fixture-only"));
  }
  assert.equal(Object.hasOwn(Object.prototype, "fixture-polluted"), false);
});

test("rejects nonfinite numbers, unsafe integers and precision loss without exposing source text", () => {
  for (const value of ["9007199254740993", "9007199254740991.1", "1.0000000000000001", "1e-9999", "1e9999", ".inf", ".nan",
    "0x20000000000001", "9".repeat(20_000)]) {
    const result = parse(`proxies: [${ssYaml}]\nmetadata: {value: ${value}}`);
    assert.equal(result.kind, "malformed");
    assert.deepEqual(result.nodes, []);
    assert(!JSON.stringify(result).includes("fixture-only"));
  }
  const result = parse(`proxies: [{name: 'a', type: ss, server: 203.0.113.10, port: 4.43e2, quota: 9007199254740991, score: 2.5}]`);
  assert.equal(result.kind, "parsed");
  assert.equal(result.nodes[0].port, 443);
  assert.equal(result.nodes[0].quota, Number.MAX_SAFE_INTEGER);
  assert.equal(result.nodes[0].score, 2.5);
});

test("enforces UTF-8, byte, depth, candidate and complexity limits with no partial nodes", () => {
  assert.equal(parse(new Uint8Array([0xc0, 0x80])).kind, "invalid-encoding");
  assert.equal(parse("\ud800").kind, "invalid-encoding");
  assert.equal(parse('{"proxies":[],"notes":"\\ud800"}', { syntax: "json" }).kind, "malformed");
  const fixtures = [
    ["字字", { maxInputBytes: 5 }, "input-bytes"],
    ["[".repeat(20_000) + "0" + "]".repeat(20_000), {}, "depth"],
    [Array.from({ length: 42 }, (_, i) => `${"  ".repeat(i)}key:`).join("\n"), {}, "depth"],
    [`proxies: [${ssYaml}]`, { maxDepth: 2 }, "depth"],
    [`proxies: [${ssYaml}, null]`, { maxNodes: 1 }, "nodes"],
    [JSON.stringify([ss, { ...ss, password: "字".repeat(Math.floor(MAX_CHUNK_BYTES / 3)) }]), {}, "node-bytes"],
    ["# c\n".repeat(130_000), {}, "complexity"],
  ] as const;
  for (const [input, options, limit] of fixtures) {
    const result = parse(input, options);
    assert.equal(result.kind, "limit");
    if (result.kind === "limit") assert.equal(result.limit, limit);
    assert.deepEqual(result.nodes, []);
  }
});

test("the browser-bundled parser runs in workerd without Node token debugging", async () => {
  const result = await build({
    stdin: { contents: `
      import { parseStructuredNodeDocument } from './src/structured-import.ts';
      export default { async fetch(req) { return Response.json(parseStructuredNodeDocument(await req.text())); } };
    `, resolveDir: fileURLToPath(new URL("..", import.meta.url)), loader: "ts" },
    bundle: true, format: "esm", platform: "browser", target: "es2022", write: false,
  });
  const script = result.outputFiles[0].text;
  assert.doesNotMatch(script, /LOG_TOKENS|node:process/u);
  const runtime = new Miniflare({ modules: true, script, compatibilityDate: "2026-07-30" });
  try {
    const response = await runtime.dispatchFetch("https://fixture.example/", { method: "POST", body: `proxies: [${ssYaml}]` });
    const parsed = await response.json();
    assert.equal(parsed.kind, "parsed");
    assert.equal(parsed.nodes.length, 1);
    assert.equal(parsed.nodes[0].port, 8388);
  } finally {
    await runtime.dispose();
  }
});
