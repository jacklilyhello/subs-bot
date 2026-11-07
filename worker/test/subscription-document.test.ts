import assert from "node:assert/strict";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { Miniflare } from "miniflare";
import { parseSubscriptionDocument as parse } from "../src/subscription-document.ts";
import { parseNodeText } from "../src/text-import.ts";
import { parseStructuredNodeDocument } from "../src/structured-import.ts";

const uri = "ss://YWVzLTI1Ni1nY206Zml4dHVyZS1vbmx5@203.0.113.10:8388";
const proxy = { name: "合成节点", type: "ss", server: "203.0.113.10", port: 8388, cipher: "aes-256-gcm", password: "fixture-only" };
const clash = `proxies: ${JSON.stringify([proxy])}\n`;
const singbox = JSON.stringify({ outbounds: [
  { type: "direct", tag: "direct" },
  { type: "shadowsocks", tag: "合成节点", server: "203.0.113.10", server_port: 8388,
    method: "aes-256-gcm", password: "fixture-only", multiplex: { enabled: false } },
] });

test("admits complete URI lists with exact nodes and fixed rejection counts", () => {
  const text = `${uri}#Synthetic label\r\n# comment\nss://wrong\ncustom://fixture.invalid\nhysteria2+realm://fixture.invalid\n`;
  const result = parse(text);
  assert.equal(result.kind, "parsed");
  assert.equal(result.format, "text");
  assert.equal(result.envelope, "plain");
  assert.deepEqual(result.nodes, parseNodeText(text).nodes);
  assert.equal(result.nodes[0].share, `${uri}#Synthetic label`);
  assert.deepEqual(result.rejected, { malformed: 1, unsupported: 2 });
  assert.equal(result.ignored, 1);
  assert.equal(result.ndjsonBytes, Buffer.byteLength(JSON.stringify(result.nodes[0])) + 1);
  assert.equal(parse("ss://wrong").kind, "malformed");
  assert.equal(parse("https://example.invalid/subscription").kind, "unsupported");
  assert.equal(parse("# comment\n\n").kind, "no-nodes");
});

test("preserves native Clash and Sing-box nodes, including with explicit syntax", () => {
  for (const [document, syntax, format] of [[clash, "yaml", "clash"], [singbox, "json", "singbox"]] as const) {
    const expected = parseStructuredNodeDocument(document, { syntax });
    for (const hint of ["auto", syntax] as const) {
      const result = parse(document, { syntax: hint });
      assert.deepEqual(result, { ...expected, format, envelope: "plain" });
      assert.equal(result.nodes.length, 1);
    }
  }
  assert.equal(parse(`- ${JSON.stringify(proxy)}`).format, "clash");
  assert.equal(parse(clash, { syntax: "json" }).kind, "malformed");
  assert.equal(parse(`${uri}\n`, { syntax: "yaml" }).kind, "no-nodes");
  const unsupported = parse(`proxies: [{name: Fixture, type: unsupported, server: example.invalid, port: 1}]`);
  assert.equal(unsupported.kind, "unsupported");
  assert.deepEqual(unsupported.rejected, { malformed: 0, unsupported: 1 });
});

test("admits one folded, URL-safe or structured Base64 envelope without recursive fallback", () => {
  const folded = Buffer.from(`${uri}#Synthetic\n`).toString("base64").match(/.{1,16}/gu)?.join("\r\n ") ?? "";
  assert.deepEqual(parse(folded), { ...parse(`${uri}#Synthetic\n`), envelope: "base64" });

  const prefix = `${uri}#`;
  const label = `${"a".repeat((3 - prefix.length % 3) % 3)}🧪`;
  const urlSafe = Buffer.from(`${prefix}${label}`).toString("base64url");
  assert.match(urlSafe, /-/u);
  assert.deepEqual(parse(urlSafe), { ...parse(`${prefix}${label}`), envelope: "base64" });

  for (const document of [clash, singbox, "[]", `proxies: [\n${uri}`]) {
    const encoded = Buffer.from(document).toString("base64");
    assert.deepEqual(parse(encoded), { ...parse(document), envelope: "base64" });
  }
  const encoded = Buffer.from(uri).toString("base64");
  const nested = parse(Buffer.from(encoded).toString("base64"));
  assert.equal(nested.envelope, "base64");
  assert.equal(nested.kind, "no-nodes");
  assert.deepEqual(nested.nodes, []);
  assert.deepEqual(parse(`${encoded}\n${uri}`).nodes, []);

  const paddedPayload = `${uri}${"\n".repeat((4 - uri.length % 3) % 3)}`;
  const canonical = Buffer.from(paddedPayload).toString("base64");
  assert.match(canonical, /==$/u);
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  const noncanonical = canonical.slice(0, -3) + alphabet[alphabet.indexOf(canonical.at(-3) ?? "") + 1] + "==";
  assert.deepEqual(parse(noncanonical).nodes, []);
});

test("never extracts URI rows from structured metadata, malformed documents, or URI-shaped YAML keys", () => {
  for (const document of [
    `notes: |\n  ${uri}\n`,
    `ss://fixture: |\n  ${uri}\n`,
    `ss://fixture:\n  ${uri}\n`,
    `ss://fixture: # inline comment\n  ${uri}\n`,
    `---\nnotes: >\n  ${uri}\n`,
    `proxies: [\n  ${uri}\n`,
    `proxies: []\nnotes: |\n  ${uri}\n`,
    `outbounds: []\nnotes: |\n  ${uri}\n`,
    JSON.stringify({ metadata: { notes: uri } }),
  ]) {
    for (const input of [document, Buffer.from(document).toString("base64")]) {
      const report = parse(input);
      assert.ok(report.kind === "no-nodes" || report.kind === "malformed");
      assert.deepEqual(report.nodes, []);
      assert.equal(report.ndjsonBytes, 0);
      assert.doesNotMatch(JSON.stringify(report), /203\.0\.113\.10/u);
    }
  }
  const withNodes = parse(`${clash}notes: |\n  ${uri}\n`);
  assert.deepEqual(withNodes.nodes, [{ ...proxy, share: "" }]);
});

test("enforces byte, row, and depth limits without retaining partial nodes", () => {
  for (const [document, options, limit] of [
    [new Uint8Array(17), { maxInputBytes: 16 }, "input-bytes"],
    ["合成节点", { maxInputBytes: 11 }, "input-bytes"],
    [`${uri}\nss://wrong`, { maxNodes: 1 }, "nodes"],
    [`${uri}\nother://fixture.invalid`, { maxNodes: 1 }, "nodes"],
    [clash, { maxDepth: 2 }, "depth"],
  ] as const) {
    const report = parse(document, options);
    assert.equal(report.kind, "limit");
    if (report.kind === "limit") assert.equal(report.limit, limit);
    assert.deepEqual(report.nodes, []);
  }
  assert.equal(parse("\ud800").kind, "invalid-encoding");
  assert.equal(parse(new Uint8Array([0xff, 0xfe, 0x61])).kind, "invalid-encoding");
  assert.equal(parse(new Uint8Array([0xef, 0xbb, 0xbf, 0xff])).kind, "invalid-encoding");
  assert.equal(parse(new Uint8Array([0xff, 0xfe, 0, 0])).kind, "invalid-encoding");
});

test("the browser-bundled classifier accepts legacy encodings in pinned workerd", async () => {
  const result = await build({
    stdin: { contents: `
      import { parseSubscriptionDocument } from './src/subscription-document.ts';
      export default { async fetch(req) { return Response.json(parseSubscriptionDocument(new Uint8Array(await req.arrayBuffer()))); } };
    `, resolveDir: fileURLToPath(new URL("..", import.meta.url)), loader: "ts" },
    bundle: true, format: "esm", platform: "browser", target: "es2022", write: false,
  });
  const script = result.outputFiles[0].text;
  assert.doesNotMatch(script, /LOG_TOKENS|node:process/u);
  const runtime = new Miniflare({ modules: true, script, compatibilityDate: "2026-07-30" });
  try {
    const labeled = `${uri}#中文`;
    const utf16le = Buffer.from(`\ufeff${labeled}`, "utf16le");
    const utf16be = Buffer.from(utf16le).swap16();
    const gb18030 = Buffer.concat([Buffer.from(`${uri}#`), new Uint8Array([0xd6, 0xd0, 0xce, 0xc4])]);
    for (const bytes of [Buffer.from(`\ufeff${labeled}`), utf16le, utf16be, gb18030]) {
      for (const [body, envelope] of [[bytes, "plain"], [Buffer.from(bytes.toString("base64")), "base64"]] as const) {
        const response = await runtime.dispatchFetch("https://fixture.example/", { method: "POST", body });
        assert.deepEqual(await response.json(), { ...parse(labeled), envelope });
      }
    }
    const truncated = await runtime.dispatchFetch("https://fixture.example/", {
      method: "POST", body: new Uint8Array([0xff, 0xfe, 0x61]),
    });
    assert.equal((await truncated.json()).kind, "invalid-encoding");
  } finally {
    await runtime.dispose();
  }
});
