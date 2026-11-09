import assert from "node:assert/strict";
import { test } from "node:test";

import { MAX_TELEGRAM_DOCUMENT_NODES } from "../src/telegram/document-persistence.ts";
import { MAX_TELEGRAM_DOCUMENT_BYTES } from "../src/telegram/document-transport.ts";
import { parseTelegramMixedDocument } from "../src/telegram/mixed-document-input.ts";
import { parseNodeText } from "../src/text-import.ts";

const encoder = new TextEncoder();
const parse = (text: string, suffix = "txt") => parseTelegramMixedDocument(encoder.encode(text), suffix);
const source = "HtTpS://provider.example.invalid/path/%2F?z=x|y&a=1";
const shadowsocks = "ss://YWVzLTI1Ni1nY206Zml4dHVyZQ@203.0.113.10:8388#label-https://other.example.invalid/source";
const hysteria2 = "hysteria2://fixture@203.0.113.22:443#Synthetic label";

test("plain mixed TXT and LOG retain node records and URL spelling in their original order", () => {
  const distinct = source.replace("%2F", "%2f");
  const nodeText = `${shadowsocks}\n${hysteria2}\n${shadowsocks}`;
  const nodes = parseNodeText(nodeText).nodes;
  assert.equal(nodes.length, 3);
  for (const suffix of ["txt", "log"]) {
    assert.deepEqual(parse(`\ufeff\r\n\t\r\n# ${source}\r\n  ${source}\t\r\n${shadowsocks}\r\n${source}\n` +
      `  ${hysteria2}  \r\n ${distinct}\n${shadowsocks}`, suffix), {
      kind: "mixed", nodes, urls: [source, distinct], overflow: 0,
    });
  }
});

test("inherits the first twenty distinct URL rule and counts unique overflow", () => {
  const urls = Array.from({ length: 23 }, (_, index) => `${source}&case=${index}`);
  assert.deepEqual(parse([urls[0], shadowsocks, ...urls, urls[21], urls[1]].join("\n")), {
    kind: "mixed", nodes: parseNodeText(shadowsocks).nodes, urls: urls.slice(0, 20), overflow: 3,
  });
  const tooManyUrls = Array.from({ length: 4097 }, (_, index) => `${source}&case=${index}`);
  assert.deepEqual(parse([shadowsocks, ...tooManyUrls].join("\n")), { kind: "invalid-mixed" });
});

test("a malformed, unsupported, or unrelated row invalidates the entire candidate", () => {
  for (const invalid of ["https://", "https:/broken", "https://provider.example.invalid:8443/fixture",
    "https://user@provider.example.invalid/", `${source}%Q0`, `${source}#fragment`, `${source}\r`,
    "hy2://", "hysteria2://fixture@203.0.113.22:443?ech=fixture.pem", "ss://wrong",
    "hysteria2+realm://fixture@realm.example.invalid/name", "custom://fixture.invalid", "unrecognized prose",
    `label | ${source}`, btoa(shadowsocks)]) {
    assert.deepEqual(parse(`${shadowsocks}\n${source}\n${invalid}`), { kind: "invalid-mixed" });
  }
  assert.deepEqual(parse(`hy2://\n${source}`), { kind: "invalid-mixed" });
  assert.deepEqual(parse(`${shadowsocks}\nhttps://`), { kind: "invalid-mixed" });
  const urls = Array.from({ length: 20 }, (_, index) => `${source}&case=${index}`);
  assert.deepEqual(parse([shadowsocks, ...urls, `${source}#fragment`].join("\n")), { kind: "invalid-mixed" });
});

test("leaves pure and other document formats to their existing entrypoints", () => {
  for (const other of ["\ufeff\r\n \t", `${shadowsocks}\n${hysteria2}`, `# ${source}\n${shadowsocks}`,
    `${source}\n${source}`, `${source}\ncustom://fixture.invalid`, btoa(`${shadowsocks}\n${source}`),
    `${source}\n${btoa(shadowsocks)}`, `${shadowsocks}\nprose mentioning ${source}`,
    JSON.stringify({ proxies: [shadowsocks], source }), `proxies:\n  - ${shadowsocks}\nsource: ${source}`]) {
    assert.deepEqual(parse(other), { kind: "not-mixed" });
  }
  for (const suffix of ["json", "yaml", "yml"]) {
    assert.deepEqual(parse(`${shadowsocks}\n${source}`, suffix), { kind: "not-mixed" });
  }
  assert.deepEqual(parseTelegramMixedDocument(new Uint8Array([0xef, 0xbb, 0xbf, 0xff]), "txt"), { kind: "not-mixed" });
  assert.deepEqual(parseTelegramMixedDocument(new Uint8Array(MAX_TELEGRAM_DOCUMENT_BYTES + 1), "log"), { kind: "not-mixed" });
});

test("uses the Telegram node limit without dropping nodes", () => {
  const exact = `${shadowsocks}\n`.repeat(MAX_TELEGRAM_DOCUMENT_NODES);
  const result = parse(`${exact}${source}`);
  assert.equal(result.kind, "mixed");
  if (result.kind === "mixed") assert.equal(result.nodes.length, MAX_TELEGRAM_DOCUMENT_NODES);
  assert.deepEqual(parse(`${exact}${shadowsocks}\n${source}`), { kind: "invalid-mixed" });
});
