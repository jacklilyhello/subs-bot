import assert from "node:assert/strict";
import { test } from "node:test";

import { parseTelegramProviderDocument, parseTelegramProviderUrlMessage } from "../src/telegram/provider-document-input.ts";
import { MAX_TELEGRAM_DOCUMENT_BYTES } from "../src/telegram/document-transport.ts";

const encoder = new TextEncoder();
const parse = (text: string, suffix = "txt") => parseTelegramProviderDocument(encoder.encode(text), suffix);
const source = "HtTpS://provider.example.invalid/path/%2F?z=x|y&a=1";
const node = "ss://YWVzLTI1Ni1nY206Zml4dHVyZQ@203.0.113.10:8388#fixture";

test("URL-only documents preserve exact first-seen spelling across BOM, CRLF, and blank lines", () => {
  const distinct = source.replace("%2F", "%2f");
  for (const suffix of ["txt", "log"]) {
    assert.deepEqual(parse(`\ufeff\r\n\t\r\n  ${source}\t\r\n${source}\n ${distinct}\n`, suffix), {
      kind: "url-list", urls: [source, distinct], overflow: 0,
    });
  }
});

test("returns the first twenty distinct URLs and counts unique overflow", () => {
  const urls = Array.from({ length: 23 }, (_, index) => `${source}&case=${index}`);
  assert.deepEqual(parse(urls.slice(0, 20).join("\n")), { kind: "url-list", urls: urls.slice(0, 20), overflow: 0 });
  assert.deepEqual(parse([...urls.slice(0, 20), urls[0], ...urls.slice(20), urls[21], urls[1]].join("\n")), {
    kind: "url-list", urls: urls.slice(0, 20), overflow: 3,
  });
  assert.deepEqual(parse([...urls, "https://provider.example.invalid:8443/fixture"].join("\n")), { kind: "invalid-url-list" });
});

test("recognized URL lists apply the provider validation without exposing any invalid row", () => {
  const prefix = "https://provider.example.invalid/";
  const multibyte = "界".repeat(Math.floor((8192 - prefix.length) / 3));
  const atLimit = prefix + multibyte + "x".repeat((8192 - prefix.length) % 3);
  assert.deepEqual(parse(atLimit), { kind: "url-list", urls: [atLimit], overflow: 0 });
  for (const invalid of [atLimit + "x", `${prefix}%Q0`, `${prefix}part\\path`, `${prefix}x#fragment`, `${prefix} x`,
    `${prefix}x\tfixture`, `${prefix}x\r`, `${prefix}x\u0000`, `${prefix}x\u2028`, "https://", "https://user@provider.example.invalid/"]) {
    assert.deepEqual(parse(`${source}\n${invalid}`), { kind: "invalid-url-list" });
  }
});

test("refuses an excessive list without treating a later node as a URL", () => {
  const text = Array.from({ length: 4097 }, (_, index) => `${source}&row=${index}`).join("\n");
  assert.deepEqual(parse(text), { kind: "invalid-url-list" });
  assert.deepEqual(parse(`${text}\n${node}`), { kind: "not-url-list" });
});

test("leaves plain, structured, encoded, and mixed node documents to the node classifier", () => {
  for (const text of ["\ufeff\r\n \t", node, btoa(node), `${source}\n${node}`, `${node}\n${source}`,
    `https://\n${node}`, `名称 | ${source}`, `proxies:\n  - {name: fixture, url: ${source}}`]) {
    assert.deepEqual(parse(text), { kind: "not-url-list" });
  }
  for (const suffix of ["json", "yaml", "yml"]) assert.deepEqual(parse(source, suffix), { kind: "not-url-list" });
  assert.deepEqual(parseTelegramProviderDocument(new Uint8Array([0xef, 0xbb, 0xbf, 0xff]), "txt"), { kind: "not-url-list" });
  assert.deepEqual(parseTelegramProviderDocument(new Uint8Array(MAX_TELEGRAM_DOCUMENT_BYTES + 1), "log"), { kind: "not-url-list" });
});

test("private URL messages keep standalone line order and report distinct overflow", () => {
  const urls = Array.from({ length: 22 }, (_, index) => `HtTpS://provider.example.invalid/%2F?value=x%7Cy&case=${index}`);
  assert.deepEqual(parseTelegramProviderUrlMessage(`\ufeff\r\n ${urls[0]}\r\n\r\n${[...urls, urls[20]].join("\r\n")}`), {
    entries: urls.slice(0, 20).map((sourceUrl) => ({ sourceUrl })), overflow: 2,
  });
  assert.deepEqual(parseTelegramProviderUrlMessage(`套餐名 | ${source}\r\n${urls[1]}\nignored | ${source}\nignored | ${urls[1]}`), {
    entries: [{ sourceUrl: source, name: "套餐名" }, { sourceUrl: urls[1] }], overflow: 0,
  });
  for (const invalid of [`${urls[0]}\n`, `${urls[0]} ${urls[1]}`, `${urls[0]}\n${node}`,
    ` | ${urls[0]}\n${urls[1]}`, `${node} | ${urls[0]}\n${urls[1]}`, `${urls[0]}\n${source}`,
    `${urls[0]}\n${urls[1]}\ud800`, `${urls[0]}\n${urls[1]}\u00a0`, `${urls[0]}\n${"界".repeat(65)} | ${urls[1]}`,
    `${urls[0]}\nhttps://user@provider.example.invalid/`, `${urls[0]}\n${urls[1]}${"x".repeat(4096)}`]) {
    assert.equal(parseTelegramProviderUrlMessage(invalid), null);
  }
});
