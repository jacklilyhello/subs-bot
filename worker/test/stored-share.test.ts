import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

import { isValidStoredShare } from "../src/stored-share.ts";

const corpus = JSON.parse(await readFile(new URL("./stored-share-corpus.json", import.meta.url), "utf8"));

type CorpusRow = { label: string; valid: boolean } & (
  | { share: unknown }
  | { scheme: string; base64Text: string; encoding?: "utf16le" | "utf32le"; fragment?: string }
);

function makeShare(row: CorpusRow): unknown {
  if ("share" in row) return row.share;
  let body: Buffer;
  if (row.encoding === "utf32le") {
    const codepoints = Array.from(row.base64Text);
    body = Buffer.alloc(codepoints.length * 4);
    codepoints.forEach((character, index) => body.writeUInt32LE(character.codePointAt(0)!, index * 4));
  } else {
    body = Buffer.from(row.base64Text, row.encoding === "utf16le" ? "utf16le" : "utf8");
  }
  return row.scheme + "://" + body.toString("base64") + (row.fragment ?? "");
}

test("stored-share acceptance matches the shared Python corpus", () => {
  for (const row of corpus) assert.equal(isValidStoredShare(makeShare(row)), row.valid, row.label);
});

test("Hysteria 2 bounds all query fields before handling ECH", () => {
  const prefix = "hy2://proxy.example.invalid?";
  assert.equal(isValidStoredShare(prefix + "x=1&".repeat(99) + "ech=AAT-DQAA"), true);
  assert.equal(isValidStoredShare(prefix + "x=1&".repeat(100) + "ech=AAT-DQAA"), false);
  assert.equal(isValidStoredShare(prefix + "&".repeat(100) + "ech=AAT-DQAA"), false);
});
