import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import { LOWER_CONTEXT_ORACLE_SHA256 } from "../src/unicode14-lower.ts";
import { selectedQuery, unicode14Lower } from "../src/telegram/selected-search.ts";

test("matches the CPython Unicode 14 oracle for every scalar and three Final_Sigma contexts", () => {
  const hash = createHash("sha256");
  for (let point = 0; point <= 0x10ffff; point += 1) {
    if (point >= 0xd800 && point <= 0xdfff) continue;
    const scalar = String.fromCodePoint(point);
    for (const value of [scalar, `AΣ${scalar}A`, `${scalar}Σ`, `A${scalar}Σ`]) {
      hash.update(JSON.stringify(unicode14Lower(value)) + "\n");
    }
  }
  assert.equal(hash.digest("hex"), LOWER_CONTEXT_ORACLE_SHA256);
});

test("preserves lowercase matching rather than full casefold and Python argument whitespace", () => {
  assert.equal(unicode14Lower("Straße STRASSE İ ΟΣ ΟΣΑ"), "straße strasse i\u0307 ος οσα");
  assert.equal(unicode14Lower("AΣ\u0345A"), "aσ\u0345a");
  assert.equal(selectedQuery("\u001c Straße\u0085  ΟΣ \t"), "straße ος");
  assert.equal(selectedQuery(""), "");
  assert.equal(selectedQuery("\ufeffStraße"), "\ufeffstraße");
  for (const invalid of ["x".repeat(257), "\u0000", "\ud800"]) assert.equal(selectedQuery(invalid), null);
});
