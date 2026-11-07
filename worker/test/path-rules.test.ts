import assert from "node:assert/strict";
import { test } from "node:test";

import { compilePathRules, foldPathText, MAX_PATH_RULES, pathRuleMapper, PathRuleContentError } from "../src/path-rules.ts";
import { SnapshotIntegrityError } from "../src/storage.ts";

test("uses pinned full Unicode 14 folding without normalization or Turkic overrides", () => {
  assert.equal(foldPathText("Straße Σςσ İIı K ﬃ Ꭰꭰ \u{10400} \u{1c89}"),
    "strasse σσσ i\u0307iı k ffi ᎠᎠ \u{10428} \u{1c89}");
  assert.notEqual(foldPathText("É"), foldPathText("E\u0301"));
});

test("matches the folded raw fields, ranks scalar length and breaks ties by original ID", () => {
  const map = pathRuleMapper(compilePathRules([
    { id: 1, keyword: "😀", remark: "astral" },
    { id: 2, keyword: "\u0085ß\u001c", remark: "\u3000first tie\u0085" },
    { id: 3, keyword: "SS", remark: "second tie" },
    { id: 4, keyword: "host SS://", remark: "crosses fields" },
    { id: 5, keyword: "%2FPath", remark: "encoded" },
    { id: 6, keyword: "\ufeffOther", remark: "BOM is not Python whitespace" },
  ]));
  assert.equal(map({ name: "😀 SS" }).name, "😀 SS → first tie");
  assert.equal(map({ name: "Other", server: "HOST", share: "ss://opaque" }).name, "Other → crosses fields");
  assert.equal(map({ name: "Other", share: "trojan://fixture@host#%2fpath" }).name, "Other → encoded");
  const untouched = { name: "Other", raw: "trojan://fixture@host#%2fpath", transport: { path: "%2FPath" } };
  assert.equal(map(untouched), untouched);
  assert.equal(map({ name: "Other", share: "trojan://fixture@host#/path" }).name, "Other");
  const native = { name: "SS", tag: "SS", password: "fixture", server: "host" };
  assert.deepEqual(map(native), { ...native, name: "SS → first tie", tag: "SS → first tie" });
  assert.equal(native.name, "SS");
  assert.equal(map({ ...native, tag: "conflict" }).tag, "conflict");
});

test("rejects unreadable rules and excessive rule count or matching work", () => {
  assert.throws(() => compilePathRules([{ id: 1, keyword: "\u0085", remark: "a" }]), SnapshotIntegrityError);
  assert.throws(() => compilePathRules([{ id: 1, keyword: "a", remark: "\ud800" }]), SnapshotIntegrityError);
  const rows = Array.from({ length: MAX_PATH_RULES + 1 }, (_, index) => ({
    id: index + 1, keyword: `absent-${index}`, remark: "fixture",
  }));
  assert.throws(() => compilePathRules(rows), PathRuleContentError);
  const map = pathRuleMapper(compilePathRules(rows.slice(0, MAX_PATH_RULES)));
  const node = { name: "x".repeat(400_000) };
  assert.equal(map(node), node);
  assert.equal(map(node), node);
  assert.throws(() => map(node), PathRuleContentError);
});
