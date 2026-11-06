import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

import { isValidStoredShare } from "../src/stored-share.ts";
import { serializeStructuredShare } from "../src/structured-share.ts";

interface Case {
  label: string;
  node: Record<string, unknown>;
  expected?: string | null;
  vmess?: Record<string, string>;
}

const corpus: Case[] = JSON.parse(await readFile(new URL("./structured-share-corpus.json", import.meta.url), "utf8"));

test("matches exact Python structured share bytes and rejects unmapped settings", () => {
  for (const { label, node, expected, vmess } of corpus) {
    const vmessJson = vmess && "{" + Object.entries(vmess)
      .map(([key, value]) => `${JSON.stringify(key)}: ${JSON.stringify(value)}`).join(", ") + "}";
    const target = vmessJson ? "vmess://" + Buffer.from(vmessJson).toString("base64") : expected;
    const snapshot = structuredClone(node);
    const actual = serializeStructuredShare(node);
    assert.equal(actual, target, label);
    assert.deepEqual(node, snapshot, label);
    if (actual !== null) assert.equal(isValidStoredShare(actual), true, label);
  }
});

test("encodes large UTF-8 credentials and VMess JSON in aligned Base64 chunks", () => {
  const password = "字🌐/ !'()*#".repeat(16_000);
  const ss = serializeStructuredShare({ type: "ss", server: "ss.example.invalid", port: 8388,
    cipher: "aes-256-gcm", password });
  const userinfo = Buffer.from(`aes-256-gcm:${password}`).toString("base64url");
  assert.equal(ss, `ss://${userinfo}@ss.example.invalid:8388#node`);

  const name = '日本\n"🌐'.repeat(16_000);
  const vmess = serializeStructuredShare({ type: "vmess", server: "vm.example.invalid", port: 443,
    name, uuid: "synthetic-client" });
  assert.ok(vmess?.startsWith("vmess://"));
  assert.equal(JSON.parse(Buffer.from(vmess.slice(8), "base64").toString("utf8")).ps, name);
});

test("does not coerce conflicting nested alias types or inherited names", () => {
  const base = { type: "ss", server: "ss.example.invalid", port: 8388, cipher: "aes-256-gcm", password: "fixture-only" };
  assert.equal(serializeStructuredShare({ ...base, plugin: "v2ray-plugin", "plugin-opts": { tls: true },
    plugin_opts: { tls: 1 } }), null);
  assert.equal(serializeStructuredShare({ ...base, ["__proto__"]: { name: "unexpected" } }), null);
  assert.equal(serializeStructuredShare(Object.assign(Object.create({ name: "unexpected" }), base)),
    "ss://YWVzLTI1Ni1nY206Zml4dHVyZS1vbmx5@ss.example.invalid:8388#node");
});
