import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import { ClashContentError, serializeClashProxy } from "../src/clash-export.ts";

interface Case {
  label: string;
  node: Record<string, unknown>;
  vmess?: Record<string, unknown>;
  proxy: Record<string, unknown>;
}

const corpus: Case[] = JSON.parse(await readFile(new URL("./clash-corpus.json", import.meta.url), "utf8"));
const base = corpus[0].node;

test("matches shared legacy values and explicit Worker conversion cases", () => {
  for (const { label, node, vmess, proxy } of corpus) {
    const input = vmess ? { ...node, share: "vmess://" + Buffer.from(JSON.stringify(vmess)).toString("base64") } : node;
    const before = structuredClone(input);
    const result = serializeClashProxy(input);
    assert.equal(result.name, node.name, label);
    assert.deepEqual(JSON.parse(JSON.stringify(result.proxy)), proxy, label);
    assert.deepEqual(input, before, label);
  }
});

test("recovers allowed whole-blob SIP003 options without interpreting a fragment as authority", () => {
  const share = "ss://" + Buffer.from(
    "aes-256-gcm:fixture@key@ss.example.invalid:8388/?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dfront.example.invalid#@shadow.example.invalid:9999",
  ).toString("base64url");
  assert.deepEqual(serializeClashProxy({ share }).proxy, {
    type: "ss", server: "ss.example.invalid", port: 8388, cipher: "aes-256-gcm", password: "fixture@key",
    plugin: "obfs", "plugin-opts": { mode: "http", host: "front.example.invalid" },
  });
});

test("rejects unsupported or unsafe options without exposing their values", () => {
  const h2 = { type: "hysteria2", server: "hy.example.invalid", port: 443, password: "fixture" };
  for (const node of [
    { ...base, name: "\ud800" },
    { ...base, password: "\ud800" },
    { ...base, server: "bücher.example" },
    { ...base, share: "ss://fixture-secret", raw: corpus[1].node.share },
    { ...base, "dialer-proxy": "fixture-secret" },
    { ...base, plugin: "exec-fixture-secret", "plugin-opts": { mode: "websocket" } },
    { ...base, plugin: "v2ray-plugin", "plugin-opts": { mode: "websocket", cert: "/fixture/fixture-secret" } },
    { share: "ss://aes-256-gcm:fixture@ss.example.invalid:8388?plugin=v2ray-plugin%3Bmux%3D2" },
    { share: "ss://aes-256-gcm:fixture@ss.example.invalid:8388?%2570lugin=fixture-secret" },
    { ...h2, fingerprint: "a".repeat(64) },
    { ...h2, "realm-opts": { enable: true, "server-url": "https://provider.example.invalid" } },
    { ...h2, "ech-opts": { enable: true, config: "/fixture/fixture-secret" } },
    { ...h2, obfs: "gecko", "obfs-password": "fixture", "obfs-max-packet-size": 2049 },
    { ...h2, ports: ["1-65535", "1"] },
    { share: "hy2://fixture-secret@hy.example.invalid?ech=%2Ffixture%2Ffixture-secret" },
    { share: "hy2://fixture-secret@hy.example.invalid?insecure=1&pinSHA256=" + "ab".repeat(32) },
    { share: "hy2://fixture-secret@hy.example.invalid?insecure=" },
    { share: "hy2://fixture-secret@hy.example.invalid:443,5000-5002?mport=" },
    { share: "hy2://fixture-secret@hy.example.invalid?mport=443:5000" },
    { share: "hy2://fixture-secret@[fe80::1%25zone]:443" },
    { share: "trojan://fixture-secret@tr.example.invalid:443?security=none" },
    { share: "vmess://fixture-secret@vm.example.invalid:443" },
    { share: "ssr://fixture-secret" },
    { type: "socks", server: "socks.example.invalid", server_port: 1080, version: "4a" },
  ]) {
    assert.throws(() => serializeClashProxy(node), (error) =>
      error instanceof ClashContentError && !String(error).includes("fixture-secret"), node.type as string | undefined);
  }
});
