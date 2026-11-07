import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

import { parseTextProxy, textProxyLine, TextExportError } from "../src/text-export.ts";

interface Case {
  label: string;
  node: Record<string, unknown>;
  vmess?: Record<string, unknown>;
  surge: string | null;
  qx: string | null;
}

const corpus: Case[] = JSON.parse(await readFile(new URL("./text-export-corpus.json", import.meta.url), "utf8"));
const base = corpus[0].node;

test("renders exact legacy and vendor grammar fixtures without changing stored nodes", () => {
  for (const { label, node, vmess, surge, qx } of corpus) {
    const input = vmess ? { ...node, share: "vmess://" + Buffer.from(JSON.stringify(vmess)).toString("base64") } : node;
    const original = structuredClone(input);
    for (const [format, expected] of [["surge", surge], ["qx", qx]] as const) {
      if (expected === null) assert.throws(() => parseTextProxy(input, format), TextExportError, label);
      else {
        const proxy = parseTextProxy(input, format);
        assert.equal(textProxyLine(proxy, proxy.name, format), expected + "\n", label);
      }
    }
    assert.deepEqual(input, original, label);
  }
});

test("rejects ambiguity or unsupported settings before writing any line", () => {
  const uuid = "11111111-1111-4111-8111-111111111111";
  for (const node of [
    { ...base, name: "fixture-secret\n[Rule]" },
    { ...base, name: "fixture-secret, DIRECT" },
    { ...base, name: "// fixture-secret" },
    { ...base, name: "fixture-secret // comment" },
    { ...base, name: "fixture-secret=alias" },
    { ...base, password: "fixture-secret\u0085next" },
    { ...base, password: "fixture-secret\u2028next" },
    { ...base, password: " fixture-secret" },
    { ...base, password: "fixture-secret\"quote" },
    { ...base, password: "fixture-secret // comment" },
    { ...base, password: "fixture-secret;skip-cert-verify=true" },
    { ...base, password: "\ud800" },
    { ...base, share: "ss://fixture-secret", raw: corpus[9].node.share },
    { ...base, "dialer-proxy": "fixture-secret" },
    { ...base, plugin: "v2ray-plugin", "plugin-opts": "tls;cert=/fixture/fixture-secret" },
    { share: "ss://aes-256-gcm:fixture@ss.example.invalid:8388?plugin=v2ray-plugin%3Bmux%3D2" },
    { share: "ssr://fixture-secret" },
    { share: "trojan://fixture-secret@tr.example.invalid:443?security=none" },
    { share: "trojan://fixture-secret@tr.example.invalid:443?type=grpc&serviceName=abc" },
    { share: "trojan://fixture-secret@tr.example.invalid:443?type=ws&path=%2Fws%3Fed%3D1024" },
    { type: "trojan", server: "tr.example.invalid", port: 443, password: "fixture-secret", alpn: [] },
    { type: "trojan", server: "tr.example.invalid", port: 443, password: "fixture-secret", network: "ws",
      "ws-opts": { headers: { "X|Injected": "fixture-secret" } } },
    { type: "vmess", server: "vm.example.invalid", port: 443, uuid, cipher: "auto" },
    { type: "vmess", server: "vm.example.invalid", port: 443, uuid, cipher: "aes-128-gcm", alterId: 1 },
    { type: "socks", server: "socks.example.invalid", server_port: 1080, version: "4a" },
    { share: "hy2://fixture-secret@hy.example.invalid?ech=AAT-DQAA" },
    { share: "hy2://fixture-secret@hy.example.invalid?pinSHA256=" + "ab".repeat(32) },
    { share: "tuic://" + uuid + ":fixture-secret@tuic.example.invalid:443?udp_relay_mode=quic" },
  ]) {
    for (const format of ["surge", "qx"] as const) {
      assert.throws(() => parseTextProxy(node, format), (error) =>
        error instanceof TextExportError && !String(error).includes("fixture-secret"));
    }
  }
  const conflicting = { share: "trojan://fixture-secret@tr.example.invalid:443?type=ws&host=front.example.invalid&sni=tls.example.invalid" };
  assert.doesNotThrow(() => parseTextProxy(conflicting, "surge"));
  assert.throws(() => parseTextProxy(conflicting, "qx"), TextExportError);
});

test("refuses Surge's SNI-off sentinel without changing literal SNI for QX", () => {
  const node = { type: "trojan", server: "tr.example.invalid", port: 443, password: "fixture", sni: "OFF" };
  assert.throws(() => parseTextProxy(node, "surge"), TextExportError);
  const proxy = parseTextProxy(node, "qx");
  assert.match(textProxyLine(proxy, proxy.name, "qx"), /, tls-host=OFF, /u);
  assert.throws(() => parseTextProxy({ ...node, server: "off", sni: undefined }, "surge"), TextExportError);
});

test("only Surge's documented two-key Shadowsocks 2022 form is emitted", () => {
  const node = { ...base, cipher: "2022-blake3-aes-128-gcm", password: "AAAAAAAAAAAAAAAAAAAAAA==:AQEBAQEBAQEBAQEBAQEBAQ==" };
  const proxy = parseTextProxy(node, "surge");
  assert.match(textProxyLine(proxy, proxy.name, "surge"), /password=AAAAAAAAAAAAAAAAAAAAAA==:AQEBAQEBAQEBAQEBAQEBAQ==\n$/u);
  assert.throws(() => parseTextProxy(node, "qx"), TextExportError);
  assert.throws(() => parseTextProxy({ ...node, password: node.password + ":AAAAAAAAAAAAAAAAAAAAAA==" }, "surge"), TextExportError);
});
