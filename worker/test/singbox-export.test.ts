import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

import { serializeSingBoxOutbound, SingBoxContentError } from "../src/singbox-export.ts";

interface Case {
  label: string;
  node: Record<string, unknown>;
  vmess?: Record<string, unknown>;
  outbound: Record<string, unknown>;
}

const corpus: Case[] = JSON.parse(await readFile(new URL("./singbox-corpus.json", import.meta.url), "utf8"));
const base = corpus[0].node;

test("converts the shared Python oracle and explicit Worker extension cases", () => {
  for (const { label, node, vmess, outbound } of corpus) {
    const input = vmess ? { ...node, share: "vmess://" + Buffer.from(JSON.stringify(vmess)).toString("base64") } : node;
    const snapshot = structuredClone(input);
    const result = serializeSingBoxOutbound(input);
    assert.equal(result.name, input.name, label);
    assert.deepEqual(JSON.parse(result.json), outbound, label);
    assert.deepEqual(input, snapshot, label);
  }
});

test("requires usable Hysteria v1 rates and preserves a matching peer/SNI", () => {
  const node = { type: "hysteria", server: "hy1.example.invalid", server_port: 443,
    tls: { enabled: true }, up: "16384 Bps", down: "1 Mbps" };
  assert.equal(JSON.parse(serializeSingBoxOutbound(node).json).up, "16384 Bps");
  assert.throws(() => serializeSingBoxOutbound({ ...node, up: "16383 Bps" }), SingBoxContentError);
  const share = "hysteria://hy1.example.invalid:443?peer=front.example.invalid&upmbps=10";
  assert.throws(() => serializeSingBoxOutbound({ share }), SingBoxContentError);
  assert.throws(() => serializeSingBoxOutbound({ share: share + "&downmbps=0" }), SingBoxContentError);
  assert.throws(() => serializeSingBoxOutbound({
    share: share + "&downmbps=20&sni=other.example.invalid",
  }), SingBoxContentError);
  assert.equal(JSON.parse(serializeSingBoxOutbound({
    share: share + "&downmbps=20&sni=front.example.invalid",
  }).json).tls.server_name, "front.example.invalid");
});

test("counts each expanded Hysteria hopping entry, including duplicates and overlaps", () => {
  const share = "hy2://fixture@hy2.example.invalid:443,5000-6000";
  assert.equal(serializeSingBoxOutbound({ share }).hoppingPorts, 1002);
  const node = { type: "hysteria2", server: "hy2.example.invalid", tls: { enabled: true } };
  const server_ports = ["1:65532", "1:2", "2:2"];
  assert.equal(serializeSingBoxOutbound({ ...node, server_ports }).hoppingPorts, 65535);
  assert.throws(() => serializeSingBoxOutbound({ ...node, server_ports: [...server_ports, "2:2"] }),
    SingBoxContentError);
});

test("checks effective Gecko bounds without rewriting explicit or omitted defaults", () => {
  const node = { type: "hysteria2", server: "hy2.example.invalid", server_port: 443, tls: { enabled: true } };
  const baseObfs = { type: "gecko", password: "fixture-gecko" };
  for (const limits of [{ min_packet_size: 1200 }, { min_packet_size: 0, max_packet_size: 512 }]) {
    const obfs = { ...baseObfs, ...limits };
    assert.deepEqual(JSON.parse(serializeSingBoxOutbound({ ...node, obfs }).json).obfs, obfs);
  }
  for (const limits of [{ min_packet_size: 1201 }, { min_packet_size: 0, max_packet_size: 511 },
    { max_packet_size: 2049 }, { min_packet_size: 700, max_packet_size: 699 }]) {
    assert.throws(() => serializeSingBoxOutbound({ ...node, obfs: { ...baseObfs, ...limits } }), SingBoxContentError);
  }
});

test("preserves a safe whole-blob SS plugin and does not reinterpret its fragment as the endpoint", () => {
  const share = "ss://" + Buffer.from(
    "aes-256-gcm:fixture@key@ss.example.invalid:8388/?plugin=obfs-local%3Bobfs%3Dhttp#@shadow.example.invalid:8888",
  ).toString("base64url");
  const { name, json } = serializeSingBoxOutbound({ share });
  assert.equal(name, "node");
  assert.deepEqual(JSON.parse(json), {
    type: "shadowsocks", server: "ss.example.invalid", server_port: 8388,
    method: "aes-256-gcm", password: "fixture@key", plugin: "obfs-local", plugin_opts: "obfs=http",
  });
});

test("rejects options that would be dropped or permit local file or executable access", () => {
  const native = { type: "trojan", server: "203.0.113.11", server_port: 443, password: "fixture-only" };
  for (const node of [
    { ...native, tls: { enabled: true, certificate_path: "/fixture/synthetic-file" } },
    { ...native, tls: { enabled: true, ech: { enabled: true, config_path: "/fixture/synthetic-file" } } },
    { ...native, tls: { enabled: true, ech: { enabled: true, config: "/fixture/synthetic-file" } } },
    { ...native, tls: { enabled: true, utls: { enabled: true, executable: "/fixture/synthetic-file" } } },
    { ...native, detour: "synthetic-file" },
    { ...native, domain_resolver: { server: "synthetic-file" } },
    { ...native, transport: { type: "ws", headers: { Host: "safe.example.invalid\r\nX-Fixture: synthetic-file" } } },
    { ...native, transport: { type: "ws", headers: { ["__proto__"]: { path: "synthetic-file" } } } },
    { ...base, plugin: "v2ray-plugin", "plugin-opts": "tls;cert=/fixture/synthetic-file" },
    { ...base, plugin: "/fixture/synthetic-program" },
    { ...base, share: "ss://malformed-synthetic-file", raw: corpus[1].node.share },
    { ...base, server: "bücher.example" },
    { ...base, name: "\ud800" },
    { ...base, password: "\ud800" },
    { share: "hy2://fixture@hy.example.invalid?ech=%2Ffixture%2Fsynthetic-file" },
    { share: "hy2://fixture@hy.example.invalid?ech=AAT-DQAA" },
    { share: "hy2://fixture@hy.example.invalid?pinSHA256=" + "a".repeat(64) },
    { share: "hy2://fixture@hy.example.invalid:443,5000-5002?mport=8443-8444" },
    { share: "vless://fixture@vless.example.invalid:443?type=grpc&mode=multi" },
    { share: "ss://aes-256-gcm:fixture@ss.example.invalid:8388?%2570lugin=synthetic-file" },
    { share: "vmess://fixture@vm.example.invalid:443" },
    { type: "ssh", server: "ssh.example.invalid", server_port: 22, private_key_path: "/fixture/synthetic-file" },
  ]) {
    assert.throws(() => serializeSingBoxOutbound(node), (error) =>
      error instanceof SingBoxContentError && !String(error).includes("synthetic-file"));
  }
});
