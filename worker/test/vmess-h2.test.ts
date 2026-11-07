import assert from "node:assert/strict";
import { test } from "node:test";

import { ClashContentError, serializeClashProxy } from "../src/clash-export.ts";
import { serializeSingBoxOutbound, SingBoxContentError } from "../src/singbox-export.ts";
import type { NodeRecord } from "../src/storage.ts";

const endpoint = { type: "vmess", server: "fixture.example.invalid", uuid: "12345678-1234-4234-8234-123456789012" };
const clash = { ...endpoint, port: 443, tls: true, network: "h2", cipher: "aes-128-gcm" };
const tls = { enabled: true };
const headers = { "aCcEpT-EnCoDiNg": ["identity"] };
const transport = { type: "http", method: "PUT", headers };
const singbox = { ...endpoint, server_port: 443, security: "aes-128-gcm", tls, transport };

const toSingBox = (node: NodeRecord) => JSON.parse(serializeSingBoxOutbound(node).json);
const toClash = (node: NodeRecord) => serializeClashProxy(node).proxy;

test("cross-export retains checked H2 defaults and authority bytes", () => {
  const defaultForward = toSingBox(clash);
  assert.equal(defaultForward.network, "tcp");
  assert.deepEqual(defaultForward.transport, { type: "http", headers: { "Accept-Encoding": "identity" } });
  const hosts = ["front.example.invalid:443", "[2001:db8::1]"];
  const path = "/a/~b_1.2";
  const forward = toSingBox({ ...clash, alpn: ["h2"], "h2-opts": { host: hosts, path }, udp: true });
  assert.equal(forward.network, undefined);
  assert.deepEqual(forward.transport, { type: "http", host: hosts, path, headers: { "Accept-Encoding": "identity" } });
  const reverse = toClash({ ...singbox, tls: { ...tls, alpn: "h2" }, transport: { ...transport, host: hosts, path } });
  assert.equal(reverse.network, "h2");
  assert.equal(reverse.udp, true);
  assert.deepEqual(JSON.parse(JSON.stringify(reverse["h2-opts"])), { host: hosts, path });
});

test("Clash H2 refuses cross-export when its request or TLS would differ", () => {
  for (const node of [
    { ...clash, cipher: "auto" },
    { ...clash, alterId: 1 },
    { ...clash, alpn: ["h2", "http/1.1"] },
    { ...clash, "client-fingerprint": "chrome" },
    { ...clash, "h2-opts": { path: "/escaped%2Fsegment" } },
    { ...clash, "h2-opts": { path: "//fixture.example.invalid/path" } },
    { ...clash, "h2-opts": { host: ["fixture.example.invalid:0"] } },
    { ...clash, "h2-opts": { host: ["fixture.example.invalid/other"] } },
  ]) {
    assert.equal(toClash(node).network, "h2");
    assert.throws(() => toSingBox(node), SingBoxContentError);
  }
});

test("native Sing-box HTTP is portable only with the exact TLS-H2 request semantics", () => {
  for (const node of [
    { ...singbox, tls: { enabled: false } },
    { ...singbox, tls: { ...tls, alpn: ["http/1.1"] } },
    { ...singbox, tls: { ...tls, min_version: "1.3" } },
    { ...singbox, security: "auto" },
    { ...singbox, transport: { ...transport, method: "GET" } },
    { ...singbox, transport: { ...transport, path: "/escaped%2Fsegment" } },
    { ...singbox, transport: { ...transport, headers: { "Accept-Encoding": "gzip" } } },
    { ...singbox, transport: { ...transport, headers: { ...headers, "X-Fixture": "one" } } },
    { ...singbox, transport: { ...transport, idle_timeout: "1s" } },
  ]) {
    assert.deepEqual(toSingBox(node).transport, node.transport);
    assert.throws(() => toClash(node), ClashContentError);
  }
});
