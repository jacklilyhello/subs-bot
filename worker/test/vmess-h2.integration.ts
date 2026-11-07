import assert from "node:assert/strict";
import { execFile, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createServer as createEchoServer } from "node:http";
import { createSecureServer, type ServerHttp2Session } from "node:http2";
import { createConnection, type Server } from "node:net";
import { networkInterfaces, tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";

import { parse as parseYaml } from "yaml";

const loopback = "127.0.0.1";
const ports = { backend: 18780, relay: 18781, echo: 18782, socks: 18783 };
const uuid = "12345678-1234-4234-8234-123456789012";
const sni = "tls.fixture.invalid";
const authority = "front.fixture.invalid";
const path = "/fixture/vmess";
const proxyName = "vmess-h2-fixture";
const requestText = "fixture tunnel request";
const replyText = "fixture tunnel reply";
const expectedWire = { alpn: "h2", sni, authority, path, method: "PUT", encoding: "identity" };
const sha256 = (body: Buffer) => createHash("sha256").update(body).digest("hex");

function command(binary: string, args: string[], scratch: string, label: string): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile(binary, args, { cwd: scratch, timeout: 25_000, maxBuffer: 16_384 }, (error, stdout) => {
      if (error) reject(new Error(`${label} failed.`));
      else resolve(stdout);
    });
  });
}

async function listen(server: Server, port: number) {
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, loopback, () => {
      server.off("error", reject);
      resolve();
    });
  });
}

function start(binary: string, args: string[], scratch: string, env = process.env) {
  const child = spawn(binary, args, { cwd: scratch, env, stdio: "ignore" });
  let done = false;
  const exited = new Promise<void>((resolve) => {
    const finish = () => { done = true; resolve(); };
    child.once("error", finish);
    child.once("exit", finish);
  });
  return {
    async ready(port: number) {
      for (let attempt = 0; attempt < 100 && !done; attempt += 1) {
        const accepted = await new Promise<boolean>((resolve) => {
          const socket = createConnection({ host: loopback, port });
          socket.once("connect", () => { socket.destroy(); resolve(true); });
          socket.once("error", () => { socket.destroy(); resolve(false); });
        });
        if (accepted) return;
        await delay(50);
      }
      assert.fail("Fixture process did not open its loopback listener.");
    },
    async stop() {
      if (!done) child.kill("SIGKILL");
      await exited;
    },
  };
}

async function replay(directory: string, scratch: string, name: string, document: object) {
  const output = await mkdtemp(join(scratch, name + "-"));
  const body = Buffer.from(JSON.stringify(document));
  const bodyFile = join(output, "source.json");
  const controls = join(output, "request.json");
  await writeFile(bodyFile, body, { mode: 0o600 });
  await writeFile(controls, JSON.stringify({ source: "https://provider.example.invalid/vmess-h2",
    decodedBytes: body.length, bodySha256: sha256(body) }), { mode: 0o600 });
  const replayScript = fileURLToPath(new URL("../tools/provider-live-worker.ts", import.meta.url));
  await command(process.execPath, [replayScript, directory, bodyFile, output, controls], scratch, "Emitted Worker replay");
  const report = JSON.parse(await readFile(join(output, "worker.json"), "utf8"));
  assert.equal(report.job, "saved");
  assert.equal(report.document.nodes, 1);
  assert.equal(report.document.malformed, 0);
  assert.equal(report.document.unsupported, 0);
  assert.equal(report.formats.base64.status, 422);
  return {
    status: { clash: report.formats.clash.status, singbox: report.formats.singbox.status },
    async clash() {
      assert.equal(report.formats.clash.status, 200);
      const { proxies } = parseYaml(await readFile(join(output, "clash.body"), "utf8"));
      assert.equal(proxies.length, 1);
      assert.equal(proxies[0].name, proxyName);
      return proxies[0];
    },
    async singbox() {
      assert.equal(report.formats.singbox.status, 200);
      const { outbounds } = JSON.parse(await readFile(join(output, "singbox.body"), "utf8"));
      const proxies = outbounds.filter((outbound: { type: string }) => outbound.type === "vmess");
      assert.equal(proxies.length, 1);
      assert.equal(proxies[0].tag, proxyName);
      return proxies[0];
    },
  };
}

test("emitted VMess configurations tunnel through a verified loopback TLS H2 relay", { timeout: 120_000 }, async (t) => {
  const interfaces = networkInterfaces();
  assert.deepEqual(Object.keys(interfaces), ["lo"], "The fixture requires a loopback-only Linux network namespace.");
  assert.ok(interfaces.lo?.some(({ address, internal }) => address === loopback && internal));
  assert.ok(process.getuid && process.getuid() !== 0, "The fixture must run as the unprivileged runner.");
  const { WORKER_TEST_BUNDLE_DIR: directory, SINGBOX_TEST_BINARY: singbox, MIHOMO_TEST_BINARY: mihomo } = process.env;
  assert.ok(directory && singbox && mihomo);
  const manifest = JSON.parse(await readFile(join(directory, "isolation.json"), "utf8"));
  assert.equal(sha256(await readFile(join(directory, "index.js"))), manifest.bundleSha256);

  const scratch = await mkdtemp(join(tmpdir(), "vmess-h2-"));
  t.after(() => rm(scratch, { recursive: true, force: true }));
  const ca = join(scratch, "ca.pem");
  await command("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
    "-subj", "/CN=Synthetic VMess H2 fixture CA", "-addext", "basicConstraints=critical,CA:TRUE",
    "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-keyout", "ca.key", "-out", "ca.pem"], scratch, "Fixture CA generation");
  await command("openssl", ["req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", `/CN=${sni}`,
    "-keyout", "server.key", "-out", "server.csr"], scratch, "Fixture TLS key generation");
  await writeFile(join(scratch, "leaf.ext"), `subjectAltName=DNS:${sni}\nextendedKeyUsage=serverAuth\n`, { mode: 0o600 });
  await command("openssl", ["x509", "-req", "-in", "server.csr", "-CA", "ca.pem", "-CAkey", "ca.key",
    "-CAcreateserial", "-days", "1", "-extfile", "leaf.ext", "-out", "server.pem"], scratch, "Fixture TLS certificate signing");

  const echo = createEchoServer((request, response) => {
    const chunks: Buffer[] = [];
    let received = 0;
    request.on("data", (chunk: Buffer) => {
      received += chunk.length;
      if (received > requestText.length) request.destroy();
      else chunks.push(chunk);
    });
    request.on("end", () => {
      if (request.method !== "POST" || request.url !== "/tunnel-proof" || Buffer.concat(chunks).toString() !== requestText) {
        response.writeHead(400).end();
        return;
      }
      response.writeHead(200, { "Content-Type": "text/plain" }).end(replyText);
    });
  });
  await listen(echo, ports.echo);
  t.after(() => {
    echo.closeAllConnections();
    return new Promise<void>((resolve) => echo.close(() => resolve()));
  });

  const backendFile = join(scratch, "backend.json");
  await writeFile(backendFile, JSON.stringify({ log: { disabled: true },
    inbounds: [{ type: "vmess", listen: loopback, listen_port: ports.backend, users: [{ uuid, alterId: 0 }] }],
    outbounds: [{ type: "direct", tag: "direct" }], route: { final: "direct" },
  }), { mode: 0o600 });
  const backend = start(singbox, ["run", "-c", backendFile], scratch);
  t.after(() => backend.stop());
  await backend.ready(ports.backend);

  const wire: object[] = [];
  const relay = createSecureServer({ key: await readFile(join(scratch, "server.key")),
    cert: await readFile(join(scratch, "server.pem")), allowHTTP1: false });
  const sessions = new Set<ServerHttp2Session>();
  relay.on("session", (session) => {
    sessions.add(session);
    session.on("error", () => {});
    session.once("close", () => sessions.delete(session));
  });
  relay.on("stream", (stream, headers) => {
    wire.push({ alpn: stream.session?.alpnProtocol, sni: stream.session?.socket.servername,
      authority: headers[":authority"], path: headers[":path"], method: headers[":method"], encoding: headers["accept-encoding"] });
    if (headers[":method"] !== "PUT" || headers[":authority"] !== authority || headers[":path"] !== path) {
      stream.respond({ ":status": 400 });
      stream.end();
      return;
    }
    const peer = createConnection({ host: loopback, port: ports.backend });
    peer.on("error", () => stream.destroy());
    stream.on("error", () => peer.destroy());
    stream.once("close", () => peer.destroy());
    // Mihomo waits for response headers before writing the VMess request.
    stream.respond({ ":status": 200 });
    stream.pipe(peer);
    peer.pipe(stream);
  });
  await listen(relay, ports.relay);
  t.after(() => {
    for (const session of sessions) session.destroy();
    return new Promise<void>((resolve) => relay.close(() => resolve()));
  });

  const clashNode = { name: proxyName, type: "vmess", server: loopback, port: ports.relay, uuid,
    alterId: 0, cipher: "aes-128-gcm", udp: false, tls: true, servername: sni, network: "h2",
    "h2-opts": { host: [authority], path } };
  const singboxNode = { tag: proxyName, type: "vmess", server: loopback, server_port: ports.relay, uuid,
    alter_id: 0, security: "aes-128-gcm", network: "tcp", tls: { enabled: true, server_name: sni },
    transport: { type: "http", host: [authority], path, headers: { "Accept-Encoding": "identity" } } };
  const clashSource = await replay(directory, scratch, "clash", { proxies: [clashNode] });
  const singboxSource = await replay(directory, scratch, "singbox", { outbounds: [singboxNode] });

  async function probe(engine: "clash" | "singbox", outbound: Record<string, unknown>) {
    const config = join(scratch, `client-${engine}.json`);
    const clientConfig = engine === "clash"
      ? { "mixed-port": ports.socks, "bind-address": loopback, "allow-lan": false, "log-level": "silent",
        mode: "rule", proxies: [outbound], rules: [`MATCH,${proxyName}`] }
      : { log: { disabled: true }, certificate: { store: "none", certificate_path: [ca] },
        inbounds: [{ type: "socks", listen: loopback, listen_port: ports.socks }], outbounds: [outbound],
        route: { final: proxyName } };
    await writeFile(config, JSON.stringify(clientConfig), { mode: 0o600 });
    const client = engine === "clash" ? start(mihomo!, ["-d", scratch, "-f", config], scratch, { ...process.env, SSL_CERT_FILE: ca })
      : start(singbox!, ["run", "-c", config], scratch);
    const offset = wire.length;
    try {
      await client.ready(ports.socks);
      const response = await command("curl", ["--disable", "--silent", "--fail", "--max-time", "5", "--noproxy", "",
        "--proxy", `socks5h://${loopback}:${ports.socks}`, "--data-binary", requestText,
        `http://${loopback}:${ports.echo}/tunnel-proof`], scratch, "Fixture SOCKS tunnel");
      assert.ok(response === replyText, "The exact application bytes must traverse the tunnel.");
      assert.equal(wire.length - offset, 1);
      const observed = wire[offset] as Record<string, unknown>;
      for (const [field, expected] of Object.entries(expectedWire)) {
        assert.ok(observed[field] === expected, `Unexpected TLS H2 fixture ${field}.`);
      }
    } finally {
      await client.stop();
    }
  }

  await t.test("native Clash H2 preserves the tunneled bytes and request envelope", async () => {
    await probe("clash", await clashSource.clash());
  });
  await t.test("native Sing-box TLS HTTP preserves the tunneled bytes and request envelope", async () => {
    await probe("singbox", await singboxSource.singbox());
  });
  await t.test("Clash TLS H2 exported to Sing-box preserves the tunneled bytes and identity encoding", async () => {
    await probe("singbox", await clashSource.singbox());
  });
  await t.test("Sing-box TLS HTTP with identity encoding exports as working Clash H2", async () => {
    const outbound = await singboxSource.clash();
    assert.equal(outbound.network, "h2");
    await probe("clash", outbound);
  });
  await t.test("both cross-exports tunnel with explicit ChaCha20-Poly1305", async () => {
    const cipher = "chacha20-poly1305";
    const clash = await replay(directory, scratch, "clash-chacha", { proxies: [{ ...clashNode, cipher }] });
    const sing = await replay(directory, scratch, "singbox-chacha", { outbounds: [{ ...singboxNode, security: cipher }] });
    const outbound = await clash.singbox();
    assert.equal(outbound.security, cipher);
    await probe("singbox", outbound);
    const proxy = await sing.clash();
    assert.equal(proxy.cipher, cipher);
    await probe("clash", proxy);
  });
  await t.test("out-of-subset inputs preserve their native route and refuse the cross-export", async () => {
    const cleartext = await replay(directory, scratch, "clash-cleartext", {
      proxies: [{ ...clashNode, tls: false, servername: "" }],
    });
    assert.deepEqual(cleartext.status, { clash: 200, singbox: 422 });
    const autoCompression = await replay(directory, scratch, "singbox-compression", {
      outbounds: [{ ...singboxNode, transport: { type: "http", host: [authority], path } }],
    });
    assert.deepEqual(autoCompression.status, { clash: 422, singbox: 200 });
  });
});
