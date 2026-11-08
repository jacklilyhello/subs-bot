/** Compare through the exact emitted Worker, with an in-memory short-row binding. */

import { createHash } from "node:crypto";
import { readFile, stat } from "node:fs/promises";
import { networkInterfaces } from "node:os";
import { createInterface } from "node:readline";
import { Log, LogLevel, Miniflare } from "miniflare";

const CODE = "oracle_00001";
const CODE_SHA256 = createHash("sha256").update(CODE).digest("hex");
const DIGEST = /^[a-f0-9]{64}$/u;
const outcomes = new Set(["equivalent", "worker-refused", "location-differs", "worker-unconfirmed"]);
const wrapper = `
import worker from './index.js';
const url = 'https://oracle.fixture.invalid/s/${CODE}';
const digest = '${CODE_SHA256}';
export default { async fetch(request, _env, ctx) {
  try {
    if (request.method !== 'POST' || new URL(request.url).pathname !== '/compare') return new Response(null, { status: 404 });
    const { target, legacySha } = await request.json();
    const db = { prepare(sql) {
      if (sql.includes('FROM sqlite_schema') && sql.includes('normal_short_links')) {
        return { async first() { return { normal: 2, legacySubscription: 1, migrationLedger: 1 }; } };
      }
      if (sql.includes('FROM normal_short_links') && sql.includes('FROM aggregate_links') && sql.includes('legacy_subscription_short_links')) {
        return { bind(...keys) {
          if (keys.length !== 3 || keys.some(key => key !== digest)) throw new Error();
          return { async all() { return { success: true, results: [{ kind: 'external', codeLength: 12,
            targetUrl: target, revokedAt: null, token: null, tokenSha256: null, format: null }] }; } };
        } };
      }
      throw new Error();
    } };
    const results = [];
    for (const method of ['GET', 'HEAD']) {
      const response = await worker.fetch(new Request(url, { method, redirect: 'manual' }), { DB: db }, ctx);
      const location = response.headers.get('Location');
      if (response.headers.get('Cache-Control') !== 'private, no-store' || response.headers.get('Referrer-Policy') !== 'no-referrer'
          || response.headers.get('X-Content-Type-Options') !== 'nosniff') return new Response('worker-unconfirmed');
      if (response.status === 404 && location === null && (method === 'GET' || response.body === null)) {
        if (response.body) await response.body.cancel();
        results.push('worker-refused');
      } else if (response.status === 302 && location !== null && response.body === null) {
        const bytes = new TextEncoder().encode(location);
        const hash = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)), b => b.toString(16).padStart(2, '0')).join('');
        results.push(hash);
      } else return new Response('worker-unconfirmed');
    }
    const state = results[0] !== results[1] ? 'worker-unconfirmed'
      : results[0] === 'worker-refused' ? 'worker-refused'
      : results[0] === legacySha ? 'equivalent' : 'location-differs';
    return new Response(state);
  } catch { return new Response('worker-unconfirmed'); }
} };
`;

async function compare() {
  const interfaces = networkInterfaces();
  if (process.platform !== "linux" || process.getuid?.() === 0 || Object.keys(interfaces).join() !== "lo"
    || !interfaces.lo?.some(({ address, internal }) => internal && address === "127.0.0.1")) throw new Error();
  const [bundle, expectedSha, compatibilityDate] = process.argv.slice(2);
  if (!bundle || !DIGEST.test(expectedSha) || !/^[0-9]{4}-[0-9]{2}-[0-9]{2}$/u.test(compatibilityDate)) throw new Error();
  const info = await stat(bundle);
  if (!info.isFile() || info.size < 1 || info.size > 4 * 1024 * 1024) throw new Error();
  const script = await readFile(bundle);
  if (script.length !== info.size || createHash("sha256").update(script).digest("hex") !== expectedSha) throw new Error();
  const runtime = new Miniflare({ compatibilityDate, log: new Log(LogLevel.NONE), modules: [
    { type: "ESModule", path: "oracle.js", contents: wrapper },
    { type: "ESModule", path: "index.js", contents: new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(script) },
  ], outboundService: () => { throw new Error("Oracle outbound denied."); } });
  const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });
  try {
    for await (const line of lines) {
      if (line.length > 3072) throw new Error();
      const { raw, legacySha } = JSON.parse(line);
      if (typeof raw !== "string" || !DIGEST.test(legacySha)) throw new Error();
      const bytes = Buffer.from(raw, "base64");
      if (!bytes.length || bytes.length > 2048 || bytes.toString("base64") !== raw) throw new Error();
      const target = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
      const result = await runtime.dispatchFetch("https://oracle.fixture.invalid/compare", {
        method: "POST", redirect: "manual", body: JSON.stringify({ target, legacySha }),
      });
      const outcome = await result.text();
      if (result.status !== 200 || !outcomes.has(outcome)) throw new Error();
      process.stdout.write(outcome + "\n");
    }
  } finally {
    lines.close();
    await runtime.dispose();
  }
}

try {
  await compare();
} catch {
  process.exitCode = 2;
}
