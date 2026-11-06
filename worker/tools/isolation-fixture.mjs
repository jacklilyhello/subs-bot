import { createHash } from "node:crypto";
import { mkdir, readdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";

const directory = process.argv[2];
const revision = process.env.BUILD_REVISION;
const ref = process.env.GITHUB_REF;
const runId = process.env.GITHUB_RUN_ID;
const runAttempt = process.env.GITHUB_RUN_ATTEMPT;
if (!directory || !/^[a-f0-9]{40}$/.test(revision ?? "") || !ref?.startsWith("refs/")
    || !/^[1-9][0-9]*$/.test(runId ?? "") || !/^[1-9][0-9]*$/.test(runAttempt ?? "")) {
  throw new Error("The hosted artifact directory and exact GitHub build provenance are required");
}

const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const compatibilityDate = "2026-07-30";
const chunkLimit = 512 * 1024;

async function putFile(file, bytes) {
  const path = join(directory, file);
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, bytes);
  return { file, bytes: Buffer.byteLength(bytes), sha256: digest(bytes) };
}

async function snapshot(id, snapshotId, token, count) {
  const prefix = `subscriptions/${id}/${snapshotId}`;
  const objects = [];
  const chunks = [];
  const shares = [];
  let lines = [];
  let bytes = 0;

  async function flush() {
    if (lines.length === 0) return;
    const key = `${prefix}/${chunks.length}.ndjson`;
    const object = await putFile(`r2/${key}`, lines.join(""));
    objects.push({ key, ...object });
    chunks.push({ bytes: object.bytes, sha256: object.sha256, count: lines.length });
    lines = [];
    bytes = 0;
  }

  for (let i = 0; i < count; i++) {
    const name = `Synthetic node ${i} ${"x".repeat(120)}`;
    const password = `fixture-only-${i}`;
    const userinfo = Buffer.from(`aes-256-gcm:${password}`).toString("base64url");
    const share = `ss://${userinfo}@203.0.113.10:8388#${encodeURIComponent(name)}`;
    const line = JSON.stringify({
      name, type: "ss", server: "203.0.113.10", port: 8388, cipher: "aes-256-gcm", password, share,
    }) + "\n";
    const length = Buffer.byteLength(line);
    if (bytes + length > chunkLimit) await flush();
    lines.push(line);
    bytes += length;
    shares.push(share);
  }
  await flush();
  const key = `${prefix}/manifest.json`;
  const manifest = await putFile(`r2/${key}`, JSON.stringify({ version: 1, chunks }));
  objects.push({ key, ...manifest });
  const body = Buffer.from(shares.join("\n")).toString("base64");
  return {
    id, token, snapshotId, nodeCount: count, manifestSha256: manifest.sha256,
    nodeBytes: chunks.reduce((total, chunk) => total + chunk.bytes, 0),
    bodyBytes: Buffer.byteLength(body), bodySha256: digest(body), objects,
  };
}

const migrations = [];
const migrationNames = (await readdir(directory)).filter((name) => name.endsWith(".sql")).sort();
if (migrationNames[0] !== "0001_subscriptions.sql") throw new Error("Missing baseline migration");
for (const [index, name] of migrationNames.entries()) {
  if (!/^[0-9]{4}_[a-z][a-z0-9_]*\.sql$/.test(name) || Number(name.slice(0, 4)) !== index + 1) {
    throw new Error("Invalid migration filename or order");
  }
  migrations.push({ name, sha256: digest(await readFile(join(directory, name))) });
}

await writeFile(join(directory, "isolation.json"), JSON.stringify({
  version: 2,
  ref,
  runId,
  runAttempt,
  revision,
  compatibilityDate,
  bundleSha256: digest(await readFile(join(directory, "index.js"))),
  migrations,
  snapshots: [
    await snapshot(1, "11111111-1111-4111-8111-111111111111", "subsbot-synthetic-small-01", 3),
    await snapshot(2, "22222222-2222-4222-8222-222222222222", "subsbot-synthetic-large-01", 9000),
  ],
}, null, 2) + "\n");
