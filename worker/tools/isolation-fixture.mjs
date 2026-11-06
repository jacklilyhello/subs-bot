import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";

const directory = process.argv[2];
const revision = process.env.BUILD_REVISION;
if (!directory || !/^[a-f0-9]{40}$/.test(revision ?? "")) {
  throw new Error("The hosted artifact directory and a full Git revision are required");
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

await writeFile(join(directory, "isolation.json"), JSON.stringify({
  version: 1,
  revision,
  compatibilityDate,
  bundleSha256: digest(await readFile(join(directory, "index.js"))),
  migrationSha256: digest(await readFile(join(directory, "0001_subscriptions.sql"))),
  snapshots: [
    await snapshot(1, "11111111-1111-4111-8111-111111111111", "subsbot-synthetic-small-01", 3),
    await snapshot(2, "22222222-2222-4222-8222-222222222222", "subsbot-synthetic-large-01", 9000),
  ],
}, null, 2) + "\n");
