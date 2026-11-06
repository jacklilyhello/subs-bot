export type NodeRecord = Record<string, unknown>;

export interface SubscriptionSnapshot {
  id: number;
  generation: number;
  snapshotId: string;
  manifestSha256: string;
  nodeCount: number;
}

export interface SubscriptionMetadata {
  id: number;
  ownerId: string;
  name: string;
  sourceUrl: string;
  token: string;
  expireAt: number | null;
  trafficUsed: number | null;
  trafficTotal: number | null;
  lastError: string | null;
  createdAt: number;
  updatedAt: number;
  generation: number;
  nodeCount: number;
}

export interface SnapshotPublication {
  id: number;
  ownerId: string;
  expectedGeneration: number;
}

interface ChunkDescriptor {
  bytes: number;
  sha256: string;
  count: number;
}

interface SnapshotManifest {
  version: 1;
  chunks: ChunkDescriptor[];
}

export const MAX_CHUNK_BYTES = 512 * 1024;
export const MAX_SNAPSHOT_BYTES = 64 * 1024 * 1024;
export const MAX_SNAPSHOT_NODES = 100_000;
const MAX_CHUNKS = 256;
const MAX_MANIFEST_BYTES = 64 * 1024;
const MAX_OWNER_ID = 9223372036854775807n;
const TOKEN_PATTERN = /^[A-Za-z0-9_-]{16,128}(?![\s\S])/u;
const SNAPSHOT_ID_PATTERN = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}(?![\s\S])/u;
const SHA256_PATTERN = /^[a-f0-9]{64}(?![\s\S])/u;
const encoder = new TextEncoder();

export class SnapshotIntegrityError extends Error {
  constructor() {
    super("Subscription snapshot is unavailable or invalid.");
    this.name = "SnapshotIntegrityError";
  }
}

function checkOwnerId(ownerId: string): void {
  if (typeof ownerId !== "string" || !/^[1-9][0-9]{0,18}(?![\s\S])/u.test(ownerId) || BigInt(ownerId) > MAX_OWNER_ID) {
    throw new RangeError("Invalid subscription owner.");
  }
}

function validInteger(value: unknown, minimum: number, maximum = Number.MAX_SAFE_INTEGER): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= minimum && value <= maximum;
}

function isRecord(value: unknown): value is NodeRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export async function createSubscription(
  db: D1Database,
  input: { ownerId: string; name: string; sourceUrl: string },
): Promise<SubscriptionMetadata> {
  checkOwnerId(input.ownerId);
  if (typeof input.name !== "string" || !input.name.trim() || input.name.length > 512 || input.name.includes("\0") ||
      typeof input.sourceUrl !== "string" || !input.sourceUrl || input.sourceUrl.includes("\0") ||
      input.sourceUrl.length > 16384 || encoder.encode(input.sourceUrl).byteLength > 16384) {
    throw new RangeError("Invalid subscription metadata.");
  }
  const token = crypto.randomUUID().replaceAll("-", "");
  const now = Math.floor(Date.now() / 1000);
  const row = await db.prepare(`
    INSERT INTO subscriptions (owner_id, name, source_url, token, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?)
    RETURNING id
  `).bind(input.ownerId, input.name, input.sourceUrl, token, now, now).first<{ id: number }>();
  if (!row || !validInteger(row.id, 1)) {
    throw new Error("Subscription creation failed.");
  }
  return {
    id: row.id, ownerId: input.ownerId, name: input.name, sourceUrl: input.sourceUrl, token,
    expireAt: null, trafficUsed: null, trafficTotal: null, lastError: null, createdAt: now, updatedAt: now,
    generation: 0, nodeCount: 0,
  };
}

export async function getOwnedSubscription(
  db: D1Database,
  ownerId: string,
  id: number,
): Promise<SubscriptionMetadata | null> {
  checkOwnerId(ownerId);
  if (!validInteger(id, 1)) {
    throw new RangeError("Invalid subscription ID.");
  }
  return db.prepare(`
    SELECT id, owner_id AS ownerId, name, source_url AS sourceUrl, token, expire_at AS expireAt,
      traffic_used AS trafficUsed, traffic_total AS trafficTotal, last_error AS lastError,
      created_at AS createdAt, updated_at AS updatedAt, generation, node_count AS nodeCount
    FROM subscriptions WHERE id = ? AND owner_id = ?
  `).bind(id, ownerId).first<SubscriptionMetadata>();
}

export async function getSubscriptionSnapshot(db: D1Database, token: string): Promise<SubscriptionSnapshot | null> {
  if (typeof token !== "string" || !TOKEN_PATTERN.test(token)) {
    return null;
  }
  return db.prepare(`
    SELECT id, generation, snapshot_id AS snapshotId, manifest_sha256 AS manifestSha256, node_count AS nodeCount
    FROM subscriptions WHERE token = ? AND generation > 0
  `).bind(token).first<SubscriptionSnapshot>();
}

function snapshotPrefix(id: number, snapshotId: string): string {
  return `subscriptions/${id}/${snapshotId}/`;
}

function digestHex(digest: ArrayBuffer): string {
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function putImmutable(
  bucket: R2Bucket,
  key: string,
  bytes: Uint8Array<ArrayBuffer>,
): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  const created = await bucket.put(key, bytes, { onlyIf: { etagDoesNotMatch: "*" }, sha256: digest });
  if (!created) {
    throw new Error("Snapshot object could not be created.");
  }
  return digestHex(digest);
}

async function discardUnpublished(bucket: R2Bucket, keys: string[]): Promise<void> {
  if (keys.length !== 0) {
    // A failed cleanup must not affect the previous version or hide the publication error.
    await bucket.delete(keys).catch(() => {});
  }
}

export async function publishNodeSnapshot(
  db: D1Database,
  bucket: R2Bucket,
  target: SnapshotPublication,
  nodes: Iterable<NodeRecord> | AsyncIterable<NodeRecord>,
): Promise<boolean> {
  const { id, ownerId, expectedGeneration } = target;
  checkOwnerId(ownerId);
  if (!validInteger(id, 1) || !validInteger(expectedGeneration, 0, Number.MAX_SAFE_INTEGER - 1)) {
    throw new RangeError("Invalid subscription version.");
  }
  const row = await db.prepare(`
    SELECT generation FROM subscriptions WHERE id = ? AND owner_id = ?
  `).bind(id, ownerId).first<{ generation: number }>();
  if (!row || row.generation !== expectedGeneration) {
    return false;
  }

  const snapshotId = crypto.randomUUID();
  const prefix = snapshotPrefix(id, snapshotId);
  const manifest: SnapshotManifest = { version: 1, chunks: [] };
  const uploaded: string[] = [];
  const chunk = new Uint8Array(MAX_CHUNK_BYTES);
  const line = new Uint8Array(MAX_CHUNK_BYTES - 1);
  let chunkBytes = 0;
  let chunkNodes = 0;
  let totalBytes = 0;
  let nodeCount = 0;

  async function uploadChunk(): Promise<void> {
    if (manifest.chunks.length >= MAX_CHUNKS) {
      throw new RangeError("Subscription snapshot exceeds storage limits.");
    }
    const body = chunk.subarray(0, chunkBytes);
    const key = `${prefix}${manifest.chunks.length}.ndjson`;
    const hash = await putImmutable(bucket, key, body);
    uploaded.push(key);
    manifest.chunks.push({ bytes: chunkBytes, sha256: hash, count: chunkNodes });
    chunkBytes = 0;
    chunkNodes = 0;
  }

  let manifestHash: string;
  try {
    for await (const node of nodes) {
      if (!isRecord(node)) {
        throw new TypeError("Invalid subscription node.");
      }
      let json: string;
      try {
        json = JSON.stringify(node);
      } catch {
        throw new TypeError("Invalid subscription node.");
      }
      if (!json?.startsWith("{")) {
        throw new TypeError("Invalid subscription node.");
      }
      const { read, written } = encoder.encodeInto(json, line);
      if (read !== json.length || ++nodeCount > MAX_SNAPSHOT_NODES ||
          (totalBytes += written + 1) > MAX_SNAPSHOT_BYTES) {
        throw new RangeError("Subscription snapshot exceeds storage limits.");
      }
      if (chunkBytes + written + 1 > MAX_CHUNK_BYTES) {
        await uploadChunk();
      }
      chunk.set(line.subarray(0, written), chunkBytes);
      chunk[chunkBytes + written] = 10;
      chunkBytes += written + 1;
      chunkNodes += 1;
    }
    if (nodeCount === 0) {
      throw new RangeError("Cannot publish an empty subscription snapshot.");
    }
    await uploadChunk();
    const body = encoder.encode(JSON.stringify(manifest));
    const key = `${prefix}manifest.json`;
    manifestHash = await putImmutable(bucket, key, body);
    uploaded.push(key);
  } catch (error) {
    await discardUnpublished(bucket, uploaded);
    throw error;
  }

  // A failed or ambiguous D1 call may have committed. Only a confirmed CAS miss permits deletion.
  const result = await db.prepare(`
    UPDATE subscriptions
    SET generation = generation + 1, snapshot_id = ?, manifest_sha256 = ?, node_count = ?,
        last_error = NULL, updated_at = ?
    WHERE id = ? AND owner_id = ? AND generation = ?
  `).bind(snapshotId, manifestHash, nodeCount, Math.floor(Date.now() / 1000), id, ownerId, expectedGeneration).run();
  if (!result.success) {
    throw new Error("Subscription snapshot publication failed.");
  }
  if (result.meta.changes === 0) {
    await discardUnpublished(bucket, uploaded);
    return false;
  }
  return true;
}

async function loadObject(bucket: R2Bucket, key: string, hash: string, limit: number, size?: number): Promise<string> {
  const object = await bucket.get(key);
  if (!object) {
    throw new SnapshotIntegrityError();
  }
  if (!validInteger(object.size, 1, limit) || (size !== undefined && object.size !== size)) {
    await object.body.cancel();
    throw new SnapshotIntegrityError();
  }
  const bytes = new Uint8Array(await object.arrayBuffer());
  if (bytes.byteLength !== object.size || digestHex(await crypto.subtle.digest("SHA-256", bytes)) !== hash) {
    throw new SnapshotIntegrityError();
  }
  return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
}

function readManifest(raw: string, nodeCount: number): SnapshotManifest {
  const value: unknown = JSON.parse(raw);
  if (!isRecord(value) || value.version !== 1 || !Array.isArray(value.chunks) ||
      value.chunks.length === 0 || value.chunks.length > MAX_CHUNKS) {
    throw new SnapshotIntegrityError();
  }
  const chunks: ChunkDescriptor[] = [];
  let totalBytes = 0;
  let totalNodes = 0;
  for (const chunk of value.chunks) {
    if (!isRecord(chunk) || !validInteger(chunk.bytes, 1, MAX_CHUNK_BYTES) ||
        typeof chunk.sha256 !== "string" || !SHA256_PATTERN.test(chunk.sha256) ||
        !validInteger(chunk.count, 1, nodeCount)) {
      throw new SnapshotIntegrityError();
    }
    chunks.push({ bytes: chunk.bytes, sha256: chunk.sha256, count: chunk.count });
    totalBytes += chunk.bytes;
    totalNodes += chunk.count;
  }
  if (totalBytes > MAX_SNAPSHOT_BYTES || totalNodes !== nodeCount) {
    throw new SnapshotIntegrityError();
  }
  return { version: 1, chunks };
}

export async function* readSnapshotNodes(bucket: R2Bucket, snapshot: SubscriptionSnapshot): AsyncGenerator<NodeRecord> {
  if (!validInteger(snapshot.id, 1) || !validInteger(snapshot.generation, 1) ||
      !SNAPSHOT_ID_PATTERN.test(snapshot.snapshotId) || !SHA256_PATTERN.test(snapshot.manifestSha256) ||
      !validInteger(snapshot.nodeCount, 1, MAX_SNAPSHOT_NODES)) {
    throw new SnapshotIntegrityError();
  }
  const prefix = snapshotPrefix(snapshot.id, snapshot.snapshotId);
  try {
    const rawManifest = await loadObject(bucket, `${prefix}manifest.json`, snapshot.manifestSha256, MAX_MANIFEST_BYTES);
    const manifest = readManifest(rawManifest, snapshot.nodeCount);
    for (const [index, chunk] of manifest.chunks.entries()) {
      const text = await loadObject(bucket, `${prefix}${index}.ndjson`, chunk.sha256, MAX_CHUNK_BYTES, chunk.bytes);
      let offset = 0;
      for (let record = 0; record < chunk.count; record += 1) {
        const end = text.indexOf("\n", offset);
        if (end <= offset) {
          throw new SnapshotIntegrityError();
        }
        const value: unknown = JSON.parse(text.slice(offset, end));
        if (!isRecord(value)) {
          throw new SnapshotIntegrityError();
        }
        yield value;
        offset = end + 1;
      }
      if (offset !== text.length) {
        throw new SnapshotIntegrityError();
      }
    }
  } catch {
    throw new SnapshotIntegrityError();
  }
}
