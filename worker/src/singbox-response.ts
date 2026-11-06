import { serializeSingBoxOutbound, SingBoxContentError } from "./singbox-export.ts";
import { readSnapshotNodes, SnapshotIntegrityError, type SubscriptionSnapshot } from "./storage.ts";

const MAX_EXPORT_BYTES = 16 * 1024 * 1024;
const MAX_NAME_BYTES = 1024;
const MAX_NAMES_BYTES = 2 * 1024 * 1024;
const MAX_OUTBOUNDS = 25_000;
const OPEN = '{"outbounds":[{"type":"selector","tag":"proxy","outbounds":[';
const DIRECT = ']},{"type":"direct","tag":"direct"}';
const CLOSE = "]}";
const TAGGED_OUTBOUND_OVERHEAD = ',{"tag":,'.length - 1;
const encoder = new TextEncoder();

interface SingBoxPlan {
  readonly bytes: number;
  readonly tags: readonly string[];
}

export async function planSingBox(
  bucket: R2Bucket, snapshot: SubscriptionSnapshot,
): Promise<SingBoxPlan> {
  let namesBytes = 0;
  let bytes = OPEN.length + DIRECT.length + CLOSE.length;
  const names: string[] = [];
  for await (const node of readSnapshotNodes(bucket, snapshot)) {
    const { name, json } = serializeSingBoxOutbound(node);
    const nameBytes = encoder.encode(JSON.stringify(name)).byteLength;
    namesBytes += nameBytes;
    bytes += encoder.encode(json).byteLength + TAGGED_OUTBOUND_OVERHEAD;
    if (nameBytes > MAX_NAME_BYTES || namesBytes > MAX_NAMES_BYTES
      || names.length === MAX_OUTBOUNDS || bytes > MAX_EXPORT_BYTES) throw new SingBoxContentError();
    names.push(name);
  }
  if (names.length !== snapshot.nodeCount || names.length === 0) throw new SnapshotIntegrityError();

  // Reserve original names even when a later outbound will use them.
  const originals = new Set(names);
  const used = new Set(["proxy", "direct"]);
  const nextSuffix = new Map<string, number>();
  const tags = names.map((name) => {
    let tag = name;
    if (used.has(tag)) {
      let suffix = nextSuffix.get(name) ?? 2;
      do {
        tag = name + " (" + suffix++ + ")";
      } while (used.has(tag) || originals.has(tag));
      nextSuffix.set(name, suffix);
    }
    used.add(tag);
    const quoted = JSON.stringify(tag);
    bytes += 2 * encoder.encode(quoted).byteLength;
    return quoted;
  });
  bytes += tags.length - 1;
  if (bytes > MAX_EXPORT_BYTES) throw new SingBoxContentError();
  return { bytes, tags };
}

export async function* singBoxChunks(
  bucket: R2Bucket, snapshot: SubscriptionSnapshot, plan: SingBoxPlan, signal: AbortSignal,
): AsyncGenerator<Uint8Array> {
  yield encoder.encode(OPEN + plan.tags.join(",") + DIRECT);
  let index = 0;
  for await (const node of readSnapshotNodes(bucket, snapshot, signal)) {
    const tag = plan.tags[index++];
    if (tag === undefined) throw new SnapshotIntegrityError();
    const { json } = serializeSingBoxOutbound(node);
    yield encoder.encode(',{"tag":' + tag + "," + json.slice(1));
  }
  if (signal.aborted) return;
  if (index !== plan.tags.length) throw new SnapshotIntegrityError();
  yield encoder.encode(CLOSE);
}
