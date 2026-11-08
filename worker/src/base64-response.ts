import { SnapshotIntegrityError, type ExportNodeSource, type NodeRecord } from "./storage.ts";
import { isValidStoredShare } from "./stored-share.ts";
import { serializeStructuredShare } from "./structured-share.ts";

const MAX_SHARE_BYTES = 16 * 1024 * 1024;
// Every complete chunk ends on a Base64 group boundary.
const SHARE_CHUNK_BYTES = 24 * 1024;

export class ExportContentError extends Error {}
export class ShareByteLimitError extends ExportContentError {}

function shareLine(node: NodeRecord): string {
  const stored = node.share;
  if (stored === undefined || stored === null || stored === "") {
    const generated = serializeStructuredShare(node);
    if (generated !== null) return generated;
  } else if (isValidStoredShare(stored)) {
    return stored;
  }
  throw new ExportContentError();
}

export async function* rawShareBytes(
  source: ExportNodeSource, signal?: AbortSignal, maxBytes = MAX_SHARE_BYTES,
): AsyncGenerator<Uint8Array> {
  const encoder = new TextEncoder();
  let total = 0;
  let count = 0;
  for await (const node of source.read(signal)) {
    count += 1;
    const share = shareLine(node);
    const line = encoder.encode(total === 0 ? share : `\n${share}`);
    total += line.length;
    if (total > maxBytes) throw new ShareByteLimitError();
    yield line;
  }
  if (!signal?.aborted && count !== source.nodeCount) throw new SnapshotIntegrityError();
}

export async function planBase64(source: ExportNodeSource, signal?: AbortSignal): Promise<number> {
  let shareLength = 0;
  for await (const line of rawShareBytes(source, signal)) shareLength += line.byteLength;
  if (shareLength === 0 || signal?.aborted) throw new SnapshotIntegrityError();
  return 4 * Math.ceil(shareLength / 3);
}

export async function* base64Chunks(source: ExportNodeSource, signal: AbortSignal): AsyncGenerator<Uint8Array> {
  const encoder = new TextEncoder();
  const chunk = new Uint8Array(SHARE_CHUNK_BYTES);
  let offset = 0;
  for await (const line of rawShareBytes(source, signal)) {
    for (let start = 0; start < line.length;) {
      const length = Math.min(line.length - start, chunk.length - offset);
      chunk.set(line.subarray(start, start + length), offset);
      start += length;
      offset += length;
      if (offset === chunk.length) {
        yield encoder.encode(btoa(String.fromCharCode(...chunk)));
        offset = 0;
      }
    }
  }
  if (offset !== 0) yield encoder.encode(btoa(String.fromCharCode(...chunk.subarray(0, offset))));
}
