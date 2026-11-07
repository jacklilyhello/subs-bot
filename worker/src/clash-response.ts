import { serializeClashProxy, ClashContentError } from "./clash-export.ts";
import { allocateExportNames } from "./export-names.ts";
import { readSnapshotNodes, SnapshotIntegrityError, type SubscriptionSnapshot } from "./storage.ts";

const MAX_BYTES = 16 * 1024 * 1024;
const MAX_NAME_BYTES = 1024;
const MAX_NAMES_BYTES = 2 * 1024 * 1024;
const MAX_PROXIES = 25_000;
const MAX_HOPPING_PORTS = 1_048_576;
const SELECT_GROUP = "🚀 节点选择";
const AUTO_GROUP = "♻️ 自动选择";
const RESERVED_NAMES = ["DIRECT", "REJECT", "REJECT-DROP", "COMPATIBLE", "PASS", "PASS-RULE", "GLOBAL", SELECT_GROUP, AUTO_GROUP];
const OPEN = "proxies:\n";
const PROXY_ENTRY = '  - {"name":';
const PROXY_ENTRY_OVERHEAD = PROXY_ENTRY.length + 1;
const SELECT = 'proxy-groups:\n  - {"name":"' + SELECT_GROUP + '","type":"select","proxies":[';
const AUTO = ']}\n  - {"name":"' + AUTO_GROUP + '","type":"url-test","proxies":[';
const CLOSE = '],"url":"http://www.gstatic.com/generate_204","interval":300}\nrules:\n  - "MATCH,' + SELECT_GROUP + '"\n';
const encoder = new TextEncoder();

function yamlFlow(value: object | string): string {
  // JSON double quotes are valid YAML flow scalars. Escape the extra YAML
  // line separators and non-printing characters before framing each item.
  return JSON.stringify(value).replace(/[\u007f-\u009f\u2028\u2029\ufeff\ufffe\uffff]/gu,
    (char) => "\\u" + char.charCodeAt(0).toString(16).padStart(4, "0"));
}

interface ClashPlan {
  readonly bytes: number;
  readonly names: readonly string[];
}

export async function planClash(bucket: R2Bucket, snapshot: SubscriptionSnapshot): Promise<ClashPlan> {
  let bytes = encoder.encode(OPEN + SELECT + AUTO + CLOSE).byteLength;
  let namesBytes = 0;
  let expandedPorts = 0;
  const names: string[] = [];
  for await (const node of readSnapshotNodes(bucket, snapshot)) {
    const { name, proxy, hoppingPorts } = serializeClashProxy(node);
    const nameBytes = encoder.encode(yamlFlow(name)).byteLength;
    namesBytes += nameBytes;
    expandedPorts += hoppingPorts;
    bytes += encoder.encode(yamlFlow(proxy)).byteLength + PROXY_ENTRY_OVERHEAD;
    if (nameBytes > MAX_NAME_BYTES || namesBytes > MAX_NAMES_BYTES || names.length === MAX_PROXIES
      || expandedPorts > MAX_HOPPING_PORTS || bytes > MAX_BYTES) throw new ClashContentError();
    names.push(name);
  }
  if (names.length !== snapshot.nodeCount || names.length === 0) throw new SnapshotIntegrityError();
  const labels = allocateExportNames(names, RESERVED_NAMES).map((name) => {
    const encoded = yamlFlow(name);
    // The proxy and both groups contain the same label.
    bytes += 3 * encoder.encode(encoded).byteLength;
    return encoded;
  });
  bytes += 2 * (labels.length - 1);
  if (bytes > MAX_BYTES) throw new ClashContentError();
  return { bytes, names: labels };
}

export async function* clashChunks(
  bucket: R2Bucket, snapshot: SubscriptionSnapshot, plan: ClashPlan, signal: AbortSignal,
): AsyncGenerator<Uint8Array> {
  yield encoder.encode(OPEN);
  let index = 0;
  for await (const node of readSnapshotNodes(bucket, snapshot, signal)) {
    const name = plan.names[index++];
    if (name === undefined) throw new SnapshotIntegrityError();
    const { proxy } = serializeClashProxy(node);
    yield encoder.encode(PROXY_ENTRY + name + "," + yamlFlow(proxy).slice(1) + "\n");
  }
  if (signal.aborted) return;
  if (index !== plan.names.length) throw new SnapshotIntegrityError();
  const group = plan.names.join(",");
  yield encoder.encode(SELECT + group);
  if (!signal.aborted) yield encoder.encode(AUTO + group + CLOSE);
}
