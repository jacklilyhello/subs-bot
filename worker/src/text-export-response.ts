import { allocateExportNames } from "./export-names.ts";
import { parseTextProxy, textProxyLine, TextExportError, type TextExportFormat } from "./text-export.ts";
import { SnapshotIntegrityError, type ExportNodeSource } from "./storage.ts";

const MAX_BYTES = 16 * 1024 * 1024;
const MAX_LINE_BYTES = 64 * 1024;
const MAX_NAME_BYTES = 1024;
const MAX_NAMES_BYTES = 2 * 1024 * 1024;
const MAX_NODES = 25_000;
const MAX_EXPANDED_PORTS = 1_048_576;
const SURGE_PREFIX = "[Proxy]\n";
const SURGE_SELECT = "Proxy = select, ";
const SURGE_GROUP = "\n[Proxy Group]\n" + SURGE_SELECT;
const SURGE_RULES = "\n\n[Rule]\nFINAL,Proxy\n";
const RESERVED_NAMES = ["Proxy", "DIRECT", "REJECT", "REJECT-DROP", "REJECT-NO-DROP", "REJECT-TINYGIF",
  "CELLULAR", "HYBRID", "NO-HYBRID"];
const encoder = new TextEncoder();

interface TextExportPlan {
  readonly bytes: number;
  readonly labels: readonly string[];
}

export async function planTextExport(
  source: ExportNodeSource, format: TextExportFormat,
): Promise<TextExportPlan> {
  let bytes = 0;
  let namesBytes = 0;
  let expanded = 0;
  const names: string[] = [];
  const lengths: number[] = [];
  for await (const node of source.read()) {
    const proxy = parseTextProxy(node, format);
    const nameBytes = encoder.encode(proxy.name).byteLength;
    const lineBytes = encoder.encode(textProxyLine(proxy, "", format)).byteLength;
    bytes += lineBytes;
    namesBytes += nameBytes;
    expanded += proxy.hoppingPorts;
    if (nameBytes > MAX_NAME_BYTES || namesBytes > MAX_NAMES_BYTES || lineBytes + nameBytes > MAX_LINE_BYTES
      || expanded > MAX_EXPANDED_PORTS || names.length === MAX_NODES || bytes > MAX_BYTES) throw new TextExportError();
    names.push(proxy.name);
    lengths.push(lineBytes);
  }
  if (names.length === 0 || names.length !== source.nodeCount) throw new SnapshotIntegrityError();

  const labels = allocateExportNames(names, RESERVED_NAMES, (name) => name.normalize("NFC").toLowerCase());
  let labelsBytes = 0;
  for (const [index, name] of labels.entries()) {
    const length = encoder.encode(name).byteLength;
    if (lengths[index] + length > MAX_LINE_BYTES) throw new TextExportError();
    labelsBytes += length;
  }
  bytes += labelsBytes;
  if (format === "surge") {
    const groupBytes = labelsBytes + 2 * (labels.length - 1);
    if (SURGE_SELECT.length + groupBytes + 1 > MAX_LINE_BYTES) throw new TextExportError();
    bytes += SURGE_PREFIX.length + SURGE_GROUP.length + groupBytes + SURGE_RULES.length;
  }
  if (bytes > MAX_BYTES) throw new TextExportError();
  return { bytes, labels };
}

export async function* textExportChunks(
  source: ExportNodeSource, format: TextExportFormat, plan: TextExportPlan, signal: AbortSignal,
): AsyncGenerator<Uint8Array> {
  if (format === "surge") yield encoder.encode(SURGE_PREFIX);
  let index = 0;
  for await (const node of source.read(signal)) {
    const name = plan.labels[index++];
    if (name === undefined) throw new SnapshotIntegrityError();
    yield encoder.encode(textProxyLine(parseTextProxy(node, format), name, format));
  }
  if (signal.aborted) return;
  if (index !== plan.labels.length) throw new SnapshotIntegrityError();
  if (format === "surge") yield encoder.encode(SURGE_GROUP + plan.labels.join(", ") + SURGE_RULES);
}
