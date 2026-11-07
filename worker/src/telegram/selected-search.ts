import { CASED, CASE_IGNORABLE, LOWER_MAPPING } from "../unicode14-lower.ts";
import { collapsePathRuleWhitespace } from "../path-rules.ts";

export function unicode14Lower(value: string): string {
  const scalars = Array.from(value);
  const following = new Uint8Array(scalars.length);
  let cased = false;
  for (let index = scalars.length - 1; index >= 0; index -= 1) {
    following[index] = Number(cased);
    if (!CASE_IGNORABLE.test(scalars[index])) cased = CASED.test(scalars[index]);
  }
  cased = false;
  return scalars.map((scalar, index) => {
    const lower = scalar === "Σ" && cased && !following[index] ? "ς" : LOWER_MAPPING[scalar] ?? scalar;
    if (!CASE_IGNORABLE.test(scalar)) cased = CASED.test(scalar);
    return lower;
  }).join("");
}

export function selectedQuery(value: string): string | null {
  const normalized = collapsePathRuleWhitespace(value);
  if (Array.from(normalized).length > 256 || new TextEncoder().encode(normalized).byteLength > 1024
    || /[\u0000\ud800-\udfff]/u.test(normalized)) return null;
  return unicode14Lower(normalized);
}
