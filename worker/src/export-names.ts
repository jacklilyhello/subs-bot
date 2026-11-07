export function allocateExportNames(names: readonly string[], reserved: readonly string[]): string[] {
  // A generated suffix must not rename an original label that occurs later.
  const originals = new Set(names);
  const used = new Set(reserved);
  const nextSuffix = new Map<string, number>();
  return names.map((name) => {
    let tag = name;
    if (used.has(tag)) {
      let suffix = nextSuffix.get(name) ?? 2;
      do {
        tag = name + " (" + suffix++ + ")";
      } while (used.has(tag) || originals.has(tag));
      nextSuffix.set(name, suffix);
    }
    used.add(tag);
    return tag;
  });
}
