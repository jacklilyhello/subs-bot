export function allocateExportNames(
  names: readonly string[], reserved: readonly string[], key: (name: string) => string = (name) => name,
): string[] {
  // A generated suffix must not rename an original label that occurs later.
  const originals = new Set(names.map(key));
  const used = new Set(reserved.map(key));
  const nextSuffix = new Map<string, number>();
  return names.map((name) => {
    let tag = name;
    const nameKey = key(name);
    if (used.has(nameKey)) {
      let suffix = nextSuffix.get(nameKey) ?? 2;
      do {
        tag = name + " (" + suffix++ + ")";
      } while (used.has(key(tag)) || originals.has(key(tag)));
      nextSuffix.set(nameKey, suffix);
    }
    used.add(key(tag));
    return tag;
  });
}
