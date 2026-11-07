"""Emit Unicode 14 lowercase mappings and Final_Sigma context properties."""

from hashlib import sha256
import json
import sys
import unicodedata


def contexts(scalar):
    return (scalar, "AΣ" + scalar + "A", scalar + "Σ", "A" + scalar + "Σ")


def main():
    if (sys.implementation.name != "cpython" or sys.version_info[:2] != (3, 11)
            or unicodedata.unidata_version != "14.0.0"):
        raise SystemExit("Lowercase generation requires CPython 3.11 and Unicode 14.0.0.")
    mappings = []
    cased = []
    ignorable = []
    oracle = sha256()
    for point in range(0x110000):
        if 0xD800 <= point <= 0xDFFF:
            continue
        scalar = chr(point)
        lower = scalar.lower()
        if lower != scalar:
            mappings.append((scalar, lower))
        is_cased = scalar.islower() or scalar.isupper() or scalar.istitle()
        if is_cased:
            cased.append(point)
        # Final_Sigma skips Case_Ignorable before it tests Cased. CPython's
        # Unicode-14 oracle distinguishes even the overlap of those properties.
        is_ignorable = not (scalar + "Σ").lower().endswith("ς") if is_cased else ("AΣ" + scalar + "A").lower()[1] == "σ"
        if is_ignorable:
            ignorable.append(point)
        for value in contexts(scalar):
            oracle.update((json.dumps(value.lower(), ensure_ascii=False) + "\n").encode("utf-8"))

    def pattern(points):
        ranges = []
        for point in points:
            if ranges and ranges[-1][1] + 1 == point:
                ranges[-1][1] = point
            else:
                ranges.append([point, point])
        return "[" + "".join("\\u{" + format(start, "x") + "}" +
            ("-\\u{" + format(end, "x") + "}" if end != start else "") for start, end in ranges) + "]"

    print("// Generated only on hosted CI by tools/generate_lowercase.py, CPython 3.11 / Unicode 14.0.0.")
    print("// Unicode character data copyright 2021 Unicode, Inc. https://www.unicode.org/license.txt")
    print("// Final_Sigma context properties are derived from the pinned CPython lower oracle.")
    print("export const LOWER_MAPPING: Readonly<Record<string, string>> = {")
    for scalar, lower in mappings:
        print(f"  {json.dumps(scalar)}: {json.dumps(lower)},")
    print("};")
    print(f"export const CASED = new RegExp({json.dumps(pattern(cased))}, \"u\");")
    print(f"export const CASE_IGNORABLE = new RegExp({json.dumps(pattern(ignorable))}, \"u\");")
    print(f"export const LOWER_CONTEXT_ORACLE_SHA256 = {json.dumps(oracle.hexdigest())};")


if __name__ == "__main__":
    main()
