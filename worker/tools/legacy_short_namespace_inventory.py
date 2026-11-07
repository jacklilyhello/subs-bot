"""Seal a closed, read-only inventory of legacy mixed short-link rows."""

from __future__ import annotations

from collections import Counter
from contextlib import closing, suppress
from hashlib import sha256
from ipaddress import ip_address, ip_network
import os
from pathlib import Path
import re
import sqlite3
import stat
import sys
from urllib.parse import unquote_to_bytes, urlsplit
from unicodedata import category

import legacy_typed_short_inventory as typed
from legacy_inventory import InventoryError as BackupError
from legacy_snapshot_convert import (
    ConversionError, HASH, MAX_OWNER, MAX_SAFE_ID, OWNER, _bounded_json, _json, _owner_map, _safe_path,
)

ROWS = "namespace.ndjson"
MANIFEST = "manifest.json"
SEAL = "manifest.sha256"
MAX_METADATA_BYTES = 64 * 1024**2
MAX_TARGET_BYTES = 4096
MAX_EXTERNAL_BYTES = 2048
MAX_SELECTED = 128
KINDS = ("typed-subscription", "aggregate-all", "aggregate-selected", "external", "unclassified")
IDS_PREFIX = b"aggregate://ids/"
ACTIVE_SCHEMA = re.compile(
    r"\ACREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?subscriptions\s*\(\s*"
    r"id\s+INTEGER\s+PRIMARY\s+KEY\s+AUTOINCREMENT\s*,", re.ASCII | re.IGNORECASE,
)
IDS = re.compile(rb"[1-9][0-9]{0,15}(?:,[1-9][0-9]{0,15})*\Z")
NUMERIC_LABEL = re.compile(r"(?:[0-9]+|0x[0-9a-f]*)\Z", re.ASCII)
HTTP_AUTHORITY = re.compile(r"(?:\[[^\]]+\]|[^:]+)(?::[0-9]{1,5})?\Z", re.ASCII)
GLOBAL_IPV6 = ip_network("2000::/3")
BAD_ESCAPE = re.compile(r"%(?![A-Fa-f0-9]{2})")
LOCAL_SUFFIXES = (".localhost", ".localdomain", ".local", ".internal", ".home.arpa", ".test", ".invalid",
                  ".example", ".onion", ".lan", ".home", ".corp", ".svc")
FAILURE = "Legacy short namespace inventory could not be confirmed safely."
USAGE = ("Usage: legacy_short_namespace_inventory.py BACKUP OUTPUT SOURCE_SHA256 OWNER_MAP_JSON "
         "OWNER_MAP_SHA256 OLD_HTTPS_ORIGIN LEGACY_BOT_ID")


class InventoryError(RuntimeError):
    """A redacted, fixed failure for invalid inventory evidence."""


def require(condition: object) -> None:
    if not condition:
        raise InventoryError(FAILURE)


def blocked(kind: str, reason: str) -> dict:
    return {"kind": kind, "state": "blocked", "reason": reason}


def active_high_water(db: sqlite3.Connection, max_active_id: int) -> int:
    definition = db.execute("SELECT sql FROM main.sqlite_schema WHERE type='table' AND name='subscriptions'").fetchone()
    require(definition is not None and ACTIVE_SCHEMA.match(definition[0]))
    sequence = db.execute("""
        SELECT CASE WHEN typeof(name)='text' AND length(CAST(name AS BLOB))=length('subscriptions') THEN name END,
            CASE WHEN typeof(seq)='integer' THEN seq END
        FROM main.sqlite_sequence WHERE lower(name)='subscriptions' LIMIT 2
    """).fetchall()
    require(len(sequence) <= 1 and (not sequence or sequence[0][0] == "subscriptions"))
    high = sequence[0][1] if sequence else 0
    require(type(high) is int and max_active_id <= high <= MAX_SAFE_ID)
    return high


def read_target(db: sqlite3.Connection, rowid: int, storage_type: str) -> tuple[bytes | None, str | None]:
    if storage_type != "text":
        return None, "target-not-text"
    with db.blobopen("short_links", "target_url", rowid, readonly=True) as blob:
        if len(blob) > MAX_TARGET_BYTES:
            return None, "target-limit"
        return blob.read(), None


def unsafe_url_text(text: str) -> bool:
    return any(ch.isspace() or ch in '\\<>"' or category(ch) in ("Cc", "Cf", "Cs", "Zl", "Zp") for ch in text)


def classify_external(target: bytes, old_host: str) -> dict:
    kind = "external"
    try:
        text = target.decode("utf-8", "strict")
        if unsafe_url_text(text) or BAD_ESCAPE.search(text):
            return blocked(kind, "external-url-shape")
        parsed = urlsplit(text)
        host = (parsed.hostname or "").removesuffix(".").lower()
        if host == old_host:
            return blocked("unclassified", "untyped-first-party-target")
        if len(target) > MAX_EXTERNAL_BYTES:
            return blocked(kind, "external-target-limit")
        if (not host or not host.isascii() or "@" in parsed.netloc or "%" in parsed.netloc
                or not HTTP_AUTHORITY.fullmatch(parsed.netloc) or parsed.port == 0):
            return blocked(kind, "external-authority")
        decoded = unquote_to_bytes(text).decode("utf-8", "strict")
        if any(ch == "\\" or category(ch) in ("Cc", "Cf", "Cs", "Zl", "Zp") for ch in decoded):
            return blocked(kind, "external-url-shape")
        try:
            address = ip_address(host)
        except ValueError:
            labels = host.split(".")
            if (len(labels) < 2 or len(host) > 253 or host == "home.arpa" or host.endswith(LOCAL_SUFFIXES)
                    or NUMERIC_LABEL.fullmatch(labels[-1]) or not all(typed._HOST_LABEL.fullmatch(label) for label in labels)):
                return blocked(kind, "external-authority")
        else:
            if not address.is_global or address.is_multicast or (address.version == 6 and address not in GLOBAL_IPV6):
                return blocked(kind, "external-authority")
    except (UnicodeError, ValueError):
        return blocked(kind, "external-url-shape")
    # Final redirect equivalence and runtime URL policy require the separate emitted-Worker oracle.
    return {"kind": kind, "state": "classified"}


def classify(target: bytes, issuer: int, origin: bytes, coalesced: set[str],
             targets: dict[bytes, tuple[str, int, int]], active: dict[int, int], high: int) -> dict:
    if target == b"aggregate://all":
        kind = "aggregate-all"
        if issuer < 0 or str(issuer) in coalesced:
            return blocked(kind, "aggregate-all-owner-scope")
        return {"kind": kind, "state": "classified"}
    if target.startswith(IDS_PREFIX):
        kind = "aggregate-selected"
        selector = target[len(IDS_PREFIX):]
        if not IDS.fullmatch(selector):
            return blocked(kind, "aggregate-selected-shape")
        if selector.count(b",") >= MAX_SELECTED:
            return blocked(kind, "aggregate-selected-limit")
        ids = [int(value) for value in selector.split(b",")]
        if any(value > high for value in ids):
            return blocked(kind, "aggregate-selected-lineage")
        if any(value in active and active[value] != issuer for value in ids):
            return blocked(kind, "aggregate-selected-foreign-owner")
        return {"kind": kind, "state": "classified", "legacyIds": ids,
                "activePositions": [position for position, value in enumerate(ids) if value in active]}
    if target.startswith(origin + b"/sub/"):
        kind = "typed-subscription"
        match = typed._TARGET.fullmatch(target[len(origin):])
        if not match:
            return blocked(kind, "typed-target-shape")
        token, alias = match.groups()
        format_name = alias.decode("ascii") if alias else ""
        if format_name not in typed.FORMATS:
            return blocked(kind, "typed-format")
        if token not in targets:
            return blocked(kind, "typed-target-missing")
        table, legacy_id, original_owner = targets[token]
        if issuer != original_owner:
            return blocked(kind, "typed-foreign-owner")
        return {"kind": kind, "state": "classified", "legacyTable": table, "legacyId": legacy_id,
                "tokenSha256": sha256(token).hexdigest(), "format": format_name}
    if target.startswith((b"http://", b"https://")):
        return classify_external(target, origin[len(b"https://"):].decode("ascii"))
    return blocked("unclassified", "unrecognized-target")


def write_rows(db: sqlite3.Connection, output: Path, origin: bytes, owners: dict[str, str]) -> tuple[dict, dict]:
    tables = typed._tables(db)
    present = "short_links" in tables
    targets = typed._targets(db, tables) if present else {}
    active = {identity: owner for table, identity, owner in targets.values() if table == "subscriptions"}
    max_active = db.execute("SELECT COALESCE(max(id),0) FROM main.subscriptions").fetchone()[0]
    require(type(max_active) is int and max_active >= 0 and (not present or max_active == max(active, default=0)))
    high = active_high_water(db, max_active)
    source_count = db.execute("SELECT count(*) FROM main.short_links").fetchone()[0] if present else 0
    require(type(source_count) is int and 0 <= source_count <= typed.MAX_SHORTS)
    coalesced = {owner for original, owner in owners.items() if original != owner}
    kinds = Counter(dict.fromkeys(KINDS, 0))
    reasons = Counter()
    seen = set()

    def lines():
        if not source_count:
            return
        rows = db.execute("""
            SELECT rowid, typeof(code), typeof(target_url),
                CASE WHEN typeof(user_id)='integer' THEN user_id END,
                CASE WHEN typeof(created_at)='integer' THEN created_at END
            FROM main.short_links ORDER BY rowid LIMIT ?
        """, (typed.MAX_SHORTS + 1,))
        for rowid, code_type, target_type, issuer, created in rows:
            code = typed._text_bytes(db, "short_links", "code", rowid, code_type, 12)
            require(typed._CODE.fullmatch(code))
            digest = sha256(code).hexdigest()
            require(digest not in seen and len(seen) < source_count)
            seen.add(digest)
            target, issue = read_target(db, rowid, target_type)
            issuer_id = str(issuer) if type(issuer) is int and issuer != 0 else None
            owner_id = owners.get(issuer_id, issuer_id) if issuer_id is not None else None
            if owner_id is not None and owner_id.startswith("-"):
                owner_id = None
            created_at = created if type(created) is int and 1 <= created <= MAX_SAFE_ID else None
            if owner_id is None:
                disposition = blocked("unclassified", "unmapped-issuer" if issuer_id else "invalid-issuer")
            elif created_at is None:
                disposition = blocked("unclassified", "invalid-created-at")
            elif issue is not None:
                disposition = blocked("unclassified", issue)
            else:
                require(target is not None)
                disposition = classify(target, issuer, origin, coalesced, targets, active, high)
            kinds[disposition["kind"]] += 1
            if disposition["state"] == "blocked":
                reasons[disposition["reason"]] += 1
            yield _json({"codeSha256": digest, "sourceIssuerId": issuer_id, "ownerId": owner_id,
                         "createdAt": created_at, "targetSha256": sha256(target).hexdigest() if target is not None else None,
                         **disposition}) + b"\n"

    file = typed._write_file(output / ROWS, lines(), MAX_METADATA_BYTES)
    require(len(seen) == source_count and sum(kinds.values()) == source_count)
    report = {"present": present, "rows": source_count, "activeHighWater": high, "rowOrder": "source-rowid",
              "kinds": dict(kinds), "blocked": sum(reasons.values()), "blockedReasons": dict(reasons)}
    return report, file


def seal_inventory(backup: Path, output: Path, *, source_sha256: str, owner_map: dict[str, str],
                   owner_map_sha256: str, old_origin: str, legacy_bot_id: str) -> None:
    destination = None
    sealed = False
    try:
        require(HASH.fullmatch(source_sha256) and HASH.fullmatch(owner_map_sha256)
                and OWNER.fullmatch(legacy_bot_id) and int(legacy_bot_id) <= MAX_OWNER)
        owners = _owner_map(owner_map)
        require(sha256(_json(dict(sorted(owners.items())))).hexdigest() == owner_map_sha256)
        origin = typed._origin(old_origin)
        source = _safe_path(backup, existing=True)
        target = _safe_path(output, existing=False)
        typed._private_parent(target)
        state = typed._source_state(source)

        def verify_source():
            require(not any(os.path.lexists(str(source) + suffix) for suffix in ("-wal", "-shm", "-journal")))
            typed._verify_source(source, source_sha256, state)

        verify_source()
        target.mkdir(mode=0o700)
        destination = target
        with closing(sqlite3.connect(source.as_uri() + "?mode=ro&immutable=1", uri=True, isolation_level=None)) as db:
            db.execute("PRAGMA trusted_schema=OFF")
            db.execute("PRAGMA query_only=ON")
            db.execute("PRAGMA cache_size=-2048")
            require(db.execute("PRAGMA trusted_schema").fetchone() == (0,)
                    and db.execute("PRAGMA query_only").fetchone() == (1,)
                    and db.execute("PRAGMA encoding").fetchone() == ("UTF-8",))
            db.execute("BEGIN")
            report, file = write_rows(db, target, origin, owners)
            db.execute("ROLLBACK")
        verify_source()
        manifest = _json({"version": 1, "kind": "legacy-short-namespace-inventory", "scope": "offline-dormant",
                          "sourceSha256": source_sha256, "ownerMapSha256": owner_map_sha256,
                          "oldOriginSha256": sha256(origin).hexdigest(), "legacyBotId": legacy_bot_id,
                          "externalRedirects": "not-validated", "inventory": report, "files": [file]}) + b"\n"
        descriptor = typed._write_file(target / MANIFEST, (manifest,), 64 * 1024)
        typed._write_file(target / SEAL, (descriptor["sha256"].encode("ascii") + b"\n",), 65)
        sealed = True
    except (BackupError, ConversionError, OSError, sqlite3.Error, typed.InventoryError, ValueError, TypeError, RecursionError):
        raise InventoryError(FAILURE) from None
    finally:
        if destination is not None and not sealed:
            for name in (SEAL, MANIFEST, ROWS):
                with suppress(OSError):
                    (destination / name).unlink()
            with suppress(OSError):
                destination.rmdir()


def main(args: list[str] | None = None) -> int:
    args = sys.argv[1:] if args is None else args
    if args in (["-h"], ["--help"]):
        print(USAGE)
        return 0
    if len(args) != 7:
        print(USAGE, file=sys.stderr)
        return 2
    try:
        backup, output, source_sha256, map_path, map_sha256, origin, bot_id = args
        path = _safe_path(Path(map_path), existing=True)
        typed._private_parent(path)
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and not info.st_mode & 0o077 and info.st_nlink == 1)
        owners = _bounded_json(path, typed.MAX_METADATA_BYTES)
        seal_inventory(Path(backup), Path(output), source_sha256=source_sha256, owner_map=owners,
                       owner_map_sha256=map_sha256, old_origin=origin, legacy_bot_id=bot_id)
    except KeyboardInterrupt:
        print("Legacy short namespace inventory was interrupted.", file=sys.stderr)
        return 130
    except Exception:
        print(FAILURE, file=sys.stderr)
        return 2
    print("Legacy short namespace inventory sealed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
