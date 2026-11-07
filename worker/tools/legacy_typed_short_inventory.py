"""Seal first-party single-subscription short links from a pinned backup."""

from __future__ import annotations

from contextlib import closing, suppress
from hashlib import sha256
import os
from pathlib import Path
import re
import sqlite3
import stat
import sys

from legacy_inventory import InventoryError as BackupError, _file_state
from legacy_snapshot_convert import (
    ConversionError,
    HASH,
    MAX_OWNER,
    MAX_SAFE_ID,
    OWNER,
    TOKEN,
    _bounded_json,
    _file_hash,
    _json,
    _new_file,
    _owner_map,
    _safe_path,
)


ROWS = "shorts.ndjson"
MANIFEST = "manifest.json"
SEAL = "manifest.sha256"
MAX_SHORTS = 20_000
MAX_SUBSCRIPTIONS = 20_000
MAX_SOURCE_BYTES = 2 * 1024**3
MAX_METADATA_BYTES = 8 * 1024**2
FORMATS = frozenset((
    "", "clash", "base64", "v2ray", "mixed", "singbox", "sing-box", "surge", "qx", "quantumult", "quantumultx",
))
_CODE = re.compile(rb"[A-Za-z0-9_-]{12}\Z")
_TARGET = re.compile(rb"/sub/([A-Za-z0-9_-]{16,128})(?:/([a-z0-9-]{1,11}))?\Z")
_HOST_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z", re.ASCII)
_COLLATION = re.compile(r"\bCOLLATE\b", re.IGNORECASE | re.ASCII)
_SHORT_COLUMNS = {
    "code": ("TEXT", 0, None, 1, 0),
    "user_id": ("INTEGER", 1, None, 0, 0),
    "target_url": ("TEXT", 1, None, 0, 0),
    "created_at": ("INTEGER", 1, None, 0, 0),
}
USAGE = (
    "Usage: legacy_typed_short_inventory.py BACKUP OUTPUT SOURCE_SHA256 "
    "OWNER_MAP_JSON OWNER_MAP_SHA256 OLD_HTTPS_ORIGIN LEGACY_BOT_ID"
)
FAILURE = "Legacy typed short inventory could not be confirmed safely."


class InventoryError(RuntimeError):
    """A fixed error for invalid backup or inventory evidence."""


def _require(condition: object) -> None:
    if not condition:
        raise InventoryError(FAILURE)


def _origin(value: str) -> bytes:
    _require(isinstance(value, str) and len(value) <= len("https://") + 253 and value.startswith("https://"))
    host = value[len("https://"):]
    labels = host.split(".")
    _require(len(labels) >= 2 and all(_HOST_LABEL.fullmatch(label) for label in labels)
             and "a" <= labels[-1][0] <= "z")
    return value.encode("ascii")


def _private_parent(path: Path) -> None:
    info = path.parent.lstat()
    _require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and not info.st_mode & 0o077)


def _source_state(path: Path) -> tuple[int, ...]:
    _private_parent(path)
    info = path.lstat()
    _require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and not info.st_mode & 0o077
             and info.st_nlink == 1 and 20 <= info.st_size <= MAX_SOURCE_BYTES)
    state = _file_state(path)
    _require(state == (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns))
    return (*state, info.st_mode)


def _verify_source(path: Path, expected: str, state: tuple[int, ...]) -> None:
    _require(_source_state(path) == state)
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as source:
        info = os.fstat(source.fileno())
        _require((info.st_dev, info.st_ino) == state[:2])
        header = source.read(20)
        _require(header.startswith(b"SQLite format 3\0") and header[18:20] == b"\x01\x01")
    _require(_file_hash(path) == (state[2], expected) and _source_state(path) == state)


def _binary_key(db: sqlite3.Connection, table: str, column: str, origin: str) -> bool:
    indexes = db.execute('SELECT name FROM pragma_index_list(?) WHERE origin=? AND "unique"=1 AND partial=0',
                         (table, origin))
    return any(db.execute('SELECT name, "desc", coll FROM pragma_index_xinfo(?) WHERE "key"=1', index)
               .fetchall() == [(column, 0, "BINARY")] for index in indexes)


def _tables(db: sqlite3.Connection) -> set[str]:
    definitions = db.execute("""
        SELECT name, type, wr, strict FROM pragma_table_list
        WHERE schema='main' AND lower(name) IN ('subscriptions','deleted_subs','short_links')
    """)
    tables = set()
    for name, kind, without_rowid, strict in definitions:
        _require(name in ("subscriptions", "deleted_subs", "short_links") and kind == "table"
                 and without_rowid == strict == 0)
        tables.add(name)
        definition = db.execute("""
            SELECT CASE WHEN length(CAST(sql AS BLOB))<=16384 THEN sql END
            FROM main.sqlite_schema WHERE type='table' AND name=?
        """, (name,)).fetchone()
        # The legacy lookup uses implicit BINARY equality. A BINARY index alone
        # cannot prove that when the column declares a different default.
        _require(definition is not None and isinstance(definition[0], str) and not _COLLATION.search(definition[0]))
        columns = {row[1]: row[2:] for row in db.execute(f"PRAGMA main.table_xinfo({name})")}
        if name == "short_links":
            _require(columns == _SHORT_COLUMNS and _binary_key(db, name, "code", "pk"))
        else:
            _require(columns.get("id") == ("INTEGER", 0, None, 1, 0)
                     and columns.get("user_id") == ("INTEGER", 1, None, 0, 0)
                     and columns.get("token") == ("TEXT", 1, None, 0, 0)
                     and not {column.lower() for column in columns}.intersection(("rowid", "_rowid_", "oid"))
                     and all(index[3] != "pk" for index in db.execute(f"PRAGMA main.index_list({name})")))
            if name == "subscriptions":
                _require(_binary_key(db, name, "token", "u"))
    _require("subscriptions" in tables)
    return tables


def _text_bytes(db: sqlite3.Connection, table: str, column: str, rowid: int, storage_type: str, limit: int) -> bytes:
    _require(storage_type == "text")
    with db.blobopen(table, column, rowid, readonly=True) as blob:
        _require(1 <= len(blob) <= limit)
        return blob.read()


def _targets(db: sqlite3.Connection, tables: set[str]) -> dict[bytes, tuple[str, int, int]]:
    targets = {}
    for table in ("subscriptions", "deleted_subs"):
        if table not in tables:
            continue
        for rowid, owner, token_type in db.execute(f"""
            SELECT id, CASE WHEN typeof(user_id)='integer' THEN user_id END, typeof(token)
            FROM main.{table} ORDER BY id LIMIT ?
        """, (MAX_SUBSCRIPTIONS - len(targets) + 1,)):
            _require(len(targets) < MAX_SUBSCRIPTIONS and 1 <= rowid <= MAX_SAFE_ID and type(owner) is int and owner != 0)
            token = _text_bytes(db, table, "token", rowid, token_type, 128)
            _require(TOKEN.fullmatch(token.decode("ascii")) is not None and token not in targets)
            targets[token] = (table, rowid, owner)
    return targets


def _shorts(db: sqlite3.Connection, targets: dict[bytes, tuple[str, int, int]], owners: dict[str, str],
            origin: bytes) -> dict[str, dict]:
    rows = {}
    for rowid, code_type, url_type, issuer, created in db.execute("""
        SELECT rowid, typeof(code), typeof(target_url),
            CASE WHEN typeof(user_id)='integer' THEN user_id END,
            CASE WHEN typeof(created_at)='integer' THEN created_at END
        FROM main.short_links ORDER BY rowid LIMIT ?
    """, (MAX_SHORTS + 1,)):
        _require(len(rows) < MAX_SHORTS and type(created) is int and 1 <= created <= MAX_SAFE_ID)
        code = _text_bytes(db, "short_links", "code", rowid, code_type, 12)
        _require(_CODE.fullmatch(code))
        digest = sha256(code).hexdigest()
        _require(digest not in rows)
        url = _text_bytes(db, "short_links", "target_url", rowid, url_type, len(origin) + len("/sub/") + 128 + 1 + 11)
        match = _TARGET.fullmatch(url[len(origin):]) if url.startswith(origin) else None
        _require(match is not None)
        token, alias = match.groups()
        format_name = alias.decode("ascii") if alias else ""
        _require(format_name in FORMATS and token in targets)
        table, legacy_id, owner = targets[token]
        # Test original ownership before a group-to-user map can collapse IDs.
        _require(issuer == owner and (owner > 0 or str(owner) in owners))
        rows[digest] = {
            "codeSha256": digest, "legacyTable": table, "legacyId": legacy_id,
            "ownerId": owners.get(str(owner), str(owner)), "tokenSha256": sha256(token).hexdigest(),
            "format": format_name, "createdAt": created,
        }
    return rows


def _capture(source: Path, origin: bytes, owners: dict[str, str]) -> tuple[bool, dict[str, dict]]:
    # Only a closed backup may be opened with immutable=1.
    with closing(sqlite3.connect(source.as_uri() + "?mode=ro&immutable=1", uri=True, isolation_level=None)) as db:
        db.execute("PRAGMA trusted_schema=OFF")
        db.execute("PRAGMA query_only=ON")
        db.execute("PRAGMA cache_size=-2048")
        _require(db.execute("PRAGMA trusted_schema").fetchone() == (0,)
                 and db.execute("PRAGMA query_only").fetchone() == (1,)
                 and db.execute("PRAGMA encoding").fetchone() == ("UTF-8",))
        db.execute("BEGIN")
        tables = _tables(db)
        present = "short_links" in tables
        rows = _shorts(db, _targets(db, tables), owners, origin) if present else {}
        db.execute("ROLLBACK")
    return present, rows


def _write_file(path: Path, chunks, limit: int) -> dict:
    size = 0
    digest = sha256()
    with _new_file(path) as file:
        for chunk in chunks:
            size += len(chunk)
            _require(size <= limit)
            digest.update(chunk)
            file.write(chunk)
        file.flush()
        os.fsync(file.fileno())
    return {"file": path.name, "bytes": size, "sha256": digest.hexdigest()}


def seal_inventory(backup: Path, output: Path, *, source_sha256: str, owner_map: dict[str, str],
                   owner_map_sha256: str, old_origin: str, legacy_bot_id: str) -> None:
    """Seal only exact old /sub destinations and digest-only capability evidence."""
    destination = None
    sealed = False
    try:
        _require(HASH.fullmatch(source_sha256) and HASH.fullmatch(owner_map_sha256)
                 and OWNER.fullmatch(legacy_bot_id) and int(legacy_bot_id) <= MAX_OWNER)
        owners = _owner_map(owner_map)
        _require(sha256(_json(dict(sorted(owners.items())))).hexdigest() == owner_map_sha256)
        origin = _origin(old_origin)
        source = _safe_path(backup, existing=True)
        target = _safe_path(output, existing=False)
        _private_parent(target)
        state = _source_state(source)
        _verify_source(source, source_sha256, state)
        present, rows = _capture(source, origin, owners)
        _verify_source(source, source_sha256, state)
        target.mkdir(mode=0o700)
        destination = target
        files = [_write_file(target / ROWS, (_json(rows[key]) + b"\n" for key in sorted(rows)), MAX_METADATA_BYTES)]
        manifest = _json({
            "version": 1, "kind": "legacy-typed-subscription-short-inventory",
            "sourceSha256": source_sha256, "ownerMapSha256": owner_map_sha256,
            "oldOriginSha256": sha256(origin).hexdigest(), "legacyBotId": legacy_bot_id,
            "inventory": {"present": present, "rows": len(rows)}, "files": files,
        }) + b"\n"
        descriptor = _write_file(target / MANIFEST, (manifest,), 64 * 1024)
        _write_file(target / SEAL, (descriptor["sha256"].encode("ascii") + b"\n",), 65)
        sealed = True
    except (BackupError, ConversionError, OSError, sqlite3.Error, ValueError, TypeError, RecursionError):
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
        owner_map = _bounded_json(path, MAX_METADATA_BYTES)
        seal_inventory(Path(backup), Path(output), source_sha256=source_sha256, owner_map=owner_map,
                       owner_map_sha256=map_sha256, old_origin=origin, legacy_bot_id=bot_id)
    except KeyboardInterrupt:
        print("Legacy typed short inventory was interrupted.", file=sys.stderr)
        return 130
    except Exception:
        print(FAILURE, file=sys.stderr)
        return 2
    print("Legacy typed short inventory sealed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
