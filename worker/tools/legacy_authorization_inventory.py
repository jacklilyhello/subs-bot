"""Seal only the effective authorization overrides from a closed legacy backup."""

from __future__ import annotations

from contextlib import closing, suppress
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import sys


MAX_ROWS = 20_000
MAX_SOURCE_BYTES = 2 * 1024**3
MAX_USER_ID = 2**63 - 1
MAX_TIMESTAMP = 2**53 - 1
SIDECAR = "auth-overrides.ndjson"
MANIFEST = "manifest.json"
SEAL = "manifest.sha256"
USAGE = "Usage: legacy_authorization_inventory.py BACKUP OUTPUT EXPECTED_SOURCE_SHA256"
SUCCESS = "Legacy authorization inventory sealed."
FAILURE = "Legacy authorization inventory could not be confirmed safely."
_SHA256 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_COLUMNS = (
    (0, "user_id", "INTEGER", 0, None, 1, 0),
    (1, "allowed", "INTEGER", 1, None, 0, 0),
    (2, "created_at", "INTEGER", 1, None, 0, 0),
    (3, "updated_at", "INTEGER", 1, None, 0, 0),
)


class InventoryError(RuntimeError):
    """The backup or inventory package could not be verified."""


def _require(condition: bool) -> None:
    if not condition:
        raise InventoryError(FAILURE)


def _directory_identity(path: Path) -> tuple[int, int, int, int]:
    info = path.lstat()
    mode = stat.S_IMODE(info.st_mode)
    # A sticky shared ancestor is safe when each following entry is owned by
    # the current account or root. Other shared writable ancestors can rename it.
    _require(stat.S_ISDIR(info.st_mode) and info.st_uid in (0, os.geteuid())
             and (not mode & 0o022 or bool(mode & stat.S_ISVTX)))
    return info.st_dev, info.st_ino, info.st_uid, mode


def _private_parent(path: Path) -> tuple[Path, tuple[tuple[int, int, int, int], ...]]:
    _require(path.name not in {"", ".", ".."} and ".." not in path.parts)
    path = path.absolute()
    parent = path.parent
    chain = tuple(_directory_identity(item) for item in reversed((parent, *parent.parents)))
    _require(chain[-1][2] == os.geteuid() and not chain[-1][3] & 0o077)
    return path, chain


def _file_identity(info: os.stat_result) -> tuple[int, ...]:
    _require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
             and not info.st_mode & 0o077 and info.st_nlink == 1 and 20 <= info.st_size <= MAX_SOURCE_BYTES)
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_mode


def _source_state(path: Path) -> tuple[int, ...]:
    info = path.lstat()
    for suffix in ("-wal", "-shm", "-journal"):
        try:
            path.with_name(path.name + suffix).lstat()
        except FileNotFoundError:
            continue
        raise InventoryError(FAILURE)
    return _file_identity(info)


def _fingerprint(path: Path, identity: tuple[int, ...]) -> str:
    _require(_source_state(path) == identity)
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    with os.fdopen(os.open(path, flags), "rb") as source:
        _require(_file_identity(os.fstat(source.fileno())) == identity)
        header = source.read(20)
        _require(header.startswith(b"SQLite format 3\x00") and header[18:20] == b"\x01\x01")
        digest = sha256(header)
        remaining = identity[2] - len(header)
        while remaining:
            block = source.read(min(64 * 1024, remaining))
            _require(bool(block))
            digest.update(block)
            remaining -= len(block)
        _require(source.read(1) == b"" and _file_identity(os.fstat(source.fileno())) == identity)
    _require(_source_state(path) == identity)
    return digest.hexdigest()


def _canonical_line(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii") + b"\n"


def _authorization_rows(db: sqlite3.Connection) -> tuple[bool, bytearray, int, int]:
    table = db.execute("""
        SELECT name, type, ncol, wr, strict FROM pragma_table_list
        WHERE schema = 'main' AND name = 'auth_overrides' COLLATE NOCASE
    """).fetchone()
    rows = bytearray()
    if table is None:
        return False, rows, 0, 0
    _require(table == ("auth_overrides", "table", 4, 0, 0)
             and tuple(db.execute("PRAGMA main.table_xinfo(auth_overrides)")) == _COLUMNS)

    # Project only SQLite INTEGERs. Malformed text/BLOB values fail validation
    # without loading an arbitrarily large cell into the inventory process.
    records = db.execute("""
        SELECT CASE WHEN typeof(user_id) = 'integer' THEN user_id END,
            CASE WHEN typeof(allowed) = 'integer' THEN allowed END,
            CASE WHEN typeof(created_at) = 'integer' THEN created_at END,
            CASE WHEN typeof(updated_at) = 'integer' THEN updated_at END
        FROM main.auth_overrides ORDER BY user_id LIMIT ?
    """, (MAX_ROWS + 1,))
    previous_id = 0
    count = allowed_count = 0
    for user_id, allowed, created_at, updated_at in records:
        _require(count < MAX_ROWS and type(user_id) is int and previous_id < user_id <= MAX_USER_ID
                 and type(allowed) is int and allowed in (0, 1)
                 and type(created_at) is int and type(updated_at) is int
                 and 1 <= created_at <= updated_at <= MAX_TIMESTAMP)
        rows.extend(_canonical_line({
            "userId": str(user_id), "allowed": allowed, "createdAt": created_at, "updatedAt": updated_at,
        }))
        previous_id = user_id
        count += 1
        allowed_count += allowed
    return True, rows, count, allowed_count


def _read_authorization(path: Path) -> tuple[bool, bytearray, int, int]:
    # immutable is valid only for a completed backup with no concurrent writer.
    with closing(sqlite3.connect(path.as_uri() + "?mode=ro&immutable=1", uri=True, isolation_level=None)) as db:
        db.execute("PRAGMA trusted_schema = OFF")
        db.execute("PRAGMA query_only = ON")
        db.execute("PRAGMA temp_store = MEMORY")
        db.execute("PRAGMA cache_size = -2048")
        _require(db.execute("PRAGMA trusted_schema").fetchone() == (0,)
                 and db.execute("PRAGMA query_only").fetchone() == (1,))
        db.execute("BEGIN")
        _require(db.execute("PRAGMA encoding").fetchone() == ("UTF-8",))
        result = _authorization_rows(db)
        db.execute("ROLLBACK")
        return result


def _write_private(path: Path, data: bytes | bytearray) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    with os.fdopen(os.open(path, flags, 0o600), "wb") as file:
        file.write(data)
        file.flush()
        os.fsync(file.fileno())


def _verified_source_rows(backup: Path, expected_source_sha256: str) -> tuple[bool, bytearray, int, int]:
    _require(_SHA256.fullmatch(expected_source_sha256) is not None)
    source, source_parent = _private_parent(backup)
    identity = _source_state(source)
    _require(_fingerprint(source, identity) == expected_source_sha256 and _private_parent(source)[1] == source_parent)
    result = _read_authorization(source)
    _require(_fingerprint(source, identity) == expected_source_sha256 and _private_parent(source)[1] == source_parent)
    return result


def _inventory_manifest(source_sha256: str, present: bool, rows: bytearray, count: int, allowed: int) -> bytes:
    return _canonical_line({
        "version": 1, "kind": "legacy-authorization-inventory", "sourceSha256": source_sha256,
        "authOverrides": {
            "present": present, "rows": count, "allowedRows": allowed, "deniedRows": count - allowed,
            "file": SIDECAR, "bytes": len(rows), "sha256": sha256(rows).hexdigest(),
        },
    })


def _seal_package(destination: Path, output_parent: tuple, manifest: bytes, sidecars: dict[str, bytes | bytearray]) -> None:
    _require(all(Path(name).name == name and name not in {"", ".", "..", MANIFEST, SEAL} for name in sidecars))
    names = {*sidecars, MANIFEST}
    _require(_private_parent(destination)[1] == output_parent)
    destination.mkdir(mode=0o700)
    output_identity = _directory_identity(destination)
    _require(output_identity[2] == os.geteuid() and not output_identity[3] & 0o077)

    def same_output() -> bool:
        return _private_parent(destination)[1] == output_parent and _directory_identity(destination) == output_identity

    try:
        for name, raw in sidecars.items():
            _write_private(destination / name, raw)
        _write_private(destination / MANIFEST, manifest)
        _require(same_output() and {path.name for path in destination.iterdir()} == names)
        _write_private(destination / SEAL, sha256(manifest).hexdigest().encode("ascii") + b"\n")
        _require(same_output() and {path.name for path in destination.iterdir()} == names | {SEAL})
    except BaseException:
        # Leave a moved directory alone. Its replacement may contain unrelated files.
        with suppress(OSError, InventoryError):
            if same_output():
                for name in (SEAL, MANIFEST, *sidecars):
                    with suppress(OSError):
                        (destination / name).unlink()
                destination.rmdir()
        raise


def seal_inventory(backup: Path, output: Path, expected_source_sha256: str) -> None:
    """Write a deterministic private package from an independently pinned source."""
    destination, output_parent = _private_parent(output)
    present, rows, count, allowed = _verified_source_rows(backup, expected_source_sha256)
    manifest = _inventory_manifest(expected_source_sha256, present, rows, count, allowed)
    _seal_package(destination, output_parent, manifest, {SIDECAR: rows})


def main(args: list[str] | None = None) -> int:
    args = sys.argv[1:] if args is None else args
    if args in (["-h"], ["--help"]):
        print(USAGE)
        return 0
    if len(args) != 3:
        print(USAGE, file=sys.stderr)
        return 2
    try:
        seal_inventory(Path(args[0]), Path(args[1]), args[2])
    except KeyboardInterrupt:
        print("Legacy authorization inventory was interrupted.", file=sys.stderr)
        return 130
    except Exception:
        print(FAILURE, file=sys.stderr)
        return 2
    print(SUCCESS)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
