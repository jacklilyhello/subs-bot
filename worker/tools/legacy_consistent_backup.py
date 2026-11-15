"""Seal a new private SQLite Online Backup API snapshot, including committed WAL.

The source is opened mode=ro without immutable, never reconfigured or stopped.
Only the new destination is normalized to DELETE journal mode, after closing the
backup connections. This is a backup primitive, not source-access authorization,
a final cutover snapshot, a data importer or a replay implementation.
"""
from __future__ import annotations

from contextlib import closing
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import sqlite3
import stat
import sys
import time


ERROR = "Legacy consistent SQLite backup could not be sealed safely."
SUCCESS = "Legacy consistent SQLite backup sealed."
DATABASE = "backup.sqlite"
MANIFEST = "manifest.json"
MARKER = "manifest.sha256"
READ_BYTES = 1024 * 1024


class BackupError(RuntimeError):
    """Fixed safe failure; never attach database contents, paths or SQL errors."""


def require(condition):
    if not condition:
        raise BackupError(ERROR)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def new_file(path, body):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(body)
        output.flush()
        os.fsync(output.fileno())


def file_digest(path):
    digest = sha256()
    size = 0
    with path.open("rb") as file:
        for block in iter(lambda: file.read(READ_BYTES), b""):
            size += len(block)
            digest.update(block)
    return size, digest.hexdigest()


def identity(path):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode))
    return info.st_dev, info.st_ino


def quote_identifier(value):
    return '"' + value.replace('"', '""') + '"'


def backup(source: Path, output: Path, *, timeout_seconds=120):
    require(type(timeout_seconds) is int and 1 <= timeout_seconds <= 900)
    source = Path(source)
    output = Path(output)
    require(source.is_absolute() and output.is_absolute() and ".." not in source.parts and ".." not in output.parts)
    marker = None
    try:
        source = source.parent.resolve(strict=True) / source.name
        source_identity = identity(source)
        with source.open("rb") as file:
            require(file.read(16) == b"SQLite format 3\0")
        parent = output.parent.resolve(strict=True)
        info = parent.stat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and info.st_mode & 0o077 == 0)
        output = parent / output.name
        require(output != source)
        output.mkdir(mode=0o700, exist_ok=False)
        sync_directory(parent)
        target = output / DATABASE
        new_file(target, b"")
        started = utc_now()
        deadline = time.monotonic() + timeout_seconds

        def progress(_status, _remaining, _total):
            require(time.monotonic() < deadline)

        # The read-only SQLite connection sees committed WAL frames. Do not add
        # immutable=1, copy the main file, or checkpoint/reconfigure the source.
        with closing(sqlite3.connect(source.as_uri() + "?mode=ro", uri=True, timeout=5)) as reader:
            reader.execute("PRAGMA trusted_schema=OFF")
            before_mode = reader.execute("PRAGMA journal_mode").fetchone()[0]
            before_version = reader.execute("PRAGMA data_version").fetchone()[0]
            with closing(sqlite3.connect(target.as_uri() + "?mode=rw", uri=True, timeout=5)) as writer:
                writer.execute("PRAGMA synchronous=FULL")
                reader.backup(writer, pages=128, progress=progress, sleep=0.05)
            after_mode = reader.execute("PRAGMA journal_mode").fetchone()[0]
            after_version = reader.execute("PRAGMA data_version").fetchone()[0]
        require(identity(source) == source_identity and before_mode == after_mode)

        # Both backup connections are closed before changing the destination's
        # journal mode. SQLite itself handles destination WAL/checkpoint state.
        with closing(sqlite3.connect(target.as_uri() + "?mode=rw", uri=True, timeout=5)) as check:
            check.execute("PRAGMA trusted_schema=OFF")
            check.execute("PRAGMA synchronous=FULL")
            require(check.execute("PRAGMA journal_mode=DELETE").fetchone() == ("delete",))
            check.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
            require(check.execute("PRAGMA integrity_check").fetchall() == [("ok",)])
            require(check.execute("PRAGMA foreign_key_check").fetchall() == [])
            schema = check.execute("SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name").fetchall()
            tables = []
            for name, in check.execute("SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name"):
                count = check.execute("SELECT count(*) FROM " + quote_identifier(name)).fetchone()[0]
                tables.append({"nameSha256": sha256(name.encode("utf-8")).hexdigest(), "rows": count})
            check.set_progress_handler(None, 0)
        require(not any(Path(str(target) + suffix).exists() for suffix in ("-wal", "-shm", "-journal")))
        require(target.stat().st_mode & 0o077 == 0)
        with target.open("rb") as file:
            os.fsync(file.fileno())
        size, digest = file_digest(target)
        require(size > 0 and time.monotonic() < deadline)
        manifest = {
            "version": 1, "kind": "legacy-sqlite-consistent-backup", "method": "sqlite-online-backup-api",
            "sqliteLibraryVersion": sqlite3.sqlite_version,
            "sourceReadOnly": True, "sourceImmutable": False,
            "sourceIdentitySha256": sha256(canonical(source_identity)).hexdigest(),
            "sourcePathSha256": sha256(str(source).encode("utf-8")).hexdigest(),
            "sourceJournalModeBefore": before_mode, "sourceJournalModeAfter": after_mode,
            "sourceWritesObserved": before_version != after_version,
            "startedAt": started, "finishedAt": utc_now(), "databaseFile": DATABASE,
            "sqliteSha256": digest, "sqliteBytes": size, "journalMode": "delete",
            "integrityCheck": "ok", "foreignKeyCheck": "ok", "schemaSha256": sha256(canonical(schema)).hexdigest(),
            "tableCounts": tables, "tableCountsSha256": sha256(canonical(tables)).hexdigest(),
            "finalCutoverSnapshot": False, "sourceServiceStopPerformed": False,
        }
        # Keep raw table names, schema, records, source paths and credentials out
        # of the manifest. The database itself is private and never a CI artifact.
        raw = canonical(manifest) + b"\n"
        new_file(output / MANIFEST, raw)
        sync_directory(output)
        marker = output / MARKER
        new_file(marker, (sha256(raw).hexdigest() + "\n").encode("ascii"))
        sync_directory(output)
        return manifest
    except (OSError, sqlite3.Error, BackupError, ValueError, UnicodeError):
        # Retain partial backup bytes for diagnosis, but never a valid seal after
        # an incomplete operation. Output was created exclusively by this call.
        if marker is not None:
            try:
                marker.unlink(missing_ok=True)
            except OSError:
                pass
        raise BackupError(ERROR) from None


def main(args=None):
    args = sys.argv[1:] if args is None else args
    if len(args) not in (2, 4) or (len(args) == 4 and args[2] != "--timeout-seconds"):
        print("Usage: legacy_consistent_backup.py ABSOLUTE_SOURCE_DB NEW_PRIVATE_OUTPUT_DIRECTORY [--timeout-seconds 120]", file=sys.stderr)
        return 2
    try:
        timeout = int(args[3]) if len(args) == 4 else 120
        backup(Path(args[0]), Path(args[1]), timeout_seconds=timeout)
    except (BackupError, ValueError):
        print(ERROR, file=sys.stderr)
        return 1
    print(SUCCESS)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
