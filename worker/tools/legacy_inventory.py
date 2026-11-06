"""Measure a sealed legacy SQLite backup without exporting its contents."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import closing
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import sys


# Direct invocation starts with worker/tools on sys.path. The legacy converter
# uses only the standard library and does not import the bot or its settings.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
_write_bytecode = sys.dont_write_bytecode
sys.dont_write_bytecode = True
try:
    from export_errors import ExportError
    from share_export import to_share_links
finally:
    sys.dont_write_bytecode = _write_bytecode
    sys.path.pop(0)


READ_BYTES = 64 * 1024
RAW_RECORD_BYTES = 4 * 1024 * 1024
MAX_DEPTH = 128
CHUNK_BYTES = 512 * 1024
SNAPSHOT_BYTES = 64 * 1024 * 1024
SHARE_BYTES = 16 * 1024 * 1024
MAX_CHUNKS = 256
MAX_NODES = 100_000
MAX_SAFE_ID = 2**53 - 1

_NON_SPACE = re.compile(rb"[^ \t\r\n]")
_STRUCTURAL = re.compile(rb'[{}\[\]"]')
_STRING = re.compile(rb'["\\]')


class InventoryError(RuntimeError):
    """A source or execution failure whose message is safe to display."""


class _RowProblem(Exception):
    """A fixed report counter for an unmeasurable row."""


def _invalid_json() -> _RowProblem:
    return _RowProblem("invalidJsonRows")


def _reject_constant(_value: str):
    raise _invalid_json()


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    node = {}
    for key, value in pairs:
        if key in node:
            raise _invalid_json()
        node[key] = value
    return node


class _ArrayReader:
    """Frame one bounded object at a time, then let json validate its grammar."""

    def __init__(self, blob: sqlite3.Blob):
        self.blob = blob
        self.buffer = b""
        self.offset = 0

    def _ready(self) -> bool:
        if self.offset == len(self.buffer):
            self.buffer = self.blob.read(READ_BYTES)
            self.offset = 0
        return bool(self.buffer)

    def _punctuation(self) -> int | None:
        while self._ready():
            match = _NON_SPACE.search(self.buffer, self.offset)
            if match is not None:
                self.offset = match.end()
                return self.buffer[match.start()]
            self.offset = len(self.buffer)
        return None

    def _record(self) -> bytearray:
        result = bytearray(b"{")
        expected = [ord("}")]
        in_string = False
        escaped = False
        while self._ready():
            start = self.offset
            end = start + int(escaped)
            escaped = False
            while end < len(self.buffer):
                pattern = _STRING if in_string else _STRUCTURAL
                match = pattern.search(self.buffer, end)
                if match is None:
                    end = len(self.buffer)
                    break
                token = self.buffer[match.start()]
                end = match.end()
                if token == ord('"'):
                    in_string = not in_string
                elif in_string:
                    # The only other string match is a backslash.
                    if end == len(self.buffer):
                        escaped = True
                    else:
                        end += 1
                elif token == ord("{") or token == ord("["):
                    expected.append(ord("}") if token == ord("{") else ord("]"))
                    if len(expected) > MAX_DEPTH:
                        raise _RowProblem("recordDepthLimitRows")
                elif token != expected.pop():
                    raise _invalid_json()
                elif not expected:
                    break
            if len(result) + end - start > RAW_RECORD_BYTES:
                raise _RowProblem("recordReadLimitRows")
            result.extend(self.buffer[start:end])
            self.offset = end
            if not expected:
                return result
        raise _invalid_json()

    def __iter__(self) -> Iterator[dict]:
        if self._punctuation() != ord("["):
            raise _invalid_json()
        token = self._punctuation()
        if token != ord("]"):
            while True:
                if token != ord("{"):
                    raise _invalid_json()
                try:
                    yield json.loads(self._record().decode("utf-8"), parse_constant=_reject_constant,
                                     object_pairs_hook=_unique_object)
                except UnicodeError:
                    raise _RowProblem("invalidTextRows") from None
                except (ValueError, RecursionError):
                    raise _invalid_json() from None
                delimiter = self._punctuation()
                if delimiter == ord("]"):
                    break
                if delimiter != ord(","):
                    raise _invalid_json()
                token = self._punctuation()
        if self._punctuation() is not None:
            raise _invalid_json()


@dataclass
class _RowSize:
    nodes: int = 0
    ndjson: int = 0
    max_line: int = 0
    chunks: int | None = 0
    shares: int | None = 0
    max_share_line: int = 0


def _measure(blob: sqlite3.Blob) -> _RowSize:
    size = _RowSize()
    chunk_bytes = 0
    for node in _ArrayReader(blob):
        # Future import representation: original key order, no separator
        # spaces, UTF-8 rather than ASCII escapes, and one LF per object.
        try:
            line = len(json.dumps(node, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")) + 1
        except UnicodeError:
            raise _RowProblem("invalidTextRows") from None
        except (ValueError, RecursionError):
            raise _invalid_json() from None
        size.nodes += 1
        size.ndjson += line
        size.max_line = max(size.max_line, line)
        if line > CHUNK_BYTES:
            size.chunks = None
        if size.chunks is not None:
            if chunk_bytes == 0 or chunk_bytes + line > CHUNK_BYTES:
                size.chunks += 1
                chunk_bytes = 0
            chunk_bytes += line
        if size.shares is not None:
            try:
                share = to_share_links([node])[0]
                share_length = len(share.encode("utf-8"))
                size.shares += share_length + (size.nodes > 1)
                size.max_share_line = max(size.max_share_line, share_length)
            except (ExportError, UnicodeError, RecursionError):
                size.shares = None
    return size


def _table_inventory(db: sqlite3.Connection, table: str, required: bool) -> dict:
    definition = db.execute(
        "SELECT type, wr FROM pragma_table_list WHERE schema = 'main' AND name = ?", (table,)
    ).fetchone()
    if definition is None and not required:
        return {"present": False}
    if definition != ("table", 0):
        raise InventoryError("Legacy backup schema is unsupported.")
    columns = {row[1].lower(): row[6] for row in db.execute(f"PRAGMA main.table_xinfo({table})")}
    if (any(columns.get(name) != 0 for name in ("id", "user_id", "nodes_json"))
            or "rowid" in columns or columns.get("node_count", 0) != 0):
        raise InventoryError("Legacy backup schema is unsupported.")
    has_metadata_count = "node_count" in columns
    stored_count = "CASE WHEN typeof(node_count) = 'integer' THEN node_count END" if has_metadata_count else "NULL"
    result = dict.fromkeys((
        "rows", "negativeOwnerRows", "invalidOwnerRows", "unsafeIdRows",
        "rawBytes", "maxRawBytes", "nonTextRows", "invalidTextRows", "invalidJsonRows",
        "recordReadLimitRows", "recordDepthLimitRows", "measuredRows", "emptyRows",
        "storedNodeCountMismatchRows", "nodeCount", "maxNodeCount", "ndjsonBytes",
        "maxNdjsonBytes", "maxNodeLineBytes", "chunkMeasurableRows", "chunkCount", "maxChunkCount",
        "lineOverLimitRows", "snapshotBytesOverLimitRows", "nodeCountOverLimitRows", "chunkCountOverLimitRows",
        "storageFitRows", "shareMeasuredRows", "shareUnsupportedRows",
        "shareBytes", "maxShareBytes", "maxShareLineBytes", "shareBytesOverLimitRows",
    ), 0)
    rows = db.execute(f"""
        SELECT rowid, typeof(nodes_json),
            typeof(user_id) = 'integer' AND user_id < 0,
            typeof(user_id) <> 'integer' OR user_id <= 0,
            typeof(id) <> 'integer' OR id IS NOT rowid OR id NOT BETWEEN 1 AND ?,
            {stored_count}
        FROM {table} ORDER BY rowid
    """, (MAX_SAFE_ID,))
    for rowid, value_type, negative_owner, invalid_owner, unsafe_id, node_count in rows:
        result["rows"] += 1
        result["negativeOwnerRows"] += negative_owner
        result["invalidOwnerRows"] += invalid_owner
        result["unsafeIdRows"] += unsafe_id
        if value_type != "text":
            result["nonTextRows"] += 1
        if value_type not in {"text", "blob"}:
            continue
        with db.blobopen(table, "nodes_json", rowid, readonly=True) as blob:
            raw_bytes = len(blob)
            result["rawBytes"] += raw_bytes
            result["maxRawBytes"] = max(result["maxRawBytes"], raw_bytes)
            if value_type != "text":
                continue
            try:
                size = _measure(blob)
            except _RowProblem as problem:
                result[problem.args[0]] += 1
                continue
        result["measuredRows"] += 1
        result["emptyRows"] += size.nodes == 0
        result["storedNodeCountMismatchRows"] += has_metadata_count and node_count != size.nodes
        result["nodeCount"] += size.nodes
        result["maxNodeCount"] = max(result["maxNodeCount"], size.nodes)
        result["ndjsonBytes"] += size.ndjson
        result["maxNdjsonBytes"] = max(result["maxNdjsonBytes"], size.ndjson)
        result["maxNodeLineBytes"] = max(result["maxNodeLineBytes"], size.max_line)
        result["lineOverLimitRows"] += size.chunks is None
        result["snapshotBytesOverLimitRows"] += size.ndjson > SNAPSHOT_BYTES
        result["nodeCountOverLimitRows"] += size.nodes > MAX_NODES
        if size.chunks is not None:
            result["chunkMeasurableRows"] += 1
            result["chunkCount"] += size.chunks
            result["maxChunkCount"] = max(result["maxChunkCount"], size.chunks)
            result["chunkCountOverLimitRows"] += size.chunks > MAX_CHUNKS
            if 0 < size.nodes <= MAX_NODES and size.ndjson <= SNAPSHOT_BYTES and size.chunks <= MAX_CHUNKS:
                result["storageFitRows"] += 1
        if size.nodes and size.shares is None:
            result["shareUnsupportedRows"] += 1
        elif size.nodes:
            result["shareMeasuredRows"] += 1
            result["shareBytes"] += size.shares
            result["maxShareBytes"] = max(result["maxShareBytes"], size.shares)
            result["maxShareLineBytes"] = max(result["maxShareLineBytes"], size.max_share_line)
            result["shareBytesOverLimitRows"] += size.shares > SHARE_BYTES
    return {"present": True, "hasStoredNodeCount": has_metadata_count, **result}


def _file_state(path: Path) -> tuple[int, int, int, int, int]:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise InventoryError("Legacy backup must be a regular file.")
    for suffix in ("-wal", "-shm", "-journal"):
        try:
            Path(str(path) + suffix).lstat()
        except FileNotFoundError:
            continue
        raise InventoryError("Legacy backup must be closed and have no SQLite sidecar files.")
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def inventory(path: Path) -> dict:
    """Read one aggregate snapshot from a completed, closed UTF-8 backup."""
    try:
        source = Path(path).absolute()
        before = _file_state(source)
        with source.open("rb") as file:
            opened = os.fstat(file.fileno())
            if (opened.st_dev, opened.st_ino) != before[:2]:
                raise InventoryError("Legacy backup changed during the inventory.")
            header = file.read(20)
        if len(header) != 20 or not header.startswith(b"SQLite format 3\0"):
            raise InventoryError("Legacy backup is not a supported SQLite file.")
        if header[18:20] != b"\x01\x01":
            raise InventoryError("Legacy backup must be prepared in SQLite DELETE journal mode.")

        # immutable avoids sidecar creation and is only safe for a completed
        # backup with no concurrent writers. It must never be used on live data.
        with closing(sqlite3.connect(source.as_uri() + "?mode=ro&immutable=1", uri=True, isolation_level=None)) as db:
            db.execute("PRAGMA trusted_schema = OFF")
            db.execute("PRAGMA query_only = ON")
            db.execute("PRAGMA temp_store = MEMORY")
            db.execute("PRAGMA cache_size = -2048")
            if (db.execute("PRAGMA trusted_schema").fetchone() != (0,)
                    or db.execute("PRAGMA query_only").fetchone() != (1,)):
                raise InventoryError("SQLite read-only safeguards could not be confirmed.")
            db.execute("BEGIN")
            if db.execute("PRAGMA encoding").fetchone() != ("UTF-8",):
                raise InventoryError("Legacy backup must use UTF-8 SQLite text encoding.")
            active = _table_inventory(db, "subscriptions", required=True)
            trash = _table_inventory(db, "deleted_subs", required=False)
            db.execute("ROLLBACK")
        if _file_state(source) != before:
            raise InventoryError("Legacy backup changed during the inventory.")
    except (OSError, sqlite3.Error, ValueError):
        raise InventoryError("Legacy backup could not be read safely.") from None
    return {
        "version": 1,
        "limits": {
            "rawRecordBytes": RAW_RECORD_BYTES, "recordDepth": MAX_DEPTH, "chunkBytes": CHUNK_BYTES,
            "snapshotBytes": SNAPSHOT_BYTES, "shareBytes": SHARE_BYTES, "chunks": MAX_CHUNKS, "nodes": MAX_NODES,
        },
        "active": active,
        "trash": trash,
    }


def main(args: list[str] | None = None) -> int:
    if args is None:
        args = sys.argv[1:]
    usage = "Usage: legacy_inventory.py BACKUP"
    if args in (["-h"], ["--help"]):
        print(usage)
        return 0
    if len(args) != 1:
        print(usage, file=sys.stderr)
        return 2
    try:
        report = inventory(Path(args[0]))
    except InventoryError as error:
        print(str(error), file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("Legacy inventory was interrupted.", file=sys.stderr)
        return 130
    except Exception:
        print("Legacy inventory could not finish safely.", file=sys.stderr)
        return 2
    print(json.dumps(report, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
