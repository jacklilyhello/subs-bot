"""Convert a sealed legacy backup to private, unapplied subscription snapshots.

This is not a database importer or a complete legacy migration. Other nonempty
legacy domains block the package. It never imports db/config or contacts a
service. Node JSON preserves its original key order and array order; only JSON
separator whitespace and Unicode escapes are normalized, as in legacy_inventory.
"""

from __future__ import annotations

from contextlib import closing
from hashlib import sha256
import io
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import stat
import sys
from uuid import NAMESPACE_URL, uuid5

import legacy_inventory as inventory


CHUNK_BYTES = 512 * 1024
SNAPSHOT_BYTES = 64 * 1024 * 1024
MAX_NODES = 100_000
MAX_CHUNKS = 256
MAX_SAFE_ID = 2**53 - 1
MAX_OWNER = 2**63 - 1
MAX_METADATA_BYTES = 32 * 1024
MAX_INDEX_LINE_BYTES = 1024
DOMAINS = {
    "subscriptions": ("id", "user_id", "name", "url", "token", "expire_at", "traffic_used", "traffic_total",
                      "nodes_json", "node_count", "last_error", "created_at", "updated_at"),
    "deleted_subs": ("id", "user_id", "name", "url", "token", "expire_at", "traffic_used", "traffic_total",
                     "nodes_json", "node_count", "last_error", "created_at", "deleted_at"),
    "path_maps": ("id", "user_id", "node_name", "remark"),
    "temp_nodes": ("id", "user_id", "url", "name", "created_at"),
    "short_links": ("code", "user_id", "target_url", "created_at"),
    "meta": ("key", "value"),
    "shares": ("code", "sender_id", "sender_name", "content", "max_views", "claimed_count", "target_user_id",
               "inline_message_id", "expire_at", "created_at"),
    "share_claims": ("id", "share_code", "user_id", "claimed_at"),
    "auth_overrides": ("user_id", "allowed", "created_at", "updated_at"),
}
HANDLED = ("subscriptions", "deleted_subs")
OPTIONAL_COLUMNS = {"subscriptions": {"node_count"}, "deleted_subs": {"node_count"}, "shares": {"inline_message_id"}}
TOKEN = re.compile(r"[A-Za-z0-9_-]{16,128}\Z", re.ASCII)
OWNER = re.compile(r"[1-9][0-9]{0,18}\Z", re.ASCII)
SIGNED_OWNER = re.compile(r"-?[1-9][0-9]{0,18}\Z", re.ASCII)
HASH = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
OBJECT_PATH = re.compile(r"objects/subscriptions/([1-9][0-9]*)/([0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})/(manifest\.json|[0-9]+\.ndjson)\Z")
PROBLEMS = ("invalidMetadataRows", "unmappedOwnerRows", "tokenCollisionRows", "invalidNodeRows",
            "nodeReadLimitRows", "lineOverLimitRows", "snapshotOverLimitRows", "nodeCountOverLimitRows", "chunkCountOverLimitRows")


class ConversionError(RuntimeError):
    """Only fixed text may cross the converter's error boundary."""


class _InvalidRow(Exception):
    pass


def _require(value: object) -> None:
    if not value:
        raise ConversionError("Legacy snapshot conversion could not be confirmed safely.")


def _json(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _safe_path(value: Path, *, existing: bool, directory: bool = False) -> Path:
    path = Path(value)
    _require(".." not in path.parts)
    path = path.absolute()
    parts = path.parts
    current = Path(parts[0])
    for index, part in enumerate(parts[1:], 1):
        current /= part
        if index == len(parts) - 1 and not existing:
            try:
                current.lstat()
            except FileNotFoundError:
                continue
            raise ConversionError("Conversion output already exists.")
        info = current.lstat()
        _require(not stat.S_ISLNK(info.st_mode))
        _require(stat.S_ISREG(info.st_mode) if index == len(parts) - 1 and existing and not directory else stat.S_ISDIR(info.st_mode))
    return path


def _new_file(path: Path):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    return os.fdopen(descriptor, "wb")


def _bounded_json(path: Path, maximum: int) -> object:
    raw = _bounded_bytes(path, maximum)
    return json.loads(raw.decode("utf-8"), object_pairs_hook=inventory._unique_object,
                      parse_constant=inventory._reject_constant)


def _bounded_bytes(path: Path, maximum: int) -> bytes:
    info = path.lstat()
    _require(stat.S_ISREG(info.st_mode) and info.st_size <= maximum)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as file:
        opened = os.fstat(file.fileno())
        _require((opened.st_dev, opened.st_ino) == (info.st_dev, info.st_ino))
        raw = file.read(maximum + 1)
    _require(len(raw) <= maximum)
    return raw


def _file_hash(path: Path) -> tuple[int, str]:
    info = path.lstat()
    _require(stat.S_ISREG(info.st_mode))
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    size = 0
    digest = sha256()
    with os.fdopen(descriptor, "rb") as file:
        opened = os.fstat(file.fileno())
        _require((opened.st_dev, opened.st_ino) == (info.st_dev, info.st_ino))
        while block := file.read(64 * 1024):
            digest.update(block)
            size += len(block)
        after = os.fstat(file.fileno())
    _require((info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
             == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns))
    return size, digest.hexdigest()


def _owner_map(value: object) -> dict[str, str]:
    _require(isinstance(value, dict) and len(value) <= 100_000)
    result = {}
    for source, target in value.items():
        _require(isinstance(source, str) and SIGNED_OWNER.fullmatch(source) and -MAX_OWNER - 1 <= int(source) <= MAX_OWNER
                 and isinstance(target, str) and OWNER.fullmatch(target) and int(target) <= MAX_OWNER
                 and (source.startswith("-") or source == target))
        result[source] = target
    return result


def _schema(db: sqlite3.Connection) -> tuple[dict, dict[str, set[str]]]:
    known = {}
    for name, kind, sql in db.execute("SELECT name, type, sql FROM sqlite_schema WHERE substr(name,1,7) <> 'sqlite_'"):
        _require(name in DOMAINS and kind == "table" and isinstance(sql, str))
        _require(tuple(db.execute("SELECT wr FROM pragma_table_list WHERE schema='main' AND name=?", (name,)).fetchone()) == (0,))
        columns = list(db.execute(f"PRAGMA main.table_xinfo({name})"))
        names = {row[1] for row in columns}
        optional = OPTIONAL_COLUMNS.get(name, set())
        _require(set(DOMAINS[name]) - optional <= names <= set(DOMAINS[name]) and all(row[6] == 0 for row in columns)
                 and not {"rowid", "_rowid_", "oid"}.intersection(names))
        if name in HANDLED:
            _require(any(row[1] == "id" and row[2].upper() == "INTEGER" and row[5] == 1 for row in columns))
        known[name] = names
    _require("subscriptions" in known)
    domains = {name: {"present": name in known, "rows": db.execute(f"SELECT count(*) FROM {name}").fetchone()[0]
                     if name in known else 0} for name in DOMAINS}
    return domains, known


def _sequence_high_water(db: sqlite3.Connection, known: dict[str, set[str]]) -> int:
    high = 0
    has_sequence = db.execute("SELECT 1 FROM sqlite_schema WHERE type='table' AND name='sqlite_sequence'").fetchone() is not None
    for table in HANDLED:
        if table not in known:
            continue
        value = db.execute(f"SELECT max(id) FROM {table}").fetchone()[0]
        _require(value is None or type(value) is int and 1 <= value <= MAX_SAFE_ID)
        high = max(high, value or 0)
        if has_sequence:
            rows = list(db.execute("SELECT seq FROM sqlite_sequence WHERE name=?", (table,)))
            _require(len(rows) <= 1)
            if rows:
                value = rows[0][0]
                _require(type(value) is int and 0 <= value <= MAX_SAFE_ID)
                high = max(high, value)
    return high


def _rows(db: sqlite3.Connection, table: str, columns: set[str]):
    # SQL guards bound each returned text cell before Python materializes it.
    # Raw errors can contain provider credentials; inspect only their type/size.
    values = []
    for name, maximum in (("name", 2048), ("url", 16384), ("token", 128)):
        values.append(f"CASE WHEN typeof({name})='text' AND length(CAST({name} AS BLOB)) <= {maximum} THEN {name} END AS {name}")
    time_column = "updated_at" if table == "subscriptions" else "deleted_at"
    stored_count = "CASE WHEN typeof(node_count)='integer' THEN node_count END AS node_count" if "node_count" in columns else "NULL AS node_count"
    stored_type = "typeof(node_count)" if "node_count" in columns else "'absent'"
    bounded_numbers = [f"CASE WHEN typeof({name})='integer' THEN {name} END AS {name}"
                       for name in ("user_id", "expire_at", "created_at", time_column)]
    bounded_numbers.extend(f"CASE WHEN typeof({name}) IN ('integer','real') THEN {name} END AS {name}"
                           for name in ("traffic_used", "traffic_total"))
    query = f"""SELECT rowid AS source_rowid, id, {','.join(bounded_numbers)}, {','.join(values)}, {stored_count},
        {stored_type} AS stored_count_type, typeof(expire_at) AS expire_type, typeof(traffic_used) AS used_type, typeof(traffic_total) AS total_type,
        typeof(nodes_json) AS nodes_type, typeof(last_error) AS error_type,
        CASE WHEN typeof(last_error)='text' THEN length(CAST(last_error AS BLOB)) END AS error_bytes
        FROM {table} ORDER BY id"""
    for row in db.execute(query):
        yield dict(row)


def _integer(value: object, minimum: int = -MAX_SAFE_ID) -> bool:
    return type(value) is int and minimum <= value <= MAX_SAFE_ID


def _metadata(row: dict, table: str, target_id: int, owners: dict[str, str]) -> dict:
    owner = row["user_id"]
    if type(owner) is not int or owner == 0 or not -MAX_OWNER - 1 <= owner <= MAX_OWNER:
        raise _InvalidRow("invalidMetadataRows")
    if owner < 0 and str(owner) not in owners:
        raise _InvalidRow("unmappedOwnerRows")
    owner = owners.get(str(owner), str(owner))
    name, url, token = (row[key] for key in ("name", "url", "token"))
    error = "legacy-refresh-failed" if row["error_type"] == "text" and row["error_bytes"] > 0 else None
    time_column = "updated_at" if table == "subscriptions" else "deleted_at"
    if not (_integer(row["id"], 1) and row["source_rowid"] == row["id"] and _integer(target_id, 1)
            and isinstance(name, str) and 1 <= len(name) <= 512 and "\0" not in name
            and isinstance(url, str) and 1 <= len(url.encode("utf-8")) <= 16384 and "\0" not in url
            and isinstance(token, str) and TOKEN.fullmatch(token)
            and row["error_type"] in ("null", "text")
            and _integer(row["created_at"], 1) and _integer(row[time_column], 1)
            and row["expire_type"] in ("null", "integer") and (row["expire_at"] is None or _integer(row["expire_at"]))
            and row["used_type"] in ("null", "integer", "real") and row["total_type"] in ("null", "integer", "real")
            and row["stored_count_type"] in ("absent", "integer")
            and (row["stored_count_type"] == "absent" or _integer(row["node_count"], 0))
            and all(value is None or type(value) in (float, int) and math.isfinite(value)
                    for value in (row["traffic_used"], row["traffic_total"]))
            and row["nodes_type"] == "text"):
        raise _InvalidRow("invalidMetadataRows")
    record = {"id": target_id, "owner_id": owner, "name": name, "source_url": url, "token": token,
              "expire_at": row["expire_at"], "traffic_used": row["traffic_used"], "traffic_total": row["traffic_total"],
              "last_error": error, "created_at": row["created_at"], "updated_at": row[time_column]}
    if table == "deleted_subs":
        record.update(deleted_at=row["deleted_at"], lifecycle_revision=1)
    return record


def _node_line(node: dict) -> bytes:
    pending = [node]
    while pending:
        value = pending.pop()
        if type(value) is int and abs(value) > MAX_SAFE_ID:
            raise _InvalidRow("invalidNodeRows")
        if isinstance(value, dict):
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
    try:
        return _json(node) + b"\n"
    except (UnicodeError, ValueError, RecursionError):
        raise _InvalidRow("invalidNodeRows") from None


def _measure(db: sqlite3.Connection, table: str, rowid: int) -> dict:
    result = {"nodeCount": 0, "bytes": 0, "maxLineBytes": 0, "chunks": 0}
    used = 0
    try:
        with db.blobopen(table, "nodes_json", rowid, readonly=True) as blob:
            for node in inventory._ArrayReader(blob):
                line = len(_node_line(node))
                result["nodeCount"] += 1
                result["bytes"] += line
                result["maxLineBytes"] = max(result["maxLineBytes"], line)
                if used == 0 or used + line > CHUNK_BYTES:
                    result["chunks"] += 1
                    used = 0
                used += line
    except inventory._RowProblem as error:
        code = "nodeReadLimitRows" if error.args[0] in ("recordReadLimitRows", "recordDepthLimitRows") else "invalidNodeRows"
        raise _InvalidRow(code) from None
    return result


class _Output:
    def __init__(self, root: Path):
        self.root = root
        self.index = _new_file(root / "files.ndjson")
        self.file_count = 0

    def record(self, relative: str) -> None:
        size, digest = _file_hash(self.root / relative)
        line = _json({"path": relative, "bytes": size, "sha256": digest}) + b"\n"
        _require(len(line) <= MAX_INDEX_LINE_BYTES)
        self.index.write(line)
        self.file_count += 1

    def write(self, relative: str, body: bytes) -> str:
        path = self.root / relative
        with _new_file(path) as file:
            file.write(body)
        self.record(relative)
        return sha256(body).hexdigest()


def _snapshot(db: sqlite3.Connection, table: str, rowid: int, target_id: int, source_digest: str, output: _Output) -> dict:
    snapshot = str(uuid5(NAMESPACE_URL, f"subs-bot-legacy-snapshot-v1:{source_digest}:{table}:{rowid}:{target_id}"))
    prefix = f"objects/subscriptions/{target_id}/{snapshot}"
    (output.root / "objects" / "subscriptions" / str(target_id)).mkdir(mode=0o700)
    (output.root / prefix).mkdir(mode=0o700)
    chunks = []
    chunk = bytearray()
    count = 0
    nodes = 0
    total_bytes = 0

    def flush():
        nonlocal chunk, count
        _require(len(chunks) < MAX_CHUNKS)
        digest = output.write(f"{prefix}/{len(chunks)}.ndjson", bytes(chunk))
        chunks.append({"bytes": len(chunk), "sha256": digest, "count": count})
        chunk = bytearray()
        count = 0

    with db.blobopen(table, "nodes_json", rowid, readonly=True) as blob:
        for node in inventory._ArrayReader(blob):
            line = _node_line(node)
            _require(len(line) <= CHUNK_BYTES and nodes < MAX_NODES and total_bytes + len(line) <= SNAPSHOT_BYTES)
            if chunk and len(chunk) + len(line) > CHUNK_BYTES:
                flush()
            chunk.extend(line)
            count += 1
            nodes += 1
            total_bytes += len(line)
    _require(nodes > 0)
    flush()
    manifest = _json({"version": 1, "chunks": chunks})
    digest = output.write(f"{prefix}/manifest.json", manifest)
    return {"generation": 1, "snapshot_id": snapshot, "manifest_sha256": digest, "node_count": nodes}


def _convert(db: sqlite3.Connection, root: Path, source_digest: str, owners: dict[str, str]) -> dict:
    domains, known = _schema(db)
    high_water = _sequence_high_water(db, known)
    _require(high_water <= MAX_SAFE_ID - domains["deleted_subs"]["rows"])
    consumed_bookkeeping = 0
    if "meta" in known:
        matching = db.execute("""SELECT count(*) FROM meta WHERE typeof(key)='text' AND key COLLATE BINARY='node_count_backfilled_v1'
            AND typeof(value)='text' AND value COLLATE BINARY='1'""").fetchone()[0]
        # The normal source schema has one primary-key marker. Duplicate derived
        # rows are not silently treated as a known schema variant.
        consumed_bookkeeping = 1 if matching == 1 else 0
    domains["meta"].update(consumedRows=consumed_bookkeeping, unhandledRows=domains["meta"]["rows"] - consumed_bookkeeping)
    blockers = {f"unhandled:{name}": value["rows"] for name, value in domains.items()
                if name not in (*HANDLED, "meta") and value["rows"]}
    if domains["meta"]["unhandledRows"]:
        blockers["unhandled:meta"] = domains["meta"]["unhandledRows"]
    problems = dict.fromkeys(PROBLEMS, 0)
    totals = {"activeRows": domains["subscriptions"]["rows"], "trashRows": domains["deleted_subs"]["rows"],
              "convertedRows": 0, "nodeCount": 0, "nodeBytes": 0, "recomputedNodeCountRows": 0,
              "emptyRows": 0, "negativeOwnerRows": 0, "redactedErrorRows": 0,
              "consumedBookkeepingRows": consumed_bookkeeping}
    totals["rawNodeBytes"] = sum(db.execute(f"SELECT COALESCE(sum(length(CAST(nodes_json AS BLOB))),0) FROM {table}").fetchone()[0]
                                for table in HANDLED if table in known)
    scratch_path = root / ".validation.sqlite"
    with _new_file(scratch_path):
        pass
    with closing(sqlite3.connect(scratch_path)) as scratch:
        scratch.execute("PRAGMA trusted_schema = OFF")
        scratch.execute("PRAGMA cache_size = -1024")
        scratch.execute("PRAGMA temp_store = FILE")
        scratch.execute("CREATE TABLE seen (token TEXT PRIMARY KEY)")
        scratch.execute("CREATE TABLE measured (source TEXT, id INTEGER, nodes INTEGER, PRIMARY KEY(source,id))")
        for table in HANDLED:
            if table not in known:
                continue
            for ordinal, row in enumerate(_rows(db, table, known[table]), 1):
                target_id = row["id"] if table == "subscriptions" else high_water + ordinal
                totals["negativeOwnerRows"] += type(row["user_id"]) is int and row["user_id"] < 0
                try:
                    metadata = _metadata(row, table, target_id, owners)
                    totals["redactedErrorRows"] += metadata["last_error"] is not None
                    try:
                        scratch.execute("INSERT INTO seen VALUES (?)", (metadata["token"],))
                    except sqlite3.IntegrityError:
                        raise _InvalidRow("tokenCollisionRows") from None
                    size = _measure(db, table, row["source_rowid"])
                    totals["nodeCount"] += size["nodeCount"]
                    totals["nodeBytes"] += size["bytes"]
                    totals["emptyRows"] += size["nodeCount"] == 0
                    totals["recomputedNodeCountRows"] += "node_count" in known[table] and row["node_count"] != size["nodeCount"]
                    for condition, code in ((size["maxLineBytes"] > CHUNK_BYTES, "lineOverLimitRows"),
                                            (size["bytes"] > SNAPSHOT_BYTES, "snapshotOverLimitRows"),
                                            (size["nodeCount"] > MAX_NODES, "nodeCountOverLimitRows"),
                                            (size["chunks"] > MAX_CHUNKS, "chunkCountOverLimitRows")):
                        problems[code] += condition
                    scratch.execute("INSERT INTO measured VALUES (?,?,?)", (table, row["id"], size["nodeCount"]))
                except _InvalidRow as error:
                    problems[error.args[0]] += 1
        blockers.update({name: count for name, count in problems.items() if count})
        output = _Output(root)
        try:
            if not any(problems.values()):
                (root / "objects").mkdir(mode=0o700)
                (root / "objects" / "subscriptions").mkdir(mode=0o700)
                for table, filename in (("subscriptions", "active.ndjson"), ("deleted_subs", "trash.ndjson")):
                    with _new_file(root / filename) as file:
                        if table in known:
                            for ordinal, row in enumerate(_rows(db, table, known[table]), 1):
                                target_id = row["id"] if table == "subscriptions" else high_water + ordinal
                                record = _metadata(row, table, target_id, owners)
                                node_count = scratch.execute("SELECT nodes FROM measured WHERE source=? AND id=?",
                                                             (table, row["id"])).fetchone()[0]
                                pointer = _snapshot(db, table, row["source_rowid"], target_id, source_digest, output) if node_count else {
                                    "generation": 0, "snapshot_id": None, "manifest_sha256": None, "node_count": 0}
                                _require(pointer["node_count"] == node_count)
                                record.update(pointer)
                                envelope = {"legacyTable": table, "legacyId": row["id"], "storedNodeCount": row["node_count"],
                                            "lifecycleRevision": 0 if table == "subscriptions" else 1, "record": record}
                                line = _json(envelope) + b"\n"
                                _require(len(line) <= MAX_METADATA_BYTES)
                                file.write(line)
                                totals["convertedRows"] += 1
                    output.record(filename)
        finally:
            output.index.close()
    scratch_path.unlink()
    _require(not any(Path(str(scratch_path) + suffix).exists() for suffix in ("-wal", "-shm", "-journal")))
    size, digest = _file_hash(root / "files.ndjson")
    manifest = {
        "version": 1, "completeImportable": not blockers, "sourceSha256": source_digest,
        "ownerMapSha256": sha256(_json(dict(sorted(owners.items())))).hexdigest(),
        "domains": domains, "blockers": blockers, "counts": totals,
        "limits": {"chunkBytes": CHUNK_BYTES, "snapshotBytes": SNAPSHOT_BYTES, "nodes": MAX_NODES, "chunks": MAX_CHUNKS},
        "trashIdMapping": {"kind": "source-high-water-plus-ordinal", "sourceHighWater": high_water,
                           "targetSequenceHighWater": high_water + domains["deleted_subs"]["rows"]},
        "exportCompatibility": "not-validated", "files": {"path": "files.ndjson", "bytes": size, "sha256": digest, "count": output.file_count},
    }
    body = _json(manifest)
    with _new_file(root / "manifest.json") as file:
        file.write(body)
    with _new_file(root / "manifest.sha256") as file:
        file.write(sha256(body).hexdigest().encode("ascii") + b"\n")
    return {"version": 1, "completeImportable": not blockers, "domains": domains, "blockers": blockers, "counts": totals}


def convert_backup(source: Path, output: Path, *, owner_map: dict[str, str] | None = None) -> dict:
    """Write a new private package; a blocked package is never importable.

    All handled rows must be valid before any target row or object is emitted.
    Failure leaves only a private incomplete directory, never a commit marker.
    """
    created_output = False
    try:
        owners = _owner_map({} if owner_map is None else owner_map)
        source = _safe_path(source, existing=True)
        output = _safe_path(output, existing=False)
        before = inventory._file_state(source)
        descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as file:
            header = file.read(20)
        _require(header.startswith(b"SQLite format 3\0") and header[18:20] == b"\x01\x01")
        _, digest = _file_hash(source)
        output.mkdir(mode=0o700)
        created_output = True
        with closing(sqlite3.connect(source.as_uri() + "?mode=ro&immutable=1", uri=True, isolation_level=None)) as db:
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA trusted_schema = OFF")
            db.execute("PRAGMA query_only = ON")
            db.execute("PRAGMA temp_store = MEMORY")
            db.execute("PRAGMA cache_size = -2048")
            _require(tuple(db.execute("PRAGMA trusted_schema").fetchone()) == (0,)
                     and tuple(db.execute("PRAGMA query_only").fetchone()) == (1,)
                     and tuple(db.execute("PRAGMA encoding").fetchone()) == ("UTF-8",))
            db.execute("BEGIN")
            report = _convert(db, output, digest, owners)
            db.execute("ROLLBACK")
        _require(inventory._file_state(source) == before and _file_hash(source)[1] == digest)
        return report
    except (ConversionError, inventory.InventoryError, inventory._RowProblem, _InvalidRow, OSError, sqlite3.Error,
            ValueError, TypeError, UnicodeError, OverflowError, RecursionError):
        # A source changing after output creation invalidates the final marker too.
        if created_output:
            try:
                (output / "manifest.sha256").unlink()
            except OSError:
                pass
        raise ConversionError("Legacy snapshot conversion could not be confirmed safely.") from None


def verify_bundle(directory: Path, *, require_complete: bool = True) -> dict:
    """Verify the private file closure, without contacting or changing a target.

    This is an integrity check, not authorization to import. Target schema,
    ownership, link compatibility and export parity remain apply-time gates.
    """
    try:
        root = _safe_path(directory, existing=True, directory=True)
        _require(root.stat().st_uid == os.getuid() and root.stat().st_mode & 0o077 == 0)
        manifest = _bounded_json(root / "manifest.json", 64 * 1024)
        _require(isinstance(manifest, dict) and set(manifest) == {"version", "completeImportable", "sourceSha256",
                 "ownerMapSha256", "domains", "blockers", "counts", "limits", "trashIdMapping", "exportCompatibility", "files"}
                 and type(manifest["version"]) is int and manifest["version"] == 1
                 and type(manifest["completeImportable"]) is bool
                 and isinstance(manifest["blockers"], dict) and manifest["completeImportable"] == (not manifest["blockers"])
                 and (not require_complete or manifest["completeImportable"])
                 and isinstance(manifest["sourceSha256"], str) and HASH.fullmatch(manifest["sourceSha256"])
                 and isinstance(manifest["ownerMapSha256"], str) and HASH.fullmatch(manifest["ownerMapSha256"])
                 and isinstance(manifest["domains"], dict) and set(manifest["domains"]) == set(DOMAINS))
        marker = _bounded_bytes(root / "manifest.sha256", 65)
        _require(marker == _file_hash(root / "manifest.json")[1].encode("ascii") + b"\n")
        index = manifest["files"]
        _require(isinstance(index, dict) and set(index) == {"path", "bytes", "sha256", "count"}
                 and index["path"] == "files.ndjson" and _integer(index["bytes"], 0) and _integer(index["count"], 0)
                 and isinstance(index["sha256"], str) and HASH.fullmatch(index["sha256"])
                 and _file_hash(root / "files.ndjson") == (index["bytes"], index["sha256"]))
        high_water = manifest["trashIdMapping"]["sourceHighWater"]
        _require(_integer(high_water, 0))
        phase = 0
        current_id = 0
        current_snapshot = None
        next_chunk = 0
        unfinished = False
        count = 0
        descriptor = os.open(root / "files.ndjson", os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor, "rb") as file:
            while raw := file.readline(MAX_INDEX_LINE_BYTES + 1):
                _require(len(raw) <= MAX_INDEX_LINE_BYTES and raw.endswith(b"\n"))
                item = json.loads(raw.decode("utf-8"), object_pairs_hook=inventory._unique_object,
                                  parse_constant=inventory._reject_constant)
                _require(isinstance(item, dict) and set(item) == {"path", "bytes", "sha256"}
                         and isinstance(item["path"], str) and _integer(item["bytes"], 0)
                         and isinstance(item["sha256"], str) and HASH.fullmatch(item["sha256"]))
                relative = item["path"]
                if relative in ("active.ndjson", "trash.ndjson"):
                    _require(not unfinished and relative == ("active.ndjson" if phase == 0 else "trash.ndjson") and phase < 2)
                    phase += 1
                else:
                    match = OBJECT_PATH.fullmatch(relative)
                    _require(match is not None and phase < 2)
                    target_id, snapshot, name = match.groups()
                    target_id = int(target_id)
                    _require(_integer(target_id, 1) and (target_id <= high_water if phase == 0 else target_id > high_water))
                    if target_id != current_id:
                        _require(not unfinished and target_id > current_id)
                        current_id, current_snapshot, next_chunk, unfinished = target_id, snapshot, 0, True
                    _require(unfinished and snapshot == current_snapshot)
                    if name == "manifest.json":
                        _require(1 <= next_chunk <= MAX_CHUNKS and item["bytes"] <= 64 * 1024)
                        unfinished = False
                    else:
                        _require(name == f"{next_chunk}.ndjson" and next_chunk < MAX_CHUNKS and 1 <= item["bytes"] <= CHUNK_BYTES)
                        next_chunk += 1
                path = _safe_path(root / relative, existing=True)
                _require(_file_hash(path) == (item["bytes"], item["sha256"]))
                count += 1
        _require(not unfinished and count == index["count"] and (phase == 2 or phase == 0 and count == 0 and not manifest["completeImportable"]))
        if phase == 2:
            _verify_metadata_closure(root, manifest, count)

        def files(path: Path, depth: int = 0) -> int:
            _require(depth <= 5)
            total = 0
            with os.scandir(path) as entries:
                for entry in entries:
                    info = entry.stat(follow_symlinks=False)
                    _require(info.st_uid == os.getuid() and info.st_mode & 0o077 == 0)
                    if stat.S_ISDIR(info.st_mode):
                        total += files(Path(entry.path), depth + 1)
                    else:
                        _require(stat.S_ISREG(info.st_mode))
                        total += 1
            return total

        _require(files(root) == count + 3)
        return manifest
    except (ConversionError, inventory._RowProblem, _InvalidRow, OSError, ValueError, TypeError, KeyError, UnicodeError, RecursionError):
        raise ConversionError("Legacy conversion package could not be verified safely.") from None


def _verify_metadata_closure(root: Path, manifest: dict, indexed_files: int) -> None:
    expected_files = 2
    total_rows = 0
    total_nodes = 0
    total_bytes = 0
    high_water = manifest["trashIdMapping"]["sourceHighWater"]
    base_fields = {"id", "owner_id", "name", "source_url", "token", "expire_at", "traffic_used", "traffic_total",
                   "last_error", "created_at", "updated_at", "generation", "snapshot_id", "manifest_sha256", "node_count"}
    for filename, table in (("active.ndjson", "subscriptions"), ("trash.ndjson", "deleted_subs")):
        rows = 0
        previous_id = 0
        descriptor = os.open(root / filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as file:
            while line := file.readline(MAX_METADATA_BYTES + 1):
                _require(len(line) <= MAX_METADATA_BYTES and line.endswith(b"\n"))
                item = json.loads(line.decode("utf-8"), object_pairs_hook=inventory._unique_object,
                                  parse_constant=inventory._reject_constant)
                _require(isinstance(item, dict) and set(item) == {"legacyTable", "legacyId", "storedNodeCount", "lifecycleRevision", "record"}
                         and item["legacyTable"] == table and _integer(item["legacyId"], 1))
                record = item["record"]
                _require(isinstance(record, dict) and set(record) == base_fields | ({"deleted_at", "lifecycle_revision"} if table == "deleted_subs" else set())
                         and _integer(record["id"], previous_id + 1) and isinstance(record["owner_id"], str)
                         and OWNER.fullmatch(record["owner_id"]) and int(record["owner_id"]) <= MAX_OWNER
                         and isinstance(record["token"], str) and TOKEN.fullmatch(record["token"])
                         and _integer(record["generation"], 0) and record["generation"] <= 1
                         and _integer(item["lifecycleRevision"], 0)
                         and _integer(record["node_count"], 0) and record["node_count"] <= MAX_NODES)
                previous_id = record["id"]
                rows += 1
                total_rows += 1
                _require((record["id"] == item["legacyId"] and record["id"] <= high_water and item["lifecycleRevision"] == 0)
                         if table == "subscriptions" else (record["id"] == high_water + rows and item["lifecycleRevision"] == 1
                                                            and type(record["lifecycle_revision"]) is int and record["lifecycle_revision"] == 1))
                if record["node_count"] == 0:
                    _require(record["generation"] == 0 and record["snapshot_id"] is None and record["manifest_sha256"] is None)
                    continue
                snapshot, digest = record["snapshot_id"], record["manifest_sha256"]
                _require(record["generation"] == 1 and isinstance(snapshot, str) and isinstance(digest, str) and HASH.fullmatch(digest))
                prefix = f"objects/subscriptions/{record['id']}/{snapshot}"
                _require(OBJECT_PATH.fullmatch(prefix + "/manifest.json"))
                body = _bounded_bytes(root / prefix / "manifest.json", 64 * 1024)
                _require(sha256(body).hexdigest() == digest)
                plan = json.loads(body.decode("utf-8"), object_pairs_hook=inventory._unique_object,
                                  parse_constant=inventory._reject_constant)
                _require(isinstance(plan, dict) and set(plan) == {"version", "chunks"} and type(plan["version"]) is int and plan["version"] == 1
                         and isinstance(plan["chunks"], list) and 1 <= len(plan["chunks"]) <= MAX_CHUNKS)
                expected_files += 1 + len(plan["chunks"])
                node_count = 0
                byte_count = 0
                for index, chunk in enumerate(plan["chunks"]):
                    _require(isinstance(chunk, dict) and set(chunk) == {"bytes", "sha256", "count"}
                             and _integer(chunk["bytes"], 1) and chunk["bytes"] <= CHUNK_BYTES
                             and _integer(chunk["count"], 1) and chunk["count"] <= MAX_NODES
                             and isinstance(chunk["sha256"], str) and HASH.fullmatch(chunk["sha256"]))
                    raw = _bounded_bytes(root / prefix / f"{index}.ndjson", CHUNK_BYTES)
                    _require(len(raw) == chunk["bytes"] and sha256(raw).hexdigest() == chunk["sha256"])
                    measured = 0
                    for node_line in io.BytesIO(raw):
                        _require(node_line.endswith(b"\n"))
                        node = json.loads(node_line.decode("utf-8"), object_pairs_hook=inventory._unique_object,
                                          parse_constant=inventory._reject_constant)
                        _require(isinstance(node, dict) and _node_line(node) == node_line)
                        measured += 1
                    _require(measured == chunk["count"])
                    node_count += measured
                    byte_count += len(raw)
                _require(node_count == record["node_count"] and byte_count <= SNAPSHOT_BYTES)
                total_nodes += node_count
                total_bytes += byte_count
        _require(rows == manifest["domains"][table]["rows"])
    _require(expected_files == indexed_files and total_rows == manifest["counts"]["convertedRows"]
             and total_nodes == manifest["counts"]["nodeCount"] and total_bytes == manifest["counts"]["nodeBytes"])


def main(args: list[str] | None = None) -> int:
    args = sys.argv[1:] if args is None else args
    if args == ["--help"]:
        print("Usage: legacy_snapshot_convert.py BACKUP OUTPUT [--owner-map MAP.json]")
        return 0
    if len(args) not in (2, 4) or len(args) == 4 and args[2] != "--owner-map":
        print("Legacy snapshot conversion arguments are invalid.", file=sys.stderr)
        return 1
    try:
        owners = {}
        if len(args) == 4:
            path = _safe_path(Path(args[3]), existing=True)
            owners = _bounded_json(path, 8 * 1024 * 1024)
        report = convert_backup(Path(args[0]), Path(args[1]), owner_map=owners)
    except (ConversionError, inventory._RowProblem, OSError, UnicodeError, ValueError):
        print("Legacy snapshot conversion could not be confirmed safely.", file=sys.stderr)
        return 1
    print(json.dumps(report, separators=(",", ":")))
    return 0 if report["completeImportable"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
