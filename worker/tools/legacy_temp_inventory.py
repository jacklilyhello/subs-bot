"""Seal a dormant, owner-only inventory of every bounded legacy temp node."""

from collections import Counter
from contextlib import closing, suppress
from dataclasses import dataclass
from hashlib import sha256
import os
from pathlib import Path
import re
import sqlite3
import stat
import sys
from unicodedata import category

import legacy_snapshot_convert as converter
import legacy_typed_short_inventory as backup


ROWS = "rows.ndjson"
MANIFEST = "manifest.json"
SEAL = "manifest.sha256"
MAX_ROWS = 20_000
MAX_ROWS_BYTES = 64 * 1024 * 1024
MAX_BATCH_NODES = 500
MAX_BATCH_BYTES = 256 * 1024
MAX_OWNER_NODES = 5_000
MAX_OWNER_BYTES = 4 * 1024 * 1024
MAX_ID = 2**53 - 1
TABLE_SQL = re.compile(r"\ACREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?temp_nodes\s*\(\s*"
    r"id\s+INTEGER\s+PRIMARY\s+KEY\s+AUTOINCREMENT\s*,\s*user_id\s+INTEGER\s+NOT\s+NULL\s*,\s*"
    r"url\s+TEXT\s+NOT\s+NULL\s*,\s*name\s+TEXT\s+NOT\s+NULL\s*,\s*created_at\s+INTEGER\s+NOT\s+NULL\s*\)\Z",
    re.ASCII | re.IGNORECASE)
URI = re.compile(r"\A([a-z][a-z0-9+.-]{0,31})://(.+)\Z", re.ASCII | re.IGNORECASE)
NON_NODE_SCHEMES = {"data", "file", "ftp", "http", "https", "javascript"}
LINE_CATEGORIES = {"Cc", "Cs", "Zl", "Zp"}
ERROR = "Legacy temporary node inventory could not be sealed safely."


class InventoryError(RuntimeError):
    """An inventory failure with a fixed, non-sensitive message."""


def require(condition, message=ERROR):
    if not condition:
        raise InventoryError(message)


def _integer(value, minimum=1, maximum=MAX_ID):
    return type(value) is int and minimum <= value <= maximum


def _verify_backup(path, state, digest):
    require(not any(os.path.lexists(str(path) + suffix) for suffix in ("-wal", "-shm", "-journal")))
    backup._verify_source(path, digest, state)
    require(not any(os.path.lexists(str(path) + suffix) for suffix in ("-wal", "-shm", "-journal")))


def _schema(db):
    definitions = db.execute("""SELECT CASE WHEN name='temp_nodes' THEN name END,type,
        CASE WHEN tbl_name='temp_nodes' THEN tbl_name END,
        CASE WHEN length(CAST(sql AS BLOB))<=16384 THEN sql END FROM main.sqlite_schema
        WHERE name COLLATE NOCASE='temp_nodes' OR tbl_name COLLATE NOCASE='temp_nodes' LIMIT 2""").fetchall()
    schema_error = "Legacy temporary node table schema differs."
    present = bool(definitions)
    if present:
        require(len(definitions) == 1 and definitions[0][:3] == ("temp_nodes", "table", "temp_nodes")
                and isinstance(definitions[0][3], str) and TABLE_SQL.fullmatch(definitions[0][3]), schema_error)
        expected = [(0, "id", "INTEGER", 0, None, 1, 0), (1, "user_id", "INTEGER", 1, None, 0, 0),
                    (2, "url", "TEXT", 1, None, 0, 0), (3, "name", "TEXT", 1, None, 0, 0),
                    (4, "created_at", "INTEGER", 1, None, 0, 0)]
        require(db.execute("PRAGMA main.table_xinfo(temp_nodes)").fetchall() == expected, schema_error)
    has_sequence = db.execute("SELECT 1 FROM main.sqlite_schema WHERE name='sqlite_sequence' AND type='table'").fetchone()
    require(not present or has_sequence, schema_error)
    sequence = db.execute("""SELECT CASE WHEN name='temp_nodes' THEN name END,
        CASE WHEN typeof(seq)='integer' THEN seq END FROM main.sqlite_sequence
        WHERE name COLLATE NOCASE='temp_nodes' LIMIT 2""").fetchall() if has_sequence else []
    require(not sequence or (present and len(sequence) == 1 and sequence[0][0] == "temp_nodes"
            and _integer(sequence[0][1], 0, 2**63 - 1)), schema_error)
    count, maximum = db.execute("SELECT count(*),max(id) FROM main.temp_nodes").fetchone() if present else (0, None)
    high = sequence[0][1] if sequence else 0
    require(maximum is None or (sequence and maximum <= high), schema_error)
    require(_integer(count, 0, MAX_ROWS), "Legacy temporary node row count exceeds the inventory limit.")
    return present, count, high


def _text(db, identity, column, storage_type):
    if storage_type != "text":
        return None, None, None, "storage"
    with db.blobopen("temp_nodes", column, identity, readonly=True) as blob:
        size = len(blob)
        if size > MAX_BATCH_BYTES:
            return None, size, None, "limit"
        raw = blob.read()
    digest = sha256(raw).hexdigest()
    try:
        text = raw.decode("utf-8", "strict")
    except UnicodeError:
        return None, size, digest, "encoding"
    return text, size, digest, None


def _uri_problem(text):
    if not text or any(category(character) in LINE_CATEGORIES for character in text):
        return "uri-text"
    match = URI.fullmatch(text)
    if not match:
        return "uri-shape"
    if match[1].lower() in NON_NODE_SCHEMES:
        return "unsupported-non-node-scheme"
    address = match[2].partition("#")[0]
    if not address or any(character.isspace() for character in address):
        return "uri-shape"
    return None


@dataclass
class _OwnerProjection:
    nodes: int = 0
    bytes: int = 0
    batches: int = 0
    batch_nodes: int = 0
    batch_bytes: int = 0

    def add(self, node_bytes):
        # Project the exact compact UTF-8 JSON array of {name,type,share}.
        # The subsequent Worker validator still owns actual admission.
        additional = node_bytes + (1 if self.batch_nodes else 2)
        if not self.batch_nodes or self.batch_nodes == MAX_BATCH_NODES or self.batch_bytes + additional > MAX_BATCH_BYTES:
            self.batches += 1
            self.batch_nodes = self.batch_bytes = 0
            additional = node_bytes + 2
        self.nodes += 1
        self.bytes += additional
        self.batch_nodes += 1
        self.batch_bytes += additional


def _row(db, row, ordinal, owners, coalesced):
    identity, original, created, uri_type, name_type = row
    issuer = str(original) if type(original) is int else None
    owner = owners.get(issuer, issuer) if issuer is not None else None
    reasons = []
    if not _integer(identity):
        reasons.append("legacy-id")
    if not _integer(created):
        reasons.append("created-at")
    if issuer is None or original == 0:
        owner = None
        reasons.append("owner-identity")
    elif original < 0:
        if owner == issuer:
            owner = None
            reasons.append("owner-unmapped")
        else:
            reasons.append("owner-remapped")
    elif owner in coalesced:
        reasons.append("owner-coalesced")
    uri, uri_bytes, uri_sha, uri_error = _text(db, identity, "url", uri_type)
    name, name_bytes, name_sha, name_error = _text(db, identity, "name", name_type)
    if uri_error:
        reasons.append("uri-" + uri_error)
    elif issue := _uri_problem(uri):
        reasons.append(issue)
    if name_error:
        reasons.append("name-" + name_error)
    node, node_bytes = None, None
    if not reasons:
        candidate = {"name": name, "type": "temp", "share": uri}
        node_bytes = len(converter._json(candidate))
        if node_bytes + 2 > MAX_BATCH_BYTES:
            reasons.append("node-batch-limit")
        else:
            node = candidate
    return {"ordinal": ordinal, "legacyId": identity, "originalOwnerId": issuer, "ownerId": owner, "createdAt": created,
            "uriBytes": uri_bytes, "uriSha256": uri_sha, "nameBytes": name_bytes, "nameSha256": name_sha,
            "disposition": "blocked" if reasons else "pending-worker", "reasons": reasons, "node": node}, node_bytes


def _capture(db, output, owners):
    present, expected, high = _schema(db)
    coalesced = {target for source, target in owners.items() if source != target}
    projections, row_reasons = {}, Counter()
    scanned = blocked = 0

    def rows():
        nonlocal scanned, blocked
        if not present:
            return
        result = db.execute("""SELECT id,CASE WHEN typeof(user_id)='integer' THEN user_id END,
            CASE WHEN typeof(created_at)='integer' THEN created_at END,typeof(url),typeof(name)
            FROM main.temp_nodes ORDER BY id LIMIT ?""", (MAX_ROWS + 1,))
        previous = None
        for ordinal, source in enumerate(result, 1):
            require(ordinal <= expected and (previous is None or source[0] > previous))
            previous, scanned = source[0], ordinal
            item, size = _row(db, source, ordinal, owners, coalesced)
            if item["disposition"] == "blocked":
                blocked += 1
                row_reasons.update(item["reasons"])
            else:
                projection = projections.setdefault(item["ownerId"], _OwnerProjection())
                projection.add(size)
            yield converter._json(item) + b"\n"

    file = backup._write_file(output / ROWS, rows(), MAX_ROWS_BYTES)
    require(scanned == expected)
    scope_reasons = Counter()
    blocked_scopes = 0
    for projection in projections.values():
        over_nodes, over_bytes = projection.nodes > MAX_OWNER_NODES, projection.bytes > MAX_OWNER_BYTES
        if over_nodes or over_bytes:
            blocked_scopes += 1
            if over_nodes:
                scope_reasons["owner-node-limit"] += 1
            if over_bytes:
                scope_reasons["owner-byte-limit"] += 1
    counts = {"present": present, "rows": scanned, "pendingWorkerRows": scanned - blocked, "blockedRows": blocked,
              "blockedOwnerScopes": blocked_scopes, "rowReasons": dict(sorted(row_reasons.items())),
              "scopeReasons": dict(sorted(scope_reasons.items())), "projection": {"status": "preflight-only",
                  "owners": len(projections), "batches": sum(value.batches for value in projections.values()),
                  "payloadBytes": sum(value.bytes for value in projections.values()),
                  "maxOwnerNodes": max((value.nodes for value in projections.values()), default=0),
                  "maxOwnerBytes": max((value.bytes for value in projections.values()), default=0)}}
    return counts, high, file


def seal_inventory(backup_path, output, *, source_sha256, owner_map, owner_map_sha256, legacy_bot_id):
    destination = None
    try:
        require(all(isinstance(value, str) and converter.HASH.fullmatch(value) for value in (source_sha256, owner_map_sha256))
                and isinstance(legacy_bot_id, str) and converter.OWNER.fullmatch(legacy_bot_id)
                and int(legacy_bot_id) <= converter.MAX_OWNER)
        owners = converter._owner_map(owner_map)
        require(sha256(converter._json(dict(sorted(owners.items())))).hexdigest() == owner_map_sha256)
        source = converter._safe_path(backup_path, existing=True)
        target = converter._safe_path(output, existing=False)
        backup._private_parent(target)
        state = backup._source_state(source)
        _verify_backup(source, state, source_sha256)
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
            counts, high, rows = _capture(db, target, owners)
            db.execute("ROLLBACK")
        _verify_backup(source, state, source_sha256)
        manifest = converter._json({"version": 1, "kind": "legacy-temp-node-inventory", "scope": "offline-dormant",
            "sourceSha256": source_sha256, "ownerMapSha256": owner_map_sha256, "legacyBotId": legacy_bot_id,
            "sourceHighWater": high, "rowOrder": "legacy-id-ascending", "workerValidation": "pending",
            "completeImportable": False, "inventory": counts, "files": [rows]}) + b"\n"
        descriptor = backup._write_file(target / MANIFEST, (manifest,), 64 * 1024)
        backup._write_file(target / SEAL, (descriptor["sha256"].encode("ascii") + b"\n",), 65)
        return {"inventory": counts, "workerValidation": "pending", "completeImportable": False,
                "manifestSha256": descriptor["sha256"]}
    except (InventoryError, backup.InventoryError, converter.ConversionError, OSError, sqlite3.Error,
            ValueError, TypeError, KeyError, RecursionError, OverflowError) as error:
        if destination is not None:
            for name in (SEAL, MANIFEST, ROWS):
                with suppress(OSError):
                    (destination / name).unlink()
            with suppress(OSError):
                destination.rmdir()
        raise InventoryError(str(error) if isinstance(error, InventoryError) else ERROR) from None


def main(args=None):
    args = sys.argv[1:] if args is None else args
    if len(args) != 6:
        print("Usage: legacy_temp_inventory.py BACKUP OUTPUT SOURCE_SHA256 OWNER_MAP_JSON OWNER_MAP_SHA256 LEGACY_BOT_ID", file=sys.stderr)
        return 2
    source, output, source_sha, owner_map, owner_sha, bot_id = args
    try:
        path = converter._safe_path(Path(owner_map), existing=True)
        backup._private_parent(path)
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and not info.st_mode & 0o077 and info.st_nlink == 1)
        owners = converter._bounded_json(path, backup.MAX_METADATA_BYTES)
        report = seal_inventory(Path(source), Path(output), source_sha256=source_sha, owner_map=owners,
                                owner_map_sha256=owner_sha, legacy_bot_id=bot_id)
        print(converter._json(report).decode("ascii"))
        counts = report["inventory"]
        return 2 if counts["blockedRows"] or counts["blockedOwnerScopes"] else 0
    except (InventoryError, backup.InventoryError, converter.ConversionError, converter.inventory._RowProblem,
            OSError, ValueError, TypeError, RecursionError) as error:
        print(str(error) if isinstance(error, InventoryError) else ERROR, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
