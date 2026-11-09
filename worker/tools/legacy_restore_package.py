"""Build an unapplied, private D1 SQL and R2 package on a hosted runner."""

from contextlib import closing
from dataclasses import dataclass
from hashlib import sha256
import io
from itertools import zip_longest
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import sys
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from uuid import NAMESPACE_URL, uuid5

import d1_migrations as migrations
import legacy_snapshot_convert as converter
import legacy_typed_short_inventory as typed_inventory
import native_restore_rehearsal as native
import prepare_isolation_artifact as artifact


ACTIVE = "subscriptions"
TRASH = "subscription_trash"
LIFECYCLE = "subscription_lifecycle"
PATH_RULES = "path_rules"
PATH_COLUMNS = ("id", "owner_id", "keyword", "remark")
EMPTY_EXPORTS = "legacy_empty_subscription_exports"
EMPTY_EXPORT_COLUMNS = ("subscription_id", "owner_id", "token_sha256")
EMPTY_EXPORT_PROFILE = "legacy-empty-v3"
EMPTY_EXPORT_MIGRATION = "0026_legacy_empty_subscription_exports.sql"
EMPTY_EXPORT_MIGRATION_SHA256 = "124eb153b8f8d1fc01165d2ba0db1adee8948cd6bffe8a8ad2465afa62da3976"
TYPED_SHORT_PROFILE = "legacy-typed-short-v4"
TYPED_SHORT_MIGRATION = "0029_legacy_subscription_short_links.sql"
TYPED_SHORT_MIGRATION_SHA256 = "1a0da8aa8aedde095b3e1a4bc71b5e03376587882288c4e276c9a1f9afa1297d"
TYPED_SHORTS = "legacy_subscription_short_links"
TYPED_SHORT_COLUMNS = ("code_sha256", "bot_id", "owner_id", "subscription_id", "token_sha256", "format", "created_at", "revoked_at")
TYPED_SHORT_LINE_BYTES = 1024
MIXED_SHORT_PROFILE = "legacy-mixed-short-v5"
EXTERNAL_SHORT_MIGRATION = "0019_telegram_short_links.sql"
EXTERNAL_SHORT_MIGRATION_SHA256 = "44cda07068dd84435542771899824c1d4196a1ffdc18f990abcb723e5bdaa3c1"
EXTERNAL_SHORTS = "normal_short_links"
EXTERNAL_SHORT_COLUMNS = ("code_sha256", "code_length", "bot_id", "owner_id", "origin_receipt_id", "nonce",
                          "key_version", "target_url", "created_at", "revoked_at")
COLUMNS = ("id", "owner_id", "name", "source_url", "token", "expire_at", "traffic_used", "traffic_total",
           "last_error", "created_at", "updated_at", "generation", "snapshot_id", "manifest_sha256", "node_count")
TABLE_COLUMNS = {
    ACTIVE: COLUMNS,
    TRASH: (*COLUMNS, "deleted_at", "lifecycle_revision"),
    LIFECYCLE: ("subscription_id", "revision"),
    migrations.LEDGER: ("position", "name", "sha256", "mode", "applied_at"),
}
MANIFEST = "manifest.json"
MARKER = "manifest.sha256"
LINEAGE = "lineage.ndjson"
SQL = "restore.sql"
ERROR = "Private legacy restore package could not be built safely."


class PackageError(RuntimeError):
    """Only fixed errors may leave the package builder."""


@dataclass(frozen=True)
class TypedShortInput:
    directory: Path
    manifest_sha256: str
    old_origin_sha256: str
    legacy_bot_id: str


def require(condition):
    if not condition:
        raise PackageError(ERROR)


def private_path(path, *, directory=False):
    path = converter._safe_path(Path(path), existing=True, directory=directory)
    info = path.stat()
    require(info.st_uid == os.getuid() and info.st_mode & 0o077 == 0)
    return path


def read_private(path, maximum):
    return converter._bounded_bytes(private_path(path), maximum)


def read_pinned(path, maximum, expected):
    require(native.matches(native.DIGEST, expected))
    body = read_private(path, maximum)
    require(sha256(body).hexdigest() == expected)
    return body


def parse_lines(body, limit):
    for line in io.BytesIO(body):
        require(len(line) <= limit and line.endswith(b"\n"))
        yield native.parsed(line[:-1], limit)


def worker_artifact(root, revision, manifest_sha):
    raw = read_pinned(root / "isolation.json", artifact._MAX_JSON, manifest_sha)
    manifest = artifact._parse_object(raw, "Verified Worker artifact manifest differs.")
    run_id, attempt = manifest.get("runId"), manifest.get("runAttempt")
    require(native.matches(artifact._REVISION, revision) and native.matches(artifact._DECIMAL, run_id)
            and native.matches(artifact._DECIMAL, attempt))
    hashes, sizes = artifact._expected_hashes(manifest, revision, run_id, attempt)
    total = 0
    for name, expected in hashes.items():
        body = read_pinned(root / name, sizes.get(name, artifact._MAX_EXPANDED), expected)
        require(body and (name not in sizes or len(body) == sizes[name]))
        total += len(body)
        require(total <= artifact._MAX_EXPANDED)
    chain = migrations._load_migrations(root, manifest)
    require(len(chain) >= 5 and chain[2].name == "0003_subscription_lifecycle.sql"
            and chain[4].name == "0005_private_shares.sql")
    identity = {key: manifest[key] for key in ("revision", "runId", "runAttempt", "bundleSha256", "compatibilityDate", "migrations")}
    return chain, {**identity, "manifestSha256": manifest_sha}


def converter_artifact(root, manifest_sha, *, typed_short_domain=None):
    raw = read_pinned(root / MANIFEST, 64 * 1024, manifest_sha)
    manifest = converter.verify_bundle(root, require_complete=typed_short_domain is None)
    require(read_pinned(root / MANIFEST, 64 * 1024, manifest_sha) == raw)
    require(read_private(root / MARKER, 65) == manifest_sha.encode("ascii") + b"\n")
    domains = manifest["domains"]
    handled = {*converter.HANDLED, "meta"}
    if manifest["version"] == 2:
        handled.add(converter.PATH_DOMAIN)
    if typed_short_domain is not None:
        # Consume only the exact domain proven by the independently sealed sidecar.
        short_count = typed_short_domain["rows"]
        require(type(domains["short_links"]["present"]) is bool and type(domains["short_links"]["rows"]) is int
                and domains["short_links"] == typed_short_domain
                and manifest["blockers"] == ({"unhandled:short_links": short_count} if short_count else {}))
        handled.add("short_links")
    require(all(type(item["rows"]) is int and item["rows"] >= 0 for item in domains.values())
            and all(domains[name]["rows"] == 0 for name in converter.DOMAINS if name not in handled)
            and domains["meta"]["unhandledRows"] == 0 and domains["meta"]["rows"] == domains["meta"]["consumedRows"])
    file_index = manifest["files"]
    metadata = metadata_files(manifest)
    max_files = native.MAX_OBJECTS + len(metadata)
    require(native.integer(file_index["count"], len(metadata), max_files))
    index = read_pinned(root / "files.ndjson", max_files * converter.MAX_INDEX_LINE_BYTES, file_index["sha256"])
    require(len(index) == file_index["bytes"])
    descriptors = {}
    for item in parse_lines(index, converter.MAX_INDEX_LINE_BYTES):
        require(item["path"] not in descriptors)
        descriptors[item["path"]] = item
    require(len(descriptors) == file_index["count"] and metadata <= descriptors.keys())
    mapping = manifest["trashIdMapping"]
    high = mapping["sourceHighWater"]
    require(mapping["kind"] == "source-high-water-plus-ordinal" and native.integer(high)
            and native.integer(mapping["targetSequenceHighWater"], high, native.MAX_SAFE - 1)
            and mapping["targetSequenceHighWater"] == high + domains["deleted_subs"]["rows"])
    return manifest, descriptors


def metadata_files(source):
    files = {"active.ndjson", "trash.ndjson"}
    if source["version"] == 2:
        files.add(converter.PATH_FILE)
    return files


def expected_file(root, descriptors, relative, limit):
    item = descriptors[relative]
    body = read_pinned(root / relative, limit, item["sha256"])
    require(len(body) == item["bytes"])
    return body


def validate_record(item, source_table, target_table, ordinal, previous, source):
    require(set(item) == {"legacyTable", "legacyId", "storedNodeCount", "lifecycleRevision", "record"}
            and item["legacyTable"] == source_table)
    row = item["record"]
    legacy_id = item["legacyId"]
    high = source["trashIdMapping"]["sourceHighWater"]
    trash = target_table == TRASH
    target_id = high + ordinal if trash else legacy_id
    require(native.integer(legacy_id, previous + 1, high) and type(item["lifecycleRevision"]) is int
            and item["lifecycleRevision"] == int(trash) and isinstance(row, dict) and set(row) == set(TABLE_COLUMNS[target_table])
            and native.integer(row["id"], 1) and row["id"] == target_id)
    require(item["storedNodeCount"] is None or native.integer(item["storedNodeCount"]))
    owner, name, url, token = (row[key] for key in ("owner_id", "name", "source_url", "token"))
    require(native.matches(converter.OWNER, owner) and int(owner) <= converter.MAX_OWNER
            and isinstance(name, str) and 1 <= len(name) <= 512 and "\0" not in name
            and isinstance(url, str) and 1 <= len(url.encode("utf-8")) <= 16384 and "\0" not in url
            and native.matches(converter.TOKEN, token) and row["last_error"] in (None, "legacy-refresh-failed")
            and native.integer(row["created_at"], 1) and native.integer(row["updated_at"], 1)
            and (row["expire_at"] is None or native.integer(row["expire_at"], -native.MAX_SAFE)))
    for value in (row["traffic_used"], row["traffic_total"]):
        require(value is None or type(value) is float and math.isfinite(value) or native.integer(value, -native.MAX_SAFE))
    require(native.integer(row["generation"], 0, 1) and native.integer(row["node_count"], 0, converter.MAX_NODES))
    if row["generation"]:
        expected_id = uuid5(NAMESPACE_URL, f"subs-bot-legacy-snapshot-v1:{source['sourceSha256']}:{source_table}:{legacy_id}:{target_id}")
        require(row["snapshot_id"] == str(expected_id) and native.matches(native.DIGEST, row["manifest_sha256"]) and row["node_count"] > 0)
    else:
        require(row["snapshot_id"] is None and row["manifest_sha256"] is None and row["node_count"] == 0)
    if trash:
        require(native.integer(row["lifecycle_revision"], 1, 1) and native.integer(row["deleted_at"], 1)
                and row["deleted_at"] == row["updated_at"])
    return row


def empty_export_identity(subscription_id, owner_id, token):
    require(native.integer(subscription_id, 1)
            and native.matches(converter.OWNER, owner_id) and int(owner_id) <= converter.MAX_OWNER
            and native.matches(converter.TOKEN, token))
    return subscription_id, owner_id, sha256(token.encode("utf-8")).hexdigest()


def verify_empty_export_markers(db):
    # Derive the complete expected set independently from the restored active and
    # trash rows. A marked trash row can serve only after a subsequent restore.
    ledger = db.execute(f"SELECT name,sha256,mode FROM {migrations.LEDGER} WHERE position=26").fetchone()
    require(ledger == (EMPTY_EXPORT_MIGRATION, EMPTY_EXPORT_MIGRATION_SHA256, "applied"))
    candidates = db.execute(f"""
        SELECT id,owner_id,token FROM {ACTIVE}
          WHERE generation=0 AND snapshot_id IS NULL AND manifest_sha256 IS NULL AND node_count=0
        UNION ALL
        SELECT id,owner_id,token FROM {TRASH}
          WHERE generation=0 AND snapshot_id IS NULL AND manifest_sha256 IS NULL AND node_count=0
        ORDER BY id
    """)
    actual = db.execute(f"SELECT {','.join(EMPTY_EXPORT_COLUMNS)} FROM {EMPTY_EXPORTS} ORDER BY subscription_id")
    expected = (empty_export_identity(*row) for row in candidates)
    require(all(marker == identity for marker, identity in zip_longest(actual, expected)))


def load_rows(db, source_root, source, descriptors, lineage, *, include_empty_exports=False):
    counts = {"activeRows": 0, "trashRows": 0, "generationZeroActiveRows": 0, "generationZeroTrashRows": 0,
              "nodeCount": 0, "redactedErrorRows": 0}
    for file, source_table, target_table, label in (
        ("active.ndjson", "subscriptions", ACTIVE, "Active"), ("trash.ndjson", "deleted_subs", TRASH, "Trash")
    ):
        columns = TABLE_COLUMNS[target_table]
        insert = f"INSERT INTO {target_table} ({','.join(columns)}) VALUES ({','.join('?' for _ in columns)})"
        prior, count = 0, 0
        raw = expected_file(source_root, descriptors, file, native.SQL_BYTES)
        for count, item in enumerate(parse_lines(raw, converter.MAX_METADATA_BYTES), 1):
            require(counts["activeRows"] + counts["trashRows"] < native.MAX_ROWS)
            row = validate_record(item, source_table, target_table, count, prior, source)
            prior = item["legacyId"]
            db.execute(insert, tuple(row[column] for column in columns))
            if target_table == TRASH:
                db.execute("INSERT INTO subscription_lifecycle(subscription_id,revision) VALUES (?,?)", (row["id"], 1))
            if include_empty_exports and row["generation"] == 0:
                db.execute(f"INSERT INTO {EMPTY_EXPORTS} ({','.join(EMPTY_EXPORT_COLUMNS)}) VALUES (?,?,?)",
                           empty_export_identity(row["id"], row["owner_id"], row["token"]))
            counts[f"{label.lower()}Rows"] += 1
            counts[f"generationZero{label}Rows"] += int(row["generation"] == 0)
            counts["nodeCount"] += row["node_count"]
            counts["redactedErrorRows"] += int(row["last_error"] is not None)
            lineage.write(native.canonical({"legacyTable": source_table, "legacyId": prior, "targetId": row["id"],
                "lifecycleRevision": item["lifecycleRevision"], "storedNodeCount": item["storedNodeCount"]}) + b"\n")
        require(count == source["domains"][source_table]["rows"])
    source_counts = source["counts"]
    require(all(type(source_counts.get(key)) is int and source_counts[key] == counts[key]
                for key in ("activeRows", "trashRows", "nodeCount", "redactedErrorRows"))
            and source_counts["convertedRows"] == counts["activeRows"] + counts["trashRows"]
            and source_counts["emptyRows"] == counts["generationZeroActiveRows"] + counts["generationZeroTrashRows"])
    return counts


def load_path_rules(db, root, source, descriptors):
    mapping = source["pathIdMapping"]
    raw = expected_file(root, descriptors, converter.PATH_FILE, converter.MAX_PATH_FILE_BYTES)
    records = converter.validate_path_records(converter._read_path_records(io.BytesIO(raw)), mapping)
    db.executemany("INSERT INTO path_rules (id,owner_id,keyword,remark) VALUES (?,?,?,?)",
                   (tuple(row[column] for column in PATH_COLUMNS) for row in records))
    db.execute("DELETE FROM sqlite_sequence WHERE name='path_rules'")
    db.execute("INSERT INTO sqlite_sequence(name,seq) VALUES ('path_rules',?)", (mapping["sourceHighWater"],))


def read_typed_short_artifact(pins, source_sha, owner_map_sha):
    require(isinstance(pins, TypedShortInput) and native.matches(native.DIGEST, pins.old_origin_sha256)
            and native.matches(converter.OWNER, pins.legacy_bot_id) and int(pins.legacy_bot_id) <= converter.MAX_OWNER)
    root = private_path(pins.directory, directory=True)
    names = {typed_inventory.MANIFEST, typed_inventory.SEAL, typed_inventory.ROWS}
    require(set(os.listdir(root)) == names and all(private_path(root / name).stat().st_nlink == 1 for name in names))
    raw = read_pinned(root / typed_inventory.MANIFEST, 64 * 1024, pins.manifest_sha256)
    require(read_private(root / typed_inventory.SEAL, 65) == pins.manifest_sha256.encode("ascii") + b"\n")
    manifest = native.parsed(raw, 64 * 1024)
    require(raw == converter._json(manifest) + b"\n"
            and set(manifest) == {"version", "kind", "sourceSha256", "ownerMapSha256", "oldOriginSha256",
                                  "legacyBotId", "inventory", "files"}
            and native.integer(manifest["version"], 1, 1) and manifest["kind"] == "legacy-typed-subscription-short-inventory"
            and (manifest["sourceSha256"], manifest["ownerMapSha256"], manifest["oldOriginSha256"], manifest["legacyBotId"])
            == (source_sha, owner_map_sha, pins.old_origin_sha256, pins.legacy_bot_id))
    domain, entries = manifest["inventory"], manifest["files"]
    require(isinstance(domain, dict) and set(domain) == {"present", "rows"} and type(domain["present"]) is bool
            and native.integer(domain["rows"], 0, typed_inventory.MAX_SHORTS) and (domain["present"] or domain["rows"] == 0)
            and isinstance(entries, list) and len(entries) == 1)
    entry = entries[0]
    require(isinstance(entry, dict) and set(entry) == {"file", "bytes", "sha256"} and entry["file"] == typed_inventory.ROWS
            and native.integer(entry["bytes"], 0, typed_inventory.MAX_METADATA_BYTES))
    raw_rows = read_pinned(root / typed_inventory.ROWS, typed_inventory.MAX_METADATA_BYTES, entry["sha256"])
    require(len(raw_rows) == entry["bytes"])
    prior, rows = "", []
    for line in io.BytesIO(raw_rows):
        require(len(line) <= TYPED_SHORT_LINE_BYTES and line.endswith(b"\n") and len(rows) < domain["rows"])
        row = native.parsed(line[:-1], TYPED_SHORT_LINE_BYTES)
        require(set(row) == {"codeSha256", "legacyTable", "legacyId", "ownerId", "tokenSha256", "format", "createdAt"}
                and line == converter._json(row) + b"\n"
                and native.matches(native.DIGEST, row["codeSha256"]) and row["codeSha256"] > prior
                and row["legacyTable"] in (ACTIVE, "deleted_subs") and native.integer(row["legacyId"], 1)
                and native.matches(converter.OWNER, row["ownerId"]) and int(row["ownerId"]) <= converter.MAX_OWNER
                and native.matches(native.DIGEST, row["tokenSha256"]) and row["format"] in typed_inventory.FORMATS
                and native.integer(row["createdAt"], 1))
        rows.append(row)
        prior = row["codeSha256"]
    require(len(rows) == domain["rows"])
    return root, domain, rows


def load_typed_short_links(db, lineage_path, rows, bot_id):
    # Keep active and trash identities distinct even if their old IDs overlap.
    required = {(row["legacyTable"], row["legacyId"]) for row in rows}
    lineage = {}
    for entry in parse_lines(read_private(lineage_path, native.SQL_BYTES), TYPED_SHORT_LINE_BYTES):
        key = (entry["legacyTable"], entry["legacyId"])
        if key in required:
            require(key not in lineage)
            lineage[key] = entry["targetId"]
    require(set(lineage) == required)
    expected, counts = [], {"rows": len(rows), "activeRows": 0, "trashRows": 0}
    for row in rows:
        active = row["legacyTable"] == ACTIVE
        target_table = ACTIVE if active else TRASH
        target_id = lineage[(row["legacyTable"], row["legacyId"])]
        target = db.execute(f"SELECT owner_id,token FROM {target_table} WHERE id=?", (target_id,)).fetchone()
        require(target is not None and target[0] == row["ownerId"]
                and native.digest(target[1].encode("ascii")) == row["tokenSha256"])
        expected.append((row["codeSha256"], bot_id, target[0], target_id, row["tokenSha256"], row["format"], row["createdAt"], None))
        counts["activeRows" if active else "trashRows"] += 1
    db.executemany(f"INSERT INTO {TYPED_SHORTS} ({','.join(TYPED_SHORT_COLUMNS)}) VALUES (?,?,?,?,?,?,?,?)", expected)
    return expected, counts


def verify_typed_short_links(db, expected):
    actual = db.execute(f"SELECT {','.join(TYPED_SHORT_COLUMNS)} FROM {TYPED_SHORTS} ORDER BY code_sha256")
    require(all(row == target for row, target in zip_longest(actual, expected)))
    require(db.execute(f"""SELECT 1 FROM {TYPED_SHORTS} AS typed
        WHERE EXISTS (SELECT 1 FROM normal_short_links WHERE code_sha256=typed.code_sha256)
           OR EXISTS (SELECT 1 FROM aggregate_links WHERE code_sha256=typed.code_sha256) LIMIT 1""").fetchone() is None)


def load_external_short_links(db, rows, bot_id):
    # Imported 12-character links have no Telegram issuance receipt or derived nonce.
    expected = [(code, 12, bot_id, owner, None, None, None, target, created_at, None)
                for code, owner, target, created_at in rows]
    db.executemany(f"INSERT INTO {EXTERNAL_SHORTS} ({','.join(EXTERNAL_SHORT_COLUMNS)}) VALUES (?,?,?,?,?,?,?,?,?,?)", expected)
    return expected


def verify_external_short_links(db, expected):
    actual = db.execute(f"SELECT {','.join(EXTERNAL_SHORT_COLUMNS)} FROM {EXTERNAL_SHORTS} ORDER BY code_sha256")
    require(all(row == target for row, target in zip_longest(actual, expected)))


def db_summary(db, layout):
    return native.data_summary(layout, lambda table, definition: db.execute(
        "SELECT " + ",".join(native._identifier(name) for name, _ in definition["columns"])
        + " FROM " + native._identifier(table) + " ORDER BY " + ",".join(map(native._identifier, definition["primary"]))))


def write_sql(db, schema, sequence, path, *, path_sequence=None, include_empty_exports=False, extra_tables=None):
    # Only the reviewed DDL and fixed-column rows are emitted. SQLite quotes
    # values itself. A subsequent independent replay checks exact round-trip.
    size = 0
    with native.private_file(path) as output:
        def write(statement):
            nonlocal size
            data = (statement + ";\n").encode("utf-8")
            size += len(data)
            require(size <= native.SQL_BYTES)
            output.write(data)

        for obj in schema:
            if obj.name != "sqlite_sequence":
                write(obj.sql)
        tables = TABLE_COLUMNS if path_sequence is None else {**TABLE_COLUMNS, PATH_RULES: PATH_COLUMNS}
        if include_empty_exports:
            tables = {**tables, EMPTY_EXPORTS: EMPTY_EXPORT_COLUMNS}
        if extra_tables:
            tables = {**tables, **extra_tables}
        for table, columns in tables.items():
            fields = ",".join(native._identifier(column) for column in columns)
            literals = ",".join(f"quote({native._identifier(column)})" for column in columns)
            order = fields if extra_tables and table in extra_tables else columns[0]
            for row in db.execute(f"SELECT {literals} FROM {table} ORDER BY {order}"):
                write(f"INSERT INTO {table} ({fields}) VALUES (" + ",".join(row) + ")")
        write("DELETE FROM sqlite_sequence WHERE name='subscriptions'")
        if sequence:
            write(f"INSERT INTO sqlite_sequence (name,seq) VALUES ('subscriptions',{sequence})")
        if path_sequence is not None:
            write("DELETE FROM sqlite_sequence WHERE name='path_rules'")
            write(f"INSERT INTO sqlite_sequence (name,seq) VALUES ('path_rules',{path_sequence})")


def describe(path):
    size, digest = native.file_hash(path)
    return {"path": path.name, "bytes": size, "sha256": digest}


def build_candidate(conversion, worker, output, *, converter_manifest_sha, worker_manifest_sha, revision, applied_at,
                    profile=None, source_sqlite_sha=None, owner_map_sha=None, typed_short=None, mixed_short=None):
    try:
        include_mixed_shorts = profile == MIXED_SHORT_PROFILE
        include_typed_shorts = profile in (TYPED_SHORT_PROFILE, MIXED_SHORT_PROFILE)
        include_empty_exports = profile in (EMPTY_EXPORT_PROFILE, TYPED_SHORT_PROFILE, MIXED_SHORT_PROFILE)
        require(profile is None or include_empty_exports)
        require((typed_short is not None) == (profile == TYPED_SHORT_PROFILE)
                and (mixed_short is not None) == include_mixed_shorts)
        if include_empty_exports:
            require(native.matches(native.DIGEST, source_sqlite_sha) and native.matches(native.DIGEST, owner_map_sha))
        else:
            require(source_sqlite_sha is None and owner_map_sha is None)
        require(native.integer(applied_at, 1))
        conversion = private_path(conversion, directory=True)
        worker = private_path(worker, directory=True)
        output = converter._safe_path(Path(output), existing=False)
        require(not output.is_relative_to(conversion) and not output.is_relative_to(worker))
        typed_domain = None
        chain, build = worker_artifact(worker, revision, worker_manifest_sha)
        if include_mixed_shorts:
            from legacy_mixed_short_candidate import MixedShortError, MixedShortInput, read_mixed_shorts

            require(isinstance(mixed_short, MixedShortInput)
                    and all(not output.is_relative_to(private_path(path, directory=True))
                            for path in (mixed_short.namespace, mixed_short.oracle)))
            try:
                mixed = read_mixed_shorts(mixed_short, source_sha=source_sqlite_sha, owner_map_sha=owner_map_sha,
                                          build=build, worker_manifest_sha=worker_manifest_sha, working_parent=output.parent)
            except MixedShortError:
                raise PackageError(ERROR) from None
            typed_domain, typed_rows, legacy_bot_id = mixed.domain, mixed.typed_rows, mixed_short.legacy_bot_id
        elif include_typed_shorts:
            typed_root, typed_domain, typed_rows = read_typed_short_artifact(typed_short, source_sqlite_sha, owner_map_sha)
            require(not output.is_relative_to(typed_root))
            legacy_bot_id = typed_short.legacy_bot_id
        source, files = converter_artifact(conversion, converter_manifest_sha, typed_short_domain=typed_domain)
        if include_empty_exports:
            require(source["sourceSha256"] == source_sqlite_sha and source["ownerMapSha256"] == owner_map_sha
                    and len(chain) >= 26 and chain[25].name == EMPTY_EXPORT_MIGRATION
                    and chain[25].sha256 == EMPTY_EXPORT_MIGRATION_SHA256)
        if include_typed_shorts:
            require(len(chain) >= 29 and (chain[28].name, chain[28].sha256)
                    == (TYPED_SHORT_MIGRATION, TYPED_SHORT_MIGRATION_SHA256))
        if include_mixed_shorts:
            require((chain[18].name, chain[18].sha256) == (EXTERNAL_SHORT_MIGRATION, EXTERNAL_SHORT_MIGRATION_SHA256))
        extra_tables = {TYPED_SHORTS: TYPED_SHORT_COLUMNS} if include_typed_shorts else {}
        if include_mixed_shorts:
            extra_tables[EXTERNAL_SHORTS] = EXTERNAL_SHORT_COLUMNS
        path_mapping = source.get("pathIdMapping")
        if path_mapping is not None:
            require(len(chain) >= 10 and chain[9].name == "0010_path_rules.sql")
        schema = migrations._objects(chain, len(chain), managed=True)
        replay_source = SimpleNamespace(objects=schema, tables=sorted(obj.name for obj in schema if obj.type == "table"))
        ledger = [{"position": position, "name": item.name, "sha256": item.sha256, "mode": "applied", "applied_at": applied_at}
                  for position, item in enumerate(chain, 1)]
        sequence = source["trashIdMapping"]["targetSequenceHighWater"]
        output.mkdir(mode=0o700)
        sql = output / SQL
        with TemporaryDirectory(prefix=".candidate-scratch-", dir=output) as temporary:
            scratch = Path(temporary) / "candidate.sqlite"
            replay_sql = Path(temporary) / SQL
            with native.private_file(scratch):
                pass
            with closing(sqlite3.connect(scratch)) as db, db:
                db.execute("PRAGMA foreign_keys=ON")
                db.execute("PRAGMA trusted_schema=OFF")
                for obj in schema:
                    if obj.name != "sqlite_sequence":
                        db.execute(obj.sql)
                db.executemany("INSERT INTO subs_bot_schema_migrations(position,name,sha256,mode,applied_at) VALUES (?,?,?,?,?)",
                               (tuple(row[column] for column in TABLE_COLUMNS[migrations.LEDGER]) for row in ledger))
                with native.private_file(output / LINEAGE) as lineage:
                    counts = load_rows(db, conversion, source, files, lineage, include_empty_exports=include_empty_exports)
                if path_mapping is not None:
                    load_path_rules(db, conversion, source, files)
                if include_typed_shorts:
                    typed_expected, typed_counts = load_typed_short_links(db, output / LINEAGE, typed_rows, legacy_bot_id)
                if include_mixed_shorts:
                    external_expected = load_external_short_links(db, mixed.external_rows, legacy_bot_id)
                require(db.execute("""SELECT 1 FROM subscriptions AS active JOIN subscription_trash AS trash
                    ON active.id=trash.id OR active.token=trash.token LIMIT 1""").fetchone() is None)
                db.execute("DELETE FROM sqlite_sequence WHERE name='subscriptions'")
                if sequence:
                    db.execute("INSERT INTO sqlite_sequence(name,seq) VALUES ('subscriptions',?)", (sequence,))
                layout = native.table_layout(db, replay_source.tables)
                summary = db_summary(db, layout)
                write_sql(db, schema, sequence, replay_sql,
                          path_sequence=path_mapping["sourceHighWater"] if path_mapping is not None else None,
                          include_empty_exports=include_empty_exports,
                          extra_tables=extra_tables)

            def read_object(key):
                raw = expected_file(conversion, files, "objects/" + key, native.OBJECT_BYTES)
                return raw, {"custom": {}, "http": {}}

            def copy_object(key, _digest, body):
                relative = Path("objects") / key
                for parent in reversed(relative.parents):
                    if parent != Path("."):
                        (output / parent).mkdir(mode=0o700, exist_ok=True)
                with native.private_file(output / relative) as target:
                    target.write(body)

            replayed, restored_layout, restored_summary = native.open_export(replay_sql, replay_source)
            with closing(replayed):
                require(restored_layout == layout and restored_summary == summary)
                if include_empty_exports:
                    verify_empty_export_markers(replayed)
                if include_typed_shorts:
                    verify_typed_short_links(replayed, typed_expected)
                if include_mixed_shorts:
                    verify_external_short_links(replayed, external_expected)
                objects = native.object_references(replayed, read_object, copy_object)
            require({"objects/" + item["key"] for item in objects} == set(files) - metadata_files(source))
            replay_sql.rename(sql)
        report = {"version": 1, "scope": "fresh-unbound-d1-r2", "legacyDomains": "active-and-trash-only",
                  "schemaSha256": native._schema_digest(schema),
                  "dataSha256": summary["dataSha256"], "counts": counts, "objectCount": len(objects),
                  "objectBytes": sum(item["bytes"] for item in objects),
                  "sourceHighWater": source["trashIdMapping"]["sourceHighWater"], "targetSequenceHighWater": sequence,
                  "generationZeroHttp": "not-validated", "formatCompatibility": "not-validated"}
        if path_mapping is not None:
            report.update(version=2, legacyDomains="active-trash-and-path-rules",
                          pathIdMapping={**path_mapping, "targetSequenceHighWater": path_mapping["sourceHighWater"]})
        if include_empty_exports:
            active, trash = counts["generationZeroActiveRows"], counts["generationZeroTrashRows"]
            require(summary["tableCounts"][EMPTY_EXPORTS] == active + trash)
            domains = "active-trash-and-empty-exports" if path_mapping is None else "active-trash-path-rules-and-empty-exports"
            report.update(version=3, legacyDomains=domains, emptyExportMarkers={
                "activeRows": active, "trashRows": trash,
                "migrationSha256": EMPTY_EXPORT_MIGRATION_SHA256, "tableSha256": summary["tableSha256"][EMPTY_EXPORTS],
            })
        source_pin = {"sqliteSha256": source["sourceSha256"], "ownerMapSha256": source["ownerMapSha256"],
                      "converterManifestSha256": converter_manifest_sha}
        if include_typed_shorts:
            require(summary["tableCounts"][TYPED_SHORTS] == typed_counts["rows"])
            report.update(version=4, legacyDomains=report["legacyDomains"] + "-and-typed-single-shorts",
                          typedShortLinks={**typed_counts, "migrationSha256": TYPED_SHORT_MIGRATION_SHA256,
                                           "tableSha256": summary["tableSha256"][TYPED_SHORTS]},
                          shortLinkCompatibility="not-validated")
            if not include_mixed_shorts:
                source_pin.update(typedShortInventoryManifestSha256=typed_short.manifest_sha256,
                                  oldOriginSha256=typed_short.old_origin_sha256, legacyBotId=legacy_bot_id)
        if include_mixed_shorts:
            external_count = len(external_expected)
            require(summary["tableCounts"][EXTERNAL_SHORTS] == external_count
                    and external_count + typed_counts["rows"] == typed_domain["rows"])
            report.update(version=5, legacyDomains=report["legacyDomains"] + "-and-external-shorts",
                          externalShortLinks={"rows": external_count, "migrationSha256": EXTERNAL_SHORT_MIGRATION_SHA256,
                                              "tableSha256": summary["tableSha256"][EXTERNAL_SHORTS]},
                          shortLinkCompatibility={"typed": "not-validated", "external": "offline-equivalent"})
            source_pin.update(mixed.proof)
        manifest = {**report, "source": source_pin, "workerArtifact": build,
                    "ledger": ledger, "layout": layout, "summary": summary, "objects": objects,
                    "lineage": describe(output / LINEAGE), "sql": {**describe(sql), "md5": native.file_hash(sql, "md5")[1]}}
        body = native.canonical(manifest)
        require(len(body) <= native.MANIFEST_BYTES)
        with native.private_file(output / MANIFEST) as file:
            file.write(body)
        manifest_sha = sha256(body).hexdigest()
        with native.private_file(output / MARKER) as file:
            file.write(manifest_sha.encode("ascii") + b"\n")
        return {**report, "manifestSha256": manifest_sha}
    except (PackageError, converter.ConversionError, migrations.MigrationError, native.RehearsalError, artifact.ArtifactError,
            OSError, sqlite3.Error, ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError):
        raise PackageError(ERROR) from None


def main(args=None):
    args = sys.argv[1:] if args is None else args
    if (len(args) not in (7, 10, 11, 14) or not re.fullmatch(r"[1-9][0-9]{0,15}", args[6])
            or (len(args) == 10 and args[7] != EMPTY_EXPORT_PROFILE) or (len(args) == 14 and args[7] != TYPED_SHORT_PROFILE)
            or (len(args) == 11 and args[7] != MIXED_SHORT_PROFILE)):
        print("Usage: legacy_restore_package.py CONVERTER_DIR WORKER_ARTIFACT_DIR OUTPUT_DIR CONVERTER_MANIFEST_SHA WORKER_MANIFEST_SHA REVISION APPLIED_AT"
              " [legacy-empty-v3 SOURCE_SQLITE_SHA OWNER_MAP_SHA | legacy-typed-short-v4 SOURCE_SQLITE_SHA OWNER_MAP_SHA "
              "TYPED_SHORT_INVENTORY TYPED_SHORT_MANIFEST_SHA OLD_ORIGIN_SHA LEGACY_BOT_ID | "
              "legacy-mixed-short-v5 SOURCE_SQLITE_SHA OWNER_MAP_SHA PRIVATE_INPUT_JSON]",
              file=sys.stderr)
        return 2
    try:
        profile, source_sqlite_sha, owner_map_sha = args[7:10] if len(args) >= 10 else (None, None, None)
        typed_short = TypedShortInput(Path(args[10]), *args[11:]) if len(args) == 14 else None
        mixed_short = None
        if len(args) == 11:
            from legacy_mixed_short_candidate import MixedShortError, read_mixed_short_input

            try:
                mixed_short = read_mixed_short_input(Path(args[10]))
            except MixedShortError:
                raise PackageError(ERROR) from None
        result = build_candidate(*map(Path, args[:3]), converter_manifest_sha=args[3], worker_manifest_sha=args[4],
                                 revision=args[5], applied_at=int(args[6]), profile=profile,
                                 source_sqlite_sha=source_sqlite_sha, owner_map_sha=owner_map_sha, typed_short=typed_short,
                                 mixed_short=mixed_short)
        print(json.dumps(result, ensure_ascii=True, sort_keys=True))
        return 0
    except PackageError as error:
        print(str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
