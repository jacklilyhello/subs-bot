"""Build an unapplied, private D1 SQL and R2 package on a hosted runner."""

from contextlib import closing
from hashlib import sha256
import io
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
import native_restore_rehearsal as native
import prepare_isolation_artifact as artifact


ACTIVE = "subscriptions"
TRASH = "subscription_trash"
LIFECYCLE = "subscription_lifecycle"
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
    require(len(chain) >= 3 and chain[2].name == "0003_subscription_lifecycle.sql")
    identity = {key: manifest[key] for key in ("revision", "runId", "runAttempt", "bundleSha256", "compatibilityDate", "migrations")}
    return chain, {**identity, "manifestSha256": manifest_sha}


def converter_artifact(root, manifest_sha):
    raw = read_pinned(root / MANIFEST, 64 * 1024, manifest_sha)
    manifest = converter.verify_bundle(root, require_complete=True)
    require(read_pinned(root / MANIFEST, 64 * 1024, manifest_sha) == raw)
    require(read_private(root / MARKER, 65) == manifest_sha.encode("ascii") + b"\n")
    domains = manifest["domains"]
    require(all(type(item["rows"]) is int and item["rows"] >= 0 for item in domains.values())
            and all(domains[name]["rows"] == 0 for name in converter.DOMAINS if name not in (*converter.HANDLED, "meta"))
            and domains["meta"]["unhandledRows"] == 0 and domains["meta"]["rows"] == domains["meta"]["consumedRows"])
    file_index = manifest["files"]
    require(native.integer(file_index["count"], 2, native.MAX_OBJECTS + 2))
    index = read_pinned(root / "files.ndjson", (native.MAX_OBJECTS + 2) * converter.MAX_INDEX_LINE_BYTES, file_index["sha256"])
    require(len(index) == file_index["bytes"])
    descriptors = {}
    for item in parse_lines(index, converter.MAX_INDEX_LINE_BYTES):
        require(item["path"] not in descriptors)
        descriptors[item["path"]] = item
    require(len(descriptors) == file_index["count"] and {"active.ndjson", "trash.ndjson"} <= descriptors.keys())
    mapping = manifest["trashIdMapping"]
    high = mapping["sourceHighWater"]
    require(mapping["kind"] == "source-high-water-plus-ordinal" and native.integer(high)
            and native.integer(mapping["targetSequenceHighWater"], high)
            and mapping["targetSequenceHighWater"] == high + domains["deleted_subs"]["rows"])
    return manifest, descriptors


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


def load_rows(db, source_root, source, descriptors, lineage):
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


def db_summary(db, layout):
    return native.data_summary(layout, lambda table, definition: db.execute(
        "SELECT " + ",".join(native._identifier(name) for name, _ in definition["columns"])
        + " FROM " + native._identifier(table) + " ORDER BY " + ",".join(map(native._identifier, definition["primary"]))))


def write_sql(db, schema, sequence, path):
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
        for table, columns in TABLE_COLUMNS.items():
            fields = ",".join(native._identifier(column) for column in columns)
            literals = ",".join(f"quote({native._identifier(column)})" for column in columns)
            for row in db.execute(f"SELECT {literals} FROM {table} ORDER BY {columns[0]}"):
                write(f"INSERT INTO {table} ({fields}) VALUES (" + ",".join(row) + ")")
        write("DELETE FROM sqlite_sequence WHERE name='subscriptions'")
        if sequence:
            write(f"INSERT INTO sqlite_sequence (name,seq) VALUES ('subscriptions',{sequence})")


def describe(path):
    size, digest = native.file_hash(path)
    return {"path": path.name, "bytes": size, "sha256": digest}


def build_candidate(conversion, worker, output, *, converter_manifest_sha, worker_manifest_sha, revision, applied_at):
    try:
        require(native.integer(applied_at, 1))
        conversion = private_path(conversion, directory=True)
        worker = private_path(worker, directory=True)
        output = converter._safe_path(Path(output), existing=False)
        require(not output.is_relative_to(conversion) and not output.is_relative_to(worker))
        source, files = converter_artifact(conversion, converter_manifest_sha)
        chain, build = worker_artifact(worker, revision, worker_manifest_sha)
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
                    counts = load_rows(db, conversion, source, files, lineage)
                require(db.execute("""SELECT 1 FROM subscriptions AS active JOIN subscription_trash AS trash
                    ON active.id=trash.id OR active.token=trash.token LIMIT 1""").fetchone() is None)
                db.execute("DELETE FROM sqlite_sequence WHERE name='subscriptions'")
                if sequence:
                    db.execute("INSERT INTO sqlite_sequence(name,seq) VALUES ('subscriptions',?)", (sequence,))
                layout = native.table_layout(db, replay_source.tables)
                summary = db_summary(db, layout)
                write_sql(db, schema, sequence, replay_sql)

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
                objects = native.object_references(replayed, read_object, copy_object)
            require({"objects/" + item["key"] for item in objects} == set(files) - {"active.ndjson", "trash.ndjson"})
            replay_sql.rename(sql)
        report = {"version": 1, "scope": "fresh-unbound-d1-r2", "legacyDomains": "active-and-trash-only",
                  "schemaSha256": native._schema_digest(schema),
                  "dataSha256": summary["dataSha256"], "counts": counts, "objectCount": len(objects),
                  "objectBytes": sum(item["bytes"] for item in objects),
                  "sourceHighWater": source["trashIdMapping"]["sourceHighWater"], "targetSequenceHighWater": sequence,
                  "generationZeroHttp": "not-validated", "formatCompatibility": "not-validated"}
        manifest = {**report, "source": {"sqliteSha256": source["sourceSha256"], "ownerMapSha256": source["ownerMapSha256"],
                    "converterManifestSha256": converter_manifest_sha}, "workerArtifact": build,
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
    if len(args) != 7 or not re.fullmatch(r"[1-9][0-9]{0,15}", args[6]):
        print("Usage: legacy_restore_package.py CONVERTER_DIR WORKER_ARTIFACT_DIR OUTPUT_DIR CONVERTER_MANIFEST_SHA WORKER_MANIFEST_SHA REVISION APPLIED_AT",
              file=sys.stderr)
        return 2
    try:
        result = build_candidate(*map(Path, args[:3]), converter_manifest_sha=args[3], worker_manifest_sha=args[4],
                                 revision=args[5], applied_at=int(args[6]))
        print(json.dumps(result, ensure_ascii=True, sort_keys=True))
        return 0
    except PackageError as error:
        print(str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
