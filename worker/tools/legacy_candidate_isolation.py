"""Build and apply only the reviewed synthetic legacy fixture on hosted runners."""

from contextlib import closing
from dataclasses import asdict
import io
import json
import os
from pathlib import Path
from platform import python_version
import sqlite3
import sys
import tempfile
from types import SimpleNamespace
from uuid import NAMESPACE_URL, uuid5
from zipfile import ZipFile

import d1_migrations as migrations
import legacy_mixed_short_candidate as mixed_shorts
import legacy_private_share_fixture as share_fixture
import legacy_restore_package as package
import legacy_short_namespace_inventory as short_namespace
import legacy_snapshot_convert as converter
import native_restore_rehearsal as native
import prepare_isolation_artifact as artifact
from cloudflare_isolation import CloudflareClient


PROFILE = native.LEGACY_CANDIDATE_PROFILE
PATH_PROFILE = native.LEGACY_PATH_CANDIDATE_PROFILE
EMPTY_PROFILE = native.LEGACY_EMPTY_CANDIDATE_PROFILE
SHARE_PROFILE = native.LEGACY_PRIVATE_SHARE_CANDIDATE_PROFILE
TYPED_PROFILE = native.LEGACY_TYPED_SHORT_CANDIDATE_PROFILE
MIXED_PROFILE = native.LEGACY_MIXED_SHORT_CANDIDATE_PROFILE
SELECTED_PROFILE = native.LEGACY_SELECTED_AGGREGATE_CANDIDATE_PROFILE
TEMP_PROFILE = native.LEGACY_TEMP_CANDIDATE_PROFILE
ARTIFACT_PREFIX = "subs-bot-legacy-candidate"
ARTIFACT_PREFIXES = {PROFILE: ARTIFACT_PREFIX, PATH_PROFILE: "subs-bot-legacy-path-candidate",
                     EMPTY_PROFILE: "subs-bot-legacy-empty-candidate", SHARE_PROFILE: "subs-bot-legacy-private-share-candidate",
                     TYPED_PROFILE: "subs-bot-legacy-typed-short-candidate", MIXED_PROFILE: "subs-bot-legacy-mixed-short-candidate",
                     SELECTED_PROFILE: "subs-bot-legacy-selected-aggregate-candidate",
                     TEMP_PROFILE: "subs-bot-legacy-temp-node-candidate"}
CANDIDATE_DIRECTORY = "subs-bot-verified-legacy-candidate"
PROVENANCE = "legacy-candidate-provenance.json"
EVIDENCE = "legacy-candidate-evidence.json"
ERROR = "The synthetic legacy candidate operation could not be confirmed safely."
ACTIONS = {"verify", "prepare", "create-restore-db", "create-restore-bucket", "pin-resource",
           "restore-objects", "start-import", "verify-restore"}
FIXTURE_CREATED = 1_700_000_000
FIXTURE_UPDATED = 1_700_001_000
APPLIED_AT = 1_700_002_000
HIGH_WATER = 70
TARGET_SEQUENCE = 71
EMPTY_TARGET_SEQUENCE = 72
PATH_SEQUENCE = 120
SQL_LIMIT = 128 * 1024
OBJECT_LIMIT = 2048
LINEAGE_LIMIT = 4096
OWNER_MAP = {"-100123": "456"}
FIXTURES = (
    ("subscriptions", 2, 2, 123, "active", "legacy-synthetic-active-02", (
        {"name": "synthetic raw", "share": "ss://YWVzLTEyOC1nY206Zml4dHVyZQ@192.0.2.1:443#synthetic"},
        {"name": "synthetic structured", "type": "ss", "server": "192.0.2.2", "port": 443,
         "cipher": "aes-128-gcm", "password": "synthetic"},
    )),
    ("subscriptions", 5, 5, 123, "empty", "legacy-synthetic-empty-05", ()),
    ("deleted_subs", 2, TARGET_SEQUENCE, -100123, "trash", "legacy-synthetic-trash-02", (
        {"name": "synthetic trash", "share": "ss://YWVzLTEyOC1nY206Zml4dHVyZQ@192.0.2.3:443#synthetic"},
    )),
)
EMPTY_TRASH_FIXTURE = ("deleted_subs", 4, EMPTY_TARGET_SEQUENCE, -100123, "empty-trash", "legacy-synthetic-empty-trash-04", ())
PATH_FIXTURES = (
    (5, -100123, "  HK\t", "  香港 '优先'  "),
    (12, -100123, "hk", "same owner and folded keyword"),
    (29, 456, " Route 日 ", "  第二条\t路径  "),
    (41, 123, "hk", "separate owner"),
)
COUNTS = {"activeRows": 2, "trashRows": 1, "generationZeroActiveRows": 1,
          "generationZeroTrashRows": 0, "nodeCount": 3, "redactedErrorRows": 1}
EMPTY_COUNTS = {**COUNTS, "trashRows": 2, "generationZeroTrashRows": 1}
TYPED_ORIGIN = "https://legacy-typed-shorts.example.invalid"
TYPED_BOT = "9000000000000199"
TYPED_INVENTORY = "typed-shorts"
TYPED_LINK_FIXTURES = (
    ("TypedAct0001", "active", ""),
    ("TypedEmp0002", "empty", "sing-box"),
    ("TypedRec0003", "trash", "v2ray"),
    ("TypedTmp0004", "empty-trash", "qx"),
)
TYPED_COUNTS = {"rows": 4, "activeRows": 2, "trashRows": 2}
EXTERNAL_LINK_FIXTURES = (
    ("MixedExt0001", 123, "https://example.org/route?value=synthetic-secret&mode=exact#keep"),
    ("MixedExt0002", -100123, "http://example.net/legacy/path?mode=original#keep"),
)
MIXED_ORACLE = "oracle"
MIXED_YARL = "1.20.0"
MIXED_COMPATIBILITY = {"typed": "not-validated", "external": "offline-equivalent"}
MIXED_ORACLE_LIMITS = {f"{MIXED_ORACLE}/{package.MANIFEST}": mixed_shorts.MANIFEST_BYTES,
                       f"{MIXED_ORACLE}/{package.MARKER}": 65,
                       f"{MIXED_ORACLE}/{mixed_shorts.ORACLE_ROWS}": 4096}
MANIFEST_FIELDS = {"version", "scope", "legacyDomains", "schemaSha256", "dataSha256", "counts", "objectCount", "objectBytes",
                   "sourceHighWater", "targetSequenceHighWater", "generationZeroHttp", "formatCompatibility", "source",
                   "workerArtifact", "ledger", "layout", "summary", "objects", "lineage", "sql"}


def require(condition):
    native.require(condition, ERROR)


def compact(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def put(path, body):
    with native.private_file(path) as file:
        file.write(body)


def fixture_source(label):
    return "https://legacy-candidate.invalid/" + label


def candidate_directory(profile):
    require(profile in ARTIFACT_PREFIXES)
    return CANDIDATE_DIRECTORY if profile == PROFILE else "subs-bot-verified-" + ARTIFACT_PREFIXES[profile].removeprefix("subs-bot-")


def candidate_version(profile):
    require(profile in ARTIFACT_PREFIXES)
    return {PROFILE: 1, PATH_PROFILE: 2, EMPTY_PROFILE: 3, SHARE_PROFILE: 1, TYPED_PROFILE: 4,
            MIXED_PROFILE: 5, SELECTED_PROFILE: 6, TEMP_PROFILE: 7}[profile]


def path_mapping():
    return {"kind": "identity", "rows": len(PATH_FIXTURES), "sourceHighWater": PATH_SEQUENCE, "targetSequenceHighWater": PATH_SEQUENCE}


def fixture_rows(profile):
    return (*FIXTURES, EMPTY_TRASH_FIXTURE) if profile in (EMPTY_PROFILE, TYPED_PROFILE, MIXED_PROFILE) else FIXTURES


def typed_fixture_links():
    by_label = {row[4]: row for row in fixture_rows(TYPED_PROFILE)}
    for index, (code, label, format_name) in enumerate(TYPED_LINK_FIXTURES):
        _, _, target_id, owner, _, token, _ = by_label[label]
        yield code, owner, target_id, token, format_name, FIXTURE_CREATED + index


def external_fixture_links():
    for index, (code, owner, target) in enumerate(EXTERNAL_LINK_FIXTURES, len(TYPED_LINK_FIXTURES)):
        yield code, owner, target, FIXTURE_CREATED + index


def make_synthetic_source(path, profile=PROFILE):
    version = candidate_version(profile)
    put(path, b"")
    with closing(sqlite3.connect(path)) as db, db:
        for table, time_field in (("subscriptions", "updated_at"), ("deleted_subs", "deleted_at")):
            unique_token = " UNIQUE" if profile in (TYPED_PROFILE, MIXED_PROFILE) and table == "subscriptions" else ""
            db.execute(f"""CREATE TABLE {table} (id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,name TEXT NOT NULL,url TEXT NOT NULL,token TEXT NOT NULL{unique_token},
                expire_at INTEGER,traffic_used REAL,traffic_total REAL,nodes_json TEXT NOT NULL,
                node_count INTEGER NOT NULL,last_error TEXT,created_at INTEGER NOT NULL,{time_field} INTEGER NOT NULL)""")
        for table, legacy_id, _, owner, label, token, nodes in fixture_rows(profile):
            active = label == "active"
            db.execute(f"INSERT INTO {table} VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (legacy_id, owner, "Synthetic " + label, fixture_source(label), token, None,
                 1.25 if active else None, 9.75 if active else None, compact(nodes).decode("utf-8"), len(nodes),
                 "synthetic historical failure" if active else None, FIXTURE_CREATED, FIXTURE_UPDATED))
        db.execute("UPDATE sqlite_sequence SET seq=50 WHERE name='subscriptions'")
        db.execute("UPDATE sqlite_sequence SET seq=? WHERE name='deleted_subs'", (HIGH_WATER,))
        if version >= 2:
            db.execute("""CREATE TABLE path_maps (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
                node_name TEXT NOT NULL, remark TEXT NOT NULL DEFAULT '', UNIQUE(user_id,node_name))""")
            db.executemany("INSERT INTO path_maps VALUES (?,?,?,?)", PATH_FIXTURES)
            db.execute("INSERT INTO path_maps VALUES (?,123,'deleted rule','synthetic')", (PATH_SEQUENCE,))
            db.execute("DELETE FROM path_maps WHERE id=?", (PATH_SEQUENCE,))
        if profile in (TYPED_PROFILE, MIXED_PROFILE):
            db.execute("""CREATE TABLE short_links (
                code TEXT PRIMARY KEY,user_id INTEGER NOT NULL,target_url TEXT NOT NULL,created_at INTEGER NOT NULL)""")
            db.executemany("INSERT INTO short_links VALUES (?,?,?,?)", (
                (code, owner, f"{TYPED_ORIGIN}/sub/{token}" + (f"/{format_name}" if format_name else ""), created)
                for code, owner, _, token, format_name, created in typed_fixture_links()))
        if profile == MIXED_PROFILE:
            db.executemany("INSERT INTO short_links VALUES (?,?,?,?)", external_fixture_links())


def convert_synthetic_source(root, profile):
    source, conversion = root / "synthetic.sqlite", root / "conversion"
    make_synthetic_source(source, profile)
    converter.convert_backup(source, conversion, owner_map=OWNER_MAP)
    pins = {"sqliteSha256": native.file_hash(source)[1], "ownerMapSha256": native.digest(native.canonical(OWNER_MAP)),
            "converterManifestSha256": native.file_hash(conversion / package.MANIFEST)[1]}
    if profile == TYPED_PROFILE:
        inventory = root / TYPED_INVENTORY
        package.typed_inventory.seal_inventory(source, inventory, source_sha256=pins["sqliteSha256"], owner_map=OWNER_MAP,
            owner_map_sha256=pins["ownerMapSha256"], old_origin=TYPED_ORIGIN, legacy_bot_id=TYPED_BOT)
        pins.update(typedShortInventoryManifestSha256=native.file_hash(inventory / package.typed_inventory.MANIFEST)[1],
                    oldOriginSha256=native.digest(TYPED_ORIGIN.encode("ascii")), legacyBotId=TYPED_BOT)
    return conversion, pins


def _build_mixed_candidate(worker, output, worker_pin, scratch, oracle, *, produce_oracle=False):
    conversion, pins = convert_synthetic_source(scratch, MIXED_PROFILE)
    source, owners, namespace = (scratch / name for name in ("synthetic.sqlite", "owners.json", "namespace"))
    put(owners, native.canonical(OWNER_MAP))
    short_namespace.seal_inventory(source, namespace, source_sha256=pins["sqliteSha256"], owner_map=OWNER_MAP,
                                  owner_map_sha256=pins["ownerMapSha256"], old_origin=TYPED_ORIGIN, legacy_bot_id=TYPED_BOT)
    namespace_sha = native.file_hash(namespace / short_namespace.MANIFEST)[1]
    if produce_oracle:
        # This branch is used by Worker CI in the pinned, network-isolated environment.
        from legacy_short_redirect_oracle import seal_oracle

        seal_oracle({"backup": str(source), "ownerMap": str(owners), "inventory": str(namespace),
                     "bundle": str(worker), "output": str(oracle), "sourceSha256": pins["sqliteSha256"],
                     "ownerMapSha256": pins["ownerMapSha256"], "oldOrigin": TYPED_ORIGIN, "legacyBotId": TYPED_BOT,
                     "inventorySha256": namespace_sha, "workerManifestSha256": worker_pin["manifestSha256"],
                     "revision": worker_pin["revision"], "pythonVersion": python_version(), "yarlVersion": MIXED_YARL})
    oracle_sha = native.digest(package.read_private(oracle / package.MANIFEST, mixed_shorts.MANIFEST_BYTES))
    sidecar = mixed_shorts.MixedShortInput(source, owners, TYPED_ORIGIN, TYPED_BOT, namespace, namespace_sha,
                                          oracle, oracle_sha, python_version(), MIXED_YARL)
    report = package.build_candidate(conversion, worker, output, converter_manifest_sha=pins["converterManifestSha256"],
                                     worker_manifest_sha=worker_pin["manifestSha256"], revision=worker_pin["revision"],
                                     applied_at=APPLIED_AT, profile=package.MIXED_SHORT_PROFILE,
                                     source_sqlite_sha=pins["sqliteSha256"], owner_map_sha=pins["ownerMapSha256"],
                                     mixed_short=sidecar)
    require(report["version"] == 5 and report["counts"] == EMPTY_COUNTS and report["objectCount"] == 4
            and report["pathIdMapping"] == path_mapping() and report["shortLinkCompatibility"] == MIXED_COMPATIBILITY
            and all(report["typedShortLinks"][key] == value for key, value in TYPED_COUNTS.items())
            and report["externalShortLinks"]["rows"] == len(EXTERNAL_LINK_FIXTURES))
    return report


def build_synthetic_candidate(worker, output, revision, run_id, attempt, *, profile=PROFILE):
    require(profile not in (SELECTED_PROFILE, TEMP_PROFILE))
    version = candidate_version(profile)
    worker_sha = native.digest(package.read_private(worker / "isolation.json", artifact._MAX_JSON))
    _, worker_pin = package.worker_artifact(worker, revision, worker_sha)
    require((worker_pin["runId"], worker_pin["runAttempt"]) == (run_id, attempt))
    if profile == SHARE_PROFILE:
        return share_fixture.build(worker, output, worker_pin, applied_at=APPLIED_AT)
    if profile == MIXED_PROFILE:
        output = converter._safe_path(output, existing=False)
        with tempfile.TemporaryDirectory(prefix="legacy-mixed-", dir=output.parent) as temporary:
            scratch = Path(temporary)
            staged, oracle = scratch / "candidate", scratch / MIXED_ORACLE
            report = _build_mixed_candidate(worker, staged, worker_pin, scratch, oracle, produce_oracle=True)
            oracle.rename(staged / MIXED_ORACLE)
            staged.rename(converter._safe_path(output, existing=False))
        return report
    with tempfile.TemporaryDirectory(prefix="legacy-synthetic-", dir=output.parent) as temporary:
        conversion, pins = convert_synthetic_source(Path(temporary), profile)
        options = {} if version < 3 else {"profile": package.EMPTY_EXPORT_PROFILE, "source_sqlite_sha": pins["sqliteSha256"],
                                          "owner_map_sha": pins["ownerMapSha256"]}
        if profile == TYPED_PROFILE:
            options.update(profile=package.TYPED_SHORT_PROFILE,
                           typed_short=package.TypedShortInput(conversion.parent / TYPED_INVENTORY,
                               pins["typedShortInventoryManifestSha256"], pins["oldOriginSha256"], pins["legacyBotId"]))
        report = package.build_candidate(conversion, worker, output, converter_manifest_sha=pins["converterManifestSha256"],
                                         worker_manifest_sha=worker_sha, revision=revision, applied_at=APPLIED_AT, **options)
    require(report["counts"] == (EMPTY_COUNTS if version >= 3 else COUNTS)
            and report["objectCount"] == 4 and report["version"] == version)
    if version >= 2:
        require(report["pathIdMapping"] == path_mapping())
    if profile == TYPED_PROFILE:
        require(all(report["typedShortLinks"][key] == value for key, value in TYPED_COUNTS.items()))
    return report


def package_files(document, *, profile=PROFILE):
    if profile == SELECTED_PROFILE:
        from legacy_selected_native_candidate import selected_candidate_files

        return selected_candidate_files(document)
    if profile == TEMP_PROFILE:
        from legacy_temp_native_candidate import temp_candidate_files

        return temp_candidate_files(document)
    files = {package.MANIFEST, package.MARKER, package.SQL, package.LINEAGE}
    objects = document.get("objects")
    require(isinstance(objects, list) and len(objects) == 4)
    for entry in objects:
        require(isinstance(entry, dict) and set(entry) == {"key", "bytes", "sha256", "metadata"}
                and native.matches(native.KEY, entry["key"]) and entry["key"].startswith("subscriptions/")
                and native.integer(entry["bytes"], 1, OBJECT_LIMIT) and native.matches(native.DIGEST, entry["sha256"])
                and entry["metadata"] == {"custom": {}, "http": {}})
        files.add("objects/" + entry["key"])
    require(len(files) == 8)
    if profile == MIXED_PROFILE:
        files.update(MIXED_ORACLE_LIMITS)
    return files


def unpack_candidate(body, archive_sha, destination, *, profile=PROFILE):
    require(len(body) <= 512 * 1024 and native.digest(body) == archive_sha)
    with ZipFile(io.BytesIO(body)) as archive:
        members = artifact._zip_members(archive)
        manifest = members.get(package.MANIFEST)
        require(manifest is not None and 0 < manifest.file_size <= native.MANIFEST_BYTES)
        document = native.parsed(archive.read(manifest), native.MANIFEST_BYTES)
        require(type(document.get("version")) is int and document["version"] == candidate_version(profile))
        limits = {package.MANIFEST: native.MANIFEST_BYTES, package.MARKER: 65,
                  package.SQL: SQL_LIMIT, package.LINEAGE: LINEAGE_LIMIT}
        if profile == MIXED_PROFILE:
            limits.update(MIXED_ORACLE_LIMITS)
        if profile == SELECTED_PROFILE:
            from legacy_selected_native_candidate import PACKAGE_LIMITS

            limits = PACKAGE_LIMITS
        if profile == TEMP_PROFILE:
            from legacy_temp_native_candidate import PACKAGE_LIMITS

            limits = PACKAGE_LIMITS
        expected_files = share_fixture.files(document, OBJECT_LIMIT) if profile == SHARE_PROFILE else package_files(document, profile=profile)
        require(set(members) == expected_files)
        require(all(0 < entry.file_size <= limits.get(name, OBJECT_LIMIT) for name, entry in members.items()))
        destination.mkdir(mode=0o700)
        for name, entry in members.items():
            path = destination / name
            for parent in reversed(path.relative_to(destination).parents):
                (destination / parent).mkdir(mode=0o700, exist_ok=True)
            put(path, archive.read(entry))


def fixture_contents(db, document, profile=PROFILE):
    """Check every synthetic value, including the original URL tokens and raw nodes."""
    expected_objects, expected_rows, lineage = {}, {package.ACTIVE: [], package.TRASH: []}, []
    source_sha = document["source"]["sqliteSha256"]
    for legacy_table, legacy_id, target_id, owner, label, token, nodes in fixture_rows(profile):
        is_trash = legacy_table == "deleted_subs"
        table = package.TRASH if is_trash else package.ACTIVE
        original = str(owner)
        mapped = OWNER_MAP.get(original, original)
        snapshot = manifest_sha = None
        if nodes:
            snapshot = str(uuid5(NAMESPACE_URL, f"subs-bot-legacy-snapshot-v1:{source_sha}:{legacy_table}:{legacy_id}:{target_id}"))
            prefix = f"subscriptions/{target_id}/{snapshot}/"
            chunk = b"".join(compact(node) + b"\n" for node in nodes)
            manifest = compact({"version": 1, "chunks": [{"bytes": len(chunk), "sha256": native.digest(chunk), "count": len(nodes)}]})
            expected_objects.update({prefix + "0.ndjson": chunk, prefix + "manifest.json": manifest})
            manifest_sha = native.digest(manifest)
        active = label == "active"
        row = (target_id, mapped, "Synthetic " + label, fixture_source(label), token, None,
               1.25 if active else None, 9.75 if active else None, "legacy-refresh-failed" if active else None,
               FIXTURE_CREATED, FIXTURE_UPDATED, int(bool(nodes)), snapshot, manifest_sha, len(nodes))
        expected_rows[table].append((*row, FIXTURE_UPDATED, 1) if is_trash else row)
        lineage.append({"legacyTable": legacy_table, "legacyId": legacy_id, "targetId": target_id,
                        "lifecycleRevision": int(is_trash), "storedNodeCount": len(nodes)})
    for table, rows in expected_rows.items():
        columns = ",".join(package.TABLE_COLUMNS[table])
        require(db.execute(f"SELECT {columns} FROM {table} ORDER BY id").fetchall() == rows)
    trash_ids = [row[0] for row in expected_rows[package.TRASH]]
    require(db.execute("SELECT subscription_id,revision FROM subscription_lifecycle ORDER BY subscription_id").fetchall()
            == [(target_id, 1) for target_id in trash_ids])
    sequences = [("subscriptions", trash_ids[-1])]
    if profile in (PATH_PROFILE, EMPTY_PROFILE, TYPED_PROFILE, MIXED_PROFILE):
        expected_paths = [(row_id, OWNER_MAP.get(str(owner), str(owner)), keyword, remark) for row_id, owner, keyword, remark in PATH_FIXTURES]
        require(db.execute("SELECT id,owner_id,keyword,remark FROM path_rules ORDER BY id").fetchall() == expected_paths)
        sequences.insert(0, ("path_rules", PATH_SEQUENCE))
    require(db.execute("SELECT name,seq FROM sqlite_sequence ORDER BY name").fetchall() == sequences)
    return expected_objects, b"".join(native.canonical(row) + b"\n" for row in lineage)


class Candidate:
    def __init__(self, root, source, worker_pin, scratch, *, profile=PROFILE, worker=None):
        version = candidate_version(profile)
        has_paths, has_empty, has_typed = version >= 2, version >= 3, profile in (TYPED_PROFILE, MIXED_PROFILE)
        has_mixed = profile == MIXED_PROFILE
        counts = EMPTY_COUNTS if has_empty else COUNTS
        sequence = EMPTY_TARGET_SEQUENCE if has_empty else TARGET_SEQUENCE
        self.profile = profile
        self.root = package.private_path(root, directory=True)
        raw = package.read_private(root / package.MANIFEST, native.MANIFEST_BYTES)
        self.manifest_sha = native.digest(raw)
        require(package.read_private(root / package.MARKER, 65) == self.manifest_sha.encode("ascii") + b"\n")
        document = native.parsed(raw, native.MANIFEST_BYTES)
        fields = MANIFEST_FIELDS | {"pathIdMapping"} if has_paths else MANIFEST_FIELDS
        domains = "active-trash-and-path-rules" if has_paths else "active-and-trash-only"
        if has_empty:
            fields |= {"emptyExportMarkers"}
            domains = "active-trash-path-rules-and-empty-exports"
        if has_typed:
            fields |= {"typedShortLinks", "shortLinkCompatibility"}
            domains += "-and-typed-single-shorts"
            require(document.get("shortLinkCompatibility") == (MIXED_COMPATIBILITY if has_mixed else "not-validated")
                    and len(source.migrations) >= 29
                    and (source.migrations[28].name, source.migrations[28].sha256)
                    == (package.TYPED_SHORT_MIGRATION, package.TYPED_SHORT_MIGRATION_SHA256))
        if has_mixed:
            fields.add("externalShortLinks")
            domains += "-and-external-shorts"
            require(worker is not None and (source.migrations[18].name, source.migrations[18].sha256)
                    == (package.EXTERNAL_SHORT_MIGRATION, package.EXTERNAL_SHORT_MIGRATION_SHA256))
        require(set(document) == fields and native.canonical(document) == raw
                and type(document.get("version")) is int and document["version"] == version
                and document.get("scope") == "fresh-unbound-d1-r2" and document.get("legacyDomains") == domains
                and document.get("generationZeroHttp") == document.get("formatCompatibility") == "not-validated"
                and document.get("counts") == counts and document.get("objectCount") == 4
                and (document.get("sourceHighWater"), document.get("targetSequenceHighWater")) == (HIGH_WATER, sequence)
                and document.get("workerArtifact") == worker_pin and document.get("schemaSha256") == source.schema_sha256)
        if has_paths:
            require(document["pathIdMapping"] == path_mapping()
                    and len(source.migrations) >= 10 and source.migrations[9].name == "0010_path_rules.sql")
        require({path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file() or path.is_symlink()}
                == package_files(document, profile=profile))
        if has_mixed:
            # Rebuild from fixed local fixtures and the sealed oracle metadata carried by
            # the exact hosted build. This path never starts the oracle or Node.
            with tempfile.TemporaryDirectory(prefix="candidate-source-", dir=scratch) as temporary:
                rebuilt_root = Path(temporary)
                rebuilt = rebuilt_root / "candidate"
                try:
                    _build_mixed_candidate(worker, rebuilt, worker_pin, rebuilt_root, root / MIXED_ORACLE)
                except (package.PackageError, short_namespace.InventoryError):
                    raise native.RehearsalError(ERROR) from None
                require(package.read_private(rebuilt / package.MANIFEST, native.MANIFEST_BYTES) == raw)
        else:
            source_hashes = {"sqliteSha256", "ownerMapSha256", "converterManifestSha256"}
            if has_typed:
                source_hashes |= {"typedShortInventoryManifestSha256", "oldOriginSha256"}
            require(set(document["source"]) == (source_hashes | ({"legacyBotId"} if has_typed else set()))
                    and all(native.matches(native.DIGEST, document["source"][key]) for key in source_hashes)
                    and (not has_typed or document["source"]["legacyBotId"] == TYPED_BOT)
                    and document["source"]["ownerMapSha256"] == native.digest(native.canonical(OWNER_MAP)))
            if has_empty:
                # Rebuild the fixed source rather than trusting an internally consistent replacement archive.
                with tempfile.TemporaryDirectory(prefix="candidate-source-", dir=scratch) as temporary:
                    _, expected_source = convert_synthetic_source(Path(temporary), profile)
                require(document["source"] == expected_source)
        self.sql = root / package.SQL
        sql = self.read_file(document["sql"], package.SQL, SQL_LIMIT, extra={"md5"})
        require(document["sql"]["md5"] == native.file_hash(self.sql, "md5")[1])
        sql_copy = scratch / package.SQL
        put(sql_copy, sql)
        db, layout, summary = native.open_export(sql_copy, source)
        with closing(db):
            require(native.canonical(layout) == native.canonical(document["layout"])
                    and summary == document["summary"] and document["dataSha256"] == summary["dataSha256"])
            objects, lineage = fixture_contents(db, document, profile)
            require(self.read_file(document["lineage"], package.LINEAGE, LINEAGE_LIMIT) == lineage)
            ledger = [{"position": i, "name": entry.name, "sha256": entry.sha256, "mode": "applied", "applied_at": APPLIED_AT}
                      for i, entry in enumerate(source.migrations, 1)]
            require(document["ledger"] == ledger and db.execute(
                "SELECT position,name,sha256,mode,applied_at FROM subs_bot_schema_migrations ORDER BY position").fetchall()
                == [tuple(entry.values()) for entry in ledger])
            expected_counts = {name: 0 for name in layout}
            expected_counts.update({package.ACTIVE: counts["activeRows"], package.TRASH: counts["trashRows"],
                                    package.LIFECYCLE: counts["trashRows"],
                                    "sqlite_sequence": 1, migrations.LEDGER: len(ledger)})
            if has_paths:
                expected_counts.update(path_rules=len(PATH_FIXTURES), sqlite_sequence=2)
            if has_empty:
                package.verify_empty_export_markers(db)
                expected_counts[package.EMPTY_EXPORTS] = 2
                require(document["emptyExportMarkers"] == {"activeRows": 1, "trashRows": 1,
                    "migrationSha256": package.EMPTY_EXPORT_MIGRATION_SHA256,
                    "tableSha256": summary["tableSha256"][package.EMPTY_EXPORTS]})
            if has_typed:
                expected_typed = sorted((native.digest(code.encode("ascii")), TYPED_BOT, OWNER_MAP.get(str(owner), str(owner)),
                    target_id, native.digest(token.encode("ascii")), format_name, created, None)
                    for code, owner, target_id, token, format_name, created in typed_fixture_links())
                columns = ",".join(package.TYPED_SHORT_COLUMNS)
                require(db.execute(f"SELECT {columns} FROM {package.TYPED_SHORTS} ORDER BY code_sha256").fetchall() == expected_typed)
                expected_counts[package.TYPED_SHORTS] = TYPED_COUNTS["rows"]
                require(document["typedShortLinks"] == {**TYPED_COUNTS, "migrationSha256": package.TYPED_SHORT_MIGRATION_SHA256,
                    "tableSha256": summary["tableSha256"][package.TYPED_SHORTS]})
            if has_mixed:
                expected_external = sorted((native.digest(code.encode("ascii")), 12, TYPED_BOT, OWNER_MAP.get(str(owner), str(owner)),
                                            None, None, None, target, created, None)
                                           for code, owner, target, created in external_fixture_links())
                package.verify_external_short_links(db, expected_external)
                expected_counts[package.EXTERNAL_SHORTS] = len(expected_external)
                require(document["externalShortLinks"] == {"rows": len(expected_external),
                    "migrationSha256": package.EXTERNAL_SHORT_MIGRATION_SHA256,
                    "tableSha256": summary["tableSha256"][package.EXTERNAL_SHORTS]})
            require(summary["tableCounts"] == expected_counts)
            self.entries = {entry["key"]: entry for entry in document["objects"]}
            require(self.entries.keys() == objects.keys() and document["objectBytes"] == sum(map(len, objects.values())))
            require(all(self.read_object(entry) == objects[entry["key"]] for entry in self.entries.values()))
            references = native.object_references(db, lambda key: (self.read_object(self.entries[key]), self.entries[key]["metadata"]))
            require(references == document["objects"])
            canonical_sql = scratch / "canonical.sql"
            extra_tables = {package.TYPED_SHORTS: package.TYPED_SHORT_COLUMNS} if has_typed else {}
            if has_mixed:
                extra_tables[package.EXTERNAL_SHORTS] = package.EXTERNAL_SHORT_COLUMNS
            package.write_sql(db, source.objects, sequence, canonical_sql, path_sequence=PATH_SEQUENCE if has_paths else None,
                              include_empty_exports=has_empty, extra_tables=extra_tables)
            require(package.read_private(canonical_sql, SQL_LIMIT) == sql)
        self.document = {**document, "sqlMd5": document["sql"]["md5"]}

    def read_file(self, entry, path, maximum, *, extra=frozenset()):
        require(isinstance(entry, dict) and set(entry) == {"path", "bytes", "sha256"} | extra and entry["path"] == path
                and native.integer(entry["bytes"], 1, maximum))
        raw = package.read_pinned(self.root / path, maximum, entry["sha256"])
        require(len(raw) == entry["bytes"])
        return raw

    def read_object(self, entry):
        path = "objects/" + entry["key"]
        return self.read_file({"path": path, "bytes": entry["bytes"], "sha256": entry["sha256"]}, path, OBJECT_LIMIT)

    def pin(self):
        result = {"packageManifestSha256": self.manifest_sha, "schemaSha256": self.document["schemaSha256"],
                  "dataSha256": self.document["dataSha256"], "sqlSha256": self.document["sql"]["sha256"],
                  "sqlMd5": self.document["sqlMd5"]}
        if self.profile in (PATH_PROFILE, EMPTY_PROFILE, TYPED_PROFILE, MIXED_PROFILE):
            result.update(pathRulesSha256=self.document["summary"]["tableSha256"]["path_rules"], pathSequenceHighWater=PATH_SEQUENCE)
        if self.profile in (EMPTY_PROFILE, TYPED_PROFILE, MIXED_PROFILE):
            result.update({key: value for key, value in self.document["source"].items() if key.endswith("Sha256")},
                          emptyExportMarkersSha256=self.document["emptyExportMarkers"]["tableSha256"],
                          emptyExportMigrationSha256=package.EMPTY_EXPORT_MIGRATION_SHA256)
        if self.profile in (TYPED_PROFILE, MIXED_PROFILE):
            result.update(typedShortLinksSha256=self.document["typedShortLinks"]["tableSha256"],
                          typedShortMigrationSha256=package.TYPED_SHORT_MIGRATION_SHA256)
        if self.profile == MIXED_PROFILE:
            result.update(externalShortLinksSha256=self.document["externalShortLinks"]["tableSha256"],
                          externalShortMigrationSha256=package.EXTERNAL_SHORT_MIGRATION_SHA256,
                          workerManifestSha256=self.document["workerArtifact"]["manifestSha256"])
        return result


class ShareCandidate(Candidate):
    def __init__(self, root, worker, worker_pin, scratch):
        self.profile = SHARE_PROFILE
        self.root = package.private_path(root, directory=True)
        self.sql = self.root / package.SQL
        raw = package.read_private(self.root / package.MANIFEST, native.MANIFEST_BYTES)
        self.manifest_sha = native.digest(raw)
        document = native.parsed(raw, native.MANIFEST_BYTES)
        paths = share_fixture.files(document, OBJECT_LIMIT)
        require({path.relative_to(self.root).as_posix() for path in self.root.rglob("*")
                 if path.is_file() or path.is_symlink()} == paths)
        expected = scratch / "expected-shares"
        report = share_fixture.build(worker, expected, worker_pin, applied_at=APPLIED_AT)
        require(report["manifestSha256"] == self.manifest_sha)
        # Only bytes reproduced from the fixed source may be used for import.
        limits = {package.MANIFEST: native.MANIFEST_BYTES, package.MARKER: 65, package.SQL: SQL_LIMIT}
        for path in paths:
            limit = limits.get(path, OBJECT_LIMIT)
            require(package.read_private(self.root / path, limit) == package.read_private(expected / path, limit))
        self.document = {**document, "sqlMd5": document["sql"]["md5"]}
        self.entries = {entry["key"]: entry for entry in document["objects"]}

    def pin(self):
        hashes = self.document["summary"]["tableSha256"]
        return {**super().pin(), "privateSharesSha256": hashes["private_shares"],
                "privateShareClaimsSha256": hashes["private_share_claims"],
                "sqliteSequenceSha256": hashes["sqlite_sequence"],
                "shareSequenceHighWater": self.document["shareSequenceHighWater"]}


class CandidateSource(native.Source):
    """The live Worker is a protected boundary, separate from candidate build provenance."""

    def live_pin(self):
        config = self.scope.worker_config()
        self.scope.verify_resources()
        active = self.scope.active()
        if self.api.profile == TEMP_PROFILE:
            version, capable = self.scope.version(active.version, with_legacy_temp=True)
            require(capable is True)
        else:
            version = self.scope.version(active.version)
        return {"deploymentId": active.id, "versionId": active.version, "version": asdict(version),
                "configurationSha256": native.digest(native.canonical(config)), "cronEnabled": self.scope.cron_enabled()}

    def verify(self, expected=None):
        self.guard_main()
        self.protected_live = self.live_pin()
        require(expected is None or self.protected_live == expected)
        return self.protected_live

    def before_write(self):
        require(self.live_pin() == self.protected_live)
        self.guard_main()

    def schema(self, database_id=None):
        require(database_id is not None and database_id == self.api.restore_id)
        return super().schema(database_id)


class CandidateRehearsal(native.Rehearsal):
    resource_kinds = ("database", "objects")
    creation_window_seconds = 120
    sql_limit = SQL_LIMIT
    import_ready_phase = "objects-restored"

    def __init__(self, api, source, journal, candidate):
        super().__init__(api, source, journal, None)
        self.candidate = candidate

    def observe(self, kind):
        identity = super().observe(kind)
        if identity is not None and kind == "objects":
            info = self.api.json("GET", self.api.root + "/r2/buckets/" + identity["name"])
            require(info.get("storage_class") == "Standard" and native.resource_identity(kind, info, identity["name"]) == identity)
            return {**identity, "storageClass": "Standard"}
        return identity

    def manifest(self):
        document = self.candidate.document
        self.api.allow_restore(keys=self.candidate.entries)
        self.candidate.read_file(document["sql"], package.SQL, self.sql_limit, extra={"md5"})
        return document, self.candidate.sql

    def before_target_write(self):
        self.verify_resources(all_required=True)
        self.source.before_write()

    def restore_objects(self):
        require("objects" in self.resource_kinds)
        self.verify_resources(all_required=True)
        document, _ = self.manifest()
        entries = document["objects"]
        by_key = self.candidate.entries
        state = self.journal.value
        actual = self.target_objects(by_key)
        if state["phase"] == "objects-restored":
            self.verify_object_bytes(document)
            return
        require(state["phase"] in {"prepared", "restoring-objects"} and state["importState"] is None)
        require(migrations._matches_schema(self.api, self.api.root + "/d1/database/" + self.api.restore_id, ()))
        if state["phase"] == "prepared":
            require(not actual)
            self.journal.update(phase="restoring-objects", objectConfirmed=0, objectIntent=None)
        confirmed, intent = self.journal.value["objectConfirmed"], self.journal.value["objectIntent"]
        require(native.integer(confirmed, 0, len(entries)) and (intent is None or intent == confirmed < len(entries)))
        completed = {entry["key"] for entry in entries[:confirmed]}
        allowed = completed if intent is None else completed | {entries[intent]["key"]}
        require(completed <= actual <= allowed)
        for index in range(confirmed, len(entries)):
            entry = entries[index]
            body = self.candidate.read_object(entry)
            if self.journal.value["objectIntent"] is None:
                self.journal.update(objectIntent=index)
            self.restore_object(entry, body)
            self.journal.update(objectIntent=None, objectConfirmed=index + 1)
        self.verify_object_bytes(document)
        self.journal.update(phase="objects-restored")


class TempCandidateRehearsal(CandidateRehearsal):
    resource_kinds = ("database",)
    import_ready_phase = "prepared"

    def __init__(self, api, source, journal, candidate):
        from legacy_temp_native_candidate import PACKAGE_LIMITS

        super().__init__(api, source, journal, candidate)
        self.sql_limit = PACKAGE_LIMITS[package.SQL]

    def verify_object_bytes(self, document):
        require(document["objectCount"] == 0 and document["objects"] == [] and self.candidate.entries == {})


def validate_checkpoint_action(action, resource, resources):
    require(isinstance(action, str) and action in ACTIONS)
    if action in {"create-restore-bucket", "restore-objects"}:
        require("objects" in resources)
    if action == "pin-resource":
        require(resource in resources)


def run_action(action, engine, pin, *, resource=None, identity_sha=None):
    resources = engine.resource_kinds
    validate_checkpoint_action(action, resource, resources)
    journal, source = engine.journal, engine.source
    state = journal.load()
    unconfirmed = {}
    observed_summary = None
    if state is not None:
        require(state.get("sourcePin") == pin and state.get("scopeSha256") == source.scope_sha256)
    if action == "verify":
        if state is not None:
            engine.verify_resources()
        for kind in resources:
            if state is None or state["resources"][kind]["pin"] is None:
                candidate = engine.observe(kind)
                if candidate is not None:
                    unconfirmed[kind] = native.digest(native.canonical(candidate))
    elif action == "verify-restore":
        require(state is not None and state.get("importState") is not None)
        observed_summary, _ = engine.read_restored_summary()
    else:
        if action == "prepare":
            engine.prepare(pin)
        else:
            require(state is not None)
            journal.claim()
        try:
            engine.verify_resources(all_required=action in {"restore-objects", "start-import"})
            if action == "create-restore-db":
                engine.create("database")
            elif action == "create-restore-bucket":
                engine.create("objects")
            elif action == "pin-resource":
                engine.pin_resource(resource, identity_sha)
            elif action == "restore-objects":
                engine.restore_objects()
            elif action == "start-import":
                require(journal.value["phase"] in {engine.import_ready_phase, "imported", "verified"})
                observed_summary = engine.start_import()
        finally:
            journal.release()
    source.before_write()
    state = journal.value
    pins = {} if state is None else {kind: state["resources"][kind]["pin"] for kind in resources}
    profile = pin["profile"]
    result = {"profile": profile, "action": action, "phase": "unprepared" if state is None else state["phase"],
              "packageManifestSha256": pin["candidate"]["packageManifestSha256"], "releasePinSha256": native.digest(native.canonical(pin)),
              "workerArtifact": pin["worker"], "candidateArtifactId": pin["candidate"]["artifactId"],
              "candidateArchiveSha256": pin["candidate"]["archiveSha256"],
              "resourceCount": sum(value is not None for value in pins.values()), "resourcePinsSha256": native.digest(native.canonical(pins)),
              "unconfirmedResourceCount": len(unconfirmed), "candidateIdentitySha256": unconfirmed,
              "objectCount": len(engine.candidate.entries)}
    if profile == SHARE_PROFILE:
        result.update(counts=share_fixture.COUNTS, shareCompatibility="not-validated")
    elif profile == SELECTED_PROFILE:
        from legacy_selected_native_candidate import SELECTED_HTTP_SCOPE

        result.update(counts=engine.candidate.document["counts"], generationZeroHttp="not-validated",
                      shortLinkCompatibility=engine.candidate.document["shortLinkCompatibility"],
                      selectedHttpOracle=SELECTED_HTTP_SCOPE, selectedHttpOracleSha256=pin["candidate"]["selectedHttpOracleSha256"])
    elif profile == TEMP_PROFILE:
        result.update(counts=engine.candidate.document["counts"], restoreScope=engine.candidate.document["scope"],
                      r2Closure="not-applicable")
    else:
        result.update(counts=EMPTY_COUNTS if profile in (EMPTY_PROFILE, TYPED_PROFILE, MIXED_PROFILE) else COUNTS,
                      generationZeroHttp="not-validated")
    if profile == TYPED_PROFILE:
        result["shortLinkCompatibility"] = "not-validated"
    if profile == MIXED_PROFILE:
        result["shortLinkCompatibility"] = MIXED_COMPATIBILITY
    if observed_summary is not None:
        result.update({"verifiedDataSha256": observed_summary["dataSha256"], "verifiedRowCount": observed_summary["rowCount"],
                       "schemaSha256": pin["candidate"]["schemaSha256"], "foreignKeys": "verified"})
        if profile != TEMP_PROFILE:
            result["r2Closure"] = "verified"
        if profile in (PATH_PROFILE, EMPTY_PROFILE, TYPED_PROFILE, MIXED_PROFILE):
            result.update(verifiedPathRuleCount=observed_summary["tableCounts"]["path_rules"],
                          verifiedPathSequenceHighWater=PATH_SEQUENCE,
                          pathRulesSha256=observed_summary["tableSha256"]["path_rules"],
                          sqliteSequenceSha256=observed_summary["tableSha256"]["sqlite_sequence"])
        if profile in (EMPTY_PROFILE, TYPED_PROFILE, MIXED_PROFILE):
            marker_count = observed_summary["tableCounts"][package.EMPTY_EXPORTS]
            marker_digest = observed_summary["tableSha256"][package.EMPTY_EXPORTS]
            require(marker_count == 2 and marker_digest == pin["candidate"]["emptyExportMarkersSha256"])
            result.update(verifiedEmptyExportMarkerCount=marker_count, emptyExportMarkersSha256=marker_digest,
                          emptyExportMigrationSha256=pin["candidate"]["emptyExportMigrationSha256"],
                          verifiedSubscriptionSequenceHighWater=EMPTY_TARGET_SEQUENCE)
        if profile in (TYPED_PROFILE, MIXED_PROFILE):
            short_count = observed_summary["tableCounts"][package.TYPED_SHORTS]
            short_digest = observed_summary["tableSha256"][package.TYPED_SHORTS]
            require(short_count == TYPED_COUNTS["rows"] and short_digest == pin["candidate"]["typedShortLinksSha256"]
                    and pin["candidate"]["typedShortMigrationSha256"] == package.TYPED_SHORT_MIGRATION_SHA256)
            result.update(verifiedTypedShortLinkCount=short_count, typedShortLinksSha256=short_digest,
                          typedShortMigrationSha256=package.TYPED_SHORT_MIGRATION_SHA256)
            if profile == TYPED_PROFILE:
                result["typedShortInventoryManifestSha256"] = pin["candidate"]["typedShortInventoryManifestSha256"]
        if profile == MIXED_PROFILE:
            external_count = observed_summary["tableCounts"][package.EXTERNAL_SHORTS]
            external_digest = observed_summary["tableSha256"][package.EXTERNAL_SHORTS]
            require(external_count == len(EXTERNAL_LINK_FIXTURES)
                    and external_digest == pin["candidate"]["externalShortLinksSha256"]
                    and pin["candidate"]["externalShortMigrationSha256"] == package.EXTERNAL_SHORT_MIGRATION_SHA256)
            result.update(verifiedExternalShortLinkCount=external_count, externalShortLinksSha256=external_digest,
                          externalShortMigrationSha256=package.EXTERNAL_SHORT_MIGRATION_SHA256,
                          namespaceManifestSha256=pin["candidate"]["namespaceManifestSha256"],
                          oracleManifestSha256=pin["candidate"]["oracleManifestSha256"])
        if profile in (SELECTED_PROFILE, TEMP_PROFILE):
            result.update(engine.candidate.native_evidence(observed_summary))
        if profile == SHARE_PROFILE:
            counts, hashes = observed_summary["tableCounts"], observed_summary["tableSha256"]
            require(counts["private_shares"] == share_fixture.COUNTS["shares"]
                    and counts["private_share_claims"] == share_fixture.COUNTS["claims"]
                    and result["objectCount"] == share_fixture.COUNTS["shares"])
            share_pin = pin["candidate"]
            require((hashes["private_shares"], hashes["private_share_claims"], hashes["sqlite_sequence"]) ==
                    (share_pin["privateSharesSha256"], share_pin["privateShareClaimsSha256"], share_pin["sqliteSequenceSha256"]))
            result.update(verifiedPrivateShareCount=counts["private_shares"], verifiedPrivateShareClaimCount=counts["private_share_claims"],
                          privateSharesSha256=hashes["private_shares"], privateShareClaimsSha256=hashes["private_share_claims"],
                          sqliteSequenceSha256=hashes["sqlite_sequence"], verifiedShareSequenceHighWater=share_pin["shareSequenceHighWater"],
                          r2Metadata="verified")
    return result


def verified_candidate(runner, provenance, scratch, *, profile=PROFILE):
    require(provenance.get("profile", PROFILE) == profile)
    release = provenance["worker"]
    worker = runner / artifact.VERIFIED_DIRECTORY
    manifest_sha = native.digest(package.read_private(worker / "isolation.json", artifact._MAX_JSON))
    chain, worker_pin = package.worker_artifact(worker, release["revision"], manifest_sha)
    require((worker_pin["runId"], worker_pin["runAttempt"]) == (release["runId"], release["runAttempt"]))
    if profile == SHARE_PROFILE:
        return ShareCandidate(runner / candidate_directory(profile), worker, worker_pin, scratch)
    if profile == SELECTED_PROFILE:
        from legacy_selected_native_candidate import SelectedCandidate

        return SelectedCandidate(runner / candidate_directory(profile), worker, worker_pin, scratch)
    if profile == TEMP_PROFILE:
        from legacy_temp_native_candidate import TempCandidate

        return TempCandidate(runner / candidate_directory(profile), worker, worker_pin, scratch)
    objects = migrations._objects(chain, len(chain), managed=True)
    schema = SimpleNamespace(migrations=chain, objects=objects, schema_sha256=native._schema_digest(objects),
                             tables=sorted(obj.name for obj in objects if obj.type == "table"))
    return Candidate(runner / candidate_directory(profile), schema, worker_pin, scratch, profile=profile, worker=worker)


def preflight(runner, revision, run_id, *, profile=PROFILE):
    require(os.environ.get("SUBS_BOT_CI_RUN_ID") == run_id)
    require(profile in ARTIFACT_PREFIXES)
    release = artifact.prepare()
    require((release["revision"], release["runId"]) == (revision, run_id))
    token = artifact._github_token()

    def select():
        return artifact.select_main_artifact(run_id, revision, token, workflow_id=artifact.WORKFLOW_ID,
            workflow_path=artifact.WORKFLOW_PATH, artifact_prefix=ARTIFACT_PREFIXES[profile], workflow_label="Worker CI")

    selected = select()
    attempt, artifact_id, digest = selected
    require(attempt == release["runAttempt"])
    archive = artifact._download(artifact_id, token)
    require(select() == selected and artifact._select_artifact(run_id, revision, token)
            == (release["runAttempt"], release["artifactId"], release["archiveSha256"]))
    unpack_candidate(archive, digest, runner / candidate_directory(profile), profile=profile)
    provenance = {"worker": release, "candidate": {"artifactId": artifact_id, "archiveSha256": digest}}
    if profile != PROFILE:
        provenance["profile"] = profile
    with tempfile.TemporaryDirectory(prefix="candidate-preflight-", dir=runner) as scratch:
        candidate = verified_candidate(runner, provenance, Path(scratch), profile=profile)
        provenance["candidate"].update(candidate.pin())
    artifact.require_current_main(revision)
    put(runner / PROVENANCE, native.canonical(provenance))


def apply(runner, revision, inputs):
    profile = inputs.get("profile", PROFILE)
    provenance = native.parsed(package.read_private(runner / PROVENANCE, 4096), 4096)
    require((provenance["worker"]["revision"], provenance["worker"]["runId"]) == (revision, inputs["source_run_id"]))
    with tempfile.TemporaryDirectory(prefix="candidate-apply-", dir=runner) as scratch:
        candidate = verified_candidate(runner, provenance, Path(scratch), profile=profile)
        require(all(provenance["candidate"].get(key) == value for key, value in candidate.pin().items()))
        target = native.parsed(os.environ.get("SUBS_BOT_CF_ISOLATION_TARGET_JSON", "").encode(), 4096)
        token = os.environ.get("SUBS_BOT_CF_BOOTSTRAP_TOKEN", "")
        deploy = os.environ.get("SUBS_BOT_CF_DEPLOY_TOKEN", "")
        require(token and deploy and token != deploy)
        api = native.RehearsalAPI(target, token, inputs["cohort"], profile=profile)
        worker_client = CloudflareClient(deploy)

        def read_worker(method, path, payload=None):
            require(method == "GET" and payload is None)
            return worker_client(method, path)

        worker = runner / artifact.VERIFIED_DIRECTORY
        manifest = native.parsed(package.read_private(worker / "isolation.json", artifact._MAX_JSON), artifact._MAX_JSON)
        source = CandidateSource(api, read_worker, target, worker, manifest, lambda: artifact.require_current_main(revision))
        live = source.verify()
        if profile in (SELECTED_PROFILE, TEMP_PROFILE):
            version = live["version"]
            require((version["revision"], version["digest"], version["compatibility"])
                    == (revision, manifest["bundleSha256"], manifest["compatibilityDate"]))
            native._verify_health(revision)
        pin = {**provenance, "profile": profile, "sourceScopeSha256": source.scope_sha256, "protectedLive": live}
        run_id, attempt = (os.environ.get(key, "") for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"))
        require(all(native.matches(artifact._DECIMAL, value) for value in (run_id, attempt)))
        journal = native.Journal(api, run_id + "/" + attempt, guard=source.before_write)
        engine = TempCandidateRehearsal if profile == TEMP_PROFILE else CandidateRehearsal
        result = run_action(inputs["action"], engine(api, source, journal, candidate), pin,
                            resource=inputs.get("resource"), identity_sha=inputs.get("identity_sha256"))
    put(runner / EVIDENCE, native.canonical(result))
    print(native.canonical(result).decode("ascii"))


def main(args):
    require(os.environ.get("GITHUB_REPOSITORY") == artifact.REPOSITORY and os.environ.get("GITHUB_REF") == artifact.MAIN_REF)
    revision = os.environ.get("GITHUB_SHA", "")
    require(native.matches(artifact._REVISION, revision))
    runner = Path(os.environ["RUNNER_TEMP"])
    event_name = os.environ.get("GITHUB_EVENT_NAME")
    if args and args[0] == "build":
        require(len(args) in {1, 2} and event_name in {"push", "workflow_dispatch"})
        profile = args[1] if len(args) == 2 else PROFILE
        require(profile in ARTIFACT_PREFIXES)
        run_id, attempt = (os.environ.get(key, "") for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"))
        require(all(native.matches(artifact._DECIMAL, value) for value in (run_id, attempt)))
        build_synthetic_candidate(runner / "subs-bot-worker", runner / ARTIFACT_PREFIXES[profile], revision, run_id, attempt, profile=profile)
        return
    require(args in (["preflight"], ["apply"]) and event_name == "workflow_dispatch")
    with Path(os.environ["GITHUB_EVENT_PATH"]).open("rb") as file:
        event = native.parsed(file.read(65537), 65536)
    inputs = event.get("inputs")
    require(isinstance(inputs, dict) and set(inputs) <= {"action", "cohort", "source_run_id", "resource", "identity_sha256", "profile"}
            and native.matches(native.COHORT, inputs.get("cohort"))
            and native.matches(artifact._DECIMAL, inputs.get("source_run_id")) and inputs.get("profile", PROFILE) in ARTIFACT_PREFIXES)
    profile = inputs.get("profile", PROFILE)
    engine = TempCandidateRehearsal if profile == TEMP_PROFILE else CandidateRehearsal
    validate_checkpoint_action(inputs.get("action"), inputs.get("resource"), engine.resource_kinds)
    if inputs["action"] == "pin-resource":
        require(native.matches(native.DIGEST, inputs.get("identity_sha256")))
    else:
        require(not inputs.get("identity_sha256"))
    if args == ["preflight"]:
        preflight(runner, revision, inputs["source_run_id"], profile=profile)
    else:
        apply(runner, revision, inputs)


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except native.RehearsalError as error:
        sys.exit(str(error))
    except Exception:
        sys.exit(ERROR)
