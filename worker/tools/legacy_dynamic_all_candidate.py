"""Compose a dormant, offline legacy dynamic-all package from one closed source."""

from contextlib import closing
from dataclasses import dataclass, field
from hashlib import sha256
from itertools import islice, zip_longest
import json
import os
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory

from cloudflare_isolation import LEGACY_DYNAMIC_ALL_MIGRATION_SHA256, LEGACY_TEMP_MIGRATION_SHA256
from legacy_mixed_short_candidate import UnifiedShortRows
import legacy_restore_package as package
import legacy_short_namespace_inventory as namespace
import legacy_snapshot_convert as converter
import legacy_temp_inventory as temp
import legacy_temp_worker_projection as projection
import legacy_typed_short_inventory as typed
import native_restore_rehearsal as native


INSTALLATIONS = "legacy_temp_installations"
BATCHES = "legacy_temp_batches"
MARKERS = "legacy_all_aggregates"
ORDER = "legacy_all_subscription_order"
DYNAMIC_COLUMNS = {
    INSTALLATIONS: ("bot_id", "inventory_sha256", "cutover_epoch"),
    BATCHES: ("bot_id", "actor_id", "first_legacy_id", "last_legacy_id", "nodes_json", "node_count", "payload_bytes", "payload_sha256"),
    package.AGGREGATE_LINKS: package.AGGREGATE_COLUMNS,
    MARKERS: ("code_sha256", "bot_id", "owner_id", "inventory_sha256"),
}
TARGET = b"aggregate://all"
BOT_ID = "74111"
OWNER, TEMP_ONLY_OWNER, EMPTY_OWNER, FOREIGN_OWNER = "74112", "74113", "74114", "74115"
OWNER_CODE, TEMP_ONLY_CODE, EMPTY_CODE = "DynAllA00001", "DynAllB00002", "DynAllC00003"
ALPHA_ID, EMPTY_ID, BETA_ID, FOREIGN_ID, LEGACY_TRASH_ID, TARGET_TRASH_ID = 2, 5, 6, 9, 4, 71
OLD_ORIGIN = "https://old.fixture.example"
CREATED_AT, APPLIED_AT, TRASH_AT = 1_700_000_000, 1_700_002_000, 2_100_000_000
ERROR = "The dormant legacy dynamic aggregate source could not be verified safely."
SEALS = {namespace.MANIFEST: 64 * 1024, namespace.SEAL: 65, namespace.ROWS: namespace.MAX_METADATA_BYTES}


@dataclass(frozen=True)
class DynamicAllInput:
    source: Path
    owner_map: dict[str, str] = field(repr=False)
    namespace_dir: Path
    namespace_sha256: str
    temp_dir: Path
    temp_manifest_sha256: str
    old_origin: str
    legacy_bot_id: str


@dataclass(frozen=True)
class VerifiedDynamicAll:
    short_domain: dict
    temp_domain: dict
    proof: dict[str, str]
    rows: dict[str, tuple[tuple[str | int | None, ...], ...]] = field(repr=False)
    active_lineage: tuple[tuple[int, str, str], ...] = field(repr=False)

    def report(self, summary, *, unified=False):
        hashes, counts = summary["tableSha256"], summary["tableCounts"]
        require(all(counts[table] == len(rows) for table, rows in self.rows.items()
                    if not unified or table != package.AGGREGATE_LINKS) and counts[ORDER] == 0)
        links = self.rows[package.AGGREGATE_LINKS]
        require(not unified or counts[package.AGGREGATE_LINKS] >= len(links))
        batches = self.rows[BATCHES]
        result = {
            "dynamicAll": {"rows": len(links), "markers": counts[MARKERS], "orderRows": counts[ORDER],
                           "state": "dormant", "migrationSha256": LEGACY_DYNAMIC_ALL_MIGRATION_SHA256,
                           "tableSha256": {table: hashes[table] for table in (package.AGGREGATE_LINKS, MARKERS, ORDER)}},
            "legacyTempBaseline": {"installations": counts[INSTALLATIONS], "batches": counts[BATCHES],
                                   "nodes": sum(row[5] for row in batches), "owners": len({row[1] for row in batches}),
                                   "state": "dormant", "migrationSha256": LEGACY_TEMP_MIGRATION_SHA256,
                                   "payloadBytes": sum(row[6] for row in batches),
                                   "tableSha256": {table: hashes[table] for table in (INSTALLATIONS, BATCHES)}},
        }
        if unified:
            result["dynamicAll"]["partitionSha256"] = native.digest(native.canonical(links))
        else:
            result["shortLinkCompatibility"] = {"dynamicAll": "not-validated"}
        return result


@dataclass(frozen=True)
class DynamicAllFixture:
    source: Path
    source_sha256: str
    candidate: Path
    candidate_sha256: str


def require(condition):
    if not condition:
        raise package.PackageError(ERROR)


def seal_dynamic_all_input(source: Path, owner_map: dict[str, str], working_parent: Path, *, source_sha256: str,
                           owner_map_sha256: str, old_origin: str, legacy_bot_id: str) -> DynamicAllInput:
    """Seal both sidecars from the same source without accepting their dispositions."""
    root = package.private_path(working_parent, directory=True)
    short_dir, temp_dir = root / "namespace", root / "temp-inventory"
    namespace.seal_inventory(source, short_dir, source_sha256=source_sha256, owner_map=owner_map,
                             owner_map_sha256=owner_map_sha256, old_origin=old_origin, legacy_bot_id=legacy_bot_id)
    report = temp.seal_inventory(source, temp_dir, source_sha256=source_sha256, owner_map=owner_map,
                                 owner_map_sha256=owner_map_sha256, legacy_bot_id=legacy_bot_id)
    return DynamicAllInput(Path(source), dict(owner_map), short_dir, native.file_hash(short_dir / namespace.MANIFEST)[1],
                           temp_dir, report["manifestSha256"], old_origin, legacy_bot_id)


def _compare_namespace(supplied, rebuilt):
    require({entry.name for entry in islice(supplied.iterdir(), len(SEALS) + 1)} == set(SEALS))
    for name, maximum in SEALS.items():
        with projection._open_private(supplied / name, maximum) as actual, projection._open_private(rebuilt / name, maximum) as expected:
            while block := expected.read(64 * 1024):
                require(actual.read(len(block)) == block)
            require(not actual.read(1))


def _source_rows(source, rows_path, owners, expected):
    coalesced = {owner for original, owner in owners.items() if original != owner}
    with closing(sqlite3.connect(source.as_uri() + "?mode=ro&immutable=1", uri=True, isolation_level=None)) as db:
        db.execute("PRAGMA trusted_schema=OFF")
        db.execute("PRAGMA query_only=ON")
        db.execute("PRAGMA cache_size=-2048")
        db.execute("BEGIN")
        targets = typed._targets(db, typed._tables(db))
        lineage = tuple(sorted((identity, owners.get(str(owner), str(owner)), sha256(token).hexdigest())
                               for token, (table, identity, owner) in targets.items() if table == "subscriptions"))
        rows = db.execute("""SELECT rowid,typeof(code),typeof(target_url),
            CASE WHEN typeof(user_id)='integer' THEN user_id END,
            CASE WHEN typeof(created_at)='integer' THEN created_at END
            FROM main.short_links ORDER BY rowid LIMIT ?""", (typed.MAX_SHORTS + 1,))
        links = []
        with rows_path.open("rb") as metadata:
            for row, line in zip(rows, metadata, strict=True):
                rowid, code_type, target_type, issuer, created_at = row
                require(len(links) < expected and native.integer(issuer, 1, converter.MAX_OWNER) and native.integer(created_at, 1))
                owner = str(issuer)
                require(owners.get(owner, owner) == owner and owner not in coalesced)
                code = typed._text_bytes(db, "short_links", "code", rowid, code_type, 12)
                target, issue = namespace.read_target(db, rowid, target_type)
                require(typed._CODE.fullmatch(code) and issue is None and target == TARGET)
                digest = sha256(code).hexdigest()
                require(json.loads(line) == {"codeSha256": digest, "sourceIssuerId": owner, "ownerId": owner,
                                             "createdAt": created_at, "targetSha256": sha256(TARGET).hexdigest(),
                                             "kind": "aggregate-all", "state": "classified"})
                links.append((digest, owner, created_at))
        db.execute("ROLLBACK")
    require(len(links) == expected and len({row[0] for row in links}) == expected)
    return sorted(links), lineage


def read_dynamic_all(pins: DynamicAllInput, *, source_sha: str, owner_map_sha: str, converter_manifest_sha: str,
                     working_parent: Path, mixed: UnifiedShortRows | None = None) -> VerifiedDynamicAll:
    try:
        require(isinstance(pins, DynamicAllInput) and all(native.matches(native.DIGEST, value) for value in (
            source_sha, owner_map_sha, converter_manifest_sha, pins.namespace_sha256, pins.temp_manifest_sha256)))
        require(mixed is None or isinstance(mixed, UnifiedShortRows))
        source = package.private_path(pins.source)
        owners = converter._owner_map(pins.owner_map)
        require(native.digest(converter._json(dict(sorted(owners.items())))) == owner_map_sha)
        short_dir, temp_dir, parent = (package.private_path(path, directory=True) for path in (
            pins.namespace_dir, pins.temp_dir, working_parent))
        require(not parent.is_relative_to(short_dir) and not parent.is_relative_to(temp_dir))
        state = typed._source_state(source)
        temp._verify_backup(source, state, source_sha)
        if mixed is not None:
            require((source, short_dir, state, source_sha, owner_map_sha) == (
                mixed.source, mixed.namespace, mixed.source_state, mixed.source_sha256, mixed.owner_map_sha256)
                and mixed.proof["namespaceManifestSha256"] == pins.namespace_sha256
                and mixed.proof["legacyBotId"] == pins.legacy_bot_id
                and mixed.proof["oldOriginSha256"] == native.digest(typed._origin(pins.old_origin)))
        with TemporaryDirectory(prefix="dynamic-all-source-", dir=parent) as temporary:
            root = Path(temporary)
            # Rebuild the converter too. Merely resealing supplied outputs would
            # allow a different owner's paths, subscription content, or pointer.
            converted = root / "conversion"
            converter.convert_backup(source, converted, owner_map=owners)
            require(native.file_hash(converted / package.MANIFEST)[1] == converter_manifest_sha)
            if mixed is None:
                rebuilt = root / "namespace"
                namespace.seal_inventory(source, rebuilt, source_sha256=source_sha, owner_map=owners,
                                         owner_map_sha256=owner_map_sha, old_origin=pins.old_origin, legacy_bot_id=pins.legacy_bot_id)
                _compare_namespace(short_dir, rebuilt)
                raw = package.read_pinned(rebuilt / namespace.MANIFEST, SEALS[namespace.MANIFEST], pins.namespace_sha256)
                short_report = native.parsed(raw, SEALS[namespace.MANIFEST])
                inventory = short_report["inventory"]
                total = inventory["rows"]
                require(inventory["present"] is True and inventory["blocked"] == 0 and native.integer(total, 1, typed.MAX_SHORTS)
                        and inventory["kinds"] == {kind: total if kind == "aggregate-all" else 0 for kind in namespace.KINDS})
                links, lineage = _source_rows(source, rebuilt / namespace.ROWS, owners, total)
                short_domain = {"present": True, "rows": total}
                origin_sha, namespace_rows_sha = short_report["oldOriginSha256"], short_report["files"][0]["sha256"]
            else:
                links, lineage, short_domain = mixed.dynamic_all_rows, mixed.active_lineage, mixed.domain
                origin_sha, namespace_rows_sha = mixed.proof["oldOriginSha256"], mixed.proof["namespaceRowsSha256"]
            projected = projection.verify_projection(source, temp_dir, root, source_sha256=source_sha, owner_map=owners,
                        owner_map_sha256=owner_map_sha, legacy_bot_id=pins.legacy_bot_id,
                        inventory_manifest_sha256=pins.temp_manifest_sha256)
        temp._verify_backup(source, state, source_sha)
        temp_manifest = native.parsed(package.read_pinned(temp_dir / temp.MANIFEST, 64 * 1024, pins.temp_manifest_sha256), 64 * 1024)
        bot, temp_sha = pins.legacy_bot_id, pins.temp_manifest_sha256
        rows = {
            INSTALLATIONS: ((bot, temp_sha, None),) if links or projected.batches else (),
            BATCHES: tuple((bot, row.owner_id, row.first_legacy_id, row.last_legacy_id, row.payload_json, row.node_count,
                            row.payload_bytes, native.digest(row.payload_json.encode("utf-8"))) for row in projected.batches),
            package.AGGREGATE_LINKS: tuple((digest, owner, "all", bot, None, created_at, None) for digest, owner, created_at in links),
            MARKERS: tuple((digest, bot, owner, temp_sha) for digest, owner, _ in links),
        }
        proof = {"legacyBotId": bot, "oldOriginSha256": origin_sha,
                 "namespaceManifestSha256": pins.namespace_sha256, "namespaceRowsSha256": namespace_rows_sha,
                 "tempInventoryManifestSha256": temp_sha, "tempInventoryRowsSha256": temp_manifest["files"][0]["sha256"],
                 "activeLineageSha256": native.digest(native.canonical(lineage))}
        return VerifiedDynamicAll(short_domain, {"present": temp_manifest["inventory"]["present"],
                                  "rows": projected.node_count}, proof, rows, lineage)
    except (namespace.InventoryError, typed.InventoryError, temp.InventoryError, projection.ProjectionError,
            converter.ConversionError, native.RehearsalError, OSError, sqlite3.Error, ValueError, TypeError, KeyError, RecursionError):
        raise package.PackageError(ERROR) from None


def _verify_active(db, data):
    active = db.execute("SELECT id,owner_id,token FROM subscriptions ORDER BY id")
    actual = ((identity, owner, native.digest(token.encode("ascii"))) for identity, owner, token in active)
    require(all(row == expected for row, expected in zip_longest(actual, data.active_lineage)))


def load_dynamic_all(db: sqlite3.Connection, data: VerifiedDynamicAll):
    _verify_active(db, data)
    for table, columns in DYNAMIC_COLUMNS.items():
        db.executemany(f"INSERT INTO {table} ({','.join(columns)}) VALUES ({','.join('?' for _ in columns)})", data.rows[table])


def verify_dynamic_all(db: sqlite3.Connection, data: VerifiedDynamicAll, objects: list[dict], *, unified=False):
    _verify_active(db, data)
    for table, columns in DYNAMIC_COLUMNS.items():
        order = "bot_id,actor_id,first_legacy_id" if table == BATCHES else columns[0]
        scope = "WHERE kind='all'" if unified and table == package.AGGREGATE_LINKS else ""
        rows = db.execute(f"SELECT {','.join(columns)} FROM {table} {scope} ORDER BY {order}")
        require(all(row == expected for row, expected in zip_longest(rows, sorted(data.rows[table]))))
    empty_tables = (ORDER, "telegram_inbox", "telegram_outbox", "telegram_temp_batch")
    if not unified:
        empty_tables += (package.SELECTED_MARKERS, package.SELECTED_WATCHES, package.EXTERNAL_SHORTS, package.TYPED_SHORTS)
    for table in empty_tables:
        require(db.execute(f"SELECT 1 FROM {table} LIMIT 1").fetchone() is None)

    # Check current composite input limits, excluding trash and foreign scopes.
    # Per-format output compatibility still requires the emitted Worker oracle.
    totals = {row[1]: {"members": 0, "nodes": 0, "bytes": 0, "chunks": 0} for row in data.rows[package.AGGREGATE_LINKS]}
    for _, owner, _, _, _, count, size, _ in data.rows[BATCHES]:
        if owner in totals:
            totals[owner]["nodes"] += count
            totals[owner]["bytes"] += size
    active = {}
    for identity, owner, count in db.execute("SELECT id,owner_id,node_count FROM subscriptions WHERE generation>0"):
        if owner in totals:
            active[identity] = owner
            totals[owner]["members"] += 1
            totals[owner]["nodes"] += count
    for entry in objects:
        prefix, identity, _, name = entry["key"].split("/")
        require(prefix == "subscriptions")
        owner = active.get(int(identity))
        if owner is not None and name != "manifest.json":
            totals[owner]["bytes"] += entry["bytes"]
            totals[owner]["chunks"] += 1
    require(all(item["members"] <= 128 and item["nodes"] <= converter.MAX_NODES and item["bytes"] <= converter.SNAPSHOT_BYTES
                and item["chunks"] <= converter.MAX_CHUNKS for item in totals.values()))
    require(all(owner not in totals or count <= 64 for owner, count in db.execute("SELECT owner_id,count(*) FROM path_rules GROUP BY owner_id")))


def fixture_share(label):
    return f"ss://YWVzLTI1Ni1nY206Zml4dHVyZQ@203.0.113.10:8388#{label}"


def fixture_token(label):
    return "legacy-dynamic-token-" + label


def _fixture_node(label):
    return {"name": label, "type": "ss", "server": "203.0.113.10", "port": 8388, "cipher": "aes-256-gcm",
            "password": "fixture", "share": fixture_share(label)}


def make_synthetic_source(path: Path):
    path = converter._safe_path(path, existing=False)
    package.private_path(path.parent, directory=True)
    with native.private_file(path):
        pass
    with closing(sqlite3.connect(path)) as db, db:
        for table, time in (("subscriptions", "updated_at"), ("deleted_subs", "deleted_at")):
            unique = " UNIQUE" if table == "subscriptions" else ""
            db.execute(f"""CREATE TABLE {table} (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
                name TEXT NOT NULL, url TEXT NOT NULL, token TEXT NOT NULL{unique}, expire_at INTEGER, traffic_used REAL,
                traffic_total REAL, nodes_json TEXT NOT NULL DEFAULT '[]', node_count INTEGER NOT NULL DEFAULT 0,
                last_error TEXT, created_at INTEGER NOT NULL, {time} INTEGER NOT NULL)""")
        for table, identity, owner, label in (("subscriptions", ALPHA_ID, OWNER, "alpha"), ("subscriptions", EMPTY_ID, OWNER, "empty"),
                ("subscriptions", BETA_ID, OWNER, "beta"), ("subscriptions", FOREIGN_ID, FOREIGN_OWNER, "foreign"),
                ("deleted_subs", LEGACY_TRASH_ID, OWNER, "trash")):
            nodes = [] if label == "empty" else [_fixture_node(label)]
            db.execute(f"INSERT INTO {table} VALUES (?,?,?,?,?,NULL,NULL,NULL,?,?,NULL,?,?)", (
                identity, int(owner), label, "uploaded://fixture/" + label, fixture_token(label),
                converter._json(nodes).decode("utf-8"), len(nodes), CREATED_AT, TRASH_AT if table == "deleted_subs" else CREATED_AT))
        db.execute("UPDATE sqlite_sequence SET seq=50 WHERE name='subscriptions'")
        db.execute("UPDATE sqlite_sequence SET seq=70 WHERE name='deleted_subs'")
        db.execute("""CREATE TABLE path_maps (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
            node_name TEXT NOT NULL, remark TEXT NOT NULL DEFAULT '', UNIQUE(user_id,node_name))""")
        db.execute("INSERT INTO path_maps VALUES (7,?,'alpha','mapped')", (int(OWNER),))
        db.execute("""CREATE TABLE temp_nodes (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
            url TEXT NOT NULL, name TEXT NOT NULL, created_at INTEGER NOT NULL)""")
        db.executemany("INSERT INTO temp_nodes VALUES (?,?,?,?,?)", (
            (identity, int(owner), fixture_share(label), name, CREATED_AT - identity) for identity, owner, label, name in (
                (2, OWNER, "temporary", "alpha"), (3, FOREIGN_OWNER, "foreign-temporary", "foreign temporary"),
                (6, TEMP_ONLY_OWNER, "temporary-only", "temporary-only"), (8, OWNER, "temporary", "alpha"))))
        db.execute("CREATE TABLE short_links (code TEXT PRIMARY KEY,user_id INTEGER NOT NULL,target_url TEXT NOT NULL,created_at INTEGER NOT NULL)")
        db.executemany("INSERT INTO short_links VALUES (?,?,'aggregate://all',?)", (
            (code, int(owner), CREATED_AT + ordinal) for ordinal, (code, owner) in enumerate(
                ((OWNER_CODE, OWNER), (TEMP_ONLY_CODE, TEMP_ONLY_OWNER), (EMPTY_CODE, EMPTY_OWNER)))))
        db.execute("CREATE TABLE meta (key TEXT PRIMARY KEY,value TEXT NOT NULL)")
        db.execute("INSERT INTO meta VALUES ('node_count_backfilled_v1','1')")


def build_dynamic_all_fixture(root: Path, worker: Path, revision: str) -> DynamicAllFixture:
    """Build the fixed private source and dormant archive; no service is contacted."""
    root, worker = package.private_path(root, directory=True), package.private_path(worker, directory=True)
    require(not root.is_relative_to(worker) and not worker.is_relative_to(root))
    source, candidate = root / "legacy.sqlite", root / "candidate"
    require(not os.path.lexists(source) and not os.path.lexists(candidate))
    make_synthetic_source(source)
    source_sha, owner_map_sha = native.file_hash(source)[1], native.digest(native.canonical({}))
    worker_sha = native.file_hash(worker / "isolation.json")[1]
    with TemporaryDirectory(prefix="dynamic-all-build-", dir=root) as temporary:
        working = Path(temporary)
        conversion = working / "conversion"
        converter.convert_backup(source, conversion, owner_map={})
        inputs = seal_dynamic_all_input(source, {}, working, source_sha256=source_sha, owner_map_sha256=owner_map_sha,
                                        old_origin=OLD_ORIGIN, legacy_bot_id=BOT_ID)
        output = working / "candidate"
        report = package.build_candidate(conversion, worker, output, converter_manifest_sha=native.file_hash(conversion / package.MANIFEST)[1],
                    worker_manifest_sha=worker_sha, revision=revision, applied_at=APPLIED_AT, profile=package.DYNAMIC_ALL_PROFILE,
                    source_sqlite_sha=source_sha, owner_map_sha=owner_map_sha, dynamic_all=inputs)
        require(report["version"] == 8 and report["targetSequenceHighWater"] == TARGET_TRASH_ID
                and report["objectCount"] == 8 and report["dynamicAll"]["rows"] == 3 and report["legacyTempBaseline"]["nodes"] == 4)
        output.rename(candidate)
    return DynamicAllFixture(source, source_sha, candidate, report["manifestSha256"])
