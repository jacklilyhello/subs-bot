"""Build and verify the fixed, dormant D1-only legacy temporary-node candidate."""

from contextlib import closing
from dataclasses import dataclass, field
from itertools import islice
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
from types import SimpleNamespace

import cloudflare_isolation as cloudflare
import d1_migrations as migrations
import legacy_candidate_isolation as isolation
import legacy_restore_package as package
import legacy_temp_inventory as inventory
from legacy_temp_worker_projection import ProjectionError, TempProjection, verify_projection
import native_restore_rehearsal as native
import prepare_isolation_artifact as artifact


TEMP_PROFILE = "synthetic-legacy-temp-nodes"
SCOPE = "fresh-unbound-d1"
ERROR = "The synthetic legacy temporary-node candidate could not be confirmed safely."
VERSION = 7
BOT_ID = "73111"
FIRST_OWNER = "73112"
SECOND_OWNER = "73113"
INSTALLATIONS = "legacy_temp_installations"
BATCHES = "legacy_temp_batches"
SQL_LIMIT = 256 * 1024
PACKAGE_LIMITS = {package.MANIFEST: native.MANIFEST_BYTES, package.MARKER: 65, package.SQL: SQL_LIMIT}
COUNTS = {"installations": 1, "batches": 3, "nodes": 503, "owners": 2}
TABLE_PINS = {INSTALLATIONS: "legacyTempInstallationsSha256", BATCHES: "legacyTempBatchesSha256"}
TEMP_COLUMNS = {INSTALLATIONS: ("bot_id", "inventory_sha256", "cutover_epoch"),
                BATCHES: ("bot_id", "actor_id", "first_legacy_id", "last_legacy_id", "nodes_json", "node_count",
                          "payload_bytes", "payload_sha256")}
SOURCE_DDL = """CREATE TABLE temp_nodes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    url TEXT NOT NULL,
    name TEXT NOT NULL,
    created_at INTEGER NOT NULL
)"""
FAILURES = (artifact.ArtifactError, cloudflare.CloudflareError, inventory.InventoryError, migrations.MigrationError,
            native.RehearsalError, package.PackageError, package.converter.ConversionError, ProjectionError,
            KeyError, OSError, RecursionError, sqlite3.Error, TypeError, ValueError)


@dataclass(frozen=True)
class TempFixture:
    source: Path
    source_sha256: str
    candidate: Path
    candidate_sha256: str
    projection: TempProjection = field(repr=False)


def require(condition):
    native.require(condition, ERROR)


def fixture_rows():
    """Return fixed synthetic rows in their original global ID order."""
    share = "ss://YWVzLTI1Ni1nY206Zml4dHVyZQ@203.0.113.10:8388"
    rows = []
    for index in range(501):
        identity = 2 * (index + 1)
        name, fragment = f"Legacy node {index:03d}", f"Raw-{index:03d}"
        if index == 0:
            name, fragment = "  旧名称 '引号'\n\x01👩\u200d💻  ", "%E5%8E%9F%E5%A7%8B%0A%26tail"
        elif index == 1:
            name = ""
        elif index >= 499:
            name, fragment = "Repeated across batches", "Repeated"
        rows.append((identity, int(FIRST_OWNER), share + "#" + fragment, name, 1_700_000_000 - identity))
    for identity in (3, 1001):
        other = f"ss://YWVzLTI1Ni1nY206Zml4dHVyZQ@192.0.2.20:8388#Other-{identity}"
        rows.append((identity, int(SECOND_OWNER), other, f"Other owner {identity}", 1_700_000_000 - identity))
    return tuple(sorted(rows))


def temp_candidate_files(document):
    require(isinstance(document, dict) and native.integer(document.get("version"), VERSION, VERSION)
            and document.get("profile") == TEMP_PROFILE and document.get("scope") == SCOPE
            and native.integer(document.get("objectCount"), 0, 0) and document.get("objects") == [])
    return set(PACKAGE_LIMITS)


def _worker(worker, revision, manifest_sha):
    chain, pin = package.worker_artifact(worker, revision, manifest_sha)
    require(cloudflare.legacy_temp_artifact(worker, pin))
    return chain, pin


def _seal_projection(source, working):
    with native.private_file(source):
        pass
    with closing(sqlite3.connect(source)) as db, db:
        db.execute(SOURCE_DDL)
        db.executemany("INSERT INTO temp_nodes(id,user_id,url,name,created_at) VALUES (?,?,?,?,?)", fixture_rows())
    source_sha = native.file_hash(source)[1]
    owner_sha = native.digest(native.canonical({}))
    sealed = working / "inventory"
    pins = {"source_sha256": source_sha, "owner_map": {}, "owner_map_sha256": owner_sha, "legacy_bot_id": BOT_ID}
    report = inventory.seal_inventory(source, sealed, **pins)
    inventory_sha = report["manifestSha256"]
    verified = verify_projection(source, sealed, working, inventory_manifest_sha256=inventory_sha, **pins)
    require(verified.node_count == COUNTS["nodes"] and tuple((row.owner_id, row.node_count) for row in verified.batches)
            == ((FIRST_OWNER, 500), (FIRST_OWNER, 1), (SECOND_OWNER, 2)))
    return verified, {"sourceSha256": source_sha, "ownerMapSha256": owner_sha, "inventoryManifestSha256": inventory_sha,
                      "inventoryRowsSha256": native.file_hash(sealed / inventory.ROWS)[1]}


def _bounded_sql(raw):
    require(0 < len(raw) <= SQL_LIMIT)
    # The writer adds a semicolon and LF per statement. Keep this fixed cohort
    # within the conservative D1 statement ceiling, even on native import.
    for statement in migrations._statements(raw.decode("utf-8")):
        require(len(statement.encode("utf-8")) + 2 <= migrations.MAX_D1_STATEMENT_BYTES)


def _write_sql(sql, chain, projected):
    schema = migrations._objects(chain, len(chain), managed=True)
    source = SimpleNamespace(objects=schema, tables=sorted(obj.name for obj in schema if obj.type == "table"))
    with closing(sqlite3.connect(":memory:")) as db, db:
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA trusted_schema=OFF")
        for obj in schema:
            if obj.name != "sqlite_sequence":
                db.execute(obj.sql)
        db.executemany(f"INSERT INTO {migrations.LEDGER} VALUES (?,?,?,?,?)",
                       ((index, item.name, item.sha256, "applied", isolation.APPLIED_AT)
                        for index, item in enumerate(chain, 1)))
        db.execute(f"INSERT INTO {INSTALLATIONS} VALUES (?,?,NULL)", (BOT_ID, projected.inventory_manifest_sha256))
        db.executemany(f"INSERT INTO {BATCHES} VALUES (?,?,?,?,?,?,?,?)", (
            (BOT_ID, batch.owner_id, batch.first_legacy_id, batch.last_legacy_id, batch.payload_json, batch.node_count,
             batch.payload_bytes, native.digest(batch.payload_json.encode("utf-8"))) for batch in projected.batches))
        layout = native.table_layout(db, source.tables)
        summary = package.db_summary(db, layout)
        package.write_sql(db, schema, 0, sql, extra_tables=TEMP_COLUMNS)
    _bounded_sql(package.read_private(sql, SQL_LIMIT))
    return source, layout, summary


def _no_object(_key):
    require(False)


def _replay(sql, source, layout, summary, ledger_count):
    db, restored_layout, restored_summary = native.open_export(sql, source)
    with closing(db):
        require(restored_layout == layout and restored_summary == summary and native.object_references(db, _no_object) == [])
        nonempty = {table: count for table, count in summary["tableCounts"].items() if count}
        require(nonempty == {migrations.LEDGER: ledger_count, INSTALLATIONS: COUNTS["installations"], BATCHES: COUNTS["batches"]})
        require(db.execute(f"SELECT cutover_epoch FROM {INSTALLATIONS}").fetchall() == [(None,)]
                and db.execute(f"SELECT sum(node_count) FROM {BATCHES}").fetchone() == (COUNTS["nodes"],))


def build_temp_fixture(root, worker, revision):
    """Return a positive synthetic source and closed candidate in a private scratch directory."""
    try:
        root, worker = package.private_path(root, directory=True), package.private_path(worker, directory=True)
        require(not root.is_relative_to(worker) and not worker.is_relative_to(root))
        manifest_sha = native.file_hash(worker / "isolation.json")[1]
        chain, worker_pin = _worker(worker, revision, manifest_sha)
        source = package.converter._safe_path(root / "legacy-temp.sqlite", existing=False)
        candidate = package.converter._safe_path(root / "candidate", existing=False)
        with TemporaryDirectory(prefix="temp-candidate-", dir=root) as temporary:
            working = Path(temporary)
            projected, source_pin = _seal_projection(working / source.name, working)
            replay_sql = working / package.SQL
            schema, layout, summary = _write_sql(replay_sql, chain, projected)
            _replay(replay_sql, schema, layout, summary, len(chain))
            sql = {**package.describe(replay_sql), "md5": native.file_hash(replay_sql, "md5")[1]}
            document = {"version": VERSION, "profile": TEMP_PROFILE, "scope": SCOPE, "counts": COUNTS,
                        "workerArtifact": worker_pin, "source": source_pin, "sql": sql, "layout": layout,
                        "summary": summary, "schemaSha256": native._schema_digest(schema.objects),
                        "dataSha256": summary["dataSha256"], "objects": [], "objectCount": 0,
                        "legacyTempMigrationSha256": cloudflare.LEGACY_TEMP_MIGRATION_SHA256,
                        "legacyTempBaseline": {"state": "dormant", "payloadBytes": projected.payload_bytes,
                                               "httpCompatibility": "legacy-link-not-validated"}}
            raw = native.canonical(document)
            require(len(raw) <= PACKAGE_LIMITS[package.MANIFEST])
            digest = native.digest(raw)
            sealed = working / candidate.name
            sealed.mkdir(mode=0o700)
            replay_sql.rename(sealed / package.SQL)
            isolation.put(sealed / package.MANIFEST, raw)
            isolation.put(sealed / package.MARKER, (digest + "\n").encode("ascii"))
            (working / source.name).rename(source)
            sealed.rename(candidate)
        return TempFixture(source, source_pin["sourceSha256"], candidate, digest, projected)
    except FAILURES:
        raise native.RehearsalError(ERROR) from None


class TempCandidate(isolation.Candidate):
    def __init__(self, root, worker, worker_pin, scratch):
        self.profile = TEMP_PROFILE
        try:
            self.root = package.private_path(root, directory=True)
            self.sql = self.root / package.SQL
            raw = package.read_private(self.root / package.MANIFEST, PACKAGE_LIMITS[package.MANIFEST])
            document = native.parsed(raw, PACKAGE_LIMITS[package.MANIFEST])
            paths = temp_candidate_files(document)
            require({path.name for path in islice(self.root.iterdir(), len(paths) + 1)} == paths
                    and document["workerArtifact"] == worker_pin)
            with TemporaryDirectory(prefix="expected-temp-", dir=package.private_path(scratch, directory=True)) as temporary:
                rebuilt = build_temp_fixture(Path(temporary), worker, worker_pin["revision"])
                require(native.digest(raw) == rebuilt.candidate_sha256)
                for name, maximum in PACKAGE_LIMITS.items():
                    require((self.root / name).lstat().st_nlink == 1 and package.read_private(self.root / name, maximum)
                            == package.read_private(rebuilt.candidate / name, maximum))
            self.manifest_sha = rebuilt.candidate_sha256
            self.document = {**document, "sqlMd5": document["sql"]["md5"]}
            self.entries = {}
        except FAILURES:
            raise native.RehearsalError(ERROR) from None

    def pin(self):
        hashes = self.document["summary"]["tableSha256"]
        return {**super().pin(), **self.document["source"], "workerManifestSha256": self.document["workerArtifact"]["manifestSha256"],
                "legacyTempMigrationSha256": cloudflare.LEGACY_TEMP_MIGRATION_SHA256,
                **{key: hashes[table] for table, key in TABLE_PINS.items()}}

    def native_evidence(self, summary):
        require(summary == self.document["summary"])
        pins = self.pin()
        counts = summary["tableCounts"]
        require(native.integer(counts[INSTALLATIONS], 1, 1) and native.integer(counts[BATCHES], 3, 3)
                and all(summary["tableSha256"][table] == pins[key] for table, key in TABLE_PINS.items()))
        return {"verifiedTempInstallationCount": 1, "verifiedTempBatchCount": 3, "verifiedTempNodeCount": COUNTS["nodes"],
                "verifiedTempCutover": "dormant", "legacyTempMigrationSha256": pins["legacyTempMigrationSha256"],
                **{key: pins[key] for key in TABLE_PINS.values()}}
