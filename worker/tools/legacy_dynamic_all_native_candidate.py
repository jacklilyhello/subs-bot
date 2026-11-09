"""Verify the exact hosted V8 synthetic package before protected native restore."""

from contextlib import closing
from itertools import islice
from pathlib import Path
import re
import sqlite3
from tempfile import TemporaryDirectory
from types import SimpleNamespace

from cloudflare_isolation import LEGACY_DYNAMIC_ALL_MIGRATION_SHA256, LEGACY_TEMP_MIGRATION_SHA256
import d1_migrations as migrations
import legacy_candidate_isolation as isolation
import legacy_dynamic_all_candidate as dynamic
import legacy_restore_package as package
import native_restore_rehearsal as native
import prepare_isolation_artifact as artifact


DYNAMIC_ALL_PROFILE = "synthetic-legacy-dynamic-all"
DYNAMIC_ALL_HTTP_REPORT = "dynamic-all-http-oracle.json"
DYNAMIC_ALL_HTTP_SCOPE = "hosted-synthetic-dynamic-all-http"
ERROR = "The synthetic legacy dynamic aggregate restore candidate could not be confirmed safely."
OBJECT_COUNT = 8
SQL_LIMIT = 256 * 1024
REPORT_LIMIT = 4096
PACKAGE_LIMITS = {package.MANIFEST: native.MANIFEST_BYTES, package.MARKER: 65, package.SQL: SQL_LIMIT,
                  package.LINEAGE: isolation.LINEAGE_LIMIT, DYNAMIC_ALL_HTTP_REPORT: REPORT_LIMIT}
WORKER_PIN_FIELDS = ("revision", "runId", "runAttempt", "manifestSha256", "bundleSha256", "compatibilityDate")
HTTP_OUTCOMES = {"candidateVersion": 8, "historicalRestoreChecks": 1, "legacyIncompleteClashTempRows": 2,
                 "dormantChecks": 12, "exportBytePairs": 17, "clashShapePairs": 2, "relativeShortPairs": 3, "missingPairs": 3}
EXPECTED_NONEMPTY = {package.ACTIVE: 4, package.TRASH: 1, package.LIFECYCLE: 1,
                     package.PATH_RULES: 1, package.EMPTY_EXPORTS: 1, package.AGGREGATE_LINKS: 3, dynamic.MARKERS: 3,
                     dynamic.INSTALLATIONS: 1, dynamic.BATCHES: 3, "sqlite_sequence": 2}
TABLE_PINS = {package.AGGREGATE_LINKS: "aggregateLinksSha256", dynamic.MARKERS: "legacyAllAggregatesSha256",
              dynamic.ORDER: "legacyAllSubscriptionOrderSha256", dynamic.INSTALLATIONS: "legacyTempInstallationsSha256",
              dynamic.BATCHES: "legacyTempBatchesSha256", "sqlite_sequence": "sqliteSequenceSha256"}


def require(condition):
    native.require(condition, ERROR)


def dynamic_all_candidate_files(document):
    """Return the exact archive members admitted for the V8 profile only."""
    require(isinstance(document, dict) and native.integer(document.get("version"), 8, 8)
            and document.get("scope") == "fresh-unbound-d1-r2"
            and native.integer(document.get("objectCount"), OBJECT_COUNT, OBJECT_COUNT))
    objects = document.get("objects")
    require(isinstance(objects, list) and len(objects) == OBJECT_COUNT)
    paths = set(PACKAGE_LIMITS)
    snapshots = {}
    for entry in objects:
        require(isinstance(entry, dict) and set(entry) == {"key", "bytes", "sha256", "metadata"}
                and native.matches(native.KEY, entry["key"]) and entry["key"].startswith("subscriptions/")
                and native.integer(entry["bytes"], 1, isolation.OBJECT_LIMIT)
                and native.matches(native.DIGEST, entry["sha256"]) and entry["metadata"] == {"custom": {}, "http": {}})
        _, identity, snapshot, name = entry["key"].split("/")
        snapshots.setdefault((int(identity), snapshot), set()).add(name)
        paths.add("objects/" + entry["key"])
    require(len(paths) == len(PACKAGE_LIMITS) + OBJECT_COUNT and len(snapshots) == 4
            and {identity for identity, _ in snapshots} == {dynamic.ALPHA_ID, dynamic.BETA_ID, dynamic.FOREIGN_ID, dynamic.TARGET_TRASH_ID}
            and all(names == {"manifest.json", "0.ndjson"} for names in snapshots.values()))
    return paths


def _verify_tree(root, paths):
    files = {Path(path) for path in paths}
    parents = {parent for path in files for parent in path.parents}
    all_paths = files | parents
    for relative in parents:
        directory = package.private_path(root / relative, directory=True)
        expected = {path.name for path in all_paths if path != relative and path.parent == relative}
        require({path.name for path in islice(directory.iterdir(), len(expected) + 1)} == expected)
    for relative in files:
        require(package.private_path(root / relative).lstat().st_nlink == 1)


def _http_report(fixture, worker_pin, outcomes):
    worker = {field: worker_pin.get(field) for field in WORKER_PIN_FIELDS}
    require(native.matches(native.REVISION, worker["revision"])
            and all(native.matches(artifact._DECIMAL, worker[field]) for field in ("runId", "runAttempt"))
            and all(native.matches(native.DIGEST, value) for value in (
                worker["manifestSha256"], worker["bundleSha256"], fixture.source_sha256, fixture.candidate_sha256))
            and native.matches(re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}"), worker["compatibilityDate"]))
    require(isinstance(outcomes, dict) and set(outcomes) == set(HTTP_OUTCOMES)
            and all(native.integer(outcomes[key], expected, expected) for key, expected in HTTP_OUTCOMES.items()))
    return native.canonical({"version": 1, "scope": DYNAMIC_ALL_HTTP_SCOPE, "worker": worker,
                             "sourceSha256": fixture.source_sha256, "packageManifestSha256": fixture.candidate_sha256,
                             "legacySerializer": {"python": "3.11.18", "aiohttp": "3.11.18", "yarl": "1.20.0"},
                             "outcomes": outcomes})


def seal_dynamic_all_http_report(fixture: dynamic.DynamicAllFixture, worker_pin: dict, outcomes: dict) -> str:
    """Seal the redacted result only after the hosted differential succeeds."""
    root = package.private_path(fixture.candidate, directory=True)
    raw = package.read_pinned(root / package.MANIFEST, PACKAGE_LIMITS[package.MANIFEST], fixture.candidate_sha256)
    document = native.parsed(raw, PACKAGE_LIMITS[package.MANIFEST])
    _verify_tree(root, dynamic_all_candidate_files(document) - {DYNAMIC_ALL_HTTP_REPORT})
    require(raw == native.canonical(document) and document["workerArtifact"] == worker_pin
            and document["source"]["sqliteSha256"] == fixture.source_sha256
            and package.read_private(root / package.MARKER, 65) == (fixture.candidate_sha256 + "\n").encode("ascii"))
    proof = _http_report(fixture, worker_pin, outcomes)
    require(len(proof) <= REPORT_LIMIT)
    isolation.put(root / DYNAMIC_ALL_HTTP_REPORT, proof)
    return native.digest(proof)


class DynamicAllCandidate(isolation.Candidate):
    def __init__(self, root, worker, worker_pin, scratch):
        self.profile = DYNAMIC_ALL_PROFILE
        try:
            self.root = package.private_path(root, directory=True)
            self.sql = self.root / package.SQL
            raw = package.read_private(self.root / package.MANIFEST, PACKAGE_LIMITS[package.MANIFEST])
            document = native.parsed(raw, PACKAGE_LIMITS[package.MANIFEST])
            paths = dynamic_all_candidate_files(document)
            _verify_tree(self.root, paths)
            chain, pinned_worker = package.worker_artifact(worker, worker_pin["revision"], worker_pin["manifestSha256"])
            require(pinned_worker == worker_pin and document["workerArtifact"] == worker_pin)
            self.manifest_sha = native.digest(raw)
            parent = package.private_path(scratch, directory=True)
            with TemporaryDirectory(prefix="expected-dynamic-all-", dir=parent) as temporary:
                rebuilt = dynamic.build_dynamic_all_fixture(Path(temporary), worker, worker_pin["revision"])
                require(self.manifest_sha == rebuilt.candidate_sha256 and document["source"]["sqliteSha256"] == rebuilt.source_sha256)
                for path in paths - {DYNAMIC_ALL_HTTP_REPORT}:
                    maximum = PACKAGE_LIMITS.get(path, isolation.OBJECT_LIMIT)
                    require(package.read_private(self.root / path, maximum) == package.read_private(rebuilt.candidate / path, maximum))
                report = package.read_private(self.root / DYNAMIC_ALL_HTTP_REPORT, REPORT_LIMIT)
                outcomes = native.parsed(report, REPORT_LIMIT)["outcomes"]
                require(report == _http_report(rebuilt, worker_pin, outcomes))
            self.http_oracle_sha = native.digest(report)
            self.entries = {entry["key"]: entry for entry in document["objects"]}
            self.document = {**document, "sqlMd5": document["sql"]["md5"]}
            self._verify_replay(chain, document, parent)
        except (package.PackageError, package.converter.ConversionError, dynamic.namespace.InventoryError,
                dynamic.temp.InventoryError, migrations.MigrationError, artifact.ArtifactError, native.RehearsalError,
                OSError, sqlite3.Error, ValueError, TypeError, KeyError, RecursionError):
            raise native.RehearsalError(ERROR) from None

    def _verify_replay(self, chain, document, scratch):
        objects = migrations._objects(chain, len(chain), managed=True)
        schema = SimpleNamespace(objects=objects, tables=sorted(obj.name for obj in objects if obj.type == "table"))
        require(document["schemaSha256"] == native._schema_digest(objects))
        sql = self.read_file(document["sql"], package.SQL, SQL_LIMIT, extra={"md5"})
        require(native.file_hash(self.sql, "md5")[1] == document["sql"]["md5"])
        copy = scratch / "dynamic-all-native-readback.sql"
        isolation.put(copy, sql)
        db, layout, summary = native.open_export(copy, schema)
        with closing(db):
            require(native.canonical(layout) == native.canonical(document["layout"])
                    and summary == document["summary"] and document["dataSha256"] == summary["dataSha256"])
            require(document["dynamicAll"]["state"] == document["legacyTempBaseline"]["state"] == "dormant"
                    and document["dynamicAll"]["migrationSha256"] == LEGACY_DYNAMIC_ALL_MIGRATION_SHA256
                    and document["legacyTempBaseline"]["migrationSha256"] == LEGACY_TEMP_MIGRATION_SHA256)
            self._check_summary(summary)
            inventory_sha = document["source"]["tempInventoryManifestSha256"]
            require(db.execute(f"SELECT bot_id,inventory_sha256,cutover_epoch FROM {dynamic.INSTALLATIONS}").fetchall()
                    == [(dynamic.BOT_ID, inventory_sha, None)])
            require(db.execute(f"SELECT count(DISTINCT actor_id),sum(node_count) FROM {dynamic.BATCHES}").fetchone() == (3, 4))
            require(db.execute("SELECT name,seq FROM sqlite_sequence ORDER BY name").fetchall()
                    == [("path_rules", 7), ("subscriptions", dynamic.TARGET_TRASH_ID)]
                    and document["targetSequenceHighWater"] == dynamic.TARGET_TRASH_ID)
            active = db.execute("SELECT id,owner_id,token FROM subscriptions ORDER BY id")
            lineage = [(identity, owner, native.digest(token.encode("ascii"))) for identity, owner, token in active]
            require(native.digest(native.canonical(lineage)) == document["source"]["activeLineageSha256"])
            references = native.object_references(db, lambda key: (self.read_object(self.entries[key]), self.entries[key]["metadata"]))
            require(references == document["objects"])

    def _check_summary(self, summary):
        counts, hashes = summary["tableCounts"], summary["tableSha256"]
        ledger_count = len(self.document["workerArtifact"]["migrations"])
        total = ledger_count + sum(EXPECTED_NONEMPTY.values())
        require(ledger_count >= 40 and native.integer(summary["rowCount"], total, total)
                and {table: count for table, count in counts.items() if count} == {**EXPECTED_NONEMPTY, migrations.LEDGER: ledger_count}
                and all(native.integer(count) for count in counts.values()) and native.integer(counts[dynamic.ORDER], 0, 0)
                and all(hashes[table] == digest for section in ("dynamicAll", "legacyTempBaseline")
                        for table, digest in self.document[section]["tableSha256"].items()))

    def pin(self):
        hashes = self.document["summary"]["tableSha256"]
        return {**super().pin(), "workerManifestSha256": self.document["workerArtifact"]["manifestSha256"],
                "dynamicAllHttpOracleSha256": self.http_oracle_sha,
                "legacyDynamicAllMigrationSha256": LEGACY_DYNAMIC_ALL_MIGRATION_SHA256,
                "legacyTempMigrationSha256": LEGACY_TEMP_MIGRATION_SHA256,
                "activeLineageSha256": self.document["source"]["activeLineageSha256"],
                **{key: hashes[table] for table, key in TABLE_PINS.items()}}

    def native_evidence(self, summary):
        require(summary == self.document["summary"])
        self._check_summary(summary)
        pins = self.pin()
        return {"verifiedDynamicAllCount": 3, "verifiedDynamicAllMarkerCount": 3, "verifiedDynamicAllOrderCount": 0,
                "verifiedTempInstallationCount": 1, "verifiedTempBatchCount": 3, "verifiedTempNodeCount": 4,
                "verifiedTempCutover": "dormant", "verifiedSubscriptionSequenceHighWater": dynamic.TARGET_TRASH_ID,
                "legacyDynamicAllMigrationSha256": pins["legacyDynamicAllMigrationSha256"],
                "legacyTempMigrationSha256": pins["legacyTempMigrationSha256"], "activeLineageSha256": pins["activeLineageSha256"],
                **{key: pins[key] for key in TABLE_PINS.values()}}
