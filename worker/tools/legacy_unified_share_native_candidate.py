"""Verify the exact hosted V10 synthetic package before protected native restore."""

from contextlib import closing
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
from types import SimpleNamespace

from cloudflare_isolation import LEGACY_DYNAMIC_ALL_MIGRATION_SHA256, LEGACY_SELECTED_MIGRATION_SHA256, LEGACY_TEMP_MIGRATION_SHA256
import d1_migrations as migrations
import legacy_candidate_isolation as isolation
import legacy_dynamic_all_candidate as dynamic
from legacy_dynamic_all_native_candidate import _verify_tree
import legacy_mixed_short_candidate as mixed
import legacy_private_share_candidate as shares
import legacy_restore_package as package
import legacy_unified_share_native_fixture as fixture
import native_restore_rehearsal as native
import prepare_isolation_artifact as artifact


UNIFIED_SHARE_PROFILE = "synthetic-legacy-unified-shares"
UNIFIED_SHARE_ORACLE_SCOPE = "hosted-synthetic-unified-external-http"
ERROR = "The synthetic unified share restore candidate could not be confirmed safely."
SQL_LIMIT = 256 * 1024
ARCHIVE_LIMIT = 512 * 1024
ORACLE_DIRECTORY = fixture.ORACLE_DIRECTORY
ORACLE_MANIFEST = f"{ORACLE_DIRECTORY}/{package.MANIFEST}"
ORACLE_MARKER = f"{ORACLE_DIRECTORY}/{package.MARKER}"
ORACLE_ROWS = f"{ORACLE_DIRECTORY}/{mixed.ORACLE_ROWS}"
ORACLE_FILES = {ORACLE_MANIFEST, ORACLE_MARKER, ORACLE_ROWS}
PACKAGE_LIMITS = {package.MANIFEST: native.MANIFEST_BYTES, package.MARKER: 65, package.SQL: SQL_LIMIT,
                  package.LINEAGE: isolation.LINEAGE_LIMIT, ORACLE_MANIFEST: 4096, ORACLE_MARKER: 65, ORACLE_ROWS: 1024}
EXPECTED_NONEMPTY = {package.ACTIVE: 4, package.TRASH: 1, package.LIFECYCLE: 1, package.PATH_RULES: 1, package.EMPTY_EXPORTS: 1,
                     package.TYPED_SHORTS: 2, package.EXTERNAL_SHORTS: 1, package.AGGREGATE_LINKS: 4,
                     package.SELECTED_MARKERS: 1, package.SELECTED_WATCHES: 3, dynamic.MARKERS: 3,
                     dynamic.INSTALLATIONS: 1, dynamic.BATCHES: 3, shares.SHARES: 2, shares.CLAIMS: 1, "sqlite_sequence": 3}
TABLE_PINS = {package.TYPED_SHORTS: "typedShortLinksSha256", package.EXTERNAL_SHORTS: "externalShortLinksSha256",
              package.AGGREGATE_LINKS: "aggregateLinksSha256", package.SELECTED_MARKERS: "selectedAggregateMarkersSha256",
              package.SELECTED_WATCHES: "selectedAggregateWatchesSha256", dynamic.MARKERS: "legacyAllAggregatesSha256",
              dynamic.ORDER: "legacyAllSubscriptionOrderSha256", dynamic.INSTALLATIONS: "legacyTempInstallationsSha256",
              dynamic.BATCHES: "legacyTempBatchesSha256", shares.SHARES: "privateSharesSha256",
              shares.CLAIMS: "privateShareClaimsSha256", "sqlite_sequence": "sqliteSequenceSha256"}
MIGRATION_PINS = {"legacySelectedMigrationSha256": LEGACY_SELECTED_MIGRATION_SHA256,
                  "legacyTempMigrationSha256": LEGACY_TEMP_MIGRATION_SHA256,
                  "legacyDynamicAllMigrationSha256": LEGACY_DYNAMIC_ALL_MIGRATION_SHA256,
                  "privateShareMigrationSha256": shares.MIGRATION_SHA256}


def require(condition):
    native.require(condition, ERROR)


def unified_share_object_limit(key):
    """Return the profile limit for one bare, private R2 object key."""
    require(native.matches(native.KEY, key))
    return shares.inventory.MAX_PAYLOAD_BYTES if key.startswith("private-shares/") else isolation.OBJECT_LIMIT


def unified_share_candidate_files(document):
    """Enumerate this profile's exact archive members without trusting its descriptors."""
    require(isinstance(document, dict) and native.integer(document.get("version"), 10, 10)
            and document.get("scope") == "fresh-unbound-d1-r2" and native.integer(document.get("objectCount"), 10, 10))
    objects = document.get("objects")
    require(isinstance(objects, list) and len(objects) == 10)
    paths = set(PACKAGE_LIMITS)
    snapshots = {}
    share_count = 0
    for entry in objects:
        require(isinstance(entry, dict) and set(entry) == {"key", "bytes", "sha256", "metadata"})
        key = entry["key"]
        require(native.integer(entry["bytes"], 1, unified_share_object_limit(key))
                and native.matches(native.DIGEST, entry["sha256"]) and entry["metadata"] == {"custom": {}, "http": {}})
        paths.add("objects/" + key)
        if key.startswith("private-shares/"):
            share_count += 1
        else:
            _, identity, snapshot, name = key.split("/")
            snapshots.setdefault((int(identity), snapshot), set()).add(name)
    require(len(paths) == 17 and share_count == 2 and len(snapshots) == 4
            and {identity for identity, _ in snapshots} == {dynamic.ALPHA_ID, dynamic.BETA_ID, dynamic.FOREIGN_ID, dynamic.TARGET_TRASH_ID}
            and all(names == {"manifest.json", "0.ndjson"} for names in snapshots.values()))
    return paths


def _member_limit(path):
    if path in PACKAGE_LIMITS:
        return PACKAGE_LIMITS[path]
    return unified_share_object_limit(path.removeprefix("objects/"))


def _oracle_pin(root, source, worker_pin):
    digest = source["oracleManifestSha256"]
    raw = package.read_pinned(root / ORACLE_MANIFEST, PACKAGE_LIMITS[ORACLE_MANIFEST], digest)
    require(package.read_private(root / ORACLE_MARKER, PACKAGE_LIMITS[ORACLE_MARKER]) == (digest + "\n").encode("ascii"))
    rows = package.converter._json({"codeSha256": native.digest(fixture.EXTERNAL_CODE.encode("ascii")), "state": "equivalent"}) + b"\n"
    require(package.read_private(root / ORACLE_ROWS, PACKAGE_LIMITS[ORACLE_ROWS]) == rows)
    outcomes = dict.fromkeys(mixed.ORACLE_OUTCOMES, 0)
    outcomes["equivalent"] = 1
    expected = {"version": 1, "kind": "legacy-external-redirect-oracle", "scope": "offline-dormant",
                "sourceSha256": source["sqliteSha256"], "inventorySha256": source["namespaceManifestSha256"],
                "worker": {key: worker_pin[key] for key in ("revision", "compatibilityDate", "bundleSha256", "manifestSha256")},
                "legacySerializer": {"python": fixture.PYTHON_VERSION, "aiohttp": "3.11.18", "yarl": fixture.YARL_VERSION},
                "sourceRows": 7, "externalRows": 1, "inventoryBlockedRows": 0, "outcomes": outcomes,
                "files": [{"file": mixed.ORACLE_ROWS, "bytes": len(rows), "sha256": native.digest(rows)}]}
    require(raw == package.converter._json(expected) + b"\n")
    return digest


class UnifiedShareCandidate(isolation.Candidate):
    def __init__(self, root, worker, worker_pin, scratch):
        self.profile = UNIFIED_SHARE_PROFILE
        try:
            self.root = package.private_path(root, directory=True)
            self.sql = self.root / package.SQL
            raw = package.read_private(self.root / package.MANIFEST, PACKAGE_LIMITS[package.MANIFEST])
            document = native.parsed(raw, PACKAGE_LIMITS[package.MANIFEST])
            paths = unified_share_candidate_files(document)
            _verify_tree(self.root, paths)
            require(sum((self.root / path).lstat().st_size for path in paths) <= ARCHIVE_LIMIT)
            chain, pinned_worker = package.worker_artifact(worker, worker_pin["revision"], worker_pin["manifestSha256"])
            require(pinned_worker == worker_pin and document["workerArtifact"] == worker_pin)
            self.manifest_sha = native.digest(raw)
            self.oracle_manifest_sha = _oracle_pin(self.root, document["source"], worker_pin)
            parent = package.private_path(scratch, directory=True)
            with TemporaryDirectory(prefix="expected-unified-share-", dir=parent) as temporary:
                rebuilt = fixture.build_unified_share_fixture(
                    Path(temporary), worker, worker_pin["revision"], oracle=self.root / ORACLE_DIRECTORY)
                require(self.manifest_sha == rebuilt.candidate_sha256 and document["source"]["sqliteSha256"] == rebuilt.source_sha256)
                for path in sorted(paths - ORACLE_FILES):
                    maximum = _member_limit(path)
                    require(package.read_private(self.root / path, maximum) == package.read_private(rebuilt.candidate / path, maximum))
            self.entries = {entry["key"]: entry for entry in document["objects"]}
            self.document = {**document, "sqlMd5": document["sql"]["md5"]}
            self._verify_replay(chain, document, parent)
        except (package.PackageError, package.converter.ConversionError, migrations.MigrationError, artifact.ArtifactError,
                dynamic.namespace.InventoryError, dynamic.temp.InventoryError, shares.inventory.InventoryError,
                native.RehearsalError, OSError, sqlite3.Error, ValueError, TypeError, KeyError, RecursionError, OverflowError):
            raise native.RehearsalError(ERROR) from None

    def _verify_replay(self, chain, document, scratch):
        objects = migrations._objects(chain, len(chain), managed=True)
        schema = SimpleNamespace(objects=objects, tables=sorted(obj.name for obj in objects if obj.type == "table"))
        require(document["schemaSha256"] == native._schema_digest(objects))
        sql = self.read_file(document["sql"], package.SQL, SQL_LIMIT, extra={"md5"})
        require(native.file_hash(self.sql, "md5")[1] == document["sql"]["md5"])
        with TemporaryDirectory(prefix="unified-share-readback-", dir=scratch) as temporary:
            copy = Path(temporary) / package.SQL
            isolation.put(copy, sql)
            db, layout, summary = native.open_export(copy, schema)
            with closing(db):
                require(native.canonical(layout) == native.canonical(document["layout"])
                        and summary == document["summary"] and document["dataSha256"] == summary["dataSha256"])
                self._check_summary(summary)
                self._check_rows(db, chain)
                references = native.object_references(
                    db, lambda key: (self.read_object(self.entries[key]), self.entries[key]["metadata"]))
                require(references == document["objects"])

    def _check_rows(self, db, chain):
        document = self.document
        ledger = [{"position": i, "name": migration.name, "sha256": migration.sha256, "mode": "applied",
                   "applied_at": fixture.APPLIED_AT} for i, migration in enumerate(chain, 1)]
        require(document["ledger"] == ledger and db.execute(
            f"SELECT position,name,sha256,mode,applied_at FROM {migrations.LEDGER} ORDER BY position").fetchall()
            == [tuple(row.values()) for row in ledger])
        package.verify_short_namespace(db, 7)
        require(db.execute(f"SELECT id,retired FROM {package.SELECTED_WATCHES} ORDER BY id").fetchall()
                == [(dynamic.ALPHA_ID, 0), (dynamic.LEGACY_TRASH_ID, 1), (dynamic.BETA_ID, 0)])
        require(db.execute(f"SELECT bot_id,inventory_sha256,cutover_epoch FROM {dynamic.INSTALLATIONS}").fetchall()
                == [(dynamic.BOT_ID, document["source"]["tempInventoryManifestSha256"], None)])
        require(db.execute(f"SELECT count(DISTINCT actor_id),sum(node_count) FROM {dynamic.BATCHES}").fetchone() == (3, 4))
        require(db.execute("SELECT name,seq FROM sqlite_sequence ORDER BY name").fetchall()
                == [("path_rules", 7), ("private_shares", 2), ("subscriptions", dynamic.TARGET_TRASH_ID)]
                and document["targetSequenceHighWater"] == dynamic.TARGET_TRASH_ID)
        active = db.execute("SELECT id,owner_id,token FROM subscriptions ORDER BY id")
        lineage = [(identity, owner, native.digest(token.encode("ascii"))) for identity, owner, token in active]
        require(native.digest(native.canonical(lineage)) == document["source"]["activeLineageSha256"])

        targeted, expired = (native.digest(code.encode("ascii")) for code in (fixture.TARGET_CODE, fixture.EXPIRED_CODE))
        exact = {
            targeted: (dynamic.OWNER, 2, dynamic.TEMP_ONLY_OWNER, fixture.TARGET_EXPIRES_AT, fixture.TARGET_PAYLOAD),
            expired: (dynamic.FOREIGN_OWNER, 1, None, fixture.EXPIRED_AT, fixture.EXPIRED_PAYLOAD),
        }
        rows = db.execute("""SELECT id,bot_id,code_sha256,sender_id,sender_name,payload_id,max_claims,target_user_id,created_at,expire_at
            FROM private_shares ORDER BY id""").fetchall()
        require([(row[0], row[2]) for row in rows] == list(enumerate(sorted(exact), 1)))
        claims = []
        for identity, bot, code, sender, name, payload_id, maximum, recipient, created, expires in rows:
            expected_sender, expected_maximum, expected_recipient, expected_expiry, payload = exact[code]
            require((bot, sender, name, maximum, recipient, created, expires)
                    == (dynamic.BOT_ID, expected_sender, fixture.SENDER_NAME, expected_maximum, expected_recipient,
                        dynamic.CREATED_AT, expected_expiry))
            key = f"private-shares/{payload_id}.txt"
            require(self.read_object(self.entries[key]) == payload.encode("utf-8"))
            if code == targeted:
                claims.append((identity, recipient, expires))
        require(db.execute("SELECT share_id,actor_id,claimed_at FROM private_share_claims").fetchall() == claims)

    def _check_summary(self, summary):
        document = self.document
        counts, hashes = summary["tableCounts"], summary["tableSha256"]
        ledger_count = len(document["workerArtifact"]["migrations"])
        total = ledger_count + sum(EXPECTED_NONEMPTY.values())
        require(ledger_count >= 40 and native.integer(summary["rowCount"], total, total)
                and {table: count for table, count in counts.items() if count} == {**EXPECTED_NONEMPTY, migrations.LEDGER: ledger_count}
                and all(native.integer(count) for count in counts.values()) and native.integer(counts[dynamic.ORDER], 0, 0))
        selected, all_links, temp, private = (document[key] for key in (
            "selectedAggregateLinks", "dynamicAll", "legacyTempBaseline", "privateShares"))
        require([selected[key] for key in ("rows", "watchRows", "retiredWatchRows")] == [1, 3, 1]
                and [all_links[key] for key in ("rows", "markers", "orderRows", "state")] == [3, 3, 0, "dormant"]
                and [temp[key] for key in ("installations", "batches", "nodes", "owners", "state")] == [1, 3, 4, 3, "dormant"]
                and [private[key] for key in ("rows", "claimRows", "inlineMessageRows", "objectCount")] == [2, 1, 1, 2]
                and [part["migrationSha256"] for part in (selected, all_links, temp, private)] == [
                    LEGACY_SELECTED_MIGRATION_SHA256, LEGACY_DYNAMIC_ALL_MIGRATION_SHA256,
                    LEGACY_TEMP_MIGRATION_SHA256, shares.MIGRATION_SHA256])
        require(all(hashes[table] == digest for section in (selected, all_links, temp, private)
                    for table, digest in section["tableSha256"].items())
                and document["typedShortLinks"]["tableSha256"] == hashes[package.TYPED_SHORTS]
                and document["externalShortLinks"]["tableSha256"] == hashes[package.EXTERNAL_SHORTS]
                and document["shortLinkCompatibility"] == {"typed": "not-validated", "external": "offline-equivalent",
                                                            "selected": "not-validated", "dynamicAll": "not-validated"}
                and document["shareCompatibility"] == "not-validated")

    def read_object(self, entry):
        path = "objects/" + entry["key"]
        return self.read_file({"path": path, "bytes": entry["bytes"], "sha256": entry["sha256"]}, path,
                              unified_share_object_limit(entry["key"]))

    def pin(self):
        hashes = self.document["summary"]["tableSha256"]
        return {**super().pin(), **MIGRATION_PINS, "workerManifestSha256": self.document["workerArtifact"]["manifestSha256"],
                "unifiedShareOracleManifestSha256": self.oracle_manifest_sha,
                "activeLineageSha256": self.document["source"]["activeLineageSha256"],
                **{key: hashes[table] for table, key in TABLE_PINS.items()}}

    def native_evidence(self, summary):
        require(summary == self.document["summary"])
        self._check_summary(summary)
        pins = self.pin()
        return {"verifiedDynamicAllCount": 3, "verifiedDynamicAllMarkerCount": 3, "verifiedDynamicAllOrderCount": 0,
                "verifiedTempInstallationCount": 1, "verifiedTempBatchCount": 3, "verifiedTempNodeCount": 4,
                "verifiedTempCutover": "dormant", "verifiedSubscriptionSequenceHighWater": dynamic.TARGET_TRASH_ID,
                "verifiedTypedShortLinkCount": 2, "verifiedExternalShortLinkCount": 1, "verifiedSelectedAggregateCount": 1,
                "verifiedSelectedMarkerCount": 1, "verifiedSelectedWatchCount": 3, "verifiedRetiredSelectedWatchCount": 1,
                "verifiedPrivateShareCount": 2, "verifiedPrivateShareClaimCount": 1, "verifiedShareSequenceHighWater": 2,
                "sourceInlineMessageRows": 1, "verifiedShortNamespaceCount": 7, "activeLineageSha256": pins["activeLineageSha256"],
                **{key: pins[key] for key in (*MIGRATION_PINS, *TABLE_PINS.values())}}
