"""Verify the fixed V6 synthetic candidate before any native restore operation."""

from contextlib import closing
from pathlib import Path
import sqlite3
from types import SimpleNamespace

import d1_migrations as migrations
import legacy_candidate_isolation as isolation
import legacy_restore_package as package
import native_restore_rehearsal as native
import prepare_isolation_artifact as artifact


SELECTED_PROFILE = "synthetic-legacy-selected-aggregates"
SELECTED_HTTP_REPORT = "selected-http-oracle.json"
SELECTED_HTTP_REPORT_LIMIT = 4096
SELECTED_HTTP_SCOPE = "hosted-synthetic-selected-http"
ERROR = "The synthetic legacy selected restore candidate could not be confirmed safely."
OBJECT_COUNT = 12
EXPECTED_COUNTS = {package.AGGREGATE_LINKS: 3, package.SELECTED_MARKERS: 3, package.SELECTED_WATCHES: 4}
TABLE_PINS = {package.AGGREGATE_LINKS: "selectedAggregateLinksSha256",
              package.SELECTED_MARKERS: "selectedAggregateMarkersSha256",
              package.SELECTED_WATCHES: "selectedAggregateWatchesSha256",
              "sqlite_sequence": "sqliteSequenceSha256"}
HTTP_COUNTS = {"requestCountPerRuntime": 50, "export-exact": 16, "clash-semantic": 2,
               "singbox-semantic": 1, "redirect-framing-differs": 3, "not-found": 3}
HTTP_RESULTS = {"legacy-lifecycle": "confirmed", "foreign-source-policy": "blocked"}
WORKER_PIN_FIELDS = ("revision", "runId", "runAttempt", "manifestSha256", "bundleSha256", "compatibilityDate")
PACKAGE_LIMITS = {package.MANIFEST: native.MANIFEST_BYTES, package.MARKER: 65, package.SQL: isolation.SQL_LIMIT,
                  package.LINEAGE: isolation.LINEAGE_LIMIT, SELECTED_HTTP_REPORT: SELECTED_HTTP_REPORT_LIMIT}


def require(condition):
    native.require(condition, ERROR)


def selected_candidate_files(document):
    """Return the closed inventory for the selected profile only."""
    require(isinstance(document, dict) and document.get("version") == 6
            and document.get("scope") == "fresh-unbound-d1-r2"
            and native.integer(document.get("objectCount"), OBJECT_COUNT, OBJECT_COUNT))
    objects = document.get("objects")
    require(isinstance(objects, list) and len(objects) == OBJECT_COUNT)
    files = set(PACKAGE_LIMITS)
    for entry in objects:
        require(isinstance(entry, dict) and set(entry) == {"key", "bytes", "sha256", "metadata"}
                and native.matches(native.KEY, entry["key"]) and entry["key"].startswith("subscriptions/")
                and native.integer(entry["bytes"], 1, isolation.OBJECT_LIMIT)
                and native.matches(native.DIGEST, entry["sha256"]) and entry["metadata"] == {"custom": {}, "http": {}})
        files.add("objects/" + entry["key"])
    require(len(files) == len(PACKAGE_LIMITS) + OBJECT_COUNT)
    return files


def _http_report(fixture, worker_pin, outcomes):
    worker = {field: worker_pin.get(field) for field in WORKER_PIN_FIELDS}
    require(native.matches(native.REVISION, worker["revision"])
            and all(native.matches(artifact._DECIMAL, worker[field]) for field in ("runId", "runAttempt"))
            and all(native.matches(native.DIGEST, value) for value in (
                worker["manifestSha256"], worker["bundleSha256"], fixture.source_sha256, fixture.candidate_sha256))
            and isinstance(worker["compatibilityDate"], str))
    require(isinstance(outcomes, dict) and set(outcomes) == set(HTTP_COUNTS) | set(HTTP_RESULTS) | {"head-length-omitted"}
            and all(native.integer(outcomes[key], count, count) for key, count in HTTP_COUNTS.items())
            and all(outcomes[key] == result for key, result in HTTP_RESULTS.items())
            and native.integer(outcomes["head-length-omitted"], 0, HTTP_COUNTS["requestCountPerRuntime"]))
    return native.canonical({"version": 1, "scope": SELECTED_HTTP_SCOPE, "worker": worker,
                             "sourceSha256": fixture.source_sha256, "packageManifestSha256": fixture.candidate_sha256,
                             "legacySerializer": {"python": "3.11.18", "aiohttp": "3.11.18", "yarl": "1.20.0"},
                             "outcomes": outcomes})


def seal_selected_http_report(fixture, worker_pin, outcomes):
    """Seal only the redacted outcome of an already successful two-runtime probe."""
    raw = _http_report(fixture, worker_pin, outcomes)
    require(len(raw) <= SELECTED_HTTP_REPORT_LIMIT)
    isolation.put(fixture.candidate / SELECTED_HTTP_REPORT, raw)
    return native.digest(raw)


class SelectedCandidate(isolation.Candidate):
    def __init__(self, root, worker, worker_pin, scratch):
        # The fixture reuses the V5 source writer. Import only on the V6 path.
        import legacy_selected_oracle_fixture as fixture

        self.profile = SELECTED_PROFILE
        try:
            self.root = package.private_path(root, directory=True)
            self.sql = self.root / package.SQL
            raw = package.read_private(self.root / package.MANIFEST, native.MANIFEST_BYTES)
            document = native.parsed(raw, native.MANIFEST_BYTES)
            paths = selected_candidate_files(document)
            require({path.relative_to(self.root).as_posix() for path in self.root.rglob("*")
                     if path.is_file() or path.is_symlink()} == paths)

            chain, pinned_worker = package.worker_artifact(worker, worker_pin["revision"], worker_pin["manifestSha256"])
            require(pinned_worker == worker_pin and document["workerArtifact"] == worker_pin)
            expected_root = Path(scratch) / "expected-selected"
            expected_root.mkdir(mode=0o700)
            rebuilt = fixture.build_selected_fixture(expected_root, worker, worker_pin["revision"])
            for path in paths - {SELECTED_HTTP_REPORT}:
                maximum = PACKAGE_LIMITS.get(path, isolation.OBJECT_LIMIT)
                require(package.read_private(self.root / path, maximum) == package.read_private(rebuilt.candidate / path, maximum))
            self.manifest_sha = native.digest(raw)
            require(self.manifest_sha == rebuilt.candidate_sha256 and document["source"]["sqliteSha256"] == rebuilt.source_sha256)
            proof = package.read_private(self.root / SELECTED_HTTP_REPORT, SELECTED_HTTP_REPORT_LIMIT)
            require(proof == _http_report(rebuilt, worker_pin, native.parsed(proof, SELECTED_HTTP_REPORT_LIMIT)["outcomes"]))
            self.http_oracle_sha = native.digest(proof)

            self.entries = {entry["key"]: entry for entry in document["objects"]}
            self.document = {**document, "sqlMd5": document["sql"]["md5"]}
            self._verify_replay(chain, document, fixture, Path(scratch))
        except (package.PackageError, package.converter.ConversionError, migrations.MigrationError, artifact.ArtifactError,
                native.RehearsalError, OSError, sqlite3.Error, ValueError, TypeError, KeyError, RecursionError):
            raise native.RehearsalError(ERROR) from None

    def _verify_replay(self, chain, document, fixture, scratch):
        objects = migrations._objects(chain, len(chain), managed=True)
        schema = SimpleNamespace(objects=objects, tables=sorted(obj.name for obj in objects if obj.type == "table"))
        require(document["schemaSha256"] == native._schema_digest(objects))
        sql = self.read_file(document["sql"], package.SQL, isolation.SQL_LIMIT, extra={"md5"})
        require(native.file_hash(self.sql, "md5")[1] == document["sql"]["md5"])
        sql_copy = scratch / "selected-native-readback.sql"
        isolation.put(sql_copy, sql)
        db, layout, summary = native.open_export(sql_copy, schema)
        with closing(db):
            require(native.canonical(layout) == native.canonical(document["layout"])
                    and summary == document["summary"] and document["dataSha256"] == summary["dataSha256"])
            links = sorted((native.digest(code.encode("ascii")), str(fixture.OWNER), "selected", None,
                            native.canonical(ids).decode("ascii"), isolation.FIXTURE_CREATED, None)
                           for code, ids in fixture.SELECTIONS)
            markers = [(link[0],) for link in links]
            watches = [(identity, int(identity == fixture.HOLE)) for identity in
                       sorted({identity for _, ids in fixture.SELECTIONS for identity in ids})]
            package.verify_selected_aggregate_links(db, {package.AGGREGATE_LINKS: links,
                package.SELECTED_MARKERS: markers, package.SELECTED_WATCHES: watches}, isolation.EMPTY_TARGET_SEQUENCE)
            require(document["targetSequenceHighWater"] == isolation.EMPTY_TARGET_SEQUENCE
                    and document["selectedAggregateLinks"]["retiredWatchRows"] == sum(retired for _, retired in watches)
                    and all(summary["tableCounts"][table] == 0 for table in
                            (package.TYPED_SHORTS, package.EXTERNAL_SHORTS, "telegram_inbox")))
            references = native.object_references(db, lambda key: (self.read_object(self.entries[key]), self.entries[key]["metadata"]))
            require(references == document["objects"])

    def pin(self):
        hashes = self.document["summary"]["tableSha256"]
        return {**super().pin(), "workerManifestSha256": self.document["workerArtifact"]["manifestSha256"],
                "selectedHttpOracleSha256": self.http_oracle_sha, "legacySelectedMigrationSha256": package.LEGACY_SELECTED_MIGRATION_SHA256,
                **{key: hashes[table] for table, key in TABLE_PINS.items()}}

    def native_evidence(self, observed_summary):
        require(observed_summary == self.document["summary"])
        counts, hashes = observed_summary["tableCounts"], observed_summary["tableSha256"]
        pins = self.pin()
        require(all(native.integer(counts[table], count, count) for table, count in EXPECTED_COUNTS.items())
                and all(hashes[table] == pins[key] for table, key in TABLE_PINS.items()))
        return {"verifiedSelectedAggregateCount": counts[package.AGGREGATE_LINKS],
                "verifiedSelectedMarkerCount": counts[package.SELECTED_MARKERS],
                "verifiedSelectedWatchCount": counts[package.SELECTED_WATCHES],
                "verifiedRetiredSelectedWatchCount": self.document["selectedAggregateLinks"]["retiredWatchRows"],
                "verifiedSubscriptionSequenceHighWater": self.document["targetSequenceHighWater"],
                "legacySelectedMigrationSha256": pins["legacySelectedMigrationSha256"],
                **{key: hashes[table] for table, key in TABLE_PINS.items()}}
