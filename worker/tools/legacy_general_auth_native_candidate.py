"""Publish and independently rebuild the fixed dormant authorization rehearsal."""

from contextlib import closing, suppress
from itertools import islice
import os
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory

import legacy_authorization_inventory as inventory
import legacy_authorization_reconcile as preview
import legacy_candidate_isolation as isolation
import legacy_general_auth_candidate as auth
import legacy_restore_package as package
import native_restore_rehearsal as native


PACKAGE_LIMITS = {package.MANIFEST: native.MANIFEST_BYTES, package.MARKER: 65, package.SQL: auth.SQL_LIMIT}
COUNTS = {"installations": 1, "principals": 5, "groups": 2, "overrides": 3}
TABLE_PINS = {auth.INSTALLATION: "generalAuthInstallationSha256", auth.PRINCIPALS: "generalAuthPrincipalsSha256",
              auth.GROUPS: "generalAuthGroupsSha256"}
BOT = "105"
OVERRIDES = ((101, 0, 10, 20), (102, 0, 12, 25), (103, 1, 15, 30))


def candidate_files(document):
    auth.require(isinstance(document, dict) and native.integer(document.get("version"), 1, 1)
                 and document.get("profile") == auth.PROFILE and document.get("scope") == auth.SCOPE
                 and document.get("activationAllowed") is False and document.get("counts") == COUNTS
                 and native.integer(document.get("objectCount"), 0, 0) and document.get("objects") == [])
    return set(PACKAGE_LIMITS)


def build_fixture(worker, output, worker_pin):
    """Only the fixed synthetic inputs can enter the protected rehearsal."""
    output = package.converter._safe_path(output, existing=False)
    with TemporaryDirectory(prefix="general-auth-native-", dir=output.parent) as temporary:
        scratch = Path(temporary)
        backup, sealed, config, target, planned, staged = (
            scratch / name for name in ("legacy.sqlite", "inventory", "config.json", "target.json", "preview", "candidate"))
        with native.private_file(backup):
            pass
        with closing(sqlite3.connect(backup)) as db, db:
            db.execute("""CREATE TABLE auth_overrides (
                user_id INTEGER PRIMARY KEY, allowed INTEGER NOT NULL,
                created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)""")
            db.executemany("INSERT INTO auth_overrides VALUES (?,?,?,?)", OVERRIDES)
        source_sha = native.file_hash(backup)[1]
        inventory.seal_inventory(backup, sealed, source_sha)
        isolation.put(config, inventory._canonical_line({
            "version": 1, "source": {"botId": BOT, "revision": "a" * 40, "deploymentSha256": "b" * 64, "sqliteSha256": source_sha},
            "allowedUserIds": ["102", "104"], "adminUserIds": ["101", "106"],
        }))
        isolation.put(target, inventory._canonical_line({
            "version": 1, "scope": preview.GENERAL_TARGET_SCOPE, "botId": BOT, "groupChatIds": ["-100200", "-100100"],
        }))
        pins = {"source_sha256": source_sha, "inventory_sha256": native.file_hash(sealed / inventory.MANIFEST)[1],
                "config_sha256": native.file_hash(config)[1], "target_sha256": native.file_hash(target)[1]}
        preview.seal_reconciliation(backup, sealed, config, target, planned, **pins, general_preview=True)
        result = auth.build_candidate(
            backup, sealed, config, target, planned, worker, staged, **pins,
            preview_sha256=native.file_hash(planned / inventory.MANIFEST)[1], worker_manifest_sha256=worker_pin["manifestSha256"],
            revision=worker_pin["revision"], applied_at=isolation.APPLIED_AT)
        auth.require(result["workerArtifact"] == worker_pin)
        candidate_files(result)
        output.mkdir(mode=0o700)
        reserved = output.lstat()
        try:
            staged.rename(output)
        except OSError:
            with suppress(OSError):
                if os.path.samestat(reserved, output.lstat()):
                    output.rmdir()
            raise
    return result


class GeneralAuthCandidate(isolation.Candidate):
    def __init__(self, root, worker, worker_pin, scratch):
        self.profile = isolation.GENERAL_AUTH_PROFILE
        self.root = package.private_path(root, directory=True)
        self.sql = self.root / package.SQL
        raw = package.read_private(self.root / package.MANIFEST, PACKAGE_LIMITS[package.MANIFEST])
        document = native.parsed(raw, PACKAGE_LIMITS[package.MANIFEST])
        files = candidate_files(document)
        auth.require({path.name for path in islice(self.root.iterdir(), len(files) + 1)} == files
                     and document.get("workerArtifact") == worker_pin)
        with TemporaryDirectory(prefix="expected-general-auth-", dir=package.private_path(scratch, directory=True)) as temporary:
            rebuilt = Path(temporary) / "candidate"
            expected = build_fixture(worker, rebuilt, worker_pin)
            self.manifest_sha = native.digest(raw)
            auth.require(self.manifest_sha == expected["manifestSha256"])
            for name, limit in PACKAGE_LIMITS.items():
                path = self.root / name
                auth.require(path.lstat().st_nlink == 1 and package.read_private(path, limit) == package.read_private(rebuilt / name, limit))
        self.document = {**document, "sqlMd5": document["sql"]["md5"]}
        self.entries = {}

    def pin(self):
        hashes = self.document["summary"]["tableSha256"]
        return {**super().pin(), "workerManifestSha256": self.document["workerArtifact"]["manifestSha256"],
                "candidateSchemaSha256": self.document["candidateSchemaSha256"],
                "previewManifestSha256": self.document["source"]["previewManifestSha256"],
                **{key: hashes[table] for table, key in TABLE_PINS.items()}}

    def native_evidence(self, summary):
        auth.require(summary == self.document["summary"])
        counts = summary["tableCounts"]
        auth.require((counts[auth.INSTALLATION], counts[auth.PRINCIPALS], counts[auth.GROUPS]) == (1, 5, 2))
        pins = self.pin()
        return {"verifiedGeneralAuthInstallationCount": 1, "verifiedGeneralAuthPrincipalCount": 5,
                "verifiedGeneralAuthGroupCount": 2, "verifiedGeneralAuthOverrideCount": 3, "activationAllowed": False,
                "candidateSchemaSha256": pins["candidateSchemaSha256"], **{key: pins[key] for key in TABLE_PINS.values()}}
