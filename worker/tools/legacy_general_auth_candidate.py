"""Build a sealed, dormant general authorization candidate for a fresh D1."""

from contextlib import closing
from dataclasses import dataclass
from itertools import islice
import os
from pathlib import Path
import sqlite3
import sys
from tempfile import TemporaryDirectory
from types import SimpleNamespace

import d1_migrations as migrations
import legacy_authorization_inventory as inventory
import legacy_authorization_reconcile as preview
import legacy_restore_package as package
from legacy_temp_native_candidate import SQL_LIMIT, _bounded_sql
import native_restore_rehearsal as native
import prepare_isolation_artifact as artifact


PROFILE = "legacy-general-auth-v1"
SCOPE = "fresh-unbound-d1"
ERROR = "The dormant general authorization candidate could not be confirmed safely."
SUCCESS = "Dormant general authorization candidate sealed."
USAGE = ("Usage: legacy_general_auth_candidate.py BACKUP INVENTORY CONFIG TARGET PREVIEW WORKER OUTPUT "
         "SOURCE_SHA256 INVENTORY_SHA256 CONFIG_SHA256 TARGET_SHA256 PREVIEW_SHA256 WORKER_MANIFEST_SHA256 REVISION APPLIED_AT")

INSTALLATION = "general_auth_installation"
PRINCIPALS = "general_auth_principals"
GROUPS = "general_auth_groups"
PROVENANCE = {"source_sha256": "sourceSha256", "source_revision": "sourceRevision",
              "source_deployment_sha256": "sourceDeploymentSha256", "inventory_manifest_sha256": "inventoryManifestSha256",
              "config_sha256": "configSha256", "target_sha256": "targetSha256", "preview_manifest_sha256": "previewManifestSha256"}
COLUMNS = {
    INSTALLATION: ("bot_id", *PROVENANCE, "admin_mode", "unlisted_default"),
    PRINCIPALS: ("bot_id", "user_id", "is_admin", "is_allowlisted", "override_allowed", "override_created_at", "override_updated_at"),
    GROUPS: ("bot_id", "chat_id"),
}
PREVIEW_LIMITS = {inventory.MANIFEST: 4096, inventory.SEAL: 65, inventory.SIDECAR: preview.MAX_OVERRIDE_BYTES,
                  preview.PRINCIPALS: preview.MAX_CONFIG_IDS * 256}


def require(condition):
    native.require(condition, ERROR)


def _id_check(column):
    return (f"{column} GLOB '[1-9]*' AND {column} NOT GLOB '*[^0-9]*' AND length({column})<=16 "
            f"AND CAST({column} AS INTEGER)<={preview.GENERAL_MAX_ID}")


# Candidate-only schema. The serving migration chain never reads this module.
_DDL = {
    INSTALLATION: f"""CREATE TABLE {INSTALLATION} (
        bot_id TEXT PRIMARY KEY NOT NULL CHECK ({_id_check("bot_id")}),
        source_sha256 TEXT NOT NULL,
        source_revision TEXT NOT NULL,
        source_deployment_sha256 TEXT NOT NULL,
        inventory_manifest_sha256 TEXT NOT NULL,
        config_sha256 TEXT NOT NULL,
        target_sha256 TEXT NOT NULL,
        preview_manifest_sha256 TEXT NOT NULL,
        admin_mode TEXT NOT NULL CHECK (admin_mode IN ('inherited','explicit')),
        unlisted_default TEXT NOT NULL CHECK (unlisted_default='denied')
    ) STRICT""",
    PRINCIPALS: f"""CREATE TABLE {PRINCIPALS} (
        bot_id TEXT NOT NULL REFERENCES {INSTALLATION} (bot_id),
        user_id TEXT NOT NULL CHECK ({_id_check("user_id")} AND user_id<>bot_id),
        is_admin INTEGER NOT NULL CHECK (is_admin IN (0,1)),
        is_allowlisted INTEGER NOT NULL CHECK (is_allowlisted IN (0,1)),
        override_allowed INTEGER CHECK (override_allowed IN (0,1)),
        override_created_at INTEGER,
        override_updated_at INTEGER,
        PRIMARY KEY (bot_id,user_id),
        CHECK (is_admin=1 OR is_allowlisted=1 OR override_allowed IS NOT NULL),
        CHECK ((override_allowed IS NULL AND override_created_at IS NULL AND override_updated_at IS NULL)
            OR (override_allowed IS NOT NULL AND override_created_at IS NOT NULL AND override_updated_at IS NOT NULL
                AND override_created_at BETWEEN 1 AND override_updated_at AND override_updated_at<=9007199254740991))
    ) STRICT""",
    GROUPS: f"""CREATE TABLE {GROUPS} (
        bot_id TEXT NOT NULL REFERENCES {INSTALLATION} (bot_id),
        chat_id TEXT NOT NULL CHECK (substr(chat_id,1,1)='-' AND {_id_check("substr(chat_id,2)")}),
        PRIMARY KEY (bot_id,chat_id)
    ) STRICT""",
}
SCHEMA = tuple(migrations.SchemaObject("table", name, name, sql) for name, sql in _DDL.items())


@dataclass(frozen=True)
class UnifiedAuthInput:
    inventory_dir: Path
    config_path: Path
    target_path: Path
    preview_dir: Path
    inventory_sha256: str
    config_sha256: str
    target_sha256: str
    preview_sha256: str


def read_unified_auth_input(path):
    fields = ("inventoryDir", "configPath", "targetPath", "previewDir", "inventorySha256", "configSha256",
              "targetSha256", "previewSha256")
    try:
        document = native.parsed(package.read_private(path, 16 * 1024), 16 * 1024)
        require(set(document) == set(fields)
                and all(isinstance(document[key], str) and Path(document[key]).is_absolute() for key in fields[:4])
                and all(native.matches(native.DIGEST, document[key]) for key in fields[4:]))
        return UnifiedAuthInput(*(Path(document[key]) for key in fields[:4]), *(document[key] for key in fields[4:]))
    except (package.PackageError, package.converter.ConversionError, native.RehearsalError, OSError, ValueError, TypeError):
        raise native.RehearsalError(ERROR) from None


@dataclass(frozen=True)
class VerifiedGeneralAuth:
    domain: dict
    provenance: dict
    rows: dict
    counts: dict


def _read_preview(root, manifest_sha):
    root, parents = inventory._private_parent(root)
    state = inventory._directory_identity(root)

    def exact_tree():
        with os.scandir(root) as entries:
            return {entry.name for entry in islice(entries, len(PREVIEW_LIMITS) + 1)} == set(PREVIEW_LIMITS)

    require(state[2] == os.geteuid() and not state[3] & 0o077 and exact_tree())
    files = {name: preview._private_bytes(root / name, limit) for name, limit in PREVIEW_LIMITS.items()}
    require(inventory._private_parent(root)[1] == parents and inventory._directory_identity(root) == state and exact_tree()
            and native.digest(files[inventory.MANIFEST]) == manifest_sha
            and files[inventory.SEAL] == (manifest_sha + "\n").encode("ascii"))
    return files


def _projection(files, manifest_sha):
    report = native.parsed(files[inventory.MANIFEST], PREVIEW_LIMITS[inventory.MANIFEST])
    require(report["kind"] == "legacy-general-authorization-preview" and report["scope"] == "offline-dormant"
            and report["activationAllowed"] is False and report["unlistedDefault"] == "denied"
            and report["blockers"] == dict.fromkeys(preview.GENERAL_BLOCKERS, 0))
    provenance = {key: report[key] for key in PROVENANCE.values() if key != "previewManifestSha256"}
    provenance["previewManifestSha256"] = manifest_sha
    target = report["target"]
    bot = target["botId"]
    overrides = {}
    for line in files[inventory.SIDECAR].splitlines():
        row = native.parsed(line, 128)
        overrides[row["userId"]] = (row["allowed"], row["createdAt"], row["updatedAt"])
    principals = []
    for line in files[preview.PRINCIPALS].splitlines():
        row = native.parsed(line, 256)
        user = row["userId"]
        principals.append((bot, user, int(row["legacyRole"] == "admin"), int(row["allowlisted"]),
                           *overrides.get(user, (None, None, None))))
    groups = [(bot, group) for group in target["groupChatIds"]]
    require(len(principals) == report["principalRows"] and len(overrides) == report["overrideRows"]
            and overrides.keys() <= {row[1] for row in principals})
    rows = {INSTALLATION: [(bot, *(provenance[key] for key in PROVENANCE.values()), report["adminMode"], "denied")],
            PRINCIPALS: principals, GROUPS: groups}
    counts = {"installations": 1, "principals": len(principals), "groups": len(groups), "overrides": len(overrides)}
    present = report["overrideTablePresent"]
    require(type(present) is bool and (present or not overrides))
    return VerifiedGeneralAuth({"present": present, "rows": len(overrides)}, provenance, rows, counts)


def verify_unified_auth_source(pins: UnifiedAuthInput, *, source: Path, source_sha: str, working_parent: Path,
                               legacy_bot_id=None):
    """Rebuild the closed general preview against the candidate's exact SQLite and Bot."""
    try:
        supplied = _read_preview(pins.preview_dir, pins.preview_sha256)
        with TemporaryDirectory(prefix="general-auth-preview-", dir=working_parent) as temporary:
            rebuilt = Path(temporary) / "preview"
            preview.seal_reconciliation(source, pins.inventory_dir, pins.config_path, pins.target_path, rebuilt,
                                        general_preview=True, source_sha256=source_sha, inventory_sha256=pins.inventory_sha256,
                                        config_sha256=pins.config_sha256, target_sha256=pins.target_sha256)
            require(supplied == _read_preview(rebuilt, pins.preview_sha256))
        result = _projection(supplied, pins.preview_sha256)
        require(result.provenance["sourceSha256"] == source_sha
                and (legacy_bot_id is None or result.rows[INSTALLATION][0][0] == legacy_bot_id))
        return result
    except (inventory.InventoryError, native.RehearsalError, package.PackageError, package.converter.ConversionError,
            OSError, sqlite3.Error, ValueError, TypeError, KeyError, RecursionError, OverflowError):
        raise native.RehearsalError(ERROR) from None


def load_general_auth(db, rows):
    for table, columns in COLUMNS.items():
        marks = ",".join("?" for _ in columns)
        db.executemany(f"INSERT INTO {table} VALUES ({marks})", rows[table])


def verify_general_auth_replay(db, projection):
    for table in COLUMNS:
        require(sorted(db.execute(f"SELECT * FROM {table}").fetchall()) == sorted(projection.rows[table]))


def _write_and_replay(sql, chain, rows, applied_at):
    schema = migrations._objects(chain, len(chain), managed=True) + SCHEMA
    source = SimpleNamespace(objects=schema, tables=sorted(obj.name for obj in schema if obj.type == "table"))
    with closing(sqlite3.connect(":memory:")) as db, db:
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA trusted_schema=OFF")
        for obj in schema:
            if obj.name != "sqlite_sequence":
                db.execute(obj.sql)
        db.executemany(f"INSERT INTO {migrations.LEDGER} VALUES (?,?,?,?,?)",
                       ((index, item.name, item.sha256, "applied", applied_at) for index, item in enumerate(chain, 1)))
        load_general_auth(db, rows)
        layout = native.table_layout(db, source.tables)
        summary = package.db_summary(db, layout)
        package.write_sql(db, schema, 0, sql, extra_tables=COLUMNS)
    body = package.read_private(sql, SQL_LIMIT)
    _bounded_sql(body)
    restored, restored_layout, restored_summary = native.open_export(sql, source)
    with closing(restored):
        require(restored_layout == layout and restored_summary == summary)
    expected = {migrations.LEDGER: len(chain), **{table: len(values) for table, values in rows.items() if values}}
    require({table: count for table, count in summary["tableCounts"].items() if count} == expected)
    return body, schema, layout, summary


def build_candidate(backup, inventory_dir, config, target, preview_dir, worker, output, *,
                    source_sha256, inventory_sha256, config_sha256, target_sha256, preview_sha256,
                    worker_manifest_sha256, revision, applied_at):
    """Rebuild the preview, then seal exact SQL that can only describe a dormant candidate."""
    try:
        require(native.matches(native.DIGEST, preview_sha256) and native.integer(applied_at, 1))
        destination, parents = inventory._private_parent(output)
        inventory_dir, preview_dir, worker = (package.private_path(path, directory=True) for path in (inventory_dir, preview_dir, worker))
        require(not destination.exists() and not destination.is_symlink()
                and all(not destination.is_relative_to(path) for path in (inventory_dir, preview_dir, worker)))
        pins = UnifiedAuthInput(inventory_dir, config, target, preview_dir, inventory_sha256,
                                config_sha256, target_sha256, preview_sha256)
        chain, worker_pin = package.worker_artifact(worker, revision, worker_manifest_sha256)
        verified = verify_unified_auth_source(pins, source=backup, source_sha=source_sha256, working_parent=destination.parent)
        with TemporaryDirectory(prefix="general-auth-candidate-", dir=destination.parent) as temporary:
            scratch = Path(temporary)
            sql = scratch / package.SQL
            body, schema, layout, summary = _write_and_replay(sql, chain, verified.rows, applied_at)
            document = {"version": 1, "profile": PROFILE, "scope": SCOPE, "activationAllowed": False,
                        "counts": verified.counts, "source": verified.provenance, "workerArtifact": worker_pin,
                        "candidateSchemaSha256": native._schema_digest(SCHEMA), "schemaSha256": native._schema_digest(schema),
                        "layout": layout, "summary": summary, "dataSha256": summary["dataSha256"],
                        "sql": {**package.describe(sql), "md5": native.file_hash(sql, "md5")[1]},
                        "objects": [], "objectCount": 0}
            manifest = native.canonical(document)
            require(len(manifest) <= native.MANIFEST_BYTES)
            inventory._seal_package(destination, parents, manifest, {package.SQL: body})
        return {**document, "manifestSha256": native.digest(manifest)}
    except (artifact.ArtifactError, inventory.InventoryError, migrations.MigrationError, native.RehearsalError,
            package.PackageError, package.converter.ConversionError, OSError, sqlite3.Error,
            ValueError, TypeError, KeyError, RecursionError, OverflowError):
        raise native.RehearsalError(ERROR) from None


def main(args=None):
    args = sys.argv[1:] if args is None else args
    if args in (["-h"], ["--help"]):
        print(USAGE)
        return 0
    if len(args) != 15:
        print(USAGE, file=sys.stderr)
        return 2
    paths = map(Path, args[:7])
    source, inventory_sha, config, target, preview_sha, worker, revision, applied_at = args[7:]
    try:
        require(applied_at.isascii() and applied_at.isdecimal() and len(applied_at) <= 16)
        build_candidate(*paths, source_sha256=source, inventory_sha256=inventory_sha, config_sha256=config,
                        target_sha256=target, preview_sha256=preview_sha, worker_manifest_sha256=worker,
                        revision=revision, applied_at=int(applied_at))
    except (native.RehearsalError, ValueError):
        print(ERROR, file=sys.stderr)
        return 2
    print(SUCCESS)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
