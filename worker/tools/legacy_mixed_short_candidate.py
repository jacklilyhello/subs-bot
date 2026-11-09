"""Verify complete legacy short-link evidence for an unbound restore package."""

from __future__ import annotations

from contextlib import closing
from dataclasses import dataclass, field
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import sqlite3
from tempfile import TemporaryDirectory

import legacy_short_namespace_inventory as namespace_inventory
import legacy_snapshot_convert as converter
import legacy_typed_short_inventory as typed_inventory
import native_restore_rehearsal as native


FAILURE = "Legacy mixed short-link evidence could not be confirmed safely."
MANIFEST_BYTES = 64 * 1024
ORACLE_ROWS = "external.ndjson"
ORACLE_ROWS_BYTES = 4 * 1024**2
ORACLE_OUTCOMES = ("equivalent", "inventory-blocked", "legacy-rejected", "worker-refused", "location-differs", "worker-unconfirmed")
TYPED_FIELDS = ("codeSha256", "legacyTable", "legacyId", "ownerId", "tokenSha256", "format", "createdAt")
VERSION = re.compile(r"(?:0|[1-9][0-9]{0,2})(?:\.(?:0|[1-9][0-9]{0,2})){2}")


class MixedShortError(RuntimeError):
    """A fixed error for untrusted or incomplete mixed namespace evidence."""


@dataclass(frozen=True)
class MixedShortInput:
    source: Path = field(repr=False)
    owner_map: Path = field(repr=False)
    old_origin: str = field(repr=False)
    legacy_bot_id: str
    namespace: Path = field(repr=False)
    namespace_sha256: str
    oracle: Path = field(repr=False)
    oracle_sha256: str
    legacy_python_version: str
    legacy_yarl_version: str


@dataclass(frozen=True)
class SelectedShortRow:
    code_sha256: str
    owner_id: str
    created_at: int
    legacy_ids: tuple[int, ...]
    active_positions: tuple[int, ...]


@dataclass(frozen=True)
class MixedShortRows:
    domain: dict
    typed_rows: list[dict]
    external_rows: list[tuple[str, str, str, int]] = field(repr=False)
    proof: dict
    selected_rows: tuple[SelectedShortRow, ...] = field(default=(), repr=False)
    selected_active_tokens: dict[int, str] = field(default_factory=dict, repr=False)


def _require(condition: object) -> None:
    if not condition:
        raise MixedShortError(FAILURE)


def _private_path(value: Path, *, directory: bool = False) -> Path:
    path = converter._safe_path(value, existing=True, directory=directory)
    info = path.lstat()
    _require(info.st_uid == os.geteuid() and not info.st_mode & 0o077 and (directory or info.st_nlink == 1))
    return path


def _private_bytes(path: Path, maximum: int) -> bytes:
    return converter._bounded_bytes(_private_path(path), maximum)


def read_mixed_short_input(path: Path) -> MixedShortInput:
    """Read an owner-only JSON pin file. Paths are absolute and private."""
    try:
        config = native.parsed(_private_bytes(path, MANIFEST_BYTES), MANIFEST_BYTES)
        _require(set(config) == {"source", "ownerMap", "oldOrigin", "legacyBotId", "namespace", "namespaceSha256",
                                 "oracle", "oracleSha256", "legacyPythonVersion", "legacyYarlVersion"}
                 and all(isinstance(value, str) for value in config.values()))
        source, owners, namespace, oracle = (Path(config[key]) for key in ("source", "ownerMap", "namespace", "oracle"))
        _require(all(value.is_absolute() for value in (source, owners, namespace, oracle)))
        return MixedShortInput(_private_path(source), _private_path(owners), config["oldOrigin"], config["legacyBotId"],
                               _private_path(namespace, directory=True), config["namespaceSha256"],
                               _private_path(oracle, directory=True), config["oracleSha256"],
                               config["legacyPythonVersion"], config["legacyYarlVersion"])
    except (MixedShortError, converter.ConversionError, native.RehearsalError, OSError, ValueError, TypeError):
        raise MixedShortError(FAILURE) from None


def _sealed_directory(directory: Path, rows_name: str, digest: str) -> tuple[bytes, Path]:
    root = _private_path(directory, directory=True)
    manifest_name, seal_name = namespace_inventory.MANIFEST, namespace_inventory.SEAL
    _require(set(os.listdir(root)) == {manifest_name, seal_name, rows_name})
    manifest = _private_bytes(root / manifest_name, MANIFEST_BYTES)
    _require(sha256(manifest).hexdigest() == digest
             and _private_bytes(root / seal_name, 65) == digest.encode("ascii") + b"\n")
    return manifest, _private_path(root / rows_name)


def _source_has_no_sidecars(source: Path) -> bool:
    return not any(os.path.lexists(str(source) + suffix) for suffix in ("-wal", "-shm", "-journal"))


def _collect_rows(source: Path, namespace_rows: Path, owners: dict[str, str], inventory: dict):
    typed_rows, external_rows, selected_rows = [], [], []
    selected_active_tokens = {}
    coalesced_owners = {owner for original, owner in owners.items() if original != owner}
    with closing(sqlite3.connect(source.as_uri() + "?mode=ro&immutable=1", uri=True, isolation_level=None)) as db:
        db.execute("PRAGMA trusted_schema=OFF")
        db.execute("PRAGMA query_only=ON")
        db.execute("PRAGMA cache_size=-2048")
        _require(db.execute("PRAGMA trusted_schema").fetchone() == (0,)
                 and db.execute("PRAGMA query_only").fetchone() == (1,)
                 and db.execute("PRAGMA encoding").fetchone() == ("UTF-8",))
        db.execute("BEGIN")
        rows = db.execute("""
            SELECT rowid, typeof(code), typeof(target_url),
                CASE WHEN typeof(user_id)='integer' THEN user_id END,
                CASE WHEN typeof(created_at)='integer' THEN created_at END
            FROM main.short_links ORDER BY rowid LIMIT ?
        """, (typed_inventory.MAX_SHORTS + 1,))
        # This file was generated in our private scratch from the pinned source.
        with namespace_rows.open("rb") as metadata:
            for record, line in zip(rows, metadata, strict=True):
                rowid, code_type, target_type, issuer, created_at = record
                item = json.loads(line)
                _require(item["state"] == "classified")
                if item["kind"] == "typed-subscription":
                    typed_rows.append({key: item[key] for key in TYPED_FIELDS})
                    continue
                _require(item["kind"] in ("external", "aggregate-selected")
                         and type(issuer) is int and type(created_at) is int)
                code = typed_inventory._text_bytes(db, "short_links", "code", rowid, code_type, 12)
                target, issue = namespace_inventory.read_target(db, rowid, target_type)
                issuer_id = str(issuer)
                _require(typed_inventory._CODE.fullmatch(code) and sha256(code).hexdigest() == item["codeSha256"]
                         and target and issue is None
                         and sha256(target).hexdigest() == item["targetSha256"]
                         and issuer_id == item["sourceIssuerId"] and owners.get(issuer_id, issuer_id) == item["ownerId"]
                         and created_at == item["createdAt"])
                if item["kind"] == "aggregate-selected":
                    legacy_ids = tuple(item["legacyIds"])
                    active_positions = tuple(item["activePositions"])
                    _require(target == namespace_inventory.IDS_PREFIX + b",".join(str(identity).encode("ascii") for identity in legacy_ids))
                    # The Worker applies path rules of the mapped owner. A remap
                    # can change those rules for any still-visible member.
                    _require(not active_positions or (issuer_id == item["ownerId"] and issuer_id not in coalesced_owners))
                    for position in active_positions:
                        identity = legacy_ids[position]
                        if identity not in selected_active_tokens:
                            _require(len(selected_active_tokens) < native.MAX_ROWS)
                            active = db.execute("SELECT user_id, typeof(token) FROM main.subscriptions WHERE id=?",
                                                (identity,)).fetchone()
                            _require(active is not None and type(active[0]) is int and active[0] == issuer)
                            token = typed_inventory._text_bytes(db, "subscriptions", "token", identity, active[1], 128)
                            _require(typed_inventory.TOKEN.fullmatch(token.decode("ascii")))
                            selected_active_tokens[identity] = sha256(token).hexdigest()
                    selected_rows.append(SelectedShortRow(item["codeSha256"], item["ownerId"], created_at,
                                                         legacy_ids, active_positions))
                else:
                    _require(len(target) <= namespace_inventory.MAX_EXTERNAL_BYTES)
                    external_rows.append((item["codeSha256"], item["ownerId"], target.decode("utf-8", "strict"), created_at))
        db.execute("ROLLBACK")
    _require(len(typed_rows) == inventory["kinds"]["typed-subscription"]
             and len(external_rows) == inventory["kinds"]["external"]
             and len(selected_rows) == inventory["kinds"]["aggregate-selected"]
             and len(typed_rows) + len(external_rows) + len(selected_rows) == inventory["rows"])
    return typed_rows, external_rows, selected_rows, selected_active_tokens


def _verify_oracle(pins: MixedShortInput, source_sha: str, worker: dict, source_count: int, external_rows: list) -> dict:
    raw, path = _sealed_directory(pins.oracle, ORACLE_ROWS, pins.oracle_sha256)
    serializer = {"python": pins.legacy_python_version, "aiohttp": "3.11.18", "yarl": pins.legacy_yarl_version}
    # The report follows the source rowid subsequence, before sorting for SQL.
    expected_rows = b"".join(converter._json({"codeSha256": row[0], "state": "equivalent"}) + b"\n"
                             for row in external_rows)
    outcomes = dict.fromkeys(ORACLE_OUTCOMES, 0)
    outcomes["equivalent"] = len(external_rows)
    expected_report = {
        "version": 1, "kind": "legacy-external-redirect-oracle", "scope": "offline-dormant",
        "sourceSha256": source_sha, "inventorySha256": pins.namespace_sha256, "worker": worker,
        "legacySerializer": serializer, "sourceRows": source_count, "externalRows": len(external_rows),
        "inventoryBlockedRows": 0, "outcomes": outcomes,
        "files": [{"file": ORACLE_ROWS, "bytes": len(expected_rows), "sha256": sha256(expected_rows).hexdigest()}],
    }
    _require(raw == converter._json(expected_report) + b"\n" and _private_bytes(path, ORACLE_ROWS_BYTES) == expected_rows)
    return serializer


def read_mixed_shorts(pins: MixedShortInput, *, source_sha: str, owner_map_sha: str, build: dict,
                      worker_manifest_sha: str, working_parent: Path) -> MixedShortRows:
    """Bind every row to the same closed source, verified Worker and trusted oracle seal."""
    return _read_shorts(pins, source_sha, owner_map_sha, build, worker_manifest_sha, working_parent, selected=False)


def read_selected_shorts(pins: MixedShortInput, *, source_sha: str, owner_map_sha: str, build: dict,
                         worker_manifest_sha: str, working_parent: Path) -> MixedShortRows:
    """Consume selected rows only for an explicitly selected dormant package."""
    return _read_shorts(pins, source_sha, owner_map_sha, build, worker_manifest_sha, working_parent, selected=True)


def _read_shorts(pins, source_sha, owner_map_sha, build, worker_manifest_sha, working_parent, *, selected):
    try:
        _require(isinstance(pins, MixedShortInput) and all(native.matches(converter.HASH, digest) for digest in (
            source_sha, owner_map_sha, worker_manifest_sha, pins.namespace_sha256, pins.oracle_sha256,
        )) and native.matches(VERSION, pins.legacy_python_version) and pins.legacy_python_version.startswith("3.")
                 and native.matches(VERSION, pins.legacy_yarl_version))
        worker = {key: build[key] for key in ("revision", "compatibilityDate", "bundleSha256")}
        _require(native.matches(native.REVISION, worker["revision"])
                 and isinstance(worker["compatibilityDate"], str)
                 and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", worker["compatibilityDate"])
                 and native.matches(converter.HASH, worker["bundleSha256"])
                 and build.get("manifestSha256", worker_manifest_sha) == worker_manifest_sha)
        worker["manifestSha256"] = worker_manifest_sha
        source = _private_path(pins.source)
        owners = converter._owner_map(native.parsed(_private_bytes(pins.owner_map, typed_inventory.MAX_METADATA_BYTES),
                                                    typed_inventory.MAX_METADATA_BYTES))
        raw, rows_path = _sealed_directory(pins.namespace, namespace_inventory.ROWS, pins.namespace_sha256)
        _require(_source_has_no_sidecars(source))
        source_state = typed_inventory._source_state(source)
        parent = _private_path(working_parent, directory=True)
        with TemporaryDirectory(prefix=".mixed-shorts-", dir=parent) as temporary:
            reconstructed = Path(temporary) / "namespace"
            namespace_inventory.seal_inventory(source, reconstructed, source_sha256=source_sha, owner_map=owners,
                                               owner_map_sha256=owner_map_sha, old_origin=pins.old_origin,
                                               legacy_bot_id=pins.legacy_bot_id)
            _require(_private_bytes(reconstructed / namespace_inventory.MANIFEST, MANIFEST_BYTES) == raw)
            manifest = native.parsed(raw, MANIFEST_BYTES)
            descriptor, = manifest["files"]
            _require(rows_path.stat().st_size == descriptor["bytes"]
                     and converter._file_hash(rows_path) == (descriptor["bytes"], descriptor["sha256"]))
            inventory = manifest["inventory"]
            kinds = inventory["kinds"]
            _require(inventory["present"] and inventory["blocked"] == 0
                     and kinds["aggregate-all"] == kinds["unclassified"] == 0)
            if selected:
                _require(kinds["aggregate-selected"] > 0)
            else:
                _require(kinds["external"] > 0 and kinds["aggregate-selected"] == 0)
            _require(_source_has_no_sidecars(source) and typed_inventory._source_state(source) == source_state)
            typed_rows, external_rows, selected_rows, active_tokens = _collect_rows(
                source, reconstructed / namespace_inventory.ROWS, owners, inventory)
        typed_inventory._verify_source(source, source_sha, source_state)
        _require(_source_has_no_sidecars(source))
        serializer = _verify_oracle(pins, source_sha, worker, inventory["rows"], external_rows)
        proof = {"namespaceManifestSha256": pins.namespace_sha256, "oracleManifestSha256": pins.oracle_sha256,
                 "oldOriginSha256": manifest["oldOriginSha256"], "legacyBotId": pins.legacy_bot_id,
                 "rows": inventory["rows"], "typedRows": len(typed_rows), "externalRows": len(external_rows),
                 "legacySerializer": serializer}
        if selected:
            proof.update(selectedRows=len(selected_rows), selectedActiveHighWater=inventory["activeHighWater"])
        return MixedShortRows({"present": True, "rows": inventory["rows"]},
                              sorted(typed_rows, key=lambda row: row["codeSha256"]), sorted(external_rows), proof,
                              tuple(sorted(selected_rows, key=lambda row: row.code_sha256)), active_tokens)
    except (MixedShortError, converter.ConversionError, namespace_inventory.InventoryError, typed_inventory.InventoryError,
            native.RehearsalError, OSError, sqlite3.Error, ValueError, TypeError, KeyError, RecursionError, OverflowError):
        raise MixedShortError(FAILURE) from None
