"""Build the fixed synthetic V6 package shared by hosted selected-link rehearsals."""

from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from platform import python_version
import sqlite3

import legacy_candidate_isolation as fixture
import legacy_mixed_short_candidate as mixed
import legacy_restore_package as package
import legacy_short_namespace_inventory as namespace
import legacy_snapshot_convert as converter


OWNER = 123
FOREIGN_OWNER = -100124
OWNER_MAP = {**fixture.OWNER_MAP, str(FOREIGN_OWNER): "457"}
ALPHA, HOLE, EMPTY, BETA, FOREIGN, UNWATCHED = 2, 4, 5, 6, 8, 9
ACTIVE_HIGH_WATER = 50
BETA_TOKEN = "legacy-synthetic-beta-06"
ORDERED_CODE, EMPTY_CODE, HOLE_CODE = "SelPair00001", "SelZero00002", "SelHole00003"
UNKNOWN_CODE, FOREIGN_CODE = "SelMiss00004", "SelBadO00005"
ACTIVE_CODES = (ORDERED_CODE, EMPTY_CODE, HOLE_CODE)
SELECTIONS = ((ORDERED_CODE, (BETA, HOLE, ALPHA, BETA, EMPTY)), (EMPTY_CODE, (EMPTY,)), (HOLE_CODE, (HOLE, HOLE)))
AIOHTTP, YARL = "3.11.18", "1.20.0"
# Keep the same-number historical trash row in the mutable legacy copy even
# when Store.init reaps trash older than 30 days.
FIXTURE_TRASH_AT = 2_100_000_000


@dataclass(frozen=True)
class SelectedFixture:
    source: Path
    source_sha256: str
    candidate: Path
    candidate_sha256: str


def fixture_node(label: str) -> dict:
    server = {
        "alpha": "203.0.113.10", "beta": "203.0.113.20", "trash": "203.0.113.30",
        "foreign": "203.0.113.40", "unwatched": "203.0.113.50", "temp": "203.0.113.60",
    }[label]
    return {"name": f"selected-{label}", "type": "ss", "server": server, "port": 8388, "cipher": "aes-256-gcm",
            "password": "fixture", "share": f"ss://YWVzLTI1Ni1nY206Zml4dHVyZQ@{server}:8388#selected-{label}"}


def selector(*ids: int) -> str:
    return "aggregate://ids/" + ",".join(map(str, ids))


def _source(path: Path) -> None:
    fixture.make_synthetic_source(path, fixture.MIXED_PROFILE)
    with closing(sqlite3.connect(path)) as db, db:
        db.execute("UPDATE subscriptions SET nodes_json=?,node_count=1,last_error=NULL WHERE id=?",
                   (fixture.compact([fixture_node("alpha")]).decode(), ALPHA))
        db.execute("UPDATE deleted_subs SET nodes_json=?,node_count=1,deleted_at=? WHERE id=?",
                   (fixture.compact([fixture_node("trash")]).decode(), FIXTURE_TRASH_AT, HOLE))
        for identity, owner, token, label in (
            (BETA, OWNER, BETA_TOKEN, "beta"),
            (FOREIGN, FOREIGN_OWNER, "legacy-synthetic-foreign-08", "foreign"),
            (UNWATCHED, OWNER, "legacy-synthetic-unwatched-09", "unwatched"),
        ):
            db.execute("INSERT INTO subscriptions VALUES (?,?,?,?,?,NULL,NULL,NULL,?,1,NULL,?,?)",
                       (identity, owner, label, fixture.fixture_source(label), token,
                        fixture.compact([fixture_node(label)]).decode(), fixture.FIXTURE_CREATED, fixture.FIXTURE_UPDATED))
        db.execute("DELETE FROM short_links")
        db.executemany("INSERT INTO short_links VALUES (?,?,?,?)",
                       [(code, OWNER, selector(*ids), fixture.FIXTURE_CREATED) for code, ids in SELECTIONS])
        fixture.require(db.execute("SELECT seq FROM sqlite_sequence WHERE name='subscriptions'").fetchone()
                        == (ACTIVE_HIGH_WATER,))


def seal_selected_inventory(source: Path, destination: Path, source_sha: str, owner_map: dict[str, str]) -> str:
    owner_sha = fixture.native.digest(fixture.native.canonical(owner_map))
    namespace.seal_inventory(source, destination, source_sha256=source_sha, owner_map=owner_map,
                             owner_map_sha256=owner_sha, old_origin=fixture.TYPED_ORIGIN, legacy_bot_id=fixture.TYPED_BOT)
    return fixture.native.file_hash(destination / namespace.MANIFEST)[1]


def _seal_zero_external_rows(path: Path, worker_pin: dict, source_sha: str, inventory_sha: str) -> str:
    # The V6 builder expects a sealed external descriptor even with zero
    # external links. This fixture proves only the selected aggregate domain.
    raw = converter._json({
        "version": 1, "kind": "legacy-external-redirect-oracle", "scope": "offline-dormant",
        "sourceSha256": source_sha, "inventorySha256": inventory_sha,
        "worker": {key: worker_pin[key] for key in ("revision", "compatibilityDate", "bundleSha256", "manifestSha256")},
        "legacySerializer": {"python": python_version(), "aiohttp": AIOHTTP, "yarl": YARL},
        "sourceRows": len(SELECTIONS), "externalRows": 0, "inventoryBlockedRows": 0,
        "outcomes": dict.fromkeys(mixed.ORACLE_OUTCOMES, 0),
        "files": [{"file": mixed.ORACLE_ROWS, "bytes": 0, "sha256": fixture.native.digest(b"")}],
    }) + b"\n"
    manifest_sha = fixture.native.digest(raw)
    path.mkdir(mode=0o700)
    fixture.put(path / mixed.ORACLE_ROWS, b"")
    fixture.put(path / package.MANIFEST, raw)
    fixture.put(path / package.MARKER, manifest_sha.encode("ascii") + b"\n")
    return manifest_sha


def build_selected_fixture(root: Path, worker: Path, revision: str) -> SelectedFixture:
    source, conversion, candidate, inventory, oracle, owners = (
        root / name for name in ("legacy.sqlite", "conversion", "candidate", "namespace", "external-oracle", "owners.json")
    )
    _source(source)
    source_sha = fixture.native.file_hash(source)[1]
    owner_data = fixture.native.canonical(OWNER_MAP)
    fixture.put(owners, owner_data)
    owner_sha = fixture.native.digest(owner_data)
    report = converter.convert_backup(source, conversion, owner_map=OWNER_MAP)
    fixture.require(report["blockers"] == {"unhandled:short_links": len(SELECTIONS)})
    inventory_sha = seal_selected_inventory(source, inventory, source_sha, OWNER_MAP)
    worker_sha = fixture.native.file_hash(worker / "isolation.json")[1]
    _, worker_pin = package.worker_artifact(worker, revision, worker_sha)
    oracle_sha = _seal_zero_external_rows(oracle, worker_pin, source_sha, inventory_sha)
    pin = mixed.MixedShortInput(source, owners, fixture.TYPED_ORIGIN, fixture.TYPED_BOT, inventory, inventory_sha,
                                oracle, oracle_sha, python_version(), YARL)
    report = package.build_candidate(
        conversion, worker, candidate, converter_manifest_sha=fixture.native.file_hash(conversion / package.MANIFEST)[1],
        worker_manifest_sha=worker_sha, revision=revision, applied_at=fixture.APPLIED_AT,
        profile=package.SELECTED_SHORT_PROFILE, source_sqlite_sha=source_sha, owner_map_sha=owner_sha, mixed_short=pin,
    )
    selected = report["selectedAggregateLinks"]
    fixture.require(report["version"] == 6 and report["shortLinkCompatibility"]["selected"] == "not-validated"
                    and (selected["rows"], selected["watchRows"], selected["retiredWatchRows"]) == (3, 4, 1))
    return SelectedFixture(source, source_sha, candidate, report["manifestSha256"])
