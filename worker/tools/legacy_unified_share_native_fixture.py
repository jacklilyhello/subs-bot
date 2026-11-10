"""Fixed synthetic sources for the unbound unified restore packages."""

from contextlib import closing
from dataclasses import dataclass, field
from pathlib import Path
import os
import sqlite3
import stat
from tempfile import TemporaryDirectory

import legacy_dynamic_all_candidate as dynamic
from legacy_mixed_short_candidate import MANIFEST_BYTES as ORACLE_MANIFEST_BYTES, MixedShortInput, ORACLE_ROWS
from legacy_private_share_candidate import UnifiedShareInput
from legacy_private_share_fixture import code
import legacy_private_share_inventory as shares
import legacy_restore_package as package
import native_restore_rehearsal as native
import prepare_isolation_artifact as artifact


ERROR = "The synthetic unified share candidate could not be confirmed safely."
PYTHON_VERSION = "3.11.18"
YARL_VERSION = "1.20.0"
APPLIED_AT = 1_800_000_000
ORACLE_DIRECTORY = "oracle"
ORACLE_FILES = (package.MANIFEST, package.MARKER, ORACLE_ROWS)
ACTIVE_CODE, TRASH_CODE, EXTERNAL_CODE, SELECTED_CODE = (
    "UnifiedAct01", "UnifiedDel01", "UnifiedExt01", "UnifiedSel01",
)
EXTERNAL_URL = "https://example.org/fixture?mode=exact#keep"
SELECTED_IDS = (dynamic.BETA_ID, dynamic.LEGACY_TRASH_ID, dynamic.ALPHA_ID, dynamic.BETA_ID)
BOT_USERNAME = "synthetic_unified_bot"
TARGET_CODE, EXPIRED_CODE = code(6), code(13)
TARGET_PAYLOAD = "\ufeff  合成私密正文\r\n\0  \n"
EXPIRED_PAYLOAD = "expired share — fixture\r\n"
INLINE_ID = "synthetic-old-inline-message-reference"
SENDER_NAME = "  合成发送者  "
TARGET_EXPIRES_AT, EXPIRED_AT = 2_100_000_000, dynamic.CREATED_AT + 30
AUTH_ARTIFACT_PREFIX = "subs-bot-legacy-unified-auth-candidate"
AUTH_COUNTS = {"installations": 1, "principals": 3, "groups": 2, "overrides": 2}
AUTH_OVERRIDES = ((int(dynamic.OWNER), 0, 10, 20), (int(dynamic.TEMP_ONLY_OWNER), 1, 11, 30))
AUTH_GROUPS = ("-100200", "-100100")
AUTH_SQL_LIMIT = 256 * 1024
AUTH_ARCHIVE_LIMIT = 512 * 1024


@dataclass(frozen=True)
class UnifiedShareFixture:
    source: Path = field(repr=False)
    source_sha256: str
    candidate: Path = field(repr=False)
    candidate_sha256: str


def require(condition):
    native.require(condition, ERROR)


def make_synthetic_source(path: Path):
    dynamic.make_synthetic_source(path)
    with closing(sqlite3.connect(path)) as db, db:
        owner = int(dynamic.OWNER)
        db.executemany("INSERT INTO short_links VALUES (?,?,?,?)", (
            (ACTIVE_CODE, owner, f"{dynamic.OLD_ORIGIN}/sub/{dynamic.fixture_token('alpha')}/clash", APPLIED_AT),
            (TRASH_CODE, owner, f"{dynamic.OLD_ORIGIN}/sub/{dynamic.fixture_token('trash')}/v2ray", APPLIED_AT),
            (EXTERNAL_CODE, owner, EXTERNAL_URL, APPLIED_AT),
            (SELECTED_CODE, owner, "aggregate://ids/" + ",".join(map(str, SELECTED_IDS)), APPLIED_AT),
        ))
        db.execute("""CREATE TABLE shares (
            code TEXT PRIMARY KEY, sender_id INTEGER NOT NULL, sender_name TEXT NOT NULL, content TEXT NOT NULL,
            max_views INTEGER NOT NULL DEFAULT 1, claimed_count INTEGER NOT NULL DEFAULT 0, target_user_id INTEGER,
            expire_at INTEGER NOT NULL, created_at INTEGER NOT NULL)""")
        db.execute("""CREATE TABLE share_claims (
            id INTEGER PRIMARY KEY AUTOINCREMENT, share_code TEXT NOT NULL, user_id INTEGER NOT NULL,
            claimed_at INTEGER NOT NULL, UNIQUE(share_code, user_id))""")
        target = int(dynamic.TEMP_ONLY_OWNER)
        db.executemany("INSERT INTO shares VALUES (?,?,?,?,?,?,?,?,?)", (
            (TARGET_CODE, owner, SENDER_NAME, TARGET_PAYLOAD, 2, 1, target, TARGET_EXPIRES_AT, dynamic.CREATED_AT),
            (EXPIRED_CODE, int(dynamic.FOREIGN_OWNER), SENDER_NAME, EXPIRED_PAYLOAD, 1, 0, None, EXPIRED_AT, dynamic.CREATED_AT),
        ))
        db.execute("ALTER TABLE shares ADD COLUMN inline_message_id TEXT")
        db.execute("UPDATE shares SET inline_message_id=? WHERE code=?", (INLINE_ID, TARGET_CODE))
        db.execute("INSERT INTO share_claims VALUES (?,?,?,?)", (41, TARGET_CODE, target, TARGET_EXPIRES_AT))


def _verify_files(staged, report, *, with_oracle):
    raw = package.read_pinned(staged / package.MANIFEST, native.MANIFEST_BYTES, report["manifestSha256"])
    manifest = native.parsed(raw, native.MANIFEST_BYTES)
    require(package.read_private(staged / package.MARKER, 65) == report["manifestSha256"].encode("ascii") + b"\n")
    keys = {row["key"] for row in manifest["objects"]}
    require(len(keys) == 10 and sum(key.startswith("private-shares/") for key in keys) == 2
            and all(native.matches(native.KEY, key) for key in keys))
    files = {Path(name) for name in (package.MANIFEST, package.MARKER, package.LINEAGE, package.SQL)}
    files.update(Path("objects") / key for key in keys)
    if with_oracle:
        files.update(Path(ORACLE_DIRECTORY) / name for name in ORACLE_FILES)
    directories = {parent for file in files for parent in file.parents if parent != Path(".")}
    entries = {path.relative_to(staged): path.lstat() for path in staged.rglob("*")}
    require(entries.keys() == files | directories)
    for path, info in entries.items():
        require(info.st_uid == os.geteuid())
        if path in directories:
            require(stat.S_IMODE(info.st_mode) == 0o700 and stat.S_ISDIR(info.st_mode))
        else:
            require(stat.S_IMODE(info.st_mode) == 0o600 and stat.S_ISREG(info.st_mode) and info.st_nlink == 1)
    if manifest["version"] == 11:
        require(0 < entries[Path(package.SQL)].st_size <= AUTH_SQL_LIMIT
                and sum(entries[path].st_size for path in files) <= AUTH_ARCHIVE_LIMIT)


def _add_authorization(source):
    with closing(sqlite3.connect(source)) as db, db:
        db.execute("""CREATE TABLE auth_overrides (
            user_id INTEGER PRIMARY KEY, allowed INTEGER NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)""")
        db.executemany("INSERT INTO auth_overrides VALUES (?,?,?,?)", AUTH_OVERRIDES)


def _seal_authorization(source, source_sha, scratch):
    import legacy_general_auth_candidate as auth

    inventory, config, target, preview = (scratch / name for name in ("auth-inventory", "auth-config.json", "auth-target.json", "auth-preview"))
    auth.inventory.seal_inventory(source, inventory, source_sha)
    with native.private_file(config) as file:
        file.write(auth.inventory._canonical_line({"version": 1, "source": {"botId": dynamic.BOT_ID, "revision": "a" * 40,
            "deploymentSha256": "b" * 64, "sqliteSha256": source_sha}, "allowedUserIds": [dynamic.FOREIGN_OWNER],
            "adminUserIds": [dynamic.OWNER]}))
    with native.private_file(target) as file:
        file.write(auth.inventory._canonical_line({"version": 1, "scope": auth.preview.GENERAL_TARGET_SCOPE, "botId": dynamic.BOT_ID,
                                                  "groupChatIds": list(AUTH_GROUPS)}))
    pins = {"inventory_sha256": native.file_hash(inventory / package.MANIFEST)[1], "config_sha256": native.file_hash(config)[1],
            "target_sha256": native.file_hash(target)[1]}
    auth.preview.seal_reconciliation(source, inventory, config, target, preview, source_sha256=source_sha, general_preview=True, **pins)
    return auth.UnifiedAuthInput(inventory, config, target, preview, **pins, preview_sha256=native.file_hash(preview / package.MANIFEST)[1])


def build_unified_share_fixture(root: Path, worker: Path, revision: str, *,
                                produce_oracle: bool = False, oracle: Path | None = None) -> UnifiedShareFixture:
    """Build from real offline comparison, or from its exact seal during protected verification."""
    return _build_fixture(root, worker, revision, produce_oracle=produce_oracle, oracle=oracle, include_auth=False)


def build_unified_auth_fixture(root: Path, worker: Path, revision: str, *,
                               produce_oracle: bool = False, oracle: Path | None = None) -> UnifiedShareFixture:
    """Rebuild V11 using its own same-source authorization and external redirect proof."""
    return _build_fixture(root, worker, revision, produce_oracle=produce_oracle, oracle=oracle, include_auth=True)


def _build_fixture(root, worker, revision, *, produce_oracle, oracle, include_auth):
    root, worker = package.private_path(root, directory=True), package.private_path(worker, directory=True)
    require(not root.is_relative_to(worker) and not worker.is_relative_to(root)
            and type(produce_oracle) is bool and produce_oracle == (oracle is None))
    source, candidate = root / "legacy.sqlite", root / "candidate"
    require(not os.path.lexists(source) and not os.path.lexists(candidate))
    worker_sha = native.file_hash(worker / "isolation.json")[1]
    chain, _ = package.worker_artifact(worker, revision, worker_sha)
    make_synthetic_source(source)
    if include_auth:
        _add_authorization(source)
    source_sha = native.file_hash(source)[1]
    owners = native.canonical({})
    owner_sha = native.digest(owners)
    with TemporaryDirectory(prefix="legacy-unified-share-build-", dir=root) as temporary:
        scratch = Path(temporary)
        conversion, staged, share_dir = (scratch / name for name in ("conversion", "candidate", "share-inventory"))
        owner_file = scratch / "owners.json"
        with native.private_file(owner_file) as file:
            file.write(owners)
        package.converter.convert_backup(source, conversion, owner_map={})
        baseline = dynamic.seal_dynamic_all_input(source, {}, scratch, source_sha256=source_sha,
            owner_map_sha256=owner_sha, old_origin=dynamic.OLD_ORIGIN, legacy_bot_id=dynamic.BOT_ID)
        shares.seal_inventory(source, share_dir, source_sha, dynamic.BOT_ID, BOT_USERNAME)
        private_shares = UnifiedShareInput(share_dir, native.file_hash(share_dir / shares.MANIFEST)[1], BOT_USERNAME)
        general_auth = _seal_authorization(source, source_sha, scratch) if include_auth else None
        if produce_oracle:
            from legacy_short_redirect_oracle import seal_oracle

            oracle = scratch / ORACLE_DIRECTORY
            seal_oracle({"backup": str(source), "ownerMap": str(owner_file), "inventory": str(baseline.namespace_dir),
                         "bundle": str(worker), "output": str(oracle), "sourceSha256": source_sha,
                         "ownerMapSha256": owner_sha, "oldOrigin": dynamic.OLD_ORIGIN, "legacyBotId": dynamic.BOT_ID,
                         "inventorySha256": baseline.namespace_sha256, "workerManifestSha256": worker_sha,
                         "revision": revision, "pythonVersion": PYTHON_VERSION, "yarlVersion": YARL_VERSION})
        oracle = package.private_path(oracle, directory=True)
        oracle_sha = native.digest(package.read_private(oracle / package.MANIFEST, ORACLE_MANIFEST_BYTES))
        mixed = MixedShortInput(source, owner_file, dynamic.OLD_ORIGIN, dynamic.BOT_ID, baseline.namespace_dir,
                                baseline.namespace_sha256, oracle, oracle_sha, PYTHON_VERSION, YARL_VERSION)
        report = package.build_candidate(conversion, worker, staged,
            converter_manifest_sha=native.file_hash(conversion / package.MANIFEST)[1], worker_manifest_sha=worker_sha,
            revision=revision, applied_at=APPLIED_AT, profile=package.UNIFIED_AUTH_PROFILE if include_auth else package.UNIFIED_SHARES_PROFILE,
            source_sqlite_sha=source_sha, owner_map_sha=owner_sha, mixed_short=mixed, dynamic_all=baseline,
            private_shares=private_shares, general_auth=general_auth)
        require(report["version"] == (11 if include_auth else 10) and report["scope"] == "fresh-unbound-d1-r2"
                and report["targetSequenceHighWater"] == dynamic.TARGET_TRASH_ID and report["objectCount"] == 10
                and report["shortLinkCompatibility"] == {"typed": "not-validated", "external": "offline-equivalent",
                                                          "selected": "not-validated", "dynamicAll": "not-validated"}
                and report["shareCompatibility"] == "not-validated"
                and [report[name]["rows"] for name in ("typedShortLinks", "externalShortLinks", "selectedAggregateLinks", "dynamicAll")]
                    == [2, 1, 1, 3]
                and [report["legacyTempBaseline"][key] for key in ("installations", "batches", "nodes")] == [1, 3, 4]
                and [report["privateShares"][key] for key in ("rows", "claimRows", "inlineMessageRows", "objectCount")] == [2, 1, 1, 2])
        if include_auth:
            manifest = native.parsed(package.read_pinned(staged / package.MANIFEST, native.MANIFEST_BYTES, report["manifestSha256"]),
                                     native.MANIFEST_BYTES)
            auth = report["generalAuthorization"]
            require(auth["activationAllowed"] is False and auth["counts"] == AUTH_COUNTS
                    and manifest["summary"]["rowCount"] == len(chain) + 38
                    and manifest["source"]["generalAuthorization"]["sourceSha256"] == source_sha
                    and manifest["source"]["oracleManifestSha256"] == oracle_sha)
        if produce_oracle:
            oracle.rename(staged / ORACLE_DIRECTORY)
        _verify_files(staged, report, with_oracle=produce_oracle)
        require(native.file_hash(source)[1] == source_sha)
        staged.rename(package.converter._safe_path(candidate, existing=False))
    return UnifiedShareFixture(source, source_sha, candidate, report["manifestSha256"])
