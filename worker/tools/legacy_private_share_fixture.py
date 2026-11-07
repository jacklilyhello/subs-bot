"""Fixed synthetic legacy share input for the protected native restore profile."""

from base64 import urlsafe_b64encode
from contextlib import closing, suppress
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory

import legacy_private_share_candidate as candidate
import legacy_private_share_inventory as inventory
import legacy_restore_package as package
import native_restore_rehearsal as native


# Outside Telegram's 52-bit identifier range. This fixture never reaches a Bot.
BOT_ID = "9000000000000901"
BOT_USERNAME = "synthetic_legacy_share_bot"
SENDER = 9000000000000902
TARGET = 9000000000000903
OTHER = 9000000000000904
CREATED_AT = 1_700_000_000
EXPIRED_AT = CREATED_AT + 60
LATER_EXPIRY = CREATED_AT + 3_600
COUNTS = {"shares": 3, "claims": 3, "sourceInlineIdRows": 1}
EMPTY_METADATA = {"custom": {}, "http": {}}


def code(number):
    return urlsafe_b64encode(number.to_bytes(8, "big")).rstrip(b"=").decode("ascii")


def make_source(path):
    shares = [
        (code(1), SENDER, "  合成发送者  ", "fixture exhausted\n", 1, 1, None, LATER_EXPIRY, CREATED_AT, None),
        (code(2), SENDER, "合成接收者", "\ufeff fixture targeted\r\n", 2, 1, TARGET, LATER_EXPIRY, CREATED_AT, None),
        (code(3), SENDER, "合成已到期", "fixture expired 合成\n", 1, 1, TARGET, EXPIRED_AT, CREATED_AT, "fixture-retired-inline"),
    ]
    claims = [(11, code(1), OTHER, CREATED_AT + 15), (21, code(2), TARGET, CREATED_AT),
              (31, code(3), TARGET, EXPIRED_AT)]
    with native.private_file(path):
        pass
    with closing(sqlite3.connect(path)) as db, db:
        db.execute("""CREATE TABLE shares (
            code TEXT PRIMARY KEY, sender_id INTEGER NOT NULL, sender_name TEXT NOT NULL, content TEXT NOT NULL,
            max_views INTEGER NOT NULL DEFAULT 1, claimed_count INTEGER NOT NULL DEFAULT 0, target_user_id INTEGER,
            expire_at INTEGER NOT NULL, created_at INTEGER NOT NULL, inline_message_id TEXT)""")
        db.execute("""CREATE TABLE share_claims (
            id INTEGER PRIMARY KEY AUTOINCREMENT, share_code TEXT NOT NULL, user_id INTEGER NOT NULL,
            claimed_at INTEGER NOT NULL, UNIQUE(share_code, user_id))""")
        db.executemany("INSERT INTO shares VALUES (?,?,?,?,?,?,?,?,?,?)", shares)
        db.executemany("INSERT INTO share_claims VALUES (?,?,?,?)", claims)


def build(worker, output, worker_pin, *, applied_at):
    with TemporaryDirectory(prefix="legacy-share-source-", dir=output.parent) as temporary:
        scratch = Path(temporary)
        source, sealed = scratch / "source.sqlite", scratch / "inventory"
        staged = scratch / "candidate"
        make_source(source)
        source_sha = native.file_hash(source)[1]
        inventory.seal_inventory(source, sealed, source_sha, BOT_ID, BOT_USERNAME)
        inventory_sha = native.file_hash(sealed / inventory.MANIFEST)[1]
        report = candidate.build_candidate(
            sealed, worker, staged, inventory_manifest_sha=inventory_sha, worker_manifest_sha=worker_pin["manifestSha256"],
            revision=worker_pin["revision"], applied_at=applied_at, source_sqlite_sha=source_sha,
            legacy_bot_id=BOT_ID, legacy_bot_username=BOT_USERNAME,
        )
        native.require(report["version"] == 1 and report["profile"] == candidate.PROFILE and report["counts"] == COUNTS
                       and report["objectCount"] == report["shareSequenceHighWater"] == COUNTS["shares"])
        # The hosted runner owns its temp root, which need not be mode 0700.
        output.mkdir(mode=0o700)
        try:
            staged.rename(output)
        except BaseException:
            with suppress(OSError):
                output.rmdir()
            raise
    return report


def files(document, object_limit):
    native.require(type(document.get("version")) is int and document["version"] == 1
                   and document.get("profile") == candidate.PROFILE)
    objects = document.get("objects")
    native.require(isinstance(objects, list) and len(objects) == COUNTS["shares"])
    paths = {package.MANIFEST, package.MARKER, package.SQL}
    for entry in objects:
        native.require(isinstance(entry, dict) and set(entry) == {"key", "bytes", "sha256", "metadata"}
                       and native.matches(native.KEY, entry["key"]) and entry["key"].startswith("private-shares/")
                       and native.integer(entry["bytes"], 1, object_limit) and native.matches(native.DIGEST, entry["sha256"])
                       and entry["metadata"] == EMPTY_METADATA)
        paths.add("objects/" + entry["key"])
    native.require(len(paths) == 3 + COUNTS["shares"])
    return paths
