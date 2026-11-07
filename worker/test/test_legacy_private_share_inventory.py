"""Synthetic hosted coverage for the sealed private legacy share package."""

from base64 import urlsafe_b64encode
from contextlib import closing, redirect_stderr, redirect_stdout
from hashlib import sha256
import io
import json
from pathlib import Path
import sqlite3
import stat
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import legacy_private_share_inventory as tool


BOT_ID = "46100"
BOT_USERNAME = "synthetic_legacy_bot"
MAX_ID = 2**63 - 1
SHARE_SCHEMA = """CREATE TABLE shares (
    code TEXT PRIMARY KEY, sender_id INTEGER NOT NULL, sender_name TEXT NOT NULL,
    content TEXT NOT NULL, max_views INTEGER NOT NULL DEFAULT 1,
    claimed_count INTEGER NOT NULL DEFAULT 0, target_user_id INTEGER,
    expire_at INTEGER NOT NULL, created_at INTEGER NOT NULL
)"""
CLAIM_SCHEMA = """CREATE TABLE share_claims (
    id INTEGER PRIMARY KEY AUTOINCREMENT, share_code TEXT NOT NULL,
    user_id INTEGER NOT NULL, claimed_at INTEGER NOT NULL, UNIQUE(share_code, user_id)
)"""


def code(number):
    return urlsafe_b64encode(number.to_bytes(8, "big")).rstrip(b"=").decode("ascii")


def share(token=None, *, target=None, maximum=2, count=0, body="fixture", created=20, expiry=80):
    return (code(1) if token is None else token, MAX_ID, "  合成发送者  ", body, maximum, count, target, expiry, created)


class LegacyPrivateShareInventoryTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.output = self.root / "private-share-output"
        self.fixture_number = 0

    def make_backup(self, shares=(), claims=(), *, inline=False, share_schema=SHARE_SCHEMA, claim_schema=CLAIM_SCHEMA):
        self.fixture_number += 1
        backup = self.root / f"fixture-private-?#-{self.fixture_number}.db"
        with closing(sqlite3.connect(backup)) as db, db:
            db.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            db.execute("INSERT INTO meta VALUES ('unrelated', 'unrelated-private-sentinel')")
            if share_schema:
                db.execute(share_schema)
                db.executemany("INSERT INTO shares VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", shares)
                if inline:
                    # Legacy ALTER TABLE added this column last.
                    db.execute("ALTER TABLE shares ADD COLUMN inline_message_id TEXT")
                    db.execute("UPDATE shares SET inline_message_id=? WHERE code=?", ("opaque-inline-provenance", code(1)))
            if claim_schema:
                db.execute(claim_schema)
                db.executemany("INSERT INTO share_claims VALUES (?, ?, ?, ?)", claims)
        backup.chmod(0o600)
        return backup, sha256(backup.read_bytes()).hexdigest()

    def run_cli(self, backup, digest, *, output=None, bot_id=BOT_ID, bot_username=BOT_USERNAME):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            status = tool.main([str(backup), str(output or self.output), digest, bot_id, bot_username])
        return status, stdout.getvalue(), stderr.getvalue()

    def assert_rejected(self, backup, digest, **options):
        self.assertEqual(self.run_cli(backup, digest, **options), (2, "", tool.FAILURE + "\n"))
        self.assertFalse(self.output.exists())

    def test_exact_private_pack_code_digests_and_claim_provenance(self):
        first, second = code(1), code(2)
        first_hash, second_hash = sha256(first.encode()).hexdigest(), sha256(second.encode()).hexdigest()
        body = f"  opaque claim_{first}\r\n中文\0  \n"
        source, digest = self.make_backup(
            [share(second, body="second\n", count=1), share(first, target=MAX_ID - 1, body=body, count=1)],
            [(MAX_ID, first, MAX_ID - 1, 80), (19, second, MAX_ID - 1, 20)], inline=True,
        )
        original = source.read_bytes()
        self.assertEqual(self.run_cli(source, digest), (0, tool.SUCCESS + "\n", ""))
        self.assertEqual(source.read_bytes(), original)
        self.assertEqual({entry.name for entry in self.root.iterdir()}, {self.output.name, source.name})
        files = {entry.name: entry.read_bytes() for entry in self.output.iterdir()}
        self.assertEqual(set(files), {tool.SHARES, tool.CLAIMS, tool.PAYLOADS, tool.MANIFEST, tool.SEAL})
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o700)
        for entry in self.output.iterdir():
            self.assertEqual(stat.S_IMODE(entry.stat().st_mode), 0o600)
        metadata = files[tool.SHARES] + files[tool.CLAIMS] + files[tool.MANIFEST]
        for sentinel in (first, second, "unrelated-private-sentinel", source.name):
            self.assertNotIn(sentinel.encode(), metadata)
        shares = [json.loads(line) for line in files[tool.SHARES].splitlines()]
        self.assertEqual([row["codeSha256"] for row in shares], sorted([first_hash, second_hash]))
        by_digest = {row["codeSha256"]: row for row in shares}
        self.assertEqual({key: value for key, value in by_digest[first_hash].items() if key != "payload"}, {
            "codeSha256": first_hash, "senderId": str(MAX_ID), "senderName": "  合成发送者  ", "targetUserId": str(MAX_ID - 1),
            "inlineMessageId": "opaque-inline-provenance", "maxViews": 2, "claimedCount": 1, "createdAt": 20, "expireAt": 80,
        })
        self.assertIsNone(by_digest[second_hash]["targetUserId"])
        self.assertIsNone(by_digest[second_hash]["inlineMessageId"])
        offset = 0
        for row in shares:
            expected = body.encode("utf-8") if row["codeSha256"] == first_hash else b"second\n"
            self.assertEqual(row["payload"], {"offset": offset, "bytes": len(expected), "sha256": sha256(expected).hexdigest()})
            self.assertEqual(files[tool.PAYLOADS][offset:offset + len(expected)], expected)
            offset += len(expected)
        self.assertEqual(offset, len(files[tool.PAYLOADS]))
        self.assertEqual([json.loads(line) for line in files[tool.CLAIMS].splitlines()], [
            {"legacyClaimId": "19", "codeSha256": second_hash, "userId": str(MAX_ID - 1), "claimedAt": 20},
            {"legacyClaimId": str(MAX_ID), "codeSha256": first_hash, "userId": str(MAX_ID - 1), "claimedAt": 80},
        ])
        self.assertEqual(json.loads(files[tool.MANIFEST]), {
            "version": 1, "kind": "legacy-private-share-inventory", "sourceSha256": digest,
            "legacyBot": {"id": BOT_ID, "username": BOT_USERNAME},
            "inventory": {"present": True, "inlineMessageIdColumn": True, "shares": 2, "claims": 2},
            "files": [{"file": name, "bytes": len(files[name]), "sha256": sha256(files[name]).hexdigest()}
                      for name in (tool.SHARES, tool.CLAIMS, tool.PAYLOADS)],
        })
        self.assertEqual(files[tool.SEAL], sha256(files[tool.MANIFEST]).hexdigest().encode("ascii") + b"\n")
        rerun = self.root / "second-pack"
        self.assertEqual(self.run_cli(source, digest, output=rerun)[0], 0)
        self.assertEqual({entry.name: entry.read_bytes() for entry in rerun.iterdir()}, files)

    def test_absent_tables_and_historical_schema_are_distinct(self):
        source, digest = self.make_backup(share_schema=None, claim_schema=None)
        self.assertEqual(self.run_cli(source, digest)[0], 0)
        for name in (tool.SHARES, tool.CLAIMS, tool.PAYLOADS):
            self.assertEqual((self.output / name).read_bytes(), b"")
        self.assertEqual(json.loads((self.output / tool.MANIFEST).read_bytes())["inventory"], {
            "present": False, "inlineMessageIdColumn": False, "shares": 0, "claims": 0,
        })
        previous = self.root / "historical-schema"
        self.assertEqual(self.run_cli(*self.make_backup([share()]), output=previous)[0], 0)
        self.assertIsNone(json.loads((previous / tool.SHARES).read_bytes())["inlineMessageId"])
        self.assertEqual(json.loads((previous / tool.MANIFEST).read_bytes())["inventory"], {
            "present": True, "inlineMessageIdColumn": False, "shares": 1, "claims": 0,
        })

    def test_fails_closed_on_malformed_shares_and_claim_relationships(self):
        first = code(1)
        malformed = [
            ([], [(1, first, 5, 20)]),                                      # orphan
            ([share(count=1)], []),                                       # missing claim
            ([share()], [(1, first, 5, 20)]),                              # unexpected claim
            ([share(target=5, count=1)], [(1, first, 6, 20)]),              # wrong recipient
            ([share(count=1)], [(1, first, 5, 19)]),                       # claim before creation
            ([share(count=1)], [(1, first, 5, 81)]),                       # claim after inclusive expiry
            ([share(count=1)], [(1, first, 0, 20)]),                        # invalid claimant
            ([share(count=1)], [(0, first, 5, 20)]),                        # invalid source row ID
            ([share(maximum=1, count=2)], []),                              # capacity mismatch
            ([share(token="private-invalid-code")], []),                  # unsupported code syntax
            ([share(token=first[:-1] + "B")], []),                         # noncanonical unused Base64 bits
            ([share(expiry=20)], []),                                      # invalid source lifetime
            ([share(expiry=tool.MAX_TIMESTAMP + 1)], []),                  # unsafe timestamp
            ([share(body=b"not-text")], []),                               # malformed stored text type
            ([share(target=0)], []),                                       # invalid targeted actor
        ]
        for index, (shares, claims) in enumerate(malformed):
            with self.subTest(case=index):
                self.assert_rejected(*self.make_backup(shares, claims))
        no_unique = CLAIM_SCHEMA.replace(", UNIQUE(share_code, user_id)", "")
        self.assert_rejected(*self.make_backup([share(count=2)], [(1, first, 5, 20), (2, first, 5, 21)], claim_schema=no_unique))
        self.assert_rejected(*self.make_backup(claim_schema=None))

    def test_bounded_payloads_and_row_counts_never_emit_partial_seal(self):
        two = [share(body="x"), share(code(2), body="y")]
        with patch.object(tool, "MAX_SHARES", 1):
            self.assert_rejected(*self.make_backup(two))
        with patch.object(tool, "MAX_CLAIMS", 1):
            claims = [(1, code(1), 5, 20), (2, code(1), 6, 20)]
            self.assert_rejected(*self.make_backup([share(count=2)], claims))
        with patch.object(tool, "MAX_TOTAL_PAYLOAD_BYTES", 1):
            self.assert_rejected(*self.make_backup(two))
        with patch.object(tool, "MAX_SHARE_METADATA_BYTES", 1):
            self.assert_rejected(*self.make_backup([share()]))
        with patch.object(tool, "MAX_PAYLOAD_BYTES", 2):
            self.assert_rejected(*self.make_backup([share(body="汉")]))
            self.assertEqual(self.run_cli(*self.make_backup([share(body="xx")]))[0], 0)

    def test_source_identity_private_modes_and_preexisting_output(self):
        source, digest = self.make_backup([share()])
        self.assert_rejected(source, "0" * 64)
        self.assert_rejected(source, digest, bot_id="046100")
        self.assert_rejected(source, digest, bot_id=str(MAX_ID + 1))
        self.assert_rejected(source, digest, bot_username="@Synthetic_Legacy_Bot")
        source.chmod(0o640)
        self.assert_rejected(source, digest)
        source.chmod(0o600)
        for suffix in ("-wal", "-shm", "-journal"):
            with self.subTest(sidecar=suffix):
                sidecar = source.with_name(source.name + suffix)
                sidecar.write_bytes(b"synthetic")
                self.assert_rejected(source, digest)
                self.assertEqual(sidecar.read_bytes(), b"synthetic")
                sidecar.unlink()
        capture = tool._capture

        def change_source(path, output):
            result = capture(path, output)
            with closing(sqlite3.connect(path)) as db, db:
                db.execute("UPDATE shares SET content='new private content'")
            return result

        with patch.object(tool, "_capture", side_effect=change_source):
            self.assert_rejected(source, digest)
        self.output.mkdir(mode=0o700)
        preexisting = self.output / tool.PAYLOADS
        preexisting.write_bytes(b"untouched")
        self.assertEqual(self.run_cli(source, sha256(source.read_bytes()).hexdigest()), (2, "", tool.FAILURE + "\n"))
        self.assertEqual(preexisting.read_bytes(), b"untouched")


if __name__ == "__main__":
    unittest.main()
