"""Hosted replay of private shares in the unified, unbound legacy candidate."""

from contextlib import closing
from dataclasses import replace
import json
import sqlite3
import unittest
from uuid import NAMESPACE_URL, uuid5

import test_legacy_unified_candidate as unified
import test_legacy_private_share_inventory as shares
import legacy_private_share_inventory as inventory
from legacy_private_share_candidate import MIGRATION_SHA256, UnifiedShareInput


package = unified.package
native = unified.native
fixtures = unified.fixtures
dynamic = unified.dynamic
BOT_USERNAME = "synthetic_unified_bot"
TARGET_CODE, EXPIRED_CODE = shares.code(6), shares.code(13)
TARGET_PAYLOAD = "\ufeff  合成私密正文\r\n\0  \n"
EXPIRED_PAYLOAD = "expired share — fixture\r\n"
INLINE_ID = "synthetic-old-inline-message-reference"
SENDER_NAME = "  合成发送者  "
CREATED_AT = dynamic.CREATED_AT
TARGET_EXPIRES_AT, EXPIRED_AT = 2_100_000_000, CREATED_AT + 30


def add_shares(db, *, targeted_payload=TARGET_PAYLOAD):
    db.execute(shares.SHARE_SCHEMA)
    db.execute(shares.CLAIM_SCHEMA)
    db.executemany("INSERT INTO shares VALUES (?,?,?,?,?,?,?,?,?)", (
        (TARGET_CODE, int(dynamic.OWNER), SENDER_NAME, targeted_payload, 2, 1,
         int(dynamic.TEMP_ONLY_OWNER), TARGET_EXPIRES_AT, CREATED_AT),
        (EXPIRED_CODE, int(dynamic.FOREIGN_OWNER), SENDER_NAME, EXPIRED_PAYLOAD, 1, 0,
         None, EXPIRED_AT, CREATED_AT),
    ))
    db.execute("ALTER TABLE shares ADD COLUMN inline_message_id TEXT")
    db.execute("UPDATE shares SET inline_message_id=? WHERE code=?", (INLINE_ID, TARGET_CODE))
    db.execute("INSERT INTO share_claims VALUES (?,?,?,?)", (41, TARGET_CODE, int(dynamic.TEMP_ONLY_OWNER), TARGET_EXPIRES_AT))


class LegacyUnifiedShareCandidateTests(unittest.TestCase):
    def setUp(self):
        self.v9 = unified.LegacyUnifiedCandidateTests()
        self.v9.setUp()
        self.addCleanup(self.v9.doCleanups)

    def seal_shares(self, case, name="share-inventory", *, bot_id=dynamic.BOT_ID):
        root = case.output.with_name(name)
        inventory.seal_inventory(case.dynamic.source, root, case.source_sha, bot_id, BOT_USERNAME)
        return UnifiedShareInput(root, fixtures.digest((root / inventory.MANIFEST).read_bytes()), BOT_USERNAME)

    def build(self, case, pins):
        return self.v9.build(case, profile=package.UNIFIED_SHARES_PROFILE, private_shares=pins)

    def test_unified_share_candidate_preserves_rows_and_private_object_bytes(self):
        case = self.v9.capture("combined", extra_source_rows=add_shares)
        pins = self.seal_shares(case)
        report = self.build(case, pins)
        manifest_raw = (case.output / package.MANIFEST).read_bytes()
        manifest = json.loads(manifest_raw)
        self.assertEqual((manifest["version"], manifest["scope"]), (10, "fresh-unbound-d1-r2"))
        self.assertEqual(report["manifestSha256"], fixtures.digest(manifest_raw))
        self.assertEqual((case.output / package.MARKER).read_bytes(), report["manifestSha256"].encode("ascii") + b"\n")
        for name, count in (("typedShortLinks", 2), ("externalShortLinks", 1), ("selectedAggregateLinks", 1), ("dynamicAll", 3)):
            self.assertEqual(manifest[name]["rows"], count)
        self.assertEqual((manifest["legacyTempBaseline"]["batches"], manifest["legacyTempBaseline"]["nodes"]), (3, 4))
        self.assertEqual(manifest["source"]["sqliteSha256"], case.source_sha)
        self.assertEqual(manifest["source"]["legacyBotId"], dynamic.BOT_ID)
        inventory_dir = case.output.with_name("share-inventory")
        for field, filename in (
            ("privateShareInventoryManifestSha256", inventory.MANIFEST),
            ("privateShareRowsSha256", inventory.SHARES),
            ("privateShareClaimRowsSha256", inventory.CLAIMS),
            ("privateSharePayloadsSha256", inventory.PAYLOADS),
        ):
            self.assertEqual(manifest["source"][field], fixtures.digest((inventory_dir / filename).read_bytes()))
        self.assertEqual(manifest["source"]["legacyShareBotUsernameSha256"], unified.digest(BOT_USERNAME))
        self.assertEqual(manifest["shareCompatibility"], "not-validated")
        self.assertEqual(manifest["privateShares"], {
            "rows": 2, "claimRows": 1, "inlineMessageRows": 1, "objectCount": 2, "migrationSha256": MIGRATION_SHA256,
            "tableSha256": {table: manifest["summary"]["tableSha256"][table] for table in ("private_shares", "private_share_claims")},
        })
        self.assertEqual(manifest["objectCount"], 10)

        sql = (case.output / package.SQL).read_bytes()
        self.assertEqual(fixtures.digest(sql), manifest["sql"]["sha256"])
        for secret in (TARGET_CODE, EXPIRED_CODE, INLINE_ID, "合成私密正文", EXPIRED_PAYLOAD.strip()):
            self.assertNotIn(secret.encode("utf-8"), sql)
            self.assertNotIn(secret.encode("utf-8"), manifest_raw)
        objects = {entry["key"]: entry for entry in manifest["objects"]}
        paths = {file.relative_to(case.output).as_posix() for file in case.output.rglob("*") if file.is_file()}
        self.assertEqual(paths, {package.MANIFEST, package.MARKER, package.LINEAGE, package.SQL} | {"objects/" + key for key in objects})
        self.assertTrue(all((case.output / path).stat().st_mode & 0o777 == 0o600 for path in paths))

        targeted_hash, expired_hash = (unified.digest(code) for code in (TARGET_CODE, EXPIRED_CODE))
        expected_shares = {
            targeted_hash: (dynamic.OWNER, TARGET_PAYLOAD, 2, dynamic.TEMP_ONLY_OWNER, TARGET_EXPIRES_AT),
            expired_hash: (dynamic.FOREIGN_OWNER, EXPIRED_PAYLOAD, 1, None, EXPIRED_AT),
        }
        with closing(sqlite3.connect(":memory:")) as db:
            db.execute("PRAGMA foreign_keys=ON")
            db.executescript(sql.decode("utf-8"))
            self.assertEqual(db.execute("PRAGMA foreign_key_check").fetchall(), [])
            self.assertEqual(package.db_summary(db, native.table_layout(db, sorted(manifest["layout"]))), manifest["summary"])
            self.assertEqual(native.object_references(db, lambda key: (
                (case.output / "objects" / key).read_bytes(), objects[key]["metadata"])), manifest["objects"])
            old_codes = (unified.ACTIVE_CODE, unified.TRASH_CODE, unified.EXTERNAL_CODE, unified.SELECTED_CODE, *unified.ALL_CODES)
            self.assertEqual(db.execute("""SELECT code_sha256 FROM legacy_subscription_short_links
                UNION ALL SELECT code_sha256 FROM normal_short_links UNION ALL SELECT code_sha256 FROM aggregate_links
                ORDER BY code_sha256""").fetchall(), sorted((unified.digest(code),) for code in old_codes))
            self.assertEqual(db.execute("SELECT selected_ids FROM aggregate_links WHERE kind='selected'").fetchall(),
                             [(native.canonical(unified.SELECTED_IDS).decode("ascii"),)])
            self.assertEqual(db.execute("SELECT * FROM legacy_selected_members WHERE retired=1").fetchall(), [(dynamic.LEGACY_TRASH_ID, 1)])
            self.assertEqual(db.execute("SELECT * FROM legacy_temp_installations").fetchall(),
                             [(dynamic.BOT_ID, case.dynamic.temp_manifest_sha256, None)])
            exact_temp = fixtures.body([{"name": "alpha", "type": "temp", "share": dynamic.fixture_share("temporary")}] * 2)
            self.assertEqual(db.execute("SELECT nodes_json,payload_sha256 FROM legacy_temp_batches WHERE actor_id=?",
                                        (dynamic.OWNER,)).fetchall(), [(exact_temp.decode("utf-8"), fixtures.digest(exact_temp))])

            rows = db.execute("""SELECT id,bot_id,code_sha256,sender_id,sender_name,payload_id,payload_sha256,payload_bytes,
                max_claims,target_user_id,created_at,expire_at FROM private_shares ORDER BY id""").fetchall()
            self.assertEqual([(row[0], row[2]) for row in rows], list(enumerate(sorted(expected_shares), 1)))
            claim_rows = []
            share_keys = set()
            for identity, bot, code, sender, name, payload_id, sha, size, maximum, target, created, expiry in rows:
                owner, payload, max_claims, recipient, expire_at = expected_shares[code]
                body = payload.encode("utf-8")
                expected_id = str(uuid5(NAMESPACE_URL, f"subs-bot-legacy-private-share-v1:{case.source_sha}:{dynamic.BOT_ID}:{code}"))
                self.assertEqual((bot, sender, name, payload_id, sha, size, maximum, target, created, expiry),
                                 (dynamic.BOT_ID, owner, SENDER_NAME, expected_id, fixtures.digest(body), len(body),
                                  max_claims, recipient, CREATED_AT, expire_at))
                key = f"private-shares/{payload_id}.txt"
                share_keys.add(key)
                self.assertEqual((case.output / "objects" / key).read_bytes(), body)
                self.assertEqual(objects[key]["metadata"], {"custom": {}, "http": {}})
                if code == targeted_hash:
                    claim_rows.append((identity, dynamic.TEMP_ONLY_OWNER, TARGET_EXPIRES_AT))
            self.assertEqual(db.execute("SELECT * FROM private_share_claims").fetchall(), claim_rows)
            self.assertEqual(db.execute("SELECT name,seq FROM sqlite_sequence ORDER BY name").fetchall(),
                             [("path_rules", 7), ("private_shares", 2), ("subscriptions", dynamic.TARGET_TRASH_ID)])
            self.assertEqual({key for key in objects if key.startswith("private-shares/")}, share_keys)
        self.assertEqual(fixtures.digest(case.dynamic.source.read_bytes()), case.source_sha)

    def test_refuses_wrong_sealed_source_or_bot_and_keeps_v9_refusal(self):
        case = self.v9.capture("input", extra_source_rows=add_shares)
        other = self.v9.capture("other-source", extra_source_rows=lambda db: add_shares(db, targeted_payload="different fixture"))
        self.assertNotEqual(other.source_sha, case.source_sha)
        wrong_source = self.seal_shares(other)
        wrong_bot = self.seal_shares(case, "wrong-bot", bot_id="74119")
        correct = self.seal_shares(case)
        wrong_username = replace(correct, legacy_bot_username="other_synthetic_bot")
        for label, pins in (("source", wrong_source), ("bot", wrong_bot), ("username", wrong_username)):
            with self.subTest(label=label):
                with self.assertRaises(package.PackageError) as caught:
                    self.build(case, pins)
                self.assertEqual(str(caught.exception), package.ERROR)
                self.assertFalse(case.output.exists())
        self.v9.assert_refused(case)


if __name__ == "__main__":
    unittest.main()
