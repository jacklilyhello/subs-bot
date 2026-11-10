"""Hosted exact replay of a single dormant subscriptions, shares and authorization package."""

from contextlib import closing
from dataclasses import replace
import json
import sqlite3
import unittest

import legacy_general_auth_candidate as auth
import legacy_general_auth_native_candidate as native_auth
import legacy_unified_share_native_candidate as native_shares
import test_legacy_unified_share_candidate as combined


package = combined.package
native = combined.native
fixtures = combined.fixtures
dynamic = combined.dynamic
OWNER, MEMBER = dynamic.OWNER, dynamic.TEMP_ONLY_OWNER
OVERRIDES = ((int(OWNER), 0, 10, 20), (int(MEMBER), 1, 11, 30))


def add_domains(db):
    combined.add_shares(db)
    db.execute("""CREATE TABLE auth_overrides (
        user_id INTEGER PRIMARY KEY, allowed INTEGER NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)""")
    db.executemany("INSERT INTO auth_overrides VALUES (?,?,?,?)", OVERRIDES)


class LegacyUnifiedAuthCandidateTests(unittest.TestCase):
    def setUp(self):
        self.v10 = combined.LegacyUnifiedShareCandidateTests()
        self.v10.setUp()
        self.addCleanup(self.v10.doCleanups)
        self.v9 = self.v10.v9

    def seal(self, case, name, *, bot=dynamic.BOT_ID, allowlist=(dynamic.FOREIGN_OWNER,)):
        root = case.output.with_name(name)
        root.mkdir(mode=0o700)
        inventory, config, target, preview = (root / filename for filename in ("inventory", "config.json", "target.json", "preview"))
        auth.inventory.seal_inventory(case.mixed.source, inventory, case.source_sha)
        fixtures.put(config, auth.inventory._canonical_line({"version": 1, "source": {"botId": bot, "revision": "a" * 40,
            "deploymentSha256": "b" * 64, "sqliteSha256": case.source_sha}, "allowedUserIds": list(allowlist),
            "adminUserIds": [OWNER]}))
        fixtures.put(target, auth.inventory._canonical_line({"version": 1, "scope": auth.preview.GENERAL_TARGET_SCOPE,
            "botId": bot, "groupChatIds": ["-100200", "-100100"]}))
        pins = {"inventory_sha256": native.file_hash(inventory / package.MANIFEST)[1], "config_sha256": native.file_hash(config)[1],
                "target_sha256": native.file_hash(target)[1]}
        auth.preview.seal_reconciliation(case.mixed.source, inventory, config, target, preview,
                                         source_sha256=case.source_sha, general_preview=True, **pins)
        result = auth.UnifiedAuthInput(inventory, config, target, preview, **pins,
                                       preview_sha256=native.file_hash(preview / package.MANIFEST)[1])
        private_input = root / "input.json"
        fixtures.put(private_input, native.canonical({"inventoryDir": str(inventory), "configPath": str(config),
            "targetPath": str(target), "previewDir": str(preview), "inventorySha256": result.inventory_sha256,
            "configSha256": result.config_sha256, "targetSha256": result.target_sha256, "previewSha256": result.preview_sha256}))
        self.assertEqual(auth.read_unified_auth_input(private_input), result)
        return result

    def test_joint_dormant_restore_matches_all_source_rows_and_keeps_the_ledger(self):
        case = self.v9.capture("combined", extra_source_rows=add_domains)
        share_pins = self.v10.seal_shares(case)
        pins = self.seal(case, "sealed-auth")
        report = self.v9.build(case, profile=package.UNIFIED_AUTH_PROFILE, private_shares=share_pins, general_auth=pins)
        raw = (case.output / package.MANIFEST).read_bytes()
        manifest = json.loads(raw)
        self.assertEqual((manifest["version"], manifest["scope"], manifest["objectCount"]), (11, "fresh-unbound-d1-r2", 10))
        self.assertEqual(report["manifestSha256"], native.digest(raw))
        self.assertEqual((case.output / package.MARKER).read_bytes(), report["manifestSha256"].encode("ascii") + b"\n")
        self.assertEqual(manifest["source"]["generalAuthorization"]["sourceSha256"], case.source_sha)
        self.assertEqual(manifest["source"]["generalAuthorization"]["previewManifestSha256"], pins.preview_sha256)
        self.assertEqual(manifest["generalAuthorization"], {"activationAllowed": False,
            "counts": {"installations": 1, "principals": 3, "groups": 2, "overrides": 2},
            "schemaSha256": native._schema_digest(auth.SCHEMA),
            "tableSha256": {table: manifest["summary"]["tableSha256"][table] for table in auth.COLUMNS}})
        sql = (case.output / package.SQL).read_bytes()
        self.assertEqual(manifest["sql"]["sha256"], native.digest(sql))
        by_key = {item["key"]: item["metadata"] for item in manifest["objects"]}
        with closing(sqlite3.connect(":memory:")) as db:
            db.execute("PRAGMA foreign_keys=ON")
            db.executescript(sql.decode("utf-8"))
            self.assertEqual(db.execute("PRAGMA foreign_key_check").fetchall(), [])
            self.assertEqual(package.db_summary(db, manifest["layout"]), manifest["summary"])
            self.assertEqual(native.object_references(db, lambda key: ((case.output / "objects" / key).read_bytes(), by_key[key])),
                             manifest["objects"])
            self.assertEqual(db.execute(f"SELECT user_id,is_admin,is_allowlisted,override_allowed,override_created_at,override_updated_at "
                                       f"FROM {auth.PRINCIPALS} ORDER BY CAST(user_id AS INTEGER)").fetchall(),
                             sorted([(OWNER, 1, 0, 0, 10, 20), (MEMBER, 0, 0, 1, 11, 30),
                                     (dynamic.FOREIGN_OWNER, 0, 1, None, None, None)], key=lambda row: int(row[0])))
            self.assertEqual(db.execute(f"SELECT chat_id FROM {auth.GROUPS} ORDER BY CAST(chat_id AS INTEGER)").fetchall(),
                             [("-100200",), ("-100100",)])
            self.assertEqual(db.execute(f"SELECT position,name,sha256,mode,applied_at FROM {package.migrations.LEDGER} "
                                       "ORDER BY position").fetchall(),
                             [tuple(row[column] for column in package.TABLE_COLUMNS[package.migrations.LEDGER])
                              for row in manifest["ledger"]])
            for table in ("telegram_auth", "telegram_inbox", "telegram_outbox"):
                self.assertEqual(db.execute(f"SELECT count(*) FROM {table}").fetchone(), (0,))
        # Native profiles only admit their own archives.
        for verify in (native_shares.unified_share_candidate_files, native_auth.candidate_files):
            with self.assertRaises(native.RehearsalError):
                verify(manifest)

    def test_refuses_non_matching_source_bot_default_and_unconsumed_auth(self):
        case = self.v9.capture("same", extra_source_rows=add_domains)
        shares = self.v10.seal_shares(case)
        pins = self.seal(case, "sealed-auth")
        other = self.v9.capture("other", extra_source_rows=combined.add_shares)
        for candidate in (self.seal(other, "other-source"), self.seal(case, "other-bot", bot="74119"),
                          self.seal(case, "public", allowlist=()), replace(pins, target_sha256="0" * 64)):
            self.v9.assert_refused(case, profile=package.UNIFIED_AUTH_PROFILE, private_shares=shares, general_auth=candidate)
        self.v9.assert_refused(case, profile=package.UNIFIED_AUTH_PROFILE, private_shares=shares)
        self.v9.assert_refused(case, profile=package.UNIFIED_SHARES_PROFILE, private_shares=shares)
        self.v9.assert_refused(case, profile=package.UNIFIED_SHARES_PROFILE, private_shares=shares, general_auth=pins)

    def test_absent_override_table_still_seals_explicit_static_authorization(self):
        case = self.v9.capture("absent-auth", extra_source_rows=combined.add_shares)
        report = self.v9.build(case, profile=package.UNIFIED_AUTH_PROFILE, private_shares=self.v10.seal_shares(case),
                               general_auth=self.seal(case, "static-auth"))
        self.assertEqual(report["generalAuthorization"]["counts"],
                         {"installations": 1, "principals": 2, "groups": 2, "overrides": 0})


if __name__ == "__main__":
    unittest.main()
