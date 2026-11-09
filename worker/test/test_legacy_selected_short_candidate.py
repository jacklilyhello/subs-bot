"""Hosted V6 package assertions. Selected HTTP compatibility is separate."""

from contextlib import closing
from dataclasses import replace
from io import BytesIO
import json
import sqlite3
import unittest
from zipfile import ZipFile

import test_legacy_restore_package as existing
import legacy_candidate_isolation as protected
import legacy_short_namespace_inventory as namespace
from cloudflare_isolation import LEGACY_SELECTED_HTTP_MARKER, LEGACY_SELECTED_RETIREMENT_MARKER
from legacy_mixed_short_candidate import MixedShortInput


package = existing.package
SELECTED = (
    ("SelMixed0001", 123, (5, 2, 4, 2, 50)),
    ("SelEmpty0002", 123, (5,)),
    ("SelHoles0003", -100123, (4, 50, 4)),
)


class LegacySelectedShortCandidateTests(unittest.TestCase):
    def setUp(self):
        self.fixture = existing.LegacyRestorePackageTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.manifest_path = self.fixture.worker / "isolation.json"

    def pin_module(self, *markers):
        module = self.fixture.worker / "index.js"
        module.write_bytes(b"export default {};\n/* " + b" ".join(markers) + b" */\n")
        build = json.loads(self.manifest_path.read_bytes())
        build["bundleSha256"] = existing.digest(module.read_bytes())
        self.manifest_path.write_bytes(existing.body(build))
        self.fixture.worker_sha = existing.digest(self.manifest_path.read_bytes())

    def capture(self, *, extra=None, external=True, selections=SELECTED, coalesced_path=False, remap_active=False, typed_active=True,
                markers=(LEGACY_SELECTED_HTTP_MARKER, LEGACY_SELECTED_RETIREMENT_MARKER)):
        self.pin_module(*markers)
        protected.make_synthetic_source(self.fixture.legacy, protected.MIXED_PROFILE)
        owners = dict(protected.OWNER_MAP)
        with closing(sqlite3.connect(self.fixture.legacy)) as db, db:
            if not external:
                db.executemany("DELETE FROM short_links WHERE code=?", [(row[0],) for row in protected.EXTERNAL_LINK_FIXTURES])
            if not typed_active:
                db.execute("DELETE FROM short_links WHERE code='TypedAct0001'")
            if coalesced_path:
                owners["-100124"] = "123"
                db.execute("DELETE FROM path_maps")
                db.execute("INSERT INTO path_maps VALUES (42,-100124,'synthetic raw','imported path')")
            if remap_active:
                db.execute("UPDATE subscriptions SET user_id=-100123 WHERE id=2")
                db.execute("UPDATE short_links SET user_id=-100123 WHERE code='TypedAct0001'")
            for code, issuer, identities in selections:
                db.execute("INSERT INTO short_links VALUES (?,?,?,?)", (code, issuer,
                    "aggregate://ids/" + ",".join(map(str, identities)), existing.APPLIED_AT))
            if extra:
                issuer, target = extra
                if issuer == -100124:
                    owners[str(issuer)] = "123"
                db.execute("INSERT INTO short_links VALUES ('SelBlocked01',?,?,?)", (issuer, target, existing.APPLIED_AT))
            source_count = db.execute("SELECT count(*) FROM short_links").fetchone()[0]
        self.source_sha = existing.digest(self.fixture.legacy.read_bytes())
        owner_map = self.fixture.root / "owners.json"
        existing.put(owner_map, existing.body(owners))
        self.owner_sha = existing.digest(owner_map.read_bytes())
        report = existing.convert.convert_backup(self.fixture.legacy, self.fixture.conversion, owner_map=owners)
        self.assertEqual(report["blockers"], {"unhandled:short_links": source_count})
        self.fixture.convert_sha = existing.digest((self.fixture.conversion / package.MANIFEST).read_bytes())
        inventory = self.fixture.root / "namespace"
        namespace.seal_inventory(self.fixture.legacy, inventory, source_sha256=self.source_sha,
            owner_map=owners, owner_map_sha256=self.owner_sha, old_origin=protected.TYPED_ORIGIN,
            legacy_bot_id=protected.TYPED_BOT)
        raw = (inventory / namespace.MANIFEST).read_bytes()
        self.inventory = json.loads(raw)["inventory"]
        self.pins = MixedShortInput(self.fixture.legacy, owner_map, protected.TYPED_ORIGIN, protected.TYPED_BOT,
            inventory, existing.digest(raw),
            self.fixture.root / "oracle", "", "3.11.18", "1.20.0")
        self.write_external_oracle(source_count, external, self.inventory["blocked"])

    def write_external_oracle(self, source_count, external, blocked):
        # Independently seal the synthetic external-only comparator output.
        external_codes = [item[0] for item in protected.EXTERNAL_LINK_FIXTURES] if external else []
        rows = b"".join(existing.body({"codeSha256": existing.digest(code.encode("ascii")), "state": "equivalent"}) + b"\n"
                        for code in external_codes)
        build = json.loads(self.manifest_path.read_bytes())
        worker = {key: build[key] for key in ("revision", "compatibilityDate", "bundleSha256")}
        worker["manifestSha256"] = self.fixture.worker_sha
        report = existing.body({"version": 1, "kind": "legacy-external-redirect-oracle", "scope": "offline-dormant",
            "sourceSha256": self.source_sha, "inventorySha256": self.pins.namespace_sha256, "worker": worker,
            "legacySerializer": {"python": "3.11.18", "aiohttp": "3.11.18", "yarl": "1.20.0"},
            "sourceRows": source_count, "externalRows": len(external_codes), "inventoryBlockedRows": blocked,
            "outcomes": {"equivalent": len(external_codes), "inventory-blocked": 0, "legacy-rejected": 0,
                         "worker-refused": 0, "location-differs": 0, "worker-unconfirmed": 0},
            "files": [{"file": "external.ndjson", "bytes": len(rows), "sha256": existing.digest(rows)}]}) + b"\n"
        self.pins = replace(self.pins, oracle_sha256=existing.digest(report))
        existing.put(self.pins.oracle / "manifest.json", report)
        existing.put(self.pins.oracle / "manifest.sha256", self.pins.oracle_sha256.encode("ascii") + b"\n")
        existing.put(self.pins.oracle / "external.ndjson", rows)

    def build(self, *, profile=package.SELECTED_SHORT_PROFILE, **overrides):
        return self.fixture.build(**({"profile": profile, "source_sqlite_sha": self.source_sha,
                                    "owner_map_sha": self.owner_sha, "mixed_short": self.pins} | overrides))

    def test_v6_replays_all_short_domains_and_permanently_watches_exact_legacy_ids(self):
        self.capture()
        with self.assertRaises(package.PackageError):
            self.build(profile=package.MIXED_SHORT_PROFILE)
        with self.assertRaises(package.PackageError):
            self.build(mixed_short=replace(self.pins, namespace_sha256="0" * 64))
        self.assertFalse(self.fixture.output.exists())

        report = self.build()
        self.assertEqual(report["version"], 6)
        self.assertEqual(report["shortLinkCompatibility"], {"typed": "not-validated", "external": "offline-equivalent",
                                                           "selected": "not-validated"})
        self.assertEqual(report["typedShortLinks"]["rows"], 4)
        self.assertEqual(report["externalShortLinks"]["rows"], 2)
        selected = report["selectedAggregateLinks"]
        self.assertEqual((selected["rows"], selected["watchRows"], selected["retiredWatchRows"]), (3, 4, 2))
        manifest_raw = (self.fixture.output / package.MANIFEST).read_bytes()
        manifest = json.loads(manifest_raw)
        self.assertEqual(manifest["source"]["selectedActiveHighWater"], 50)
        self.assertEqual(selected["tableSha256"], {table: manifest["summary"]["tableSha256"][table]
                                                  for table in package.SELECTED_COLUMNS})
        self.assertEqual(report["objectCount"], 4)
        self.assertEqual((self.fixture.output / package.MARKER).read_text(), existing.digest(manifest_raw) + "\n")
        sql = (self.fixture.output / package.SQL).read_text()
        for code, _, _ in SELECTED:
            self.assertNotIn(code, sql)
        with closing(sqlite3.connect(":memory:")) as db:
            db.execute("PRAGMA foreign_keys=ON")
            db.executescript(sql)
            actual = db.execute("SELECT * FROM aggregate_links ORDER BY code_sha256").fetchall()
            expected = sorted((existing.digest(code.encode("ascii")), "123" if issuer == 123 else "456", "selected", None,
                               existing.body(ids).decode("ascii"), existing.APPLIED_AT, None) for code, issuer, ids in SELECTED)
            self.assertEqual(actual, expected)
            self.assertEqual(db.execute("SELECT * FROM legacy_selected_members ORDER BY id").fetchall(),
                             [(2, 0), (4, 1), (5, 0), (50, 1)])
            self.assertEqual(db.execute("SELECT * FROM legacy_selected_aggregates ORDER BY code_sha256").fetchall(),
                             [(row[0],) for row in expected])
            self.assertEqual(db.execute("SELECT id FROM subscription_trash ORDER BY id").fetchall(), [(71,), (72,)])
            self.assertEqual(db.execute("SELECT seq FROM sqlite_sequence WHERE name='subscriptions'").fetchone(), (72,))
            self.assertEqual(db.execute("SELECT count(*) FROM telegram_inbox").fetchone(), (0,))
            self.assertEqual(db.execute("PRAGMA foreign_key_check").fetchall(), [])

        zipped = BytesIO()
        with ZipFile(zipped, "w") as archive:
            for file in self.fixture.output.rglob("*"):
                if file.is_file():
                    archive.write(file, file.relative_to(self.fixture.output))
        body = zipped.getvalue()
        destination = self.fixture.root / "protected-v5"
        with self.assertRaises(protected.native.RehearsalError):
            protected.unpack_candidate(body, existing.digest(body), destination, profile=protected.MIXED_PROFILE)
        self.assertFalse(destination.exists())

    def test_selected_can_be_packaged_with_a_verified_zero_row_external_oracle(self):
        self.capture(external=False)
        report = self.build()
        self.assertEqual(report["externalShortLinks"]["rows"], 0)
        self.assertEqual(report["shortLinkCompatibility"]["external"], "not-applicable")

    def test_refuses_foreign_source_owner_before_mapping_even_when_same_target_owner_is_possible(self):
        self.capture(extra=(-100124, "aggregate://ids/2"))
        self.assertEqual(self.inventory["blockedReasons"], {"aggregate-selected-foreign-owner": 1})
        with self.assertRaises(package.PackageError):
            self.build()
        self.assertFalse(self.fixture.output.exists())

    def test_refuses_outside_independent_active_allocator_even_below_trash_allocator(self):
        self.capture(extra=(123, "aggregate://ids/60"))
        self.assertEqual(self.inventory["blockedReasons"], {"aggregate-selected-lineage": 1})
        with self.assertRaises(package.PackageError):
            self.build()
        self.assertFalse(self.fixture.output.exists())

    def test_refuses_even_a_classified_dynamic_link(self):
        self.capture(extra=(123, "aggregate://all"))
        self.assertEqual(self.inventory["kinds"]["aggregate-all"], 1)
        self.assertEqual(self.inventory["blocked"], 0)
        with self.assertRaises(package.PackageError):
            self.build()
        self.assertFalse(self.fixture.output.exists())

    def test_refuses_live_member_when_another_source_contributes_a_path_rule(self):
        self.capture(coalesced_path=True)
        self.assertEqual(self.inventory["blocked"], 0)
        with self.assertRaises(package.PackageError):
            self.build()
        self.assertFalse(self.fixture.output.exists())

    def test_refuses_live_member_of_a_remapped_original_owner(self):
        self.capture(selections=(("SelMixed0001", -100123, (2,)),), remap_active=True)
        self.assertEqual(self.inventory["blocked"], 0)
        with self.assertRaises(package.PackageError):
            self.build()
        self.assertFalse(self.fixture.output.exists())

    def test_refuses_resealed_conversion_with_wrong_live_member_token(self):
        self.capture(typed_active=False)
        self.fixture.reseal_row("active.ndjson", lambda item: item["record"].update(token="fixture-replaced-selected-token"),
                                valid=False)
        self.assertEqual(existing.convert.verify_bundle(self.fixture.conversion, require_complete=False)["sourceSha256"], self.source_sha)
        with self.assertRaises(package.PackageError):
            self.build()
        self.assertFalse((self.fixture.output / package.MARKER).exists())

    def test_remapped_and_coalesced_owners_can_keep_all_hole_selections(self):
        self.capture(selections=(("SelMixed0001", 123, (4,)), SELECTED[2]), coalesced_path=True)
        report = self.build()
        selected = report["selectedAggregateLinks"]
        self.assertEqual((selected["rows"], selected["watchRows"], selected["retiredWatchRows"]), (2, 2, 2))
        with closing(sqlite3.connect(":memory:")) as db:
            db.executescript((self.fixture.output / package.SQL).read_text())
            self.assertEqual(db.execute("SELECT owner_id FROM aggregate_links ORDER BY owner_id").fetchall(), [("123",), ("456",)])
            self.assertEqual(db.execute("SELECT id,retired FROM legacy_selected_members ORDER BY id").fetchall(), [(4, 1), (50, 1)])
            self.assertEqual(db.execute("SELECT owner_id,keyword FROM path_rules").fetchall(), [("123", "synthetic raw")])

    def test_refuses_artifact_missing_one_capability(self):
        self.capture(markers=(LEGACY_SELECTED_HTTP_MARKER,))
        with self.assertRaises(package.PackageError):
            self.build()
        self.assertFalse(self.fixture.output.exists())


if __name__ == "__main__":
    unittest.main()
