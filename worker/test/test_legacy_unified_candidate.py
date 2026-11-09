"""Hosted replay of all supported legacy short-link types and temporary nodes."""

from contextlib import closing
from dataclasses import replace
import json
import sqlite3
from types import SimpleNamespace
import unittest

import test_legacy_restore_package as fixtures
import cloudflare_isolation as cloudflare
import legacy_dynamic_all_candidate as dynamic
from legacy_mixed_short_candidate import MixedShortInput, ORACLE_OUTCOMES
import legacy_short_namespace_inventory as namespace


package = fixtures.package
native = package.native
CAPABILITIES = (
    cloudflare.LEGACY_SELECTED_HTTP_MARKER, cloudflare.LEGACY_SELECTED_RETIREMENT_MARKER,
    cloudflare.LEGACY_TEMP_READ_MARKER, cloudflare.LEGACY_TEMP_MUTATE_MARKER,
    cloudflare.LEGACY_DYNAMIC_ALL_READ_MARKER, cloudflare.LEGACY_DYNAMIC_ALL_ORDER_MARKER,
)
ACTIVE_CODE, TRASH_CODE, EXTERNAL_CODE, SELECTED_CODE = (
    "UnifiedAct01", "UnifiedDel01", "UnifiedExt01", "UnifiedSel01",
)
EXTERNAL_URL = "https://example.org/fixture?mode=exact#keep"
SELECTED_IDS = (dynamic.BETA_ID, dynamic.LEGACY_TRASH_ID, dynamic.ALPHA_ID, dynamic.BETA_ID)
ALL_CODES = (dynamic.OWNER_CODE, dynamic.TEMP_ONLY_CODE, dynamic.EMPTY_CODE)


def digest(value):
    return fixtures.digest(value.encode("ascii"))


class LegacyUnifiedCandidateTests(unittest.TestCase):
    def setUp(self):
        self.base = fixtures.LegacyRestorePackageTests()
        self.base.setUp()
        self.addCleanup(self.base.doCleanups)
        self.pin_worker(*CAPABILITIES)

    def pin_worker(self, *markers):
        module = b"export default {};\n/* " + b" ".join(markers) + b" */\n"
        (self.base.worker / "index.js").write_bytes(module)
        path = self.base.worker / "isolation.json"
        build = json.loads(path.read_bytes())
        build["bundleSha256"] = fixtures.digest(module)
        raw = fixtures.body(build)
        path.write_bytes(raw)
        self.base.worker_sha = fixtures.digest(raw)
        self.worker_pin = {key: build[key] for key in ("revision", "compatibilityDate", "bundleSha256")}
        self.worker_pin["manifestSha256"] = self.base.worker_sha

    def capture(self, name, *, coalesced=False, absent_domains=False, extra_source_rows=None):
        root = self.base.root / name
        root.mkdir(mode=0o700)
        source, conversion, output = (root / item for item in ("source.sqlite", "conversion", "candidate"))
        dynamic.make_synthetic_source(source)
        former_group = -10074112
        owners = {str(former_group): dynamic.OWNER} if coalesced else {}
        owner = int(dynamic.OWNER)
        with closing(sqlite3.connect(source)) as db, db:
            db.executemany("INSERT INTO short_links VALUES (?,?,?,?)", (
                (ACTIVE_CODE, owner, f"{dynamic.OLD_ORIGIN}/sub/{dynamic.fixture_token('alpha')}/clash", fixtures.APPLIED_AT),
                (TRASH_CODE, owner, f"{dynamic.OLD_ORIGIN}/sub/{dynamic.fixture_token('trash')}/v2ray", fixtures.APPLIED_AT),
                (EXTERNAL_CODE, owner, EXTERNAL_URL, fixtures.APPLIED_AT),
                (SELECTED_CODE, owner, "aggregate://ids/" + ",".join(map(str, SELECTED_IDS)), fixtures.APPLIED_AT),
            ))
            if coalesced:
                db.execute("INSERT INTO temp_nodes VALUES (99,?,?,?,?)",
                           (former_group, dynamic.fixture_share("old-group"), "former group scope", fixtures.APPLIED_AT))
            if absent_domains:
                db.execute("DROP TABLE short_links")
                db.execute("DROP TABLE temp_nodes")
            if extra_source_rows is not None:
                extra_source_rows(db)
        source_sha = fixtures.digest(source.read_bytes())
        owner_map = root / "owners.json"
        fixtures.put(owner_map, fixtures.body(owners))
        owner_sha = fixtures.digest(owner_map.read_bytes())
        fixtures.convert.convert_backup(source, conversion, owner_map=owners)
        dynamic_input = dynamic.seal_dynamic_all_input(source, owners, root, source_sha256=source_sha,
            owner_map_sha256=owner_sha, old_origin=dynamic.OLD_ORIGIN, legacy_bot_id=dynamic.BOT_ID)
        inventory = json.loads((dynamic_input.namespace_dir / namespace.MANIFEST).read_bytes())["inventory"]
        mixed = MixedShortInput(source, owner_map, dynamic.OLD_ORIGIN, dynamic.BOT_ID,
            dynamic_input.namespace_dir, dynamic_input.namespace_sha256, root / "oracle", "", "3.11.18", "1.20.0")
        mixed = self.seal_external_oracle(mixed, source_sha, inventory)
        return SimpleNamespace(conversion=conversion, output=output, source_sha=source_sha, owner_sha=owner_sha,
                               mixed=mixed, dynamic=dynamic_input, inventory=inventory)

    def seal_external_oracle(self, mixed, source_sha, inventory):
        # Model one exact result from the independent offline comparator.
        # Emitted Worker redirect behavior remains covered by the real oracle.
        count = inventory["kinds"]["external"]
        self.assertIn(count, (0, 1))
        rows = (fixtures.body({"codeSha256": digest(EXTERNAL_CODE), "state": "equivalent"}) + b"\n") if count else b""
        outcomes = dict.fromkeys(ORACLE_OUTCOMES, 0)
        outcomes["equivalent"] = count
        report = fixtures.body({
            "version": 1, "kind": "legacy-external-redirect-oracle", "scope": "offline-dormant",
            "sourceSha256": source_sha, "inventorySha256": mixed.namespace_sha256, "worker": self.worker_pin,
            "legacySerializer": {"python": "3.11.18", "aiohttp": "3.11.18", "yarl": "1.20.0"},
            "sourceRows": inventory["rows"], "externalRows": count, "inventoryBlockedRows": inventory["blocked"],
            "outcomes": outcomes, "files": [{"file": "external.ndjson", "bytes": len(rows), "sha256": fixtures.digest(rows)}],
        }) + b"\n"
        seal = fixtures.digest(report)
        fixtures.put(mixed.oracle / "manifest.json", report)
        fixtures.put(mixed.oracle / "manifest.sha256", seal.encode("ascii") + b"\n")
        fixtures.put(mixed.oracle / "external.ndjson", rows)
        return replace(mixed, oracle_sha256=seal)

    def build(self, case, **overrides):
        options = {"profile": package.UNIFIED_PROFILE, "source_sqlite_sha": case.source_sha, "owner_map_sha": case.owner_sha,
                   "mixed_short": case.mixed, "dynamic_all": case.dynamic}
        return package.build_candidate(case.conversion, self.base.worker, case.output,
            converter_manifest_sha=fixtures.digest((case.conversion / package.MANIFEST).read_bytes()),
            worker_manifest_sha=self.base.worker_sha, revision=fixtures.REVISION, applied_at=fixtures.APPLIED_AT,
            **(options | overrides))

    def assert_refused(self, case, **overrides):
        with self.assertRaises(package.PackageError) as caught:
            self.build(case, **overrides)
        self.assertEqual(str(caught.exception), package.ERROR)
        self.assertFalse(case.output.exists())

    def test_unified_manifest_and_exact_dormant_replay(self):
        case = self.capture("unified")
        report = self.build(case)
        raw = (case.output / package.MANIFEST).read_bytes()
        manifest = json.loads(raw)
        self.assertEqual((manifest["version"], manifest["scope"]), (9, "fresh-unbound-d1-r2"))
        self.assertEqual(report["manifestSha256"], fixtures.digest(raw))
        self.assertEqual((case.output / package.MARKER).read_bytes(), report["manifestSha256"].encode("ascii") + b"\n")
        self.assertEqual(manifest["shortLinkCompatibility"], {"typed": "not-validated", "external": "offline-equivalent",
                                                            "selected": "not-validated", "dynamicAll": "not-validated"})
        for name, expected in (
            ("typedShortLinks", {"rows": 2, "activeRows": 1, "trashRows": 1}),
            ("externalShortLinks", {"rows": 1}),
            ("selectedAggregateLinks", {"rows": 1, "watchRows": 3, "retiredWatchRows": 1}),
            ("dynamicAll", {"rows": 3, "markers": 3, "orderRows": 0, "state": "dormant"}),
            ("legacyTempBaseline", {"installations": 1, "batches": 3, "nodes": 4, "owners": 3, "state": "dormant"}),
        ):
            self.assertEqual({key: manifest[name][key] for key in expected}, expected)
        for key, expected in {
            "sqliteSha256": case.source_sha, "ownerMapSha256": case.owner_sha,
            "namespaceManifestSha256": case.mixed.namespace_sha256, "oracleManifestSha256": case.mixed.oracle_sha256,
            "tempInventoryManifestSha256": case.dynamic.temp_manifest_sha256, "legacyBotId": dynamic.BOT_ID,
        }.items():
            self.assertEqual(manifest["source"][key], expected)
        self.assertEqual(manifest["workerArtifact"]["manifestSha256"], self.base.worker_sha)
        self.assertEqual(manifest["objectCount"], 8)
        sql = (case.output / package.SQL).read_bytes()
        self.assertEqual(fixtures.digest(sql), manifest["sql"]["sha256"])
        for code in (*ALL_CODES, ACTIVE_CODE, TRASH_CODE, EXTERNAL_CODE, SELECTED_CODE):
            self.assertNotIn(code.encode("ascii"), sql)
            self.assertNotIn(code.encode("ascii"), raw)
        paths = {entry.relative_to(case.output).as_posix() for entry in case.output.rglob("*") if entry.is_file()}
        objects = {entry["key"]: entry for entry in manifest["objects"]}
        self.assertEqual(paths, {package.MANIFEST, package.MARKER, package.LINEAGE, package.SQL}
                         | {"objects/" + key for key in objects})
        self.assertEqual(case.output.stat().st_mode & 0o777, 0o700)
        self.assertTrue(all((case.output / path).stat().st_mode & 0o777 == 0o600 for path in paths))

        with closing(sqlite3.connect(":memory:")) as db:
            db.execute("PRAGMA foreign_keys=ON")
            db.executescript(sql.decode("utf-8"))
            self.assertEqual(db.execute("PRAGMA foreign_key_check").fetchall(), [])
            self.assertEqual(package.db_summary(db, native.table_layout(db, sorted(manifest["layout"]))), manifest["summary"])
            self.assertEqual(native.object_references(db, lambda key: (
                (case.output / "objects" / key).read_bytes(), objects[key]["metadata"])), manifest["objects"])
            self.assertEqual(db.execute("SELECT id,owner_id,keyword,remark FROM path_rules").fetchall(),
                             [(7, dynamic.OWNER, "alpha", "mapped")])
            self.assertEqual(db.execute("SELECT * FROM legacy_empty_subscription_exports").fetchall(),
                             [(dynamic.EMPTY_ID, dynamic.OWNER, digest(dynamic.fixture_token("empty")))])
            self.assertEqual(db.execute("SELECT id,owner_id,token FROM subscription_trash").fetchall(),
                             [(dynamic.TARGET_TRASH_ID, dynamic.OWNER, dynamic.fixture_token("trash"))])
            self.assertEqual(db.execute("SELECT seq FROM sqlite_sequence WHERE name='subscriptions'").fetchone(),
                             (dynamic.TARGET_TRASH_ID,))
            self.assertEqual(db.execute("SELECT * FROM legacy_subscription_short_links ORDER BY code_sha256").fetchall(), sorted((
                (digest(ACTIVE_CODE), dynamic.BOT_ID, dynamic.OWNER, dynamic.ALPHA_ID,
                 digest(dynamic.fixture_token("alpha")), "clash", fixtures.APPLIED_AT, None),
                (digest(TRASH_CODE), dynamic.BOT_ID, dynamic.OWNER, dynamic.TARGET_TRASH_ID,
                 digest(dynamic.fixture_token("trash")), "v2ray", fixtures.APPLIED_AT, None),
            )))
            self.assertEqual(db.execute("SELECT * FROM normal_short_links").fetchall(),
                             [(digest(EXTERNAL_CODE), 12, dynamic.BOT_ID, dynamic.OWNER, None, None, None,
                               EXTERNAL_URL, fixtures.APPLIED_AT, None)])
            self.assertEqual(db.execute("SELECT * FROM legacy_selected_aggregates").fetchall(), [(digest(SELECTED_CODE),)])
            self.assertEqual(db.execute("SELECT * FROM legacy_selected_members ORDER BY id").fetchall(),
                             [(dynamic.ALPHA_ID, 0), (dynamic.LEGACY_TRASH_ID, 1), (dynamic.BETA_ID, 0)])
            scopes = tuple(zip(ALL_CODES, (dynamic.OWNER, dynamic.TEMP_ONLY_OWNER, dynamic.EMPTY_OWNER), strict=True))
            all_links = sorted((digest(code), owner, "all", dynamic.BOT_ID, None, dynamic.CREATED_AT + i, None)
                               for i, (code, owner) in enumerate(scopes))
            selected_link = (digest(SELECTED_CODE), dynamic.OWNER, "selected", None,
                             native.canonical(SELECTED_IDS).decode("ascii"), fixtures.APPLIED_AT, None)
            self.assertEqual(db.execute("SELECT * FROM aggregate_links ORDER BY code_sha256").fetchall(),
                             sorted([*all_links, selected_link]))
            self.assertEqual(manifest["dynamicAll"]["partitionSha256"], fixtures.digest(native.canonical(all_links)))
            self.assertEqual(manifest["selectedAggregateLinks"]["partitionSha256"], fixtures.digest(native.canonical([selected_link])))
            inventory_sha = case.dynamic.temp_manifest_sha256
            self.assertEqual(db.execute("SELECT * FROM legacy_all_aggregates ORDER BY code_sha256").fetchall(),
                             sorted((digest(code), dynamic.BOT_ID, owner, inventory_sha) for code, owner in scopes))
            self.assertEqual(db.execute("SELECT * FROM legacy_temp_installations").fetchall(),
                             [(dynamic.BOT_ID, inventory_sha, None)])
            batches = db.execute("""SELECT actor_id,first_legacy_id,last_legacy_id,nodes_json,node_count,payload_bytes,payload_sha256
                FROM legacy_temp_batches ORDER BY actor_id""").fetchall()
            self.assertEqual([(row[0], row[1], row[2], row[4]) for row in batches],
                             [(dynamic.OWNER, 2, 8, 2), (dynamic.TEMP_ONLY_OWNER, 6, 6, 1), (dynamic.FOREIGN_OWNER, 3, 3, 1)])
            for row, label, name in zip(batches, ("temporary", "temporary-only", "foreign-temporary"),
                                       ("alpha", "temporary-only", "foreign temporary"), strict=True):
                exact = fixtures.body([{"name": name, "type": "temp", "share": dynamic.fixture_share(label)}] * row[4])
                self.assertEqual((row[3].encode("utf-8"), row[5], row[6]), (exact, len(exact), fixtures.digest(exact)))
            for table in ("legacy_all_subscription_order", "telegram_inbox", "telegram_outbox", "telegram_temp_batch"):
                self.assertEqual(db.execute(f"SELECT count(*) FROM {table}").fetchone(), (0,))

    def test_existing_profiles_and_unrelated_pins_cannot_consume_unified_source(self):
        case = self.capture("pins")
        self.assert_refused(case, profile=package.DYNAMIC_ALL_PROFILE, mixed_short=None)
        self.assert_refused(case, profile=package.SELECTED_SHORT_PROFILE, dynamic_all=None)
        self.assert_refused(case, mixed_short=replace(case.mixed, oracle_sha256="0" * 64))
        self.assert_refused(case, dynamic_all=replace(case.dynamic, legacy_bot_id="74119"))
        copy = case.dynamic.source.with_name("different-source.sqlite")
        fixtures.put(copy, case.dynamic.source.read_bytes())
        self.assert_refused(case, dynamic_all=replace(case.dynamic, source=copy))
        self.pin_worker(*CAPABILITIES[:-1])
        self.assert_refused(case)

    def test_missing_optional_tables_keep_zero_rows_and_objects_intact(self):
        case = self.capture("absent", absent_domains=True)
        self.assertFalse(case.inventory["present"])
        report = self.build(case)
        self.assertEqual(report["shortLinkCompatibility"], dict.fromkeys(("typed", "external", "selected", "dynamicAll"), "not-applicable"))
        self.assertEqual((report["legacyTempBaseline"]["installations"], report["legacyTempBaseline"]["nodes"]), (0, 0))
        self.assertEqual(report["objectCount"], 8)

    def test_unified_source_cannot_widen_dynamic_all_owner_scope(self):
        case = self.capture("coalesced", coalesced=True)
        self.assertEqual(case.inventory["blockedReasons"], {"aggregate-all-owner-scope": 1})
        self.assert_refused(case)


if __name__ == "__main__":
    unittest.main()
