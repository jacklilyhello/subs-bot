"""Hosted tests for the sealed, dormant legacy dynamic-all package."""

from contextlib import closing
from dataclasses import replace
from io import BytesIO
import json
import sqlite3
from types import SimpleNamespace
import unittest
from zipfile import ZipFile

import test_legacy_restore_package as fixtures
import cloudflare_isolation as cloudflare
import legacy_candidate_isolation as protected
import legacy_dynamic_all_candidate as dynamic
import legacy_short_namespace_inventory as namespace
import legacy_temp_inventory as temp


package = fixtures.package
native = protected.native
CAPABILITIES = (cloudflare.LEGACY_TEMP_READ_MARKER, cloudflare.LEGACY_TEMP_MUTATE_MARKER,
                cloudflare.LEGACY_DYNAMIC_ALL_READ_MARKER, cloudflare.LEGACY_DYNAMIC_ALL_ORDER_MARKER)


class LegacyDynamicAllCandidateTests(unittest.TestCase):
    def setUp(self):
        self.base = fixtures.LegacyRestorePackageTests()
        self.base.setUp()
        self.addCleanup(self.base.doCleanups)
        self.root, self.worker = self.base.root, self.base.worker
        self.pin_worker(*CAPABILITIES)

    def pin_worker(self, *markers):
        module = b"export default {};\n/* " + b" ".join(markers) + b" */\n"
        (self.worker / "index.js").write_bytes(module)
        path = self.worker / "isolation.json"
        manifest = json.loads(path.read_bytes())
        manifest["bundleSha256"] = native.digest(module)
        for item in manifest["migrations"]:
            item["sha256"] = native.digest((self.worker / item["name"]).read_bytes())
        raw = native.canonical(manifest)
        path.write_bytes(raw)
        self.worker_sha = native.digest(raw)

    def capture(self, name, *, owner_map=None, change=None):
        root = self.root / name
        root.mkdir(mode=0o700)
        source, conversion, output = (root / item for item in ("source.sqlite", "conversion", "candidate"))
        dynamic.make_synthetic_source(source)
        if change is not None:
            with closing(sqlite3.connect(source)) as db, db:
                change(db)
        source_sha = native.file_hash(source)[1]
        owners = owner_map if owner_map is not None else {}
        owner_sha = native.digest(native.canonical(owners))
        fixtures.convert.convert_backup(source, conversion, owner_map=owners)
        inputs = dynamic.seal_dynamic_all_input(source, owners, root, source_sha256=source_sha,
            owner_map_sha256=owner_sha, old_origin=dynamic.OLD_ORIGIN, legacy_bot_id=dynamic.BOT_ID)
        return SimpleNamespace(source=source, source_sha=source_sha, conversion=conversion, owner_sha=owner_sha,
                               inputs=inputs, output=output)

    def build(self, case, **overrides):
        options = {"converter_manifest_sha": native.file_hash(case.conversion / package.MANIFEST)[1],
                   "worker_manifest_sha": self.worker_sha, "revision": fixtures.REVISION, "applied_at": fixtures.APPLIED_AT,
                   "profile": package.DYNAMIC_ALL_PROFILE, "dynamic_all": case.inputs, "source_sqlite_sha": case.source_sha,
                   "owner_map_sha": case.owner_sha}
        return package.build_candidate(case.conversion, self.worker, case.output, **(options | overrides))

    def assert_refused(self, case, **overrides):
        with self.assertRaises(package.PackageError) as caught:
            self.build(case, **overrides)
        self.assertEqual(str(caught.exception), package.ERROR)
        self.assertFalse(case.output.exists())

    def test_fixed_package_has_exact_dormant_rows_lineage_and_object_closure(self):
        root = self.root / "fixed"
        root.mkdir(mode=0o700)
        result = dynamic.build_dynamic_all_fixture(root, self.worker, fixtures.REVISION)
        raw = (result.candidate / package.MANIFEST).read_bytes()
        manifest = json.loads(raw)
        self.assertEqual((manifest["version"], manifest["scope"]), (8, "fresh-unbound-d1-r2"))
        self.assertEqual(result.candidate_sha256, native.digest(raw))
        self.assertEqual((result.candidate / package.MARKER).read_bytes(), result.candidate_sha256.encode("ascii") + b"\n")
        self.assertEqual(manifest["source"]["sqliteSha256"], result.source_sha256)
        self.assertEqual(manifest["workerArtifact"]["manifestSha256"], self.worker_sha)
        self.assertEqual(manifest["objectCount"], 8)
        ledger_count = len(self.base.chain)
        self.assertEqual((manifest["summary"]["rowCount"], manifest["summary"]["tableCounts"]["subs_bot_schema_migrations"]),
                         (20 + ledger_count, ledger_count))
        self.assertEqual({key: manifest["dynamicAll"][key] for key in ("rows", "markers", "orderRows", "state")},
                         {"rows": 3, "markers": 3, "orderRows": 0, "state": "dormant"})
        self.assertEqual({key: manifest["legacyTempBaseline"][key] for key in ("installations", "batches", "nodes", "owners", "state")},
                         {"installations": 1, "batches": 3, "nodes": 4, "owners": 3, "state": "dormant"})
        hashes = manifest["summary"]["tableSha256"]
        self.assertEqual(manifest["dynamicAll"]["tableSha256"],
                         {table: hashes[table] for table in ("aggregate_links", "legacy_all_aggregates", "legacy_all_subscription_order")})
        self.assertEqual(manifest["legacyTempBaseline"]["tableSha256"],
                         {table: hashes[table] for table in ("legacy_temp_installations", "legacy_temp_batches")})
        paths = {file.relative_to(result.candidate).as_posix() for file in result.candidate.rglob("*") if file.is_file()}
        self.assertEqual(paths, {package.MANIFEST, package.MARKER, package.LINEAGE, package.SQL}
                         | {"objects/" + entry["key"] for entry in manifest["objects"]})
        self.assertEqual(len(paths), 12)
        self.assertEqual(result.candidate.stat().st_mode & 0o777, 0o700)
        self.assertTrue(all((result.candidate / path).stat().st_mode & 0o777 == 0o600 for path in paths))
        sql = (result.candidate / package.SQL).read_bytes()
        self.assertEqual(manifest["sql"]["sha256"], native.digest(sql))
        lineage_bytes = (result.candidate / package.LINEAGE).read_bytes()
        self.assertEqual(manifest["lineage"]["sha256"], native.digest(lineage_bytes))
        lineage = [json.loads(line) for line in lineage_bytes.splitlines()]
        self.assertEqual([(row["legacyId"], row["targetId"], row["lifecycleRevision"]) for row in lineage],
                         [(identity, identity, 0) for identity in (dynamic.ALPHA_ID, dynamic.EMPTY_ID, dynamic.BETA_ID, dynamic.FOREIGN_ID)]
                         + [(dynamic.LEGACY_TRASH_ID, dynamic.TARGET_TRASH_ID, 1)])

        with closing(sqlite3.connect(result.source.as_uri() + "?mode=ro&immutable=1", uri=True)) as source, \
                closing(sqlite3.connect(":memory:")) as restored:
            restored.execute("PRAGMA foreign_keys=ON")
            restored.executescript(sql.decode("utf-8"))
            self.assertEqual(restored.execute("PRAGMA quick_check").fetchall(), [("ok",)])
            self.assertEqual(restored.execute("PRAGMA foreign_key_check").fetchall(), [])
            self.assertEqual(package.db_summary(restored, native.table_layout(restored, sorted(manifest["layout"]))), manifest["summary"])
            source_active = source.execute("SELECT id,CAST(user_id AS TEXT),token FROM subscriptions ORDER BY id").fetchall()
            self.assertEqual(restored.execute("SELECT id,owner_id,token FROM subscriptions ORDER BY id").fetchall(), source_active)
            self.assertEqual(restored.execute("SELECT id,owner_id,token FROM subscription_trash").fetchall(),
                             [(dynamic.TARGET_TRASH_ID, dynamic.OWNER, dynamic.fixture_token("trash"))])
            self.assertEqual(restored.execute("SELECT count(*) FROM legacy_all_subscription_order").fetchone(), (0,))
            self.assertEqual(restored.execute("SELECT count(*) FROM telegram_inbox").fetchone(), (0,))
            self.assertEqual(restored.execute("SELECT count(*) FROM telegram_temp_batch").fetchone(), (0,))
            bot, inventory_sha, cutover = restored.execute("SELECT * FROM legacy_temp_installations").fetchone()
            self.assertEqual((bot, cutover), (dynamic.BOT_ID, None))
            self.assertEqual(inventory_sha, manifest["source"]["tempInventoryManifestSha256"])
            self.assertEqual(restored.execute("SELECT name,sha256 FROM subs_bot_schema_migrations WHERE position IN (39,40) ORDER BY position").fetchall(),
                             [(cloudflare.LEGACY_TEMP_MIGRATION, cloudflare.LEGACY_TEMP_MIGRATION_SHA256),
                              (cloudflare.LEGACY_DYNAMIC_ALL_MIGRATION, cloudflare.LEGACY_DYNAMIC_ALL_MIGRATION_SHA256)])
            expected_links = []
            for code, issuer, created in source.execute("SELECT code,user_id,created_at FROM short_links"):
                self.assertNotIn(code.encode("ascii"), sql)
                expected_links.append((native.digest(code.encode("ascii")), str(issuer), "all", bot, None, created, None))
            self.assertEqual(restored.execute("SELECT * FROM aggregate_links ORDER BY code_sha256").fetchall(), sorted(expected_links))
            self.assertEqual(restored.execute("SELECT * FROM legacy_all_aggregates ORDER BY code_sha256").fetchall(),
                             sorted((link[0], bot, link[1], inventory_sha) for link in expected_links))
            original = source.execute("SELECT id,user_id,url,name FROM temp_nodes ORDER BY id").fetchall()
            batches = restored.execute("SELECT * FROM legacy_temp_batches ORDER BY actor_id,first_legacy_id").fetchall()
            self.assertEqual(len(batches), 3)
            for batch_bot, owner, first, last, nodes, count, size, sha in batches:
                expected = [(identity, {"name": name, "type": "temp", "share": uri}) for identity, actor, uri, name in original
                            if str(actor) == owner]
                self.assertTrue(expected)
                self.assertEqual((batch_bot, first, last, count), (bot, expected[0][0], expected[-1][0], len(expected)))
                self.assertEqual(json.loads(nodes), [node for _, node in expected])
                self.assertEqual((size, sha), (len(nodes.encode("utf-8")), native.digest(nodes.encode("utf-8"))))
            by_key = {entry["key"]: entry for entry in manifest["objects"]}
            self.assertEqual(native.object_references(restored, lambda key: (
                (result.candidate / "objects" / key).read_bytes(), by_key[key]["metadata"])), manifest["objects"])

        zipped = BytesIO()
        with ZipFile(zipped, "w") as archive:
            for path in paths:
                archive.write(result.candidate / path, path)
        blob = zipped.getvalue()
        for profile in (protected.MIXED_PROFILE, protected.SELECTED_PROFILE, protected.TEMP_PROFILE):
            with self.subTest(profile=profile), self.assertRaises(native.RehearsalError):
                protected.unpack_candidate(blob, native.digest(blob), self.root / profile, profile=profile)

    def test_refuses_remapped_or_coalesced_scope_even_for_an_empty_link(self):
        group = -10074114

        def remap(db):
            db.execute("UPDATE short_links SET user_id=? WHERE code=?", (group, dynamic.EMPTY_CODE))

        def coalesce(db):
            db.execute("INSERT INTO temp_nodes (id,user_id,url,name,created_at) VALUES (99,?,?,?,?)",
                       (group, dynamic.fixture_share("foreign-empty-scope"), "Synthetic foreign node", fixtures.APPLIED_AT))

        for label, change in (("remapped", remap), ("coalesced", coalesce)):
            with self.subTest(label=label):
                case = self.capture(label, owner_map={str(group): dynamic.EMPTY_OWNER}, change=change)
                inventory = json.loads((case.inputs.namespace_dir / namespace.MANIFEST).read_bytes())["inventory"]
                self.assertEqual(inventory["blockedReasons"], {"aggregate-all-owner-scope": 1})
                self.assert_refused(case)

    def test_refuses_mixed_short_namespaces_without_filtering_rows(self):
        targets = {"external": "https://example.org/synthetic-target", "aggregate-selected": f"aggregate://ids/{dynamic.ALPHA_ID}",
                   "typed-subscription": f"{dynamic.OLD_ORIGIN}/sub/{dynamic.fixture_token('alpha')}/base64"}
        for kind, target in targets.items():
            with self.subTest(kind=kind):
                def add(db):
                    db.execute("INSERT INTO short_links VALUES ('DynAllMix004',?,?,?)", (int(dynamic.OWNER), target, fixtures.APPLIED_AT))
                case = self.capture(kind, change=add)
                inventory = json.loads((case.inputs.namespace_dir / namespace.MANIFEST).read_bytes())["inventory"]
                self.assertEqual(inventory["blocked"], 0)
                self.assertEqual(inventory["rows"], 4)
                self.assertEqual((inventory["kinds"]["aggregate-all"], inventory["kinds"][kind]), (3, 1))
                self.assert_refused(case)

    def test_refuses_missing_or_changed_inventory_files_and_independent_pins(self):
        case = self.capture("closure")
        for path in (case.inputs.namespace_dir / namespace.ROWS, case.inputs.temp_dir / temp.ROWS):
            original = path.read_bytes()
            path.unlink()
            self.assert_refused(case)
            fixtures.put(path, original + b"\n")
            self.assert_refused(case)
            path.write_bytes(original)
        for field in ("namespace_sha256", "temp_manifest_sha256"):
            with self.subTest(field=field):
                self.assert_refused(case, dynamic_all=replace(case.inputs, **{field: "0" * 64}))

    def test_refuses_resealed_converter_lineage_from_the_wrong_owner(self):
        case = self.capture("lineage")
        self.base.conversion = case.conversion
        self.base.reseal_row("active.ndjson", lambda row: row["record"].update(owner_id=dynamic.FOREIGN_OWNER), valid=False)
        self.assertEqual(fixtures.convert.verify_bundle(case.conversion, require_complete=False)["sourceSha256"], case.source_sha)
        self.assert_refused(case, converter_manifest_sha=self.base.convert_sha)

    def test_requires_both_capabilities_and_exact_migrations_0039_and_0040(self):
        case = self.capture("release-pins")
        for marker in CAPABILITIES:
            with self.subTest(missing=marker):
                self.pin_worker(*(item for item in CAPABILITIES if item != marker))
                self.assert_refused(case)
        for name in (cloudflare.LEGACY_TEMP_MIGRATION, cloudflare.LEGACY_DYNAMIC_ALL_MIGRATION):
            with self.subTest(migration=name):
                path = self.worker / name
                original = path.read_bytes()
                path.write_bytes(original + b"\n")
                try:
                    self.pin_worker(*CAPABILITIES)
                    self.assert_refused(case)
                finally:
                    path.write_bytes(original)


if __name__ == "__main__":
    unittest.main()
