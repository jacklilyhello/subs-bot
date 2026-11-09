from contextlib import closing
from copy import deepcopy
from hashlib import md5
import json
import sqlite3
import unittest

import test_legacy_restore_package as fixtures
import legacy_temp_native_candidate as tool


class LegacyTempNativeCandidateTests(unittest.TestCase):
    def setUp(self):
        fixture = fixtures.LegacyRestorePackageTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.root, self.worker = fixture.root, fixture.worker
        self._module(tool.cloudflare.LEGACY_TEMP_READ_MARKER, tool.cloudflare.LEGACY_TEMP_MUTATE_MARKER)

    def _module(self, *markers):
        module = b"export default {};\n" + b"\n".join(b"/* " + marker + b" */" for marker in markers)
        (self.worker / "index.js").write_bytes(module)
        path = self.worker / "isolation.json"
        manifest = json.loads(path.read_bytes())
        manifest["bundleSha256"] = tool.native.digest(module)
        raw = tool.native.canonical(manifest)
        path.write_bytes(raw)
        _, self.worker_pin = tool.package.worker_artifact(self.worker, fixtures.REVISION, tool.native.digest(raw))

    def _directory(self, name):
        path = self.root / name
        path.mkdir(mode=0o700)
        return path

    def _build(self, name="build"):
        return tool.build_temp_fixture(self._directory(name), self.worker, fixtures.REVISION)

    def _verify(self, fixture, worker_pin=None):
        return tool.TempCandidate(fixture.candidate, self.worker, worker_pin or self.worker_pin,
                                  self._directory("verification"))

    def test_exact_dormant_replay_preserves_order_and_duplicates(self):
        first = self._build()
        second = self._build("second")
        self.assertEqual((first.source_sha256, first.candidate_sha256), (second.source_sha256, second.candidate_sha256))
        candidate = self._verify(first)
        self.assertEqual(candidate.document["counts"], {"installations": 1, "owners": 2, "batches": 3, "nodes": 503})
        self.assertEqual(candidate.document["objects"], [])
        self.assertEqual(candidate.entries, {})
        self.assertEqual({path.name for path in first.candidate.iterdir()}, {"manifest.json", "manifest.sha256", "restore.sql"})
        self.assertEqual(first.candidate.stat().st_mode & 0o777, 0o700)
        self.assertTrue(all(path.stat().st_mode & 0o777 == 0o600 for path in first.candidate.iterdir()))
        with closing(sqlite3.connect(first.source.as_uri() + "?mode=ro&immutable=1", uri=True)) as source, \
                closing(sqlite3.connect(":memory:")) as restored:
            original = source.execute("SELECT id,user_id,url,name,created_at FROM temp_nodes ORDER BY id").fetchall()
            self.assertEqual(original, list(tool.fixture_rows()))
            self.assertGreater(original[0][4], original[-1][4])
            restored.execute("PRAGMA foreign_keys=ON")
            restored.executescript(candidate.sql.read_text(encoding="utf-8"))
            self.assertEqual(restored.execute("PRAGMA quick_check").fetchall(), [("ok",)])
            self.assertEqual(restored.execute("PRAGMA foreign_key_check").fetchall(), [])
            self.assertEqual(restored.execute("SELECT * FROM legacy_temp_installations").fetchall(),
                             [(tool.BOT_ID, candidate.pin()["inventoryManifestSha256"], None)])
            rows = restored.execute("SELECT bot_id,actor_id,first_legacy_id,last_legacy_id,nodes_json,node_count,"
                                    "payload_bytes,payload_sha256 FROM legacy_temp_batches ORDER BY actor_id,first_legacy_id").fetchall()
            self.assertEqual([(row[1], row[2], row[3], row[5]) for row in rows],
                             [(tool.FIRST_OWNER, 2, 1000, 500), (tool.FIRST_OWNER, 1002, 1002, 1),
                              (tool.SECOND_OWNER, 3, 1001, 2)])
            restored_nodes = {tool.FIRST_OWNER: [], tool.SECOND_OWNER: []}
            for bot, owner, _, _, nodes, count, size, digest in rows:
                body = nodes.encode("utf-8")
                self.assertEqual((bot, len(body), tool.native.digest(body)), (tool.BOT_ID, size, digest))
                self.assertEqual(len(json.loads(body)), count)
                restored_nodes[owner].extend(json.loads(body))
            for owner, nodes in restored_nodes.items():
                self.assertEqual(nodes, [{"name": name, "type": "temp", "share": uri}
                                         for _, user, uri, name, _ in original if user == int(owner)])
            self.assertEqual(restored_nodes[tool.FIRST_OWNER][499], restored_nodes[tool.FIRST_OWNER][500])
            self.assertIn("\n\x01", restored_nodes[tool.FIRST_OWNER][0]["name"])
            self.assertEqual(restored_nodes[tool.FIRST_OWNER][1]["name"], "")
            self.assertEqual(restored.execute("SELECT count(*) FROM telegram_inbox").fetchone(), (0,))
            self.assertEqual(restored.execute("SELECT count(*) FROM telegram_temp_batch").fetchone(), (0,))
        summary = candidate.document["summary"]
        evidence = candidate.native_evidence(summary)
        self.assertEqual((evidence["verifiedTempNodeCount"], evidence["verifiedTempCutover"]), (503, "dormant"))
        changed = deepcopy(summary)
        changed["tableSha256"][tool.BATCHES] = "0" * 64
        with self.assertRaisesRegex(tool.native.RehearsalError, tool.ERROR):
            candidate.native_evidence(changed)

    def test_resealed_activation_is_rejected(self):
        fixture = self._build()
        path = fixture.candidate / tool.package.MANIFEST
        document = json.loads(path.read_bytes())
        sql = fixture.candidate / tool.package.SQL
        statements = sql.read_text(encoding="utf-8").splitlines(keepends=True)
        matches = [index for index, statement in enumerate(statements)
                   if statement.startswith(f"INSERT INTO {tool.INSTALLATIONS} (")]
        self.assertEqual(len(matches), 1)
        index, = matches
        statement = statements[index]
        self.assertTrue(statement.endswith(",NULL);\n"))
        statements[index] = statement.removesuffix("NULL);\n") + "1700000000);\n"
        changed = "".join(statements).encode("utf-8")
        sql.write_bytes(changed)
        document["sql"].update(bytes=len(changed), sha256=tool.native.digest(changed), md5=md5(changed, usedforsecurity=False).hexdigest())
        raw = tool.native.canonical(document)
        path.write_bytes(raw)
        (fixture.candidate / tool.package.MARKER).write_bytes((tool.native.digest(raw) + "\n").encode("ascii"))
        with self.assertRaisesRegex(tool.native.RehearsalError, tool.ERROR):
            self._verify(fixture)

    def test_extra_entry_and_non_temp_profile_fail_closed(self):
        fixture = self._build()
        (fixture.candidate / "extra").mkdir(mode=0o700)
        with self.assertRaisesRegex(tool.native.RehearsalError, tool.ERROR):
            self._verify(fixture)
        document = json.loads((fixture.candidate / tool.package.MANIFEST).read_bytes())
        for update in ({"version": 6}, {"scope": "fresh-unbound-d1-r2"}, {"objects": [{"key": "foreign"}]}):
            with self.assertRaisesRegex(tool.native.RehearsalError, tool.ERROR):
                tool.temp_candidate_files({**document, **update})

    def test_incomplete_compiled_capability_stops_before_output(self):
        self._module(tool.cloudflare.LEGACY_TEMP_READ_MARKER)
        destination = self._directory("unbuilt")
        with self.assertRaisesRegex(tool.native.RehearsalError, tool.ERROR):
            tool.build_temp_fixture(destination, self.worker, fixtures.REVISION)
        self.assertEqual(list(destination.iterdir()), [])

    def test_statement_bound_uses_utf8_bytes(self):
        tool._bounded_sql(b"SELECT 1;\n" * 20_000)
        with self.assertRaisesRegex(tool.native.RehearsalError, tool.ERROR):
            tool._bounded_sql(("SELECT '" + "界" * 34_000 + "';\n").encode("utf-8"))
