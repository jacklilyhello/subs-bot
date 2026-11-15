"""Hosted loopback-only restored-link replay; no production or network client."""
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import unittest

import test_native_restore_rehearsal as fixtures
from test_native_restore_rehearsal import SNAPSHOT, native


class RestoredLinksTests(unittest.TestCase):
    def test_exact_bundle_restored_exports_denials_and_corrupt_object(self):
        fixture = fixtures.SnapshotTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.snapshot()
        share = "ss://YWVzLTI1Ni1nY206Zml4dHVyZQ@203.0.113.10:8388#restored-synthetic"
        raw = native.canonical({"share": share}) + b"\n"
        prefix = f"subscriptions/1/{SNAPSHOT}/"
        plan = native.canonical({"version": 1, "chunks": [{"bytes": len(raw), "sha256": native.digest(raw), "count": 1}]})
        fixture.bodies[prefix + "0.ndjson"] = raw
        fixture.bodies[prefix + "manifest.json"] = plan
        fixture.db.execute("UPDATE subscriptions SET manifest_sha256=? WHERE id=1", (native.digest(plan),))
        fixture.db.execute("INSERT INTO subscriptions(id,owner_id,name,source_url,token,created_at,updated_at) VALUES (2,'881001','empty','https://example.invalid/','native-empty-token-001',1,1)")
        fixture.db.execute("INSERT INTO legacy_empty_subscription_exports VALUES(2,'881001',?)", (native.digest(b"native-empty-token-001"),))
        fixture.db.execute("INSERT INTO subscriptions(id,owner_id,name,source_url,token,created_at,updated_at) VALUES (3,'881001','unpublished','https://example.invalid/','native-pending-token-01',1,1)")
        fixture.db.execute("INSERT INTO subscription_lifecycle VALUES(4,1)")
        fixture.db.execute("""INSERT INTO subscription_trash(id,owner_id,name,source_url,token,created_at,updated_at,generation,node_count,deleted_at,lifecycle_revision)
            VALUES(4,'881001','trash','https://example.invalid/','native-trash-token-001',1,1,0,0,1,1)""")
        # Native import permits large TEXT despite query SQL's 100KB bound.
        # Replay must bind it, preserve it exactly and retain sequence highwater.
        fixture.db.execute("INSERT INTO telegram_inbox(receipt_id,bot_id,update_id,actor_id,chat_id,chat_type,message_id,message_date,command,receipt_nonce) VALUES (1,'881000',1,'881001','881001','private',1,1,'list','temp:v1')")
        node = {"share": share, "padding": ""}
        node["padding"] = "x" * (262_144 - len(native.canonical([node])))
        large_text = native.canonical([node]).decode()
        fixture.db.execute("INSERT INTO telegram_temp_batch VALUES (1,'881000','881001',1,1,?,1,?)", (large_text, len(large_text.encode())))
        fixture.db.execute("UPDATE subscriptions SET traffic_used=1.25 WHERE id=1")
        # A retained valid snapshot can exceed the separate raw-share export
        # cap by one byte while remaining below the encoded oracle body cap.
        oversized_snapshot = "cccccccc-dddd-eeee-ffff-000000000000"
        oversized_prefix = f"subscriptions/5/{oversized_snapshot}/"
        lengths = [((16 * 1024 * 1024 + 1 - 32) // 33) + (index < (16 * 1024 * 1024 + 1 - 32) % 33) for index in range(33)]
        chunks = []
        for index, length in enumerate(lengths):
            body = native.canonical({"share": "ssr://" + "x" * (length - 6)}) + b"\n"
            self.assertLessEqual(len(body), native.OBJECT_BYTES)
            fixture.bodies[oversized_prefix + f"{index}.ndjson"] = body
            chunks.append({"bytes": len(body), "sha256": native.digest(body), "count": 1})
        oversized_manifest = native.canonical({"version": 1, "chunks": chunks})
        fixture.bodies[oversized_prefix + "manifest.json"] = oversized_manifest
        fixture.db.execute("""INSERT INTO subscriptions(id,owner_id,name,source_url,token,created_at,updated_at,generation,snapshot_id,manifest_sha256,node_count)
            VALUES(5,'881001','oversize','https://example.invalid/','native-oversize-token-01',1,1,1,?,?,33)""", (oversized_snapshot, native.digest(oversized_manifest)))
        fixture.db.execute("UPDATE sqlite_sequence SET seq=9 WHERE name='subscriptions'")
        bundle = Path(os.environ["WORKER_TEST_BUNDLE_DIR"]).resolve()
        manifest = json.loads((bundle / "isolation.json").read_bytes())
        fixture.source.manifest = manifest
        sql = fixture.dump("restore")
        db, layout, summary = native.open_export(sql, fixture.source)
        db.close()
        refs = [{"key": key, "bytes": len(body), "sha256": native.digest(body), "metadata": {"custom": {}, "http": {}}}
            for key, body in sorted(fixture.bodies.items())]
        document = {"sqlSha256": native.digest(sql.read_bytes()), "objects": refs, "summary": summary}
        root = fixture.directory / "validation"
        api = SimpleNamespace(names={"objects": "synthetic-restored-r2"},
            object_or_none=lambda bucket, key: (fixture.bodies.get(key), None))
        engine = native.Rehearsal(api, fixture.source, None, fixture.directory, validation_directory=root)
        engine.prepare_link_validation(document)
        report = fixture.directory / "report.json"
        command = [os.environ.get("SUBS_BOT_NATIVE_ORACLE_NODE", "node"), "tools/native-restored-links.ts", str(root), str(bundle), str(report)]
        result = subprocess.run(command, capture_output=True, timeout=120)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        output = json.loads(result.stdout)
        self.assertEqual(output, json.loads(report.read_bytes()))
        self.assertEqual(output["counts"], {"storedShareExports": 1, "legacyEmptyExports": 1, "unpublishedDenials": 1, "oversizeDenials": 1,
            "trashDenials": 1, "missingDenials": 1, "omittedStructuredOrInvalidShare": 0,
            "omittedResponseLimit": 0, "omittedHashedCapabilities": 0})
        self.assertEqual(output["outboundAttempts"], 0)
        self.assertEqual(output["migrationCount"], len(manifest["migrations"]))
        self.assertEqual(output["restoredEffectiveDisplayTimezones"], ["UTC"])
        self.assertNotIn(b"abcdefghijklmnop", result.stdout)
        self.assertNotIn(share.encode(), result.stdout)
        input_path = root / "input.json"
        original_input = input_path.read_bytes()
        altered_input = json.loads(original_input)
        altered_input["replay"]["tables"][0]["rows"].append([["text", "private alteration"]])
        input_path.write_bytes(native.canonical(altered_input))
        altered = subprocess.run(command, capture_output=True, timeout=120)
        self.assertNotEqual(altered.returncode, 0)
        self.assertIn(b"stage=private-input", altered.stderr)
        self.assertEqual(altered.stdout, b"")
        input_path.write_bytes(original_input)
        (root / "object-0.bin").write_bytes(b"corrupt")
        corrupted = subprocess.run(command, capture_output=True, timeout=120)
        self.assertNotEqual(corrupted.returncode, 0)
        self.assertIn(b"stage=private-input", corrupted.stderr)
        self.assertEqual(corrupted.stdout, b"")


if __name__ == "__main__":
    unittest.main()
