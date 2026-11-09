"""Hosted checks for strict legacy temporary-node projection provenance."""

from contextlib import closing
from hashlib import sha256
import json
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import test_legacy_temp_inventory as source_fixture
import legacy_temp_worker_projection as projection


inventory = source_fixture.tool
SHARE = source_fixture.SHARE


class LegacyTempWorkerProjectionTests(unittest.TestCase):
    def setUp(self):
        scratch = TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.root = Path(scratch.name).resolve()
        self.source = self.root / "legacy.sqlite"
        self.sealed = self.root / "inventory"
        self.scratch = self.root / "verification"
        self.scratch.mkdir(mode=0o700)

    def seal(self, records):
        with closing(sqlite3.connect(self.source)) as db, db:
            db.execute(source_fixture.DDL)
            db.executemany("INSERT INTO temp_nodes VALUES (?,?,?,?,?)", records)
        self.source.chmod(0o600)
        self.pins = {"source_sha256": sha256(self.source.read_bytes()).hexdigest(), "owner_map": {},
                     "owner_map_sha256": sha256(b"{}").hexdigest(), "legacy_bot_id": source_fixture.BOT}
        report = inventory.seal_inventory(self.source, self.sealed, **self.pins)
        self.manifest_sha = report["manifestSha256"]
        return report

    def verify(self, **overrides):
        pins = {**self.pins, "inventory_manifest_sha256": self.manifest_sha} | overrides
        return projection.verify_projection(self.source, self.sealed, self.scratch, **pins)

    def test_owner_numeric_order_and_exact_legacy_payloads(self):
        names = ('旧名称"\n\x01', "", "重复 URI")
        with patch.object(inventory, "MAX_BATCH_NODES", 2):
            report = self.seal([(9, 10, SHARE, names[2], 1), (4, 2, SHARE, "other owner", 2),
                                (2, 10, SHARE, names[0], 3), (6, 10, SHARE, names[1], 4)])
            result = self.verify()
        self.assertEqual([(item.owner_id, item.first_legacy_id, item.last_legacy_id, item.node_count) for item in result.batches],
                         [("2", 4, 4, 1), ("10", 2, 6, 2), ("10", 9, 9, 1)])
        for batch, group in zip(result.batches, (("other owner",), names[:2], names[2:]), strict=True):
            expected = source_fixture.json_bytes([{"name": name, "type": "temp", "share": SHARE} for name in group])
            self.assertEqual(batch.payload_json.encode("utf-8"), expected)
            self.assertEqual(batch.payload_bytes, len(expected))
            self.assertNotIn(SHARE, repr(batch))
        self.assertEqual((result.node_count, result.payload_bytes, result.inventory_manifest_sha256),
                         (4, report["inventory"]["projection"]["payloadBytes"], self.manifest_sha))
        self.assertEqual(list(self.scratch.iterdir()), [])

    def test_quota_blocker_rejects_whole_projection(self):
        with patch.object(inventory, "MAX_OWNER_NODES", 1):
            report = self.seal([(1, 123, SHARE, "first", 1), (2, 123, SHARE, "second", 2)])
            self.assertEqual(report["inventory"]["pendingWorkerRows"], 2)
            self.assertEqual(report["inventory"]["blockedOwnerScopes"], 1)
            with self.assertRaisesRegex(projection.ProjectionError, "could not be verified safely"):
                self.verify()
        self.assertEqual(list(self.scratch.iterdir()), [])

    def test_structural_blocker_rejects_whole_projection(self):
        self.seal([(1, 123, SHARE, "first", 1), (2, 123, SHARE + "\n", "invalid", 2)])
        with self.assertRaises(projection.ProjectionError):
            self.verify()

    def test_mutated_and_independently_resealed_rows_cannot_replace_source(self):
        self.seal([(1, 123, SHARE, "source name", 1)])
        rows = self.sealed / inventory.ROWS
        raw = rows.read_bytes().replace(b"source name", b"tampered name")
        rows.write_bytes(raw)
        with self.assertRaises(projection.ProjectionError):
            self.verify()
        manifest_path = self.sealed / inventory.MANIFEST
        manifest = json.loads(manifest_path.read_bytes())
        manifest["files"][0].update(bytes=len(raw), sha256=sha256(raw).hexdigest())
        manifest_raw = source_fixture.json_bytes(manifest) + b"\n"
        manifest_sha = sha256(manifest_raw).hexdigest()
        manifest_path.write_bytes(manifest_raw)
        (self.sealed / inventory.SEAL).write_bytes(manifest_sha.encode("ascii") + b"\n")
        with self.assertRaises(projection.ProjectionError):
            self.verify(inventory_manifest_sha256=manifest_sha)

    def test_private_exact_file_closure_is_required(self):
        self.seal([])
        self.assertEqual(self.verify().batches, ())
        stray = self.sealed / "unsealed-sidecar"
        stray.touch()
        with self.assertRaises(projection.ProjectionError):
            self.verify()
        stray.unlink()
        (self.sealed / inventory.ROWS).chmod(0o644)
        with self.assertRaises(projection.ProjectionError):
            self.verify()


if __name__ == "__main__":
    unittest.main()
