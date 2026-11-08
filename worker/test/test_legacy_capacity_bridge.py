"""Hosted fixture tests for the legacy conversion and capacity handoff."""

from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import capacity_fixtures
import legacy_capacity_bridge as bridge


REVISION = "a" * 40


class LegacyCapacityBridgeTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(TemporaryDirectory()))
        self.output = self.root / "fixtures"
        self.enterContext(patch.object(bridge, "LEGACY_BYTES", 4096))
        self.enterContext(patch.multiple(capacity_fixtures, CHUNK_BYTES=1024, SNAPSHOT_BYTES=2048,
                                         SHARE_BYTES=512, NODE_COUNT=4))
        self.enterContext(patch.multiple(bridge.converter, CHUNK_BYTES=1024, SNAPSHOT_BYTES=2048))

    def test_real_converter_files_are_moved_into_the_existing_capacity_layout(self):
        adopted = {}
        move = bridge.os.replace

        def record_move(source, destination):
            source, destination = Path(source), Path(destination)
            if source.parent.parent.parent.name == "subscriptions":
                adopted[destination.name] = source.stat().st_ino
            return move(source, destination)

        with patch.object(bridge.os, "replace", side_effect=record_move):
            proof = bridge.generate_legacy_capacity(self.output, REVISION)
        self.assertEqual((proof["syntheticLegacyCellBytes"], proof["convertedNdjsonBytes"], proof["nodes"], proof["chunks"]),
                         (4096, 2048, 4, 2))
        self.assertEqual(proof["revision"], REVISION)
        self.assertEqual(set(adopted), {"0.ndjson", "1.ndjson", "manifest.json"})
        for name, inode in adopted.items():
            self.assertEqual((self.output / "at-limits" / name).stat().st_ino, inode)
        self.assertEqual({path.name for path in self.output.iterdir()},
                         {"capacity.json", "at-limits", "share-over", "snapshot-over"})
        self.assertEqual(list(self.root.iterdir()), [self.output])

    def test_refuses_changed_converter_bytes_before_any_fixture_publication(self):
        verify = bridge.converter.verify_bundle

        def verify_then_change(package):
            result = verify(package)
            file, = (package / "objects").glob("subscriptions/*/*/0.ndjson")
            file.write_bytes(b"{}\n")
            return result

        with patch.object(bridge.converter, "verify_bundle", side_effect=verify_then_change):
            with self.assertRaisesRegex(ValueError, bridge.ERROR):
                bridge.generate_legacy_capacity(self.output, REVISION)
        self.assertEqual(list(self.root.iterdir()), [])
