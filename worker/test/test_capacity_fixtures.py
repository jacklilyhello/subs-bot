"""Check the exact synthetic export and storage boundaries on the hosted runner."""

import base64
from collections import Counter
import hashlib
import json
from pathlib import Path
import stat
import sys
from tempfile import TemporaryDirectory
import unittest
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from capacity_fixtures import generate_capacity_fixtures


REVISION = "a" * 40


def digest(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


class CapacityFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        directory = TemporaryDirectory()
        cls.addClassCleanup(directory.cleanup)
        cls.root = Path(directory.name) / "capacity"
        cls.generated = generate_capacity_fixtures(cls.root, REVISION)
        cls.metadata = json.loads((cls.root / "capacity.json").read_bytes())
        cls.fixtures = {fixture["label"]: fixture for fixture in cls.metadata["fixtures"]}

    def read_manifest(self, fixture):
        expected_file = f"{fixture['label']}/manifest.json"
        self.assertEqual(fixture["manifestFile"], expected_file)
        body = (self.root / expected_file).read_bytes()
        self.assertLessEqual(len(body), 65536)
        self.assertEqual(digest(body), fixture["manifestSha256"])
        manifest = json.loads(body)
        self.assertEqual(manifest["version"], 1)
        return manifest["chunks"]

    def read_chunks(self, fixture):
        descriptors = self.read_manifest(fixture)
        self.assertEqual(len(descriptors), len(fixture["chunks"]))
        for index, (item, descriptor) in enumerate(zip(fixture["chunks"], descriptors)):
            filename = f"{fixture['label']}/{index}.ndjson"
            self.assertEqual(item["file"], filename)
            self.assertEqual({key: item[key] for key in ("bytes", "count", "sha256")}, descriptor)
            body = (self.root / filename).read_bytes()
            self.assertTrue(body.endswith(b"\n"))
            self.assertEqual(len(body), item["bytes"])
            self.assertLessEqual(len(body), 524288)
            self.assertEqual(digest(body), item["sha256"])
            records = [json.loads(line) for line in body.splitlines()]
            self.assertEqual(len(records), item["count"])
            yield body, records

    def test_exact_metadata_and_private_paths(self):
        self.assertEqual(self.metadata, self.generated)
        self.assertEqual(set(self.metadata), {"version", "revision", "fixtures"})
        self.assertEqual((self.metadata["version"], self.metadata["revision"]), (1, REVISION))
        self.assertEqual(list(self.fixtures), ["at-limits", "share-over", "snapshot-over"])
        paths = {Path("capacity.json")}
        tokens = set()
        snapshot_ids = set()
        for fixture in self.fixtures.values():
            self.assertEqual(set(fixture), {
                "label", "token", "snapshotId", "nodeCount", "nodeBytes", "shareBytes",
                "exportBytes", "exportSha256", "manifestFile", "manifestSha256", "status", "chunks",
            })
            paths.add(Path(fixture["manifestFile"]))
            paths.update(Path(chunk["file"]) for chunk in fixture["chunks"])
            self.assertRegex(fixture["token"], r"^subsbot-synthetic-capacity-[A-Za-z0-9_-]{32}$")
            snapshot_id = uuid.UUID(fixture["snapshotId"])
            self.assertEqual(snapshot_id.version, 4)
            self.assertEqual(str(snapshot_id), fixture["snapshotId"])
            tokens.add(fixture["token"])
            snapshot_ids.add(snapshot_id)
        self.assertEqual((len(tokens), len(snapshot_ids)), (3, 3))
        actual_files = set()
        self.assertEqual(stat.S_IMODE(self.root.stat().st_mode), 0o700)
        for entry in self.root.rglob("*"):
            self.assertFalse(entry.is_symlink())
            if entry.is_dir():
                self.assertEqual(stat.S_IMODE(entry.stat().st_mode), 0o700)
            else:
                actual_files.add(entry.relative_to(self.root))
                self.assertEqual(stat.S_IMODE(entry.stat().st_mode), 0o600)
        self.assertEqual(actual_files, paths)

    def test_exact_maximum_snapshot_and_export_digest_from_disk(self):
        fixture = self.fixtures["at-limits"]
        self.assertEqual(
            (fixture["status"], fixture["nodeCount"], fixture["nodeBytes"], fixture["shareBytes"], fixture["exportBytes"]),
            (200, 100000, 67108864, 16777216, 22369624),
        )
        self.assertEqual(len(fixture["chunks"]), 128)
        self.assertEqual(Counter(chunk["count"] for chunk in fixture["chunks"]), {782: 32, 781: 96})
        previous_suffix = b""
        export_digest = hashlib.sha256()
        node_bytes = share_bytes = export_bytes = node_count = 0
        share_sizes = Counter()
        for body, records in self.read_chunks(fixture):
            self.assertEqual(len(body), 524288)
            node_bytes += len(body)
            raw_lines = [record["share"].encode("ascii") for record in records]
            for offset, share in enumerate(raw_lines):
                self.assertTrue(share.startswith(
                    f"ss://YWVzLTI1Ni1nY206Zml4dHVyZS1vbmx5@203.0.113.10:8388#capacity-{node_count + offset:06d}-"
                    .encode("ascii")
                ))
            share_sizes.update(map(len, raw_lines))
            raw = (b"\n" if node_count else b"") + b"\n".join(raw_lines)
            share_bytes += len(raw)
            node_count += len(records)
            part = previous_suffix + raw
            complete_groups = len(part) // 3 * 3
            encoded = base64.b64encode(part[:complete_groups])
            export_bytes += len(encoded)
            export_digest.update(encoded)
            previous_suffix = part[complete_groups:]
        last = base64.b64encode(previous_suffix)
        export_digest.update(last)
        self.assertEqual(share_sizes, {166: 22783, 167: 77217})
        self.assertEqual((node_count, node_bytes, share_bytes, export_bytes + len(last)),
                         (100000, 67108864, 16777216, 22369624))
        self.assertEqual(export_digest.hexdigest(), fixture["exportSha256"])

    def test_share_over_is_independently_one_byte_past_export_limit(self):
        fixture = self.fixtures["share-over"]
        self.assertEqual(
            (fixture["status"], fixture["nodeCount"], fixture["nodeBytes"], fixture["shareBytes"]),
            (422, 33, 16777911, 16777217),
        )
        self.assertEqual((fixture["exportBytes"], fixture["exportSha256"]), (0, None))
        lengths = []
        snapshot_bytes = 0
        for body, records in self.read_chunks(fixture):
            self.assertEqual(len(records), 1)
            lengths.append(len(records[0]["share"].encode("ascii")))
            snapshot_bytes += len(body)
        self.assertEqual(lengths, [524266] * 32 + [673])
        self.assertEqual(sum(lengths) + len(lengths) - 1, 16777217)
        self.assertEqual(snapshot_bytes, 16777911)

    def test_snapshot_over_manifest_exceeds_limit_by_one_without_payloads(self):
        fixture = self.fixtures["snapshot-over"]
        self.assertEqual(
            (fixture["status"], fixture["nodeCount"], fixture["nodeBytes"], fixture["shareBytes"]),
            (503, 129, 67108865, 0),
        )
        self.assertEqual((fixture["exportBytes"], fixture["exportSha256"], fixture["chunks"]), (0, None, []))
        chunks = self.read_manifest(fixture)
        self.assertEqual([entry["bytes"] for entry in chunks], [524288] * 127 + [524286, 3])
        self.assertEqual(sum(entry["bytes"] for entry in chunks), 67108865)
        self.assertEqual(sum(entry["count"] for entry in chunks), fixture["nodeCount"])
        for entry in chunks:
            self.assertRegex(entry["sha256"], r"^[a-f0-9]{64}$")
        self.assertEqual(list((self.root / "snapshot-over").iterdir()), [self.root / fixture["manifestFile"]])

    def test_rejects_invalid_revision_and_existing_output_without_writes(self):
        new_root = self.root.parent / "invalid"
        with self.assertRaisesRegex(ValueError, "full lowercase Git revision"):
            generate_capacity_fixtures(new_root, "main")
        self.assertFalse(new_root.exists())
        before = (self.root / "capacity.json").read_bytes()
        with self.assertRaises(FileExistsError):
            generate_capacity_fixtures(self.root, REVISION)
        self.assertEqual((self.root / "capacity.json").read_bytes(), before)
