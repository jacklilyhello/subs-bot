"""Cloud-hosted synthetic checks of complete, private provider source preservation."""

from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import archive_production_provider as archive
import production_provider as control
from test_production_provider import config


class MemoryStore:
    def __init__(self):
        self.run_id, self.attempt = "100", "1"
        self.prefix = "maintenance/production-provider/100/1/"
        self.objects, self.writes, self.verifications = {}, 0, 0

    def verify(self):
        self.verifications += 1

    def read(self, key):
        return self.objects.get(key)

    def put(self, key, raw):
        if key in self.objects:
            archive.require(self.objects[key] == raw)
        else:
            self.objects[key] = raw
            self.writes += 1


def fixture(directory):
    values = {name: ("synthetic file " + name).encode() for name in archive.FILE_LIMITS}
    target = config(active=True)
    target["build"].update({"archiveSha256": sha256(values["provider-source-archive.zip"]).hexdigest(),
                             "workerSha256": sha256(values["source/provider-worker.js"]).hexdigest(),
                             "ociArchiveSha256": sha256(values["source/provider-image.tar"]).hexdigest()})
    proof = {"status": "complete", "productionMutation": False, "controllerRevision": "b" * 40,
             "runId": "100", "runAttempt": "1", "target": target}
    values["provider-rehearsal-proof.json"] = control.canonical(proof)
    values["provider-rehearsal-target.json"] = control.canonical(target)
    for name, raw in values.items():
        path = directory / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    return values


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.values = fixture(self.root)
        self.store = MemoryStore()

    def test_complete_source_archive_and_r2_only_readback(self):
        result = archive.archive(self.store, self.root)
        self.assertEqual(result["files"], len(archive.FILE_LIMITS))
        self.assertEqual(result["bytes"], sum(len(value) for value in self.values.values()))
        self.assertEqual(result["readback"], "R2-only-complete")
        independent = archive.verify_archive(self.store, result["manifestSha256"])
        self.assertEqual(independent, result)
        self.assertGreaterEqual(self.store.verifications, 4)

    def test_repeat_preserves_bytes_and_no_extra_writes(self):
        first = archive.archive(self.store, self.root)
        written = self.store.writes
        self.assertEqual(archive.archive(self.store, self.root), first)
        self.assertEqual(self.store.writes, written)

    def test_missing_object_or_corrupt_bytes_never_reports_complete(self):
        result = archive.archive(self.store, self.root)
        blob = next(key for key in self.store.objects if key.startswith("blobs/"))
        original = self.store.objects.pop(blob)
        with self.assertRaises(control.ProviderError):
            archive.verify_archive(self.store, result["manifestSha256"])
        self.store.objects[blob] = original + b"corrupt"
        with self.assertRaises(control.ProviderError):
            archive.verify_archive(self.store, result["manifestSha256"])

    def test_wrong_manifest_digest_and_failed_proof_are_refused(self):
        result = archive.archive(self.store, self.root)
        with self.assertRaises(control.ProviderError):
            archive.verify_archive(self.store, "0" * 64)
        proof = json.loads(self.values["provider-rehearsal-proof.json"])
        proof["status"] = "failed"
        (self.root / "provider-rehearsal-proof.json").write_bytes(control.canonical(proof))
        with self.assertRaises(control.ProviderError):
            archive.archive(MemoryStore(), self.root)

    def test_capacity_limit_stops_before_writing(self):
        with patch.object(archive, "MAX_TOTAL_BYTES", 1), self.assertRaises(control.ProviderError):
            archive.archive(self.store, self.root)
        self.assertEqual(self.store.writes, 0)

    def test_unknown_extra_file_or_symlink_is_refused(self):
        (self.root / "extra-secret-file").write_bytes(b"synthetic")
        with self.assertRaises(control.ProviderError):
            archive.archive(self.store, self.root)
        (self.root / "extra-secret-file").unlink()
        selected = self.root / "source/provider-worker.js"
        selected.unlink()
        selected.symlink_to(self.root / "source/provider-image.tar")
        with self.assertRaises(ValueError):
            archive.archive(self.store, self.root)


if __name__ == "__main__":
    unittest.main()
