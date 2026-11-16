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
import production_provider_rehearsal as rehearsal
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


class PartialArchiveTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.store = MemoryStore()
        self.names = ["subs-bot-provider-attempt-source-100-1", "subs-bot-provider-attempt-result-stage-100-1"]
        self.provenance = {"revision": "b" * 40, "runId": "100", "runAttempt": "1", "workflowPath": control.REHEARSAL_WORKFLOW_PATH,
                           "artifacts": {name: {"artifactId": str(index + 200), "archiveSha256": "5" * 64} for index, name in enumerate(self.names)}}
        target = config()
        target["versionId"] = None
        for index, name in enumerate(self.names):
            directory = self.root / name
            directory.mkdir()
            journal = {"version": 2, "controllerRevision": "b" * 40, "runId": "100", "runAttempt": "1",
                       "targetSha256": control.digest(target), "events": [{"phase": "intent"}] * (index + 1),
                       "currentIntent": {"operation": "stage", "status": "unconfirmed", "intentSha256": "6" * 64}}
            envelope = {"version": 2, "target": target, "journal": journal}
            (directory / rehearsal.CHECKPOINT).write_bytes(control.canonical(envelope))
            (directory / "provider-rehearsal-target.json").write_bytes(control.canonical(target))

    def test_partial_originals_are_complete_storage_but_never_business_acceptance(self):
        result = archive.archive_partial(self.store, self.root, self.provenance)
        self.assertEqual(result["status"], "partial-preserved")
        self.assertEqual(result["completion"], "not-complete")
        self.assertEqual(result["latestCheckpoint"]["intent"]["status"], "unconfirmed")
        self.assertNotIn("manifest.json", self.store.objects)
        self.assertLess(result["uniqueBytes"], result["logicalBytes"])
        self.assertEqual(archive.verify_partial(self.store, result["manifestSha256"]), result)

    def test_missing_or_corrupt_partial_blob_is_not_verified(self):
        result = archive.archive_partial(self.store, self.root, self.provenance)
        blob = next(key for key in self.store.objects if key.startswith("blobs/"))
        del self.store.objects[blob]
        with self.assertRaises(control.ProviderError):
            archive.verify_partial(self.store, result["manifestSha256"])

    def test_unknown_artifact_and_capacity_fail_before_writing(self):
        wrong = deepcopy(self.provenance)
        wrong["artifacts"]["subs-bot-provider-attempt-intent-create-100-1"] = {"artifactId": "300", "archiveSha256": "5" * 64}
        with self.assertRaises(control.ProviderError):
            archive.archive_partial(self.store, self.root, wrong)
        self.assertEqual(self.store.writes, 0)
        with patch.object(archive, "MAX_PARTIAL_LOGICAL_BYTES", 1), self.assertRaises(control.ProviderError):
            archive.archive_partial(self.store, self.root, self.provenance)
        self.assertEqual(self.store.writes, 0)

    def test_partial_manifest_cannot_be_relabelled_complete(self):
        result = archive.archive_partial(self.store, self.root, self.provenance)
        manifest = json.loads(self.store.objects["partial-manifest.json"])
        manifest["completion"] = "complete"
        raw = control.canonical(manifest)
        self.store.objects["partial-manifest.json"] = raw
        with self.assertRaises(control.ProviderError):
            archive.verify_partial(self.store, sha256(raw).hexdigest())


if __name__ == "__main__":
    unittest.main()
