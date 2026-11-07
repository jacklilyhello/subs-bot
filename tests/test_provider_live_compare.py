"""Synthetic checks for the hosted comparator's result boundary."""

from hashlib import sha256
import base64
import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "worker" / "tools"))
import provider_live_compare as tool


SOURCE = "https://fixture.example.invalid/subscriptions?token=synthetic-source-only"
PASSWORD = "synthetic-node-only"
BODY = b"ss://" + base64.urlsafe_b64encode(f"aes-256-gcm:{PASSWORD}".encode()).rstrip(b"=") + b"@203.0.113.10:8388#fixture"


class ProviderLiveCompareTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.samples = self.root / "samples"
        self.samples.mkdir(mode=0o700)
        self.sample = {
            "case": 1, "outcome": "ok", "file": "sample-01.body", "decodedBytes": len(BODY),
            "bodySha256": sha256(BODY).hexdigest(), "legacyContentType": "text/plain; charset=utf-8",
            "rpcMetadata": {"subscription-userinfo": "upload=12345; total=2147483648; expire=2000000000"},
        }
        tool.write_private(self.samples / self.sample["file"], BODY)
        tool.write_private(self.samples / "index.json", tool.compact({"version": 1, "samples": [self.sample]}))

    def test_real_legacy_parser_compares_private_worker_output_without_returning_secrets(self):
        def worker_replay(_bundle, sample_file, _row, source, scratch):
            self.assertEqual(sample_file.read_bytes(), BODY)
            self.assertEqual(source, SOURCE)
            exported = base64.b64encode(BODY)
            tool.write_private(scratch / "base64.body", exported)
            formats = {name: {"status": 422, "bytes": 0} for name in tool.FORMATS}
            formats["base64"] = {"status": 200, "bytes": len(exported)}
            return {"job": "saved", "document": {"nodes": 1}, "chunks": 1, "ndjsonBytes": 180,
                    "formats": formats, "metadata": {"trafficUsed": 12345 / 2**30, "trafficTotal": 2, "expireAt": None}}

        with patch.object(tool, "worker_replay", side_effect=worker_replay):
            report = tool.compare_sample(self.samples, self.root, tool.read_samples(self.samples, 1)[0], SOURCE)
        self.assertEqual(report["legacy"], {"kind": "parsed", "nodes": 1, "rejectedHysteria2": 0})
        self.assertEqual(report["formats"]["base64"]["comparison"], "exact")
        self.assertEqual(report["formats"]["surge"]["workerStatus"], 422)
        self.assertEqual(report["worker"]["metadata"], {"trafficUsed": "equal", "trafficTotal": "equal", "expireAt": "different"})
        serialized = json.dumps(report)
        for private in (SOURCE, PASSWORD, BODY.decode(), self.sample["bodySha256"], "12345", "2000000000"):
            self.assertNotIn(private, serialized)
        self.assertEqual(list(self.root.iterdir()), [self.samples])

    def test_malformed_or_extra_sample_input_fails_closed(self):
        tool.write_private(self.samples / "unexpected.body", b"unexpected")
        with self.assertRaises(tool.ComparisonError):
            tool.read_samples(self.samples, 1)
        manifest = tool.compact({"version": 1, "origin": "https://fixture.example.invalid", "path": "/subscriptions", "urls": [SOURCE]})
        self.assertEqual(tool.sample_urls(manifest.decode(), sha256(manifest).hexdigest()), [SOURCE])
        with self.assertRaises(tool.ComparisonError):
            tool.sample_urls(manifest.decode(), "0" * 64)

    def test_artifact_run_provenance_uses_the_hosted_string_fields(self):
        bundle = self.root / "bundle"
        bundle.mkdir(mode=0o700)
        revision = "a" * 40
        digest = sha256(b"synthetic artifact").hexdigest()
        for name in ("index.js", "0001_subscriptions.sql"):
            tool.write_private(bundle / name, b"synthetic artifact")
        snapshot = "12345678-1234-4234-8234-123456789012"
        prefix = f"subscriptions/1/{snapshot}/"
        manifest = {
            "version": 2, "ref": "refs/heads/main", "revision": revision, "runId": "1234", "runAttempt": "1",
            "compatibilityDate": "2026-07-30", "bundleSha256": digest,
            "migrations": [{"name": "0001_subscriptions.sql", "sha256": digest}],
            "snapshots": [{
                "id": 1, "snapshotId": snapshot, "token": "subsbot-synthetic-fixture", "bodySha256": digest,
                "manifestSha256": digest, "nodeCount": 1, "nodeBytes": 1, "bodyBytes": 4,
                "objects": [{"key": prefix + key, "file": "r2/" + prefix + key, "bytes": 1, "sha256": digest}
                            for key in ("0.ndjson", "manifest.json")],
            }],
        }
        tool.write_private(bundle / "isolation.json", tool.compact(manifest))
        self.assertEqual(tool.verify_bundle(bundle, revision, "1234"), "1")
        (bundle / "isolation.json").unlink()
        manifest["runAttempt"] = 1
        tool.write_private(bundle / "isolation.json", tool.compact(manifest))
        with self.assertRaises(tool.ComparisonError):
            tool.verify_bundle(bundle, revision, "1234")


if __name__ == "__main__":
    unittest.main()
