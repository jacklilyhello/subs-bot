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
            diagnostics = {"protocols": {"ss": 1}, "formats": {
                name: {"admitted": {"ss": 1}, "rejected": {}, "rejectedTraits": {}} for name in tool.FORMATS
            }}
            return {"job": "saved", "document": {"nodes": 1}, "chunks": 1, "ndjsonBytes": 180,
                    "formats": formats, "diagnostics": diagnostics,
                    "metadata": {"trafficUsed": 12345 / 2**30, "trafficTotal": 2, "expireAt": None}}

        with patch.object(tool, "worker_replay", side_effect=worker_replay):
            report = tool.compare_sample(self.samples, self.root, tool.read_samples(self.samples, 1)[0], SOURCE)
        self.assertEqual(report["legacy"], {"kind": "parsed", "nodes": 1, "rejectedHysteria2": 0, "protocols": {"ss": 1}})
        self.assertEqual(report["formats"]["base64"]["comparison"], "exact")
        self.assertEqual(report["formats"]["base64"]["workerCoverage"], {"declarations": 1})
        self.assertEqual(report["formats"]["qx"]["legacyCoverage"], {"declarations": 0, "uriRows": 1, "unrecognizedRows": 0})
        self.assertEqual(report["formats"]["surge"]["workerStatus"], 422)
        self.assertIsNone(report["formats"]["surge"]["workerCoverage"])
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
        oversized = json.loads(manifest)
        oversized["urls"] = [SOURCE + str(i) for i in range(5)]
        body = tool.compact(oversized)
        with self.assertRaises(tool.ComparisonError):
            tool.sample_urls(body.decode(), sha256(body).hexdigest())

    def test_legacy_declaration_counts_distinguish_bytes_from_complete_exports(self):
        sys.path.insert(0, str(tool.ROOT))
        import convert

        nodes = convert.parse_nodes_from_text("""
proxies:
  - {name: Fixture SS, type: ss, server: 203.0.113.10, port: 8388, cipher: aes-128-gcm, password: synthetic}
  - {name: Fixture AnyTLS, type: anytls, server: 203.0.113.11, port: 443, password: synthetic, client-fingerprint: randomized}
""")
        self.assertEqual(tool.protocol_counts(nodes), {"ss": 1, "anytls": 1})
        self.assertEqual(tool.emitted_coverage("clash", convert.to_clash(nodes).encode()), {"declarations": 2})
        self.assertEqual(tool.emitted_coverage("singbox", convert.to_singbox(nodes).encode()), {"declarations": 2})
        self.assertEqual(tool.emitted_coverage("surge", convert.to_surge(nodes).encode()), {
            "declarations": 1, "commentRows": 0, "danglingGroupReferences": 1, "unrecognizedRows": 0,
        })
        self.assertEqual(tool.emitted_coverage("qx", convert.to_qx(nodes).encode()), {
            "declarations": 1, "uriRows": 0, "unrecognizedRows": 0,
        })
        commented = b"[Proxy]\n# Fixture = ss, ignored\n[Proxy Group]\nProxy = select, Fixture\n[Rule]\nFINAL,Proxy\n"
        self.assertEqual(tool.emitted_coverage("surge", commented), {
            "declarations": 0, "commentRows": 1, "danglingGroupReferences": 1, "unrecognizedRows": 0,
        })
        self.assertEqual(tool.emitted_coverage("base64", base64.b64encode(BODY + b" label")), {"declarations": 1})
        with self.assertRaises(convert.ExportError):
            convert.to_base64_sub(nodes)

    def test_worker_count_dictionaries_are_closed_and_reconcile_each_family(self):
        value = {"protocols": {"ss": 1}, "formats": {
            name: {"admitted": {}, "rejected": {"ss": 1}, "rejectedTraits": {}} for name in tool.FORMATS
        }}
        self.assertEqual(tool.verified_diagnostics(value, 1)["protocols"], {"ss": 1})
        value["formats"]["clash"]["rejectedTraits"] = {PASSWORD: 1}
        with self.assertRaises(tool.ComparisonError):
            tool.verified_diagnostics(value, 1)
        value["formats"]["clash"]["rejectedTraits"] = {}
        value["formats"]["clash"]["rejected"] = {"vless": 1}
        with self.assertRaises(tool.ComparisonError):
            tool.verified_diagnostics(value, 1)

    def test_vmess_traits_are_bounded_by_rejected_family_and_target_format(self):
        value = {"protocols": {"ss": 1, "vmess": 2}, "formats": {
            name: {"admitted": {"vmess": 1}, "rejected": {"ss": 1, "vmess": 1}, "rejectedTraits": {}}
            for name in tool.FORMATS
        }}
        base64_traits = value["formats"]["base64"]["rejectedTraits"]
        base64_traits.update({"vmess-alpn-csv": 1, "vmess-boolean-spelling": 1})
        value["formats"]["surge"]["rejectedTraits"] = {"vmess-cipher-auto-or-default": 1}
        value["formats"]["qx"]["rejectedTraits"] = {"vmess-non-aead-alter-id": 1}
        self.assertEqual(tool.verified_diagnostics(value, 3)["formats"], value["formats"])
        for format_name, trait, count in (
            ("base64", "vmess-alpn-csv", 2),
            ("base64", "vmess-cipher-auto-or-default", 1),
            ("base64", "vmess-unrecognized", 1),
            ("surge", "vmess-alpn-csv", 1),
            ("clash", "vmess-non-aead-alter-id", 1),
        ):
            with self.subTest(format=format_name, trait=trait):
                traits = value["formats"][format_name]["rejectedTraits"]
                with patch.dict(traits, {trait: count}), self.assertRaises(tool.ComparisonError):
                    tool.verified_diagnostics(value, 3)
        value["formats"]["base64"].update(admitted={"vmess": 2}, rejected={"ss": 1})
        with self.assertRaises(tool.ComparisonError):
            tool.verified_diagnostics(value, 3)

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
