"""Exercise the small export smoke with in-memory cloud storage and HTTP fakes."""

from contextlib import contextmanager
from hashlib import sha256
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, patch

from test_capacity_probe import Response, probe
from test_capacity_resources import FakeCloud, REVISION, RUN, TARGET, capacity
from capacity_fixtures import STRUCTURED_SMOKE, generate_capacity_fixtures, structured_smoke_fixture


class StructuredExportSmokeTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name) / "fixtures"
        metadata = generate_capacity_fixtures(self.directory, REVISION, profile=STRUCTURED_SMOKE)
        self.fixtures = metadata["fixtures"]
        self.export = structured_smoke_fixture("structured-mixed")[2]
        self.calls = []
        self.positive_body = self.export
        self.negative_body = b"Subscription content cannot be exported."

    def test_seed_and_idempotent_cleanup_are_scoped_to_two_snapshots(self):
        cloud = FakeCloud(self.directory)
        self.addCleanup(cloud.db.close)
        resources = capacity.Resources(TARGET, cloud, cloud)
        guard = Mock()
        with capacity.locked_directory(self.directory):
            capacity.seed(self.directory, resources, REVISION, RUN, guard, profile=STRUCTURED_SMOKE)
            self.assertEqual([row["generation"] for row in cloud.capacity_rows()], [1, 1])
            self.assertEqual(len(cloud.objects), 6)
            self.assertEqual(guard.call_count, 2)
            journal = (self.directory / capacity.LEDGER_FILE).read_bytes()
            for fixture in self.fixtures:
                self.assertNotIn(fixture["token"].encode("ascii"), journal)
            self.assertNotIn(self.export, journal)
            (self.directory / "capacity.json").unlink()
            capacity.cleanup(self.directory, resources, profile=STRUCTURED_SMOKE)
            writes = list(cloud.writes)
            capacity.cleanup(self.directory, resources, profile=STRUCTURED_SMOKE)
            self.assertEqual(cloud.writes, writes)
        self.assertEqual(cloud.capacity_rows(), [])
        self.assertEqual(cloud.objects, {})
        self.assertEqual(cloud.db.execute("SELECT name FROM subscriptions").fetchone()[0], "Other row")
        ledger = capacity.load_ledger(self.directory, resources.scope_hash, profile=STRUCTURED_SMOKE)
        self.assertEqual(ledger["phase"], "retired")

    def test_validation_requires_the_explicit_profile_and_exact_oracle(self):
        with self.assertRaises(capacity.CapacityError):
            capacity.read_fixtures(self.directory, REVISION)
        path = self.directory / "capacity.json"
        metadata = json.loads(path.read_bytes())
        self.assertEqual(metadata["fixtures"][0]["exportSha256"], sha256(self.export).hexdigest())
        metadata["fixtures"][0]["exportSha256"] = "0" * 64
        path.write_text(json.dumps(metadata), encoding="ascii")
        with self.assertRaisesRegex(capacity.CapacityError, "fixed synthetic plan"):
            capacity.read_fixtures(self.directory, REVISION, profile=STRUCTURED_SMOKE)

    @contextmanager
    def request(self, method, path, deadline, label):
        self.assertGreater(deadline, probe.monotonic())
        self.calls.append((method, path))
        if path == "/health":
            data = json.dumps({"ok": True, "service": "subs-bot", "revision": REVISION}).encode("ascii")
            response = Response(200, data, **{"Content-Type": "application/json"})
        else:
            fixture = next(item for item in self.fixtures if path == f"/sub/{item['token']}/base64")
            self.assertEqual(label, fixture["label"])
            status = fixture["status"]
            if method == "HEAD":
                response = Response(status, b"")
            elif status == 200:
                response = Response(200, self.positive_body, **{"Content-Length": str(len(self.positive_body))})
            else:
                response = Response(422, self.negative_body)
        try:
            yield response
        finally:
            response.close()

    def test_exact_six_requests_and_redacted_report(self):
        with patch.object(probe, "_request", self.request):
            report = probe.run_structured_smoke(self.directory, REVISION)
        expected = [("GET", "/health")]
        for fixture in self.fixtures:
            expected.extend((method, f"/sub/{fixture['token']}/base64") for method in ("GET", "HEAD"))
        self.assertEqual(self.calls, expected + [("GET", "/health")])
        self.assertEqual(report["requests"], 6)
        self.assertTrue(report["pythonOracleDigestMatched"])
        self.assertEqual(report["exports"], {
            "structured-mixed": {
                "GET": {"status": 200, "bodyBytes": len(self.export)},
                "HEAD": {"status": 200, "bodyBytes": 0},
            },
            "structured-unsupported": {
                "GET": {"status": 422, "bodyBytes": len(self.negative_body)},
                "HEAD": {"status": 422, "bodyBytes": 0},
            },
        })
        output = json.dumps(report)
        self.assertNotIn(self.export.decode("ascii"), output)
        for fixture in self.fixtures:
            self.assertNotIn(fixture["token"], output)

    def test_wrong_digest_or_reflected_error_fails_safely(self):
        with patch.object(probe, "_request", self.request):
            self.positive_body = b"x" * len(self.export)
            with self.assertRaisesRegex(probe.ProbeError, "length or digest differs"):
                probe.run_structured_smoke(self.directory, REVISION)
            self.positive_body = self.export
            capability = self.fixtures[1]["token"]
            self.negative_body = capability.encode("ascii")
            with self.assertRaisesRegex(probe.ProbeError, "fixed error response differs") as rejected:
                probe.run_structured_smoke(self.directory, REVISION)
        self.assertNotIn(capability, str(rejected.exception))
