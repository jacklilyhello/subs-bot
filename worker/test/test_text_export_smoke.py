"""Check the protected Surge and Quantumult X probe without network access."""

from contextlib import contextmanager
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, patch

from test_capacity_probe import Response, probe
from test_capacity_resources import FakeCloud, REVISION, RUN, TARGET, capacity
from capacity_fixtures import TEXT_EXPORT_SMOKE, generate_capacity_fixtures, smoke_fixture


ROUTES = {
    "surge-mixed": ("surge",),
    "surge-unsupported": ("surge",),
    "qx-mixed": ("qx", "quantumult", "quantumultx"),
    "qx-unsupported": ("qx", "quantumult", "quantumultx"),
}


class TextExportSmokeTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name) / "fixtures"
        self.fixtures = generate_capacity_fixtures(self.directory, REVISION, profile=TEXT_EXPORT_SMOKE)["fixtures"]
        self.exports = {row["label"]: smoke_fixture(TEXT_EXPORT_SMOKE, row["label"])[2] for row in self.fixtures}
        self.calls = []
        self.overrides = {}

    @contextmanager
    def request(self, method, path, deadline, label):
        self.assertGreater(deadline, probe.monotonic())
        self.calls.append((method, label))
        if path == "/health":
            body = json.dumps({"ok": True, "service": "subs-bot", "revision": REVISION}).encode("ascii")
            response = Response(200, body, **{"Content-Type": "application/json"})
        else:
            fixture = next((row for row in self.fixtures if any(
                path == f"/sub/{row['token']}/{route}" and label == f"{row['label']}:{route}"
                for route in ROUTES[row["label"]]
            )), None)
            if fixture is None:
                self.fail("The probe requested a path outside the fixed synthetic export plan.")
            status = fixture["status"]
            body = b""
            if method == "GET":
                body = self.exports[fixture["label"]] if status == 200 else probe.ERROR_BODY[422]
            override_body, headers = self.overrides.get((method, label), (body, {}))
            response = Response(status, override_body, **({"Content-Length": str(len(body))} | headers))
        try:
            yield response
        finally:
            response.close()

    def test_checks_exact_alias_matrix_without_reporting_capabilities_or_bodies(self):
        with patch.object(probe, "_request", self.request):
            report = probe.run_structured_smoke(self.directory, REVISION, profile=TEXT_EXPORT_SMOKE)
        health = ("GET", "export smoke health")
        export_calls = [(method, f"{label}:{alias}") for label, aliases in ROUTES.items() for alias in aliases
                        for method in ("GET", "HEAD")]
        self.assertEqual(self.calls, [health, *export_calls, health])
        self.assertEqual(report["requests"], 18)
        self.assertEqual(report["exactHealth"], 2)
        self.assertTrue(report["fixedTextExportFixtureDigestMatched"])
        report_text = json.dumps(report, ensure_ascii=False)
        self.assertTrue(all(row["token"] not in report_text for row in self.fixtures), "Report exposed a capability.")
        self.assertTrue("password=" not in report_text, "Report exposed an export body.")
        for fixture in self.fixtures:
            label, status = fixture["label"], fixture["status"]
            expected = self.exports[label] if status == 200 else probe.ERROR_BODY[422]
            for alias in ROUTES[label]:
                self.assertEqual(report["exports"][f"{label}:{alias}"], {
                    "GET": {"status": status, "bodyBytes": len(expected)}, "HEAD": {"status": status, "bodyBytes": 0},
                })

    def test_rejects_wire_drift_and_reflected_rejection_without_leaking_details(self):
        body = self.exports["qx-mixed"]
        changed = body.replace(b"obfs=wss", b"obfs=tls")
        capability = self.fixtures[-1]["token"]
        self.assertEqual(len(changed), len(body))
        self.assertTrue(changed != body)
        cases = [
            ("GET", "qx-mixed:quantumultx", changed, {}, "length or digest differs"),
            ("GET", "qx-mixed:qx", body, {"Content-Length": str(len(body) + 1)}, "did not declare its exact length"),
            ("GET", "qx-mixed:qx", body, {"Transfer-Encoding": "chunked"}, "did not declare its exact length"),
            ("GET", "qx-mixed:qx", body, {"Age": "1"}, "privacy headers differ"),
            ("HEAD", "qx-mixed:quantumult", b"", {"Content-Type": "text/plain; charset=us-ascii"}, "charset differs"),
            ("HEAD", "surge-mixed:surge", b"x", {}, "HEAD returned a body"),
            ("GET", "qx-unsupported:quantumultx", capability.encode("ascii"), {}, "fixed error response differs"),
        ]
        with patch.object(probe, "_request", self.request):
            for method, label, data, headers, message in cases:
                with self.subTest(method=method, label=label, message=message):
                    self.overrides = {(method, label): (data, headers)}
                    with self.assertRaises(probe.ProbeError) as rejected:
                        probe.run_structured_smoke(self.directory, REVISION, profile=TEXT_EXPORT_SMOKE)
                    self.assertTrue(capability not in str(rejected.exception), "Probe error exposed a capability.")
                    self.assertTrue("password=" not in str(rejected.exception), "Probe error exposed an export body.")
                    self.assertTrue(message in str(rejected.exception), "The probe returned an unexpected safe failure.")

    def test_seed_and_cleanup_touch_only_the_four_fixed_fixtures(self):
        cloud = FakeCloud(self.directory)
        self.addCleanup(cloud.db.close)
        resources = capacity.Resources(TARGET, cloud, cloud)
        with capacity.locked_directory(self.directory):
            capacity.seed(self.directory, resources, REVISION, RUN, Mock(), profile=TEXT_EXPORT_SMOKE)
            self.assertEqual([row["generation"] for row in cloud.capacity_rows()], [1] * 4)
            self.assertEqual(len(cloud.objects), 12)
            journal = (self.directory / capacity.LEDGER_FILE).read_bytes()
            self.assertTrue(all(row["token"].encode("ascii") not in journal for row in self.fixtures),
                            "The cleanup ledger exposed a capability.")
            self.assertTrue(b"password" not in journal, "The cleanup ledger exposed an export body.")
            (self.directory / "capacity.json").unlink()
            capacity.cleanup(self.directory, resources, profile=TEXT_EXPORT_SMOKE)
            writes = list(cloud.writes)
            capacity.cleanup(self.directory, resources, profile=TEXT_EXPORT_SMOKE)
            self.assertEqual(cloud.writes, writes)
            self.assertEqual(len(cloud.capacity_rows()), 0)
            self.assertEqual(len(cloud.objects), 0)
            self.assertEqual(cloud.db.execute("SELECT name FROM subscriptions").fetchone()[0], "Other row")
