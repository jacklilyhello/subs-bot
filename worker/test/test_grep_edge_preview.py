"""Synthetic coverage for the protected diagnostic's request boundaries."""

import json
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import grep_edge_preview as probe


ACCOUNT = "1" * 32
REVISION = "2" * 40
ORIGIN = f"https://{probe.NAME}.{probe.NAMESPACE}.workers.dev/"
EXCHANGE = f"https://temporary-preview.{probe.NAMESPACE}.workers.dev/session"
ROOT = f"{probe.API_ORIGIN}/accounts/{ACCOUNT}/workers"
SCRIPT = f"{ROOT}/scripts/{probe.NAME}"
REPORT = {
    "version": 1, "mode": "worker-runtime-shape", "phases": [], "authorizationCheck": False,
    "grepElapsedMs": 100, "elapsedMs": 200,
    "projection": {"blocks": 0, "textBlocks": 0, "fixtureMetadata": 0, "canonicalLinks": 0, "knownPathMatches": 0},
    "repository": {"status": 200, "outcome": "confirmed-public", "elapsedMs": 80},
}


def response(status, value=None, headers=None):
    return status, headers or {}, b"" if value is None else json.dumps(value).encode()


def cloudflare(result, status=200):
    return response(status, {"success": True, "errors": [], "result": result})


ABSENT = response(404, {"success": False, "result": None, "errors": [{"code": 10007}]})


class EdgePreviewTests(unittest.TestCase):
    def execute(self, transport, guard=None):
        with patch.object(probe, "TARGET_ACCOUNT_SHA256", probe.sha256(ACCOUNT.encode()).hexdigest()):
            return probe.run(Mock(), REVISION, b"synthetic-module", ACCOUNT, "synthetic-deploy",
                             guard=guard or Mock(), transport=transport)

    def test_exact_preview_exchange_upload_invoke_and_readback(self):
        transport = Mock(side_effect=[
            cloudflare({"subdomain": probe.NAMESPACE}), ABSENT, response(404),
            cloudflare({"token": "initial", "exchange_url": EXCHANGE}), response(200, {"token": "session"}),
            cloudflare({"preview_token": "preview", "tail_url": "https://example.invalid/do-not-contact"}, 201),
            response(404),
            response(200, REPORT, {probe.IDENTITY_HEADER: REVISION, "Cache-Control": "private, no-store",
                                   "Content-Type": "application/json"}),
            ABSENT, response(404),
        ])
        guard = Mock()
        self.assertEqual(self.execute(transport, guard), REPORT)
        calls = transport.call_args_list
        self.assertEqual([call.args[0] for call in calls], [
            f"{ROOT}/subdomain", f"{ROOT}/workers/{probe.NAME}", ORIGIN,
            f"{SCRIPT}/subdomain/edge-preview", EXCHANGE, f"{SCRIPT}/edge-preview", ORIGIN, ORIGIN,
            f"{ROOT}/workers/{probe.NAME}", ORIGIN,
        ])
        self.assertEqual(guard.call_count, 3)
        self.assertEqual(calls[4].kwargs, {})
        upload = calls[5].kwargs
        self.assertEqual(upload["method"], "POST")
        self.assertEqual(upload["headers"]["CF-Preview-Upload-Config-Token"], "session")
        self.assertIn(b'"bindings": []', upload["body"])
        self.assertIn(b'"logpush": false', upload["body"])
        self.assertIn(b'"invocation_logs": false', upload["body"])
        self.assertEqual(calls[6].kwargs, {})
        self.assertEqual(calls[7].kwargs["headers"], {"CF-Workers-Preview-Token": "preview"})

    def test_occupied_identity_or_off_namespace_exchange_stops_before_upload(self):
        namespace = cloudflare({"subdomain": probe.NAMESPACE})
        occupied = Mock(side_effect=[namespace, cloudflare({"name": probe.NAME})])
        with self.assertRaises(probe.ProbeError):
            self.execute(occupied)
        self.assertEqual(occupied.call_count, 2)
        foreign = Mock(side_effect=[
            namespace, ABSENT, response(404),
            cloudflare({"token": "initial", "exchange_url": "https://elsewhere.workers.dev/session"}),
            ABSENT, response(404),
        ])
        with self.assertRaises(probe.ProbeError):
            self.execute(foreign)
        self.assertEqual(foreign.call_count, 6)
        self.assertTrue(all("method" not in call.kwargs for call in foreign.call_args_list))

    def test_public_preview_is_never_invoked_with_credentials(self):
        transport = Mock(side_effect=[
            cloudflare({"subdomain": probe.NAMESPACE}), ABSENT, response(404),
            cloudflare({"token": "initial"}), cloudflare({"preview_token": "preview"}),
            response(204, headers={probe.IDENTITY_HEADER: REVISION}), ABSENT, response(404),
        ])
        with self.assertRaises(probe.ProbeError):
            self.execute(transport)
        self.assertTrue(all("CF-Workers-Preview-Token" not in call.kwargs.get("headers", {})
                            for call in transport.call_args_list))

    def test_report_with_arbitrary_strings_is_refused(self):
        body = json.dumps({**REPORT, "repository": {**REPORT["repository"], "outcome": "private-content"}}).encode()
        with self.assertRaises(probe.ProbeError):
            probe.validated_report(body)
