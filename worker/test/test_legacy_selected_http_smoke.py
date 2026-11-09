from base64 import b64encode
from contextlib import contextmanager
from io import BytesIO
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import legacy_selected_http_smoke as smoke


CODES = {"marked": "legacy_00001", "marked-empty": "legacy_00002",
         "ordinary": "legacy_00003", "ordinary-empty": "legacy_00004"}
ALPHA = b"ss://YWVzLTI1Ni1nY206Zml4dHVyZQ@203.0.113.10:8388#legacy-selected-alpha"
BETA = b"ss://YWVzLTI1Ni1nY206Zml4dHVyZQ@203.0.113.20:8388#legacy-selected-beta"
PRIVACY = {"Cache-Control": "private, no-store", "Referrer-Policy": "no-referrer",
           "X-Content-Type-Options": "nosniff", "CF-Cache-Status": "DYNAMIC"}


class LegacySelectedHttpTests(unittest.TestCase):
    def test_published_and_retired_route_plans(self):
        marked = f"/agg/{CODES['marked']}"
        empty = f"/agg/{CODES['marked-empty']}"
        ordinary = f"/agg/{CODES['ordinary']}"
        encoded = b64encode(BETA + b"\n" + ALPHA + b"\n" + BETA)
        with patch.object(smoke, "_probe_pair", return_value={"status": 200}) as probe:
            report = smoke.verify_legacy_selected_http(CODES, "published")
            paths = {call.args[0]: call.args[3:] for call in probe.call_args_list}
            self.assertEqual(len(report), len(paths))
            self.assertEqual(probe.call_count, 21)
            for suffix in ("base64", "v2ray", "mixed"):
                self.assertEqual(paths[f"{marked}/{suffix}"], (200, smoke.TEXT, encoded))
            clash = paths[f"{marked}/clash"]
            self.assertEqual(clash, paths[f"{marked}/unknown-format"])
            self.assertIn(b'"name":"legacy-selected-beta (2)"', clash[2])
            self.assertEqual(paths[f"{empty}/clash"], (200, smoke.YAML, smoke.EXPECTED_CLASH))
            self.assertEqual(paths[f"{empty}/sing-box"], (200, smoke.SINGBOX, smoke.EMPTY_SINGBOX))
            self.assertEqual(paths[f"{empty}/surge"], (200, smoke.TEXT, smoke.EMPTY_SURGE))
            self.assertEqual(paths[f"{empty}/quantumultx"], (200, smoke.TEXT, b""))
            self.assertEqual(paths[f"{ordinary}/unknown-format"][0], 406)
            self.assertEqual(paths[f"/agg/{CODES['ordinary-empty']}/base64"][0], 404)
            for link in ("marked", "marked-empty"):
                redirect = next(call for call in probe.call_args_list if call.args[0] == f"/s/{CODES[link]}")
                self.assertEqual(redirect.kwargs["location"], f"/agg/{CODES[link]}/clash")
            self.assertTrue(all(code not in repr(report) for code in CODES.values()))

            probe.reset_mock()
            smoke.verify_legacy_selected_http(CODES, "member-retired")
            paths = {call.args[0]: call.args[3:] for call in probe.call_args_list}
            self.assertEqual(paths[f"{marked}/base64"], (200, smoke.TEXT, b64encode(ALPHA)))
            self.assertEqual(paths[f"{ordinary}/base64"], (200, smoke.TEXT, b64encode(BETA + b"\n" + ALPHA)))
            self.assertEqual(probe.call_count, 3)

            probe.reset_mock()
            smoke.verify_legacy_selected_http(CODES, "cohort-retired")
            self.assertEqual(probe.call_count, 8)
            self.assertTrue(all(call.args[3:] == (404, smoke.TEXT, smoke.NOT_FOUND) and call.kwargs.get("location") is None
                                for call in probe.call_args_list))

    def test_pairs_enforce_wire_framing_and_keep_failure_diagnostics_private(self):
        path = f"/agg/{CODES['marked']}/base64"
        body = b"Zml4dHVyZQ=="
        calls = []

        @contextmanager
        def request(method, target, deadline, label):
            calls.append((method, target))
            self.assertEqual(label, "synthetic")
            self.assertGreater(deadline, smoke.monotonic())
            headers = PRIVACY | {"Content-Type": smoke.TEXT}
            if method == "GET":
                headers["Content-Length"] = str(len(body))
            headers.update(changes.get(method, {}))
            payload = (body if method == "GET" else b"") if payloads is None else payloads[method]
            with BytesIO(payload) as stream:
                yield SimpleNamespace(status=200, getheader=headers.get, read=stream.read)

        payloads = None
        with patch.object(smoke, "_request", new=request):
            for observed in (None, "0", str(len(body))):
                changes = {"HEAD": {"Content-Length": observed}}
                calls.clear()
                report = smoke._probe_pair(path, "synthetic", smoke.monotonic() + 90, 200, smoke.TEXT, body)
                self.assertEqual(report["bodyBytes"], len(body))
                self.assertEqual(report["headContentLength"], None if observed is None else int(observed))
                self.assertEqual(calls, [("GET", path), ("HEAD", path)])

            for method, name, value in (
                ("GET", "Cache-Control", "public"), ("HEAD", "Set-Cookie", CODES["marked"]),
                ("GET", "CF-Cache-Status", "HIT"), ("HEAD", "Age", "1"),
                ("GET", "Content-Type", "text/plain"), ("GET", "Content-Encoding", "gzip"),
                ("GET", "Content-Length", "1"), ("GET", "Transfer-Encoding", "chunked"),
                ("HEAD", "Content-Length", "1"), ("GET", "Location", path),
            ):
                with self.subTest(method=method, header=name):
                    changes = {method: {name: value}}
                    with self.assertRaises(smoke.ProbeError) as caught:
                        smoke._probe_pair(path, "synthetic", smoke.monotonic() + 90, 200, smoke.TEXT, body)
                    self.assertNotIn(CODES["marked"], str(caught.exception))
            changes = {}
            for payloads in ({"GET": b"bad", "HEAD": b""}, {"GET": body, "HEAD": b"bad"},
                             {"GET": b"x" * 1025, "HEAD": b""}):
                with self.assertRaises(smoke.ProbeError):
                    smoke._probe_pair(path, "synthetic", smoke.monotonic() + 90, 200, smoke.TEXT, body)

    def test_exact_redirect_is_compared_without_requesting_its_destination(self):
        code = CODES["marked"]
        location = f"/agg/{code}/clash"
        path = f"/s/{code}"
        calls = []

        @contextmanager
        def request(method, target, deadline, label):
            calls.append((method, target))
            headers = PRIVACY | {"Location": actual}
            yield SimpleNamespace(status=302, getheader=headers.get, read=BytesIO().read)

        with patch.object(smoke, "_request", new=request):
            actual = location
            report = smoke._probe_pair(path, "synthetic redirect", smoke.monotonic() + 90, 302, None, b"", location=location)
            self.assertEqual(report["status"], 302)
            self.assertEqual(calls, [("GET", path), ("HEAD", path)])
            calls.clear()
            actual = f"https://example.invalid{location}"
            with self.assertRaises(smoke.ProbeError) as caught:
                smoke._probe_pair(path, "synthetic redirect", smoke.monotonic() + 90, 302, None, b"", location=location)
            self.assertEqual(calls, [("GET", path)])
            self.assertNotIn(code, str(caught.exception))

    def test_invalid_fixture_inputs_fail_before_any_request(self):
        with patch.object(smoke, "_request") as request:
            for codes, stage in ((CODES | {"marked": "a/../invalid"}, "published"),
                                 (CODES | {"marked": CODES["ordinary"]}, "published"),
                                 (CODES | {"extra": "legacy_00005"}, "published"), (CODES, "unknown")):
                with self.assertRaises(smoke.ProbeError):
                    smoke.verify_legacy_selected_http(codes, stage)
            request.assert_not_called()
