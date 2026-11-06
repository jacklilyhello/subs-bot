"""Hosted unit tests for the capacity probe without network access."""

from contextlib import contextmanager, redirect_stderr, redirect_stdout
from hashlib import sha256
from http.client import BadStatusLine
from io import BytesIO, StringIO
import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
from threading import Lock
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import capacity_probe as probe


REVISION = "a" * 40
BODY = b"Y2FwYWNpdHk="
PRIVATE = {
    "Cache-Control": "private, no-store",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "CF-Cache-Status": "DYNAMIC",
}


class Response:
    def __init__(self, status, body, **headers):
        self.status = status
        self.headers = PRIVATE | {"Content-Type": "text/plain; charset=utf-8"} | headers
        self.stream = BytesIO(body)
        self.read_bytes = 0
        self.closed = False

    def getheader(self, name, default=None):
        return self.headers.get(name, default)

    def read(self, limit):
        data = self.stream.read(limit)
        self.read_bytes += len(data)
        return data

    def close(self):
        self.stream.close()
        self.closed = True


class CapacityProbeTests(unittest.TestCase):
    def setUp(self):
        self.fixtures = {
            label: probe.Fixture(
                label, f"subsbot-synthetic-capacity-{label}", status,
                len(BODY) if status == 200 else 0, sha256(BODY).hexdigest() if status == 200 else None,
            )
            for label, status in probe.FIXTURE_STATUS.items()
        }
        self.calls = []
        self.lock = Lock()
        self.health_count = 0
        self.last_revision = REVISION

    @contextmanager
    def network(self, method, path, deadline):
        self.assertGreater(deadline, probe.monotonic())
        with self.lock:
            if path == "/health":
                self.health_count += 1
                revision = REVISION if self.health_count == 1 else self.last_revision
                health = {"ok": True, "service": "subs-bot", "revision": revision}
                response = Response(200, json.dumps(health).encode(), **{"Content-Type": "application/json"})
            else:
                fixture = next(item for item in self.fixtures.values() if path == f"/sub/{item.token}/base64")
                if method == "HEAD":
                    response = Response(fixture.status, b"")
                elif fixture.status == 200:
                    response = Response(200, BODY, **{"Content-Length": str(len(BODY))})
                else:
                    response = Response(fixture.status, probe.ERROR_BODY[fixture.status])
            self.calls.append((method, path, response))
        try:
            yield response
        finally:
            response.close()

    def run_mocked(self):
        with (patch.object(probe, "_load_fixtures", return_value=self.fixtures),
              patch.object(probe, "_request", self.network),
              patch.object(probe, "READ_BYTES", 4), patch.object(probe, "CANCEL_BYTES", 4),
              patch.object(probe, "SLOW_INTERVAL_BYTES", 4), patch.object(probe, "sleep") as pause):
            report = probe.run_probe("synthetic-directory", REVISION)
        self.assertEqual(pause.call_count, 2)
        return report

    def test_request_budget_statuses_and_bounded_body_reads(self):
        report = self.run_mocked()
        self.assertEqual(report["requests"], 18)
        self.assertEqual(len(self.calls), 18)
        self.assertEqual([self.calls[index][:2] for index in (0, -1)], [("GET", "/health")] * 2)
        self.assertEqual(report["health"]["samples"], 2)
        self.assertGreater(report["health"]["bodyBytes"], 0)
        self.assertEqual({label: row["status"] for label, row in report["head"].items()}, probe.FIXTURE_STATUS)
        self.assertEqual(
            {label: row["status"] for label, row in report["rejectedGet"].items()},
            {"share-over": 422, "snapshot-over": 503},
        )
        self.assertEqual(
            {mode: row["samples"] for mode, row in report["export"].items()},
            {"serial": 3, "parallel2": 2, "parallel4": 4, "slow": 1, "cancel": 1},
        )
        for mode, row in report["export"].items():
            self.assertGreaterEqual(row["firstBodyByteMs"]["min"], 0)
            self.assertLessEqual(row["firstBodyByteMs"]["max"], row["elapsedMs"]["max"])
            if mode == "cancel":
                self.assertNotIn("bodyBytesPerSecond", row)
            else:
                self.assertGreater(row["bodyBytesPerSecond"]["min"], 0)
        for row in [report["health"], *report["head"].values(), *report["rejectedGet"].values()]:
            self.assertNotIn("firstBodyByteMs", row)
            self.assertNotIn("bodyBytesPerSecond", row)
        positive_path = f"/sub/{self.fixtures['at-limits'].token}/base64"
        successful = [response for method, path, response in self.calls if method == "GET" and path == positive_path]
        self.assertEqual(sorted(response.read_bytes for response in successful), [4] + [len(BODY)] * 10)
        self.assertTrue(all(response.closed for _, _, response in self.calls))
        output = json.dumps(report)
        for fixture in self.fixtures.values():
            self.assertNotIn(fixture.token, output)
        self.assertNotIn("/sub/", output)

    def test_slow_body_timing_uses_first_and_last_body_reads_and_includes_pauses(self):
        response = Response(200, BODY, **{"Content-Length": str(len(BODY))})
        read = response.read
        clock = 100.0
        read_sizes = []

        def read_at_time(size):
            nonlocal clock
            clock += 0.5
            read_sizes.append(size)
            return read(size)

        def pause(seconds):
            nonlocal clock
            clock += seconds

        with (patch.object(response, "read", side_effect=read_at_time),
              patch.object(probe, "monotonic", side_effect=lambda: clock),
              patch.object(probe, "sleep", side_effect=pause),
              patch.object(probe, "READ_BYTES", 4), patch.object(probe, "SLOW_INTERVAL_BYTES", 4)):
            measured = probe._verify_export(response, self.fixtures["at-limits"], "slow", 110.0)
        # The final EOF verification happens after the complete-body timestamp.
        self.assertEqual(read_sizes, [1, 4, 4, 3, 1])
        self.assertEqual(measured, (len(BODY), 100.5, 102.5))

    def test_postflight_requires_exact_same_revision(self):
        self.last_revision = "b" * 40
        with self.assertRaisesRegex(probe.ProbeError, "exact expected revision"):
            self.run_mocked()
        self.assertEqual(len(self.calls), 18)

    def test_cap_and_deadline_stop_before_an_additional_connection(self):
        with (patch.object(probe, "_load_fixtures", return_value=self.fixtures),
              patch.object(probe, "_request", self.network),
              patch.object(probe, "MAX_REQUESTS", 1)):
            with self.assertRaisesRegex(probe.ProbeError, "request limit"):
                probe.run_probe("synthetic-directory", REVISION)
        self.assertEqual(len(self.calls), 1)
        with (patch.object(probe, "_load_fixtures", return_value=self.fixtures),
              patch.object(probe, "_request", self.network),
              patch.object(probe, "RUN_SECONDS", 0)):
            with self.assertRaisesRegex(probe.ProbeError, "deadline"):
                probe.run_probe("synthetic-directory", REVISION)
        self.assertEqual(len(self.calls), 1)

    def test_rejects_cache_hits_cookies_redirects_and_bad_content(self):
        for header in ({"CF-Cache-Status": "HIT"}, {"Cache-Control": "public, no-store"},
                       {"Set-Cookie": "fake-session"}, {"Age": "0"}):
            with self.subTest(header=header), self.assertRaisesRegex(probe.ProbeError, "privacy headers"):
                probe._check_headers(Response(200, BODY, **header), 200, "at-limits", "text/plain")
        with self.assertRaisesRegex(probe.ProbeError, "HTTP status 302"):
            probe._check_headers(Response(302, b"", Location="https://elsewhere.example.invalid"), 200, "at-limits", "text/plain")
        deadline = probe.monotonic() + 10
        for wrong in (b"", BODY[:-1], b"A" * len(BODY), BODY + b"X"):
            with self.subTest(wrong=wrong), self.assertRaisesRegex(probe.ProbeError, "length or digest"):
                response = Response(200, wrong, **{"Content-Length": str(len(BODY))})
                probe._verify_export(response, self.fixtures["at-limits"], "full", deadline)

    def test_transport_is_fixed_and_errors_are_safe_to_print(self):
        token = self.fixtures["at-limits"].token
        path = f"/sub/{token}/base64"
        connection = Mock()
        connection.getresponse.side_effect = BadStatusLine(path)
        with (patch.object(probe, "HTTPSConnection", return_value=connection) as connect,
              patch.object(probe, "Timer") as timer):
            with self.assertRaisesRegex(probe.ProbeError, "HTTPS request failed") as failure:
                with probe._request("GET", path, probe.monotonic() + 10):
                    self.fail("Unexpected response")
        self.assertNotIn(token, str(failure.exception))
        self.assertEqual(connect.call_args.args, (probe.HOST,))
        self.assertGreater(connect.call_args.kwargs["timeout"], 0)
        connection.request.assert_called_once_with(
            "GET", path, headers={"Accept-Encoding": "identity", "Connection": "close", "User-Agent": "subs-bot-isolation-release/1.0"},
        )
        connection.close.assert_called_once()
        timer.return_value.cancel.assert_called_once()
        out, error = StringIO(), StringIO()
        with (patch.object(probe, "run_probe", side_effect=ValueError(path)),
              redirect_stdout(out), redirect_stderr(error)):
            self.assertEqual(probe.main(["synthetic-directory"]), 1)
        self.assertEqual(out.getvalue(), "")
        self.assertNotIn(token, error.getvalue())

    def test_manifest_identity_revision_and_boundaries(self):
        rows = []
        for index, fixture in enumerate(self.fixtures.values(), 1):
            node_count, node_bytes, share_bytes = {
                200: (probe.MAX_NODES, probe.MAX_SNAPSHOT_BYTES, probe.MAX_SHARE_BYTES),
                422: (33, 33 * probe.MAX_CHUNK_BYTES, probe.MAX_SHARE_BYTES + 1),
                503: (129, probe.MAX_SNAPSHOT_BYTES + 1, 0),
            }[fixture.status]
            chunks = []
            if fixture.status != 503:
                count = node_bytes // probe.MAX_CHUNK_BYTES
                per_chunk, extra = divmod(node_count, count)
                chunks = [
                    {"file": f"{fixture.label}/{chunk}.ndjson", "bytes": probe.MAX_CHUNK_BYTES,
                     "sha256": "c" * 64, "count": per_chunk + (chunk < extra)}
                    for chunk in range(count)
                ]
            rows.append({
                "label": fixture.label, "token": fixture.token, "status": fixture.status,
                "snapshotId": f"00000000-0000-4000-8000-{index:012d}",
                "nodeCount": node_count, "nodeBytes": node_bytes, "shareBytes": share_bytes,
                "exportBytes": 4 * ((share_bytes + 2) // 3) if fixture.status == 200 else 0,
                "exportSha256": fixture.export_sha256, "chunks": chunks,
                "manifestFile": f"{fixture.label}/manifest.json", "manifestSha256": "d" * 64,
            })
        with TemporaryDirectory() as directory:
            manifest = Path(directory) / "capacity.json"
            data = {"version": 1, "revision": REVISION, "fixtures": rows}
            manifest.write_text(json.dumps(data), encoding="utf-8")
            self.assertEqual(set(probe._load_fixtures(directory, REVISION)), set(probe.FIXTURE_STATUS))
            with self.assertRaisesRegex(probe.ProbeError, "revision"):
                probe._load_fixtures(directory, "b" * 40)
            rows[1]["shareBytes"] -= 1
            manifest.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaisesRegex(probe.ProbeError, "share-limit"):
                probe._load_fixtures(directory, REVISION)


if __name__ == "__main__":
    unittest.main()
