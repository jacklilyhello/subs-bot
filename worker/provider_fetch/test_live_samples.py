"""Synthetic hosted checks for the protected provider sampler."""

import asyncio
from contextlib import redirect_stderr, redirect_stdout
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import stat
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import AsyncMock, call, patch

import live_samples as tool
from transport import FetchFailure, FetchSuccess


ORIGIN = "https://synthetic-provider.example.invalid"
PATH = "/account/%2fsubscription"
URLS = tuple(f"{ORIGIN}{PATH}?token=synthetic%2Bcase{n}+raw%2f&profile=clash" for n in range(1, 5))


def manifest(urls=URLS, **changes):
    return json.dumps({"version": 1, "origin": ORIGIN, "path": PATH, "urls": urls, **changes}, separators=(",", ":"))


def digest(secret):
    return sha256(secret.encode("utf-8")).hexdigest()


class ManifestTests(unittest.TestCase):
    def test_exact_provenance_and_url_wire_spelling(self):
        source = manifest()
        self.assertEqual(tool.read_manifest(source, digest(source)), URLS)
        with self.assertRaisesRegex(tool.SampleError, r"^Hosted provider sampling could not be confirmed safely\.$"):
            tool.read_manifest(source + "\n", digest(source))

    def test_rejects_out_of_scope_or_changed_wire_urls_before_sampling(self):
        bad_urls = (
            URLS[0].replace("https://", "http://", 1), URLS[0].replace(ORIGIN, ORIGIN + ".wrong"),
            URLS[0].replace(ORIGIN, ORIGIN + ":8443"), URLS[0].replace(ORIGIN, ORIGIN.replace("https://", "https://secret@")),
            URLS[0].replace(PATH, "/other"), URLS[0].replace("%2f", "%2F", 1), URLS[0] + "#private",
            URLS[0] + "#", ORIGIN + PATH, ORIGIN + PATH + "?", URLS[0] + "\n", URLS[0].replace("%2B", "%XX"),
        )
        bad = [manifest((URLS[1], url)) for url in bad_urls] + [
            manifest(()), manifest((URLS[0], URLS[0])), manifest(tuple(f"{ORIGIN}{PATH}?n={i}" for i in range(13))),
            manifest(version=True), manifest(version=1.0), manifest(extra="synthetic-private"),
            manifest(origin=ORIGIN + "/"), manifest(path=PATH + "?private=1"), manifest(path="//other"),
            manifest().replace('"version":1', '"version":1,"version":1'),
            " " * (tool.MAX_MANIFEST_BYTES + 1),
        ]
        for index, source in enumerate(bad):
            with self.subTest(case=index), self.assertRaises(tool.SampleError):
                tool.read_manifest(source, digest(source))


class SamplerTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        root = TemporaryDirectory()
        self.addCleanup(root.cleanup)
        self.runner = Path(root.name).resolve()
        self.output = self.runner / "samples"
        self.output.mkdir(mode=0o700)

    async def test_one_application_attempt_per_case_serial_and_private_index(self):
        body = b"private synthetic body \x00\xff"
        headers = {"content-type": "text/plain; charset=gb18030", "subscription-userinfo": "upload=1;total=5"}
        results = [FetchSuccess(body, headers), FetchFailure("invalid-redirect"), FetchFailure("http-status", 429)]
        requests = []
        active = False

        async def fetch(url, *, follow_redirects):
            nonlocal active
            self.assertFalse(active)
            self.assertFalse(follow_redirects)
            active = True
            requests.append(url)
            await asyncio.sleep(0)
            active = False
            return results[len(requests) - 1]

        with patch.object(tool, "fetch_provider", side_effect=fetch), patch.object(tool, "sleep", new_callable=AsyncMock) as pace:
            rows = await tool.sample_sources(URLS, self.output)
        self.assertEqual(requests, list(URLS[:3]))
        self.assertEqual(pace.await_args_list, [call(1), call(1)])
        self.assertEqual(rows, [
            {"case": 1, "outcome": "ok", "decodedBytes": len(body)},
            {"case": 2, "outcome": "invalid-redirect"},
            {"case": 3, "outcome": "http-status", "httpStatus": 429},
            {"case": 4, "outcome": "skipped-rate-limit"},
        ])
        self.assertEqual({path.name for path in self.output.iterdir()}, {"sample-01.body", "index.json"})
        for path in self.output.iterdir():
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual((self.output / "sample-01.body").read_bytes(), body)
        expected = {**rows[0], "file": "sample-01.body", "bodySha256": sha256(body).hexdigest(),
                    "rpcMetadata": headers, "legacyContentType": headers["content-type"]}
        index = (self.output / "index.json").read_bytes()
        self.assertEqual(json.loads(index), {"version": 1, "samples": [expected, *rows[1:]]})
        self.assertNotIn(ORIGIN.encode(), index)
        self.assertNotIn(b"synthetic%2B", index)

    async def test_private_rpc_metadata_uses_the_container_bound(self):
        fetch = AsyncMock(return_value=FetchSuccess(b"", {"content-type": "text/plain", "profile-title": "私" * 1000}))
        with patch.object(tool, "fetch_provider", fetch):
            self.assertEqual(await tool.sample_sources(URLS[:1], self.output), [{"case": 1, "outcome": "ok", "decodedBytes": 0}])
        row = json.loads((self.output / "index.json").read_bytes())["samples"][0]
        self.assertNotIn("rpcMetadata", row)
        self.assertEqual(row["legacyContentType"], "text/plain")


class WorkflowEntryTests(unittest.TestCase):
    def setUp(self):
        root = TemporaryDirectory()
        self.addCleanup(root.cleanup)
        self.runner = Path(root.name).resolve()
        self.output = self.runner / "samples"
        self.output.mkdir(mode=0o700)
        secret = manifest(URLS[:1])
        self.environment = {"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": "jacklilyhello/subs-bot",
                            "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REF": "refs/heads/main",
                            "GITHUB_RUN_ATTEMPT": "1", "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_TEMP": str(self.runner),
                            tool.SECRET: secret, tool.DIGEST: digest(secret)}

    def invoke(self, env, fetch):
        out, errors = io.StringIO(), io.StringIO()
        with patch.dict(os.environ, env, clear=True), patch.object(tool, "fetch_provider", fetch), \
             patch.object(tool.logging, "disable"), redirect_stdout(out), redirect_stderr(errors):
            status = tool.main([str(self.output)])
        return status, out.getvalue(), errors.getvalue()

    def test_main_reports_only_allowlisted_outcomes(self):
        fetch = AsyncMock(return_value=FetchSuccess(b"private-body", {"profile-title": "private-metadata"}))
        status, stdout, stderr = self.invoke(self.environment, fetch)
        self.assertEqual((status, stderr), (0, ""))
        self.assertEqual(json.loads(stdout), {"version": 1, "runtime": "github-hosted",
                                             "samples": [{"case": 1, "outcome": "ok", "decodedBytes": 12}]})
        self.assertEqual(fetch.await_args_list, [call(URLS[0], follow_redirects=False)])

    def test_a_completed_sample_reports_http_failure_without_runner_failure(self):
        fetch = AsyncMock(return_value=FetchFailure("http-status", 403))
        status, stdout, stderr = self.invoke(self.environment, fetch)
        self.assertEqual((status, stderr), (0, ""))
        self.assertEqual(json.loads(stdout)["samples"], [{"case": 1, "outcome": "http-status", "httpStatus": 403}])

    def test_ref_attempt_pin_and_output_fail_closed_without_egress(self):
        fetch = AsyncMock()
        for change in ({"GITHUB_REF": "refs/heads/unreviewed"}, {"GITHUB_RUN_ATTEMPT": "2"},
                       {"GITHUB_EVENT_NAME": "pull_request"}, {"RUNNER_ENVIRONMENT": "self-hosted"},
                       {tool.DIGEST: "0" * 64}, {tool.SECRET: ""}):
            with self.subTest(change=tuple(change)):
                self.assertEqual(self.invoke(self.environment | change, fetch), (2, "", tool.FAILURE + "\n"))
        invalid_last = manifest((URLS[0], URLS[1].replace(ORIGIN, ORIGIN + ".wrong")))
        self.assertEqual(self.invoke(self.environment | {tool.SECRET: invalid_last, tool.DIGEST: digest(invalid_last)}, fetch),
                         (2, "", tool.FAILURE + "\n"))
        self.output.chmod(0o750)
        self.assertEqual(self.invoke(self.environment, fetch), (2, "", tool.FAILURE + "\n"))
        self.output.chmod(0o700)
        (self.output / "preexisting").write_bytes(b"fixture")
        self.assertEqual(self.invoke(self.environment, fetch), (2, "", tool.FAILURE + "\n"))
        fetch.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
