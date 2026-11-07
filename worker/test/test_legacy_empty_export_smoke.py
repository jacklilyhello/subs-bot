from base64 import urlsafe_b64encode
from contextlib import redirect_stdout
from email.message import Message
from io import BytesIO, StringIO
import json
import os
from pathlib import Path
import sqlite3
import sys
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import legacy_empty_export_smoke as smoke
from d1_migrations import LEDGER_SQL
from telegram_view_fixtures import FixtureError


class ExportResponse(BytesIO):
    def __init__(self, status, body, media=None):
        super().__init__(body)
        self.status = status
        self.headers = Message()
        self.headers["Cache-Control"] = "private, no-store"
        self.headers["Referrer-Policy"] = "no-referrer"
        self.headers["X-Content-Type-Options"] = "nosniff"
        if media is not None:
            self.headers["Content-Type"] = media


class FixtureDatabase:
    scope_hash = "a" * 64
    database = "/fixture"

    def __init__(self):
        self.db = sqlite3.connect(":memory:")
        self.db.row_factory = sqlite3.Row
        migrations = Path(__file__).resolve().parents[1] / "migrations"
        for path in sorted(migrations.glob("*.sql")):
            self.db.executescript(path.read_text())
        self.lose_response = False
        self.queries = []

    def query(self, sql, params):
        return [dict(row) for row in self.db.execute(sql, params)]

    def api(self, method, path, payload):
        assert (method, path) == ("POST", self.database + "/query")
        if set(payload) == {"sql", "params"}:
            self.queries.append(payload)
            return [{"success": True, "results": self.query(payload["sql"], payload["params"])}]
        try:
            with self.db:
                result = [{"success": True, "results": self.query(row["sql"], row["params"])} for row in payload["batch"]]
        except sqlite3.Error:
            raise smoke.CloudflareError("Synthetic batch was rejected.") from None
        if self.lose_response:
            raise smoke.CloudflareError("Synthetic acknowledgement was lost.")
        return result


class EmptyExportSmokeTests(unittest.TestCase):
    def setUp(self):
        self.data = FixtureDatabase()
        self.addCleanup(self.data.db.close)
        self.fixtures = smoke.EmptyFixtures(self.data, {"adminId": "123", "memberId": "456"}, b"k" * 32, "a" * 16)
        self.guards = 0

    def guard(self):
        self.guards += 1

    def test_reconciles_lost_seed_and_retire_acknowledgements(self):
        self.data.lose_response = True
        self.fixtures.seed(self.guard)
        self.fixtures.seed(self.guard)
        self.assertEqual(len(self.fixtures.observe()), 2)
        self.assertEqual(self.guards, 1)
        self.assertEqual(self.data.query("SELECT count(*) AS n FROM legacy_empty_subscription_exports", ()), [{"n": 1}])
        self.assertEqual(self.fixtures.retire(self.guard), 2)
        self.assertEqual(self.fixtures.retire(self.guard), 0)
        self.assertEqual(self.guards, 2)

    def test_retirement_rejects_changed_identity_and_dangling_marker(self):
        self.fixtures.seed(self.guard)
        self.data.db.execute("UPDATE subscriptions SET name='foreign' WHERE owner_id='123'")
        with self.assertRaises(FixtureError):
            self.fixtures.retire(self.guard)
        self.assertEqual(len(self.data.query("SELECT id FROM subscriptions", ())), 2)
        self.data.db.execute("DELETE FROM subscriptions")
        with self.assertRaises(sqlite3.Error):
            self.fixtures.retire(self.guard)

    def test_checks_all_formats_and_unmarked_control(self):
        checks = []
        marked = self.fixtures.targets["marked"]["token"]

        def request(token, suffix, method):
            checks.append((token, suffix, method))
            if token != marked:
                return 404, "text/plain", b"Not found." if method == "GET" else b""
            if suffix in {"", "clash"}:
                media, body = "text/yaml", b"proxies: []\nproxy-groups:\nrules:\n"
            elif suffix in {"singbox", "sing-box"}:
                media, body = "application/json", json.dumps(smoke.EXPECTED_SINGBOX).encode()
            else:
                media, body = "text/plain", smoke.EXPECTED_SURGE if suffix == "surge" else b""
            return 200, media, body if method == "GET" else b""

        smoke.verify_formats(self.fixtures, request)
        self.assertEqual(len(checks), 24)

    def test_recovery_requires_explicit_exact_confirmation(self):
        cohort = "1" * 16
        self.assertEqual(smoke.parse_inputs({"inputs": {"action": "retire", "cohort": cohort, "confirm_retire": "retire " + cohort}}),
                         ("retire", cohort, "legacy-empty"))
        self.assertEqual(smoke.parse_inputs({"inputs": {"action": "verify", "cohort": cohort, "profile": "typed-shorts"}}),
                         ("verify", cohort, "typed-shorts"))
        with self.assertRaises(FixtureError):
            smoke.parse_inputs({"inputs": {"action": "retire", "cohort": cohort}})

    def test_run_uses_real_resources_signature_and_retires_the_probe_capabilities(self):
        revision, cohort = "b" * 40, "d" * 16
        config = json.dumps({"botId": "789", "adminId": "123", "memberId": "456", "groupId": "-321",
                             "botUsername": "test_cfsubs_bot", "botToken": "789:" + "T" * 36, "webhookSecret": "W" * 36})
        key = urlsafe_b64encode(b"k" * 32).decode("ascii").rstrip("=")
        target = {"accountId": "a" * 32, "workerId": "b" * 32, "d1Id": "00000000-0000-4000-8000-000000000001",
                  "workerCreatedOn": "2026-07-30T00:00:00Z", "d1CreatedAt": "2026-07-30T00:00:00Z",
                  "r2CreatedOn": "2026-07-30T00:00:00Z", "namespace": "lilyya"}
        resources = smoke.Resources(target, self.data.api, None)
        self.data.database = resources.database
        self.data.db.execute(LEDGER_SQL)
        self.data.db.execute("INSERT INTO subs_bot_schema_migrations VALUES (26,?,?, 'applied',1)",
                             (smoke.MIGRATION, smoke.MIGRATION_SHA256))
        self.data.db.commit()
        scope = Mock()
        active = SimpleNamespace(version="00000000-0000-4000-8000-000000000002")
        scope.active.return_value = active
        scope.version.return_value = SimpleNamespace(revision=revision, telegram_config_sha256=smoke.digest(config.encode()),
                                                     telegram_aggregate_key_sha256=smoke.digest(key.encode()))
        opener = Mock()

        def open_export(request, timeout):
            parsed = urlsplit(request.full_url)
            self.assertEqual((parsed.scheme, parsed.netloc, parsed.query, parsed.fragment),
                             ("https", "subs-bot-cf-dev-01.lilyya.workers.dev", "", ""))
            self.assertEqual(request.get_header("User-agent"), "subs-bot-isolation-release/1.0")
            self.assertEqual(request.get_header("Accept-encoding"), "identity")
            self.assertEqual(timeout, 8)
            _, endpoint, token, *parts = parsed.path.split("/")
            self.assertEqual(endpoint, "sub")
            suffix = parts[0] if parts else ""
            marked = bool(self.data.query("""SELECT 1 FROM subscriptions JOIN legacy_empty_subscription_exports
                ON subscription_id=subscriptions.id WHERE token=?""", (token,)))
            status, media, body = 404, "text/plain; charset=utf-8", b"Not found."
            if marked:
                status = 200
                if suffix in ("", "clash"):
                    media, body = "text/yaml; charset=utf-8", b"proxies: []\nproxy-groups:\nrules:\n"
                elif suffix in ("singbox", "sing-box"):
                    media, body = "application/json", json.dumps(smoke.EXPECTED_SINGBOX).encode()
                else:
                    body = smoke.EXPECTED_SURGE if suffix == "surge" else b""
            return ExportResponse(status, body if request.get_method() == "GET" else b"", media)

        opener.open.side_effect = open_export
        with TemporaryDirectory() as directory:
            event = Path(directory) / "event.json"
            event.write_text(json.dumps({"inputs": {"action": "verify", "cohort": cohort}}))
            environment = {"GITHUB_SHA": revision, "GITHUB_REPOSITORY": smoke.REPOSITORY, "GITHUB_REF": smoke.MAIN_REF,
                           "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_EVENT_PATH": str(event),
                           "SUBS_BOT_TELEGRAM_TEST_CONFIG": config, "SUBS_BOT_TELEGRAM_AGGREGATE_KEY": key,
                           "SUBS_BOT_CF_ISOLATION_TARGET_JSON": json.dumps(target), "SUBS_BOT_CF_BOOTSTRAP_TOKEN": "data",
                           "SUBS_BOT_CF_DEPLOY_TOKEN": "deploy"}
            output = StringIO()
            with (patch.dict(os.environ, environment, clear=True),
                  patch.object(smoke, "CloudflareClient", side_effect=[self.data.api, Mock()]),
                  patch.object(smoke, "_Isolation", return_value=scope), patch.object(smoke, "_verify_health"),
                  patch.object(smoke, "require_current_main"), patch.object(smoke, "build_opener", return_value=opener),
                  redirect_stdout(output)):
                smoke.run()
        self.assertEqual(self.data.queries[0], {"sql": "SELECT name,sha256,mode FROM subs_bot_schema_migrations WHERE position=26",
                                                "params": []})
        self.assertEqual(json.loads(output.getvalue()), {"action": "verify", "verifiedFormats": 11, "syntheticRowsRemoved": 2,
                                                        "privateNoStore": True, "activeVersion": active.version})
        self.assertEqual(opener.open.call_count, 28)
        self.assertEqual(self.data.query("SELECT count(*) AS n FROM subscriptions", ()), [{"n": 0}])
        self.assertEqual(self.data.query("SELECT count(*) AS n FROM legacy_empty_subscription_exports", ()), [{"n": 0}])

    def test_missing_media_type_and_private_failure_detail_cannot_pass_through(self):
        opener = Mock()
        opener.open.return_value = ExportResponse(200, b"")
        self.assertEqual(smoke.request_export(opener, "synthetic-token", "base64", "GET"), (200, "", b""))
        private_detail = "synthetic private capability"
        with self.assertRaisesRegex(smoke.SmokePhaseError, "Failed phase format probes") as failure:
            with smoke.phase("format probes"):
                raise ValueError(private_detail)
        self.assertNotIn(private_detail, str(failure.exception))


if __name__ == "__main__":
    unittest.main()
