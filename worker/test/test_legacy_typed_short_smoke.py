from base64 import urlsafe_b64encode
from io import StringIO
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from urllib.parse import urlsplit

from test_legacy_empty_export_smoke import ExportResponse, FixtureDatabase, smoke
import legacy_typed_short_smoke as typed


class TypedShortSmokeTests(unittest.TestCase):
    def setUp(self):
        self.data = FixtureDatabase()
        self.addCleanup(self.data.db.close)
        self.policy = {"botId": "789", "adminId": "123", "memberId": "456"}
        self.cohort = "a" * 16
        self.fixtures = typed.TypedShortFixtures(self.data, self.policy, b"k" * 32, self.cohort)
        self.guard = Mock()

    def test_recovers_exact_committed_phases_and_retires_from_trash(self):
        self.data.lose_response = True
        sid = self.fixtures.seed(self.guard)
        self.assertEqual(self.fixtures.observe(), (sid, "seed"))
        self.fixtures.move(sid, True, self.guard)
        self.assertEqual(self.fixtures.observe(), (sid, "trash"))
        self.fixtures.move(sid, False, self.guard)
        self.assertEqual(self.fixtures.observe(), (sid, "restored"))
        self.assertEqual(self.fixtures.retire(self.guard, sid), 1)
        self.assertEqual(self.fixtures.observe(sid), (sid, "absent"))
        self.assertEqual(self.fixtures.retire(self.guard), 0)
        self.assertEqual(self.guard.call_count, 4)

        sid = self.fixtures.seed(self.guard)
        self.fixtures.move(sid, True, self.guard)
        self.assertEqual(self.fixtures.retire(self.guard), 1)
        self.assertEqual(self.fixtures.observe(sid), (sid, "absent"))

    def test_unconfirmed_seed_is_observed_but_never_resubmitted(self):
        api = self.data.api
        seed_batches = []

        def reject(method, path, payload):
            if any(item["sql"].startswith("INSERT INTO subscriptions ") for item in payload.get("batch", [])):
                seed_batches.append(True)
                raise typed.CloudflareError("Unconfirmed write.", uncertain=True)
            return api(method, path, payload)

        with patch.object(self.data, "api", side_effect=reject), patch.object(typed, "sleep") as sleep:
            with self.assertRaises(typed.FixtureError):
                self.fixtures.seed(self.guard)
        self.assertEqual(len(seed_batches), 1)
        self.assertEqual([call.args for call in sleep.call_args_list], [(1,), (2,)])
        self.assertEqual(self.fixtures.observe(), (0, "absent"))

    def test_existing_foreign_digest_and_cas_changes_are_preserved(self):
        contested = self.fixtures.hashes["normal-conflict"]
        self.data.db.execute("""INSERT INTO normal_short_links
            (code_sha256,code_length,bot_id,owner_id,target_url) VALUES (?,12,'12','34','https://example.com')""", (contested,))
        self.data.db.commit()
        with self.assertRaises(typed.FixtureError):
            self.fixtures.seed(self.guard)
        with self.assertRaises(typed.FixtureError):
            self.fixtures.retire(self.guard)
        self.assertEqual(self.data.query("SELECT owner_id FROM normal_short_links", ()), [{"owner_id": "34"}])
        self.guard.assert_not_called()
        self.data.db.execute("DELETE FROM normal_short_links")
        self.data.db.commit()

        sid = self.fixtures.seed(self.guard)

        def change_after_read():
            self.data.db.execute("UPDATE subscriptions SET name='other-owner-change' WHERE id=?", (sid,))
            self.data.db.commit()

        with patch.object(typed, "sleep"):
            with self.assertRaises(typed.FixtureError):
                self.fixtures.retire(change_after_read, sid)
        self.assertEqual(self.data.query("SELECT name FROM subscriptions", ()), [{"name": "other-owner-change"}])
        self.assertEqual(self.data.query("SELECT count(*) AS n FROM legacy_subscription_short_links", ()), [{"n": 8}])

    def test_get_and_head_cover_redirect_targets_payloads_and_all_retirement_states(self):
        requests = []

        def respond(request, timeout):
            parsed = urlsplit(request.full_url)
            self.assertEqual((parsed.scheme, parsed.netloc, parsed.query, parsed.fragment),
                             ("https", "subs-bot-cf-dev-01.lilyya.workers.dev", "", ""))
            self.assertEqual(request.get_header("User-agent"), "subs-bot-isolation-release/1.0")
            self.assertEqual(request.get_header("Accept-encoding"), "identity")
            self.assertEqual(timeout, 8)
            _, endpoint, capability, *tail = parsed.path.split("/")
            method = request.get_method()
            _, stage = self.fixtures.observe()
            requests.append((stage, endpoint, method))
            status, media, location, body = 404, "text/plain", None, b"Not found."
            if stage in ("seed", "restored") and endpoint == "s":
                suffix = next((suffix for label, suffix in typed.FORMATS.items() if self.fixtures.codes[label] == capability), None)
                if suffix is not None:
                    status, media, location, body = 302, None, "/sub/" + self.fixtures.token + ("/" + suffix if suffix else ""), b""
            if stage in ("seed", "restored") and endpoint == "sub":
                self.assertEqual(capability, self.fixtures.token)
                suffix = tail[0] if tail else "clash"
                status, media = 200, "text/yaml" if suffix == "clash" else "text/plain"
                body = {"clash": typed.EXPECTED_CLASH, "surge": smoke.EXPECTED_SURGE, "mixed": b""}[suffix]
            response = ExportResponse(status, body if method == "GET" else b"", media)
            if location:
                response.headers["Location"] = location
            return response

        opener = Mock()
        opener.open.side_effect = respond
        result = smoke.run_typed_shorts(self.fixtures, opener, lambda *args: smoke.request_export(opener, *args),
                                       "verify", self.guard)
        self.assertEqual(result, {"verifiedRedirectFormats": 3, "syntheticRowsRemoved": 1})
        for stage, count in (("seed", 26), ("trash", 20), ("restored", 26), ("absent", 20)):
            self.assertEqual(sum(seen == stage for seen, _, _ in requests), count)
        self.assertEqual({method for _, _, method in requests}, {"GET", "HEAD"})
        self.assertEqual(self.fixtures.observe(), (0, "absent"))

    def test_never_follows_an_absolute_redirect(self):
        response = ExportResponse(302, b"")
        response.headers["Location"] = "https://example.com/typed-short-fixture"
        opener = Mock()
        opener.open.return_value = response
        export = Mock()
        with self.assertRaises(typed.FixtureError):
            typed.verify_short_probes(self.fixtures, opener, export, smoke.EXPECTED_SURGE, True)
        opener.open.assert_called_once()
        export.assert_not_called()

    def test_disabled_live_version_stops_before_fixture_setup(self):
        revision = "b" * 40
        raw_policy = json.dumps(self.policy)
        key = urlsafe_b64encode(b"k" * 32).decode("ascii").rstrip("=")
        env = {"GITHUB_SHA": revision, "GITHUB_REPOSITORY": smoke.REPOSITORY, "GITHUB_REF": smoke.MAIN_REF,
               "GITHUB_EVENT_NAME": "workflow_dispatch", "SUBS_BOT_TELEGRAM_AGGREGATE_KEY": key,
               "SUBS_BOT_CF_ISOLATION_TARGET_JSON": "{}", "SUBS_BOT_CF_BOOTSTRAP_TOKEN": "data",
               "SUBS_BOT_CF_DEPLOY_TOKEN": "deploy"}
        resources = Mock()
        resources.query.return_value = [{"name": smoke.MIGRATION, "sha256": smoke.MIGRATION_SHA256, "mode": "applied"}]
        scope = Mock()
        scope.version.return_value = SimpleNamespace(
            revision=revision, telegram_config_sha256=smoke.digest(raw_policy.encode()),
            telegram_aggregate_key_sha256=smoke.digest(key.encode()), legacy_subscription_shorts=False,
        )
        with TemporaryDirectory() as directory:
            event = Path(directory) / "event.json"
            event.write_text(json.dumps({"inputs": {"action": "verify", "profile": "typed-shorts", "cohort": self.cohort}}))
            with (patch.dict(os.environ, env | {"GITHUB_EVENT_PATH": str(event)}, clear=True),
                  patch.object(smoke, "require_current_main"), patch.object(smoke, "CloudflareClient"),
                  patch.object(smoke, "_Isolation", return_value=scope), patch.object(smoke, "_verify_health"),
                  patch.object(smoke, "telegram_release_config", return_value=raw_policy),
                  patch.object(smoke, "Resources", return_value=resources), patch.object(smoke, "TypedShortFixtures") as fixtures):
                with self.assertRaisesRegex(smoke.SmokePhaseError, "Failed phase migration ledger"):
                    smoke.run()
        scope.verify_legacy_subscription_shorts.assert_called_once_with()
        fixtures.assert_not_called()


if __name__ == "__main__":
    unittest.main()
