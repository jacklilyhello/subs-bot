"""Synthetic, no-network coverage for the private provider Worker bootstrap."""

from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, call, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import bootstrap_provider_worker as bootstrap


ACCOUNT = "a" * 32
WORKER_ID = "b" * 32
CREATED = "2026-11-07T01:00:00.001Z"
UPDATED = "2026-11-07T01:00:00.123456789Z"
TARGET = bootstrap.provider.SERVICE
IDENTITY = bootstrap.Identity(WORKER_ID, CREATED)
PIN = {"workerId": WORKER_ID, "workerCreatedOn": CREATED}


def worker():
    return {
        **deepcopy(bootstrap.CREATE_SETTINGS), "id": WORKER_ID, "created_on": CREATED, "updated_on": UPDATED,
        "deployed_on": None, "references": {key: [] for key in bootstrap.REFERENCE_FIELDS},
    }


def envelope(status, result=None, *, success=True, errors=None, **extra):
    return status, {}, json.dumps({"success": success, "result": result, "errors": errors or [], **extra}).encode()


class WorkerAPITests(unittest.TestCase):
    def setUp(self):
        pin = patch.object(bootstrap, "TARGET_ACCOUNT_SHA256", sha256(ACCOUNT.encode()).hexdigest())
        pin.start()
        self.addCleanup(pin.stop)
        self.api = bootstrap.WorkerAPI(ACCOUNT, "synthetic-worker-token")

    def test_api_calls_have_only_expected_paths_methods_and_atomic_private_settings(self):
        with patch.object(bootstrap, "_response", side_effect=[
            envelope(404, success=False, errors=[{"code": 10007}]),
            envelope(201, worker()), envelope(200, worker()),
            envelope(200, [], result_info={"count": 0, "total_count": 0, "page": 1, "per_page": 1}),
        ]) as read:
            self.assertIsNone(self.api.by_name(absent=True))
            self.assertEqual(self.api.create(), worker())
            self.assertEqual(self.api.by_id(IDENTITY), worker())
            self.api.require_no_versions(IDENTITY)
        requests = [item.args[0] for item in read.call_args_list]
        base = f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT}/workers/workers"
        self.assertEqual([(request.method, request.full_url) for request in requests],
                         [("GET", f"{base}/{TARGET}"), ("POST", base), ("GET", f"{base}/{WORKER_ID}"),
                          ("GET", f"{base}/{WORKER_ID}/versions?page=1&per_page=1")])
        for request in requests:
            self.assertEqual(request.get_header("Authorization"), "Bearer synthetic-worker-token")
        payload = json.loads(requests[1].data)
        self.assertEqual(set(payload), {"name", "subdomain", "logpush", "observability", "tail_consumers",
                                        "tags", "previews_base_config"})
        self.assertEqual(payload["name"], TARGET)
        self.assertEqual(payload["tags"], ["subs-bot-provider-isolation"])
        self.assertEqual(payload["subdomain"], {"enabled": False, "previews_enabled": False})
        for scope in (payload, payload["previews_base_config"]):
            self.assertIs(scope["logpush"], False)
            self.assertEqual(scope["tail_consumers"], [])
            self.assertIs(scope["observability"]["enabled"], False)
            self.assertIs(scope["observability"]["logs"]["invocation_logs"], False)
            self.assertIs(scope["observability"]["traces"]["enabled"], False)

    def test_only_real_exact_404_is_absence(self):
        for response in [
            envelope(403, success=False, errors=[{"code": 10007}]),
            envelope(404, success=False, errors=[{"code": "10007"}]),
            envelope(404, success=False, errors=[{"code": 10007}, {"code": 9999}]),
            envelope(404, worker(), success=False, errors=[{"code": 10007}]),
            envelope(404, success=True, errors=[{"code": 10007}]),
            envelope(200, None),
            (404, {}, b"not an API envelope"),
        ]:
            with self.subTest(response=response), patch.object(bootstrap, "_response", return_value=response):
                with self.assertRaises((bootstrap.BootstrapError, bootstrap.github.ArtifactError)):
                    self.api.by_name(absent=True)
        with patch.object(bootstrap, "_response", return_value=envelope(404, success=False, errors=[{"code": 10007}])):
            with self.assertRaises(bootstrap.BootstrapError):
                self.api.by_name()

    def test_create_redirect_or_conflict_is_unconfirmed(self):
        for status in (302, 409, 500):
            with self.subTest(status=status), patch.object(bootstrap, "_response", return_value=envelope(
                    status, success=False, errors=[{"code": 9999, "message": "synthetic sensitive detail"}])):
                with self.assertRaisesRegex(bootstrap.BootstrapError, "creation was not confirmed"):
                    self.api.create()

    def test_empty_versions_read_rejects_a_nonempty_or_contradictory_response(self):
        for payload in (envelope(200, [{}]), envelope(200, [], result_info={"total_count": 1}),
                        envelope(200, [], result_info={"count": False}), envelope(200, {"items": []})):
            with self.subTest(payload=payload), patch.object(bootstrap, "_response", return_value=payload):
                with self.assertRaisesRegex(bootstrap.BootstrapError, "private, empty settings"):
                    self.api.require_no_versions(IDENTITY)

    def test_successful_real_empty_page_can_return_null_errors(self):
        result = {"success": True, "errors": None, "result": [],
                  "result_info": {"count": 0, "total_count": 0, "page": 1, "per_page": 1}}
        with patch.object(bootstrap, "_response", return_value=(200, {}, json.dumps(result).encode())):
            self.api.require_no_versions(IDENTITY)

    def test_wrong_account_or_missing_worker_token_fails_before_network(self):
        with self.assertRaisesRegex(bootstrap.BootstrapError, "account does not match"):
            bootstrap.WorkerAPI("1" * 32, "synthetic-token")
        with self.assertRaisesRegex(bootstrap.BootstrapError, "credential is missing"):
            bootstrap.WorkerAPI(ACCOUNT, "")


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.api = Mock(spec=bootstrap.WorkerAPI)
        self.guard = Mock()
        self.api.by_id.return_value = worker()
        self.api.create.return_value = worker()

    def test_one_create_is_followed_by_immutable_id_name_and_version_readback(self):
        self.api.by_name.side_effect = [None, None, worker()]
        self.assertEqual(bootstrap._bootstrap(self.api, "create", None, self.guard), ("created", IDENTITY))
        self.assertEqual(self.api.method_calls, [
            call.by_name(absent=True), call.by_name(absent=True), call.create(),
            call.by_id(IDENTITY), call.require_no_versions(IDENTITY), call.by_name(),
        ])
        self.assertEqual(self.guard.call_count, 2)

    def test_verification_accepts_only_the_protected_pin_and_never_writes(self):
        self.api.by_name.return_value = worker()
        with self.assertRaisesRegex(bootstrap.BootstrapError, "identity pin"):
            bootstrap._bootstrap(self.api, "verify", None, self.guard)
        self.assertEqual(self.api.method_calls, [])
        self.assertEqual(bootstrap._bootstrap(self.api, "verify", IDENTITY, self.guard), ("verified", IDENTITY))
        self.api.create.assert_not_called()
        self.api.reset_mock()
        with self.assertRaisesRegex(bootstrap.BootstrapError, "already pinned"):
            bootstrap._bootstrap(self.api, "create", IDENTITY, self.guard)
        self.assertEqual(self.api.method_calls, [])

    def test_existing_name_and_race_refuse_adoption_even_with_exact_tag(self):
        for responses in ([worker()], [None, worker()]):
            with self.subTest(responses=responses):
                self.api.by_name.side_effect = responses
                with self.assertRaisesRegex(bootstrap.BootstrapError, "occupied"):
                    bootstrap._bootstrap(self.api, "create", None, self.guard)
                self.api.create.assert_not_called()
                self.api.by_id.assert_not_called()

    def test_never_retries_or_adopts_an_unconfirmed_create(self):
        self.api.by_name.side_effect = [None, None]
        self.api.create.side_effect = bootstrap.PublicationError("ambiguous")
        with self.assertRaisesRegex(bootstrap.BootstrapError, "Inspect the exact target"):
            bootstrap._bootstrap(self.api, "create", None, self.guard)
        self.api.create.assert_called_once()
        self.api.by_id.assert_not_called()

    def test_stale_main_stops_before_create(self):
        self.api.by_name.return_value = None
        self.guard.side_effect = bootstrap.github.ArtifactError("main changed")
        with self.assertRaisesRegex(bootstrap.github.ArtifactError, "main changed"):
            bootstrap._bootstrap(self.api, "create", None, self.guard)
        self.api.create.assert_not_called()

    def test_private_settings_and_ownership_fail_closed(self):
        mutations = [
            ("id", "c" * 32), ("created_on", "2026-11-07T00:00:00Z"), ("name", "other-worker"),
            ("updated_on", "2026-11-07T00:00:00Z"), ("updated_on", "2026-02-30T01:00:00Z"),
            ("tags", [bootstrap.OWNERSHIP_TAG, "different-owner"]), ("logpush", True),
            ("subdomain", {"enabled": False, "previews_enabled": True}),
            ("subdomain", {"enabled": True, "previews_enabled": False}),
            ("observability", {"enabled": True}), ("tail_consumers", [{"name": "other-worker"}]),
            ("references", {"domains": [{}]}), ("deployed_on", UPDATED),
            ("previews_base_config", {"logpush": True}),
        ]
        for key, value in mutations:
            with self.subTest(key=key, value=value):
                self.api.by_name.return_value = worker()
                self.api.by_id.return_value = {**worker(), key: value}
                with self.assertRaises(bootstrap.BootstrapError):
                    bootstrap._bootstrap(self.api, "verify", IDENTITY, self.guard)
                self.api.create.assert_not_called()
        unsafe = worker()
        unsafe["observability"]["logs"]["invocation_logs"] = True
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap._verify_profile(unsafe, IDENTITY)

    def test_disabled_real_readback_defaults_do_not_admit_a_enabled_log_stream(self):
        live = worker()
        live["observability"]["logs"].update(invocation_logs=True, persist=True)
        live["observability"]["traces"]["persist"] = True
        del live["previews_base_config"]["tail_consumers"]
        bootstrap._verify_profile(live, IDENTITY)
        for stream in ("logs", "traces"):
            with self.subTest(stream=stream):
                unsafe = deepcopy(live)
                unsafe["observability"][stream]["enabled"] = True
                with self.assertRaises(bootstrap.BootstrapError):
                    bootstrap._verify_profile(unsafe, IDENTITY)

    def test_final_name_readback_must_still_match_the_immutable_id(self):
        self.api.by_name.side_effect = [None, None, {**worker(), "id": "d" * 32}]
        with self.assertRaisesRegex(bootstrap.BootstrapError, "pinned identity"):
            bootstrap._bootstrap(self.api, "create", None, self.guard)
        self.api.create.assert_called_once()

    def test_pin_rejects_invalid_fields_and_duplicate_json(self):
        self.assertEqual(bootstrap._pin(json.dumps(PIN)), IDENTITY)
        for value in ('{"workerId":"x","workerId":"y"}', json.dumps({**PIN, "unexpected": True}),
                      json.dumps({**PIN, "workerId": f"../{WORKER_ID}"})):
            with self.subTest(value=value), self.assertRaises((bootstrap.BootstrapError, bootstrap.github.ArtifactError)):
                bootstrap._pin(value)

    def test_exact_main_and_artifact_are_verified_and_public_output_omits_identity(self):
        env = {
            "GITHUB_REPOSITORY": bootstrap.github.REPOSITORY, "GITHUB_REF": bootstrap.github.MAIN_REF,
            "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_SHA": "c" * 40,
            "SUBS_BOT_PROVIDER_CI_RUN_ID": "42", "RUNNER_TEMP": "/tmp/synthetic-runner",
            "SUBS_BOT_PROVIDER_WORKER_ACTION": "verify", bootstrap.IDENTITY_ENV: json.dumps(PIN),
        }
        evidence = {"revision": env["GITHUB_SHA"], "artifactId": "98"}
        with patch.dict(os.environ, env, clear=True), patch.object(
                bootstrap, "WorkerAPI", return_value=self.api), patch.object(
                bootstrap, "_verified_input", return_value=(None, evidence)) as artifact, patch.object(
                bootstrap, "_guard_main") as guard:
            self.api.by_name.return_value = worker()
            result = bootstrap.bootstrap()
            artifact.assert_called_once_with(Path(env["RUNNER_TEMP"]), env["GITHUB_SHA"], "42")
            self.assertEqual(guard.call_args_list, [call(evidence), call(evidence)])
        self.assertEqual(result["workerIdentitySha256"], sha256(f"{WORKER_ID}\n{CREATED}".encode()).hexdigest())
        self.assertEqual(result["status"], "verified")
        self.assertNotIn(WORKER_ID, json.dumps(result))
        self.assertNotIn(CREATED, json.dumps(result))
        with patch.dict(os.environ, {**env, "GITHUB_REF": "refs/heads/feature"}, clear=True), patch.object(
                bootstrap, "WorkerAPI") as cloud:
            with self.assertRaisesRegex(bootstrap.BootstrapError, "exact main revision"):
                bootstrap.bootstrap()
            cloud.assert_not_called()


if __name__ == "__main__":
    unittest.main()
