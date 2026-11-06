"""Cloudflare management release tests with a stateful, in-process API fake."""

import base64
from copy import deepcopy
from hashlib import sha256
from http.client import IncompleteRead
from io import BytesIO
import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import MagicMock, Mock, patch
from urllib.error import HTTPError

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import cloudflare_isolation as cloudflare


TARGET = {
    "accountId": "a" * 32,
    "workerId": "b" * 32,
    "workerCreatedOn": "2026-07-30T00:00:00.001Z",
    "d1Id": "00000000-0000-4000-8000-000000000001",
    "d1CreatedAt": "2026-07-30T00:00:00.002Z",
    "r2CreatedOn": "2026-07-30T00:00:00.003Z",
    "namespace": cloudflare.NAMESPACE,
}
OLD_REVISION = "c" * 40
NEW_REVISION = "d" * 40
COMPATIBILITY = "2026-07-30"
OLD_VERSION = "10000000-0000-4000-8000-000000000001"
NEW_VERSION = "10000000-0000-4000-8000-000000000002"
OLD_DEPLOYMENT = "20000000-0000-4000-8000-000000000001"
NEW_DEPLOYMENT = "20000000-0000-4000-8000-000000000002"
ROLLBACK_DEPLOYMENT = "20000000-0000-4000-8000-000000000003"
CONCURRENT_DEPLOYMENT = "20000000-0000-4000-8000-000000000004"
OLD_MODULE = b"export default { fetch() {} };"
NEW_MODULE = b"export default { async fetch() {} };"
ACCOUNT = f"/accounts/{TARGET['accountId']}"
SCRIPT = f"{ACCOUNT}/workers/scripts/{cloudflare.WORKER_NAME}"
WORKER = f"{ACCOUNT}/workers/workers/{TARGET['workerId']}"
VERSIONS = WORKER + "/versions"
DEPLOYMENTS = SCRIPT + "/deployments"
SCHEDULES = SCRIPT + "/schedules"
DATABASE = f"{ACCOUNT}/d1/database/{TARGET['d1Id']}"
BUCKET = f"{ACCOUNT}/r2/buckets/{cloudflare.WORKER_NAME}"
DOMAINS = f"{ACCOUNT}/workers/domains?service={cloudflare.WORKER_NAME}"
TELEGRAM_CONFIG = '{"fixture":"synthetic-only"}'
CRON = {"cron": cloudflare.TELEGRAM_CRON}


def deployment(deployment_id, version, message=None):
    return {
        "id": deployment_id,
        "strategy": "percentage",
        "versions": [{"version_id": version, "percentage": 100, "extra": "ignored"}],
        "annotations": {"workers/message": message},
    }


def version(version_id, revision, module):
    return {
        "id": version_id,
        "main_module": "index.js",
        "compatibility_date": COMPATIBILITY,
        "usage_model": "standard",
        "bindings": [
            {"type": "d1", "name": "DB", "database_id": TARGET["d1Id"]},
            {"type": "r2_bucket", "name": "NODES", "bucket_name": cloudflare.WORKER_NAME},
            {"type": "plain_text", "name": "BUILD_REVISION", "text": revision},
        ],
        "modules": [{
            "name": "index.js",
            "content_type": "application/javascript+module",
            "content_base64": base64.b64encode(module).decode("ascii"),
        }],
        "annotations": {"workers/tag": revision},
    }


class FakeCloudflare:
    def __init__(self):
        self.active = deployment(OLD_DEPLOYMENT, OLD_VERSION)
        self.versions = {OLD_VERSION: version(OLD_VERSION, OLD_REVISION, OLD_MODULE)}
        self.worker_responses = {
            WORKER: {
                "id": TARGET["workerId"],
                "name": cloudflare.WORKER_NAME,
                "created_on": TARGET["workerCreatedOn"],
                "subdomain": {"url": cloudflare.ORIGIN, "enabled": True, "previews_enabled": False},
                "observability": {"enabled": False, "logs": {"enabled": False, "invocation_logs": True},
                                  "traces": {"enabled": False, "destinations": []}},
                "logpush": False,
                "tail_consumers": [],
            },
            SCRIPT + "/settings": {"tags": ["subs-bot", "isolation-01"]},
            DOMAINS: [],
            SCHEDULES: {"schedules": []},
            ACCOUNT + "/workers/subdomain": {"subdomain": cloudflare.NAMESPACE},
        }
        self.data_responses = {
            DATABASE: {"uuid": TARGET["d1Id"], "name": cloudflare.WORKER_NAME, "created_at": TARGET["d1CreatedAt"]},
            BUCKET: {"name": cloudflare.WORKER_NAME, "creation_date": TARGET["r2CreatedOn"], "jurisdiction": "default"},
            BUCKET + "/domains/managed": {"enabled": False},
            BUCKET + "/domains/custom": [],
        }
        self.calls = []
        self.lose_upload = False
        self.lose_activation = False
        self.lose_activation_readback = False
        self.health_available = True
        self.activation_available = True
        self.concurrent_activation = False
        self.stale = False
        self.stale_after_upload = False
        self.concurrent_after_upload = False
        self.cron_available = True
        self.lose_cron_response = False
        self.health_verified_deployment = None
        self.telegram_upload = None
        self.alter_config_digest = False

    def worker_api(self, method, path, payload=None):
        self.calls.append((method, path))
        if method == "GET":
            if path == DEPLOYMENTS:
                if self.active["id"] == NEW_DEPLOYMENT and self.lose_activation_readback:
                    self.lose_activation_readback = False
                    raise cloudflare.CloudflareError("Readback connection failed.")
                return {"deployments": [deepcopy(self.active)]}
            if path == VERSIONS + "?page=1&per_page=100":
                return [{"id": row["id"], "annotations": deepcopy(row["annotations"])}
                        for row in self.versions.values()]
            if path.startswith(VERSIONS + "/") and path.endswith("?include=modules"):
                return deepcopy(self.versions[path.split("/")[-1].split("?")[0]])
            if path == SCRIPT + "/settings":
                # This endpoint changes on upload even while the old version serves traffic.
                return {**self.worker_responses[path], "bindings": self.versions[list(self.versions)[-1]]["bindings"]}
            return deepcopy(self.worker_responses[path])
        if method == "POST" and path == VERSIONS + "?deploy=false":
            assert payload["modules"][0]["content_base64"] == base64.b64encode(NEW_MODULE).decode("ascii")
            assert payload["bindings"][0]["database_id"] == TARGET["d1Id"]
            self.versions[NEW_VERSION] = {**deepcopy(payload), "id": NEW_VERSION}
            for row in self.versions[NEW_VERSION]["bindings"]:
                if row["name"] == cloudflare.TELEGRAM_CONFIG_BINDING:
                    self.telegram_upload = deepcopy(row)
                    row.pop("text")
                if row["name"] == cloudflare.TELEGRAM_DIGEST_BINDING and self.alter_config_digest:
                    row["text"] = "e" * 64
            if self.stale_after_upload:
                self.stale = True
            if self.concurrent_after_upload:
                self.active = deployment(CONCURRENT_DEPLOYMENT, OLD_VERSION)
            if self.lose_upload:
                raise cloudflare.CloudflareError("Upload connection failed.", uncertain=True)
            return {"id": NEW_VERSION}
        if method == "POST" and path == DEPLOYMENTS:
            assert payload["strategy"] == "percentage"
            assert len(payload["versions"]) == 1 and payload["versions"][0]["percentage"] == 100
            version_id = payload["versions"][0]["version_id"]
            deployment_id = NEW_DEPLOYMENT if version_id == NEW_VERSION else ROLLBACK_DEPLOYMENT
            if version_id == NEW_VERSION and not self.activation_available:
                raise cloudflare.CloudflareError("Activation connection failed.", uncertain=True)
            self.active = deployment(deployment_id, version_id, payload["annotations"]["workers/message"])
            if version_id == NEW_VERSION and self.lose_activation:
                raise cloudflare.CloudflareError("Activation connection failed.", uncertain=True)
            return deepcopy(self.active)
        if method == "PUT" and path == SCHEDULES:
            assert payload == [CRON]
            assert self.active["id"] == self.health_verified_deployment
            assert any(row["type"] == "secret_text"
                       for row in self.versions[self.active["versions"][0]["version_id"]]["bindings"])
            if not self.cron_available:
                raise cloudflare.CloudflareError("Cron setup rejected.")
            self.worker_responses[path] = {"schedules": [{**CRON, "created_on": "2026-07-30T00:00:00Z"}]}
            if self.lose_cron_response:
                raise cloudflare.CloudflareError("Cron connection failed.", uncertain=True)
            return deepcopy(self.worker_responses[path])
        raise AssertionError("Unexpected Worker operation.")

    def data_api(self, method, path, payload=None):
        if method != "GET" or payload is not None:
            raise AssertionError("Release attempted to write data.")
        return deepcopy(self.data_responses[path])

    def health(self):
        version_id = self.active["versions"][0]["version_id"]
        if version_id == NEW_VERSION and not self.health_available:
            if self.concurrent_activation:
                self.active = deployment(CONCURRENT_DEPLOYMENT, NEW_VERSION, "Another operator")
            return {"ok": False}
        revision = self.versions[version_id]["bindings"][2]["text"]
        self.health_verified_deployment = self.active["id"]
        return {"ok": True, "service": "subs-bot", "revision": revision}

    def guard(self):
        self.calls.append(("GUARD", "main"))
        return not self.stale

    def writes(self):
        return [path for method, path in self.calls if method in {"POST", "PUT"}]


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.bundle = Path(directory.name)
        (self.bundle / "index.js").write_bytes(NEW_MODULE)
        self.manifest = {"version": 2, "revision": NEW_REVISION, "bundleSha256": sha256(NEW_MODULE).hexdigest(),
                         "compatibilityDate": COMPATIBILITY, "migrations": []}
        self.api = FakeCloudflare()
        health = patch.object(cloudflare, "_read_health", side_effect=self.api.health)
        health.start()
        self.addCleanup(health.stop)
        sleeper = patch.object(cloudflare, "sleep")
        sleeper.start()
        self.addCleanup(sleeper.stop)

    def release(self, telegram_config=None):
        return cloudflare.release_worker(self.api.worker_api, self.api.data_api, TARGET, self.bundle,
                                         self.manifest, self.api.guard, telegram_config=telegram_config)

    def set_old_telegram_config(self, config=TELEGRAM_CONFIG):
        self.api.versions[OLD_VERSION]["bindings"].extend([
            {"type": "secret_text", "name": cloudflare.TELEGRAM_CONFIG_BINDING},
            {"type": "plain_text", "name": cloudflare.TELEGRAM_DIGEST_BINDING,
             "text": sha256(config.encode("utf-8")).hexdigest()},
        ])

    def test_read_only_preflight_rejects_wrong_resource_or_domain(self):
        self.assertEqual(cloudflare.verify_worker_target(self.api.worker_api, self.api.data_api, TARGET),
                         {"deploymentId": OLD_DEPLOYMENT, "versionId": OLD_VERSION, "revision": OLD_REVISION})
        for path, replacement in ((BUCKET + "/domains/managed", {"enabled": True}),
                                  (DATABASE, {"uuid": "wrong"}),
                                  (DOMAINS, [{"hostname": "unexpected.example"}]),
                                  (SCHEDULES, {"schedules": [{"cron": "0 0 * * *"}]})):
            container = self.api.worker_responses if path in (DOMAINS, SCHEDULES) else self.api.data_responses
            previous = container[path]
            with self.subTest(path=path):
                container[path] = replacement
                with self.assertRaises(cloudflare.CloudflareError):
                    self.release()
                container[path] = previous
        self.assertEqual(self.api.writes(), [])

    def test_upload_activate_and_same_revision_retry_are_idempotent(self):
        self.assertEqual(self.release(), {
            "revision": NEW_REVISION, "versionId": NEW_VERSION, "deploymentId": NEW_DEPLOYMENT,
            "previousVersionId": OLD_VERSION, "changed": True,
        })
        self.assertFalse(self.release()["changed"])
        self.assertEqual(self.api.writes(), [VERSIONS + "?deploy=false", DEPLOYMENTS])
        for index, (method, _) in enumerate(self.api.calls):
            if method == "POST":
                self.assertEqual(self.api.calls[index - 2:index], [("GET", DEPLOYMENTS), ("GUARD", "main")])

    def test_same_revision_with_wrong_bytes_is_rejected(self):
        self.api.versions[OLD_VERSION] = version(OLD_VERSION, NEW_REVISION, OLD_MODULE)
        with self.assertRaisesRegex(cloudflare.CloudflareError, "digest"):
            self.release()
        self.assertEqual(self.api.writes(), [])

    def test_verified_staged_version_is_reused(self):
        self.api.versions[NEW_VERSION] = version(NEW_VERSION, NEW_REVISION, NEW_MODULE)
        self.assertEqual(self.release()["versionId"], NEW_VERSION)
        self.assertEqual(self.api.writes(), [DEPLOYMENTS])

    def test_telegram_is_secret_bound_and_cron_is_set_after_healthy_activation(self):
        result = self.release(TELEGRAM_CONFIG)
        self.assertEqual(result["versionId"], NEW_VERSION)
        self.assertNotIn("synthetic-only", json.dumps(result))
        self.assertNotIn(sha256(TELEGRAM_CONFIG.encode("utf-8")).hexdigest(), json.dumps(result))
        self.assertEqual(self.api.telegram_upload, {
            "name": cloudflare.TELEGRAM_CONFIG_BINDING, "type": "secret_text", "text": TELEGRAM_CONFIG,
        })
        self.assertEqual(self.api.versions[NEW_VERSION]["bindings"][-1], {
            "name": cloudflare.TELEGRAM_DIGEST_BINDING, "type": "plain_text",
            "text": sha256(TELEGRAM_CONFIG.encode("utf-8")).hexdigest(),
        })
        self.assertFalse(self.release(TELEGRAM_CONFIG)["changed"])
        self.assertEqual(self.api.writes(), [VERSIONS + "?deploy=false", DEPLOYMENTS, SCHEDULES])
        cron_index = self.api.calls.index(("PUT", SCHEDULES))
        self.assertEqual(self.api.calls[cron_index - 2:cron_index], [("GET", DEPLOYMENTS), ("GUARD", "main")])

    def test_telegram_config_can_change_without_changing_the_git_revision(self):
        self.api.versions[OLD_VERSION] = version(OLD_VERSION, NEW_REVISION, NEW_MODULE)
        self.set_old_telegram_config('{"fixture":"old-synthetic-only"}')
        self.api.worker_responses[SCHEDULES] = {"schedules": [CRON]}
        self.assertTrue(self.release(TELEGRAM_CONFIG)["changed"])
        self.assertEqual(self.api.writes(), [VERSIONS + "?deploy=false", DEPLOYMENTS])

    def test_failed_cron_setup_can_be_retried_without_redeploying(self):
        self.api.cron_available = False
        with self.assertRaisesRegex(cloudflare.CloudflareError, "active.*rejected the Cron setup"):
            self.release(TELEGRAM_CONFIG)
        self.assertEqual(self.api.active["id"], NEW_DEPLOYMENT)
        self.assertEqual(self.api.worker_responses[SCHEDULES], {"schedules": []})
        self.api.cron_available = True
        self.assertTrue(self.release(TELEGRAM_CONFIG)["changed"])
        self.assertFalse(self.release(TELEGRAM_CONFIG)["changed"])
        self.assertEqual(self.api.writes(), [VERSIONS + "?deploy=false", DEPLOYMENTS, SCHEDULES, SCHEDULES])

    def test_lost_cron_response_is_reconciled_by_readback(self):
        self.api.lose_cron_response = True
        self.assertTrue(self.release(TELEGRAM_CONFIG)["changed"])
        self.assertFalse(self.release(TELEGRAM_CONFIG)["changed"])
        self.assertEqual(self.api.writes(), [VERSIONS + "?deploy=false", DEPLOYMENTS, SCHEDULES])

    def test_rollback_preserves_preexisting_cron_and_config(self):
        self.set_old_telegram_config()
        self.api.worker_responses[SCHEDULES] = {"schedules": [CRON]}
        self.api.health_available = False
        with self.assertRaisesRegex(cloudflare.CloudflareError, "prior version was restored"):
            self.release(TELEGRAM_CONFIG)
        self.assertEqual(self.api.active["versions"][0]["version_id"], OLD_VERSION)
        self.assertEqual(self.api.worker_responses[SCHEDULES], {"schedules": [CRON]})
        self.assertEqual(self.api.writes(), [VERSIONS + "?deploy=false", DEPLOYMENTS, DEPLOYMENTS])

    def test_omitting_config_cannot_remove_existing_telegram_bindings(self):
        self.set_old_telegram_config()
        with self.assertRaisesRegex(cloudflare.CloudflareError, "required to preserve"):
            self.release()
        self.assertEqual(self.api.writes(), [])

    def test_staged_config_digest_must_match_before_activation(self):
        self.api.alter_config_digest = True
        with self.assertRaisesRegex(cloudflare.CloudflareError, "differs from the verified artifact"):
            self.release(TELEGRAM_CONFIG)
        self.assertEqual(self.api.writes(), [VERSIONS + "?deploy=false"])

    def test_active_config_binding_must_be_secret_text(self):
        self.set_old_telegram_config()
        self.api.versions[OLD_VERSION]["bindings"][-2]["type"] = "plain_text"
        with self.assertRaisesRegex(cloudflare.CloudflareError, "Telegram binding mismatch"):
            self.release(TELEGRAM_CONFIG)
        self.assertEqual(self.api.writes(), [])

    def test_invalid_config_cannot_trigger_cloudflare_calls(self):
        for value in ("", "é" * 2501, 1):
            with self.subTest(value_type=type(value)), self.assertRaises(cloudflare.CloudflareError):
                self.release(value)
        self.assertEqual(self.api.calls, [])

    def test_ref_and_current_deployment_are_rechecked_before_activation(self):
        for attribute, message in (("stale_after_upload", "main revision changed"),
                                   ("concurrent_after_upload", "deployment changed before activation")):
            with self.subTest(attribute=attribute):
                self.api.active = deployment(OLD_DEPLOYMENT, OLD_VERSION)
                self.api.versions.pop(NEW_VERSION, None)
                self.api.calls.clear()
                self.api.stale = False
                setattr(self.api, attribute, True)
                with self.assertRaisesRegex(cloudflare.CloudflareError, message):
                    self.release()
                self.assertEqual(self.api.writes(), [VERSIONS + "?deploy=false"])
                setattr(self.api, attribute, False)

    def test_ambiguous_write_responses_are_reconciled_without_another_post(self):
        self.api.lose_upload = True
        self.api.lose_activation = True
        self.api.lose_activation_readback = True
        self.assertTrue(self.release()["changed"])
        self.assertEqual(self.api.writes(), [VERSIONS + "?deploy=false", DEPLOYMENTS])

    def test_unconfirmed_activation_does_not_retry_or_attempt_rollback(self):
        self.api.activation_available = False
        with self.assertRaisesRegex(cloudflare.CloudflareError, "activation could not be confirmed"):
            self.release()
        self.assertEqual(self.api.writes(), [VERSIONS + "?deploy=false", DEPLOYMENTS])
        self.assertEqual(self.api.active["id"], OLD_DEPLOYMENT)

    def test_health_failure_restores_verified_previous_version(self):
        self.api.health_available = False
        with self.assertRaisesRegex(cloudflare.CloudflareError, "prior version was restored"):
            self.release()
        self.assertEqual(self.api.writes(), [VERSIONS + "?deploy=false", DEPLOYMENTS, DEPLOYMENTS])
        self.assertEqual(self.api.active["id"], ROLLBACK_DEPLOYMENT)
        self.assertEqual(self.api.active["versions"][0]["version_id"], OLD_VERSION)

    def test_newer_deployment_prevents_rollback_even_with_same_version(self):
        self.api.health_available = False
        self.api.concurrent_activation = True
        with self.assertRaisesRegex(cloudflare.CloudflareError, "safe rollback could not be confirmed"):
            self.release()
        self.assertEqual(self.api.writes(), [VERSIONS + "?deploy=false", DEPLOYMENTS])
        self.assertEqual(self.api.active["id"], CONCURRENT_DEPLOYMENT)

    def test_bad_artifact_or_failed_guard_does_not_write(self):
        self.manifest["bundleSha256"] = "a" * 64
        with self.assertRaisesRegex(cloudflare.CloudflareError, "module digest mismatch"):
            self.release()
        self.assertEqual(self.api.calls, [])
        self.manifest["bundleSha256"] = sha256(NEW_MODULE).hexdigest()
        guard = Mock(side_effect=ValueError("sensitive upstream body"))
        with self.assertRaises(cloudflare.CloudflareError) as error:
            cloudflare.release_worker(self.api.worker_api, self.api.data_api, TARGET, self.bundle,
                                      self.manifest, guard)
        self.assertNotIn("sensitive", str(error.exception))
        self.assertEqual(self.api.writes(), [])


class ClientTests(unittest.TestCase):
    def test_client_blocks_host_overrides_and_redacts_http_errors(self):
        opener = Mock()
        opener.open.side_effect = HTTPError("https://example.invalid/secret", 403, "sensitive body", {},
                                            BytesIO(b"private response"))
        with patch.object(cloudflare, "build_opener", return_value=opener) as factory:
            client = cloudflare.CloudflareClient("synthetic-token")
        self.assertIsInstance(factory.call_args.args[1], cloudflare._NoRedirect)
        for path in ("https://example.invalid/", "//example.invalid/", "/ok#fragment", "/invalid\n",
                     "/../user", "/%2e%2e/user"):
            with self.subTest(path=path), self.assertRaises(cloudflare.CloudflareError):
                client("GET", path)
        opener.open.assert_not_called()
        with self.assertRaises(cloudflare.CloudflareError) as error:
            client("GET", "/accounts/test")
        self.assertEqual(str(error.exception), "Cloudflare API rejected the request (HTTP 403).")
        self.assertFalse(error.exception.uncertain)
        request = opener.open.call_args.args[0]
        self.assertEqual(request.full_url, cloudflare.API_ORIGIN + "/accounts/test")
        self.assertEqual(request.get_header("Authorization"), "Bearer synthetic-token")

    def test_truncated_post_is_ambiguous(self):
        opener = Mock()
        opener.open.side_effect = IncompleteRead(b"response prefix")
        with patch.object(cloudflare, "build_opener", return_value=opener):
            client = cloudflare.CloudflareClient("synthetic-token")
        with self.assertRaises(cloudflare.CloudflareError) as error:
            client("POST", "/accounts/test", {})
        self.assertTrue(error.exception.uncertain)
        self.assertNotIn("response prefix", str(error.exception))

    def test_client_put_is_limited_to_the_isolated_cron_path_and_body(self):
        opener = MagicMock()
        opener.open.return_value.__enter__.return_value.read.return_value = (
            b'{"success":true,"result":{"schedules":[]}}'
        )
        with patch.object(cloudflare, "build_opener", return_value=opener):
            client = cloudflare.CloudflareClient("synthetic-token")
        for path, payload in ((DEPLOYMENTS, [CRON]), (SCHEDULES + "?extra=1", [CRON]),
                              (SCHEDULES, []), (SCHEDULES, [{"cron": "0 0 * * *"}])):
            with self.subTest(path=path), self.assertRaises(cloudflare.CloudflareError):
                client("PUT", path, payload)
        opener.open.assert_not_called()
        self.assertEqual(client("PUT", SCHEDULES, [CRON]), {"schedules": []})
        request = opener.open.call_args.args[0]
        self.assertEqual(request.get_method(), "PUT")
        self.assertEqual(json.loads(request.data), [CRON])


if __name__ == "__main__":
    unittest.main()
