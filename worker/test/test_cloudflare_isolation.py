"""Cloudflare management release tests with a stateful, in-process API fake."""

import base64
from contextlib import closing
from copy import deepcopy
from hashlib import sha256
from http.client import IncompleteRead
from io import BytesIO
import json
import os
from pathlib import Path
import sqlite3
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import MagicMock, Mock, patch
from urllib.error import HTTPError

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import attest_api_status_container as attestation
import cloudflare_isolation as cloudflare
import release_isolation as release_entry


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
INLINE_BOT = "97001"
INLINE_CONFIG = json.dumps({"botId": INLINE_BOT, "fixture": "synthetic-only"})
INLINE_BINDING = {"name": cloudflare.INLINE_SEARCH_BINDING, "type": "plain_text", "text": "1"}
INLINE_MIGRATION = {"name": cloudflare.INLINE_SEARCH_MIGRATION, "sha256": cloudflare.INLINE_SEARCH_MIGRATION_SHA256}
PROVIDER_URL_BINDING = {"name": cloudflare.PROVIDER_URL_IMPORT_BINDING, "type": "plain_text", "text": "1"}
PROVIDER_REFRESH_BINDING = {"name": cloudflare.PROVIDER_REFRESH_BINDING, "type": "plain_text", "text": "1"}
PROVIDER_BATCH_BINDING = {"name": cloudflare.PROVIDER_BATCH_BINDING, "type": "plain_text", "text": "1"}
LEGACY_SHORT_BINDING = {"name": cloudflare.LEGACY_SUBSCRIPTION_SHORT_BINDING, "type": "plain_text", "text": "1"}
LEGACY_SHORT_MIGRATION = {"name": cloudflare.LEGACY_SUBSCRIPTION_SHORT_MIGRATION,
                          "sha256": cloudflare.LEGACY_SUBSCRIPTION_SHORT_SHA256}
AGGREGATE_KEY = base64.urlsafe_b64encode(b"\x17" * 32).decode("ascii").rstrip("=")
PRIVATE_SHARE_KEY = base64.urlsafe_b64encode(b"\x18" * 32).decode("ascii").rstrip("=")
CRON = {"cron": cloudflare.TELEGRAM_CRON}
PROVIDER_BINDING = cloudflare.ProviderBinding(NEW_REVISION, "a" * 64, "b" * 64)
API_STATUS_PIN = cloudflare.ProviderApiStatusBinding(OLD_REVISION, "e" * 64, "f" * 64)


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
        self.aggregate_upload = None
        self.private_share_upload = None
        self.alter_config_digest = False
        self.candidate_readback_errors = []
        self.upload_error = None
        self.inline_checks = []
        self.inline_consents = 0
        self.inline_ledger_drift = set()
        self.provider_url_checks = []
        self.provider_url_ledger_drift = set()
        self.provider_refresh_checks = []
        self.provider_refresh_ledger_drift = {}
        self.provider_batch_ledger_drift = False
        self.provider_batch_schema_drift = False
        self.provider_batch_drain_reads = 0
        self.provider_batch_live_reads = set()
        self.api_status_ledger_drift = False
        self.api_status_schema_drift = False
        self.api_status_drain_reads = 0
        self.api_status_live_reads = set()
        self.legacy_short_checks = []
        self.legacy_short_ledger_drift = {}

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
                version_id = path.split("/")[-1].split("?")[0]
                if version_id == NEW_VERSION and self.candidate_readback_errors:
                    status = self.candidate_readback_errors.pop(0)
                    raise cloudflare.CloudflareError("Synthetic version readback error.", http_status=status)
                return deepcopy(self.versions[version_id])
            if path == SCRIPT + "/settings":
                # This endpoint changes on upload even while the old version serves traffic.
                return {**self.worker_responses[path], "bindings": self.versions[list(self.versions)[-1]]["bindings"]}
            return deepcopy(self.worker_responses[path])
        if method == "POST" and path == VERSIONS + "?deploy=false":
            if self.upload_error:
                raise cloudflare.CloudflareError("Synthetic upload error.", http_status=self.upload_error)
            assert payload["modules"][0]["content_base64"] == base64.b64encode(NEW_MODULE).decode("ascii")
            assert payload["bindings"][0]["database_id"] == TARGET["d1Id"]
            self.versions[NEW_VERSION] = {**deepcopy(payload), "id": NEW_VERSION}
            for row in self.versions[NEW_VERSION]["bindings"]:
                if row["name"] == cloudflare.TELEGRAM_CONFIG_BINDING:
                    self.telegram_upload = deepcopy(row)
                    row.pop("text")
                if row["name"] == cloudflare.AGGREGATE_KEY_BINDING:
                    self.aggregate_upload = deepcopy(row)
                    row.pop("text")
                if row["name"] == cloudflare.PRIVATE_SHARE_KEY_BINDING:
                    self.private_share_upload = deepcopy(row)
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
        if method == "POST" and path == DATABASE + "/query":
            sql = payload["sql"]
            if "AS apiStatusActive" in sql:
                self.api_status_drain_reads += 1
                return [{"success": True, "results": [
                    {"apiStatusActive": int(self.api_status_drain_reads in self.api_status_live_reads)}]}]
            if "WHERE position=34" in sql:
                digest = "0" * 64 if self.api_status_ledger_drift else cloudflare.API_STATUS_MIGRATION_SHA256
                return [{"success": True, "results": [{"position": 34, "name": cloudflare.API_STATUS_MIGRATION,
                                                       "sha256": digest, "mode": "applied"}]}]
            if "tbl_name='telegram_api_status'" in sql:
                path = Path(__file__).resolve().parents[1] / "migrations" / cloudflare.API_STATUS_MIGRATION
                body = path.read_bytes()
                assert sha256(body).hexdigest() == cloudflare.API_STATUS_MIGRATION_SHA256
                with closing(sqlite3.connect(":memory:")) as db:
                    db.row_factory = sqlite3.Row
                    db.executescript(body.decode("utf-8"))
                    if self.api_status_schema_drift:
                        db.execute("DROP INDEX telegram_api_status_expiry")
                    return [{"success": True, "results": [dict(row) for row in db.execute(sql)]}]
            if "AS batchActive" in sql:
                self.provider_batch_drain_reads += 1
                return [{"success": True, "results": [
                    {"batchActive": int(self.provider_batch_drain_reads in self.provider_batch_live_reads)}]}]
            if "WHERE position IN (21,23,31,32)" in sql:
                rows = [{"position": position, "name": name, "sha256": digest, "mode": "applied"}
                        for position, name, digest in cloudflare.PROVIDER_BATCH_MIGRATIONS]
                if self.provider_batch_ledger_drift:
                    rows[-1]["sha256"] = "0" * 64
                return [{"success": True, "results": rows}]
            if "name GLOB 'telegram_provider_batch*'" in sql:
                directory = Path(__file__).resolve().parents[1] / "migrations"
                with closing(sqlite3.connect(":memory:")) as db:
                    db.row_factory = sqlite3.Row
                    db.execute("CREATE TABLE telegram_inbox (receipt_id INTEGER PRIMARY KEY, bot_id TEXT, actor_id TEXT, "
                               "message_date INTEGER, message_id INTEGER, receipt_nonce TEXT)")
                    for _, name, digest in cloudflare.PROVIDER_BATCH_MIGRATIONS[-2:]:
                        body = (directory / name).read_bytes()
                        assert sha256(body).hexdigest() == digest
                        db.executescript(body.decode("utf-8"))
                    if self.provider_batch_schema_drift:
                        db.execute("DROP INDEX telegram_provider_batch_tickets_expiry")
                    return [{"success": True, "results": [dict(row) for row in db.execute(sql)]}]
            if "AS primaryIndex" in payload["sql"]:
                assert set(payload) == {"sql"} and payload["sql"].strip().startswith("SELECT ")
                self.legacy_short_checks.append(self.active["versions"][0]["version_id"])
                migration = Path(__file__).resolve().parents[1] / "migrations" / LEGACY_SHORT_MIGRATION["name"]
                body = migration.read_bytes()
                assert sha256(body).hexdigest() == LEGACY_SHORT_MIGRATION["sha256"]
                with closing(sqlite3.connect(":memory:")) as db:
                    db.row_factory = sqlite3.Row
                    db.executescript(body.decode("utf-8"))
                    db.execute("CREATE TABLE subs_bot_schema_migrations (position INTEGER PRIMARY KEY, name TEXT, sha256 TEXT, mode TEXT)")
                    db.execute("INSERT INTO subs_bot_schema_migrations VALUES (29,?,?,'applied')",
                               (LEGACY_SHORT_MIGRATION["name"], LEGACY_SHORT_MIGRATION["sha256"]))
                    row = dict(db.execute(payload["sql"]).fetchone())
                row.update(self.legacy_short_ledger_drift.get(len(self.legacy_short_checks), {}))
                return [{"success": True, "results": [row]}]
            if "AS refreshIndex" in payload["sql"]:
                assert set(payload) == {"sql"} and payload["sql"].strip().startswith("SELECT ")
                self.provider_refresh_checks.append(self.active["versions"][0]["version_id"])
                rows = [{"position": position, "name": name, "sha256": digest, "mode": "applied",
                         "refreshTables": 5, "refreshIndex": 1} for position, name, digest in cloudflare.PROVIDER_REFRESH_MIGRATIONS]
                rows[-1].update(self.provider_refresh_ledger_drift.get(len(self.provider_refresh_checks), {}))
                return [{"success": True, "results": rows}]
            if payload["sql"].strip().startswith("SELECT position, name, sha256, mode,"):
                assert set(payload) == {"sql"}
                self.provider_url_checks.append(self.active["versions"][0]["version_id"])
                rows = [{"position": position, "name": name, "sha256": digest, "mode": "applied", "queueTables": 3}
                        for position, name, digest in cloudflare.PROVIDER_URL_IMPORT_MIGRATIONS]
                if len(self.provider_url_checks) in self.provider_url_ledger_drift:
                    rows[-1]["queueTables"] = 2
                return [{"success": True, "results": rows}]
            assert payload["sql"].strip().startswith("SELECT name, sha256, mode,")
            fresh, bot_id = payload["params"]
            assert fresh in ("0", "1") and bot_id == INLINE_BOT
            self.inline_checks.append((self.active["versions"][0]["version_id"], fresh))
            row = {**INLINE_MIGRATION, "mode": "applied", "activeConsent": self.inline_consents if fresh == "1" else 0}
            if len(self.inline_checks) in self.inline_ledger_drift:
                row["sha256"] = "0" * 64
            return [{"success": True, "results": [row]}]
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

    def release(self, telegram_config=None, aggregate_key=None, private_share_key=None, **options):
        return cloudflare.release_worker(self.api.worker_api, self.api.data_api, TARGET, self.bundle,
                                         self.manifest, self.api.guard, telegram_config=telegram_config,
                                         aggregate_key=aggregate_key, private_share_key=private_share_key, **options)

    def set_old_telegram_config(self, config=TELEGRAM_CONFIG):
        self.api.versions[OLD_VERSION]["bindings"].extend([
            {"type": "secret_text", "name": cloudflare.TELEGRAM_CONFIG_BINDING},
            {"type": "plain_text", "name": cloudflare.TELEGRAM_DIGEST_BINDING,
             "text": sha256(config.encode("utf-8")).hexdigest()},
        ])

    def set_inline_baseline(self):
        self.manifest["migrations"] = [{"name": f"{position:04d}_fixture.sql", "sha256": "a" * 64}
                                       for position in range(1, 25)] + [INLINE_MIGRATION.copy()]
        self.api.versions[OLD_VERSION] = version(OLD_VERSION, NEW_REVISION, NEW_MODULE)
        self.set_old_telegram_config(INLINE_CONFIG)
        self.api.worker_responses[SCHEDULES] = {"schedules": [CRON]}
        return self.api.versions[OLD_VERSION]

    def set_provider_url_baseline(self, *, enabled=False, same_artifact=True, inline=False):
        off = self.set_inline_baseline()
        for position, name, digest in cloudflare.PROVIDER_URL_IMPORT_MIGRATIONS:
            self.manifest["migrations"][position - 1] = {"name": name, "sha256": digest}
        if not same_artifact:
            off["bindings"][2]["text"] = OLD_REVISION
            off["modules"][0]["content_base64"] = base64.b64encode(OLD_MODULE).decode("ascii")
        tag = cloudflare._release_tag(off["bindings"][2]["text"], sha256(INLINE_CONFIG.encode()).hexdigest(),
                                     None, None, PROVIDER_BINDING)
        off["annotations"] = {"workers/tag": cloudflare._telegram_feature_tag(tag, inline, enabled),
                              "workers/message": cloudflare.PROVIDER_MESSAGE + PROVIDER_BINDING.identity_sha256}
        off["bindings"].extend([
            {"type": "service", "name": "PROVIDER_FETCH", "service": cloudflare.PROVIDER_SERVICE,
             "entrypoint": cloudflare.PROVIDER_ENTRYPOINT},
            {"type": "plain_text", "name": "PROVIDER_REVISION", "text": PROVIDER_BINDING.revision},
            {"type": "plain_text", "name": "PROVIDER_IMAGE_SHA256", "text": PROVIDER_BINDING.image_sha256},
        ])
        if inline:
            off["bindings"].append(INLINE_BINDING)
        if enabled:
            off["bindings"].append(PROVIDER_URL_BINDING)
        return off

    def set_provider_refresh_baseline(self, *, enabled=False, url=False, same_artifact=True, inline=False):
        active = self.set_provider_url_baseline(enabled=url, same_artifact=same_artifact, inline=inline)
        self.manifest["migrations"].extend({"name": f"{position:04d}_fixture.sql", "sha256": "a" * 64}
                                          for position in range(26, 29))
        for position, name, digest in cloudflare.PROVIDER_REFRESH_MIGRATIONS:
            self.manifest["migrations"][position - 1] = {"name": name, "sha256": digest}
        if enabled:
            active["bindings"].append(PROVIDER_REFRESH_BINDING)
            active["annotations"]["workers/tag"] = cloudflare._telegram_feature_tag(
                active["annotations"]["workers/tag"], False, False, True)
        return active

    def set_provider_batch_baseline(self, *, capable=True, enabled=False, same_artifact=True):
        active = self.set_provider_refresh_baseline(enabled=True, url=True, same_artifact=same_artifact, inline=True)
        self.manifest["migrations"].extend({"name": f"{position:04d}_fixture.sql", "sha256": "a" * 64}
                                          for position in range(29, 33))
        for position, name, digest in cloudflare.PROVIDER_BATCH_MIGRATIONS:
            self.manifest["migrations"][position - 1] = {"name": name, "sha256": digest}
        tag = active["annotations"]["workers/tag"]
        digest = sha256(NEW_MODULE if same_artifact else OLD_MODULE).hexdigest()
        active["annotations"]["workers/tag"] = cloudflare._telegram_feature_tag(
            tag, False, False, provider_batch=enabled, batch_module_sha256=digest if capable else None)
        if enabled:
            active["bindings"].append(PROVIDER_BATCH_BINDING)
        return active

    def set_api_status_baseline(self, *, same_artifact=True):
        active = self.set_provider_batch_baseline(enabled=True, same_artifact=same_artifact)
        self.manifest["migrations"].extend([
            {"name": "0033_fixture.sql", "sha256": "a" * 64},
            {"name": cloudflare.API_STATUS_MIGRATION, "sha256": cloudflare.API_STATUS_MIGRATION_SHA256},
        ])
        return active

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
            "previousVersionId": OLD_VERSION, "changed": True, "inlineSearchEnabled": False,
            "providerUrlImportEnabled": False, "providerRefreshEnabled": False, "legacySubscriptionShortsEnabled": False,
            "providerBatchEnabled": False, "apiStatusEnabled": False,
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

    def test_same_artifact_inline_flag_changes_preserve_provider_and_keys(self):
        off = self.set_inline_baseline()
        _, previous = cloudflare._artifact(self.bundle, self.manifest, INLINE_CONFIG, AGGREGATE_KEY, PRIVATE_SHARE_KEY, PROVIDER_BINDING)
        off["annotations"] = {"workers/tag": previous.tag,
                              "workers/message": cloudflare.PROVIDER_MESSAGE + PROVIDER_BINDING.identity_sha256}
        off["bindings"].extend([
            {"type": "secret_text", "name": cloudflare.AGGREGATE_KEY_BINDING},
            {"type": "plain_text", "name": cloudflare.AGGREGATE_DIGEST_BINDING, "text": previous.telegram_aggregate_key_sha256},
            {"type": "secret_text", "name": cloudflare.PRIVATE_SHARE_KEY_BINDING},
            {"type": "plain_text", "name": cloudflare.PRIVATE_SHARE_DIGEST_BINDING, "text": previous.telegram_private_share_key_sha256},
            {"type": "service", "name": "PROVIDER_FETCH", "service": cloudflare.PROVIDER_SERVICE, "entrypoint": cloudflare.PROVIDER_ENTRYPOINT},
            {"type": "plain_text", "name": "PROVIDER_REVISION", "text": PROVIDER_BINDING.revision},
            {"type": "plain_text", "name": "PROVIDER_IMAGE_SHA256", "text": PROVIDER_BINDING.image_sha256},
        ])
        proof = Mock(side_effect=cloudflare.CloudflareError("Synthetic unavailable activation proof."))
        options = {"provider_binding": PROVIDER_BINDING, "provider_guard": Mock(), "provider_first_binding_guard": proof}
        enabled = self.release(INLINE_CONFIG, AGGREGATE_KEY, PRIVATE_SHARE_KEY, inline_search=True, **options)
        self.assertTrue(enabled["changed"])
        self.assertTrue(enabled["inlineSearchEnabled"])
        self.assertEqual(enabled["previousVersionId"], OLD_VERSION)
        on = self.api.versions[NEW_VERSION]
        self.assertNotEqual(on["annotations"]["workers/tag"], previous.tag)
        self.assertEqual({row["name"]: row for row in on["bindings"]},
                         {row["name"]: row for row in [*off["bindings"], INLINE_BINDING]})
        self.assertEqual(self.api.inline_checks, [(OLD_VERSION, "1"), (OLD_VERSION, "1"), (NEW_VERSION, "0")])

        self.api.inline_consents = 1
        repeated = self.release(INLINE_CONFIG, AGGREGATE_KEY, PRIVATE_SHARE_KEY, **options)
        self.assertFalse(repeated["changed"])
        self.assertTrue(repeated["inlineSearchEnabled"])
        disabled = self.release(INLINE_CONFIG, AGGREGATE_KEY, PRIVATE_SHARE_KEY, inline_search=False, **options)
        self.assertTrue(disabled["changed"])
        self.assertFalse(disabled["inlineSearchEnabled"])
        self.assertEqual(disabled["versionId"], OLD_VERSION)
        self.assertEqual(self.api.writes(), [VERSIONS + "?deploy=false", DEPLOYMENTS, DEPLOYMENTS])
        with self.assertRaisesRegex(cloudflare.CloudflareError, "consent must end"):
            self.release(INLINE_CONFIG, AGGREGATE_KEY, PRIVATE_SHARE_KEY, inline_search=True, **options)
        self.assertEqual(self.api.active["versions"][0]["version_id"], OLD_VERSION)
        proof.assert_not_called()

    def test_inline_binding_is_exact_and_requires_existing_telegram_config(self):
        self.api.versions[OLD_VERSION]["bindings"].append(INLINE_BINDING)
        with self.assertRaisesRegex(cloudflare.CloudflareError, "inline search binding"):
            cloudflare.verify_worker_target(self.api.worker_api, self.api.data_api, TARGET)
        self.set_old_telegram_config(INLINE_CONFIG)
        rows = self.api.versions[OLD_VERSION]["bindings"]
        for malformed in ({**INLINE_BINDING, "text": "0"}, {**INLINE_BINDING, "type": "secret_text"},
                          {**INLINE_BINDING, "text": True}, {**INLINE_BINDING, "extra": "fixture"}):
            with self.subTest(malformed=malformed), self.assertRaisesRegex(cloudflare.CloudflareError, "inline search binding"):
                rows[3] = malformed
                cloudflare.verify_worker_target(self.api.worker_api, self.api.data_api, TARGET)
        rows[3] = INLINE_BINDING
        with self.assertRaisesRegex(cloudflare.CloudflareError, "inline search release tag"):
            cloudflare.verify_worker_target(self.api.worker_api, self.api.data_api, TARGET)
        tag = cloudflare._release_tag(OLD_REVISION, sha256(INLINE_CONFIG.encode()).hexdigest(), None, None, None)
        self.api.versions[OLD_VERSION]["annotations"]["workers/tag"] = cloudflare._inline_search_tag(tag)
        self.assertEqual(cloudflare.verify_worker_target(self.api.worker_api, self.api.data_api, TARGET)["versionId"], OLD_VERSION)
        self.assertEqual(self.api.inline_checks, [])
        self.assertEqual(self.api.writes(), [])

    def test_inline_enable_requires_exact_off_artifact_and_migration(self):
        active = self.set_inline_baseline()
        active["bindings"][2]["text"] = OLD_REVISION
        with self.assertRaisesRegex(cloudflare.CloudflareError, "same Worker artifact"):
            self.release(INLINE_CONFIG, inline_search=True)
        active["bindings"][2]["text"] = NEW_REVISION
        self.manifest["migrations"][24]["sha256"] = "0" * 64
        with self.assertRaisesRegex(cloudflare.CloudflareError, "exact 0025 migration artifact"):
            self.release(INLINE_CONFIG, inline_search=True)
        self.manifest["migrations"][24] = INLINE_MIGRATION
        with self.assertRaisesRegex(cloudflare.CloudflareError, "separate scoped release"):
            self.release(INLINE_CONFIG + " ", inline_search=True)
        with self.assertRaisesRegex(cloudflare.CloudflareError, "same keys and provider binding"):
            self.release(INLINE_CONFIG, AGGREGATE_KEY, inline_search=True)
        self.api.worker_responses[SCHEDULES] = {"schedules": []}
        with self.assertRaisesRegex(cloudflare.CloudflareError, "existing Cron"):
            self.release(INLINE_CONFIG, inline_search=True)
        self.assertEqual(self.api.writes(), [])

    def test_inline_activation_verifies_post_release_ledger_and_rolls_back_to_off(self):
        self.set_inline_baseline()
        self.api.inline_ledger_drift = {3}
        with self.assertRaisesRegex(cloudflare.CloudflareError, "prior version was restored"):
            self.release(INLINE_CONFIG, inline_search=True)
        self.assertEqual(self.api.inline_checks, [(OLD_VERSION, "1"), (OLD_VERSION, "1"), (NEW_VERSION, "0")])
        self.assertEqual(self.api.active["versions"][0]["version_id"], OLD_VERSION)
        self.assertNotIn(INLINE_BINDING, self.api.versions[OLD_VERSION]["bindings"])
        self.assertEqual(self.api.writes(), [VERSIONS + "?deploy=false", DEPLOYMENTS, DEPLOYMENTS])

    def test_protected_inline_entry_checks_ledger_before_migrations(self):
        self.set_inline_baseline()
        directory = self.bundle / "subs-bot-verified"
        directory.mkdir()
        (directory / "isolation.json").write_text(json.dumps(self.manifest), encoding="utf-8")
        environment = {"GITHUB_SHA": NEW_REVISION, "GITHUB_REPOSITORY": "jacklilyhello/subs-bot",
            "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REF": "refs/heads/main", "RUNNER_TEMP": str(self.bundle),
            "SUBS_BOT_CF_ISOLATION_TARGET_JSON": json.dumps(TARGET), "SUBS_BOT_CF_BOOTSTRAP_TOKEN": "synthetic-data",
            "SUBS_BOT_CF_DEPLOY_TOKEN": "synthetic-deploy", "SUBS_BOT_INLINE_SEARCH_MODE": "enable",
            "SUBS_BOT_INLINE_SEARCH_CONFIRMATION": f"enable inline search for {cloudflare.WORKER_NAME}"}
        self.api.inline_ledger_drift = {1}
        with patch.dict(os.environ, environment, clear=True), \
             patch.object(release_entry, "telegram_release_config", return_value=INLINE_CONFIG), \
             patch.object(release_entry, "CloudflareClient", side_effect=[self.api.data_api, self.api.worker_api]), \
             patch.object(release_entry, "require_current_main"), patch.object(release_entry, "apply_migrations") as migrate:
            with self.assertRaisesRegex(cloudflare.CloudflareError, "migration could not be verified"):
                release_entry.release()
            migrate.assert_not_called()
        self.assertEqual(self.api.inline_checks, [(OLD_VERSION, "1")])
        self.assertEqual(self.api.writes(), [])

    def test_inline_operator_modes_require_literal_isolation_confirmation(self):
        for mode, confirmation, desired in (("preserve", "", None),
                                            ("enable", f"enable inline search for {cloudflare.WORKER_NAME}", True),
                                            ("disable", f"disable inline search for {cloudflare.WORKER_NAME}", False)):
            with self.subTest(mode=mode), patch.dict(os.environ, {
                    "SUBS_BOT_INLINE_SEARCH_MODE": mode, "SUBS_BOT_INLINE_SEARCH_CONFIRMATION": confirmation}, clear=True):
                self.assertIs(release_entry.inline_search_release_mode(), desired)
        for mode, confirmation in (("enable", ""), ("disable", "enable inline search for subs-bot-cf-dev-01"),
                                   ("preserve", "unused"), ("enabled", "")):
            with self.subTest(mode=mode), patch.dict(os.environ, {
                    "SUBS_BOT_INLINE_SEARCH_MODE": mode, "SUBS_BOT_INLINE_SEARCH_CONFIRMATION": confirmation}, clear=True), \
                 self.assertRaisesRegex(cloudflare.CloudflareError, "mode or confirmation"):
                release_entry.inline_search_release_mode()

    def test_provider_url_toggle_keeps_same_provider_and_inline_setting(self):
        off = self.set_provider_url_baseline(inline=True)
        proof = Mock(side_effect=cloudflare.CloudflareError("Synthetic expired activation proof."))
        guard = Mock()
        options = {"provider_binding": PROVIDER_BINDING, "provider_guard": guard, "provider_first_binding_guard": proof}
        self.assertFalse(self.release(INLINE_CONFIG, **options)["providerUrlImportEnabled"])
        self.assertEqual(self.api.writes(), [])
        self.assertEqual(self.api.provider_url_checks, [])

        enabled = self.release(INLINE_CONFIG, provider_url_import=True, **options)
        self.assertTrue(enabled["changed"])
        self.assertTrue(enabled["providerUrlImportEnabled"])
        self.assertTrue(enabled["inlineSearchEnabled"])
        self.assertEqual(enabled["previousVersionId"], OLD_VERSION)
        on = self.api.versions[NEW_VERSION]
        self.assertNotEqual(on["annotations"]["workers/tag"], off["annotations"]["workers/tag"])
        self.assertEqual({row["name"]: row for row in on["bindings"]},
                         {row["name"]: row for row in [*off["bindings"], PROVIDER_URL_BINDING]})
        self.assertEqual(self.api.provider_url_checks, [OLD_VERSION, OLD_VERSION, NEW_VERSION])
        self.assertFalse(self.release(INLINE_CONFIG, **options)["changed"])

        disabled = self.release(INLINE_CONFIG, provider_url_import=False, **options)
        self.assertTrue(disabled["changed"])
        self.assertFalse(disabled["providerUrlImportEnabled"])
        self.assertTrue(disabled["inlineSearchEnabled"])
        self.assertEqual(disabled["versionId"], OLD_VERSION)
        self.assertEqual(self.api.writes(), [VERSIONS + "?deploy=false", DEPLOYMENTS, DEPLOYMENTS])
        proof.assert_not_called()
        self.assertGreaterEqual(guard.call_count, 6)

    def test_new_revision_preserves_enabled_provider_url_import(self):
        self.set_provider_url_baseline(enabled=True, same_artifact=False)
        guard = Mock()
        proof = Mock(side_effect=cloudflare.CloudflareError("Synthetic expired activation proof."))
        released = self.release(INLINE_CONFIG, provider_binding=PROVIDER_BINDING, provider_guard=guard,
                                provider_first_binding_guard=proof)
        self.assertTrue(released["changed"])
        self.assertTrue(released["providerUrlImportEnabled"])
        self.assertIn(PROVIDER_URL_BINDING, self.api.versions[NEW_VERSION]["bindings"])
        self.assertEqual(self.api.provider_url_checks, [OLD_VERSION, OLD_VERSION, NEW_VERSION])
        self.assertEqual(guard.call_count, 3)
        proof.assert_not_called()

    def test_provider_url_enable_requires_off_artifact_bound_provider_and_exact_migrations(self):
        self.set_provider_url_baseline(same_artifact=False)
        options = {"provider_binding": PROVIDER_BINDING, "provider_guard": Mock(), "provider_url_import": True}
        with self.assertRaisesRegex(cloudflare.CloudflareError, "same Worker artifact"):
            self.release(INLINE_CONFIG, **options)
        self.set_provider_url_baseline()
        self.manifest["migrations"][22]["sha256"] = "0" * 64
        with self.assertRaisesRegex(cloudflare.CloudflareError, "exact 0021 and 0023 migration artifacts"):
            self.release(INLINE_CONFIG, **options)
        self.set_inline_baseline()
        proof = Mock()
        with self.assertRaisesRegex(cloudflare.CloudflareError, "same active provider"):
            self.release(INLINE_CONFIG, provider_first_binding_guard=proof, **options)
        proof.assert_not_called()
        self.set_provider_url_baseline()
        self.api.worker_responses[SCHEDULES] = {"schedules": []}
        with self.assertRaisesRegex(cloudflare.CloudflareError, "same active provider"):
            self.release(INLINE_CONFIG, **options)
        self.assertEqual(self.api.writes(), [])

    def test_provider_url_preflight_and_activation_recheck_live_schema(self):
        self.set_provider_url_baseline()
        self.api.provider_url_ledger_drift = {1, 4}
        with self.assertRaisesRegex(cloudflare.CloudflareError, "provider URL migrations could not be verified"):
            cloudflare.verify_worker_target(self.api.worker_api, self.api.data_api, TARGET,
                telegram_config=INLINE_CONFIG, provider_binding=PROVIDER_BINDING, release_manifest=self.manifest,
                provider_url_import=True)
        self.assertEqual(self.api.writes(), [])
        with self.assertRaisesRegex(cloudflare.CloudflareError, "prior version was restored"):
            self.release(INLINE_CONFIG, provider_binding=PROVIDER_BINDING, provider_guard=Mock(), provider_url_import=True)
        self.assertEqual(self.api.provider_url_checks, [OLD_VERSION, OLD_VERSION, OLD_VERSION, NEW_VERSION])
        self.assertEqual(self.api.active["versions"][0]["version_id"], OLD_VERSION)
        self.assertNotIn(PROVIDER_URL_BINDING, self.api.versions[OLD_VERSION]["bindings"])
        self.assertEqual(self.api.writes(), [VERSIONS + "?deploy=false", DEPLOYMENTS, DEPLOYMENTS])

    def test_provider_url_binding_readback_rejects_noncanonical_value_or_absence(self):
        active = self.set_provider_url_baseline(enabled=True)
        active["bindings"][-1] = {**PROVIDER_URL_BINDING, "text": "0"}
        with self.assertRaisesRegex(cloudflare.CloudflareError, "provider URL import binding"):
            cloudflare.verify_worker_target(self.api.worker_api, self.api.data_api, TARGET)
        active["bindings"].pop()
        with self.assertRaisesRegex(cloudflare.CloudflareError, "provider URL import release tag"):
            cloudflare.verify_worker_target(self.api.worker_api, self.api.data_api, TARGET)
        self.assertEqual(self.api.writes(), [])

    def test_provider_url_operator_modes_require_literal_isolation_confirmation(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(release_entry.provider_url_import_release_mode())
        for mode, desired in (("enable", True), ("disable", False)):
            confirmation = f"{mode} provider URL import for {cloudflare.WORKER_NAME}"
            with self.subTest(mode=mode), patch.dict(os.environ, {
                    "SUBS_BOT_PROVIDER_URL_IMPORT_MODE": mode, "SUBS_BOT_PROVIDER_URL_IMPORT_CONFIRMATION": confirmation}, clear=True):
                self.assertIs(release_entry.provider_url_import_release_mode(), desired)
        for mode, confirmation in (("enable", ""), ("disable", "enable provider URL import for subs-bot-cf-dev-01"),
                                   ("preserve", "unused"), ("enabled", "")):
            with self.subTest(mode=mode), patch.dict(os.environ, {
                    "SUBS_BOT_PROVIDER_URL_IMPORT_MODE": mode, "SUBS_BOT_PROVIDER_URL_IMPORT_CONFIRMATION": confirmation}, clear=True), \
                 self.assertRaisesRegex(cloudflare.CloudflareError, "mode or confirmation"):
                release_entry.provider_url_import_release_mode()

    def test_refresh_toggle_preserves_provider_and_other_flags(self):
        off = self.set_provider_refresh_baseline(url=True, inline=True)
        options = {"provider_binding": PROVIDER_BINDING, "provider_guard": Mock(),
                   "provider_first_binding_guard": Mock(side_effect=AssertionError("Provider already bound."))}
        self.assertFalse(self.release(INLINE_CONFIG, **options)["providerRefreshEnabled"])
        self.assertEqual(self.api.provider_refresh_checks, [])
        self.assertEqual(self.api.writes(), [])

        enabled = self.release(INLINE_CONFIG, provider_refresh=True, **options)
        self.assertTrue(enabled["providerRefreshEnabled"])
        self.assertTrue(enabled["providerUrlImportEnabled"])
        self.assertTrue(enabled["inlineSearchEnabled"])
        on = self.api.versions[NEW_VERSION]
        self.assertNotEqual(on["annotations"]["workers/tag"], off["annotations"]["workers/tag"])
        self.assertEqual({row["name"]: row for row in on["bindings"]},
                         {row["name"]: row for row in [*off["bindings"], PROVIDER_REFRESH_BINDING]})
        self.assertEqual(self.api.provider_refresh_checks, [OLD_VERSION, OLD_VERSION, NEW_VERSION])
        self.assertFalse(self.release(INLINE_CONFIG, **options)["changed"])

        disabled = self.release(INLINE_CONFIG, provider_refresh=False, **options)
        self.assertFalse(disabled["providerRefreshEnabled"])
        self.assertTrue(disabled["providerUrlImportEnabled"])
        self.assertTrue(disabled["inlineSearchEnabled"])
        self.assertEqual(disabled["versionId"], OLD_VERSION)
        self.assertEqual(self.api.writes(), [VERSIONS + "?deploy=false", DEPLOYMENTS, DEPLOYMENTS])

    def test_new_revision_preserves_refresh_independently_of_url_import(self):
        self.set_provider_refresh_baseline(enabled=True, same_artifact=False)
        result = self.release(INLINE_CONFIG, provider_binding=PROVIDER_BINDING, provider_guard=Mock())
        self.assertTrue(result["changed"])
        self.assertTrue(result["providerRefreshEnabled"])
        self.assertFalse(result["providerUrlImportEnabled"])
        self.assertIn(PROVIDER_REFRESH_BINDING, self.api.versions[NEW_VERSION]["bindings"])
        self.assertEqual(self.api.provider_refresh_checks, [OLD_VERSION, OLD_VERSION, NEW_VERSION])
        self.assertEqual(self.api.provider_url_checks, [])

    def test_refresh_enable_requires_existing_provider_cron_artifact_and_migrations(self):
        options = {"provider_binding": PROVIDER_BINDING, "provider_guard": Mock(), "provider_refresh": True}
        self.set_provider_refresh_baseline(same_artifact=False)
        with self.assertRaisesRegex(cloudflare.CloudflareError, "same Worker artifact"):
            self.release(INLINE_CONFIG, **options)
        self.set_provider_refresh_baseline()
        self.manifest["migrations"][27]["sha256"] = "0" * 64
        with self.assertRaisesRegex(cloudflare.CloudflareError, "exact 0018, 0021, 0023 and 0028"):
            self.release(INLINE_CONFIG, **options)
        self.set_inline_baseline()
        proof = Mock()
        with self.assertRaisesRegex(cloudflare.CloudflareError, "same active provider"):
            self.release(INLINE_CONFIG, provider_first_binding_guard=proof, **options)
        proof.assert_not_called()
        self.set_provider_refresh_baseline()
        different = cloudflare.ProviderBinding(OLD_REVISION, PROVIDER_BINDING.image_sha256,
                                                PROVIDER_BINDING.identity_sha256)
        with self.assertRaisesRegex(cloudflare.CloudflareError, "separate rotation release"):
            self.release(INLINE_CONFIG, **{**options, "provider_binding": different})
        self.api.worker_responses[SCHEDULES] = {"schedules": []}
        with self.assertRaisesRegex(cloudflare.CloudflareError, "same active provider"):
            self.release(INLINE_CONFIG, **options)
        self.assertEqual(self.api.writes(), [])

    def test_refresh_schema_is_checked_before_migrations_activation_and_after_activation(self):
        self.set_provider_refresh_baseline()
        self.api.provider_refresh_ledger_drift = {1: {"sha256": "0" * 64}, 3: {"refreshIndex": 0}, 6: {"refreshTables": 4}}
        options = {"provider_binding": PROVIDER_BINDING, "provider_refresh": True}
        with self.assertRaisesRegex(cloudflare.CloudflareError, "provider refresh migrations could not be verified"):
            cloudflare.verify_worker_target(self.api.worker_api, self.api.data_api, TARGET,
                                           telegram_config=INLINE_CONFIG, release_manifest=self.manifest, **options)
        self.assertEqual(self.api.writes(), [])
        with self.assertRaisesRegex(cloudflare.CloudflareError, "provider refresh migrations could not be verified"):
            self.release(INLINE_CONFIG, provider_guard=Mock(), **options)
        self.assertEqual(self.api.writes(), [VERSIONS + "?deploy=false"])
        self.assertEqual(self.api.active["versions"][0]["version_id"], OLD_VERSION)
        with self.assertRaisesRegex(cloudflare.CloudflareError, "prior version was restored"):
            self.release(INLINE_CONFIG, provider_guard=Mock(), **options)
        self.assertEqual(self.api.provider_refresh_checks, [OLD_VERSION] * 5 + [NEW_VERSION])
        self.assertEqual(self.api.active["versions"][0]["version_id"], OLD_VERSION)
        self.assertNotIn(PROVIDER_REFRESH_BINDING, self.api.versions[OLD_VERSION]["bindings"])
        self.assertEqual(self.api.writes(), [VERSIONS + "?deploy=false", DEPLOYMENTS, DEPLOYMENTS])

    def test_refresh_binding_readback_rejects_wrong_value_missing_flag_and_other_flag_drift(self):
        active = self.set_provider_refresh_baseline(enabled=True, url=True)
        active["bindings"][-1] = {**PROVIDER_REFRESH_BINDING, "text": "0"}
        with self.assertRaisesRegex(cloudflare.CloudflareError, "provider refresh binding"):
            cloudflare.verify_worker_target(self.api.worker_api, self.api.data_api, TARGET)
        active["bindings"].pop()
        with self.assertRaisesRegex(cloudflare.CloudflareError, "provider refresh release tag"):
            cloudflare.verify_worker_target(self.api.worker_api, self.api.data_api, TARGET)
        active["bindings"].remove(PROVIDER_URL_BINDING)
        active["bindings"].append(PROVIDER_REFRESH_BINDING)
        with self.assertRaisesRegex(cloudflare.CloudflareError, "provider refresh release tag"):
            cloudflare.verify_worker_target(self.api.worker_api, self.api.data_api, TARGET)
        self.assertEqual(self.api.writes(), [])

    def test_refresh_operator_modes_require_literal_isolation_confirmation(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(release_entry.provider_refresh_release_mode())
        for mode, desired in (("enable", True), ("disable", False)):
            with self.subTest(mode=mode), patch.dict(os.environ, {
                    "SUBS_BOT_PROVIDER_REFRESH_MODE": mode,
                    "SUBS_BOT_PROVIDER_REFRESH_CONFIRMATION": f"{mode} provider refresh for {cloudflare.WORKER_NAME}"}, clear=True):
                self.assertIs(release_entry.provider_refresh_release_mode(), desired)
        for mode, confirmation in (("enable", ""), ("disable", "enable provider refresh for subs-bot-cf-dev-01"),
                                   ("preserve", "unused"), ("enabled", "")):
            with self.subTest(mode=mode), patch.dict(os.environ, {
                    "SUBS_BOT_PROVIDER_REFRESH_MODE": mode, "SUBS_BOT_PROVIDER_REFRESH_CONFIRMATION": confirmation}, clear=True), \
                 self.assertRaisesRegex(cloudflare.CloudflareError, "mode or confirmation"):
                release_entry.provider_refresh_release_mode()

    def test_batch_enable_requires_the_exact_verified_off_artifact_and_preserves_other_flags(self):
        options = {"provider_binding": PROVIDER_BINDING, "provider_guard": Mock(), "provider_batch": True}
        self.set_provider_batch_baseline(capable=False)
        with self.assertRaisesRegex(cloudflare.CloudflareError, "same Worker artifact"):
            self.release(INLINE_CONFIG, **options)
        self.set_provider_batch_baseline(same_artifact=False)
        with self.assertRaisesRegex(cloudflare.CloudflareError, "same Worker artifact"):
            self.release(INLINE_CONFIG, **options)
        off = self.set_provider_batch_baseline()
        self.assertEqual(self.api.writes(), [])
        enabled = self.release(INLINE_CONFIG, **options)
        for key in ("providerBatchEnabled", "providerRefreshEnabled", "providerUrlImportEnabled", "inlineSearchEnabled"):
            self.assertTrue(enabled[key])
        on = self.api.versions[NEW_VERSION]
        self.assertEqual({row["name"]: row for row in on["bindings"]},
                         {row["name"]: row for row in [*off["bindings"], PROVIDER_BATCH_BINDING]})
        disabled = self.release(INLINE_CONFIG, **{**options, "provider_batch": False})
        self.assertFalse(disabled["providerBatchEnabled"])
        self.assertEqual(disabled["versionId"], OLD_VERSION)
        self.assertEqual(self.api.provider_batch_drain_reads, 0)

    def test_batch_release_refuses_ledger_schema_and_unproven_rollback_drift(self):
        options = {"provider_binding": PROVIDER_BINDING, "provider_guard": Mock()}
        self.set_provider_batch_baseline(capable=False, same_artifact=False)
        for drift in ("provider_batch_ledger_drift", "provider_batch_schema_drift"):
            setattr(self.api, drift, True)
            with self.assertRaisesRegex(cloudflare.CloudflareError, "schema or ledger"):
                self.release(INLINE_CONFIG, **options)
            setattr(self.api, drift, False)
        self.assertEqual(self.api.writes(), [])
        # The readback saw active work after activation and still sees it before rollback.
        self.api.provider_batch_live_reads = {3, 4}
        with self.assertRaisesRegex(cloudflare.CloudflareError, "safe rollback could not be confirmed"):
            self.release(INLINE_CONFIG, **options)
        self.assertEqual(self.api.writes(), [VERSIONS + "?deploy=false", DEPLOYMENTS])
        self.assertEqual(self.api.active["versions"][0]["version_id"], NEW_VERSION)

    def test_batch_preflight_checks_active_module_and_exact_ledger_before_migration(self):
        active = self.set_provider_batch_baseline(enabled=True)
        readback = lambda: cloudflare.verify_worker_target(self.api.worker_api, self.api.data_api, TARGET,
            release_manifest=self.manifest, telegram_config=INLINE_CONFIG, provider_binding=PROVIDER_BINDING)
        self.api.provider_batch_ledger_drift = True
        with self.assertRaisesRegex(cloudflare.CloudflareError, "schema or ledger"):
            readback()
        self.api.provider_batch_ledger_drift = False
        active["modules"][0]["content_base64"] = base64.b64encode(OLD_MODULE).decode("ascii")
        with self.assertRaisesRegex(cloudflare.CloudflareError, "provider batch release tag"):
            readback()
        self.assertEqual(self.api.writes(), [])

    def test_batch_rollback_to_proven_drain_runtime_is_allowed_while_work_exists(self):
        self.set_provider_batch_baseline(enabled=False, same_artifact=False)
        self.api.health_available = False
        self.api.provider_batch_live_reads = {1, 2, 3, 4}
        with self.assertRaisesRegex(cloudflare.CloudflareError, "prior version was restored"):
            self.release(INLINE_CONFIG, provider_binding=PROVIDER_BINDING, provider_guard=Mock())
        self.assertEqual(self.api.active["versions"][0]["version_id"], OLD_VERSION)
        self.assertEqual(self.api.provider_batch_drain_reads, 0)

    def test_batch_operator_mode_is_default_off_and_requires_literal_isolation_confirmation(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(release_entry.provider_batch_release_mode())
        for mode, enabled in (("enable", True), ("disable", False)):
            with patch.dict(os.environ, {"SUBS_BOT_PROVIDER_BATCH_MODE": mode}, clear=True):
                with self.assertRaisesRegex(cloudflare.CloudflareError, "mode or confirmation"):
                    release_entry.provider_batch_release_mode()
                os.environ["SUBS_BOT_PROVIDER_BATCH_CONFIRMATION"] = f"{mode} provider batch for {cloudflare.WORKER_NAME}"
                self.assertIs(release_entry.provider_batch_release_mode(), enabled)

    def test_api_status_enable_preserve_and_disable_keep_v1_and_the_other_flags(self):
        off = self.set_api_status_baseline()
        gate = Mock(binding=API_STATUS_PIN)
        load = Mock(return_value=gate)
        options = {"provider_binding": PROVIDER_BINDING, "provider_guard": Mock(), "api_status_gate": load}
        self.assertFalse(self.release(INLINE_CONFIG, **options)["apiStatusEnabled"])
        self.assertFalse(attestation.inspect_required(self.api.worker_api, TARGET))
        load.assert_not_called()
        self.assertTrue(self.release(INLINE_CONFIG, api_status=True, **options)["apiStatusEnabled"])
        self.assertTrue(attestation.inspect_required(self.api.worker_api, TARGET))
        on = self.api.versions[NEW_VERSION]
        names = {row["name"] for row in on["bindings"]}
        self.assertEqual(names - {row["name"] for row in off["bindings"]},
                         cloudflare.PROVIDER_API_STATUS_BINDINGS | {cloudflare.API_STATUS_BINDING})
        self.assertEqual(on["annotations"]["workers/message"], off["annotations"]["workers/message"])
        self.assertTrue(on["annotations"]["workers/tag"].startswith(cloudflare.PROVIDER_BATCH_TAG_PREFIX))
        gate.verify_first_binding.assert_called_once_with(NEW_REVISION)
        self.assertEqual(gate.verify.call_count, 3)
        self.assertFalse(self.release(INLINE_CONFIG, **options)["changed"])
        gate.verify_first_binding.assert_called_once_with(NEW_REVISION)
        gate.binding = cloudflare.ProviderApiStatusBinding(NEW_REVISION, API_STATUS_PIN.image_sha256, "c" * 64)
        with self.assertRaisesRegex(cloudflare.CloudflareError, "separate release"):
            self.release(INLINE_CONFIG, **options)
        self.assertEqual(self.api.active["versions"][0]["version_id"], NEW_VERSION)
        load.reset_mock(side_effect=True)
        load.side_effect = AssertionError("Disabled releases must not load the V2 proof.")
        # The fake has one candidate ID. Rotate its stored enabled record to a fresh synthetic ID before the second upload.
        active_id = "10000000-0000-4000-8000-000000000009"
        self.api.versions[active_id] = {**self.api.versions.pop(NEW_VERSION), "id": active_id}
        self.api.active["versions"][0]["version_id"] = active_id
        self.assertFalse(self.release(INLINE_CONFIG, api_status=False, **options)["apiStatusEnabled"])
        self.assertFalse(attestation.inspect_required(self.api.worker_api, TARGET))
        disabled_names = {row["name"] for row in self.api.versions[NEW_VERSION]["bindings"]}
        self.assertEqual(disabled_names, names - {cloudflare.API_STATUS_BINDING})
        load.assert_not_called()

    def test_api_status_container_attestation_reads_only_exact_application_and_checks_private_settings(self):
        account = TARGET["accountId"]
        account_digest = sha256(account.encode("ascii")).hexdigest()
        namespace = "c" * 32
        created = "2026-07-30T00:00:00.001Z"
        expected = {"applicationId": namespace, "createdAt": created}
        active = {"namespaceId": namespace}
        response = {"id": namespace, "account_id": account, "name": cloudflare.PROVIDER_API_STATUS_SERVICE,
                    "scheduling_policy": "durable_object", "durable_objects": {"namespace_id": namespace},
                    "created_at": created, "observability": {"logs": {"enabled": False}},
                    "configuration": {"authorized_keys": [], "wrangler_ssh": {"enabled": False}}}
        api = Mock(return_value=response)
        with patch.object(attestation.publication, "TARGET_ACCOUNT_SHA256", account_digest):
            actual = attestation.observe_container(api, account, active, expected)
            api.assert_called_once_with("GET", f"{ACCOUNT}/containers/applications/{namespace}")
            self.assertEqual(actual, attestation.activation._fingerprint(expected))
            for drift in ({"observability": {"logs": {"enabled": True}}},
                          {"configuration": {"authorized_keys": ["synthetic"], "wrangler_ssh": {"enabled": False}}},
                          {"configuration": {"authorized_keys": [], "wrangler_ssh": {"enabled": True}}},
                          {"created_at": "2026-07-30T00:00:00.002Z"},
                          {"name": cloudflare.PROVIDER_SERVICE}):
                with self.subTest(drift=drift), self.assertRaisesRegex(cloudflare.CloudflareError, "Container privacy"):
                    api.return_value = {**response, **drift}
                    attestation.observe_container(api, account, active, expected)
            api.reset_mock()
            with self.assertRaisesRegex(cloudflare.CloudflareError, "Container privacy"):
                attestation.observe_container(api, account, active, {**expected, "applicationId": "d" * 32})
            api.assert_not_called()

    def test_api_status_attestation_is_bound_to_the_current_job_and_sealed_v3_identity(self):
        account = attestation.publication.TARGET_ACCOUNT_SHA256
        container = "e" * 64
        now = 1_800_000_000
        context = (NEW_REVISION, "123", "1")
        proof = {"version": 1, "revision": NEW_REVISION, "runId": "123", "runAttempt": "1", "observedAt": now,
                 "accountSha256": account, "containerIdentitySha256": container}
        attestation.verify_attestation(json.dumps(proof), context, account, container, now)
        for drift in ({"runId": "124"}, {"runAttempt": "2"}, {"revision": OLD_REVISION},
                      {"observedAt": now - attestation.ATTESTATION_MAX_AGE - 1}, {"observedAt": now + 1},
                      {"accountSha256": "a" * 64}, {"containerIdentitySha256": "f" * 64}):
            with self.subTest(drift=drift), self.assertRaisesRegex(cloudflare.CloudflareError, "Container privacy"):
                attestation.verify_attestation(json.dumps({**proof, **drift}), context, account, container, now)
        with self.assertRaisesRegex(cloudflare.CloudflareError, "Container privacy"):
            attestation.verify_attestation("", context, account, container, now)

    def test_api_status_preflight_rejects_unverified_artifact_ledger_and_live_identity(self):
        gate = Mock(binding=API_STATUS_PIN)
        options = {"release_manifest": self.manifest, "release_revision": NEW_REVISION,
                   "telegram_config": INLINE_CONFIG, "provider_binding": PROVIDER_BINDING,
                   "api_status": True, "api_status_gate": lambda: gate}
        preflight = lambda: cloudflare.verify_worker_target(self.api.worker_api, self.api.data_api, TARGET, **options)
        self.set_api_status_baseline(same_artifact=False)
        with self.assertRaisesRegex(cloudflare.CloudflareError, "same Worker artifact"):
            preflight()
        self.set_api_status_baseline()
        for drift in ("api_status_ledger_drift", "api_status_schema_drift"):
            setattr(self.api, drift, True)
            with self.assertRaisesRegex(cloudflare.CloudflareError, "schema or ledger"):
                preflight()
            setattr(self.api, drift, False)
        gate.verify_first_binding.assert_not_called()
        gate.verify.side_effect = cloudflare.CloudflareError("Synthetic dependency identity changed.")
        with self.assertRaisesRegex(cloudflare.CloudflareError, "dependency identity changed"):
            preflight()
        gate.verify_first_binding.assert_called_once_with(NEW_REVISION)
        self.assertEqual(self.api.writes(), [])

    def test_api_status_rollback_refuses_old_runtime_when_recovery_work_is_active(self):
        self.set_api_status_baseline(same_artifact=False)
        self.api.api_status_live_reads = {3, 4}
        with self.assertRaisesRegex(cloudflare.CloudflareError, "safe rollback could not be confirmed"):
            self.release(INLINE_CONFIG, provider_binding=PROVIDER_BINDING, provider_guard=Mock())
        self.assertEqual(self.api.writes(), [VERSIONS + "?deploy=false", DEPLOYMENTS])
        self.assertEqual(self.api.active["versions"][0]["version_id"], NEW_VERSION)

    def test_api_status_operator_requires_literal_isolation_confirmation(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(release_entry.api_status_release_mode())
        for mode, expected in (("enable", True), ("disable", False)):
            with patch.dict(os.environ, {"SUBS_BOT_API_STATUS_MODE": mode}, clear=True):
                with self.assertRaisesRegex(cloudflare.CloudflareError, "mode or confirmation"):
                    release_entry.api_status_release_mode()
                os.environ["SUBS_BOT_API_STATUS_CONFIRMATION"] = f"{mode} API status for {cloudflare.WORKER_NAME}"
                self.assertIs(release_entry.api_status_release_mode(), expected)

    def test_legacy_short_toggle_preserves_existing_provider_and_telegram_flags(self):
        off = self.set_provider_refresh_baseline(enabled=True, url=True, inline=True)
        self.manifest["migrations"].append(LEGACY_SHORT_MIGRATION.copy())
        options = {"provider_binding": PROVIDER_BINDING, "provider_guard": Mock()}
        self.assertFalse(self.release(INLINE_CONFIG, **options)["legacySubscriptionShortsEnabled"])
        self.assertEqual(self.api.legacy_short_checks, [])
        self.assertEqual(self.api.writes(), [])

        enabled = self.release(INLINE_CONFIG, legacy_subscription_shorts=True, **options)
        self.assertTrue(enabled["legacySubscriptionShortsEnabled"])
        self.assertTrue(all(enabled[key] for key in ("inlineSearchEnabled", "providerUrlImportEnabled", "providerRefreshEnabled")))
        on = self.api.versions[NEW_VERSION]
        self.assertNotEqual(on["annotations"]["workers/tag"], off["annotations"]["workers/tag"])
        self.assertEqual({row["name"]: row for row in on["bindings"]},
                         {row["name"]: row for row in [*off["bindings"], LEGACY_SHORT_BINDING]})
        self.assertEqual(self.api.legacy_short_checks, [OLD_VERSION, OLD_VERSION, NEW_VERSION])
        self.assertFalse(self.release(INLINE_CONFIG, **options)["changed"])

        disabled = self.release(INLINE_CONFIG, legacy_subscription_shorts=False, **options)
        self.assertFalse(disabled["legacySubscriptionShortsEnabled"])
        self.assertTrue(all(disabled[key] for key in ("inlineSearchEnabled", "providerUrlImportEnabled", "providerRefreshEnabled")))
        self.assertEqual(disabled["versionId"], OLD_VERSION)
        self.assertEqual(self.api.writes(), [VERSIONS + "?deploy=false", DEPLOYMENTS, DEPLOYMENTS])

    def test_legacy_short_enable_requires_off_artifact_and_exact_migration(self):
        self.manifest["migrations"] = [{"name": f"{position:04d}_fixture.sql", "sha256": "a" * 64}
                                       for position in range(1, 29)] + [LEGACY_SHORT_MIGRATION.copy()]
        with self.assertRaisesRegex(cloudflare.CloudflareError, "same Worker artifact"):
            self.release(legacy_subscription_shorts=True)
        self.api.versions[OLD_VERSION] = version(OLD_VERSION, NEW_REVISION, NEW_MODULE)
        self.manifest["migrations"][28]["sha256"] = "0" * 64
        with self.assertRaisesRegex(cloudflare.CloudflareError, "exact 0029 migration artifact"):
            self.release(legacy_subscription_shorts=True)
        self.assertEqual(self.api.writes(), [])

    def test_legacy_short_schema_drift_fails_before_writes_and_rolls_back_first_enable(self):
        self.api.versions[OLD_VERSION] = version(OLD_VERSION, NEW_REVISION, NEW_MODULE)
        self.manifest["migrations"] = [{"name": f"{position:04d}_fixture.sql", "sha256": "a" * 64}
                                       for position in range(1, 29)] + [LEGACY_SHORT_MIGRATION.copy()]
        self.api.legacy_short_ledger_drift = {1: {"sha256": "0" * 64}, 2: {"tableSql": "invalid"}, 5: {"primaryIndex": 0}}
        for _ in range(2):
            with self.assertRaisesRegex(cloudflare.CloudflareError, "short-link schema could not be verified"):
                cloudflare.verify_worker_target(self.api.worker_api, self.api.data_api, TARGET,
                    release_manifest=self.manifest, legacy_subscription_shorts=True)
        self.assertEqual(self.api.writes(), [])
        with self.assertRaisesRegex(cloudflare.CloudflareError, "prior version was restored"):
            self.release(legacy_subscription_shorts=True)
        self.assertEqual(self.api.legacy_short_checks, [OLD_VERSION] * 4 + [NEW_VERSION])
        self.assertEqual(self.api.active["versions"][0]["version_id"], OLD_VERSION)
        self.assertEqual(self.api.writes(), [VERSIONS + "?deploy=false", DEPLOYMENTS, DEPLOYMENTS])

    def test_legacy_short_binding_readback_and_operator_confirmation_are_exact(self):
        active = self.api.versions[OLD_VERSION]
        active["annotations"]["workers/tag"] = cloudflare._telegram_feature_tag(OLD_REVISION, False, False, False, True)
        active["bindings"].append({**LEGACY_SHORT_BINDING, "text": "0"})
        with self.assertRaisesRegex(cloudflare.CloudflareError, "short-link binding"):
            cloudflare.verify_worker_target(self.api.worker_api, self.api.data_api, TARGET)
        active["bindings"].pop()
        with self.assertRaisesRegex(cloudflare.CloudflareError, "short-link release tag"):
            cloudflare.verify_worker_target(self.api.worker_api, self.api.data_api, TARGET)
        self.assertEqual(self.api.writes(), [])
        with patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(release_entry.legacy_subscription_shorts_release_mode())
        for mode, desired in (("enable", True), ("disable", False)):
            with self.subTest(mode=mode), patch.dict(os.environ, {
                    "SUBS_BOT_LEGACY_SUBSCRIPTION_SHORTS_MODE": mode,
                    "SUBS_BOT_LEGACY_SUBSCRIPTION_SHORTS_CONFIRMATION": f"{mode} legacy subscription shorts for {cloudflare.WORKER_NAME}"}, clear=True):
                self.assertIs(release_entry.legacy_subscription_shorts_release_mode(), desired)
        with patch.dict(os.environ, {"SUBS_BOT_LEGACY_SUBSCRIPTION_SHORTS_MODE": "enable"}, clear=True), \
             self.assertRaisesRegex(cloudflare.CloudflareError, "mode or confirmation"):
            release_entry.legacy_subscription_shorts_release_mode()

    def test_inline_consent_read_is_exact_bot_order_and_expiry(self):
        db = sqlite3.connect(":memory:")
        self.addCleanup(db.close)
        db.row_factory = sqlite3.Row
        db.executescript("""
            CREATE TABLE subs_bot_schema_migrations(position INTEGER PRIMARY KEY,name TEXT,sha256 TEXT,mode TEXT);
            CREATE TABLE telegram_inline_search_consent(receipt_id INTEGER PRIMARY KEY,bot_id TEXT,actor_id TEXT,
              kind TEXT,message_date INTEGER,update_id INTEGER,expires_at INTEGER);
        """)
        db.execute("INSERT INTO subs_bot_schema_migrations VALUES (25, ?, ?, 'applied')",
                   (INLINE_MIGRATION["name"], INLINE_MIGRATION["sha256"]))
        db.executemany("INSERT INTO telegram_inline_search_consent VALUES (?, ?, ?, ?, ?, ?, unixepoch() + ?)", [
            (1, INLINE_BOT, "97002", "on", 1, 1, 100), (2, INLINE_BOT, "97002", "off", 1, 2, 0),
            (3, INLINE_BOT, "97003", "on", 1, 3, -1), (4, "97009", "97002", "on", 1, 4, 100),
        ])

        def select(method, path, payload):
            self.assertEqual((method, path), ("POST", DATABASE + "/query"))
            return [{"success": True, "results": [dict(row) for row in db.execute(payload["sql"], payload["params"])]}]

        scope = cloudflare._Isolation(self.api.worker_api, select, TARGET)
        scope.verify_inline_search(INLINE_BOT, require_fresh=True)
        db.execute("DELETE FROM telegram_inline_search_consent WHERE receipt_id=2")
        with self.assertRaisesRegex(cloudflare.CloudflareError, "consent must end"):
            scope.verify_inline_search(INLINE_BOT, require_fresh=True)
        scope.verify_inline_search(INLINE_BOT)

    def test_verified_staged_version_is_reused(self):
        self.api.versions[NEW_VERSION] = version(NEW_VERSION, NEW_REVISION, NEW_MODULE)
        self.assertEqual(self.release()["versionId"], NEW_VERSION)
        self.assertEqual(self.api.writes(), [DEPLOYMENTS])

    def test_recently_uploaded_version_is_read_back_without_duplicate_upload(self):
        self.api.candidate_readback_errors = [404, 404]
        self.assertEqual(self.release()["versionId"], NEW_VERSION)
        self.assertEqual(self.api.writes(), [VERSIONS + "?deploy=false", DEPLOYMENTS])
        self.assertEqual(self.api.calls.count(("GET", f"{VERSIONS}/{NEW_VERSION}?include=modules")), 4)

    def test_recently_listed_version_is_read_back_without_upload(self):
        self.api.versions[NEW_VERSION] = version(NEW_VERSION, NEW_REVISION, NEW_MODULE)
        self.api.candidate_readback_errors = [404]
        self.assertEqual(self.release()["versionId"], NEW_VERSION)
        self.assertEqual(self.api.writes(), [DEPLOYMENTS])

    def test_unreadable_candidate_stops_before_activation(self):
        self.api.candidate_readback_errors = [404] * len(cloudflare.READBACK_DELAYS)
        with self.assertRaisesRegex(cloudflare.CloudflareError, "candidate.*HTTP 404"):
            self.release()
        self.assertEqual(self.api.writes(), [VERSIONS + "?deploy=false"])
        self.assertEqual(self.api.active["id"], OLD_DEPLOYMENT)
        self.assertEqual(self.release()["versionId"], NEW_VERSION)
        self.assertEqual(self.api.writes(), [VERSIONS + "?deploy=false", DEPLOYMENTS])

    def test_candidate_permission_error_and_upload_404_fail_without_retry(self):
        self.api.candidate_readback_errors = [403, 404]
        with self.assertRaisesRegex(cloudflare.CloudflareError, "Synthetic version readback error"):
            self.release()
        self.assertEqual(self.api.candidate_readback_errors, [404])
        self.assertEqual(self.api.writes(), [VERSIONS + "?deploy=false"])
        del self.api.versions[NEW_VERSION]
        self.api.calls.clear()
        self.api.upload_error = 404
        with self.assertRaisesRegex(cloudflare.CloudflareError, r"upload was rejected \(HTTP 404\)"):
            self.release()
        self.assertEqual(self.api.writes(), [VERSIONS + "?deploy=false"])

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

    def test_ordinary_release_preserves_existing_telegram_configuration(self):
        self.api.versions[OLD_VERSION] = version(OLD_VERSION, NEW_REVISION, NEW_MODULE)
        self.set_old_telegram_config()
        self.api.worker_responses[SCHEDULES] = {"schedules": [CRON]}
        self.assertEqual(cloudflare.verify_worker_target(self.api.worker_api, self.api.data_api, TARGET)["versionId"], OLD_VERSION)
        for config in ('{"fixture":"different-synthetic-policy"}', None):
            with self.subTest(configured=config is not None):
                with self.assertRaisesRegex(cloudflare.CloudflareError, "separate scoped release"):
                    cloudflare.verify_worker_target(self.api.worker_api, self.api.data_api, TARGET, telegram_config=config)
                with self.assertRaisesRegex(cloudflare.CloudflareError, "separate scoped release"):
                    self.release(config)
        self.assertEqual(cloudflare.verify_worker_target(self.api.worker_api, self.api.data_api, TARGET,
                                                         telegram_config=TELEGRAM_CONFIG)["versionId"], OLD_VERSION)
        self.assertFalse(self.release(TELEGRAM_CONFIG)["changed"])
        self.assertEqual(self.api.writes(), [])

    def test_aggregate_key_is_private_idempotent_and_requires_explicit_rotation(self):
        result = self.release(TELEGRAM_CONFIG, AGGREGATE_KEY)
        self.assertTrue(result["changed"])
        self.assertEqual(self.api.aggregate_upload, {"name": cloudflare.AGGREGATE_KEY_BINDING, "type": "secret_text",
                                                   "text": AGGREGATE_KEY})
        self.assertNotIn(AGGREGATE_KEY, json.dumps(result))
        self.assertFalse(self.release(TELEGRAM_CONFIG, AGGREGATE_KEY)["changed"])
        self.assertEqual(cloudflare.verify_worker_target(self.api.worker_api, self.api.data_api, TARGET),
                         {"deploymentId": NEW_DEPLOYMENT, "versionId": NEW_VERSION, "revision": NEW_REVISION})
        writes = self.api.writes()
        for different in (None, "A" * 43):
            with self.subTest(key_absent=different is None):
                with self.assertRaisesRegex(cloudflare.CloudflareError, "separate rotation release"):
                    self.release(TELEGRAM_CONFIG, different)
        self.assertEqual(self.api.writes(), writes)

    def test_invalid_aggregate_key_fails_before_cloudflare(self):
        with self.assertRaisesRegex(cloudflare.CloudflareError, "canonical Base64URL"):
            self.release(TELEGRAM_CONFIG, "A" * 42 + "B")
        self.assertEqual(self.api.calls, [])

    def test_private_share_key_composes_with_aggregate_and_preserves_secret_free_readback(self):
        result = self.release(TELEGRAM_CONFIG, AGGREGATE_KEY, PRIVATE_SHARE_KEY)
        self.assertTrue(result["changed"])
        self.assertEqual(self.api.private_share_upload, {"name": cloudflare.PRIVATE_SHARE_KEY_BINDING,
            "type": "secret_text", "text": PRIVATE_SHARE_KEY})
        self.assertNotIn(PRIVATE_SHARE_KEY, json.dumps(result))
        self.assertFalse(self.release(TELEGRAM_CONFIG, AGGREGATE_KEY, PRIVATE_SHARE_KEY)["changed"])
        self.assertEqual(cloudflare.verify_worker_target(self.api.worker_api, self.api.data_api, TARGET),
                         {"deploymentId": NEW_DEPLOYMENT, "versionId": NEW_VERSION, "revision": NEW_REVISION})
        writes = self.api.writes()
        for changed in (None, "A" * 43):
            with self.subTest(absent=changed is None):
                with self.assertRaisesRegex(cloudflare.CloudflareError, "separate rotation release"):
                    self.release(TELEGRAM_CONFIG, AGGREGATE_KEY, changed)
                with self.assertRaises(cloudflare.CloudflareError):
                    cloudflare.verify_worker_target(self.api.worker_api, self.api.data_api, TARGET,
                                                   aggregate_key=AGGREGATE_KEY, private_share_key=changed)
        self.assertEqual(self.api.writes(), writes)

    def test_invalid_or_reused_private_share_key_fails_before_cloudflare(self):
        for bad in ("A" * 42 + "B", AGGREGATE_KEY):
            with self.subTest(reused=bad == AGGREGATE_KEY):
                with self.assertRaises(cloudflare.CloudflareError):
                    self.release(TELEGRAM_CONFIG, AGGREGATE_KEY, bad)
        self.assertEqual(self.api.calls, [])

    def test_protected_entry_rejects_key_change_before_any_migration(self):
        directory = self.bundle / "subs-bot-verified"
        directory.mkdir()
        manifest = {**self.manifest, "migrations": [{"name": "0014_telegram_aggregate_issuance.sql"},
                                                   {"name": "0016_telegram_private_share_creation.sql"}]}
        (directory / "isolation.json").write_text(json.dumps(manifest), encoding="utf-8")
        environment = {"GITHUB_SHA": NEW_REVISION, "GITHUB_REPOSITORY": "jacklilyhello/subs-bot",
            "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REF": "refs/heads/main", "RUNNER_TEMP": str(self.bundle),
            "SUBS_BOT_CF_ISOLATION_TARGET_JSON": json.dumps(TARGET), "SUBS_BOT_CF_BOOTSTRAP_TOKEN": "synthetic-data",
            "SUBS_BOT_CF_DEPLOY_TOKEN": "synthetic-deploy", "SUBS_BOT_TELEGRAM_AGGREGATE_KEY": AGGREGATE_KEY,
            "SUBS_BOT_TELEGRAM_PRIVATE_SHARE_CREATION_KEY": PRIVATE_SHARE_KEY}
        with patch.dict(os.environ, environment, clear=True), \
             patch.object(release_entry, "telegram_release_config", return_value=TELEGRAM_CONFIG), \
             patch.object(release_entry, "CloudflareClient"), patch.object(release_entry, "require_current_main"), \
             patch.object(release_entry, "verify_worker_target", side_effect=cloudflare.CloudflareError("separate rotation release")) as verify, \
             patch.object(release_entry, "apply_migrations") as migrate, patch.object(release_entry, "release_worker") as deploy:
            with self.assertRaisesRegex(cloudflare.CloudflareError, "rotation"):
                release_entry.release()
            self.assertEqual(verify.call_args.kwargs["private_share_key"], PRIVATE_SHARE_KEY)
            migrate.assert_not_called()
            deploy.assert_not_called()

    def test_protected_entry_rejects_provider_drift_before_any_migration(self):
        directory = self.bundle / "subs-bot-verified"
        directory.mkdir()
        (directory / "isolation.json").write_text(json.dumps(self.manifest), encoding="utf-8")
        environment = {"GITHUB_SHA": NEW_REVISION, "GITHUB_REPOSITORY": "jacklilyhello/subs-bot",
            "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REF": "refs/heads/main", "RUNNER_TEMP": str(self.bundle),
            "SUBS_BOT_CF_ISOLATION_TARGET_JSON": json.dumps(TARGET), "SUBS_BOT_CF_BOOTSTRAP_TOKEN": "synthetic-data",
            "SUBS_BOT_CF_DEPLOY_TOKEN": "synthetic-deploy", release_entry.CONFIG_ENV: "fixture-provider-pin"}
        provider = Mock(binding=PROVIDER_BINDING, historical_application_revision=None)
        provider.verify.side_effect = cloudflare.CloudflareError("Provider drift.")
        with patch.dict(os.environ, environment, clear=True), patch.object(release_entry, "CloudflareClient"), \
             patch.object(release_entry, "require_current_main"), patch.object(release_entry, "verify_worker_target") as verify, \
             patch.object(release_entry, "load_provider_gate", return_value=provider), \
             patch.object(release_entry, "apply_migrations") as migrate, patch.object(release_entry, "release_worker") as deploy:
            with self.assertRaisesRegex(cloudflare.CloudflareError, "Provider drift"):
                release_entry.release()
            self.assertEqual(verify.call_args.kwargs["provider_binding"], PROVIDER_BINDING)
            self.assertEqual(verify.call_args.kwargs["release_revision"], NEW_REVISION)
            self.assertEqual(verify.call_args.kwargs["provider_first_binding_guard"], provider.verify_first_binding)
            migrate.assert_not_called()
            deploy.assert_not_called()

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
        with self.assertRaisesRegex(cloudflare.CloudflareError, "separate scoped release"):
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

    def test_provider_binding_exact_named_entrypoint_and_repeated_release(self):
        guard, proof = Mock(), Mock()
        self.assertTrue(self.release(provider_binding=PROVIDER_BINDING, provider_guard=guard, provider_first_binding_guard=proof)["changed"])
        self.assertEqual(guard.call_count, 3)
        proof.assert_called_once_with()
        uploaded = self.api.versions[NEW_VERSION]
        self.assertEqual(uploaded["bindings"][-3:], [
            {"type": "service", "name": "PROVIDER_FETCH", "service": "subs-bot-provider-fetch-dev-01", "entrypoint": "ProviderFetch"},
            {"type": "plain_text", "name": "PROVIDER_REVISION", "text": NEW_REVISION},
            {"type": "plain_text", "name": "PROVIDER_IMAGE_SHA256", "text": PROVIDER_BINDING.image_sha256},
        ])
        self.assertEqual(uploaded["annotations"]["workers/message"], cloudflare.PROVIDER_MESSAGE + PROVIDER_BINDING.identity_sha256)
        proof.side_effect = cloudflare.CloudflareError("Synthetic expired artifact.")
        self.assertFalse(self.release(provider_binding=PROVIDER_BINDING, provider_guard=guard, provider_first_binding_guard=proof)["changed"])
        proof.assert_called_once_with()
        self.assertEqual(guard.call_count, 4)
        self.assertEqual(self.api.writes(), [VERSIONS + "?deploy=false", DEPLOYMENTS])

    def test_provider_drop_rotation_and_partial_binding_are_refused(self):
        self.release(provider_binding=PROVIDER_BINDING, provider_guard=Mock(), provider_first_binding_guard=Mock())
        writes = self.api.writes()
        for different in (None, cloudflare.ProviderBinding(NEW_REVISION, PROVIDER_BINDING.image_sha256, "c" * 64)):
            with self.subTest(different=different), self.assertRaisesRegex(cloudflare.CloudflareError, "separate rotation release"):
                cloudflare.verify_worker_target(self.api.worker_api, self.api.data_api, TARGET, provider_binding=different,
                                                release_revision=NEW_REVISION)
        with self.assertRaisesRegex(cloudflare.CloudflareError, "separate rotation release"):
            self.release()
        self.api.versions[NEW_VERSION]["bindings"].pop()
        with self.assertRaisesRegex(cloudflare.CloudflareError, "binding names"):
            self.release(provider_binding=PROVIDER_BINDING, provider_guard=Mock())
        self.assertEqual(self.api.writes(), writes)

    def test_new_app_revision_preserves_verified_provider_after_artifact_expiry(self):
        binding = cloudflare.ProviderBinding(OLD_REVISION, PROVIDER_BINDING.image_sha256, PROVIDER_BINDING.identity_sha256)
        old = self.api.versions[OLD_VERSION]
        old["bindings"].extend([
            {"type": "service", "name": "PROVIDER_FETCH", "service": cloudflare.PROVIDER_SERVICE, "entrypoint": "ProviderFetch"},
            {"type": "plain_text", "name": "PROVIDER_REVISION", "text": binding.revision},
            {"type": "plain_text", "name": "PROVIDER_IMAGE_SHA256", "text": binding.image_sha256},
        ])
        old["annotations"]["workers/message"] = cloudflare.PROVIDER_MESSAGE + binding.identity_sha256
        proof = Mock(side_effect=cloudflare.CloudflareError("Synthetic expired artifact."))
        guard = Mock()
        active = cloudflare.verify_worker_target(self.api.worker_api, self.api.data_api, TARGET, provider_binding=binding,
                                                 release_revision=NEW_REVISION, provider_first_binding_guard=proof)
        result = self.release(expected_active=active, provider_binding=binding, provider_guard=guard,
                              provider_first_binding_guard=proof)
        self.assertTrue(result["changed"])
        self.assertEqual(result["revision"], NEW_REVISION)
        self.assertEqual(self.api.versions[NEW_VERSION]["bindings"][-3:], old["bindings"][-3:])
        self.assertEqual(self.api.versions[NEW_VERSION]["annotations"]["workers/message"], old["annotations"]["workers/message"])
        self.assertEqual(guard.call_count, 3)
        proof.assert_not_called()

    def test_first_provider_binding_requires_current_contract_revision_and_guard(self):
        stale = cloudflare.ProviderBinding(OLD_REVISION, PROVIDER_BINDING.image_sha256, PROVIDER_BINDING.identity_sha256)
        with self.assertRaisesRegex(cloudflare.CloudflareError, "verified dependency guard"):
            self.release(provider_binding=PROVIDER_BINDING)
        guard = Mock()
        with self.assertRaisesRegex(cloudflare.CloudflareError, "same main revision"):
            self.release(provider_binding=stale, provider_guard=guard)
        with self.assertRaisesRegex(cloudflare.CloudflareError, "verified GitHub activation artifact"):
            self.release(provider_binding=PROVIDER_BINDING, provider_guard=guard)
        guard.assert_not_called()
        self.assertEqual(self.api.writes(), [])

    def test_first_historical_binding_requires_exact_app_artifact_and_keeps_provider_revision(self):
        binding = cloudflare.ProviderBinding(OLD_REVISION, PROVIDER_BINDING.image_sha256, PROVIDER_BINDING.identity_sha256)
        proof = Mock()
        options = {"provider_binding": binding, "provider_first_binding_guard": proof,
                   "historical_application_revision": NEW_REVISION}
        with self.assertRaisesRegex(cloudflare.CloudflareError, "same main revision"):
            cloudflare.verify_worker_target(self.api.worker_api, self.api.data_api, TARGET,
                                            release_revision="e" * 40, **options)
        self.api.versions[OLD_VERSION]["bindings"][2]["text"] = "e" * 40
        with self.assertRaisesRegex(cloudflare.CloudflareError, "exact active isolated health baseline"):
            cloudflare.verify_worker_target(self.api.worker_api, self.api.data_api, TARGET,
                                            release_revision=NEW_REVISION, **options)
        with self.assertRaisesRegex(cloudflare.CloudflareError, "exact active isolated health baseline"):
            self.release(provider_guard=Mock(), **options)
        proof.assert_not_called()
        self.assertEqual(self.api.writes(), [])
        self.api.versions[OLD_VERSION]["bindings"][2]["text"] = OLD_REVISION

        active = cloudflare.verify_worker_target(self.api.worker_api, self.api.data_api, TARGET,
                                                 release_revision=NEW_REVISION, **options)
        released = self.release(expected_active=active, provider_guard=Mock(), **options)
        self.assertEqual(released["revision"], NEW_REVISION)
        self.assertEqual(self.api.versions[NEW_VERSION]["bindings"][-2],
                         {"type": "plain_text", "name": "PROVIDER_REVISION", "text": OLD_REVISION})
        self.assertEqual(proof.call_count, 2)
        proof.side_effect = cloudflare.CloudflareError("Synthetic expired historical proof.")
        self.assertFalse(self.release(provider_guard=Mock(), **options)["changed"])
        self.assertEqual(proof.call_count, 2)
        self.assertEqual(self.api.writes(), [VERSIONS + "?deploy=false", DEPLOYMENTS])

    def test_protected_first_binding_requires_live_artifact_before_migrations(self):
        directory = self.bundle / "subs-bot-verified"
        directory.mkdir()
        (directory / "isolation.json").write_text(json.dumps(self.manifest), encoding="utf-8")
        environment = {"GITHUB_SHA": NEW_REVISION, "GITHUB_REPOSITORY": "jacklilyhello/subs-bot",
            "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REF": "refs/heads/main", "RUNNER_TEMP": str(self.bundle),
            "SUBS_BOT_CF_ISOLATION_TARGET_JSON": json.dumps(TARGET), "SUBS_BOT_CF_BOOTSTRAP_TOKEN": "synthetic-data",
            "SUBS_BOT_CF_DEPLOY_TOKEN": "synthetic-deploy", release_entry.CONFIG_ENV: "fixture-provider-capsule"}
        historical = cloudflare.ProviderBinding(OLD_REVISION, PROVIDER_BINDING.image_sha256, PROVIDER_BINDING.identity_sha256)
        for binding, application_revision in ((PROVIDER_BINDING, None), (historical, NEW_REVISION)):
            provider = Mock(binding=binding, historical_application_revision=application_revision)
            provider.verify_first_binding.side_effect = cloudflare.CloudflareError("Synthetic expired artifact.")
            with self.subTest(historical=application_revision is not None), patch.dict(os.environ, environment, clear=True), \
                 patch.object(release_entry, "CloudflareClient", side_effect=[self.api.data_api, self.api.worker_api]), \
                 patch.object(release_entry, "require_current_main"), patch.object(release_entry, "load_provider_gate", return_value=provider), \
                 patch.object(release_entry, "apply_migrations") as migrate, patch.object(release_entry, "release_worker") as deploy:
                with self.assertRaisesRegex(cloudflare.CloudflareError, "expired artifact"):
                    release_entry.release()
                provider.verify_first_binding.assert_called_once_with()
                provider.verify.assert_not_called()
                migrate.assert_not_called()
                deploy.assert_not_called()
        self.assertEqual(self.api.writes(), [])

    def test_provider_drift_after_staging_blocks_activation(self):
        guard = Mock(side_effect=[None, cloudflare.CloudflareError("Provider drift.")])
        with self.assertRaisesRegex(cloudflare.CloudflareError, "Provider drift"):
            self.release(provider_binding=PROVIDER_BINDING, provider_guard=guard, provider_first_binding_guard=Mock())
        self.assertEqual(self.api.writes(), [VERSIONS + "?deploy=false"])
        self.assertEqual(self.api.active["id"], OLD_DEPLOYMENT)

    def test_provider_drift_after_activation_rolls_back_without_provider_read(self):
        guard = Mock(side_effect=[None, None, cloudflare.CloudflareError("Provider drift.")])
        with self.assertRaisesRegex(cloudflare.CloudflareError, "prior version was restored"):
            self.release(provider_binding=PROVIDER_BINDING, provider_guard=guard, provider_first_binding_guard=Mock())
        self.assertEqual(guard.call_count, 3)
        self.assertEqual(self.api.writes(), [VERSIONS + "?deploy=false", DEPLOYMENTS, DEPLOYMENTS])
        self.assertEqual(self.api.active["versions"][0]["version_id"], OLD_VERSION)

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
        self.assertEqual(error.exception.http_status, 403)
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
