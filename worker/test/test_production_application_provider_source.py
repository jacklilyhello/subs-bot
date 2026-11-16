"""Hosted source-closure and exact read-only dependency transport checks."""

from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from urllib.parse import urlencode

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import archive_production_provider as archive
import production_application_provider_source as source
import production_provider as provider
import test_production_control as app_fixtures
import test_production_provider as provider_fixtures

ACTOR = "6" * 64


class MemoryStore:
    def __init__(self, values):
        self.run_id, self.attempt = "100", "1"
        self.prefix = "maintenance/production-provider/100/1/"
        self.objects, self.reads = {}, []
        files = {}
        for name, raw in values.items():
            digest = sha256(raw).hexdigest()
            self.objects["blobs/" + digest] = raw
            files[name] = {"bytes": len(raw), "sha256": digest, "chunks": [{"bytes": len(raw), "sha256": digest}]}
        manifest = {"version": 1, "kind": "subs-bot-provider-source-proof", "controllerRevision": provider_fixtures.REVISION,
            "runId": self.run_id, "runAttempt": self.attempt, "proofSha256": files["provider-rehearsal-proof.json"]["sha256"],
            "files": files, "totalBytes": sum(len(raw) for raw in values.values())}
        raw = provider.canonical(manifest)
        self.objects["manifest.json"] = raw
        self.manifest_sha256 = sha256(raw).hexdigest()

    def read(self, key):
        self.reads.append(key)
        return self.objects.get(key)

    def verify(self):
        pass

    def put(self, *_args):
        raise AssertionError("Source loading must never write to private storage.")


def complete_values():
    values = {name: ("synthetic source closure " + name).encode() for name in archive.FILE_LIMITS}
    config = provider_fixtures.config(active=True)
    config["build"].update({"archiveSha256": sha256(values["provider-source-archive.zip"]).hexdigest(),
        "workerSha256": sha256(values["source/provider-worker.js"]).hexdigest(),
        "ociArchiveSha256": sha256(values["source/provider-image.tar"]).hexdigest()})
    journal = {"version": 2, "completion": "complete", "controllerRevision": provider_fixtures.REVISION,
        "runId": "100", "runAttempt": "1", "targetSha256": provider.digest(config), "source": config["build"],
        "steps": [{"operation": "smoke", "status": "confirmed"}], "currentIntent": None}
    journal_raw = provider.canonical(journal)
    proof = {"version": 1, "status": "complete", "productionMutation": False,
        "controllerRevision": provider_fixtures.REVISION, "runId": "100", "runAttempt": "1", "target": config,
        "binding": {"service": config["service"], "entrypoint": "ProviderFetch", "revision": config["build"]["revision"],
            "imageSha256": config["build"]["ociManifestSha256"], "callerState": "unbound", "proofSha256": "9" * 64},
        "steps": journal["steps"], "journalSha256": sha256(journal_raw).hexdigest()}
    values.update({"provider-rehearsal-target.json": provider.canonical(config), "provider-rehearsal-proof.json": provider.canonical(proof),
                   "provider-rehearsal-journal.json": journal_raw})
    return values, config, proof


class ProviderSourceTests(unittest.TestCase):
    def load(self, values, *, pin=None):
        store = MemoryStore(values)
        runner = SimpleNamespace(original={"accountId": app_fixtures.contract.ACCOUNT, "namespace": "lilyya",
            "r2CreatedOn": provider_fixtures.STAMP}, env={"SUBS_BOT_CF_BOOTSTRAP_TOKEN": "synthetic-private-token"})
        with patch.object(archive, "PrivateProofStore", return_value=store) as constructor:
            result = source.load_provider(runner, "100", "1", pin or store.manifest_sha256)
        constructor.assert_called_once_with(runner.original, "synthetic-private-token", "100", "1")
        return result, store

    def test_complete_private_closure_returns_only_safe_evidence_projection(self):
        values, config, proof = complete_values()
        result, store = self.load(values)
        self.assertEqual(result["config"], config)
        self.assertEqual(result["proof"], proof)
        self.assertEqual(result["evidence"]["files"], len(archive.FILE_LIMITS))
        self.assertEqual(result["evidence"]["readback"], "R2-only-complete")
        self.assertEqual(result["evidence"]["manifestSha256"], store.manifest_sha256)
        self.assertTrue(all("blobs/" + sha256(raw).hexdigest() in store.reads for raw in values.values()))
        self.assertNotIn("https://", json.dumps(result["evidence"]))
        self.assertNotIn("synthetic-private-token", json.dumps(result["evidence"]))

    def test_wrong_manifest_corrupt_or_missing_source_bytes_never_load(self):
        values, _config, _proof = complete_values()
        with self.assertRaises(ValueError):
            self.load(values, pin="0" * 64)
        for missing in (False, True):
            store = MemoryStore(values)
            key = "blobs/" + sha256(values["source/provider-image.tar"]).hexdigest()
            if missing:
                store.objects.pop(key)
            else:
                store.objects[key] += b"corruption"
            with self.subTest(missing=missing), patch.object(archive, "PrivateProofStore", return_value=store), self.assertRaises(ValueError):
                source.load_provider(SimpleNamespace(original={}, env={}), "100", "1", store.manifest_sha256)

    def test_partial_bound_wrong_source_or_nonmatching_proof_is_refused(self):
        for changed in ({"status": "partial-preserved"}, {"productionMutation": True}, {"runId": "101"},
                        {"journalSha256": "0" * 64}, {"controllerRevision": "7" * 40}):
            values, _config, proof = complete_values()
            values["provider-rehearsal-proof.json"] = provider.canonical({**proof, **changed})
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                self.load(values)
        for changed in ({"caller": {"id": "5" * 32, "name": "subs-bot-cf-control-drill-01"}}, {"workflow": None},
                        {"worker": None}, {"service": "subs-bot-provider-fetch-dev-01"}):
            values, config, proof = complete_values()
            config.update(changed)
            proof["target"] = config
            values["provider-rehearsal-target.json"], values["provider-rehearsal-proof.json"] = provider.canonical(config), provider.canonical(proof)
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                self.load(values)


class DependencyScopeTests(unittest.TestCase):
    def setUp(self):
        self.target, _ = app_fixtures.fixture()
        self.config = provider_fixtures.config(active=True)
        self.config["worker"]["workerId"] = "e" * 32
        self.api = Mock(return_value={"success": True, "result": {}})
        with patch.object(source.lifecycle, "API", return_value=self.api):
            self.reader = source.DependencyReadOnly(self.target, "synthetic-read-token-0000", self.config)
        self.root = "/accounts/" + self.target.account_id
        self.namespace = self.config["activation"]["namespaceId"]
        self.objects = self.root + "/workers/durable_objects/namespaces/" + self.namespace + "/objects"
        self.app = self.root + "/containers/applications/" + self.namespace

    def test_every_exact_verifier_route_is_get_only_and_envelope_preserving(self):
        service, version = self.config["service"], self.config["versionId"]
        beta = self.root + "/workers/workers/" + self.config["worker"]["workerId"]
        script, workflow = self.root + "/workers/scripts/" + service, self.root + "/workflows/" + service + "-smoke"
        paths = [self.root + "/workers/workers/" + service, beta, beta + "/versions?page=1&per_page=10",
            beta + "/versions/" + version + "?include=modules", script + "/versions/" + version,
            script + "/deployments?page=1&per_page=100", script + "/deployments/" + self.config["activation"]["deploymentId"],
            self.root + "/workers/durable_objects/namespaces?page=1&per_page=1000",
            self.root + "/containers/applications?per_page=500", self.app, self.app + "/instances-v2?per_page=2&state=active",
            workflow, workflow + "/versions?page=1&per_page=10", workflow + "/versions/" + self.config["workflow"]["versionId"],
            workflow + "/instances?page=1&per_page=10", workflow + "/instances/provider-release-" + self.config["build"]["revision"] + "?simple=true"]
        for path in paths:
            self.api.return_value = {"success": True, "result": {"synthetic": True}}
            with self.subTest(path=path):
                self.assertEqual(self.reader.request("GET", path, envelope=True), self.api.return_value)
                self.api.assert_called_with("GET", path, envelope=True)
        self.assertEqual(self.reader.request("GET", self.root + "/workflows/" + self.config["service"] + "-smoke"), {"synthetic": True})

    def test_writes_other_services_unknown_ids_queries_and_encoded_paths_stop_before_transport(self):
        service = self.config["service"]
        paths = ["/zones/" + self.target.data["zoneId"], self.root + "/d1/database", self.root + "/r2/buckets",
            self.root + "/workers/workers/foreign-service", self.root + "/workers/workers/" + "f" * 32,
            self.root + "/workers/scripts/" + service + "/versions/" + "66666666-7777-8888-9999-aaaaaaaaaaaa",
            self.root + "/containers/applications?per_page=501", self.app + "/instances/" + ACTOR,
            self.objects + "?limit=10&cursor=unissued", self.root + "/workflows/" + service + "-smoke?extra=1",
            self.root + "/workers/%2e%2e/containers", self.root + "/workers/workers/" + service + "#private",
            "https://api.cloudflare.com/client/v4" + self.root + "/workers/workers/" + service]
        for path in paths:
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.reader.request("GET", path, envelope=True)
        allowed = self.root + "/workers/workers/" + service
        for method in ("POST", "PUT", "PATCH", "DELETE"):
            with self.subTest(method=method), self.assertRaises(ValueError):
                self.reader.request(method, allowed)
        with self.assertRaises(ValueError):
            self.reader.request("GET", allowed, {})
        self.api.assert_not_called()

    def test_actor_details_require_both_exact_namespace_inventories_and_issued_cursor(self):
        cursor = "safe+opaque/cursor="
        self.api.return_value = {"success": True, "result": [{"id": ACTOR, "hasStoredData": True}],
                                 "result_info": {"count": 1, "cursor": cursor}}
        self.reader.request("GET", self.objects + "?limit=10", envelope=True)
        following = self.objects + "?" + urlencode({"limit": 10, "cursor": cursor})
        self.api.return_value = {"success": True, "result": [], "result_info": {"count": 0}}
        self.reader.request("GET", following, envelope=True)
        self.api.return_value = {"success": True, "result": [{"id": ACTOR, "application_id": self.namespace}], "result_info": {}}
        self.reader.request("GET", self.app + "/instances-v2?per_page=2", envelope=True)
        self.api.return_value = {"success": True, "result": {"id": ACTOR}}
        self.assertEqual(self.reader.request("GET", self.app + "/instances/" + ACTOR), {"id": ACTOR})
        before = self.api.call_count
        with self.assertRaises(ValueError):
            self.reader.request("GET", self.app + "/instances/" + "7" * 64)
        with self.assertRaises(ValueError):
            self.reader.request("GET", self.objects + "?limit=10&cursor=unissued")
        self.assertEqual(self.api.call_count, before)

    def test_wrong_environment_or_caller_is_refused_before_client_creation(self):
        config = deepcopy(self.config)
        config["caller"] = {"id": "5" * 32, "name": "subs-bot-cf-control-drill-01"}
        with patch.object(source.lifecycle, "API") as api, self.assertRaises(ValueError):
            source.DependencyReadOnly(self.target, "synthetic-read-token-0000", config)
        api.assert_not_called()
        raw = deepcopy(self.target.data)
        service, backup, hostname = app_fixtures.contract.NAMES["production"]
        raw.update(environment="production", workerName=service, d1Name=service, bucketName=service,
            backupBucketName=backup, hostname=hostname, botUsername="SyntheticFormalBot")
        with patch.object(source.lifecycle, "API") as api, self.assertRaises(ValueError):
            source.DependencyReadOnly(app_fixtures.contract.validate_target(raw), "synthetic-read-token-0000", self.config)
        api.assert_not_called()


if __name__ == "__main__":
    unittest.main()
