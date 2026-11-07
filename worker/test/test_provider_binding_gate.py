"""Synthetic provider proof, reference and release boundaries on hosted CI."""

from copy import deepcopy
from hashlib import sha256
from io import BytesIO
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch
from zipfile import ZipFile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import provider_binding_gate as gate
from test_activate_provider_isolation import ACCOUNT, ACTIVATION, EVIDENCE, IDENTITY, ISOLATED, RELEASE, START, VERSION, worker


RUN = "1234"
ATTEMPT = "2"
ARTIFACT = "1235"
WORKFLOW_ID = 1236
TARGET = {"accountId": ACCOUNT, "workerId": "9" * 32}
CALLER = {"id": TARGET["workerId"], "name": gate.WORKER_NAME}
ACCOUNT_SHA = sha256(ACCOUNT.encode("ascii")).hexdigest()


def zipped(manifest, extra=None):
    out = BytesIO()
    with ZipFile(out, "w") as archive:
        archive.writestr(gate.activation.BINDING_PROOF_FILE, gate.activation._proof_bytes(manifest))
        if extra is not None:
            archive.writestr(extra, "synthetic-private")
    return out.getvalue()


class ProofGateTests(unittest.TestCase):
    def setUp(self):
        self.proof = {
            "version": 1, "accountSha256": ACCOUNT_SHA, "providerBuild": EVIDENCE,
            "activation": {"runId": RUN, "runAttempt": ATTEMPT, "isolatedRevision": ISOLATED},
            "verification": {
                "status": "complete", "publicDenied": True, "stopped": True, "blockedPrivateTargets": 3,
                "healthBytes": 5, "approvedDnsFamilies": [4, 6], "healthSha256": "1" * 64, "actorSha256": "2" * 64,
                "workerIdentitySha256": IDENTITY.fingerprint(), "versionSha256": gate.activation._hash(VERSION),
                "activationIdentitySha256": gate.activation._fingerprint(ACTIVATION),
                "containerIdentitySha256": "3" * 64, "workflowIdentitySha256": "4" * 64,
            },
        }
        self.pin = {"version": 2, "proof": {"revision": RELEASE["revision"], "runId": RUN, "runAttempt": ATTEMPT,
                                             "artifactId": ARTIFACT, "archiveSha256": "0" * 64},
                    "proofDocument": deepcopy(self.proof),
                    "worker": {"workerId": IDENTITY.worker_id, "workerCreatedOn": IDENTITY.created_on},
                    "activation": {**ACTIVATION, "versionId": VERSION}}
        self.use_archive(zipped(self.proof))
        repo = {"id": gate.github.REPOSITORY_ID}
        self.run = {"id": int(RUN), "workflow_id": WORKFLOW_ID, "path": gate.activation.WORKFLOW_PATH,
                    "event": "workflow_dispatch", "status": "completed", "conclusion": "success", "head_branch": "main",
                    "head_sha": RELEASE["revision"], "run_attempt": int(ATTEMPT), "repository": repo, "head_repository": repo}
        self.workflow = {"id": WORKFLOW_ID, "path": gate.activation.WORKFLOW_PATH, "state": "active"}
        self.origin = {"id": int(RUN), "repository_id": repo["id"], "head_repository_id": repo["id"],
                       "head_branch": "main", "head_sha": RELEASE["revision"]}
        for mock in (patch.object(gate.publication, "TARGET_ACCOUNT_SHA256", ACCOUNT_SHA),
                     patch.object(gate.bootstrap, "TARGET_ACCOUNT_SHA256", ACCOUNT_SHA),
                     patch.object(gate.github, "_github_token", return_value="fixture-github"),
                     patch.object(gate.github, "_get_json", side_effect=self.get_json),
                     patch.object(gate, "_download", side_effect=lambda *_: self.archive)):
            mock.start()
            self.addCleanup(mock.stop)

    def use_archive(self, raw):
        self.archive = raw
        self.pin["proof"]["archiveSha256"] = sha256(raw).hexdigest()

    def get_json(self, path, token):
        self.assertEqual(token, "fixture-github")
        if path == "/actions/workflows/worker-provider-isolation-activate.yml":
            return self.workflow
        if path == f"/actions/runs/{RUN}":
            return self.run
        artifact_name = f"{gate.PROOF_PREFIX}-{RELEASE['revision']}-{self.run['run_attempt']}"
        self.assertEqual(path, f"/actions/runs/{RUN}/artifacts?name={artifact_name}&per_page=2")
        return {"total_count": 1, "artifacts": [{"id": int(ARTIFACT), "name": artifact_name,
                "expired": False, "digest": "sha256:" + self.pin["proof"]["archiveSha256"], "workflow_run": self.origin}]}

    def load(self):
        return gate.load_provider_gate(json.dumps(self.pin), TARGET, "fixture-worker")

    def test_exact_provenance_and_live_same_account_private_provider(self):
        loaded = self.load()
        gate._download.assert_not_called()
        loaded.verify_first_binding()
        loaded.verify_first_binding()
        gate._download.assert_called_once_with(ARTIFACT, "fixture-github")
        self.assertEqual(loaded.binding.revision, EVIDENCE["revision"])
        self.assertEqual(loaded.binding.image_sha256, EVIDENCE["ociManifestSha256"])
        self.assertEqual(loaded.binding, self.load().binding)
        observed = worker()
        observed["deployed_on"] = START
        observed["references"]["workers"] = [CALLER]
        api = Mock(spec=gate.activation.ProviderAPI)
        api.worker = Mock()
        api.worker.by_id.return_value = observed
        api.worker.by_name.return_value = observed
        api.deployment.return_value = {"id": ACTIVATION["deploymentId"]}
        api.version.return_value = ACTIVATION["namespaceId"]
        loaded._api = api
        with patch.object(gate.activation, "_public") as denial:
            loaded.verify()
        self.assertEqual(api.deployment.call_count, 2)
        api.version.assert_called_once_with(RELEASE, True)
        api.worker.by_id.assert_called_once_with(IDENTITY)
        denial.assert_called_once_with(gate.activation.PROVIDER_URL)

        observed["references"]["workers"].append({"id": "8" * 32, "name": "foreign"})
        with patch.object(gate.activation, "_public") as denial, self.assertRaisesRegex(gate.CloudflareError, "no longer matches"):
            loaded.verify()
        denial.assert_not_called()

        observed["references"]["workers"] = []
        api.deployment.side_effect = [{"id": ACTIVATION["deploymentId"]}, {"id": "0" * 36}]
        with patch.object(gate.activation, "_public"), self.assertRaisesRegex(gate.CloudflareError, "no longer matches"):
            loaded.verify()

    def test_wrong_workflow_run_attempt_or_origin_fails_before_download(self):
        for changed in ({"event": "push"}, {"run_attempt": 1}, {"conclusion": "failure"}, {"workflow_id": 10},
                        {"head_repository": {"id": 10}}, {"head_branch": "feature"}):
            with self.subTest(changed=changed), patch.dict(self.run, changed):
                with self.assertRaisesRegex(gate.CloudflareError, "proof could not be verified"):
                    self.load().verify_first_binding()
        gate._download.assert_not_called()

    def test_bad_bytes_wrong_pins_and_extra_entries_fail_before_provider_reads(self):
        with patch.object(gate.activation, "ProviderAPI") as provider:
            self.archive += b"bad"
            with self.assertRaises(gate.CloudflareError):
                self.load().verify_first_binding()
            self.use_archive(zipped(self.proof, "unexpected"))
            with self.assertRaises(gate.CloudflareError):
                self.load().verify_first_binding()
            changed = deepcopy(self.proof)
            changed["verification"]["versionSha256"] = "0" * 64
            self.pin["proofDocument"] = changed
            with self.assertRaises(gate.CloudflareError):
                self.load()
            provider.return_value.deployment.assert_not_called()
            provider.return_value.version.assert_not_called()

    def test_first_binding_rejects_an_authentic_archive_for_a_different_capsule(self):
        changed = deepcopy(self.proof)
        changed["verification"]["healthBytes"] += 1
        self.use_archive(zipped(changed))
        with self.assertRaisesRegex(gate.CloudflareError, "proof could not be verified"):
            self.load().verify_first_binding()

    def test_capsule_has_no_github_dependency_and_fingerprints_exact_evidence(self):
        original = self.load().binding
        self.pin["proofDocument"]["verification"]["healthBytes"] += 1
        self.assertNotEqual(self.load().binding, original)
        gate.github._github_token.assert_not_called()
        gate.github._get_json.assert_not_called()
        gate._download.assert_not_called()

    def test_expired_or_unavailable_artifact_has_no_first_binding_fallback(self):
        loaded = self.load()
        gate.github._get_json.side_effect = gate.github.ArtifactError("Synthetic unavailable artifact.")
        with self.assertRaisesRegex(gate.CloudflareError, "proof could not be verified"):
            loaded.verify_first_binding()
        self.assertFalse(loaded._first_binding_verified)
        gate._download.assert_not_called()

    def test_empty_config_is_unbound_and_partial_or_cross_account_config_fails(self):
        self.assertIsNone(gate.load_provider_gate("", {}, ""))
        with patch.dict(self.pin, version=1):
            with self.assertRaisesRegex(gate.CloudflareError, "pin is invalid"):
                self.load()
        with self.assertRaisesRegex(gate.CloudflareError, "pin is invalid"):
            gate.load_provider_gate(json.dumps(self.pin), {**TARGET, "accountId": "f" * 32}, "fixture-worker")
        del self.pin["activation"]["namespaceId"]
        with self.assertRaisesRegex(gate.CloudflareError, "pin is invalid"):
            self.load()
        gate.github._get_json.assert_not_called()

    def test_provider_worker_reader_never_sends_container_or_mutating_requests(self):
        api = self.load()._api
        with patch.object(gate.publication, "_response") as response:
            with self.assertRaises(gate.activation.ActivationError):
                api.deploy(RELEASE)
            with self.assertRaises(gate.activation.ActivationError):
                api._request("/containers/applications", container=True)
            with self.assertRaises(gate.activation.ActivationError):
                api._request("/workflows/fixture")
        response.assert_not_called()


if __name__ == "__main__":
    unittest.main()
