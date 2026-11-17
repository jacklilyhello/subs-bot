"""Cloud-hosted synthetic checks of complete, private provider source preservation."""

from copy import deepcopy
from base64 import b64encode
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
from urllib.error import HTTPError
from urllib.parse import unquote

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import archive_production_provider as archive
import production_provider as control
import production_provider_rehearsal as rehearsal
from test_production_provider import config, STAMP, VERSION, WORKER_ID, worker_profile


class MemoryStore:
    def __init__(self):
        self.run_id, self.attempt = "100", "1"
        self.prefix = "maintenance/production-provider/100/1/"
        self.objects, self.writes, self.verifications = {}, 0, 0

    def verify(self):
        self.verifications += 1

    def read(self, key):
        return self.objects.get(key)

    def put(self, key, raw):
        if key in self.objects:
            archive.require(self.objects[key] == raw)
        else:
            self.objects[key] = raw
            self.writes += 1


def fixture(directory):
    values = {name: ("synthetic file " + name).encode() for name in archive.FILE_LIMITS}
    target = config(active=True)
    target["build"].update({"archiveSha256": sha256(values["provider-source-archive.zip"]).hexdigest(),
                             "workerSha256": sha256(values["source/provider-worker.js"]).hexdigest(),
                             "ociArchiveSha256": sha256(values["source/provider-image.tar"]).hexdigest()})
    proof = {"status": "complete", "productionMutation": False, "controllerRevision": "b" * 40,
             "runId": "100", "runAttempt": "1", "target": target}
    values["provider-rehearsal-proof.json"] = control.canonical(proof)
    values["provider-rehearsal-target.json"] = control.canonical(target)
    for name, raw in values.items():
        path = directory / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    return values


class ArchiveTests(unittest.TestCase):
    def test_token_identity_prefers_account_and_only_falls_back_on_explicit_denial(self):
        account, token_id = "a" * 32, "b" * 32
        account_path = f"/accounts/{account}/tokens/verify"
        identity = {"status": "active", "id": token_id}
        api = Mock(return_value=identity)
        self.assertEqual(archive.verified_token_identity(api, account), identity)
        api.assert_called_once_with("GET", account_path)
        api = Mock(side_effect=[archive.CloudflareError("denied", http_status=401), identity])
        self.assertEqual(archive.verified_token_identity(api, account), identity)
        self.assertEqual(api.call_args_list, [unittest.mock.call("GET", account_path), unittest.mock.call("GET", "/user/tokens/verify")])
        api = Mock(side_effect=archive.CloudflareError("transport"))
        with self.assertRaises(control.ProviderError):
            archive.verified_token_identity(api, account)
        api.assert_called_once_with("GET", account_path)
        for invalid in ({"status": "disabled", "id": token_id}, {"status": "active", "id": "bad"}):
            with self.subTest(invalid=invalid), self.assertRaises(control.ProviderError):
                archive.verified_token_identity(Mock(return_value=invalid), account)

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.values = fixture(self.root)
        self.store = MemoryStore()

    def test_complete_source_archive_and_r2_only_readback(self):
        result = archive.archive(self.store, self.root)
        self.assertEqual(result["files"], len(archive.FILE_LIMITS))
        self.assertEqual(result["bytes"], sum(len(value) for value in self.values.values()))
        self.assertEqual(result["readback"], "R2-only-complete")
        independent = archive.verify_archive(self.store, result["manifestSha256"])
        self.assertEqual(independent, result)
        self.assertGreaterEqual(self.store.verifications, 4)

    def test_repeat_preserves_bytes_and_no_extra_writes(self):
        first = archive.archive(self.store, self.root)
        written = self.store.writes
        self.assertEqual(archive.archive(self.store, self.root), first)
        self.assertEqual(self.store.writes, written)

    def test_missing_object_or_corrupt_bytes_never_reports_complete(self):
        result = archive.archive(self.store, self.root)
        blob = next(key for key in self.store.objects if key.startswith("blobs/"))
        original = self.store.objects.pop(blob)
        with self.assertRaises(control.ProviderError):
            archive.verify_archive(self.store, result["manifestSha256"])
        self.store.objects[blob] = original + b"corrupt"
        with self.assertRaises(control.ProviderError):
            archive.verify_archive(self.store, result["manifestSha256"])

    def test_wrong_manifest_digest_and_failed_proof_are_refused(self):
        result = archive.archive(self.store, self.root)
        with self.assertRaises(control.ProviderError):
            archive.verify_archive(self.store, "0" * 64)
        proof = json.loads(self.values["provider-rehearsal-proof.json"])
        proof["status"] = "failed"
        (self.root / "provider-rehearsal-proof.json").write_bytes(control.canonical(proof))
        with self.assertRaises(control.ProviderError):
            archive.archive(MemoryStore(), self.root)

    def test_capacity_limit_stops_before_writing(self):
        with patch.object(archive, "MAX_TOTAL_BYTES", 1), self.assertRaises(control.ProviderError):
            archive.archive(self.store, self.root)
        self.assertEqual(self.store.writes, 0)

    def test_unknown_extra_file_or_symlink_is_refused(self):
        (self.root / "extra-secret-file").write_bytes(b"synthetic")
        with self.assertRaises(control.ProviderError):
            archive.archive(self.store, self.root)
        (self.root / "extra-secret-file").unlink()
        selected = self.root / "source/provider-worker.js"
        selected.unlink()
        selected.symlink_to(self.root / "source/provider-image.tar")
        with self.assertRaises(ValueError):
            archive.archive(self.store, self.root)


class PartialArchiveTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.store = MemoryStore()
        self.names = ["subs-bot-provider-attempt-source-100-1", "subs-bot-provider-attempt-result-stage-100-1"]
        self.provenance = {"revision": "b" * 40, "runId": "100", "runAttempt": "1", "workflowPath": control.REHEARSAL_WORKFLOW_PATH,
                           "artifacts": {name: {"artifactId": str(index + 200), "archiveSha256": "5" * 64} for index, name in enumerate(self.names)}}
        target = config()
        target["versionId"] = None
        for index, name in enumerate(self.names):
            directory = self.root / name
            directory.mkdir()
            journal = {"version": 2, "controllerRevision": "b" * 40, "runId": "100", "runAttempt": "1",
                       "targetSha256": control.digest(target), "events": [{"phase": "intent"}] * (index + 1),
                       "currentIntent": {"operation": "stage", "status": "unconfirmed", "intentSha256": "6" * 64}}
            envelope = {"version": 2, "target": target, "journal": journal}
            (directory / rehearsal.CHECKPOINT).write_bytes(control.canonical(envelope))
            (directory / "provider-rehearsal-target.json").write_bytes(control.canonical(target))

    def test_partial_originals_are_complete_storage_but_never_business_acceptance(self):
        result = archive.archive_partial(self.store, self.root, self.provenance)
        self.assertEqual(result["status"], "partial-preserved")
        self.assertEqual(result["completion"], "not-complete")
        self.assertEqual(result["latestCheckpoint"]["intent"]["status"], "unconfirmed")
        self.assertNotIn("manifest.json", self.store.objects)
        self.assertLess(result["uniqueBytes"], result["logicalBytes"])
        self.assertEqual(archive.verify_partial(self.store, result["manifestSha256"]), result)

    def test_missing_or_corrupt_partial_blob_is_not_verified(self):
        result = archive.archive_partial(self.store, self.root, self.provenance)
        blob = next(key for key in self.store.objects if key.startswith("blobs/"))
        del self.store.objects[blob]
        with self.assertRaises(control.ProviderError):
            archive.verify_partial(self.store, result["manifestSha256"])

    def test_unknown_artifact_and_capacity_fail_before_writing(self):
        wrong = deepcopy(self.provenance)
        wrong["artifacts"]["subs-bot-provider-attempt-intent-create-100-1"] = {"artifactId": "300", "archiveSha256": "5" * 64}
        with self.assertRaises(control.ProviderError):
            archive.archive_partial(self.store, self.root, wrong)
        self.assertEqual(self.store.writes, 0)
        with patch.object(archive, "MAX_PARTIAL_LOGICAL_BYTES", 1), self.assertRaises(control.ProviderError):
            archive.archive_partial(self.store, self.root, self.provenance)
        self.assertEqual(self.store.writes, 0)

    def test_partial_manifest_cannot_be_relabelled_complete(self):
        result = archive.archive_partial(self.store, self.root, self.provenance)
        manifest = json.loads(self.store.objects["partial-manifest.json"])
        manifest["completion"] = "complete"
        raw = control.canonical(manifest)
        self.store.objects["partial-manifest.json"] = raw
        with self.assertRaises(control.ProviderError):
            archive.verify_partial(self.store, sha256(raw).hexdigest())


class ReconciliationTests(unittest.TestCase):
    def setUp(self):
        self.target = config()
        self.target["versionId"] = None
        self.module = b"export default {fetch(){return new Response(null,{status:404})}};"
        self.target["build"]["workerSha256"] = sha256(self.module).hexdigest()
        self.identity = {"operation": "stage", "intentSha256": "6" * 64, "identities": {"versionId": VERSION}}

    def client(self, *, corrupt=False):
        from unittest.mock import Mock
        candidate = deepcopy(self.target)
        candidate["versionId"] = VERSION
        client = Mock()
        client.identity = control.bootstrap.Identity(WORKER_ID, STAMP)
        client.beta_path = "/workers/workers/" + WORKER_ID + "/versions"
        client.worker_path = "/workers/scripts/" + candidate["service"]
        observed = worker_profile(candidate)
        client.by_name.return_value = observed
        client.worker.by_id.return_value = observed
        client.deployment.return_value = None
        metadata = control.metadata(candidate)
        beta = {**metadata, "id": VERSION, "urls": [], "modules": [{"name": control.provider.WORKER,
                "content_type": control.stage.MODULE_TYPE, "content_base64": b64encode(b"wrong" if corrupt else self.module).decode()}]}
        legacy = {"id": VERSION, "resources": {"script_runtime": {"compatibility_date": metadata["compatibility_date"],
                  "containers": metadata["containers"]}, "bindings": metadata["bindings"]}}
        client._request.side_effect = lambda path, **_kwargs: {"result": beta if "include=modules" in path else legacy}
        return client

    def test_exact_response_is_registered_only_after_repeated_source_module_readback(self):
        client = self.client()
        with patch.object(archive, "ReconciliationReader", return_value=client), patch.object(control, "public_denied"):
            confirmed = archive.reconcile_identity(self.target, self.identity)
        self.assertEqual(confirmed["versionId"], VERSION)
        self.assertEqual(self.target["versionId"], None)
        self.assertEqual(client.deployment.call_count, 2)
        client._write.assert_not_called()
        client.upload.assert_not_called()

    def test_wrong_module_or_active_consumer_is_not_registered(self):
        client = self.client(corrupt=True)
        with patch.object(archive, "ReconciliationReader", return_value=client), self.assertRaises(ValueError):
            archive.reconcile_identity(self.target, self.identity)
        client = self.client()
        client.deployment.return_value = {"id": "unexpected-active-deployment"}
        with patch.object(archive, "ReconciliationReader", return_value=client), self.assertRaises(control.ProviderError):
            archive.reconcile_identity(self.target, self.identity)

    def test_reconciliation_transport_has_no_write_capability(self):
        client = archive.ReconciliationReader(self.target, "synthetic-worker-token")
        with self.assertRaises(control.ProviderError):
            client._write("/workers/workers", {})
        with self.assertRaises(control.ProviderError):
            client.upload(b"module")



class TerminalPrerequisiteTests(unittest.TestCase):
    def prepared(self, operation):
        target = config(active=True)
        if operation == "activate":
            previous = deepcopy(target)
            target.update({"previous": previous, "versionId": "33333333-4444-5555-6666-777777777777",
                           "activation": {**target["activation"], "deploymentId": "44444444-5555-6666-7777-888888888888"}})
            target["build"]["revision"] = "7" * 40
        target = control.validate_config(target)
        before = {**deepcopy(target), "workflow": None}
        if operation == "activate":
            before["activation"] = None
        intent = {"operation": operation, "status": "started-unknown", "executed": False,
                  "targetSha256": control.digest(before), "source": before["build"],
                  "approvalSha256": control.digest({"operation": operation, "target": before})}
        intent["intentSha256"] = control.digest(intent)
        original = {"target": before, "journal": {"currentIntent": intent}}
        name = "subs-bot-provider-attempt-intent-" + operation + "-100-1"
        manifest = {"source": {"artifacts": {name: {"artifactId": "200", "archiveSha256": "9" * 64}}}}
        journal = {"steps": [{"operation": operation, "status": "confirmed", "targetSha256": control.digest(target),
                             "intentSha256": intent["intentSha256"]}],
                   "events": [{"phase": "intent-persisted", "operation": operation, "intentSha256": intent["intentSha256"],
                               "artifactId": "200", "archiveSha256": "9" * 64}]}
        return target, manifest, journal, original, name

    def test_original_provision_and_registered_reuse_require_their_exact_immutable_intents(self):
        for operation in ("provision-workflow", "activate"):
            target, manifest, journal, original, name = self.prepared(operation)
            with self.subTest(operation=operation), patch.object(archive, "read_record", return_value=control.canonical(original)) as read:
                archive.terminal_prerequisite(MemoryStore(), manifest, target, journal)
                read.assert_called_once_with(unittest.mock.ANY, manifest, name + "/provider-rehearsal-checkpoint.json")

    def test_skipped_step_missing_receipt_wrong_approval_or_source_never_authorizes_reuse(self):
        for change in ("skipped", "receipt", "approval", "source", "executed", "pin"):
            target, manifest, journal, original, _name = self.prepared("activate")
            if change == "skipped": journal["steps"][0]["status"] = "skipped"
            if change == "receipt": journal["events"][0]["archiveSha256"] = "8" * 64
            if change == "approval": original["journal"]["currentIntent"]["approvalSha256"] = "8" * 64
            if change == "source": original["target"]["build"]["revision"] = "8" * 40
            if change == "executed": original["journal"]["currentIntent"]["executed"] = True
            if change == "pin": target["workflow"]["createdOn"] = "2026-11-16T00:00:02.000Z"
            with self.subTest(change=change), patch.object(archive, "read_record", return_value=control.canonical(original)), \
                    self.assertRaises(ValueError):
                archive.terminal_prerequisite(MemoryStore(), manifest, target, journal)


class FailedTerminalArchiveTests(unittest.TestCase):
    def setUp(self):
        from test_production_provider_forward import recovery
        environment = patch.dict(os.environ, {"GITHUB_SHA": "b" * 40})
        environment.start()
        self.addCleanup(environment.stop)
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.target = config(active=True)
        self.state = {"status": "failed-terminal-preserved", "completion": "not-complete", "state": "failed", "exitCode": 137,
                      "targetSha256": control.digest(self.target), "sourceRevision": self.target["build"]["revision"],
                      "instanceIdSha256": "5" * 64, "processSha256": "6" * 64}
        self.recovery = {**recovery(self.target), "terminalSha256": control.digest(self.state)}
        self.write()
        self.store = MemoryStore()

    def write(self):
        for name, value in (("provider-reconciled-target.json", self.target), ("provider-forward-terminal.json", self.recovery),
                            ("provider-failed-terminal-state.json", self.state),
                            ("provider-failed-terminal-readback.json", {"version": 1, "summarySha256": control.digest(self.state),
                                "targetSha256": control.digest(self.target), "observations": 2})):
            (self.root / name).write_bytes(control.canonical(value))

    def test_failed_terminal_is_sealed_and_independently_read_only_as_not_complete(self):
        with patch("production_provider_forward.artifact_receipt"):
            result = archive.terminal_archive(self.store, self.root)
        self.assertEqual(result["completion"], "not-complete")
        self.assertEqual(result["status"], "failed-terminal-preserved")
        writes = self.store.writes
        self.assertEqual(archive.terminal_archive(self.store, expected=result["manifestSha256"]), result)
        self.assertEqual(self.store.writes, writes)
        self.assertNotIn("manifest.json", self.store.objects)
        self.assertNotIn("partial-manifest.json", self.store.objects)

    def test_stop_failure_archive_binds_the_exact_failed_output_and_never_claims_rpc(self):
        failure = {"ok": False, "stage": "stop"}
        self.state.update({"smokeFailure": "stop", "workflowFailureSha256": control.digest(failure)})
        self.recovery["terminalSha256"] = control.digest(self.state)
        self.write()
        path = self.root / "provider-failed-terminal-readback.json"
        readback = json.loads(path.read_bytes())
        readback["workflowResult"] = {"namedRpcVerified": False, "output": failure}
        path.write_bytes(control.canonical(readback))
        with patch("production_provider_forward.artifact_receipt"):
            result = archive.terminal_archive(self.store, self.root)
        self.assertEqual(result["completion"], "not-complete")
        readback["workflowResult"]["namedRpcVerified"] = True
        path.write_bytes(control.canonical(readback))
        with patch("production_provider_forward.artifact_receipt"), self.assertRaises(ValueError):
            archive.terminal_archive(MemoryStore(), self.root)

    def test_mismatched_receipt_hash_state_or_target_never_seals(self):
        with patch("production_provider_forward.artifact_receipt", side_effect=control.ProviderError("refused")), \
                self.assertRaises(control.ProviderError):
            archive.terminal_archive(self.store, self.root)
        self.assertEqual(self.store.writes, 0)
        for changed in ({"completion": "complete"}, {"state": "stopped"}, {"exitCode": 0}, {"targetSha256": "8" * 64}):
            original = deepcopy(self.state)
            self.state.update(changed)
            self.recovery["terminalSha256"] = control.digest(self.state)
            self.write()
            with patch("production_provider_forward.artifact_receipt"), self.subTest(changed=changed), \
                    self.assertRaises(control.ProviderError):
                archive.terminal_archive(self.store, self.root)
            self.assertEqual(self.store.writes, 0)
            self.state = original

    def test_corrupt_or_missing_terminal_record_cannot_be_verified(self):
        with patch("production_provider_forward.artifact_receipt"):
            result = archive.terminal_archive(self.store, self.root)
        self.store.objects["terminal/provider-failed-terminal-state.json"] += b"changed"
        with self.assertRaises(control.ProviderError):
            archive.terminal_archive(self.store, expected=result["manifestSha256"])


class PrivateProofTransportTests(unittest.TestCase):
    """Exercise the actual key/read/signed-put layer; only HTTP is synthetic."""

    def setUp(self):
        self.objects, self.requests = {}, []
        self.store = archive.PrivateProofStore({"accountId": "9431815bdb8beb2272f6668e06b7d3be", "namespace": "lilyya",
                                               "r2CreatedOn": STAMP}, "synthetic-token", "100", "1")
        self.store.access_key = "a" * 32
        owner = self

        class Response:
            status = 200
            headers = {"Content-Encoding": "identity"}

            def __init__(self, raw=b""):
                self.raw = raw

            def read(self, limit):
                return self.raw[:limit]

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                pass

            def close(self):
                pass

        class Connection:
            def __init__(self, host, **_kwargs):
                owner.assertEqual(host, owner.store.target["accountId"] + ".r2.cloudflarestorage.com")

            def request(self, method, path, body, headers):
                owner.assertEqual(method, "PUT")
                owner.assertEqual(headers["if-none-match"], "*")
                owner.assertTrue(headers["Authorization"].startswith("AWS4-HMAC-SHA256 "))
                prefix = "/" + owner.store.bucket + "/"
                owner.assertTrue(path.startswith(prefix))
                key = unquote(path[len(prefix):])
                owner.assertTrue(key.startswith(owner.store.prefix))
                owner.assertNotIn(key, owner.objects)
                owner.objects[key] = body
                owner.requests.append((method, key))

            def getresponse(self):
                return Response()

            def close(self):
                pass

        def get(request, **_kwargs):
            self.assertEqual(request.get_method(), "GET")
            origin = archive.API_ORIGIN + self.store.base + "/objects/"
            self.assertTrue(request.full_url.startswith(origin))
            key = unquote(request.full_url[len(origin):])
            if key not in self.objects:
                raise HTTPError(request.full_url, 404, "synthetic missing", {}, None)
            return Response(self.objects[key])

        self.store.opener = Mock()
        self.store.opener.open.side_effect = get
        transport = patch.object(archive, "HTTPSConnection", Connection)
        transport.start()
        self.addCleanup(transport.stop)

    def test_only_the_five_exact_terminal_keys_reach_real_signed_put_and_readback(self):
        keys = {"terminal-manifest.json", "terminal/provider-reconciled-target.json", "terminal/provider-forward-terminal.json",
                "terminal/provider-failed-terminal-state.json", "terminal/provider-failed-terminal-readback.json"}
        self.assertEqual(archive.TERMINAL_KEYS, keys)
        for relative in keys:
            raw = ("synthetic " + relative).encode()
            self.store.put(relative, raw)
            self.assertEqual(self.store.read(relative), raw)
            self.store.put(relative, raw)
        self.assertEqual(len(self.requests), 5)
        for relative in ("terminal/unknown.json", "terminal/../manifest.json", "../terminal-manifest.json",
                         "terminal-manifest.json/extra", "terminal/provider-forward-terminal.json?x=1", "terminal/%2e%2e/manifest.json"):
            calls = self.store.opener.open.call_count
            with self.subTest(relative=relative), self.assertRaises(control.ProviderError):
                self.store.put(relative, b"refused")
            self.assertEqual(self.store.opener.open.call_count, calls)
        self.assertEqual(len(self.requests), 5)

    def test_terminal_archive_and_independent_verify_use_actual_store_keys_and_transport(self):
        from test_production_provider_forward import recovery
        target = config(active=True)
        state = {"status": "failed-terminal-preserved", "completion": "not-complete", "state": "failed", "exitCode": 137,
                 "targetSha256": control.digest(target), "sourceRevision": target["build"]["revision"],
                 "instanceIdSha256": "5" * 64, "processSha256": "6" * 64}
        proof = {**recovery(target), "terminalSha256": control.digest(state)}
        self.store.verify = Mock()
        with tempfile.TemporaryDirectory() as temporary, patch.dict(os.environ, {"GITHUB_SHA": "b" * 40}), \
                patch("production_provider_forward.artifact_receipt"):
            directory = Path(temporary)
            for name, value in (("provider-reconciled-target.json", target), ("provider-forward-terminal.json", proof),
                    ("provider-failed-terminal-state.json", state), ("provider-failed-terminal-readback.json",
                     {"version": 1, "summarySha256": control.digest(state), "targetSha256": control.digest(target), "observations": 2})):
                (directory / name).write_bytes(control.canonical(value))
            result = archive.terminal_archive(self.store, directory)
        self.assertEqual(result["completion"], "not-complete")
        self.assertEqual(result["readback"], "R2-only-failed-terminal")
        self.assertEqual(len(self.requests), 5)
        self.assertEqual(archive.terminal_archive(self.store, expected=result["manifestSha256"]), result)
        self.assertEqual(len(self.requests), 5)


class ForwardStageArchiveTests(unittest.TestCase):
    def setUp(self):
        from test_production_provider_forward import recovery
        from test_production_provider import DEPLOYMENT
        environment = patch.dict(os.environ, {"GITHUB_SHA": "b" * 40})
        environment.start()
        self.addCleanup(environment.stop)
        previous = config(active=True)
        self.target = config()
        self.target.update({"versionId": DEPLOYMENT, "container": previous["container"], "previous": previous,
                            "forwardRecovery": recovery(previous)})
        self.target["build"]["revision"] = "7" * 40
        self.result = {"version": 1, "status": "confirmed-identity-only", "completion": "not-complete", "operation": "forward-stage",
                       "readOnly": True, "controllerRevision": "b" * 40, "runId": "100", "runAttempt": "1",
                       "targetSha256": control.digest(self.target), "sourceRevision": self.target["build"]["revision"],
                       "sourceRunId": "200", "sourceRunAttempt": "1", "sourceManifestSha256": "1" * 64,
                       "responseIdentitySha256": "2" * 64, "sourceTargetSha256": control.digest({**self.target, "versionId": None})}
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.store = MemoryStore()
        self.write()

    def write(self):
        for name, value in (("provider-reconciled-target.json", self.target), ("provider-reconciliation.json", self.result)):
            (self.root / name).write_bytes(control.canonical(value))

    def test_identity_is_sealed_and_r2_only_verified_without_marking_rehearsal_complete(self):
        with patch("production_provider_forward.artifact_receipt"):
            result = archive.stage_identity_archive(self.store, self.root)
        self.assertEqual(result["completion"], "not-complete")
        self.assertEqual(result["readback"], "R2-only-forward-stage-identity")
        self.assertNotIn("manifest.json", self.store.objects)
        self.assertEqual(archive.stage_identity_archive(self.store, expected=result["manifestSha256"]), result)

    def test_wrong_target_response_or_complete_label_is_not_sealed(self):
        for changed in ({"targetSha256": "9" * 64}, {"sourceTargetSha256": "9" * 64}, {"completion": "complete"},
                        {"readOnly": False}, {"operation": "activate"}, {"sourceManifestSha256": ""}, {"runId": "101"}):
            original = deepcopy(self.result)
            self.result.update(changed)
            self.write()
            with patch("production_provider_forward.artifact_receipt"), self.subTest(changed=changed), self.assertRaises(ValueError):
                archive.stage_identity_archive(self.store, self.root)
            self.assertEqual(self.store.writes, 0)
            self.result = original

    def test_corruption_or_wrong_manifest_never_registers_identity(self):
        with patch("production_provider_forward.artifact_receipt"):
            result = archive.stage_identity_archive(self.store, self.root)
        with self.assertRaises(ValueError):
            archive.stage_identity_archive(self.store, expected="0" * 64)
        key = next(key for key in self.store.objects if key.startswith("blobs/"))
        self.store.objects[key] += b"corrupt"
        with self.assertRaises(ValueError):
            archive.stage_identity_archive(self.store, expected=result["manifestSha256"])


if __name__ == "__main__":
    unittest.main()
