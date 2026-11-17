"""Hosted-only refusal and one-shot dispatch tests for private Provider publication."""

from hashlib import sha256
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import production_provider as control
import production_provider_encrypted_publish as encrypted
import production_provider_reviewed_head_harness as reviewed
from test_production_provider import config


class PrivatePublishTests(unittest.TestCase):
    def test_reviewed_adapter_rejects_cross_job_action(self):
        with patch.dict(os.environ, {"GITHUB_JOB": "verify_sources", "SUBS_BOT_PROVIDER_REVIEWED_ACTION": "persist-intent"}, clear=True), \
                patch.object(reviewed.handoff, "context"), \
                patch.object(reviewed.handoff, "workflow_path", return_value=reviewed.handoff.REVIEWED_WORKFLOW_PATH), \
                patch.object(reviewed.publish, "persist_intent") as writer, self.assertRaises(control.ProviderError):
            reviewed.run()
        writer.assert_not_called()

    def test_reviewed_source_path_checks_current_and_all_previous_before_output(self):
        target = config(active=True)
        events = []
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "output"
            output.write_text("")
            env = {"RUNNER_TEMP": temporary, "GITHUB_OUTPUT": str(output), "GITHUB_JOB": "verify_sources",
                   "SUBS_BOT_PROVIDER_REVIEWED_ACTION": "verify-archived-chain"}
            with patch.dict(os.environ, env, clear=True), patch.object(reviewed.handoff, "context"), \
                    patch.object(reviewed.handoff, "workflow_path", return_value=reviewed.handoff.REVIEWED_WORKFLOW_PATH), \
                    patch.object(reviewed.publish, "config", return_value=target), \
                    patch.object(reviewed.durable, "restore", side_effect=lambda: events.append("restore")), \
                    patch.object(control, "guard_sources", side_effect=lambda _target: events.append("guard")), \
                    patch.object(control, "prepare_durable", side_effect=lambda _build: events.append("current")), \
                    patch.object(control, "verify_previous_archives", side_effect=lambda _target, _root: events.append("previous")), \
                    patch.object(reviewed.publish, "persist_intent") as writer:
                reviewed.run()
            self.assertEqual(events, ["restore", "guard", "current", "previous", "guard"])
            self.assertEqual(output.read_text(), "target_sha256=" + control.digest(target) + "\n")
            writer.assert_not_called()

    def test_reviewed_source_failure_does_not_emit_attestation(self):
        target = config(active=True)
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "output"
            output.write_text("")
            with patch.dict(os.environ, {"RUNNER_TEMP": temporary, "GITHUB_OUTPUT": str(output)}, clear=True), \
                    patch.object(reviewed.publish, "config", return_value=target), patch.object(reviewed.durable, "restore"), \
                    patch.object(control, "guard_sources"), patch.object(control, "prepare_durable"), \
                    patch.object(control, "verify_previous_archives", side_effect=control.ProviderError("damaged source")), \
                    self.assertRaises(control.ProviderError):
                reviewed.verify_archived_chain()
            self.assertEqual(output.read_text(), "")

    def test_new_candidate_reads_exact_previous_unbound_dependency(self):
        previous = config(active=True)
        target = config()
        target["build"]["revision"] = "7" * 40
        target.update({"versionId": None, "container": previous["container"], "workflow": None, "previous": previous})
        state = {"activation": previous["activation"], "container": previous["container"],
                 "workflow": previous["workflow"], "instance": {"fixture": "previous"}}
        api, registry = Mock(), Mock()
        registry.manifest.return_value = target["build"]["ociManifestSha256"]
        with patch.object(control, "ProviderAPI", return_value=api), patch.object(control, "Registry", return_value=registry), \
                patch.object(control, "observe", return_value=state), patch.object(control, "unbound_upgrade") as previous_guard, \
                patch.object(control, "caller_state", return_value="unbound"):
            result = encrypted.live_state(target, "synthetic")
        self.assertEqual(previous_guard.call_count, 2)
        self.assertEqual(result["tagManifestSha256"], target["build"]["ociManifestSha256"])

    def test_changed_previous_or_bound_caller_stops_before_registry_access(self):
        previous = config(active=True)
        target = config()
        target["build"]["revision"] = "7" * 40
        target.update({"versionId": None, "container": previous["container"], "workflow": None, "previous": previous})
        with patch.object(control, "ProviderAPI"), patch.object(control, "Registry") as registry, \
                patch.object(control, "observe", return_value={}), \
                patch.object(control, "unbound_upgrade", side_effect=control.ProviderError("unbound prestate changed")), \
                self.assertRaises(control.ProviderError):
            encrypted.live_state(target, "synthetic")
        registry.assert_not_called()

    def test_workflow_artifacts_are_ciphertext_and_keys_stay_in_archive_jobs(self):
        workflow = (Path(__file__).resolve().parents[2] / ".github/workflows/worker-production-provider-encrypted-rehearsal.yml").read_text()
        self.assertEqual(workflow.count("path: ${{ runner.temp }}/payload.age"), 3)
        self.assertEqual(workflow.count("uses: actions/upload-artifact@"), 3)
        for producer in ("preflight", "dispatch", "verify"):
            self.assertIn(f"${{{{ needs.{producer}.outputs.artifact_id }}}}", workflow)
            self.assertIn(f"${{{{ needs.{producer}.outputs.artifact_sha256 }}}}", workflow)
            self.assertIn(f"${{{{ needs.{producer}.outputs.cipher_sha256 }}}}", workflow)
        jobs = {}
        for name, following in (("preflight", "archive_intent"), ("dispatch", "archive_response"),
                                ("verify", "archive_completion")):
            jobs[name] = workflow.split(f"\n  {name}:\n", 1)[1].split(f"\n  {following}:\n", 1)[0]
            self.assertNotIn("SUBS_BOT_PROVIDER_REHEARSAL_AGE_IDENTITY", jobs[name])
            self.assertNotIn("SUBS_BOT_CF_PROVIDER_ARCHIVE_WRITE_TOKEN", jobs[name])
        for name, following in (("archive_intent", "dispatch"), ("archive_response", "verify"),
                                ("archive_completion", "independent_readback")):
            job = workflow.split(f"\n  {name}:\n", 1)[1].split(f"\n  {following}:\n", 1)[0]
            self.assertNotIn("SUBS_BOT_CF_PROVIDER_WORKER_READ_TOKEN", job)
            self.assertNotIn("SUBS_BOT_CF_PROVIDER_CONTAINER_TOKEN", job)

    def intent(self, target, prestate):
        return {"version": 1, "kind": "private-provider-encrypted-handoff", "phase": "intent", "runId": "101",
                "runAttempt": "1", "controllerRevision": "b" * 40, "operation": "publish", "target": target,
                "targetSha256": control.digest(target), "approvalSha256": control.digest({"operation": "publish", "target": target}),
                "intentSha256": None, "state": {**prestate, "archiveRefs": [{"fixture": "reference"}]}}

    def test_incomplete_prior_private_attempt_blocks_new_intent(self):
        reader = Mock()
        keys = [encrypted.BASE + "100/1/intent.json"]
        with patch.object(encrypted.durable, "list_private_keys", return_value=keys), \
                patch.object(encrypted, "ledger", return_value={}), self.assertRaises(control.ProviderError):
            encrypted.inventory(reader)

    def test_missing_registry_tag_is_rejected_before_encrypted_intent_or_r2_write(self):
        target = config(active=True)
        with patch.object(encrypted, "config", return_value=target), patch.object(encrypted, "verify_sources"), \
                patch.object(encrypted, "live_state", return_value={"dependencySha256": "1" * 64, "tagManifestSha256": None}), \
                patch.object(encrypted, "write_cipher") as cipher, patch.object(encrypted, "store") as store, \
                self.assertRaises(control.ProviderError):
            encrypted.preflight()
        cipher.assert_not_called()
        store.assert_not_called()

    def test_changed_prestate_stops_before_registry_write(self):
        target = config(active=True)
        prestate = {"dependencySha256": "1" * 64, "tagManifestSha256": None}
        raw = control.canonical(self.intent(target, prestate))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "provider-encrypted-intent.json").write_bytes(raw)
            env = {"RUNNER_TEMP": temporary, "SUBS_BOT_PROVIDER_ENCRYPTED_INTENT_SHA256": sha256(raw).hexdigest(),
                   "SUBS_BOT_PROVIDER_CONTROL_OPERATION": "publish",
                   "SUBS_BOT_PROVIDER_CONTROL_APPROVAL": control.digest({"operation": "publish", "target": target}),
                   "GITHUB_RUN_ID": "101", "GITHUB_SHA": "b" * 40}
            changed = {"dependencySha256": "2" * 64, "tagManifestSha256": None}
            with patch.dict(os.environ, env, clear=True), patch.object(encrypted, "config", return_value=target), \
                    patch.object(control, "request_context"), patch.object(control, "guard_sources"), \
                    patch.object(encrypted, "refs", return_value=[{"fixture": "reference"}]), \
                    patch.object(encrypted, "live_state", return_value=changed), \
                    patch.object(control.publication, "_copy") as copy, self.assertRaises(control.ProviderError):
                encrypted.dispatch()
            copy.assert_not_called()

    def test_existing_exact_image_is_encrypted_without_registry_write(self):
        target = config(active=True)
        digest = target["build"]["ociManifestSha256"]
        prestate = {"dependencySha256": "1" * 64, "tagManifestSha256": digest}
        raw = control.canonical(self.intent(target, prestate))
        registry = Mock()
        registry.repository = target["accountId"] + "/" + target["service"]
        registry.manifest.return_value = digest
        registry.mint.return_value = ("synthetic", "synthetic")
        events = []
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "provider-encrypted-intent.json").write_bytes(raw)
            archive = root / "image.tar"
            archive.write_bytes(b"synthetic")
            env = {"RUNNER_TEMP": temporary, "SUBS_BOT_PROVIDER_ENCRYPTED_INTENT_SHA256": sha256(raw).hexdigest(),
                   "SUBS_BOT_PROVIDER_CONTROL_OPERATION": "publish", "SUBS_BOT_PROVIDER_CONTAINER_TOKEN": "synthetic",
                   "SUBS_BOT_PROVIDER_CONTROL_APPROVAL": control.digest({"operation": "publish", "target": target}),
                   "GITHUB_RUN_ID": "101", "GITHUB_SHA": "b" * 40}
            def ciphertext(phase, value):
                self.assertEqual(phase, "response")
                self.assertEqual(value["state"]["dispatchStatus"], "already-present")
                events.append("encrypted")
            with patch.dict(os.environ, env, clear=True), patch.object(encrypted, "config", return_value=target), \
                    patch.object(control, "request_context"), patch.object(control, "guard_sources"), \
                    patch.object(encrypted, "refs", return_value=[{"fixture": "reference"}]), \
                    patch.object(encrypted, "live_state", return_value=prestate), patch.object(control, "Registry", return_value=registry), \
                    patch.object(control.publication, "_verified_input", return_value=(archive, target["build"])), \
                    patch.object(control.publication, "_copy") as copy, \
                    patch.object(encrypted, "write_cipher", side_effect=ciphertext):
                encrypted.dispatch()
        self.assertEqual(events, ["encrypted"])
        self.assertEqual(registry.manifest.call_count, 1)
        copy.assert_not_called()

    def test_missing_tag_is_refused_without_any_copy(self):
        target = config(active=True)
        prestate = {"dependencySha256": "1" * 64, "tagManifestSha256": None}
        raw = control.canonical(self.intent(target, prestate))
        registry = Mock()
        registry.repository = target["accountId"] + "/" + target["service"]
        registry.manifest.return_value = None
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "provider-encrypted-intent.json").write_bytes(raw)
            env = {"RUNNER_TEMP": temporary, "SUBS_BOT_PROVIDER_ENCRYPTED_INTENT_SHA256": sha256(raw).hexdigest(),
                   "SUBS_BOT_PROVIDER_CONTROL_OPERATION": "publish", "GITHUB_RUN_ID": "101", "GITHUB_SHA": "b" * 40,
                   "SUBS_BOT_PROVIDER_CONTROL_APPROVAL": control.digest({"operation": "publish", "target": target})}
            with patch.dict(os.environ, env, clear=True), patch.object(encrypted, "config", return_value=target), \
                    patch.object(control, "request_context"), patch.object(control, "guard_sources"), \
                    patch.object(encrypted, "refs", return_value=[{"fixture": "reference"}]), \
                    patch.object(encrypted, "live_state", return_value=prestate), patch.object(control, "Registry", return_value=registry), \
                    patch.object(control.publication, "_verified_input", return_value=(root / "image", target["build"])), \
                    patch.object(control.publication, "_copy") as copy, \
                    patch.object(encrypted, "write_cipher") as write, self.assertRaises(control.ProviderError):
                encrypted.dispatch()
        copy.assert_not_called()
        write.assert_not_called()


if __name__ == "__main__":
    unittest.main()
