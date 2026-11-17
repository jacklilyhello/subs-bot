"""Hosted checks for admission and immutable evidence of Provider mutations."""

import base64
from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import production_provider as control
import provider_private_mutation_journal as journal
import provider_private_mutation_reconcile as reconcile
from test_production_provider import config


class ProviderMutationJournalTests(unittest.TestCase):
    def complete_bundle(self):
        target = config(active=True)
        value = {"runId": "101", "operation": "stage", "controllerRevision": "a" * 40,
                 "candidateRevision": "b" * 40, "reviewedPr": "290", "targetSha256": control.digest(target)}
        intent_sha = control.digest(value)
        observation = {"kind": "response-only", "method": "POST", "path": f"/workers/scripts/{target['service']}/versions",
                       "identities": {"versionId": "11111111-1111-1111-1111-111111111111"}}
        result = {"activation": target["activation"], "container": target["container"], "workflow": target["workflow"],
                  "instance": None, "versionId": observation["identities"]["versionId"]}
        confirmed = {"intentSha256": intent_sha, "target": target, "operation": "stage", "observation": observation, "result": result}
        next_target = journal.rehearsal.confirmed_target(target, "stage", result)
        keys, pins, payloads = {}, {}, {}
        for index, kind in enumerate(("archive", "live"), 1):
            row = {"environmentId": str(index), "keyId": "fixture", "publicKey": base64.b64encode(bytes([index]) * 32).decode()}
            environment = "subs-bot-provider-archive-head-isolation" if kind == "archive" else "subs-bot-provider-head-isolation"
            keys[kind] = row
            pins[kind] = control.digest({"version": 1, "repositoryId": control.github.REPOSITORY_ID, "environment": environment, **row})
            payloads[kind] = control.canonical({"key_id": row["keyId"], "encrypted_value": base64.b64encode(b"x" * 48).decode()})
        raw = {"intent.json": control.canonical(value), "observation.age": b"observation cipher", "response.age": b"confirmed cipher",
               "observation-plaintext.json": control.canonical({"intentSha256": intent_sha, "observation": observation}),
               "response.json": control.canonical(confirmed), "next-target.age": b"next target cipher",
               "next-target.json": control.canonical({"target": next_target, "sourceIntentSha256": intent_sha}),
               "next-target-archive.json": payloads["archive"], "next-target-live.json": payloads["live"],
               "recipient-keys.json": control.canonical({"keys": keys, "pins": pins})}
        wrapped = {"version": 1, "kind": "isolated-provider-response-only", "runId": "101", "operation": "stage",
                   "controllerRevision": value["controllerRevision"], "candidateRevision": value["candidateRevision"],
                   "reviewedPr": "290", "targetSha256": value["targetSha256"], "intentSha256": intent_sha,
                   "observationCipherSha256": sha256(raw["observation.age"]).hexdigest(),
                   "confirmedCipherSha256": sha256(raw["response.age"]).hexdigest(), "resultSha256": control.digest(result),
                   "observation": observation}
        raw["observation.json"] = control.canonical(wrapped)
        verified = {key: "1" * 64 for key in journal.VERIFICATION_HASH_FIELDS}
        verified.update(status="independently-verified", operation="stage", targetSha256=value["targetSha256"],
                        resultSha256=control.digest(result), nextTargetSha256=control.digest(next_target),
                        nextTargetCipherSha256=sha256(raw["next-target.age"]).hexdigest(),
                        nextTargetArchiveSha256=sha256(payloads["archive"]).hexdigest(),
                        nextTargetLiveSha256=sha256(payloads["live"]).hexdigest())
        done = {"version": 2, "kind": "isolated-provider-mutation-completion", "runId": "101", "intentSha256": intent_sha,
                "responseSha256": sha256(raw["response.age"]).hexdigest(),
                "observationSha256": sha256(raw["observation.age"]).hexdigest(),
                "observationPlaintextSha256": control.digest(wrapped), "verification": verified,
                "originals": {name: sha256(raw[name]).hexdigest() for name in journal.V2_ORIGINALS}}
        raw["completion.json"] = control.canonical(done)
        return value, target, next_target, raw

    def test_keyless_bundle_reconstructs_original_and_rejects_tampering(self):
        value, target, next_target, original = self.complete_bundle()
        reader = Mock()
        reader.read.side_effect = original.get
        self.assertEqual(journal.keyless_bundle(reader, value)[:2], (target, next_target))
        reader.put_once.assert_not_called()
        for name in ("response.age", "next-target.age", "response.json", "next-target.json", "recipient-keys.json", "completion.json"):
            damaged = dict(original)
            damaged[name] = b"corrupted"
            reader.read.side_effect = damaged.get
            with self.subTest(name=name), self.assertRaises((control.ProviderError, control.github.ArtifactError)):
                journal.keyless_bundle(reader, value)
        missing = dict(original)
        del missing["next-target-live.json"]
        reader.read.side_effect = missing.get
        with self.assertRaises(control.ProviderError):
            journal.keyless_bundle(reader, value)

    def test_failure_keyless_pin_rejects_missing_reader_or_changed_original(self):
        intent = {"controllerRevision": "a" * 40, "candidateRevision": "b" * 40, "reviewedPr": "290"}
        files = {"failure-target.json": b"{}", "failure-observation.age": b"cipher", "failure-observation.json": b"{}"}
        pin = {"originalRunId": "101", "originalControllerRevision": "a" * 40, "readbackJobId": "201",
               "keylessReadbackJobId": "202", "evidenceVersion": 2}
        pin["keyedReceiptSha256"] = control.digest(journal.failure_keyed_projection("101", intent, files, "201"))
        pin["keylessReceiptSha256"] = control.digest(journal.failure_keyless_projection("101", intent, "201", pin["keyedReceiptSha256"], "202"))
        reader = Mock()
        reader.read.side_effect = files.get
        with patch.object(journal.digest_journal, "workflow_job") as job:
            files["failure-observation-plaintext.json"] = b"{}"
            pin["keyedReceiptSha256"] = control.digest(journal.failure_keyed_projection("101", intent, files, "201"))
            pin["keylessReceiptSha256"] = control.digest(journal.failure_keyless_projection("101", intent, "201", pin["keyedReceiptSha256"], "202"))
            reconcile.verify_failure_keyless(reader, set(files), intent, pin)
            job.assert_called_once()
            bad = deepcopy(files)
            bad["failure-observation.age"] = b"changed"
            reader.read.side_effect = bad.get
            with self.assertRaises(control.ProviderError):
                reconcile.verify_failure_keyless(reader, set(files), intent, pin)
            with self.assertRaises(control.ProviderError):
                reconcile.verify_failure_keyless(reader, set(files), intent, {k: v for k, v in pin.items() if k != "evidenceVersion"})
            with self.assertRaises(control.ProviderError):
                reconcile.verify_failure_keyless(reader, set(files) - {"failure-target.json"}, intent,
                                                  {k: v for k, v in pin.items() if k != "evidenceVersion"})

    def test_hosted_age_originals_survive_after_removing_identity(self):
        runner = os.environ.get("RUNNER_TEMP", "")
        age_dir = Path(runner) / "provider-age/usr/bin"
        if not runner or not (age_dir / "age").is_file() or not (age_dir / "age-keygen").is_file():
            self.skipTest("pinned hosted age package is unavailable")
        value, target, next_target, raw = self.complete_bundle()
        with tempfile.TemporaryDirectory(dir=runner) as directory:
            root = Path(directory)
            key = root / "key"
            subprocess.run([str(age_dir / "age-keygen"), "-o", str(key)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            recipient = subprocess.run([str(age_dir / "age-keygen"), "-y", str(key)], check=True,
                                       stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True).stdout.strip()
            identity = next(line for line in key.read_text().splitlines() if line.startswith("AGE-SECRET-KEY-1"))
            for plaintext, ciphertext in (("observation-plaintext.json", "observation.age"), ("response.json", "response.age"),
                                          ("next-target.json", "next-target.age")):
                source, destination = root / plaintext, root / ciphertext
                source.write_bytes(raw[plaintext])
                subprocess.run([str(age_dir / "age"), "-r", recipient, "-o", str(destination), str(source)],
                               check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                raw[ciphertext] = destination.read_bytes()
            wrapped = json.loads(raw["observation.json"])
            wrapped.update(observationCipherSha256=sha256(raw["observation.age"]).hexdigest(),
                           confirmedCipherSha256=sha256(raw["response.age"]).hexdigest())
            raw["observation.json"] = control.canonical(wrapped)
            done = json.loads(raw["completion.json"])
            done.update(responseSha256=sha256(raw["response.age"]).hexdigest(), observationSha256=sha256(raw["observation.age"]).hexdigest(),
                        observationPlaintextSha256=control.digest(wrapped))
            done["verification"]["nextTargetCipherSha256"] = sha256(raw["next-target.age"]).hexdigest()
            done["originals"] = {name: sha256(raw[name]).hexdigest() for name in journal.V2_ORIGINALS}
            raw["completion.json"] = control.canonical(done)
            with patch.dict(os.environ, {"RUNNER_TEMP": directory, "SUBS_BOT_PROVIDER_SOURCE_AGE_IDENTITY": identity}, clear=True), \
                    patch.object(journal.transfer.handoff, "age_binary", side_effect=lambda name: str(age_dir / name)):
                observed, confirmed = journal.response_plaintexts(target, value, raw["observation.age"], raw["response.age"])
                self.assertEqual(control.canonical(observed), raw["observation-plaintext.json"])
                self.assertEqual(control.canonical(confirmed), raw["response.json"])
                self.assertEqual(control.canonical(journal.checked_next_plaintext(target, value, confirmed, raw["next-target.age"])), raw["next-target.json"])
            reader = Mock()
            reader.read.side_effect = raw.get
            with patch.dict(os.environ, {}, clear=True):
                self.assertEqual(journal.keyless_bundle(reader, value)[:2], (target, next_target))
            reader.put_once.assert_not_called()

    def test_main_self_mutation_ledger_binds_candidate_to_dispatcher(self):
        row = {key: "a" * 64 for key in ("intentSha256", "responseSha256", "observationSha256", "observationPlaintextSha256",
                                          "completionSha256", "targetSha256", "readbackSha256")}
        row.update(controllerRevision="b" * 40, candidateRevision="b" * 40, reviewedPr="main",
                   operation="stage", readbackJobId="201")
        with patch.dict(os.environ, {"SUBS_BOT_PROVIDER_MUTATION_LEDGER_JSON": json.dumps({"101": row})}, clear=True):
            self.assertEqual(journal.ledger()["101"]["reviewedPr"], "main")
            row["candidateRevision"] = "c" * 40
            with patch.dict(os.environ, {"SUBS_BOT_PROVIDER_MUTATION_LEDGER_JSON": json.dumps({"101": row})}), \
                    self.assertRaises(control.ProviderError):
                journal.ledger()

    def test_reconciled_ledger_must_be_explicit_and_key_match_original_run(self):
        with patch.dict(os.environ, {}, clear=True), self.assertRaises((ValueError, KeyError)):
            journal.reconciled()
        with patch.dict(os.environ, {"SUBS_BOT_PROVIDER_MUTATION_RECONCILED_JSON": '{"101":{"pin":{"originalRunId":"102"}}}'}, clear=True), \
                self.assertRaises(control.ProviderError):
            journal.reconciled()
        with patch.dict(os.environ, {"SUBS_BOT_PROVIDER_MUTATION_RECONCILED_JSON": '{}'}, clear=True):
            self.assertEqual(journal.reconciled(), {})

    def test_stage_requires_exact_independently_registered_image_preparation(self):
        value = {"targetSha256": "a" * 64, "imagePreparationSha256": "b" * 64}
        registered = {"100": {"operation": "prepare-image", "targetSha256": "a" * 64,
                              "completionSha256": "c" * 64}}
        writer = Mock()
        env = {"GITHUB_RUN_ID": "101", "GITHUB_SHA": "d" * 40}
        with patch.dict(os.environ, env, clear=True), patch.object(journal, "planned", return_value=(None, None, "stage", value)), \
                patch.object(journal.digest_journal, "workflow_job"), patch.object(journal, "store", return_value=writer), \
                patch.object(journal, "inventory", return_value={"100": set()}), \
                patch.object(journal, "ledger", return_value=registered), \
                patch.object(journal, "history") as history, self.assertRaises(control.ProviderError):
            journal.write_intent()
        writer.put_once.assert_not_called()
        history.assert_not_called()

    def test_incomplete_verification_cannot_be_registered_as_completion(self):
        value = {"operation": "stage", "targetSha256": "a" * 64, "runId": "101"}
        verification = {"status": "independently-verified", "operation": "stage", "targetSha256": "a" * 64}
        env = {"SUBS_BOT_PROVIDER_MUTATION_VERIFICATION_JSON": json.dumps(verification),
               "SUBS_BOT_PROVIDER_MUTATION_RESPONSE_SHA256": "b" * 64}
        with patch.dict(os.environ, env, clear=True), self.assertRaises(control.ProviderError):
            journal.completion_value(value, {})

    def test_completion_binds_safe_original_and_both_cipher_digests(self):
        value = {"operation": "stage", "targetSha256": "a" * 64, "runId": "101"}
        verified = {key: "1" * 64 for key in journal.VERIFICATION_HASH_FIELDS}
        verified.update({"status": "independently-verified", "operation": "stage", "targetSha256": "a" * 64})
        original = {"confirmedCipherSha256": "b" * 64, "observationCipherSha256": "c" * 64,
                    "resultSha256": verified["resultSha256"]}
        env = {"SUBS_BOT_PROVIDER_MUTATION_VERIFICATION_JSON": json.dumps(verified),
               "SUBS_BOT_PROVIDER_MUTATION_RESPONSE_SHA256": "b" * 64}
        with patch.dict(os.environ, env, clear=True):
            completed = journal.completion_value(value, original)
            self.assertEqual(completed["observationSha256"], "c" * 64)
            self.assertEqual(completed["observationPlaintextSha256"], control.digest(original))
            with self.assertRaises(control.ProviderError):
                journal.completion_value(value, {**original, "confirmedCipherSha256": "0" * 64})

    def test_unknown_inventory_blocks_next_mutation(self):
        reader = Mock()
        with patch.object(journal.durable, "list_private_keys", return_value=[
                journal.BASE + "100/1/intent.json"]), patch.object(journal, "ledger", return_value={}), \
                patch.object(journal, "reconciled", return_value={}), patch.object(journal, "controllers", return_value=["d" * 40]), \
                self.assertRaises(control.ProviderError):
            journal.inventory(reader)

    def test_failure_evidence_is_single_write_and_does_not_create_completion(self):
        from hashlib import sha256
        value = {"kind": "fixture-intent"}
        raw = control.canonical(value)
        reader = Mock()
        reader.run_id = "101"
        reader.read.return_value = raw
        env = {"GITHUB_RUN_ID": "101", "GITHUB_SHA": "d" * 40,
               "SUBS_BOT_PROVIDER_MUTATION_INTENT_SHA256": sha256(raw).hexdigest()}
        original = {"confirmedCipherSha256": None}
        with patch.dict(os.environ, env, clear=True), patch.object(journal, "planned", return_value=(config(active=True), None, "stage", value)), \
                patch.object(journal, "store", return_value=reader), patch.object(journal, "inventory", return_value={"101": {"intent.json"}}), \
                patch.object(journal, "download_response", return_value=b"encrypted observation"), \
                patch.object(journal, "response_plaintexts", return_value=({"fixture": "observation"}, None)), \
                patch.object(journal, "response_original", return_value=original), patch.object(journal.digest_journal, "output"):
            journal.failure_evidence()
        self.assertEqual([call.args[0] for call in reader.put_once.call_args_list],
                         ["failure-observation.age", "failure-observation-plaintext.json", "failure-target.json", "failure-observation.json"])

    def test_failure_evidence_accepts_absent_verify_outputs_and_never_overwrites_completed_bundle(self):
        value = {"kind": "fixture-intent"}
        raw = control.canonical(value)
        env = {"GITHUB_RUN_ID": "101", "GITHUB_SHA": "d" * 40,
               "SUBS_BOT_PROVIDER_MUTATION_INTENT_SHA256": sha256(raw).hexdigest()}
        reader = Mock()
        reader.read.return_value = raw
        with patch.dict(os.environ, env, clear=True), patch.object(journal, "planned", return_value=(config(active=True), None, "stage", value)), \
                patch.object(journal, "store", return_value=reader), \
                patch.object(journal, "inventory", return_value={"101": journal.V1_FILES | journal.V2_ORIGINALS}), \
                patch.object(journal, "download_response", return_value=b"observation cipher"), \
                patch.object(journal, "response_plaintexts", return_value=({"fixture": "observation"}, None)), \
                patch.object(journal, "response_original", return_value={"confirmedCipherSha256": None}), \
                patch.object(journal.digest_journal, "output"):
            journal.failure_evidence()
        written = {call.args[0] for call in reader.put_once.call_args_list}
        self.assertEqual(written, {"failure-observation.age", "failure-observation-plaintext.json", "failure-target.json", "failure-observation.json"})
        self.assertFalse(written & (journal.V1_FILES | journal.V2_ORIGINALS))

    def test_incomplete_next_artifact_pin_stops_and_keeps_only_unknown_evidence(self):
        value = {"kind": "fixture-intent"}
        raw = control.canonical(value)
        env = {"GITHUB_RUN_ID": "101", "GITHUB_SHA": "d" * 40,
               "SUBS_BOT_PROVIDER_MUTATION_INTENT_SHA256": sha256(raw).hexdigest(),
               "SUBS_BOT_PROVIDER_NEXT_AGE_ARTIFACT_ID": "456"}
        reader = Mock()
        reader.read.return_value = raw
        with patch.dict(os.environ, env, clear=True), patch.object(journal, "planned", return_value=(config(active=True), None, "stage", value)), \
                patch.object(journal, "store", return_value=reader), patch.object(journal, "inventory", return_value={"101": {"intent.json"}}), \
                patch.object(journal, "download_response", return_value=b"observation cipher"), \
                patch.object(journal, "response_plaintexts", return_value=({"fixture": "observation"}, None)), \
                patch.object(journal, "response_original", return_value={"confirmedCipherSha256": None}), \
                patch.object(journal, "download_next_artifact") as download, self.assertRaises(control.ProviderError):
            journal.failure_evidence()
        download.assert_not_called()
        self.assertNotIn("completion.json", {call.args[0] for call in reader.put_once.call_args_list})

    def test_unreadable_observation_preserves_authenticated_cipher_only(self):
        value = {"kind": "fixture-intent"}
        raw = control.canonical(value)
        env = {"GITHUB_RUN_ID": "101", "GITHUB_SHA": "d" * 40,
               "SUBS_BOT_PROVIDER_MUTATION_INTENT_SHA256": sha256(raw).hexdigest()}
        reader = Mock()
        reader.read.return_value = raw
        with patch.dict(os.environ, env, clear=True), patch.object(journal, "planned", return_value=(config(active=True), None, "stage", value)), \
                patch.object(journal, "store", return_value=reader), patch.object(journal, "inventory", return_value={"101": {"intent.json"}}), \
                patch.object(journal, "download_response", return_value=b"authenticated cipher"), \
                patch.object(journal, "response_plaintexts", side_effect=control.ProviderError("fixture")), \
                self.assertRaises(control.ProviderError):
            journal.failure_evidence()
        reader.put_once.assert_called_once_with("failure-observation.age", b"authenticated cipher")

    def test_readonly_resolution_requires_every_writing_job_skipped_and_empty_prefix(self):
        revision, run_id = "d" * 40, "101"
        run = {"id": 101, "run_attempt": 1, "head_sha": revision, "path": journal.WORKFLOW,
               "head_branch": "main", "event": "workflow_dispatch", "status": "completed", "conclusion": "failure",
               "repository": {"id": control.github.REPOSITORY_ID}, "head_repository": {"id": control.github.REPOSITORY_ID}}
        jobs = [{"name": name, "id": 200 + index, "run_id": 101, "run_attempt": 1, "head_sha": revision,
                 "status": "completed", "conclusion": "skipped", "steps": []}
                for index, name in enumerate(journal.JOBS.values())]
        reader = Mock(target={"bucket": "fixture"})
        def get(path, _token):
            return {"jobs": jobs, "total_count": len(jobs)} if path.endswith("jobs?per_page=100") else run
        with patch.object(control.github, "_github_token", return_value="fixture"), patch.object(control.github, "_get_json", side_effect=get), \
                patch.object(journal.durable, "source_ancestor"), patch.object(journal.durable, "list_private_keys", return_value=[]) as listing:
            report = journal.inspect_readonly_run(reader, run_id, [revision])
            self.assertEqual(report["objectCount"], 0)
            job = next(row for row in jobs if row["name"] == journal.JOBS["failure-write"])
            job["conclusion"] = "failure"
            with self.assertRaises(control.ProviderError):
                journal.inspect_readonly_run(reader, run_id, [revision])
            job["conclusion"] = "skipped"
            listing.return_value = [journal.BASE + run_id + "/1/intent.json"]
            with self.assertRaises(control.ProviderError):
                journal.inspect_readonly_run(reader, run_id, [revision])
            listing.return_value = []
            def rerun_get(path, token):
                if path == f"/actions/runs/{run_id}":
                    return {**run, "run_attempt": 2}
                return get(path, token)
            with patch.object(control.github, "_get_json", side_effect=rerun_get), self.assertRaises(control.ProviderError):
                journal.inspect_readonly_run(reader, run_id, [revision])

    def test_decrypted_response_original_is_strict_and_bound_to_both_ciphers(self):
        target = config(active=True)
        value = {"runId": "101", "operation": "stage", "controllerRevision": "a" * 40,
                 "candidateRevision": "b" * 40, "reviewedPr": "290", "targetSha256": control.digest(target)}
        obs = {"kind": "response-only", "method": "POST", "path": f"/workers/scripts/{target['service']}/versions",
               "identities": {"versionId": "11111111-1111-1111-1111-111111111111"}}
        first = {"intentSha256": control.digest(value), "observation": obs}
        result_state = {"activation": target["activation"], "container": target["container"], "workflow": target["workflow"],
                        "instance": None, "versionId": "11111111-1111-1111-1111-111111111111"}
        confirmed = {"intentSha256": control.digest(value), "target": target, "operation": "stage", "observation": obs, "result": result_state}
        with patch.object(journal, "decrypt_record", side_effect=[first, confirmed]):
            result = journal.response_original(target, value, b"observation", b"confirmed")
        self.assertEqual(result["observation"], obs)
        self.assertNotIn("target", result)
        first["observation"] = {**obs, "token": "synthetic"}
        with patch.object(journal, "decrypt_record", return_value=first), self.assertRaises(control.ProviderError):
            journal.response_original(target, value, b"observation")


if __name__ == "__main__":
    unittest.main()
