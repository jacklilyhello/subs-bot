"""Hosted-only isolation checks for encrypted Provider source transport."""

from hashlib import sha256
from contextlib import nullcontext
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
from zipfile import ZIP_STORED, ZipFile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import production_provider as control
import provider_source_transfer as transfer
from test_production_provider import config
import test_prepare_provider_artifact as artifact_fixture


class SourceTransferTests(unittest.TestCase):
    def test_reviewed_dispatch_keeps_candidate_and_main_separate(self):
        main, head = "a" * 40, "b" * 40
        refs = [{"fixture": "pinned"}]
        spec = {"version": 1, "pr": "290", "headSha": head, "providerCiRunId": "101", "approvalSha256": "1" * 64,
                "archiveRefs": refs, "simulateActionsUnavailable": True}
        env = {"GITHUB_WORKFLOW_REF": f"{control.github.REPOSITORY}/{transfer.REVIEWED_WORKFLOW_PATH}@{control.github.MAIN_REF}",
               "PROVIDER_HEAD_VALIDATION_JSON": json.dumps(spec), "PROVIDER_HEAD_REVIEWED_SHA": head,
               "PROVIDER_HEAD_TRUSTED_MAIN_SHA": main, "SUBS_BOT_PROVIDER_CI_RUN_ID": "101",
               "SUBS_BOT_PROVIDER_DIGEST_APPROVAL": "1" * 64, "SUBS_BOT_PROVIDER_SIMULATE_ARTIFACT_UNAVAILABLE": "1",
               "SUBS_BOT_PROVIDER_ARCHIVE_REFS": json.dumps(refs), "SUBS_BOT_PROVIDER_TRUSTED_ARCHIVE_REFS_JSON": json.dumps(refs)}
        with patch.dict(os.environ, env, clear=True):
            self.assertEqual(transfer.execution_identity(main), {"workflowPath": transfer.REVIEWED_WORKFLOW_PATH,
                                                                  "candidateRevision": head, "reviewedPr": "290"})
            for change in ({"PROVIDER_HEAD_REVIEWED_SHA": main}, {"PROVIDER_HEAD_TRUSTED_MAIN_SHA": head},
                           {"SUBS_BOT_PROVIDER_DIGEST_APPROVAL": "2" * 64},
                           {"SUBS_BOT_PROVIDER_TRUSTED_ARCHIVE_REFS_JSON": "[]"}):
                with self.subTest(change=change), patch.dict(os.environ, change), self.assertRaises(control.ProviderError):
                    transfer.execution_identity(main)
            source_spec = {**spec, "simulateActionsUnavailable": False}
            source_env = {"GITHUB_WORKFLOW_REF": f"{control.github.REPOSITORY}/{transfer.REVIEWED_SOURCE_WORKFLOW_PATH}@{control.github.MAIN_REF}",
                          "PROVIDER_HEAD_VALIDATION_JSON": json.dumps(source_spec), "SUBS_BOT_PROVIDER_SIMULATE_ARTIFACT_UNAVAILABLE": "0"}
            with patch.dict(os.environ, source_env):
                self.assertEqual(transfer.execution_identity(main)["workflowPath"], transfer.REVIEWED_SOURCE_WORKFLOW_PATH)
                with patch.dict(os.environ, {"SUBS_BOT_PROVIDER_SIMULATE_ARTIFACT_UNAVAILABLE": "1"}), self.assertRaises(control.ProviderError):
                    transfer.execution_identity(main)

    def test_exact_target_approval_and_unbound_caller_are_required(self):
        target = config(active=True)
        env = {"SUBS_BOT_PROVIDER_CI_RUN_ID": target["build"]["runId"], "SUBS_BOT_PROVIDER_DURABLE_REQUIRED": "1",
               "SUBS_BOT_PROVIDER_DIGEST_APPROVAL": control.digest({"operation": "publish-digest", "target": target})}
        with patch.dict(os.environ, env, clear=True), patch.object(control, "read_config", return_value=target):
            self.assertEqual(transfer.target(), target)
            for key, bad in (("SUBS_BOT_PROVIDER_DIGEST_APPROVAL", "0" * 64), ("SUBS_BOT_PROVIDER_CI_RUN_ID", "999")):
                with patch.dict(os.environ, {key: bad}), self.assertRaises(control.ProviderError):
                    transfer.target()
            with patch.dict(target, {"caller": {"fixture": "bound"}}), self.assertRaises(control.ProviderError):
                transfer.target()

    def test_recipient_and_refs_are_independently_pinned(self):
        recipient = "age1" + "q" * 58
        env = {"SUBS_BOT_PROVIDER_SOURCE_RECIPIENT": recipient,
               "SUBS_BOT_PROVIDER_SOURCE_RECIPIENT_SHA256": sha256(recipient.encode()).hexdigest(),
               "SUBS_BOT_PROVIDER_ARCHIVE_REFS": json.dumps([{"fixture": "pinned"}]),
               "SUBS_BOT_PROVIDER_TRUSTED_ARCHIVE_REFS_JSON": json.dumps([{"fixture": "pinned"}])}
        with patch.dict(os.environ, env, clear=True):
            self.assertEqual(transfer.recipient(), recipient)
            self.assertEqual(transfer.refs(), [{"fixture": "pinned"}])
            with patch.dict(os.environ, {"SUBS_BOT_PROVIDER_SOURCE_RECIPIENT_SHA256": "0" * 64}), \
                    self.assertRaises(control.ProviderError):
                transfer.recipient()
            with patch.dict(os.environ, {"SUBS_BOT_PROVIDER_TRUSTED_ARCHIVE_REFS_JSON": "[]"}), \
                    self.assertRaises(control.ProviderError):
                transfer.refs()

    def test_wrong_artifact_origin_is_rejected_before_download(self):
        revision = "b" * 40
        env = {"SUBS_BOT_PROVIDER_SOURCE_ARTIFACT_ID": "42", "SUBS_BOT_PROVIDER_SOURCE_ARTIFACT_SHA256": "d" * 64,
               "SUBS_BOT_PROVIDER_SOURCE_CIPHER_SHA256": "e" * 64, "GITHUB_RUN_ID": "101", "GITHUB_SHA": revision,
               "SUBS_BOT_PROVIDER_TRUSTED_SOURCE_ARTIFACT_ID": "42", "SUBS_BOT_PROVIDER_TRUSTED_SOURCE_ARTIFACT_SHA256": "d" * 64,
               "SUBS_BOT_PROVIDER_TRUSTED_SOURCE_CIPHER_SHA256": "e" * 64}
        bad = {"id": 42, "expired": False, "name": "provider-encrypted-source-101-1", "digest": "sha256:" + "d" * 64,
               "workflow_run": {"id": 101, "head_branch": "main", "head_sha": "c" * 40,
                                "repository_id": control.github.REPOSITORY_ID, "head_repository_id": control.github.REPOSITORY_ID}}
        with patch.dict(os.environ, env, clear=True), patch.object(control.github, "_github_token", return_value="synthetic"), \
                patch.object(control.github, "_get_json", return_value=bad), \
                patch.object(control.github, "artifact_storage_request") as request, self.assertRaises(control.ProviderError):
            transfer.download_cipher()
        request.assert_not_called()

    def test_source_zip_refuses_trailing_or_excess_members(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "source.zip"
            with ZipFile(path, "w", compression=ZIP_STORED) as archive:
                archive.writestr("fixture", b"fixture")
            transfer.strict_zip_end(path, 1)
            with self.assertRaises(control.ProviderError):
                transfer.strict_zip_end(path, 0)
            with path.open("ab") as output:
                output.write(b"unapproved trailing bytes")
            with self.assertRaises(control.ProviderError):
                transfer.strict_zip_end(path, 1)

    def test_insufficient_scratch_stops_before_reading_private_archive(self):
        with tempfile.TemporaryDirectory() as temporary, patch.dict(os.environ, {"RUNNER_TEMP": temporary}, clear=True), \
                patch.object(transfer, "context"), patch.object(transfer, "target", return_value=config(active=True)), \
                patch.object(transfer.shutil, "disk_usage", return_value=Mock(free=0)), \
                patch.object(transfer.durable, "restore") as restore, self.assertRaises(control.ProviderError):
            transfer.produce()
        restore.assert_not_called()

    def test_hosted_age_roundtrip_reverifies_current_and_previous_originals(self):
        runner = Path(os.environ.get("RUNNER_TEMP", ""))
        age_dir = runner / "provider-age/usr/bin"
        if not (age_dir / "age").is_file() or not (age_dir / "age-keygen").is_file():
            self.skipTest("pinned hosted age package is unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            producer, receiver = root / "producer", root / "receiver"
            producer.mkdir()
            receiver.mkdir()
            source_dir = producer / "provider-durable-sources"
            source_dir.mkdir(mode=0o700)
            key_path = root / "age-key"
            subprocess.run([str(age_dir / "age-keygen"), "-o", str(key_path)], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            recipient = subprocess.run([str(age_dir / "age-keygen"), "-y", str(key_path)], check=True,
                                       stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True).stdout.strip()
            identity = next(line for line in key_path.read_text().splitlines() if line.startswith("AGE-SECRET-KEY-1"))
            requirements = Path(control.provider.__file__).with_name("requirements.txt")
            def release(revision, run_id, artifact_id):
                scratch = root / ("release-" + run_id)
                scratch.mkdir()
                with patch.object(artifact_fixture, "REVISION", revision):
                    (scratch / control.provider.IMAGE).write_bytes(artifact_fixture.oci_fixture())
                (scratch / control.provider.WORKER).write_bytes(b"export default {};\n")
                manifest = control.provider.release_manifest(scratch, revision, requirements, ref=control.github.MAIN_REF,
                                                              run_id=run_id, run_attempt="1")
                members = {name: (scratch / name).read_bytes() for name in (control.provider.IMAGE, control.provider.WORKER)}
                members[control.provider.MANIFEST] = artifact_fixture.encoded(manifest)
                original = artifact_fixture.zip_fixture(members)
                build = {"revision": revision, "runId": run_id, "runAttempt": "1", "artifactId": artifact_id,
                         "archiveSha256": sha256(original).hexdigest(),
                         **{key: manifest[key] for key in control.publication.MANIFEST_FIELDS}}
                (source_dir / (build["archiveSha256"] + ".zip")).write_bytes(original)
                return build
            previous = config(active=True)
            previous["build"] = release("b" * 40, "101", "201")
            current = config()
            current["build"] = release("7" * 40, "102", "202")
            current.update({"versionId": None, "container": previous["container"], "workflow": None, "previous": previous})
            rows = [{"build": item["build"], "target": item} for item in (current, previous)]
            (source_dir / "index.json").write_bytes(control.canonical(rows))
            refs = [{"kind": "complete", "runId": "201", "runAttempt": "1", "manifestSha256": "1" * 64,
                     "targetSha256": control.digest(current)},
                    {"kind": "partial", "runId": "202", "runAttempt": "1", "manifestSha256": "2" * 64,
                     "targetSha256": control.digest(previous)}]
            comparison = {"status": "ahead", "ahead_by": 1, "behind_by": 0,
                          "base_commit": {"sha": previous["build"]["revision"]},
                          "merge_base_commit": {"sha": previous["build"]["revision"]}}
            env = {"RUNNER_TEMP": str(producer), "GITHUB_OUTPUT": str(root / "output"), "GITHUB_RUN_ID": "501",
                   "GITHUB_SHA": current["build"]["revision"], "SUBS_BOT_PROVIDER_CONTROL_TARGET_JSON": json.dumps(current),
                   "SUBS_BOT_PROVIDER_CI_RUN_ID": "102", "SUBS_BOT_PROVIDER_DURABLE_REQUIRED": "1",
                   "SUBS_BOT_PROVIDER_DIGEST_APPROVAL": control.digest({"operation": "publish-digest", "target": current}),
                   "SUBS_BOT_PROVIDER_ARCHIVE_REFS": json.dumps(refs), "SUBS_BOT_PROVIDER_TRUSTED_ARCHIVE_REFS_JSON": json.dumps(refs),
                   "SUBS_BOT_PROVIDER_SOURCE_RECIPIENT": recipient,
                   "SUBS_BOT_PROVIDER_SOURCE_RECIPIENT_SHA256": sha256(recipient.encode()).hexdigest(),
                   "SUBS_BOT_PROVIDER_SOURCE_AGE_IDENTITY": identity}
            def age_binary(name):
                return age_dir / name
            with patch.dict(os.environ, env, clear=True), patch.object(transfer, "context"), \
                    patch.object(transfer.durable, "restore"), patch.object(transfer.handoff, "age_binary", side_effect=age_binary), \
                    patch.object(control.github, "require_current_main"), patch.object(control.github, "verify_main_run"), \
                    patch.object(control.github, "_github_token", return_value="synthetic"), \
                    patch.object(control.github, "_get_json", return_value=comparison), \
                    patch.object(control.provenance, "source_requirements", side_effect=lambda _revision: nullcontext(requirements)):
                transfer.produce()
            cipher = receiver / "received.age"
            shutil.copyfile(producer / "provider-source-transfer.age", cipher)
            with patch.dict(os.environ, {**env, "RUNNER_TEMP": str(receiver)}, clear=True), patch.object(transfer, "context"), \
                    patch.object(transfer, "download_cipher", return_value=cipher), patch.object(transfer.handoff, "age_binary", side_effect=age_binary), \
                    patch.object(control.github, "require_current_main"), patch.object(control.github, "verify_main_run"), \
                    patch.object(control.github, "_github_token", return_value="synthetic"), \
                    patch.object(control.github, "_get_json", return_value=comparison), \
                    patch.object(control.provenance, "source_requirements", side_effect=lambda _revision: nullcontext(requirements)):
                transfer.receive()
                self.assertEqual(control.durable_builds(), rows)
            corrupt_root = root / "corrupt"
            corrupt_root.mkdir()
            broken = corrupt_root / "broken.age"
            data = cipher.read_bytes()
            broken.write_bytes(data[:-1] + bytes([data[-1] ^ 1]))
            with patch.dict(os.environ, {**env, "RUNNER_TEMP": str(corrupt_root)}, clear=True), \
                    patch.object(transfer, "context"), patch.object(transfer, "download_cipher", return_value=broken), \
                    patch.object(transfer.handoff, "age_binary", side_effect=age_binary), self.assertRaises(control.ProviderError):
                transfer.receive()
            self.assertFalse((corrupt_root / "provider-durable-sources").exists())
            other_key = root / "wrong-age-key"
            subprocess.run([str(age_dir / "age-keygen"), "-o", str(other_key)], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            wrong_identity = next(line for line in other_key.read_text().splitlines() if line.startswith("AGE-SECRET-KEY-1"))
            wrong_root = root / "wrong-recipient"
            wrong_root.mkdir()
            with patch.dict(os.environ, {**env, "RUNNER_TEMP": str(wrong_root), "SUBS_BOT_PROVIDER_SOURCE_AGE_IDENTITY": wrong_identity}, clear=True), \
                    patch.object(transfer, "context"), patch.object(transfer, "download_cipher", return_value=cipher), \
                    patch.object(transfer.handoff, "age_binary", side_effect=age_binary), self.assertRaises(control.ProviderError):
                transfer.receive()
            self.assertFalse((wrong_root / "provider-durable-sources").exists())


if __name__ == "__main__":
    unittest.main()
