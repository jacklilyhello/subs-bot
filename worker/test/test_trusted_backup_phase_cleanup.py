"""Synthetic independent checks for trusted reviewed-phase cleanup evidence."""
from datetime import datetime, timezone
from hashlib import sha256
from io import BytesIO
from pathlib import Path
import sys
import time
import unittest
from unittest.mock import Mock, patch
from zipfile import ZipFile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import trusted_backup_phase_cleanup as cleanup
from production_target import ContractError, canonical


class TrustedPhaseCleanupTests(unittest.TestCase):
    def fixture(self):
        target, main, candidate, session = "a" * 64, "b" * 40, "c" * 40, "123"
        source, manifest, validation, limit = "d" * 32, "e" * 64, '{"synthetic":true}', 1800
        store = Mock()
        store.objects = Mock()
        data, runs, results = {}, [], []
        policy = {"pauseLimitSeconds": 300}
        start = {"version": 1, "action": "run", "targetSha256": target, "session": session,
                 "controlRevision": main, "candidateRevision": candidate, "profile": "rehearsal",
                 "validationSha256": sha256(validation.encode()).hexdigest(), "sourceCheckpointId": source,
                 "sourceManifestSha256": manifest, "policySha256": sha256(canonical(policy)).hexdigest(),
                 "writerRunId": "999", "writerAttempt": "1"}
        data[cleanup.BASE + target + "/" + session + "/start-intent.json"] = canonical(start)
        now = int(time.time()) - 5
        created = datetime.fromtimestamp(now, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        pause_until = None
        statuses = {"plan-begin": "plan-only", "begin": "started", "preflight": "observed", "pause": "paused",
                    "drain": "drained", "freeze": "frozen", "capture": "captured-unverified", "verify": "verified", "activate": "resumed"}
        for i, action in enumerate(cleanup.STEPS, 1):
            nonce, run_id = (hex(i)[2:] * 64)[:64], str(200 + i)
            inputs = {"action": action, "source_checkpoint_id": source, "source_manifest_sha256": manifest}
            if results:
                inputs.update(session="201-1", session_day="2026/11/18")
            index = {"begin": 0, "preflight": 0, "pause": 3, "freeze": 5, "capture": 6, "verify": 6, "activate": 9}.get(action)
            if index is not None:
                inputs["state_sha256"] = results[index]["stateSha256"]
            if action == "pause":
                pause_until = now + limit
            inputs.update(dispatch_nonce=nonce, coordinator_session=session, dispatch_deadline=str(pause_until or 0), validation_json=validation)
            intent = {"version": 1, "kind": "backup-dispatch-intent", "targetSha256": target, "session": session,
                      "sequence": i, "action": action, "controllerRevision": main, "candidateRevision": candidate,
                      "profile": "rehearsal", "nonce": nonce, "inputSha256": sha256(canonical(inputs)).hexdigest(),
                      "createdAt": now, "writerRunId": "999", "writerAttempt": "1"}
            intent_sha = sha256(canonical(intent)).hexdigest()
            claim = {"version": 1, "kind": "backup-dispatch-child-claim", "intentSha256": intent_sha,
                     "targetSha256": target, "session": session, "sequence": i, "nonce": nonce, "profile": "rehearsal",
                     "controllerRevision": main, "candidateRevision": candidate, "childRunId": run_id, "childAttempt": "1"}
            result = {"action": action, "targetSha256": target, "controlRevision": candidate, "dispatcherRevision": main,
                      "consumerSwitch": "not-authorized", "automaticReplay": False, "stateSha256": "f" * 64}
            if action in statuses:
                result["status"] = statuses[action]
            if action == "plan-begin":
                result.update(session="201-1", day="2026/11/18")
            if action == "verify":
                result.update(checkpointId="1" * 32, manifestSha256="2" * 64)
            if action == "activate":
                result.update(pauseSeconds=42, pauseLimitExceeded=False)
            buffer = BytesIO()
            with ZipFile(buffer, "w") as archive:
                archive.writestr("production-backup-result.json", canonical(result))
            raw_zip = buffer.getvalue()
            receipt = {"version": 1, "kind": "backup-dispatch-receipt", "intentSha256": intent_sha, "runId": run_id,
                       "runAttempt": "1", "resultSha256": sha256(canonical(result)).hexdigest(), "result": result,
                       "artifactId": str(500 + i), "artifactSha256": sha256(raw_zip).hexdigest()}
            root = cleanup.BASE + target + "/" + session + "/" + str(i).zfill(2)
            data.update({root + "-intent.json": canonical(intent), root + "-child-claim.json": canonical(claim),
                         root + "-receipt.json": canonical(receipt), root + "-result.zip": raw_zip})
            runs.append({"id": int(run_id), "display_title": "Rehearsal backup " + action + " at " + main + " candidate " + candidate + " #" + nonce,
                         "created_at": created, "path": cleanup.CHILD, "workflow_id": 42, "head_sha": main, "head_branch": "main",
                         "event": "workflow_dispatch", "run_attempt": 1, "status": "completed", "conclusion": "success",
                         "repository": {"id": cleanup.github.REPOSITORY_ID}, "head_repository": {"id": cleanup.github.REPOSITORY_ID}})
            results.append(result)
        store.objects.get.side_effect = lambda key: (data[key], '"synthetic"')
        receipt = {"planBeginSession": "201-1", "planBeginDay": "2026/11/18", "checkpointId": "1" * 32,
                   "manifestSha256": "2" * 64, "pauseSeconds": 42, "pauseLimitExceeded": False}
        def api(path, _token):
            if path == "/actions/workflows/worker-backup-phase-rehearsal.yml":
                return {"path": cleanup.CHILD, "id": 42}
            if path.startswith("/actions/workflows/worker-backup-phase-rehearsal.yml/runs?"):
                return {"total_count": len(runs), "workflow_runs": runs}
            run_id = path.split("/")[3]
            if path.endswith("/attempts/1/jobs?per_page=100"):
                names = ("Verify trusted phase identity before candidate checkout", "Verify exact reviewed phase checkout",
                         "Verify isolated test Bot identity", "Execute one reviewed rehearsal phase")
                job = {"name": "phase", "run_id": int(run_id), "run_attempt": 1, "head_sha": main, "status": "completed",
                       "conclusion": "success", "steps": [{"name": name, "status": "completed", "conclusion": "success"} for name in names]}
                return {"total_count": 1, "jobs": [job]}
            return {"id": int(run_id), "run_attempt": 1, "status": "completed"}
        def execute():
            with patch.object(cleanup.github, "_get_json", side_effect=api):
                return cleanup.child_evidence(store, target, session, main, candidate, "synthetic", source_checkpoint=source,
                    source_manifest=manifest, validation_json=validation, policy=policy, writer_run_id="999", parent_receipt=receipt)
        return execute, data, runs, receipt

    def test_full_private_chain_and_original_jobs_are_required(self):
        execute, data, runs, receipt = self.fixture()
        self.assertRegex(execute(), r"^[a-f0-9]{64}$")
        runs[4]["status"] = "in_progress"
        with self.assertRaises(ContractError):
            execute()
        runs[4]["status"] = "completed"
        receipt["manifestSha256"] = "3" * 64
        with self.assertRaises(ContractError):
            execute()
        receipt["manifestSha256"] = "2" * 64
        key = next(key for key in data if key.endswith("-child-claim.json"))
        data[key] = b"{}"
        with self.assertRaises(ContractError):
            execute()
