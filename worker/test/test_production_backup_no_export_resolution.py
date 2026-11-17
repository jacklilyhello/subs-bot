import hashlib
import base64
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import production_backup_no_export_resolution as resolution

SEAL = {"runId": "123", "runAttempt": "1", "dispatcherRevision": "c" * 40, "controlRevision": "d" * 40}

class MemoryStore:
    def __init__(self):
        self.items = {}

    def put_exclusive(self, key, raw):
        if key in self.items:
            raise ValueError("occupied")
        self.items[key] = raw

    def get(self, key):
        return self.items[key]


class NoExportEvidenceTests(unittest.TestCase):
    def test_original_log_binds_exact_old_candidate_and_private_source(self):
        spec = {"version": 1, "pr": "291", "headSha": resolution.OLD_HEAD, "action": "backup",
                "fault": "readback-failure", "approvalSha256": "f" * 64, "checkpointId": "",
                "manifestSha256": "", "genesisSha256": "a" * 64, "registrationSha256": "b" * 64,
                "sourceCheckpointId": "c" * 32, "sourceManifestSha256": "d" * 64}
        line = "timestamp HEAD_VALIDATION_JSON: " + json.dumps(spec) + "\n"
        raw = (line * 4).encode()
        review = {"candidateCodeSha256": {"candidate.py": hashlib.sha256(b"source").hexdigest()},
                  "dispatcherCodeSha256": {"trusted.py": hashlib.sha256(b"source").hexdigest()},
                  "sourceLogSha256": hashlib.sha256(raw).hexdigest()}
        def get(path, _token):
            name = path.split("/contents/", 1)[1].split("?", 1)[0]
            return {"path": name, "type": "file", "encoding": "base64", "size": 6,
                    "content": base64.b64encode(b"source").decode()}
        with patch.object(resolution.github, "_get_json", side_effect=get), \
                patch.object(resolution, "OLD_LOG_SHA", review["sourceLogSha256"]):
            originals = resolution.historical_originals(review, spec, "token", lambda *_: raw)
            self.assertEqual(originals["original-job-log"], raw)
            wrong = dict(spec, sourceManifestSha256="e" * 64)
            with self.assertRaises(Exception):
                resolution.historical_originals(review, wrong, "token", lambda *_: raw)
            with self.assertRaises(Exception):
                resolution.historical_originals(review, spec, "token", lambda *_: raw[:-1])

    def test_originals_are_sealed_once_and_rechecked_byte_for_byte(self):
        store = MemoryStore()
        originals = {"candidate/code": b"private source", "original-job-log": b"private log" * 75000}
        guard = Mock()
        evidence = resolution.seal_originals(store, "private/", "a" * 64, originals, SEAL, guard)
        self.assertEqual(resolution.read_originals(store, "private/", "a" * 64, originals, SEAL, evidence), evidence)
        self.assertGreater(guard.call_count, 3)
        with self.assertRaises(ValueError):
            resolution.seal_originals(store, "private/", "a" * 64, originals, SEAL, guard)
        self.assertEqual(len([key for key in store.items if key.endswith("evidence-intent.json")]), 1)
        store.items["private/objects/002/001"] += b"corrupt"
        with self.assertRaises(Exception):
            resolution.read_originals(store, "private/", "a" * 64, originals, SEAL, evidence)

    def test_changed_plan_or_fresh_originals_rejected(self):
        store = MemoryStore()
        evidence = resolution.seal_originals(store, "private/", "a" * 64, {"original-job-log": b"one"}, SEAL, lambda: None)
        with self.assertRaises(Exception):
            resolution.read_originals(store, "private/", "b" * 64, {"original-job-log": b"one"}, SEAL, evidence)
        with self.assertRaises(Exception):
            resolution.read_originals(store, "private/", "a" * 64, {"original-job-log": b"two"}, SEAL, evidence)
        self.assertNotEqual(evidence, hashlib.sha256(b"one").hexdigest())

    def test_current_entrypoint_is_fail_closed(self):
        with self.assertRaises(Exception):
            resolution.main()

    def test_original_seal_and_fresh_reader_are_both_required(self):
        main, candidate, run_id = "c" * 40, "d" * 40, "123"
        def job(name, final):
            return {"name": name, "run_id": 123, "run_attempt": 1, "head_sha": main,
                    "status": "completed", "conclusion": "success", "steps": [
                        {"name": step, "status": "completed", "conclusion": "success"}
                        for step in (*resolution.GATES, final)]}
        jobs = [job("resolution", "Plan or apply the no-export resolution"),
                job("readback", "Independently verify no-export evidence")]
        run = {"id": 123, "run_attempt": 1, "workflow_id": 5, "event": "workflow_dispatch",
               "head_branch": "main", "head_sha": main, "status": "completed", "conclusion": "success",
               "repository": {"id": resolution.github.REPOSITORY_ID},
               "display_title": "No-export seal at " + main + " candidate " + candidate}
        def get(path, _token):
            if path.startswith("/actions/workflows/"):
                return {"id": 5}
            if path.endswith("/attempts/1"):
                return run
            if path == "/actions/runs/123":
                return run
            return {"total_count": len(jobs), "jobs": jobs}
        with patch.object(resolution.github, "_github_token", return_value="token"), \
                patch.object(resolution.github, "_get_json", side_effect=get):
            resolution.verify_jobs(run_id, main, candidate, "seal")
            jobs[1]["steps"][-1]["conclusion"] = "failure"
            with self.assertRaises(Exception):
                resolution.verify_jobs(run_id, main, candidate, "seal")
            jobs.pop()
            with self.assertRaises(Exception):
                resolution.verify_jobs(run_id, main, candidate, "seal")

    def test_release_claim_is_unique_and_never_retries_unknown_journal_write(self):
        plan = {"version": 1, "kind": "synthetic-plan"}
        plan_sha = hashlib.sha256(resolution.canonical(plan)).hexdigest()
        review = {"targetSha256": "a" * 64, "oldAnchorSha256": hashlib.sha256(b"active").hexdigest(),
                  "threatModel": "reviewed-writers-no-unapproved-deletion"}
        spec = {"headSha": "b" * 40}
        env = {"NO_EXPORT_ACTION": "release", "NO_EXPORT_VALIDATION_JSON": json.dumps(spec),
               "NO_EXPORT_SEAL_RUN_ID": "123", "SUBS_BOT_BACKUP_NO_EXPORT_SEAL_RUN_ID": "123",
               "NO_EXPORT_PLAN_SHA256": plan_sha, "NO_EXPORT_PROTECTED_PLAN_SHA256": plan_sha,
               "NO_EXPORT_EVIDENCE_SHA256": "c" * 64, "NO_EXPORT_PROTECTED_EVIDENCE_SHA256": "c" * 64,
               "GITHUB_RUN_ID": "456", "GITHUB_SHA": "d" * 40}
        store, journal, anchor, controller = Mock(), Mock(), Mock(), Mock()
        state = {"control": {"admission": "closed", "workers": "frozen"}, "stateSha256": "e" * 64}
        observed = (Mock(), controller, store, journal, anchor, state, plan)
        controller.inspect.return_value = state
        journal.append_no_export.side_effect = RuntimeError("unknown synthetic response")
        def save(_key, raw):
            store.get.return_value = raw
        store.put_exclusive.side_effect = save
        with patch.object(resolution, "checked_gate", return_value=review), \
                patch.object(resolution, "verify_jobs"), patch.object(resolution, "log_reader", return_value=Mock()), \
                patch.object(resolution, "historical_originals", return_value={"source": b"source"}), \
                patch.object(resolution, "custody_original", return_value=b"custody"), \
                patch.object(resolution, "inventory_original", return_value=b"inventory"), \
                patch.object(resolution, "read_originals"), patch.object(resolution, "observe", return_value=observed), \
                patch.object(resolution.github, "_github_token", return_value="token"):
            with self.assertRaises(RuntimeError):
                resolution.run(env)
        store.put_exclusive.assert_called_once()
        journal.append_no_export.assert_called_once()
        self.assertFalse(journal.append_no_export.call_args.args[0]["backupVerified"])
        anchor.release.assert_not_called()


if __name__ == "__main__":
    unittest.main()
