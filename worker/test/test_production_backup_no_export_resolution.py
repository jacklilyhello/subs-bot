import hashlib
import base64
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

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
    def test_legacy_seal_requires_readonly_bucket_and_all_exact_private_originals(self):
        import scoped_r2
        import production_backup_webhook_recovery as webhook
        log = b"synthetic private evidence"
        registration = b"synthetic registration"
        spec = {"registrationSha256": hashlib.sha256(registration).hexdigest()}
        plan = {"version": 1, "kind": "test-webhook-history-log-archive", "registrationSha256": spec["registrationSha256"],
                "record": {"sourceRunId": "123", "logSha256": hashlib.sha256(log).hexdigest()}}
        intent = {"version": 1, "plan": plan, "planSha256": hashlib.sha256(resolution.canonical(plan)).hexdigest(),
                  "archiveRunId": "456", "archiveAttempt": "1"}
        intent_raw = resolution.canonical(intent)
        done = {"version": 1, "intentSha256": hashlib.sha256(intent_raw).hexdigest(),
                "logSha256": hashlib.sha256(log).hexdigest()}
        records = {"private/history-log-123-intent.json": intent_raw,
                   "private/history-log-123-complete.json": resolution.canonical(done),
                   "private/history-log-123-original.log": log}
        ledger = {"456": {"action": "seal", "sourceRunId": "123", "sourceLogSha256": hashlib.sha256(log).hexdigest(),
                          "planSha256": intent["planSha256"], "completionSha256": hashlib.sha256(resolution.canonical(done)).hexdigest()}}
        objects = Mock(write_credential=None)
        objects.get.side_effect = lambda key, **_kwargs: (records[key], '"etag"')
        store = Mock(api=Mock(target={"accountId": "a" * 32}), bucket="synthetic-bucket")
        store.get.return_value = registration
        env = {"NO_EXPORT_LEGACY_ARCHIVES_JSON": json.dumps(ledger), "SUBS_BOT_SCOPED_R2_WRITE_JSON": "not-for-reading"}
        with patch.object(webhook, "open_store", return_value=(None, None, None, store, "private/")), \
                patch.object(scoped_r2, "from_environment", return_value=objects) as scoped:
            self.assertEqual(resolution.verify_legacy_archives(env, spec), ledger)
            self.assertNotIn("SUBS_BOT_SCOPED_R2_WRITE_JSON", scoped.call_args.args[2])
            store.verify.assert_called()
            records["private/history-log-123-original.log"] = b"corrupt"
            with self.assertRaises(Exception):
                resolution.verify_legacy_archives(env, spec)
            records["private/history-log-123-original.log"] = log
            records.pop("private/history-log-123-complete.json")
            with self.assertRaises(Exception):
                resolution.verify_legacy_archives(env, spec)
            objects.write_credential = {"unexpected": True}
            with self.assertRaises(Exception):
                resolution.verify_legacy_archives(env, spec)

    def test_failed_plan_originals_require_candidate_steps_skipped(self):
        run = {"id": int(resolution.FAILED_PLAN_RUN), "run_attempt": 1, "head_sha": resolution.FAILED_PLAN_MAIN,
               "head_branch": "main", "event": "workflow_dispatch", "status": "completed", "conclusion": "failure",
               "path": resolution.WORKFLOW, "display_title": "No-export plan at " + resolution.FAILED_PLAN_MAIN
                    + " candidate " + resolution.FAILED_PLAN_HEAD,
               "repository": {"id": resolution.github.REPOSITORY_ID}, "head_repository": {"id": resolution.github.REPOSITORY_ID}}
        checkout = "Run actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
        steps = [{"number": number, "name": name, "status": "completed", "conclusion": conclusion}
                 for number, name, conclusion in ((2, checkout, "success"), (3, resolution.GATES[0], "failure"),
                    (4, checkout, "skipped"), (5, resolution.GATES[1], "skipped"),
                    (6, resolution.GATES[2], "skipped"), (7, "Plan or apply the no-export resolution", "skipped"))]
        jobs = [{"name": "resolution", "id": int(resolution.FAILED_PLAN_JOB), "run_id": int(resolution.FAILED_PLAN_RUN),
                 "run_attempt": 1, "head_sha": resolution.FAILED_PLAN_MAIN, "status": "completed",
                 "conclusion": "failure", "steps": steps},
                {"name": "readback", "run_id": int(resolution.FAILED_PLAN_RUN), "run_attempt": 1,
                 "head_sha": resolution.FAILED_PLAN_MAIN, "status": "completed", "conclusion": "skipped"}]
        log = b'prefix GitHub metadata read diagnostic {"family":"other","phase":"response","httpStatus":200}\n'
        body = b"reviewed workflow"
        def get(path, _token):
            if "/contents/" in path:
                name = path.split("/contents/", 1)[1].split("?", 1)[0]
                return {"path": name, "type": "file", "encoding": "base64", "size": len(body),
                        "content": base64.b64encode(body).decode()}
            if "/jobs?" in path:
                return {"total_count": 2, "jobs": jobs}
            return run
        with patch.object(resolution.github, "_get_json", side_effect=get), \
                patch.object(resolution, "FAILED_PLAN_LOG_SHA", hashlib.sha256(log).hexdigest()), \
                patch.object(resolution, "FAILED_PLAN_WORKFLOW_SHA", hashlib.sha256(body).hexdigest()), \
                patch.object(resolution, "FAILED_PLAN_GATE_SHA", hashlib.sha256(body).hexdigest()):
            self.assertEqual(resolution.failed_plan_originals("token", lambda *_: log)["known-preflight-failure-job-log"], log)
            steps[-1]["conclusion"] = "success"
            with self.assertRaises(Exception):
                resolution.failed_plan_originals("token", lambda *_: log)

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
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory) / "no-export-reviewed-source-cache"
            cache.mkdir(mode=0o700)
            for revision, path in ((resolution.OLD_HEAD, "candidate.py"), (resolution.OLD_MAIN, "trusted.py")):
                name = hashlib.sha256((revision + "\n" + path).encode()).hexdigest()
                file = cache / name
                file.write_bytes(b"source")
                file.chmod(0o600)
            with patch.object(resolution, "OLD_LOG_SHA", review["sourceLogSha256"]):
                originals = resolution.historical_originals(review, spec, "token", lambda *_: raw, directory=directory)
                self.assertEqual(originals["original-job-log"], raw)
                wrong = dict(spec, sourceManifestSha256="e" * 64)
                with self.assertRaises(Exception):
                    resolution.historical_originals(review, wrong, "token", lambda *_: raw, directory=directory)
                with self.assertRaises(Exception):
                    resolution.historical_originals(review, spec, "token", lambda *_: raw[:-1], directory=directory)
                file.write_bytes(b"tampered")
                with self.assertRaises(Exception):
                    resolution.historical_originals(review, spec, "token", lambda *_: raw, directory=directory)
                file.unlink()
                file.symlink_to(cache / "missing")
                with self.assertRaises(Exception):
                    resolution.historical_originals(review, spec, "token", lambda *_: raw, directory=directory)

    def test_originals_are_sealed_once_and_rechecked_byte_for_byte(self):
        store = MemoryStore()
        originals = {"candidate/code": b"private source", "original-job-log": b"private log" * 75000}
        guard = Mock()
        stages = []
        evidence = resolution.seal_originals(store, "private/", "a" * 64, originals, SEAL, guard, stages.append)
        self.assertEqual(stages, ["seal-intent", "seal-chunks", "seal-manifest"])
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

    def test_entrypoint_rejects_an_untrusted_action_before_gate(self):
        with patch.dict(resolution.os.environ, {"NO_EXPORT_ACTION": "unreviewed"}, clear=True), \
                patch.object(resolution, "checked_gate") as gate:
            with self.assertRaises(Exception):
                resolution.main()
            gate.assert_not_called()

    def test_request_budget_rejects_low_quota_before_a_write(self):
        review = {"targetSha256": "a" * 64}
        response = MagicMock()
        response.__enter__.return_value = response
        response.read.return_value = json.dumps({"resources": {"core": {"remaining": 100, "reset": 2000}}}).encode()
        with patch.object(resolution, "checked_gate", return_value=(review, 2, 14)), \
                patch.object(resolution.github, "_github_token", return_value="token"), \
                patch.object(resolution.github._OPENER, "open", return_value=response), \
                patch.object(resolution.time, "time", return_value=1000):
            with self.assertRaises(Exception):
                resolution.require_request_budget({"NO_EXPORT_ACTION": "seal"}, review, 20)
            response.read.return_value = json.dumps({"resources": {"core": {"remaining": 5000, "reset": 2000}}}).encode()
            result = resolution.require_request_budget({"NO_EXPORT_ACTION": "seal"}, review, 20)
            self.assertEqual(result["required"], (17 + 2 * (2 + 2)) * 20 + 3 * 14 + 13 + 100)
            self.assertEqual(result["writerLimit"], 4)
        with patch.object(resolution, "checked_gate", return_value=(review, 4, 14)), \
                patch.object(resolution, "verify_legacy_archives"):
            resolution.guarded_review({}, review, 4, {})
        with patch.object(resolution, "checked_gate", return_value=(review, 5, 14)), self.assertRaises(Exception):
            resolution.guarded_review({}, review, 4, {})

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
               "GITHUB_RUN_ID": "456", "GITHUB_SHA": "d" * 40, "RUNNER_TEMP": "/synthetic"}
        store, journal, anchor, controller = Mock(), Mock(), Mock(), Mock()
        state = {"control": {"admission": "closed", "workers": "frozen"}, "stateSha256": "e" * 64}
        observed = (Mock(), controller, store, journal, anchor, state, plan)
        controller.inspect.return_value = state
        journal.append_no_export.side_effect = RuntimeError("unknown synthetic response")
        def save(_key, raw):
            store.get.return_value = raw
        store.put_exclusive.side_effect = save
        with patch.object(resolution, "checked_gate", side_effect=lambda _env, with_stats=False: (review, 0, 0) if with_stats else review), \
                patch.object(resolution, "verify_legacy_archives"), \
                patch.object(resolution, "verify_jobs"), patch.object(resolution, "log_reader", return_value=Mock()), \
                patch.object(resolution, "historical_originals", return_value={"source": b"source"}), \
                patch.object(resolution, "failed_plan_originals", return_value={"failed-log": b"log"}), \
                patch.object(resolution, "custody_original", return_value=b"custody"), \
                patch.object(resolution, "inventory_original", return_value=b"inventory"), \
                patch.object(resolution, "require_request_budget", return_value={"writerLimit": 2}), \
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
