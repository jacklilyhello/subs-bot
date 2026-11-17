"""Trusted early cleanup never treats another capture as the old no-export proof."""
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import trusted_backup_no_export_gate as gate
import trusted_backup_no_export_terminal as terminal
from production_target import ContractError, canonical


class TerminalProofTests(unittest.TestCase):
    def test_full_terminal_proof_rejects_missing_fresh_job_or_receipt(self):
        target = SimpleNamespace(environment="rehearsal", digest="a" * 64)
        control = {"admission": "closed", "workers": "frozen", "epoch": 1}
        events, previous = [], None
        for number, stage in enumerate(("started", "preflight", "frozen", "frozen-data", "capture-intent"), 1):
            details = {"control": control, "checkpointId": gate.CHECKPOINT} if number == 1 else ({"checkpointId": gate.CHECKPOINT} if number == 5 else {})
            item = {"version": 1, "session": terminal.OLD_SESSION, "targetSha256": target.digest,
                    "controlRevision": gate.OLD_CANDIDATE, "sequence": number, "previousSha256": previous,
                    "timestamp": 1000 + number, "stage": stage, "details": details}
            events.append(item)
            previous = sha256(canonical(item)).hexdigest()
        review = {key: None for key in gate.REVIEW_KEYS}
        review.update(version=1, targetSha256=target.digest, oldRunId=gate.OLD_RUN,
            oldCandidateSha=gate.OLD_CANDIDATE, checkpointId=gate.CHECKPOINT,
            oldTransactionSha256=sha256(canonical(events)).hexdigest(), oldAnchorSha256="b" * 64,
            candidateCodeSha256={path: sha256(b"candidate").hexdigest() for path in gate.CANDIDATE_PATHS},
            dispatcherCodeSha256={path: sha256(b"dispatcher").hexdigest() for path in gate.DISPATCHER_PATHS},
            writerInventorySha256=sha256(b"inventory").hexdigest(), custodySha256=sha256(b"custody").hexdigest())
        review_raw = canonical(review)
        review_sha = sha256(review_raw).hexdigest()
        plan_raw = canonical({"reviewSha256": review_sha, "targetSha256": target.digest,
            "oldTransactionSha256": review["oldTransactionSha256"], "oldAnchorSha256": review["oldAnchorSha256"],
            "exportDispatchedUnderCustodyAssumption": False})
        plan_sha = sha256(plan_raw).hexdigest()
        originals = {**{"candidate/" + path: b"candidate" for path in gate.CANDIDATE_PATHS},
                     **{"dispatcher/" + path: b"dispatcher" for path in gate.DISPATCHER_PATHS},
                     "original-job-log": b"old log", "known-preflight-failure-workflow.yml": b"workflow",
                     "known-preflight-failure-gate.py": b"gate", "known-preflight-failure-job-log": b"failed log",
                     "known-preflight-failure-evidence.json": b"evidence", "protected-custody.json": b"custody",
                     "writer-inventory.json": b"inventory", "resolution-plan.json": plan_raw, "protected-review.json": review_raw}
        main, candidate, seal, release = "c" * 40, "d" * 40, "101", "102"
        manifest = {"version": 1, "kind": "no-export-original-evidence", "planSha256": plan_sha,
            "originalRunId": gate.OLD_RUN, "originalAttempt": "1", "originalJobId": gate.OLD_JOB,
            "threatModel": "reviewed-writers-no-unapproved-deletion",
            "seal": {"runId": seal, "runAttempt": "1", "dispatcherRevision": main, "controlRevision": candidate},
            "originals": []}
        manifest_raw = canonical(manifest)
        evidence_sha = sha256(manifest_raw).hexdigest()
        release_raw = canonical({"version": 1, "kind": "no-export-release-intent", "planSha256": plan_sha,
            "evidenceSha256": evidence_sha, "sealRunId": seal, "releaseRunId": release, "releaseAttempt": "1",
            "dispatcherRevision": main, "controlRevision": candidate, "targetSha256": target.digest,
            "originalRunId": gate.OLD_RUN, "originalAttempt": "1"})
        final = {"version": 1, "session": terminal.OLD_SESSION, "targetSha256": target.digest,
                 "controlRevision": gate.OLD_CANDIDATE, "sequence": 6, "previousSha256": previous,
                 "timestamp": 1006, "stage": "preserved-frozen", "details": {"control": control, "backupVerified": False,
                    "noExportEvidenceSha256": evidence_sha, "releaseIntentSha256": sha256(release_raw).hexdigest(),
                    "threatModel": "reviewed-writers-no-unapproved-deletion"}}
        events.append(final)
        anchor_sha = "e" * 64
        receipt_raw = canonical({"version": 1, "kind": "no-export-release-complete", "intentSha256": sha256(release_raw).hexdigest(),
            "planSha256": plan_sha, "evidenceSha256": evidence_sha, "originalRunId": gate.OLD_RUN,
            "releaseRunId": release, "terminalJournalSha256": sha256(canonical(events)).hexdigest(),
            "anchorSha256": anchor_sha, "backupVerified": False})
        prefix = "maintenance/production-control/evidence/no-export-resolution/" + target.digest + "/" + terminal.OLD_SESSION + "/"
        journal = "maintenance/production-control/evidence/daily-backup/" + terminal.DAY + "/" + terminal.OLD_SESSION + "/"
        records = {prefix + "evidence-manifest.json": manifest_raw,
                   prefix + "evidence-intent.json": canonical({"version": 1, "kind": "no-export-evidence-intent",
                       "planSha256": plan_sha, "manifestSha256": evidence_sha}),
                   prefix + "release-intent.json": release_raw, prefix + "release-complete.json": receipt_raw}
        records.update({journal + str(i).zfill(4) + ".json": canonical(event) for i, event in enumerate(events, 1)})
        store = SimpleNamespace(get=lambda key: records[key])
        env = {"GITHUB_SHA": main, "SUBS_BOT_BACKUP_NO_EXPORT_REVIEW_SHA256": review_sha,
               "SUBS_BOT_BACKUP_NO_EXPORT_PLAN_SHA256": plan_sha, "SUBS_BOT_BACKUP_NO_EXPORT_EVIDENCE_SHA256": evidence_sha,
               "SUBS_BOT_BACKUP_NO_EXPORT_RELEASE_SHA256": sha256(receipt_raw).hexdigest(),
               "SUBS_BOT_BACKUP_NO_EXPORT_SEAL_RUN_ID": seal, "SUBS_BOT_BACKUP_NO_EXPORT_RELEASE_RUN_ID": release,
               "SUBS_BOT_BACKUP_NO_EXPORT_DISPATCHER_SHA": main, "SUBS_BOT_BACKUP_NO_EXPORT_CANDIDATE_SHA": candidate}
        comparison = {"status": "identical", "behind_by": 0, "base_commit": {"sha": main}, "merge_base_commit": {"sha": main}}
        failed_sources = {gate.WORKFLOW: sha256(b"workflow").hexdigest(),
                          "worker/tools/trusted_backup_no_export_gate.py": sha256(b"gate").hexdigest()}
        with patch.object(terminal, "_originals", return_value=originals), patch.object(terminal, "_original_anchor", return_value=anchor_sha), \
                patch("production_backup_admission_recovery.list_history", return_value=sorted(key for key in records if key.startswith(journal))), \
                patch.object(gate, "OLD_LOG", sha256(b"old log").hexdigest()), patch.object(gate, "FAILED_PLAN_SOURCES", failed_sources), \
                patch.object(terminal, "FAILED_PLAN_LOG_SHA", sha256(b"failed log").hexdigest()), \
                patch.object(gate, "reviewed_run") as jobs, patch.object(terminal.github, "_github_token", return_value="synthetic"), \
                patch.object(terminal.github, "compare_commits_metadata", return_value=comparison):
            self.assertFalse(terminal.verify(store, target, "f" * 64, env)["backupVerified"])
            self.assertEqual(jobs.call_count, 2)
            jobs.side_effect = ContractError("fresh reader missing")
            with self.assertRaises(ContractError):
                terminal.verify(store, target, "f" * 64, env)
            jobs.side_effect = None
            del records[prefix + "release-complete.json"]
            with self.assertRaises(KeyError):
                terminal.verify(store, target, "f" * 64, env)

    def test_original_anchor_must_be_exact_old_active_predecessor(self):
        target = SimpleNamespace(digest="a" * 64)
        review = {"oldAnchorSha256": "b" * 64}
        value = {"version": 1, "targetSha256": target.digest, "generation": 7, "previousSha256": "b" * 64,
                 "state": "idle", "session": terminal.OLD_SESSION, "day": terminal.DAY,
                 "controlRevision": gate.OLD_CANDIDATE}
        store = Mock()
        def observe(candidate):
            raw = canonical(candidate)
            store.get.return_value = raw
            with patch("production_backup_admission_recovery.idle_anchor", return_value=sha256(raw).hexdigest()):
                return terminal._original_anchor(store, target, review, "c" * 64)
        self.assertEqual(observe(value), sha256(canonical(value)).hexdigest())
        for altered in ({**value, "previousSha256": "d" * 64}, {**value, "generation": 9},
                        {**value, "session": "123-1"}, {**value, "day": "2026/11/18"}):
            with self.subTest(altered=altered), self.assertRaises(ContractError):
                observe(altered)

    def test_every_original_chunk_is_verified_and_paths_are_fixed(self):
        parts = [b"first", b"second"]
        record = {"name": "original-job-log", "bytes": sum(map(len, parts)),
                  "sha256": sha256(b"".join(parts)).hexdigest(),
                  "chunks": [{"key": "objects/001/001", "bytes": len(parts[0]), "sha256": sha256(parts[0]).hexdigest()},
                             {"key": "objects/001/002", "bytes": len(parts[1]), "sha256": sha256(parts[1]).hexdigest()}]}
        values = {"private/objects/001/001": parts[0], "private/objects/001/002": parts[1]}
        store = SimpleNamespace(get=lambda key: values[key])
        self.assertEqual(terminal._originals(store, "private/", {"originals": [record]}), {"original-job-log": b"firstsecond"})
        values["private/objects/001/002"] = b"altered"
        with self.assertRaises(ContractError):
            terminal._originals(store, "private/", {"originals": [record]})
        bad = {**record, "chunks": [{**record["chunks"][0], "key": "../other"}, record["chunks"][1]]}
        with self.assertRaises(ContractError):
            terminal._originals(store, "private/", {"originals": [bad]})


if __name__ == "__main__":
    unittest.main()
