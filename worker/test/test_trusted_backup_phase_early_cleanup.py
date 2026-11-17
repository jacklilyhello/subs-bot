"""Synthetic early interruption tests: no old backup is promoted to success."""
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock, patch
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import trusted_backup_phase_early_cleanup as early
from production_target import ContractError, canonical, parsed


class EarlyCleanupTests(unittest.TestCase):
    def test_rate_budget_accounts_for_resumed_history_before_writes(self):
        response = Mock()
        response.read.return_value = b'{"resources":{"core":{"remaining":1000,"reset":9999999999}}}'
        opener = MagicMock()
        opener.open.return_value.__enter__.return_value = response
        with patch.object(early.github, "_github_token", return_value="synthetic"), \
                patch.object(early.github, "_OPENER", opener):
            early.require_read_budget(120)
            early.require_read_budget(360)
            with self.assertRaises(ContractError):
                early.require_read_budget(720)

    def test_prior_pause_writer_requires_exact_current_main_and_completed_job(self):
        revision = "a" * 40
        intent = {"writerRunId": "456", "writerAttempt": "1", "dispatcherRevision": revision}
        env = {"SUBS_BOT_PHASE_EARLY_WRITER_SHA": revision, "GITHUB_SHA": revision, "RUNNER_TEMP": "/synthetic"}
        repo = {"id": early.github.REPOSITORY_ID}
        run = {"id": 456, "run_attempt": 1, "status": "completed", "head_sha": revision, "head_branch": "main",
               "event": "workflow_dispatch", "path": ".github/workflows/worker-backup-admission-recovery.yml",
               "display_title": "Backup admission recovery 123-1", "repository": repo, "head_repository": repo}
        steps = [{"name": "Require protected admission recovery switch", "status": "completed", "conclusion": "success"},
                 {"name": "Close, drain and freeze once using trusted main", "status": "completed", "conclusion": "failure"}]
        job = {"name": "recover", "run_id": 456, "run_attempt": 1, "head_sha": revision, "status": "completed", "steps": steps}
        comparison = {"status": "identical", "behind_by": 0, "base_commit": {"sha": revision}, "merge_base_commit": {"sha": revision}}
        with patch.object(early.github, "_github_token", return_value="synthetic"), \
                patch.object(early.github, "compare_commits_metadata", return_value=comparison), \
                patch.object(early.github, "_get_json", side_effect=[run, {"total_count": 1, "jobs": [job]}]):
            early.finished_pause_writer(env, intent, "123")
        with self.assertRaises(ContractError):
            early.finished_pause_writer({**env, "GITHUB_SHA": "b" * 40}, intent, "123")
        steps[1]["conclusion"] = "skipped"
        with patch.object(early.github, "_github_token", return_value="synthetic"), \
                patch.object(early.github, "compare_commits_metadata", return_value=comparison), \
                patch.object(early.github, "_get_json", side_effect=[run, {"total_count": 1, "jobs": [job]}]), \
                self.assertRaises(ContractError):
            early.finished_pause_writer(env, intent, "123")

    def test_continuation_requires_full_chain_and_completed_pinned_writer(self):
        target = SimpleNamespace(digest="a" * 64)
        prefix, pause = "private/backup-admission-123-1-", "b" * 64
        record = {"version": 1, "kind": "phase-early-continuation", "targetSha256": target.digest,
                  "sourceRunId": "123", "pauseConfirmationSha256": pause, "planSha256": "c" * 64,
                  "writerRunId": "456", "writerAttempt": "1", "dispatcherRevision": "d" * 40,
                  "sequence": 1, "previousSha256": None}
        key = prefix + "continuation-0001-intent.json"
        values = {key: canonical(record)}
        store = SimpleNamespace(objects=SimpleNamespace(list=lambda p, maximum: sorted(k for k in values if k.startswith(p))),
                                verify=Mock(), get=lambda k: values[k])
        env = {"SUBS_BOT_PHASE_EARLY_CONTINUATION_WRITERS_JSON": canonical({"456": "d" * 40}).decode()}
        with patch.object(early, "finished_pause_writer") as writer:
            result = early.continuation_history(env, store, prefix, target, "123", pause)
            self.assertEqual(result[0]["key"], key)
            writer.assert_called_once()
        current_key = prefix + "continuation-0002-intent.json"
        current_raw = canonical({"current": True})
        values[current_key] = current_raw
        with patch.object(early, "finished_pause_writer"):
            self.assertEqual(early.continuation_history(env, store, prefix, target, "123", pause,
                             current=(current_key, current_raw)), result)
            values[current_key] = canonical({"current": False})
            with self.assertRaises(ContractError):
                early.continuation_history(env, store, prefix, target, "123", pause, current=(current_key, current_raw))
        del values[current_key]
        with patch.object(early, "finished_pause_writer", side_effect=ContractError("writer not finished")), self.assertRaises(ContractError):
            early.continuation_history(env, store, prefix, target, "123", pause)
        values[prefix + "continuation-0003-intent.json"] = canonical({**record, "sequence": 3})
        with self.assertRaises(ContractError):
            early.continuation_history(env, store, prefix, target, "123", pause)

    def test_no_child_requires_reviewed_parent_and_empty_private_start_inventory(self):
        main, candidate, target_sha = "a" * 40, "b" * 40, "c" * 64
        target = SimpleNamespace(digest=target_sha)
        review = {"version": 1, "targetSha256": target_sha, "dispatcherRevision": main,
                  "candidateRevision": candidate, "ordering": "durable-start-before-child-dispatch",
                  "custody": "no-unapproved-private-evidence-deletion"}
        env = {"SUBS_BOT_PHASE_EARLY_REVIEW_JSON": canonical(review).decode(), "WEBHOOK_SOURCE_MAIN_SHA": main,
               "GITHUB_SHA": main}
        repo = {"id": early.github.REPOSITORY_ID}
        original = {"id": 123, "run_attempt": 1, "head_sha": main, "head_branch": "main", "path": early.PARENT,
                    "event": "workflow_dispatch", "status": "completed", "created_at": "2000-01-01T00:00:00Z",
                    "display_title": "Rehearsal backup coordinator run at " + main + " candidate " + candidate,
                    "repository": repo, "head_repository": repo}
        steps = [{"name": name, "status": "completed", "conclusion": "success"} for name in early.GATES]
        steps.append({"name": "Coordinate reviewed isolated backup phases", "status": "completed", "conclusion": "failure"})
        job = {"name": "coordinate", "run_id": 123, "run_attempt": 1, "head_sha": main,
               "status": "completed", "steps": steps}
        root = early.BASE + target_sha + "/coordination/maintenance/production-control/"
        initial = canonical({"version": 1, "targetSha256": target_sha, "generation": 1, "previousSha256": None,
                             "state": "idle", "session": "1-1", "day": "1970/01/01", "controlRevision": "0" * 40})
        import hashlib
        genesis = canonical({"version": 1, "targetSha256": target_sha, "initialAnchorSha256": hashlib.sha256(initial).hexdigest()})
        env["SUBS_BOT_BACKUP_COORDINATOR_GENESIS_SHA256"] = hashlib.sha256(genesis).hexdigest()
        records = {root + "registrations/daily-backup-genesis-" + target_sha + ".json": genesis,
                   root + "registrations/daily-backup-anchor-" + target_sha + ".json": initial,
                   root + "evidence/daily-backup-anchor/" + target_sha + "/000000000001-" + hashlib.sha256(initial).hexdigest() + ".json": initial}
        objects = Mock()
        objects.list.return_value = sorted(records)
        store = SimpleNamespace(objects=objects, get=lambda key: records[key])
        comparison = {"status": "identical", "behind_by": 0, "base_commit": {"sha": main}, "merge_base_commit": {"sha": main}}
        parents = [{"id": 123, "status": "completed"}]
        with patch.object(early.github, "_github_token", return_value="synthetic"), \
                patch.object(early.github, "compare_commits_metadata", return_value=comparison), \
                patch.object(early.github, "_get_json", side_effect=[original, {"total_count": 1, "jobs": [job]}]), \
                patch.object(early, "_runs", side_effect=[[], parents]):
            self.assertEqual(early.no_child_started(env, store, target, "123", candidate)["children"], 0)
        objects.list.return_value = sorted([*records, early.BASE + target_sha + "/124/02-child-claim.json"])
        with patch.object(early.github, "_github_token", return_value="synthetic"), \
                patch.object(early.github, "compare_commits_metadata", return_value=comparison), \
                patch.object(early.github, "_get_json", side_effect=[original, {"total_count": 1, "jobs": [job]}]), \
                self.assertRaises(ContractError):
            early.no_child_started(env, store, target, "123", candidate)

    def test_plan_then_once_close_and_freeze_preserves_restore_contract(self):
        target = SimpleNamespace(environment="rehearsal", digest="a" * 64, configuration_digest="c" * 64,
            data={"workerName": early.SERVICE, "botId": early.TEST_BOT_ID, "botUsername": "test_cfsubs_bot",
                  **{key: "pinned" for key in ("workerId", "workerCreatedOn", "d1Id", "d1CreatedAt", "bucketCreatedAt", "backupBucketCreatedAt")}})
        draft = SimpleNamespace(data=dict(target.data), digest="d" * 64)
        previous = {"botId": early.TEST_BOT_ID}
        registration = canonical({"target": {}, "draftSha256": draft.digest, "targetSha256": target.digest,
                                  "configurationSha256": target.configuration_digest})
        import hashlib
        records = {"private/registration.json": registration}
        def get(key, *, absent=False):
            if absent:
                return records.get(key)
            return records[key]
        def put(key, raw):
            if key in records:
                raise ContractError("occupied")
            records[key] = raw
        objects = SimpleNamespace(list=lambda prefix, maximum: sorted(key for key in records if key.startswith(prefix)))
        store = SimpleNamespace(get=get, put_exclusive=put, objects=objects, verify=Mock())
        backup_store = SimpleNamespace(verify=Mock(), objects=object())
        lock = Mock()
        lock.read.return_value = ({"state": "active", "session": "123-1", "controlRevision": "b" * 40}, b"lock", '"etag"')
        webhook = {"status": "observed", "snapshotSha256": "e" * 64, "intentPresent": False, "completionPresent": False}
        state = {"control": {"admission": "open", "workers": "run", "epoch": 1}, "release": {"revision": "source"},
                 "terminal": {}, "work": {"invocations": 1}, "stateSha256": "f" * 64,
                 "configurationSha256": target.configuration_digest}
        paused = {"control": {"admission": "closed", "workers": "run", "epoch": 2}, "stateSha256": "1" * 64,
                  "release": state["release"], "configurationSha256": target.configuration_digest}
        drained = {"control": paused["control"], "release": state["release"], "configurationSha256": target.configuration_digest,
                   "terminal": {}, "work": {"invocations": 0}, "stateSha256": "2" * 64}
        frozen = {**drained, "control": {"admission": "closed", "workers": "frozen", "epoch": 3}, "stateSha256": "3" * 64}
        ctl = Mock()
        ctl.plan_pause.return_value = state
        ctl.inspect.return_value = drained
        outcomes = iter((paused, frozen))
        def transition(*_args):
            ctl.guard()
            return next(outcomes)
        ctl.transition.side_effect = transition
        ctl.revision = "4" * 40
        archived = {"sourceTarget": target, "bundle": object(), "manifest": {}}
        with tempfile.TemporaryDirectory() as directory:
            env = {"WEBHOOK_SOURCE_KIND": "phase-coordinator", "WEBHOOK_SNAPSHOT_SHA256": "e" * 64,
                   "WEBHOOK_REGISTRATION_SHA256": hashlib.sha256(registration).hexdigest(), "GITHUB_SHA": "5" * 40,
                   "WEBHOOK_SOURCE_MAIN_SHA": "6" * 40, "RUNNER_TEMP": directory, "SUBS_BOT_CF_BOOTSTRAP_TOKEN": "synthetic",
                   "GITHUB_RUN_ID": "456", "GITHUB_RUN_ATTEMPT": "1"}
            with patch.object(early, "context", return_value=False), patch.object(early, "source_run", return_value=("123", "1", "b" * 40)), \
                    patch.object(early, "inspect_webhook", return_value=webhook), patch.object(early, "open_store", return_value=(draft, {}, previous, store, "private/")), \
                    patch.object(early, "validate_target", return_value=target), patch.object(early, "webhook_anchor", return_value=lock), \
                    patch.object(early, "PrivateStore", return_value=backup_store), patch.object(early, "API", return_value=Mock()), \
                    patch.object(early, "verify_old_terminal", return_value={"backupVerified": False}), \
                    patch.object(early, "no_child_started", return_value={"children": 0}), patch.object(early, "load_release", return_value=archived), \
                    patch.object(early, "Controller", return_value=ctl), patch.object(early, "Telegram", return_value=Mock()), \
                    patch.object(early, "approval", return_value={}), patch.object(early, "require_read_budget"), \
                    patch.object(early.github, "require_current_main"), \
                    patch("production_backup_webhook_recovery.claim_intent_once", side_effect=lambda _s, key, raw: put(key, raw)):
                plan = early.run(env, execute=False)
                self.assertFalse(plan["mutationPerformed"])
                self.assertEqual(ctl.transition.call_count, 0)
                env.update(BACKUP_APPROVED_PLAN_SHA256=plan["planSha256"],
                           SUBS_BOT_PHASE_EARLY_CLEANUP_APPROVAL_SHA256=plan["planSha256"])
                result = early.run(env, execute=True)
                self.assertEqual(result["status"], "closed-and-frozen")
                intent = parsed(records["private/backup-admission-123-1-pause-intent.json"])
                self.assertEqual((intent["session"], intent["candidateRevision"]), ("123-1", "b" * 40))
                self.assertEqual(ctl.transition.call_count, 2)
                with self.assertRaises(ContractError):
                    early.run(env, execute=True)
                self.assertEqual(ctl.transition.call_count, 2)
                ctl.inspect.return_value = frozen
                with patch.object(early, "finished_pause_writer") as writer:
                    observed = early.run(env, execute=False, inspect_frozen=True)
                    self.assertEqual(observed["status"], "freeze-confirmed")
                    self.assertFalse(observed["mutationPerformed"])
                    self.assertEqual(writer.call_count, 2)
                    self.assertEqual(ctl.transition.call_count, 2)
                # A separate synthetic interruption after confirmed pause may
                # continue to freeze, but cannot replay the pause.
                records.pop("private/backup-admission-123-1-freeze-intent.json")
                records.pop("private/backup-admission-123-1-freeze-confirmed.json")
                ctl.transition.reset_mock()
                ctl.transition.side_effect = lambda *_args: (ctl.guard(), frozen)[1]
                ctl.inspect.return_value = drained
                env["GITHUB_RUN_ID"] = "789"
                with patch.object(early, "finished_pause_writer") as writer:
                    resumed_plan = early.run(env, execute=False, resume=True)
                    env.update(BACKUP_APPROVED_PLAN_SHA256=resumed_plan["planSha256"],
                               SUBS_BOT_PHASE_EARLY_CLEANUP_APPROVAL_SHA256=resumed_plan["planSha256"])
                    resumed = early.run(env, execute=True, resume=True)
                    self.assertEqual(resumed["status"], "closed-and-frozen")
                    self.assertEqual(ctl.transition.call_count, 1)
                    self.assertEqual(ctl.transition.call_args.args[0], "freeze")
                    self.assertIn("private/backup-admission-123-1-continuation-0001-intent.json", records)
                    self.assertGreaterEqual(writer.call_count, 2)


if __name__ == "__main__":
    unittest.main()
