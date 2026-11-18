"""Hosted fault checks for production backup coordinator evidence."""
from pathlib import Path
from hashlib import sha256
from io import BytesIO
from types import SimpleNamespace
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
from zipfile import ZipFile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import production_backup_coordinator as coordinator
import production_backup_cli as cli
from production_target import ContractError, canonical


class CoordinatorTests(unittest.TestCase):
    def test_anchor_history_cache_rehashes_only_immutable_content_and_keeps_pointer_fresh(self):
        target, objects = "a" * 64, Mock()
        store = coordinator.CoordinatorStore(objects, target)
        cache = cli.ImmutableAnchorHistory(store, target)
        raw = b"reviewed immutable history"
        key = "maintenance/production-control/evidence/daily-backup-anchor/" + target + "/000000000001-" + sha256(raw).hexdigest() + ".json"
        objects.get.return_value = (raw, '"etag"')
        self.assertEqual(cache.get(key), raw)
        self.assertEqual(cache.get(key), raw)
        self.assertEqual(objects.get.call_count, 1)
        cache._history[key] = b"changed"
        with self.assertRaises(ContractError):
            cache.get(key)
        pointer = "maintenance/production-control/registrations/daily-backup-anchor-" + target + ".json"
        cache.get_with_etag(pointer)
        cache.get_with_etag(pointer)
        self.assertEqual(objects.get.call_count, 3)

    def test_schedule_scope_genesis_is_bound_to_original_bucket_identity(self):
        scope, store = "a" * 64, Mock()
        first = coordinator.ScheduleScopeAnchor(store, scope, "0" * 64, "private-backup", "2026-11-18T00:00:00Z")
        renamed = coordinator.ScheduleScopeAnchor(store, scope, "0" * 64, "other-backup", "2026-11-18T00:00:00Z")
        recreated = coordinator.ScheduleScopeAnchor(store, scope, "0" * 64, "private-backup", "2026-11-19T00:00:00Z")
        initial, genesis = first.initial_material()
        self.assertEqual(initial, renamed.initial_material()[0])
        self.assertNotEqual(genesis, renamed.initial_material()[1])
        self.assertNotEqual(genesis, recreated.initial_material()[1])

    def test_scope_bootstrap_without_reviewed_recovery_inventory_cannot_write(self):
        target, objects, anchor = Mock(), Mock(), Mock()
        with self.assertRaises(ContractError):
            coordinator.scope_initialization({}, "initialize-schedule-anchor", target, objects,
                                             "a" * 40, anchor, "b" * 64)
        objects.assert_not_called()
        objects.put_once.assert_not_called()
        anchor.assert_not_called()

    def test_scheduled_start_material_binds_both_idle_predecessors(self):
        from test_production_backup_schedule import TestScheduledPolicy
        fixture = TestScheduledPolicy()
        fixture.setUp()
        target, policy, authority = fixture.target, fixture.policy, fixture.authority
        scope_raw = coordinator.maintenance.Anchor(None, authority["scopeSha256"], "0" * 64).initial_material()[0]
        target_raw = coordinator.maintenance.Anchor(None, target.digest, "0" * 64).initial_material()[0]
        scope_prior, target_prior = coordinator.parsed(scope_raw), coordinator.parsed(target_raw)
        material = coordinator.scheduled_start_material(target, policy, authority, sha256(canonical(authority)).hexdigest(),
            "2026-11-18", "123", scope_prior, scope_raw, target_prior, target_raw)
        self.assertEqual(material["scopeStart"]["targetStartSha256"], sha256(canonical(material["targetStart"])).hexdigest())
        self.assertEqual(material["targetStart"]["slotSha256"], sha256(canonical(material["slot"])).hexdigest())
        self.assertEqual(material["slot"]["scopeAnchorSha256"], sha256(canonical(material["scopeActive"])).hexdigest())
        self.assertEqual(material["slot"]["coordinatorAnchorSha256"], sha256(canonical(material["targetActive"])).hexdigest())
        with self.assertRaises(ContractError):
            coordinator.scheduled_start_material(target, policy, authority, sha256(canonical(authority)).hexdigest(),
                "2026-11-18", "123", {**scope_prior, "state": "active"}, scope_raw, target_prior, target_raw)

    def test_scheduled_parent_requires_completed_trusted_steps_and_live_execution(self):
        revision = "a" * 40
        names = ("Check scheduled authority switch", "Check out trusted current main", "Verify scheduled dispatcher identity")
        steps = [{"name": name, "status": "completed", "conclusion": "success"} for name in names]
        steps.append({"name": "Coordinate one explicitly approved operation", "status": "in_progress", "conclusion": None})
        job = {"id": 456, "name": "coordinate", "run_id": 123, "run_attempt": 1, "head_sha": revision,
               "status": "in_progress", "conclusion": None, "steps": steps}
        self.assertTrue(coordinator.scheduled_running_job(job, "123", revision, 456))
        for bad in ({**job, "run_attempt": 2}, {**job, "status": "completed"},
                    {**job, "steps": [steps[0], {**steps[1], "conclusion": "skipped"}, *steps[2:]]}):
            with self.subTest(job=bad), self.assertRaises(ContractError):
                coordinator.scheduled_running_job(bad, "123", revision, 456)

    def test_scheduled_owner_rejects_a_changed_start_after_its_claim(self):
        import production_backup_schedule as schedule
        from test_production_backup_schedule import TestScheduledPolicy
        fixture = TestScheduledPolicy()
        fixture.setUp()
        target, policy, authority = fixture.target, fixture.policy, fixture.authority
        scope, revision = authority["scopeSha256"], authority["controlRevision"]
        scope_raw = coordinator.maintenance.Anchor(None, scope, "0" * 64).initial_material()[0]
        target_raw = coordinator.maintenance.Anchor(None, target.digest, "0" * 64).initial_material()[0]
        pin = sha256(canonical(authority)).hexdigest()
        material = coordinator.scheduled_start_material(target, policy, authority, pin, "2026-11-18", "123",
            coordinator.parsed(scope_raw), scope_raw, coordinator.parsed(target_raw), target_raw)
        objects = Mock()
        scope_anchor = coordinator.ScheduleScopeAnchor(coordinator.CoordinatorStore(objects, scope), scope,
            authority["ledgerGenesisSha256"], target.data["backupBucketName"], target.data["backupBucketCreatedAt"])
        target_anchor = coordinator.maintenance.Anchor(coordinator.CoordinatorStore(objects, target.digest), target.digest,
            authority["targetCoordinatorGenesisSha256"])
        scope_active, target_active = material["scopeActive"], material["targetActive"]
        scope_anchor.read = Mock(return_value=(scope_active, canonical(scope_active), '"etag"'))
        target_anchor.read = Mock(return_value=(target_active, canonical(target_active), '"etag"'))
        slot = material["slot"]
        scope_key = schedule.scope_start_key(scope, "123")
        slot_key = schedule.slot_key(scope, slot["slotDay"])
        target_key = coordinator.BASE + target.digest + "/123/start-intent.json"
        bodies = {scope_key: canonical(material["scopeStart"]), target_key: canonical(material["targetStart"]),
                  slot_key: canonical(slot)}
        objects.get.side_effect = lambda key: (bodies[key], '"etag"')
        objects.list.side_effect = lambda prefix, **_kw: [] if prefix.endswith("/writers/") else [scope_key, slot_key]
        env = {"GITHUB_REPOSITORY": coordinator.artifact.REPOSITORY,
               "GITHUB_REPOSITORY_ID": str(coordinator.artifact.REPOSITORY_ID), "GITHUB_REF": coordinator.artifact.MAIN_REF,
               "GITHUB_EVENT_NAME": "schedule", "RUNNER_ENVIRONMENT": "github-hosted", "GITHUB_RUN_ATTEMPT": "1",
               "GITHUB_WORKFLOW_REF": coordinator.artifact.REPOSITORY + "/.github/workflows/worker-production-backup-coordinator.yml@" + coordinator.artifact.MAIN_REF,
               "GITHUB_SHA": revision, "GITHUB_WORKFLOW_SHA": revision, "GITHUB_RUN_ID": "123",
               "SUBS_BOT_PRODUCTION_BACKUP_SCHEDULE_ENABLED": "true",
               "SUBS_BOT_PRODUCTION_BACKUP_SCHEDULE_AUTHORITY_SHA256": pin,
               "SUBS_BOT_BACKUP_SCHEDULE_SCOPE_GENESIS_SHA256": authority["ledgerGenesisSha256"],
               "SUBS_BOT_BACKUP_COORDINATOR_GENESIS_SHA256": authority["targetCoordinatorGenesisSha256"],
               "SUBS_BOT_BACKUP_GENESIS_SHA256": authority["applicationGenesisSha256"]}
        owner = coordinator.ScheduledScopeOwner(env, target, objects, scope_anchor, target_anchor, material, [scope_key, slot_key], 456)
        with patch.object(cli, "settings", return_value=policy), patch.object(schedule, "authority_document", return_value=authority), \
             patch.object(cli, "scheduled_main_guard"), patch.object(owner.client, "get", return_value={}), \
             patch("time.time", return_value=fixture.start + 60):
            owner.guard()
            material["targetStart"]["sourceCheckpointId"] = "0" * 32
            with self.assertRaises(ContractError):
                owner.guard()

    def test_scope_bootstrap_reserves_three_guards_before_any_write(self):
        evidence = {"reviewedRunCount": 4, "safePlanRunCount": 1, "guardGithubUpperBound": 57}
        with patch.object(coordinator, "bootstrap_rate_limit", return_value={"resources": {"core": {"remaining": 271, "reset": 4102444800}}}):
            coordinator.require_bootstrap_budget(evidence, "token")
        with patch.object(coordinator, "bootstrap_rate_limit", return_value={"resources": {"core": {"remaining": 270, "reset": 4102444800}}}), \
             self.assertRaises(ContractError):
            coordinator.require_bootstrap_budget(evidence, "token")
        with patch.object(coordinator, "bootstrap_rate_limit", return_value={"resources": {"core": {"remaining": 999, "reset": 1}}}), \
             self.assertRaises(ContractError):
            coordinator.require_bootstrap_budget(evidence, "token")
        with self.assertRaises(ContractError):
            coordinator.require_bootstrap_budget({**evidence, "guardGithubUpperBound": 48}, "token")

    def test_bootstrap_quota_reads_the_global_endpoint_once(self):
        from io import BytesIO
        response = BytesIO(b'{"resources":{"core":{"remaining":271,"reset":4102444800}}}')
        response.status = 200
        with patch.object(coordinator.artifact._OPENER, "open", return_value=response) as opened:
            quota = coordinator.bootstrap_rate_limit("synthetic")
            self.assertEqual(quota["resources"]["core"]["remaining"], 271)
            self.assertEqual(opened.call_args.args[0].full_url, "https://api.github.com/rate_limit")
            opened.assert_called_once()

    def test_one_scheduled_child_reuses_only_its_own_liveness_client(self):
        import production_backup_schedule as schedule
        args = dict(env={"BACKUP_ACTION": "capture"}, objects=Mock(), target=Mock(), policy={},
                    authority={}, authority_sha256="a" * 64, slot={}, target_history=Mock(), scope_history=Mock())
        runtime = cli.ScheduledBackupRuntime(**args)
        other = cli.ScheduledBackupRuntime(**args)
        with patch.object(schedule, "ScheduledApproval", return_value=Mock()) as grant:
            runtime.envelope("recovery-prepare:" + "b" * 64, "c" * 64)
            runtime.envelope("recovery-capture:" + "b" * 64, "c" * 64)
            first, second = grant.call_args_list
            self.assertIs(first.kwargs["fresh_client"], runtime.fresh_client)
            self.assertIs(second.kwargs["fresh_client"], runtime.fresh_client)
            self.assertIsNot(runtime.fresh_client, other.fresh_client)

    def test_scheduled_begin_rebinds_live_work_but_refuses_unknown_or_changed_control(self):
        state = {"targetSha256": "a" * 64, "configurationSha256": "b" * 64,
                 "release": {"revision": "c" * 40}, "control": {"epoch": 7, "admission": "open"},
                 "migrationCount": 40, "work": {"invocations": 0}, "terminal": {"unknownInvocations": 0}}
        first = cli.scheduled_begin_state(state)["stateSha256"]
        self.assertEqual(cli.scheduled_begin_state({**state, "work": {"invocations": 2}})["stateSha256"], first)
        self.assertNotEqual(cli.scheduled_begin_state({**state, "control": {"epoch": 8}})["stateSha256"], first)
        with self.assertRaises(ContractError):
            cli.scheduled_begin_state({**state, "terminal": {"unknownInvocations": 1}})

    def test_manual_report_does_not_claim_unobserved_schedule_is_disabled(self):
        import json
        target = Mock(digest="a" * 64)
        with tempfile.TemporaryDirectory() as directory, patch.object(cli.artifact, "require_current_main"):
            cli.emit_result({"status": "observed", "action": "inspect"}, target, "b" * 40, Path(directory))
            report = json.loads((Path(directory) / "production-backup-result.json").read_text())
            self.assertIsNone(report["scheduleEnabled"])

    def test_scheduled_source_review_requires_exact_protected_tree_and_all_python_sources(self):
        revision, tree = "a" * 40, "b" * 40
        paths = [*coordinator.SCHEDULE_REVIEW_WORKFLOWS, "worker/tools/production_backup_coordinator.py",
                 "worker/tools/production_backup_schedule.py"]
        contents = {path: ("synthetic " + path).encode() for path in paths}
        hashes = {path: sha256(raw).hexdigest() for path, raw in contents.items()}
        row = {"treeSha": tree, "workflowSha256": hashes[paths[0]], "childWorkflowSha256": hashes[paths[1]],
               "sourceClosureSha256": sha256(canonical(hashes)).hexdigest()}
        review = canonical({"version": 1, "controllers": {revision: row}}).decode()
        def fake_run(args, **_kwargs):
            command = args[3:]
            if command == ["rev-parse", "--verify", "HEAD"]:
                return SimpleNamespace(stdout=(revision + "\n").encode())
            if command == ["rev-parse", "--verify", revision + "^{tree}"]:
                return SimpleNamespace(stdout=(tree + "\n").encode())
            if command == ["ls-tree", "-r", "--name-only", revision, "--", "worker/tools"]:
                return SimpleNamespace(stdout=("\n".join(paths[2:]) + "\n").encode())
            path = command[-1].split(":", 1)[1]
            return SimpleNamespace(stdout=(str(len(contents[path])) + "\n").encode() if command[0] == "cat-file" else contents[path])
        with tempfile.TemporaryDirectory() as directory, patch("subprocess.run", side_effect=fake_run):
            env = {"GITHUB_WORKSPACE": directory, "GITHUB_SHA": revision, "SUBS_BOT_PRODUCTION_BACKUP_SCHEDULE_REVIEW_JSON": review,
                   "SUBS_BOT_PRODUCTION_BACKUP_SCHEDULE_REVIEW_SHA256": sha256(review.encode()).hexdigest()}
            source = coordinator.scheduled_source_review(env, revision)
            self.assertEqual(source["treeSha"], tree)
            self.assertTrue(coordinator.historical_schedule_source_review(env, revision,
                {"version": 1, "controllers": {revision: row}}, source))
            with self.assertRaises(ContractError):
                coordinator.historical_schedule_source_review(env, revision,
                    {"version": 1, "controllers": {revision: {**row, "treeSha": "0" * 40}}}, source)
            with self.assertRaises(ContractError):
                coordinator.scheduled_source_review({**env, "SUBS_BOT_PRODUCTION_BACKUP_SCHEDULE_REVIEW_SHA256": "0" * 64}, revision)
            contents[paths[-1]] += b" changed"
            with self.assertRaises(ContractError):
                coordinator.scheduled_source_review(env, revision)

    def test_scheduled_fresh_reader_requires_original_job_and_reader_identity(self):
        revision = "a" * 40
        slot = {"writerRunId": "123", "writerAttempt": "1", "session": "123",
                "authority": {"controlRevision": revision}}
        repo = {"id": coordinator.artifact.REPOSITORY_ID}
        run = {"id": 123, "run_attempt": 1, "head_sha": revision, "head_branch": "main",
               "event": "schedule", "path": ".github/workflows/worker-production-backup-coordinator.yml",
               "display_title": "Production backup coordinator scheduled-run at " + revision,
               "status": "in_progress", "repository": repo, "head_repository": repo}
        def step(name, running=False):
            return {"name": name, "status": "in_progress" if running else "completed",
                    "conclusion": None if running else "success"}
        common = {"run_id": 123, "run_attempt": 1, "head_sha": revision}
        coordinate = {**common, "id": 1, "name": "coordinate", "status": "completed", "conclusion": "success",
                      "steps": [step(name) for name in ("Check scheduled authority switch", "Check out trusted current main",
                               "Verify scheduled dispatcher identity", "Coordinate one explicitly approved operation")]}
        reader = {**common, "id": 2, "name": "schedule_readback", "status": "in_progress", "conclusion": None,
                  "steps": [step("Check out trusted current main"), step("Independently verify completed scheduled backup", True)]}
        env = {"GITHUB_SHA": revision, "GITHUB_REPOSITORY": coordinator.artifact.REPOSITORY,
               "GITHUB_REPOSITORY_ID": str(coordinator.artifact.REPOSITORY_ID), "GITHUB_REF": coordinator.artifact.MAIN_REF,
               "RUNNER_ENVIRONMENT": "github-hosted", "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1",
               "GITHUB_EVENT_NAME": "schedule", "GITHUB_WORKFLOW_REF": coordinator.artifact.REPOSITORY +
               "/.github/workflows/worker-production-backup-coordinator.yml@" + coordinator.artifact.MAIN_REF}
        response = {"total_count": 2, "jobs": [coordinate, reader]}
        def check(jobs):
            with patch.object(coordinator.artifact, "_github_token", return_value="synthetic"), \
                 patch.object(coordinator.artifact, "_get_json", side_effect=[run, run, jobs]):
                return coordinator.verify_scheduled_parent(env, slot, mode="fresh-reader")
        self.assertEqual(check(response)["readerJobId"], 2)
        for changed in ({**reader, "id": 1}, {**reader, "status": "completed", "conclusion": "success"},
                        {**coordinate, "conclusion": "failure"}):
            jobs = [coordinate, changed] if changed["name"] == "schedule_readback" else [changed, reader]
            with self.subTest(changed=changed), self.assertRaises(ContractError):
                check({"total_count": 2, "jobs": jobs})

    def test_scheduled_anchor_history_rejects_session_reuse_and_pointer_drift(self):
        first = {"generation": 1, "state": "idle", "previousSha256": None}
        second = {"generation": 2, "state": "active", "session": "123-1", "day": "2026/11/18",
                  "controlRevision": "a" * 40, "previousSha256": sha256(canonical(first)).hexdigest()}
        third = {"generation": 3, "state": "idle", "session": "123-1", "day": "2026/11/18",
                 "controlRevision": "a" * 40, "previousSha256": sha256(canonical(second)).hexdigest()}
        fourth = {"generation": 4, "state": "active", "session": "456-1", "day": "2026/11/19",
                  "controlRevision": "a" * 40, "previousSha256": sha256(canonical(third)).hexdigest()}
        rows = {sha256(canonical(row)).hexdigest(): canonical(row) for row in (first, second, third)}
        anchor = Mock()
        anchor.history_digest_key.side_effect = lambda _generation, digest: digest
        anchor.store.get.side_effect = rows.__getitem__
        anchor.read.return_value = (fourth, canonical(fourth), '"etag"')
        self.assertEqual([row["session"] for row in coordinator.coordinator_anchor_history(anchor)], ["123-1", "456-1"])
        duplicate = {**fourth, "session": "123-1"}
        anchor.read.return_value = (duplicate, canonical(duplicate), '"etag"')
        with self.assertRaises(ContractError):
            coordinator.coordinator_anchor_history(anchor)
        anchor.read.side_effect = [(fourth, canonical(fourth), '"etag"'), (third, canonical(third), '"etag"')]
        with self.assertRaises(ContractError):
            coordinator.coordinator_anchor_history(anchor)

    def test_scheduled_monitor_checks_environment_before_read_credentials(self):
        workflow = (Path(__file__).resolve().parents[2] / ".github/workflows/worker-production-backup-coordinator.yml").read_text()
        monitor = workflow.split("  monitor:\n", 1)[1]
        job_condition = monitor.split("    environment:", 1)[0]
        self.assertNotIn("vars.SUBS_BOT_PRODUCTION_BACKUP_COORDINATOR_MONITOR_ENABLED", job_condition)
        self.assertIn("MONITOR_ENABLED: ${{ vars.SUBS_BOT_PRODUCTION_BACKUP_COORDINATOR_MONITOR_ENABLED }}", monitor)
        self.assertIn("echo 'status=disabled'", monitor)
        self.assertEqual(monitor.count("if: steps.gate.outputs.enabled == 'true'"), 2)

    def test_scheduled_jobs_require_repository_switch_before_environment(self):
        root = Path(__file__).resolve().parents[2] / ".github/workflows"
        coordinator_workflow = (root / "worker-production-backup-coordinator.yml").read_text()
        coordinate = coordinator_workflow.split("  coordinate:\n", 1)[1].split("    environment:", 1)[0]
        monitor = coordinator_workflow.split("  monitor:\n", 1)[1].split("    environment:", 1)[0]
        production = (root / "worker-production-backup.yml").read_text().split("  checkpoint:\n", 1)[1].split("    environment:", 1)[0]
        self.assertIn("vars.SUBS_BOT_PRODUCTION_BACKUP_SCHEDULE_DISPATCH_ENABLED == 'true'", coordinate)
        self.assertIn("vars.SUBS_BOT_PRODUCTION_BACKUP_MONITOR_DISPATCH_ENABLED == 'true'", monitor)
        self.assertIn("vars.SUBS_BOT_PRODUCTION_BACKUP_MONITOR_DISPATCH_ENABLED == 'true'", production)
        self.assertIn('s in {"completed", "not-due"}', coordinator_workflow)
        reader = coordinator_workflow.split("  schedule_readback:\n", 1)[1].split("  inspect_or_reconcile:\n", 1)[0]
        self.assertIn("needs.coordinate.outputs.scheduled_status == 'completed'", reader)
        self.assertIn("name: Independently verify completed scheduled backup", reader)
        self.assertNotIn("SUBS_BOT_CF_DATA_TOKEN", reader)
        self.assertNotIn("SUBS_BOT_CF_WORKER_TOKEN", reader)
        self.assertNotIn("SUBS_BOT_CONTROL_SECRETS", reader)

    def test_backup_run_name_quotes_nonce_expression(self):
        workflow = (Path(__file__).resolve().parents[2] / ".github/workflows/worker-production-backup.yml").read_text()
        run_name = next(line for line in workflow.splitlines() if line.startswith("run-name:"))
        self.assertTrue(run_name.startswith('run-name: "') and run_name.endswith('"'))
        self.assertIn("format(' #{0}', inputs.dispatch_nonce)", run_name)

    def test_manual_child_requires_the_exact_parent_scope_and_unchanged_inventory(self):
        import production_backup_manual_scope as manual
        import production_backup_schedule as scheduled
        scope, revision, writer = "a" * 64, "b" * 40, "789"
        target = Mock(digest="c" * 64, configuration_digest="d" * 64,
                      data={"backupBucketName": "private-backup", "backupBucketCreatedAt": "2026-11-18T00:00:00Z"})
        policy = {"pauseLimitSeconds": 300}
        current = {"state": "active", "session": writer + "-1", "controlRevision": revision,
                   "previousSha256": "e" * 64, "day": "2026/11/18"}
        raw = canonical(current)
        key = manual.start_key(scope, writer)
        previous_keys = [scheduled.BASE + scope + "/previous.json"]
        start = {"version": 1, "kind": "manual-backup-scope-start", "scopeSha256": scope,
                 "targetSha256": target.digest, "configurationSha256": target.configuration_digest,
                 "targetDocument": target.data, "policy": policy, "policySha256": sha256(canonical(policy)).hexdigest(),
                 "readerLogPolicy": {}, "readerLogPolicySha256": "1" * 64,
                 "priorScopeKeysSha256": sha256(canonical(previous_keys)).hexdigest(),
                 "targetCoordinatorGenesisSha256": "2" * 64, "applicationGenesisSha256": "3" * 64,
                 "action": "run", "approvalActionSha256": "4" * 64, "approvalSha256": "5" * 64,
                 "predecessorSha256": "6" * 64, "scopePredecessorSha256": current["previousSha256"],
                 "scopeAnchorSha256": sha256(raw).hexdigest(), "writerRunId": writer, "writerAttempt": "1",
                 "day": current["day"], "workflowRef": cli.artifact.REPOSITORY +
                    "/.github/workflows/worker-production-backup-coordinator.yml@" + cli.artifact.MAIN_REF,
                 "controlRevision": revision, "sourceRevision": None, "coordinatorSession": "123"}
        env = {"GITHUB_SHA": revision, "SUBS_BOT_BACKUP_SCHEDULE_SCOPE_GENESIS_SHA256": "7" * 64,
               "SUBS_BOT_BACKUP_COORDINATOR_GENESIS_SHA256": "2" * 64,
               "SUBS_BOT_BACKUP_GENESIS_SHA256": "3" * 64}
        objects, anchor = Mock(), Mock()
        anchor.read.return_value = (current, raw, '"etag"')
        objects.get.return_value = (canonical(start), '"etag"')
        objects.list.return_value = previous_keys + [key]
        intent = {"writerRunId": writer, "session": "123"}
        with patch.object(scheduled, "logical_scope", return_value=scope), \
             patch.object(coordinator, "ScheduleScopeAnchor", return_value=anchor):
            self.assertEqual(cli.verify_manual_parent_scope(env, target, objects, policy, intent), "run")
            objects.list.return_value += [scheduled.BASE + scope + "/orphan.json"]
            with self.assertRaises(ContractError):
                cli.verify_manual_parent_scope(env, target, objects, policy, intent)
            objects.list.return_value = previous_keys + [key]
            anchor.read.return_value = ({**current, "session": "999-1"}, raw, '"etag"')
            with self.assertRaises(ContractError):
                cli.verify_manual_parent_scope(env, target, objects, policy, intent)

    def archive(self, result):
        raw = BytesIO()
        with ZipFile(raw, "w") as archive:
            archive.writestr("production-backup-result.json", canonical(result))
        return raw.getvalue()

    def intent(self):
        return coordinator.dispatch_intent(target="a" * 64, session="123", sequence=1,
            revision="b" * 40, nonce="c" * 64, input_sha256="d" * 64, created_at=1000, writer_run_id="789")

    def test_single_use_intent_is_read_back_and_existing_intent_cannot_be_reissued(self):
        value = self.intent()
        store = Mock()
        store.get.side_effect = [(None, None), (canonical(value), '"etag"')]
        coordinator.write_dispatch_once(store, value)
        store.put_once.assert_called_once_with(coordinator.event_key("a" * 64, "123", 1), canonical(value))
        store.reset_mock()
        store.get.side_effect = None
        store.get.return_value = (canonical(value), '"etag"')
        with self.assertRaises(ContractError):
            coordinator.write_dispatch_once(store, value)
        store.put_once.assert_not_called()

    def test_uncertain_write_and_missing_receipt_never_allow_dispatch(self):
        value = self.intent()
        store = Mock()
        store.get.return_value = (None, None)
        store.put_once.side_effect = RuntimeError("unconfirmed")
        with self.assertRaises(RuntimeError):
            coordinator.write_dispatch_once(store, value)
        store.put_once.assert_called_once()
        store.get.side_effect = [(canonical(value), '"etag"'), (None, None), (None, None), (None, None)]
        result = coordinator.inspect_stage(store, "a" * 64, "123", 1)
        self.assertEqual(result["status"], "unknown")
        self.assertFalse(result["dispatchPermitted"])

    def test_receipt_never_substitutes_for_gh_run_verification(self):
        value = self.intent()
        result_value = {"action": "plan-begin"}
        original = self.archive(result_value)
        done = coordinator.receipt(value, "456", result_value, "789", sha256(original).hexdigest())
        store = Mock()
        claim = canonical(coordinator.child_claim(value, "456", "1"))
        store.get.side_effect = [(canonical(value), '"etag"'), (canonical(done), '"etag"'), (original, '"etag"'), (claim, '"etag"')]
        result = coordinator.inspect_stage(store, "a" * 64, "123", 1)
        self.assertEqual(result["status"], "receipt-needs-independent-run-verification")
        self.assertFalse(result["dispatchPermitted"])
        self.assertEqual(result["runId"], "456")

    def test_receipt_preserves_canonical_result_and_rejects_replacement(self):
        value = self.intent()
        result = {"action": "plan-begin", "stateSha256": "e" * 64}
        original = self.archive(result)
        saved = coordinator.receipt(value, "456", result, "789", sha256(original).hexdigest())
        self.assertEqual(saved["result"], result)
        changed = {**saved, "result": {"action": "plan-begin", "stateSha256": "f" * 64}}
        store = Mock()
        store.get.side_effect = [(canonical(value), '"etag"'), (canonical(changed), '"etag"'), (original, '"etag"'), (None, None)]
        with self.assertRaises(ContractError):
            coordinator.inspect_stage(store, "a" * 64, "123", 1)

    def test_child_claim_is_single_use_and_bound_to_the_exact_run(self):
        value = self.intent()
        store = Mock()
        raw = canonical(coordinator.child_claim(value, "456", "1"))
        store.get.side_effect = [(None, None), (raw, '"etag"')]
        coordinator.claim_child_once(store, value, "456", "1")
        store.put_once.assert_called_once_with(coordinator.child_claim_key("a" * 64, "123", 1), raw)
        store.get.side_effect = None
        store.get.return_value = (raw, '"etag"')
        coordinator.verify_child_claim(store, value, "456")
        with self.assertRaises(ContractError):
            coordinator.verify_child_claim(store, value, "457")
        store.put_once.reset_mock()
        with self.assertRaises(ContractError):
            coordinator.claim_child_once(store, value, "457", "1")
        store.put_once.assert_not_called()

    def test_child_claim_unknown_write_never_retries_or_accepts_receipt(self):
        value = self.intent()
        store = Mock()
        store.get.return_value = (None, None)
        store.put_once.side_effect = RuntimeError("uncertain conditional write")
        with self.assertRaises(RuntimeError):
            coordinator.claim_child_once(store, value, "456", "1")
        store.put_once.assert_called_once()
        result = {"action": "plan-begin"}
        original = self.archive(result)
        done = coordinator.receipt(value, "456", result, "789", sha256(original).hexdigest())
        store.get.side_effect = [(canonical(value), '"etag"'), (canonical(done), '"etag"'), (original, '"etag"'), (None, None)]
        with self.assertRaises(ContractError):
            coordinator.inspect_stage(store, "a" * 64, "123", 1)

    def test_pause_deadline_starts_before_dispatch_and_rejects_future_intent(self):
        value = coordinator.dispatch_intent(target="a" * 64, session="123", sequence=5,
            revision="b" * 40, nonce="c" * 64, input_sha256="d" * 64, created_at=1000, writer_run_id="789")
        self.assertEqual(coordinator.pause_deadline(value, 900, now=1005), 1900)
        with self.assertRaises(ContractError):
            coordinator.pause_deadline(value, 900, now=900)

    def test_drain_cannot_hold_the_parent_past_pause_deadline(self):
        self.assertEqual(coordinator.checkpoint_wait_deadline("drain", 5000, 1100, now=1050, monotonic_now=2000), 2050)
        with self.assertRaises(ContractError):
            coordinator.checkpoint_wait_deadline("drain", 5000, 1100, now=1100, monotonic_now=2000)
        self.assertEqual(coordinator.checkpoint_wait_deadline("activate", 5000, 1100, now=1101, monotonic_now=2000), 5000)

    def test_alarm_threshold_does_not_become_the_maximum_pause(self):
        intent = coordinator.dispatch_intent(target="a" * 64, session="123", sequence=5,
            revision="b" * 40, nonce="c" * 64, input_sha256="d" * 64, created_at=1000, writer_run_id="789")
        maximum = coordinator.pause_deadline(intent, 1800, now=1301)
        self.assertEqual(maximum, 2800)
        self.assertEqual(coordinator.checkpoint_wait_deadline("drain", 5000, maximum, now=1301, monotonic_now=2000), 3499)

    def test_stage_inputs_bind_prior_predecessor_and_source(self):
        from hashlib import sha256
        prior = [{"action": "plan-begin", "status": "plan-only", "session": "456-1",
                  "day": "2026/11/18", "stateSha256": "e" * 64}]
        intent = coordinator.dispatch_intent(target="a" * 64, session="123", sequence=2,
            revision="b" * 40, nonce="c" * 64, input_sha256="d" * 64, created_at=1000, writer_run_id="789")
        value, deadline = coordinator.stage_inputs(prior, "1" * 32, "2" * 64, "123", intent, 900, None)
        self.assertIsNone(deadline)
        self.assertEqual(value["state_sha256"], "e" * 64)
        changed, _ = coordinator.stage_inputs([{**prior[0], "stateSha256": "f" * 64}],
                                               "1" * 32, "2" * 64, "123", intent, 900, None)
        self.assertNotEqual(sha256(canonical(value)).hexdigest(), sha256(canonical(changed)).hexdigest())
        changed_source, _ = coordinator.stage_inputs(prior, "1" * 32, "3" * 64, "123", intent, 900, None)
        self.assertNotEqual(sha256(canonical(value)).hexdigest(), sha256(canonical(changed_source)).hexdigest())

    def test_rehearsal_binds_real_dispatcher_and_separate_candidate(self):
        value = coordinator.dispatch_intent(target="a" * 64, session="123", sequence=1,
            revision="b" * 40, candidate_revision="c" * 40, profile="rehearsal", nonce="d" * 64,
            input_sha256="e" * 64, created_at=1000, writer_run_id="789")
        self.assertEqual(value["controllerRevision"], "b" * 40)
        self.assertEqual(value["candidateRevision"], "c" * 40)
        self.assertEqual(coordinator.child_title(value), "Rehearsal backup plan-begin at " + "b" * 40
                         + " candidate " + "c" * 40 + " #" + "d" * 64)
        inputs, _ = coordinator.stage_inputs([], "1" * 32, "2" * 64, "123", value, 900, None,
                                              validation_json='{"version":1}')
        self.assertEqual(inputs["validation_json"], '{"version":1}')
        with self.assertRaises(ContractError):
            coordinator.dispatch_intent(target="a" * 64, session="123", sequence=1, revision="b" * 40,
                candidate_revision="c" * 40, profile="production", nonce="d" * 64,
                input_sha256="e" * 64, created_at=1000, writer_run_id="789")

    def test_resume_writer_claim_does_not_retry_an_existing_or_ambiguous_slot(self):
        history = {"writers": [], "lastSha256": "e" * 64}
        store = Mock()
        store.get.return_value = (b"existing", '"etag"')
        with self.assertRaises(ContractError):
            coordinator.claim_resume_writer(store, "a" * 64, "123", "b" * 40, history, "456")
        store.put_once.assert_not_called()
        store.get.return_value = (None, None)
        store.put_once.side_effect = RuntimeError("unknown response")
        with self.assertRaises(RuntimeError):
            coordinator.claim_resume_writer(store, "a" * 64, "123", "b" * 40, history, "456")
        store.put_once.assert_called_once()
        store.put_once.reset_mock(side_effect=True)
        store.get.return_value = (b"competing writer", '"etag"')
        with self.assertRaises(ContractError):
            coordinator.claim_resume_writer(store, "a" * 64, "123", "b" * 40, history, "457", action="reconcile")
        store.put_once.assert_not_called()

    def test_recovery_writer_uses_the_same_exclusive_slot_and_is_rehearsal_only(self):
        history = {"writers": [], "lastSha256": "c" * 64}
        store = Mock()
        objects = {}
        store.get.side_effect = lambda key, **_: (objects.get(key), '"etag"')
        store.put_once.side_effect = lambda key, body: objects.update({key: body})
        args = (store, "a" * 64, "123", "b" * 40, history, "456")
        with self.assertRaises(ContractError):
            coordinator.claim_resume_writer(*args, action="recovery", recovery_action="resume-failed", recovery_plan_sha="d" * 64)
        coordinator.claim_resume_writer(*args, action="recovery", profile="rehearsal", candidate_revision="e" * 40,
                                        recovery_action="resume-failed", recovery_plan_sha="d" * 64)
        with self.assertRaises(ContractError):
            coordinator.claim_resume_writer(*args, action="resume", profile="rehearsal", candidate_revision="e" * 40)
        self.assertEqual(store.put_once.call_count, 1)

    def test_only_exact_in_progress_recovery_writer_can_extend_a_stopped_chain(self):
        target, revision, candidate, session = "a" * 64, "b" * 40, "c" * 40, "123"
        source, manifest, policy, validation, plan = "d" * 32, "e" * 64, "f" * 64, "1" * 64, "2" * 64
        start = {"version": 1, "action": "run", "targetSha256": target, "controlRevision": revision,
                 "session": session, "sourceCheckpointId": source, "sourceManifestSha256": manifest,
                 "anchorSha256": "3" * 64, "policySha256": policy, "writerRunId": "700", "writerAttempt": "1",
                 "profile": "rehearsal", "candidateRevision": candidate, "validationSha256": validation}
        writer = {"version": 1, "targetSha256": target, "session": session, "controlRevision": revision,
                  "position": 1, "previousSha256": sha256(canonical(start)).hexdigest(), "writerRunId": "701",
                  "writerAttempt": "1", "action": "recovery", "profile": "rehearsal", "candidateRevision": candidate,
                  "recoveryAction": "resume-failed", "recoveryPlanSha256": plan}
        base = coordinator.BASE + target + "/" + session + "/"
        objects = {base + "start-intent.json": canonical(start), base + "writers/0001.json": canonical(writer)}
        store = Mock()
        store.get.side_effect = lambda key, **_: (objects[key], '"etag"')
        store.list.return_value = [base + "writers/0001.json"]
        repo = {"id": coordinator.artifact.REPOSITORY_ID}
        original = {"id": 700, "head_sha": revision, "path": coordinator.PROFILES["rehearsal"]["parent"],
                    "display_title": coordinator.parent_title("rehearsal", "run", revision, candidate), "event": "workflow_dispatch",
                    "head_branch": "main", "status": "completed", "run_attempt": 1, "repository": repo, "head_repository": repo}
        current = {**original, "id": 701, "path": ".github/workflows/worker-backup-phase-recovery.yml", "status": "in_progress",
                   "display_title": "Rehearsal backup recovery resume-failed at " + revision + " candidate " + candidate + " session " + session}
        names = ("Verify recovery identity before candidate checkout", "Verify exact reviewed recovery checkout",
                 "Verify isolated recovery test Bot identity", "Plan or execute one reviewed recovery phase")
        steps = [{"name": name, "status": "completed", "conclusion": "success"} for name in names[:-1]]
        steps.append({"name": names[-1], "status": "in_progress", "conclusion": None})
        job = {"name": "recovery", "run_id": 701, "run_attempt": 1, "head_sha": revision, "status": "in_progress", "steps": steps}
        job_list = [job]
        def api(path, _token):
            if path.endswith("/jobs?per_page=100"):
                return {"total_count": len(job_list), "jobs": job_list}
            return original if "/700" in path else current
        env = {"GITHUB_RUN_ID": "701", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_SHA": revision,
               "GITHUB_WORKFLOW_REF": coordinator.artifact.REPOSITORY + "/.github/workflows/worker-backup-phase-recovery.yml@" + coordinator.artifact.MAIN_REF,
               "BACKUP_ACTION": "resume-failed", "BACKUP_RECOVERY_PLAN_SHA256": plan, "BACKUP_GATE_ROLE": "recovery"}
        args = (store, target, session, revision, source, manifest, policy)
        kwargs = {"profile": "rehearsal", "candidate_revision": candidate, "validation_sha": validation}
        with patch.dict("os.environ", env, clear=True), patch.object(coordinator.artifact, "_github_token", return_value="synthetic"), \
             patch.object(coordinator.artifact, "_get_json", side_effect=api):
            result = coordinator.finished_controller(*args, **kwargs, current_writer=writer, current_mode="execute")
            self.assertEqual(result["writers"], [writer])
            objects[base + "writers/0001.json"] = canonical({**writer, "version": True})
            with self.assertRaises(ContractError):
                coordinator.finished_controller(*args, **kwargs, current_writer=writer, current_mode="execute")
            objects[base + "writers/0001.json"] = canonical(writer)
            with self.assertRaises(ContractError):
                coordinator.finished_controller(*args, **kwargs)
            with patch.dict("os.environ", {"BACKUP_RECOVERY_PLAN_SHA256": "9" * 64}):
                with self.assertRaises(ContractError):
                    coordinator.finished_controller(*args, **kwargs, current_writer=writer, current_mode="execute")
            steps[-1] = {"name": names[-1], "status": "completed", "conclusion": "failure"}
            with self.assertRaises(ContractError):
                coordinator.finished_controller(*args, **kwargs, current_writer=writer, current_mode="execute")
            steps[-1]["conclusion"] = "success"
            job["status"] = "completed"
            job["conclusion"] = "success"
            read_names = ("Verify recovery readback identity before candidate checkout", "Verify exact reviewed recovery readback checkout",
                          "Verify recovery readback test Bot identity", "Independently read back the recovery evidence")
            read_steps = [{"name": name, "status": "completed", "conclusion": "success"} for name in read_names[:-1]]
            read_steps.append({"name": read_names[-1], "status": "in_progress", "conclusion": None})
            job_list.append({"name": "readback", "run_id": 701, "run_attempt": 1, "head_sha": revision,
                             "status": "in_progress", "steps": read_steps})
            with patch.dict("os.environ", {"BACKUP_GATE_ROLE": "recovery-readback", "BACKUP_RECOVERY_MODE": "readback"}):
                coordinator.finished_controller(*args, **kwargs, current_writer=writer, current_mode="readback")
                read_steps[0]["conclusion"] = "failure"
                with self.assertRaises(ContractError):
                    coordinator.finished_controller(*args, **kwargs, current_writer=writer, current_mode="readback")

    def test_legacy_begin_intent_can_identify_nonce_named_writer(self):
        title = "Production backup begin at " + "b" * 40 + " #" + "c" * 64
        self.assertEqual(cli.run_action(title, "b" * 40), "begin")
        self.assertEqual(cli.run_action(title, "b" * 40, nonce="c" * 64), "begin")
        with self.assertRaises(ContractError):
            cli.run_action(title, "b" * 40, nonce="d" * 64)

    def test_finished_legacy_begin_keeps_full_run_identity_checks(self):
        revision, nonce = "b" * 40, "c" * 64
        workflow = {"id": 7, "path": ".github/workflows/worker-production-backup.yml"}
        run = {"id": 456, "run_attempt": 1, "workflow_id": 7, "event": "workflow_dispatch",
               "head_branch": "main", "head_sha": revision, "status": "completed",
               "display_title": "Production backup begin at " + revision + " #" + nonce,
               "repository": {"id": cli.artifact.REPOSITORY_ID}, "head_repository": {"id": cli.artifact.REPOSITORY_ID}}
        details = {"runId": "456", "runAttempt": "1", "controlRevision": revision}
        def checked(candidate, provided=details):
            with patch.object(cli.artifact, "_github_token", return_value="token"), \
                 patch.object(cli.artifact, "_get_json", side_effect=[candidate, workflow]):
                cli.require_finished_intent(provided, allowed_actions={"begin"})
        checked(run)
        for change in ({"id": 457}, {"run_attempt": 2}, {"head_sha": "d" * 40}):
            with self.subTest(change=change), self.assertRaises(ContractError):
                checked({**run, **change})
        with self.assertRaises(ContractError):
            checked(run, {**details, "dispatchNonce": "d" * 64})

    def test_scheduled_phase_rechecks_slot_start_and_active_anchor_before_claim_guard(self):
        import production_backup_schedule as schedule
        from production_backup_fresh_github import FreshConditionalJSON
        from hashlib import sha256
        target = Mock(digest="a" * 64, configuration_digest="b" * 64)
        target.data = {"backupBucketName": "synthetic-backup", "backupBucketCreatedAt": "2026-11-18T00:00:00Z"}
        policy = {"pauseLimitSeconds": 60}
        revision, source, manifest = "c" * 40, "d" * 32, "e" * 64
        authority = {"targetSha256": target.digest, "configurationSha256": target.configuration_digest,
                     "controlRevision": revision, "policySha256": cli.digest(policy),
                     "ledgerGenesisSha256": "f" * 64, "sourceCheckpointId": source,
                     "sourceManifestSha256": manifest, "scopeSha256": "9" * 64,
                     "targetCoordinatorGenesisSha256": "f" * 64, "applicationGenesisSha256": "7" * 64}
        current = {"state": "active", "session": "123-1", "day": "2026/11/18",
                   "controlRevision": revision, "previousSha256": "1" * 64}
        raw_anchor = canonical(current)
        slot = {"targetSha256": target.digest, "session": "123", "writerRunId": "123",
                "writerAttempt": "1", "slotDay": "2026-11-18",
                "coordinatorAnchorSha256": sha256(raw_anchor).hexdigest(), "scopeSha256": "9" * 64,
                "scopeAnchorSha256": sha256(raw_anchor).hexdigest()}
        start = {"version": 1, "action": "run", "targetSha256": target.digest,
                 "controlRevision": revision, "session": "123", "sourceCheckpointId": source,
                 "sourceManifestSha256": manifest, "anchorSha256": current["previousSha256"],
                 "policySha256": cli.digest(policy), "writerRunId": "123", "writerAttempt": "1",
                 "profile": "production", "candidateRevision": revision, "validationSha256": None,
                 "authoritySha256": "2" * 64, "slotDay": slot["slotDay"], "slotSha256": "3" * 64,
                 "scopePredecessorSha256": "1" * 64}
        env = {"GITHUB_SHA": revision, "BACKUP_ACTION": "pause", "BACKUP_DISPATCH_NONCE": "4" * 64,
               "BACKUP_STATE_SHA256": "5" * 64, "SUBS_BOT_BACKUP_COORDINATOR_GENESIS_SHA256": "f" * 64,
               "SUBS_BOT_BACKUP_SCHEDULE_SCOPE_GENESIS_SHA256": "f" * 64,
               "SUBS_BOT_BACKUP_GENESIS_SHA256": "7" * 64}
        objects, guard, anchor = Mock(), Mock(), Mock()
        client = FreshConditionalJSON()
        objects.get.return_value = (canonical(start), '"etag"')
        anchor.read.return_value = (current, raw_anchor, '"etag"')
        with patch.object(schedule, "read_slot", return_value="3" * 64), \
             patch.object(schedule, "logical_scope", return_value="9" * 64), \
             patch.object(cli, "verify_schedule_scope_start", return_value="8" * 64), \
             patch.object(cli.maintenance, "Anchor", return_value=anchor), \
             patch.object(coordinator, "ScheduleScopeAnchor", return_value=anchor), \
             patch.object(cli, "coordinator_guard", return_value=guard) as make_guard:
            self.assertTrue(cli.verify_claimed_schedule_phase(env, target, objects, policy, slot, "pause", "5" * 64, authority, "2" * 64, "pause", client))
            self.assertFalse(make_guard.call_args.kwargs["claim"])
            self.assertIs(make_guard.call_args.kwargs["scheduled_client"], client)
            for change in ({"slotSha256": "0" * 64}, {"anchorSha256": "0" * 64}, {"writerRunId": "456"}):
                with self.subTest(change=change), self.assertRaises(ContractError):
                    objects.get.return_value = (canonical({**start, **change}), '"etag"')
                    cli.verify_claimed_schedule_phase(env, target, objects, policy, slot, "pause", "5" * 64, authority, "2" * 64, "pause", client)
            objects.get.return_value = (canonical(start), '"etag"')
            with self.assertRaises(ContractError):
                cli.verify_claimed_schedule_phase({**env, "BACKUP_DISPATCH_NONCE": ""}, target, objects, policy, slot,
                                                 "pause", "5" * 64, authority, "2" * 64, "pause", client)

    @patch.object(coordinator, "stage_inputs")
    @patch.object(coordinator, "completed_results")
    @patch.object(coordinator, "verify_child_claim")
    @patch.object(coordinator, "claim_child_once")
    @patch.object(cli, "verify_manual_parent_scope", return_value="run")
    def test_expired_dispatched_pause_is_rejected_but_activation_is_allowed(self, manual_check, _claim, _verify, completed, stage):
        from hashlib import sha256
        target, store = Mock(digest="a" * 64), Mock()
        pause = coordinator.dispatch_intent(target=target.digest, session="123", sequence=5,
            revision="b" * 40, nonce="c" * 64, input_sha256="d" * 64, created_at=1000, writer_run_id="789")
        env = {"GITHUB_SHA": "b" * 40, "GITHUB_RUN_ID": "456", "GITHUB_RUN_ATTEMPT": "1", "BACKUP_ACTION": "pause", "BACKUP_DISPATCH_NONCE": "c" * 64,
               "BACKUP_COORDINATOR_SESSION": "123", "BACKUP_DISPATCH_DEADLINE": "1060",
               "BACKUP_SOURCE_CHECKPOINT_ID": "e" * 32, "BACKUP_SOURCE_MANIFEST_SHA256": "f" * 64,
               "BACKUP_SESSION": "456-1", "BACKUP_SESSION_DAY": "2026/11/18", "BACKUP_STATE_SHA256": "1" * 64}
        inputs = {"action": "pause", "source_checkpoint_id": "e" * 32, "source_manifest_sha256": "f" * 64,
                  "dispatch_nonce": "c" * 64, "coordinator_session": "123", "dispatch_deadline": "1060",
                  "session": "456-1", "session_day": "2026/11/18", "state_sha256": "1" * 64}
        completed.side_effect = lambda *_args, **kwargs: ([{}] * (kwargs["stop_before"] - 1), 1060)
        stage.side_effect = lambda *_args, **_kwargs: (dict(inputs), 1060)
        pause["inputSha256"] = sha256(canonical(inputs)).hexdigest()
        store.objects.get.return_value = (canonical(pause), '"etag"')
        parent = {"id": 789, "run_attempt": 1, "path": ".github/workflows/worker-production-backup-coordinator.yml",
                  "head_sha": "b" * 40, "head_branch": "main", "event": "workflow_dispatch", "status": "in_progress",
                  "display_title": "Production backup coordinator run at " + "b" * 40,
                  "repository": {"id": cli.artifact.REPOSITORY_ID}, "head_repository": {"id": cli.artifact.REPOSITORY_ID}}
        jobs = {"total_count": 1, "jobs": [{"name": "coordinate", "run_id": 789, "run_attempt": 1,
                "head_sha": "b" * 40, "status": "in_progress", "conclusion": None,
                "steps": [{"name": "Coordinate one explicitly approved operation", "status": "in_progress", "conclusion": None}]}]}
        with patch.object(cli.time, "time", return_value=1001), \
             patch.object(cli.artifact, "_github_token", return_value="token"), \
             patch.object(cli.artifact, "_get_json", side_effect=[parent, jobs, parent, jobs, {**parent, "status": "completed"}]):
            guard = cli.coordinator_guard(env, target, store, {"pauseLimitSeconds": 60}, lambda: None)
            with self.assertRaises(ContractError):
                guard()
        resumed = {**parent, "display_title": "Production backup coordinator resume at " + "b" * 40}
        manual_check.return_value = "resume"
        with patch.object(cli.time, "time", return_value=1001) as clock, \
             patch.object(cli.artifact, "_github_token", return_value="token"), \
             patch.object(cli.artifact, "_get_json", side_effect=[resumed, jobs, resumed, jobs]):
            guard = cli.coordinator_guard(env, target, store, {"pauseLimitSeconds": 60}, lambda: None)
            clock.return_value = 1061
            with self.assertRaises(ContractError):
                guard()
        manual_check.return_value = "run"
        ended = {"total_count": 1, "jobs": [{**jobs["jobs"][0],
                 "steps": [{"name": "Coordinate one explicitly approved operation", "status": "completed", "conclusion": "failure"}]}]}
        with patch.object(cli.time, "time", return_value=1001), \
             patch.object(cli.artifact, "_github_token", return_value="token"), \
             patch.object(cli.artifact, "_get_json", side_effect=[parent, ended]), \
             self.assertRaises(ContractError):
            cli.coordinator_guard(env, target, store, {"pauseLimitSeconds": 60}, lambda: None)
        for change in ({"run_attempt": 2}, {"head_sha": "d" * 40}, {"repository": {"id": -1}}):
            with self.subTest(change=change), patch.object(cli.time, "time", return_value=1001), \
                 patch.object(cli.artifact, "_github_token", return_value="token"), \
                 patch.object(cli.artifact, "_get_json", return_value={**parent, **change}), \
                 self.assertRaises(ContractError):
                cli.coordinator_guard(env, target, store, {"pauseLimitSeconds": 60}, lambda: None)
        with patch.object(cli.time, "time", return_value=1001), \
             patch.object(cli.artifact, "_github_token", return_value="token"), \
             patch.object(cli.artifact, "_get_json", side_effect=OSError("unavailable")), \
             self.assertRaises(OSError):
            cli.coordinator_guard(env, target, store, {"pauseLimitSeconds": 60}, lambda: None)
        with patch.object(cli.time, "time", return_value=1001), \
             patch.object(cli.artifact, "_github_token", return_value="token"), \
             patch.object(cli.artifact, "_get_json", return_value={"id": 789, "status": "completed"}), \
             self.assertRaises(ContractError):
            cli.coordinator_guard(env, target, store, {"pauseLimitSeconds": 60}, lambda: None)
        with patch.object(cli.time, "time", return_value=1061), \
             patch.object(cli.artifact, "_github_token", return_value="token"), self.assertRaises(ContractError):
            cli.coordinator_guard(env, target, store, {"pauseLimitSeconds": 60}, lambda: None)
        env["BACKUP_ACTION"] = "activate"
        inputs["action"] = "activate"
        activate = coordinator.dispatch_intent(target=target.digest, session="123", sequence=11,
            revision="b" * 40, nonce="c" * 64, input_sha256=sha256(canonical(inputs)).hexdigest(), created_at=1050, writer_run_id="789")
        store.objects.get.side_effect = [(canonical(activate), '"etag"'), (canonical(pause), '"etag"')]
        with patch.object(cli.time, "time", return_value=1061), \
             patch.object(cli.artifact, "_github_token", return_value="token"), \
             patch.object(cli.artifact, "_get_json", side_effect=[parent, jobs, parent, jobs, parent, jobs]):
            guard = cli.coordinator_guard(env, target, store, {"pauseLimitSeconds": 60}, lambda: None)
            guard()

    def test_abort_rejects_a_child_that_has_not_finished(self):
        from hashlib import sha256
        target, objects, app_store = Mock(digest="a" * 64), Mock(), Mock()
        provisional = coordinator.dispatch_intent(target=target.digest, session="123", sequence=1,
            revision="b" * 40, nonce="c" * 64, input_sha256="0" * 64, created_at=1000, writer_run_id="789")
        inputs, _ = coordinator.stage_inputs([], "1" * 32, "2" * 64, "123", provisional, 900, None)
        intent = {**provisional, "inputSha256": sha256(canonical(inputs)).hexdigest()}
        objects.get.return_value = (canonical(intent), '"etag"')
        workflow = {"path": ".github/workflows/worker-production-backup.yml", "id": 7}
        with patch.object(coordinator.artifact, "_github_token", return_value="token"), \
             patch.object(coordinator.artifact, "_get_json", return_value=workflow), \
             patch.object(coordinator, "inspect_stage", return_value={"status": "unknown"}), \
             patch.object(coordinator, "discover_run", return_value={"id": 456, "status": "in_progress"}), \
             self.assertRaises(ContractError):
            coordinator.abort_observation(objects, app_store, target, "123", "b" * 40,
                                          "1" * 32, "2" * 64, 900, "3" * 64)
        app_store.get.assert_not_called()

    def test_run_discovery_queries_a_bounded_window_and_requires_complete_pages(self):
        from urllib.parse import parse_qs, urlsplit
        value = self.intent()
        rows = [{"id": index + 1, "created_at": "1970-01-01T00:16:40Z"} for index in range(51)]
        first = {"total_count": 51, "workflow_runs": rows[:50]}
        second = {"total_count": 51, "workflow_runs": rows[50:]}
        with patch.object(coordinator.artifact, "_get_json", side_effect=[first, second]) as read, \
             patch.object(coordinator, "matching_run", return_value={"id": 456}) as match:
            self.assertEqual(coordinator.discover_run(value, 7, "token"), {"id": 456})
        query = parse_qs(urlsplit(read.call_args_list[0].args[0]).query)
        self.assertEqual(query["created"], ["1970-01-01T00:14:40Z..1970-01-02T00:16:40Z"])
        self.assertEqual(query["per_page"], ["50"])
        self.assertEqual(len(match.call_args.args[0]), 51)
        with patch.object(coordinator.artifact, "_get_json", side_effect=[first, {**second, "total_count": 52}]), \
             self.assertRaises(ContractError):
            coordinator.discover_run(value, 7, "token")
        with patch.object(coordinator.artifact, "_get_json", side_effect=[first, {**second, "workflow_runs": [rows[0]]}]), \
             self.assertRaises(ContractError):
            coordinator.discover_run(value, 7, "token")


if __name__ == "__main__":
    unittest.main()
