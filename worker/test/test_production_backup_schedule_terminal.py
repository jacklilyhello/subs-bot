"""Synthetic hosted checks for retained scheduled phase evidence."""
from hashlib import sha256
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
from zipfile import ZipFile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import production_backup_coordinator as core
import production_backup_schedule as schedule
import production_backup_schedule_terminal as terminal
import production_backup_transaction as transaction
from production_target import canonical, digest


def phase_jobs(run_id, revision, profile="production"):
    names = (["Run one explicitly selected production checkpoint"] if profile == "production" else
             ["Verify trusted phase identity before candidate checkout", "Verify exact reviewed phase checkout",
              "Verify isolated test Bot identity", "Execute one reviewed rehearsal phase"])
    return {"total_count": 1, "jobs": [{"id": int(run_id) + 50000,
        "name": "checkpoint" if profile == "production" else "phase", "run_id": int(run_id), "run_attempt": 1,
        "head_sha": revision, "status": "completed", "conclusion": "success",
        "steps": [{"name": name, "status": "completed", "conclusion": "success"} for name in names]}]}


class Target:
    environment = "production"
    data = {"d1Name": "subs-bot-source", "bucketName": "subs-bot-data", "backupBucketName": "subs-bot-backup",
            "environment": "production", "workerName": "subs-bot-worker", "accountId": "1" * 32, "workerId": "2" * 32,
            "workerCreatedOn": "2026-01-01T00:00:00Z", "d1Id": "3" * 32, "d1CreatedAt": "2026-01-01T00:00:00Z",
            "bucketCreatedAt": "2026-01-01T00:00:00Z", "backupBucketCreatedAt": "2026-01-01T00:00:00Z", "botId": "12345"}

    @property
    def digest(self):
        return digest({k: v for k, v in self.data.items() if k not in {"features", "provider", "keyDigests", "webhook"}})

    @property
    def configuration_digest(self):
        return digest(self.data)


class Store:
    def __init__(self):
        self.values = {}
        self.reads = 0

    def get(self, key, *, absent=False, limit=16 * 1024 * 1024):
        self.reads += 1
        raw = self.values.get(key)
        if raw is None and absent:
            return None, None
        if raw is None or len(raw) > limit:
            raise ValueError("missing or oversized synthetic original")
        return raw, '"' + "0" * 32 + '"'

    def list(self, prefix, *, maximum=10000):
        keys = sorted(key for key in self.values if key.startswith(prefix))
        if len(keys) > maximum:
            raise ValueError("synthetic inventory exceeds its bound")
        return keys

    def put_once(self, key, raw):
        if key in self.values:
            raise ValueError("synthetic object already exists")
        self.values[key] = raw

    def compare_and_put(self, key, old, etag, raw):
        if self.values.get(key) != old:
            raise ValueError("synthetic predecessor differs")
        self.values[key] = raw
        return '"' + "0" * 32 + '"'


class AppStore:
    def __init__(self):
        self.values = {}

    def get(self, key, *, absent=False):
        if absent:
            return self.values.get(key)
        return self.values[key]

    def get_with_etag(self, key):
        value = self.values.get(key)
        return value, ('"' + "0" * 32 + '"') if value is not None else None

    def put(self, key, raw):
        if key in self.values:
            raise ValueError("synthetic immutable object already exists")
        self.values[key] = raw

    def compare_and_put(self, key, old, etag, raw):
        if self.values.get(key) != old:
            raise ValueError("synthetic predecessor differs")
        self.values[key] = raw

    def list_backup_anchor_history(self, target):
        prefix = "maintenance/production-control/evidence/daily-backup-anchor/" + target + "/"
        return sorted(key for key in self.values if key.startswith(prefix))

    def list_backup_session(self, prefix):
        return sorted(key for key in self.values if key.startswith(prefix))

    def list_backup_journals(self):
        return []


class TerminalEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.target, self.store = Target(), Store()
        self.policy = {"frequencyHours": 24, "windowStartUtc": "01:00", "windowMinutes": 60,
                       "pauseLimitSeconds": 300, "maximumPauseSeconds": 1800}
        self.start_time = int(datetime(2026, 11, 18, tzinfo=timezone.utc).timestamp())
        self.authority = {"version": 1, "kind": "production-backup-schedule", "environment": "production",
            "targetSha256": self.target.digest, "configurationSha256": self.target.configuration_digest,
            "controlRevision": "c" * 40, "sourceRevision": "d" * 40, "sourceCheckpointId": "e" * 32,
            "sourceManifestSha256": "f" * 64, "policySha256": digest(self.policy), "validFrom": self.start_time,
            "validUntil": self.start_time + 604800, "frequencyHours": 24, "maxExecutions": 7,
            "recoveryGraceSeconds": 3600, "ledgerGenesisSha256": "1" * 64,
            "scopeSha256": schedule.logical_scope(self.target), "resourcePins": schedule.resource_pins(self.target),
            "targetCoordinatorGenesisSha256": "4" * 64,
            "applicationGenesisSha256": schedule._hash(transaction.Anchor(None, self.target.digest, "0" * 64).initial_material()[1]),
            "readerLogRetentionDays": 90, "readerLogWarningDays": 7, "readerLogStopBeforeDays": 2,
            "actions": list(schedule.ACTIONS), "authorization": "approved-recurring-backup-only"}
        pin = digest(self.authority)
        self.slot = schedule.slot_intent(self.authority, pin, "2026-11-18", target=self.target, policy=self.policy, session="123",
            scope_anchor_sha256="5" * 64, anchor_sha256="2" * 64, writer_run_id="123", writer_attempt="1")
        self.store.values[schedule.slot_key(self.slot["scopeSha256"], self.slot["slotDay"])] = canonical(self.slot)
        self.workflow = {"path": core.PROFILES["production"]["child"], "id": 999}
        self.responses = {"/actions/workflows/worker-production-backup.yml": self.workflow}
        results, pause_until = [], None
        status = {"plan-begin": "plan-only", "begin": "started", "preflight": "observed", "pause": "paused",
                  "drain": "drained", "freeze": "frozen", "capture": "captured-unverified", "verify": "verified",
                  "activate": "resumed", "plan-pause": "plan-only", "plan-activate": "plan-only"}
        checkpoint = schedule.checkpoint_contract(self.authority, self.target, self.slot["slotDay"])["checkpointId"]
        for sequence, action in enumerate(core.STEPS, 1):
            nonce = str(sequence).zfill(64)
            initial = core.dispatch_intent(target=self.target.digest, session="123", sequence=sequence,
                revision="c" * 40, nonce=nonce, input_sha256="0" * 64, created_at=1700000000 + sequence, writer_run_id="123")
            inputs, pause_until = core.stage_inputs(results, self.authority["sourceCheckpointId"],
                self.authority["sourceManifestSha256"], "123", initial, 1800, pause_until)
            intent = {**initial, "inputSha256": digest(inputs)}
            result = {"status": status[action], "action": action, "targetSha256": self.target.digest,
                      "controlRevision": "c" * 40, "sourceRevision": "d" * 40,
                      "consumerSwitch": "not-authorized", "automaticReplay": False,
                      "stateSha256": "7" * 64}
            if sequence == 1:
                result.update(session="1001-1", day="2026/11/18")
            if action == "verify":
                result.update(checkpointId=checkpoint, manifestSha256="8" * 64)
            result_bytes = BytesIO()
            with ZipFile(result_bytes, "w") as archive:
                archive.writestr("production-backup-result.json", canonical(result))
            archive = result_bytes.getvalue()
            run_id = str(1000 + sequence)
            receipt = core.receipt(intent, run_id, result, str(2000 + sequence), sha256(archive).hexdigest())
            self.store.values[core.event_key(self.target.digest, "123", sequence)] = canonical(intent)
            self.store.values[core.child_claim_key(self.target.digest, "123", sequence)] = canonical(core.child_claim(intent, run_id, "1"))
            self.store.values[core.receipt_key(self.target.digest, "123", sequence)] = canonical(receipt)
            self.store.values[core.result_archive_key(self.target.digest, "123", sequence)] = archive
            run = {"id": int(run_id), "display_title": core.child_title(intent), "run_attempt": 1, "workflow_id": 999,
                   "head_branch": "main", "head_sha": "c" * 40, "event": "workflow_dispatch", "status": "completed",
                   "conclusion": "success", "repository": {"id": core.artifact.REPOSITORY_ID},
                   "head_repository": {"id": core.artifact.REPOSITORY_ID}}
            self.responses["/actions/runs/" + run_id + "/attempts/1"] = run
            self.responses["/actions/runs/" + run_id] = dict(run)
            self.responses["/actions/runs/" + run_id + "/attempts/1/jobs?per_page=100"] = phase_jobs(run_id, "c" * 40)
            results.append(result)

    def collect(self):
        with patch.object(terminal.artifact, "_get_json", side_effect=lambda path, token: self.responses[path]):
            return terminal.collect_phase_evidence(self.store, self.target, self.slot, "test-token")

    def test_complete_chain_and_retained_originals(self):
        evidence = self.collect()
        self.assertEqual(terminal.verify_phase_evidence(self.store, self.target, self.slot, evidence), digest(evidence))
        self.assertEqual(len(evidence["stages"]), len(core.STEPS))
        evidence["stages"][0]["latest"]["conclusion"] = "failure"
        with self.assertRaises(ValueError):
            terminal.verify_phase_evidence(self.store, self.target, self.slot, evidence)

    def test_rehearsal_chain_binds_dispatcher_candidate_and_validation(self):
        class Rehearsal(Target):
            environment = "rehearsal"
            data = {**Target.data, "environment": "rehearsal"}
        target, store = Rehearsal(), Store()
        checkpoint = schedule.checkpoint_id(target.digest, "2026-11-18", profile="rehearsal")
        app_genesis = sha256(transaction.Anchor(None, target.digest, "0" * 64).initial_material()[1]).hexdigest()
        validation = canonical({"version": 1, "pr": "302", "checkpointId": checkpoint, "headSha": "c" * 40,
            "registrationSha256": "9" * 64, "sourceCheckpointId": "e" * 32,
            "sourceManifestSha256": "f" * 64, "genesisSha256": app_genesis}).decode()
        authority = {**self.authority, "environment": "rehearsal", "kind": "rehearsal-backup-schedule",
            "authorization": "approved-isolated-recurring-backup-only", "targetSha256": target.digest,
            "configurationSha256": target.configuration_digest, "scopeSha256": schedule.logical_scope(target),
            "resourcePins": schedule.resource_pins(target), "dispatcherRevision": "a" * 40, "applicationGenesisSha256": app_genesis,
            "registrationSha256": "9" * 64, "validationSha256": sha256(validation.encode()).hexdigest()}
        slot = schedule.slot_intent(authority, digest(authority), "2026-11-18", target=target, policy=self.policy,
            session="123", scope_anchor_sha256="5" * 64, anchor_sha256="2" * 64, writer_run_id="123",
            writer_attempt="1", validation_json=validation)
        store.values[schedule.slot_key(slot["scopeSha256"], slot["slotDay"], profile="rehearsal")] = canonical(slot)
        child = core.PROFILES["rehearsal"]["child"]
        responses = {"/actions/workflows/" + child.rsplit("/", 1)[-1]: {"path": child, "id": 999}}
        statuses = {"plan-begin": "plan-only", "begin": "started", "preflight": "observed", "pause": "paused",
                    "drain": "drained", "freeze": "frozen", "capture": "captured-unverified", "verify": "verified",
                    "activate": "resumed", "plan-pause": "plan-only", "plan-activate": "plan-only"}
        results, pause_until = [], None
        for sequence, action in enumerate(core.STEPS, 1):
            intent = core.dispatch_intent(target=target.digest, session="123", sequence=sequence, revision="a" * 40,
                candidate_revision="c" * 40, profile="rehearsal", nonce=str(sequence).zfill(64),
                input_sha256="0" * 64, created_at=1700000000 + sequence, writer_run_id="123")
            inputs, pause_until = core.stage_inputs(results, authority["sourceCheckpointId"], authority["sourceManifestSha256"],
                "123", intent, 1800, pause_until, validation_json=validation)
            intent["inputSha256"] = digest(inputs)
            result = {"status": statuses[action], "action": action, "targetSha256": target.digest,
                "controlRevision": "c" * 40, "dispatcherRevision": "a" * 40, "sourceRevision": "d" * 40,
                "consumerSwitch": "not-authorized", "automaticReplay": False, "stateSha256": "7" * 64}
            if sequence == 1:
                result.update(session="1001-1", day="2026/11/18")
            if action == "verify":
                result.update(checkpointId=checkpoint, manifestSha256="8" * 64)
            buf = BytesIO()
            with ZipFile(buf, "w") as archive:
                archive.writestr("production-backup-result.json", canonical(result))
            archive = buf.getvalue()
            run_id = str(1000 + sequence)
            receipt = core.receipt(intent, run_id, result, str(2000 + sequence), sha256(archive).hexdigest())
            store.values[core.event_key(target.digest, "123", sequence)] = canonical(intent)
            store.values[core.child_claim_key(target.digest, "123", sequence)] = canonical(core.child_claim(intent, run_id, "1"))
            store.values[core.receipt_key(target.digest, "123", sequence)] = canonical(receipt)
            store.values[core.result_archive_key(target.digest, "123", sequence)] = archive
            run = {"id": int(run_id), "display_title": core.child_title(intent), "run_attempt": 1, "workflow_id": 999,
                "head_branch": "main", "head_sha": "a" * 40, "event": "workflow_dispatch", "status": "completed",
                "conclusion": "success", "repository": {"id": core.artifact.REPOSITORY_ID},
                "head_repository": {"id": core.artifact.REPOSITORY_ID}}
            responses["/actions/runs/" + run_id + "/attempts/1"] = run
            responses["/actions/runs/" + run_id] = dict(run)
            responses["/actions/runs/" + run_id + "/attempts/1/jobs?per_page=100"] = phase_jobs(run_id, "a" * 40, "rehearsal")
            results.append(result)
        with patch.object(terminal.artifact, "_get_json", side_effect=lambda path, token: responses[path]):
            evidence = terminal.collect_phase_evidence(store, target, slot, "synthetic")
            self.assertEqual(terminal.verify_phase_evidence(store, target, slot, evidence), digest(evidence))
            changed = {**slot, "validationJson": validation + " "}
            with self.assertRaises(ValueError):
                terminal.verify_phase_evidence(store, target, changed, evidence)
            altered = dict(evidence)
            altered["workflow"] = {"path": core.PROFILES["production"]["child"], "id": 999}
            with self.assertRaises(ValueError):
                terminal.verify_phase_evidence(store, target, slot, altered)
            evidence["stages"][0]["jobs"]["jobs"][0]["steps"][0]["conclusion"] = "skipped"
            with self.assertRaises(ValueError):
                terminal.verify_phase_evidence(store, target, slot, evidence)

    def test_seven_daily_phase_evidence_chains_have_bounded_reads(self):
        """Synthetic clock/metadata exercise; this is not seven live backups."""
        statuses = {"plan-begin": "plan-only", "begin": "started", "preflight": "observed", "pause": "paused",
                    "drain": "drained", "freeze": "frozen", "capture": "captured-unverified", "verify": "verified",
                    "activate": "resumed", "plan-pause": "plan-only", "plan-activate": "plan-only"}
        all_gh_reads = 0
        for cycle in range(7):
            clock = patch("time.time", return_value=self.start_time + cycle * 86400 + 4000)
            clock.start()
            self.addCleanup(clock.stop)
            store, session, day = Store(), str(500 + cycle), "2026-11-" + str(18 + cycle)
            self.assertEqual(schedule.eligible_slot(self.authority, self.policy,
                                                    self.start_time + cycle * 86400 + 3600), day)
            slot = schedule.slot_intent(self.authority, digest(self.authority), day, target=self.target, policy=self.policy,
                session=session, scope_anchor_sha256="5" * 64, anchor_sha256="2" * 64,
                writer_run_id=session, writer_attempt="1")
            store.values[schedule.slot_key(slot["scopeSha256"], day)] = canonical(slot)
            responses = {"/actions/workflows/worker-production-backup.yml": self.workflow}
            values, pause_until = [], None
            checkpoint = schedule.checkpoint_id(self.target.digest, day)
            first_run = str(20000 + cycle * 100 + 1)
            for sequence, action in enumerate(core.STEPS, 1):
                run_id, nonce = str(20000 + cycle * 100 + sequence), format(cycle * 32 + sequence, "064x")
                initial = core.dispatch_intent(target=self.target.digest, session=session, sequence=sequence,
                    revision="c" * 40, nonce=nonce, input_sha256="0" * 64,
                    created_at=self.start_time + 3600 + cycle * 86400 + sequence, writer_run_id=session)
                inputs, pause_until = core.stage_inputs(values, self.authority["sourceCheckpointId"],
                    self.authority["sourceManifestSha256"], session, initial, 1800, pause_until)
                intent = {**initial, "inputSha256": digest(inputs)}
                result = {"status": statuses[action], "action": action, "targetSha256": self.target.digest,
                          "controlRevision": "c" * 40, "sourceRevision": "d" * 40, "consumerSwitch": "not-authorized",
                          "automaticReplay": False, "stateSha256": "7" * 64}
                if sequence == 1:
                    result.update(session=first_run + "-1", day=day.replace("-", "/"))
                if action == "verify":
                    result.update(checkpointId=checkpoint, manifestSha256="8" * 64)
                stream = BytesIO()
                with ZipFile(stream, "w") as archive:
                    archive.writestr("production-backup-result.json", canonical(result))
                raw_archive = stream.getvalue()
                receipt = core.receipt(intent, run_id, result, str(30000 + cycle * 100 + sequence), sha256(raw_archive).hexdigest())
                store.values[core.event_key(self.target.digest, session, sequence)] = canonical(intent)
                store.values[core.child_claim_key(self.target.digest, session, sequence)] = canonical(core.child_claim(intent, run_id, "1"))
                store.values[core.receipt_key(self.target.digest, session, sequence)] = canonical(receipt)
                store.values[core.result_archive_key(self.target.digest, session, sequence)] = raw_archive
                run = {"id": int(run_id), "display_title": core.child_title(intent), "run_attempt": 1, "workflow_id": 999,
                       "head_branch": "main", "head_sha": "c" * 40, "event": "workflow_dispatch", "status": "completed",
                       "conclusion": "success", "repository": {"id": core.artifact.REPOSITORY_ID},
                       "head_repository": {"id": core.artifact.REPOSITORY_ID}}
                responses["/actions/runs/" + run_id + "/attempts/1"] = run
                responses["/actions/runs/" + run_id] = dict(run)
                responses["/actions/runs/" + run_id + "/attempts/1/jobs?per_page=100"] = phase_jobs(run_id, "c" * 40)
                values.append(result)
            with patch.object(terminal.artifact, "_get_json", side_effect=lambda path, token: responses[path]) as gh:
                evidence = terminal.collect_phase_evidence(store, self.target, slot, "synthetic")
                self.assertEqual(terminal.verify_phase_evidence(store, self.target, slot, evidence), digest(evidence))
                self.assertEqual(gh.call_count, 57)
                self.assertLess(store.reads, 500)
                all_gh_reads += gh.call_count
            clock.stop()
        self.assertEqual(all_gh_reads, 399)

    def test_reader_log_must_uniquely_bind_exact_witness(self):
        line = b"2026-11-18T01:02:03.123Z SCHEDULE_WITNESS_SHA256=" + b"a" * 64 + b"\n"
        with patch("trusted_backup_webhook_log_archive.download_log", return_value=line):
            self.assertTrue(terminal.verify_reader_log("123", "synthetic", "a" * 64))
            with self.assertRaises(ValueError):
                terminal.verify_reader_log("123", "synthetic", "b" * 64)
        with patch("trusted_backup_webhook_log_archive.download_log", return_value=line + line):
            with self.assertRaises(ValueError):
                terminal.verify_reader_log("123", "synthetic", "a" * 64)
        with patch("trusted_backup_webhook_log_archive.download_log", return_value=line + b"SCHEDULE_WITNESS_SHA256=invalid\n"):
            with self.assertRaises(ValueError):
                terminal.verify_reader_log("123", "synthetic", "a" * 64)
        manual_line = b"2026-11-18T01:02:03.123Z SCHEDULE_MANUAL_COMPLETE_SHA256=" + b"b" * 64 + b"\n"
        with patch("trusted_backup_webhook_log_archive.download_log", return_value=manual_line):
            self.assertTrue(terminal._verify_job_marker("123", "synthetic", "b" * 64, "SCHEDULE_MANUAL_COMPLETE_SHA256"))
            with self.assertRaises(ValueError):
                terminal._verify_job_marker("123", "synthetic", "b" * 64, "SCHEDULE_WITNESS_SHA256")

    def test_reader_retention_warns_and_stops_before_operator_bound(self):
        created = "2026-11-18T00:00:00Z"
        # Test the helper using a standard-library UTC conversion rather than a platform claim.
        from datetime import datetime, timezone
        start = int(datetime.strptime(created, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp())
        normal = terminal.reader_log_deadlines(created, self.authority, start + 82 * 86400)
        self.assertFalse(normal["warning"])
        warning = terminal.reader_log_deadlines(created, self.authority, start + 83 * 86400)
        self.assertTrue(warning["warning"])
        self.assertFalse(warning["stop"])
        stopped = terminal.reader_log_deadlines(created, self.authority, start + 88 * 86400)
        self.assertTrue(stopped["stop"])
        with self.assertRaises(ValueError):
            terminal.reader_log_deadlines("unknown", self.authority, start)

    def test_manual_writer_requires_original_success_and_exact_completion_marker(self):
        from datetime import datetime, timezone
        now = int(datetime(2026, 11, 19, tzinfo=timezone.utc).timestamp())
        path = ".github/workflows/worker-production-recovery.yml"
        start = {"controlRevision": "c" * 40, "writerRunId": "123", "workflowRef": core.artifact.REPOSITORY +
                 "/" + path + "@" + core.artifact.MAIN_REF, "action": "capture",
                 "readerLogPolicy": {"version": 1, "retentionDays": 90, "warningDays": 7, "stopBeforeDays": 2}}
        record = {"start": start, "complete": {}, "result": {}, "completeSha256": "5" * 64}
        run = {"id": 123, "run_attempt": 1, "head_sha": "c" * 40, "head_branch": "main", "event": "workflow_dispatch",
               "path": path, "status": "completed", "conclusion": "success", "created_at": "2026-11-18T00:00:00Z",
               "repository": {"id": core.artifact.REPOSITORY_ID}, "head_repository": {"id": core.artifact.REPOSITORY_ID}}
        job = {"id": 456, "name": "recovery", "run_id": 123, "run_attempt": 1, "head_sha": "c" * 40,
               "status": "completed", "conclusion": "success", "steps": [{"name": "Verify identities and execute one production-aware checkpoint",
                                                                            "status": "completed", "conclusion": "success"}]}
        def query(url, token):
            return {"total_count": 1, "jobs": [job]} if "/jobs?" in url else dict(run)
        with patch.object(core, "historical_manual_source_review", return_value={"revision": "c" * 40}), \
                patch.object(terminal.artifact, "_get_json", side_effect=query), \
                patch.object(terminal, "_verify_job_marker", return_value=True):
            self.assertFalse(terminal.verify_manual_job(record, "synthetic", {}, now)["warning"])
            near_expiry = now + 88 * 86400
            with self.assertRaises(ValueError):
                terminal.verify_manual_job(record, "synthetic", {}, near_expiry)
            self.assertTrue(terminal.verify_manual_job(record, "synthetic", {}, near_expiry, allow_expiring=True)["stop"])
            run["run_attempt"] = 2
            with self.assertRaises(ValueError):
                terminal.verify_manual_job(record, "synthetic", {}, now)
            run["run_attempt"] = 1
            job["steps"][0]["conclusion"] = "skipped"
            with self.assertRaises(ValueError):
                terminal.verify_manual_job(record, "synthetic", {}, now)

    def test_changed_archive_or_reordered_stage_is_rejected(self):
        evidence = self.collect()
        key = core.result_archive_key(self.target.digest, "123", 5)
        self.store.values[key] += b"changed"
        with self.assertRaises(ValueError):
            terminal.verify_phase_evidence(self.store, self.target, self.slot, evidence)
        self.store.values[key] = self.store.values[key][:-7]
        evidence["stages"][0], evidence["stages"][1] = evidence["stages"][1], evidence["stages"][0]
        with self.assertRaises(ValueError):
            terminal.verify_phase_evidence(self.store, self.target, self.slot, evidence)

    def test_witness_structure_rechecks_terminal_and_private_originals(self):
        phase = self.collect()
        terminal_value = schedule.terminal_record(self.slot, chain_sha256=digest(phase),
                                                  scope_idle_anchor_sha256="4" * 64,
                                                  coordinator_idle_anchor_sha256="6" * 64, result="success")
        raw_terminal = canonical(terminal_value)
        self.store.values[schedule.terminal_key(self.slot["scopeSha256"], self.slot["slotDay"])] = raw_terminal
        review = {"version": 1, "controllers": {}}
        witness = {"version": 1, "kind": "scheduled-backup-independent-witness", "targetSha256": self.target.digest,
                   "scopeSha256": self.slot["scopeSha256"],
                   "slotDay": self.slot["slotDay"], "session": self.slot["session"],
                   "slotSha256": sha256(canonical(self.slot)).hexdigest(), "terminalSha256": sha256(raw_terminal).hexdigest(),
                   "reviewSha256": digest(review), "review": review, "parent": {}, "phaseEvidence": phase,
                   "appTerminal": {}}
        key = terminal.witness_key(self.slot["scopeSha256"], self.slot["slotDay"])
        self.store.values[key] = canonical(witness)
        observed = terminal.read_witness_structure(self.store, self.target, self.slot)
        self.assertEqual(observed["witnessSha256"], sha256(canonical(witness)).hexdigest())
        # Structural validation does not authenticate the empty synthetic parent/app evidence.
        self.store.values[schedule.terminal_key(self.slot["scopeSha256"], self.slot["slotDay"])] += b" "
        with self.assertRaises(ValueError):
            terminal.read_witness_structure(self.store, self.target, self.slot)

    def test_app_terminal_requires_exact_verified_resumed_chain(self):
        phase = self.collect()
        app = AppStore()
        seed = transaction.Anchor(app, self.target.digest, "0" * 64)
        genesis_sha = sha256(seed.initial_material()[1]).hexdigest()
        anchor = transaction.Anchor(app, self.target.digest, genesis_sha)
        anchor.initialize()
        session, day = "1001-1", "2026/11/18"
        anchor.acquire(session, day, "c" * 40)
        journal = transaction.Transaction(app, session, day, self.target.digest, "c" * 40)
        checkpoint = schedule.checkpoint_contract(self.authority, self.target, self.slot["slotDay"])["checkpointId"]
        started = {"checkpointId": checkpoint, "policySha256": digest(self.policy),
                   "configurationSha256": self.target.configuration_digest,
                   "release": {"revision": "d" * 40},
                   "control": {"admission": "open", "workers": "run"}}
        observed_capacity = {"version": 1, "consistency": "unfrozen-observation", "snapshot": False,
            "rows": 1, "rowLimit": 20000, "rowStatus": "normal", "tableCounts": {"subs_bot_schema_migrations": 1},
            "warningPercent": 80, "objectCount": 0, "objectLimit": 512, "objectBytes": 0,
            "objectBytesLimit": 256 * 1024 * 1024, "objectStatus": "normal", "objectBytesStatus": "normal",
            "objectClosureSha256": sha256(canonical([])).hexdigest(), "sqlBytes": None,
            "sqlBytesStatus": "unknown-until-native-export", "backupVerified": False}
        stages = (("started", started), ("preflight", {"capacity": observed_capacity}), ("pause-intent", {}), ("paused", {}),
                  ("freeze-intent", {}), ("frozen", {}), ("frozen-data", {}), ("capture-intent", {}),
                  ("verified", {"checkpointId": checkpoint, "manifestSha256": "8" * 64}),
                  ("resume-intent", {}), ("resumed", {"control": {"admission": "open", "workers": "run"}}))
        for index, (stage, details) in enumerate(stages, 1):
            journal.append(stage, details, 1700000000 + index)
        anchor.release(session)
        observed = terminal.collect_app_terminal(self.store, app, self.target, self.slot, phase, genesis_sha)
        self.assertEqual(observed["session"], session)
        app.values[journal.prefix + "0011.json"] += b" "
        with self.assertRaises(ValueError):
            terminal.collect_app_terminal(self.store, app, self.target, self.slot, phase, genesis_sha)

    def test_later_github_attempt_or_absent_receipt_is_not_evidence(self):
        self.responses["/actions/runs/1001"]["run_attempt"] = 2
        with self.assertRaises(ValueError):
            self.collect()
        self.responses["/actions/runs/1001"]["run_attempt"] = 1
        del self.store.values[core.receipt_key(self.target.digest, "123", 3)]
        with self.assertRaises(ValueError):
            self.collect()

    def test_empty_scope_inventory_rejects_orphan_scope_start(self):
        store = Store()
        scope = schedule.logical_scope(self.target)
        scope_store = core.CoordinatorStore(store, scope)
        scope_seed = core.ScheduleScopeAnchor(scope_store, scope, "0" * 64,
                                             self.target.data["backupBucketName"], self.target.data["backupBucketCreatedAt"])
        scope_genesis = sha256(scope_seed.initial_material()[1]).hexdigest()
        scope_anchor = core.ScheduleScopeAnchor(scope_store, scope, scope_genesis,
                                               self.target.data["backupBucketName"], self.target.data["backupBucketCreatedAt"])
        scope_anchor.initialize()
        target_store = core.CoordinatorStore(store, self.target.digest)
        target_seed = transaction.Anchor(target_store, self.target.digest, "0" * 64)
        target_genesis = sha256(target_seed.initial_material()[1]).hexdigest()
        transaction.Anchor(target_store, self.target.digest, target_genesis).initialize()
        observed = terminal.scope_inventory(store, self.target, scope_anchor, target_genesis)
        self.assertEqual(observed["records"], [])
        self.assertEqual(observed["historyCount"], 0)
        store.values[schedule.scope_start_key(scope, "123")] = b"{}"
        with self.assertRaises(ValueError):
            terminal.scope_inventory(store, self.target, scope_anchor, target_genesis)

    def test_manual_scope_requires_all_private_originals_and_exact_anchor(self):
        import production_backup_manual_scope as manual_scope
        store = Store()
        scope = schedule.logical_scope(self.target)
        scope_store = core.CoordinatorStore(store, scope)
        seed = core.ScheduleScopeAnchor(scope_store, scope, "0" * 64,
                                        self.target.data["backupBucketName"], self.target.data["backupBucketCreatedAt"])
        scope_genesis = sha256(seed.initial_material()[1]).hexdigest()
        scope_anchor = core.ScheduleScopeAnchor(scope_store, scope, scope_genesis,
                                                self.target.data["backupBucketName"], self.target.data["backupBucketCreatedAt"])
        scope_anchor.initialize()
        target_store = core.CoordinatorStore(store, self.target.digest)
        target_seed = transaction.Anchor(target_store, self.target.digest, "0" * 64)
        target_genesis = sha256(target_seed.initial_material()[1]).hexdigest()
        transaction.Anchor(target_store, self.target.digest, target_genesis).initialize()
        previous, raw, _ = scope_anchor.read()
        predicted = {"version": 1, "targetSha256": scope, "generation": previous["generation"] + 1,
                     "previousSha256": sha256(raw).hexdigest(), "state": "active", "session": "123-1",
                     "day": "2026/11/18", "controlRevision": "c" * 40}
        active_sha = sha256(canonical(predicted)).hexdigest()
        retention = {"version": 1, "retentionDays": 90, "warningDays": 7, "stopBeforeDays": 2}
        start = {"version": 1, "kind": "manual-backup-scope-start", "scopeSha256": scope,
            "targetSha256": self.target.digest, "configurationSha256": self.target.configuration_digest,
            "targetDocument": self.target.data, "policy": self.policy, "policySha256": digest(self.policy),
            "readerLogPolicy": retention, "readerLogPolicySha256": digest(retention),
            "priorScopeKeysSha256": digest([]),
            "targetCoordinatorGenesisSha256": target_genesis,
            "applicationGenesisSha256": self.authority["applicationGenesisSha256"], "action": "capture",
            "approvalActionSha256": "1" * 64, "approvalSha256": "2" * 64, "predecessorSha256": "3" * 64,
            "scopePredecessorSha256": sha256(raw).hexdigest(), "scopeAnchorSha256": active_sha,
            "coordinatorSession": None, "writerRunId": "123", "writerAttempt": "1", "day": "2026/11/18",
            "workflowRef": core.artifact.REPOSITORY + "/.github/workflows/worker-production-recovery.yml@" + core.artifact.MAIN_REF,
            "controlRevision": "c" * 40, "sourceRevision": "d" * 40}
        store.put_once(manual_scope.start_key(scope, "123"), canonical(start))
        scope_anchor.acquire("123-1", "2026/11/18", "c" * 40)
        result_raw = canonical({"action": "capture", "phase": "captured"})
        store.put_once(manual_scope.result_key(scope, "123"), result_raw)
        scope_anchor.release("123-1")
        _idle, idle_raw, _etag = scope_anchor.read()
        done = {"version": 1, "kind": "manual-backup-scope-complete", "scopeSha256": scope,
                "startSha256": sha256(canonical(start)).hexdigest(), "idleAnchorSha256": sha256(idle_raw).hexdigest(),
                "resultSha256": sha256(result_raw).hexdigest(), "writerRunId": "123", "writerAttempt": "1"}
        store.put_once(manual_scope.complete_key(scope, "123"), canonical(done))
        with patch("production_target.validate_target", return_value=self.target):
            observed = terminal.scope_inventory(store, self.target, scope_anchor, target_genesis)
            self.assertEqual(observed["records"][0]["kind"], "manual-needs-verification")
            del store.values[manual_scope.complete_key(scope, "123")]
            with self.assertRaises(ValueError):
                terminal.scope_inventory(store, self.target, scope_anchor, target_genesis)

    def test_manual_result_reconciliation_plan_never_replays_or_authorizes(self):
        import production_backup_manual_scope as manual_scope
        store = Store()
        scope = schedule.logical_scope(self.target)
        scope_store = core.CoordinatorStore(store, scope)
        seed = core.ScheduleScopeAnchor(scope_store, scope, "0" * 64,
                                        self.target.data["backupBucketName"], self.target.data["backupBucketCreatedAt"])
        genesis = sha256(seed.initial_material()[1]).hexdigest()
        anchor = core.ScheduleScopeAnchor(scope_store, scope, genesis,
                                         self.target.data["backupBucketName"], self.target.data["backupBucketCreatedAt"])
        anchor.initialize()
        target_store = core.CoordinatorStore(store, self.target.digest)
        target_seed = transaction.Anchor(target_store, self.target.digest, "0" * 64)
        target_genesis = sha256(target_seed.initial_material()[1]).hexdigest()
        transaction.Anchor(target_store, self.target.digest, target_genesis).initialize()
        prior, prior_raw, _ = anchor.read()
        predicted = {"version": 1, "targetSha256": scope, "generation": prior["generation"] + 1,
                     "previousSha256": sha256(prior_raw).hexdigest(), "state": "active", "session": "123-1",
                     "day": "2026/11/18", "controlRevision": "c" * 40}
        workflow = ".github/workflows/worker-production-backup.yml"
        retention = {"version": 1, "retentionDays": 90, "warningDays": 7, "stopBeforeDays": 2}
        start = {"version": 1, "kind": "manual-backup-scope-start", "scopeSha256": scope, "targetSha256": self.target.digest,
                 "configurationSha256": self.target.configuration_digest, "targetDocument": self.target.data,
                 "policy": self.policy, "policySha256": digest(self.policy), "readerLogPolicy": retention,
                 "readerLogPolicySha256": digest(retention), "priorScopeKeysSha256": digest([]),
                 "applicationGenesisSha256": "1" * 64, "targetCoordinatorGenesisSha256": target_genesis,
                 "approvalActionSha256": "3" * 64, "approvalSha256": "4" * 64, "predecessorSha256": "5" * 64,
                 "writerRunId": "123", "writerAttempt": "1", "controlRevision": "c" * 40,
                 "scopeAnchorSha256": sha256(canonical(predicted)).hexdigest(),
                 "scopePredecessorSha256": sha256(prior_raw).hexdigest(), "action": "pause",
                 "coordinatorSession": None, "sourceRevision": "d" * 40, "day": "2026/11/18",
                 "workflowRef": core.artifact.REPOSITORY + "/" + workflow + "@" + core.artifact.MAIN_REF}
        store.put_once(manual_scope.start_key(scope, "123"), canonical(start))
        anchor.acquire("123-1", "2026/11/18", "c" * 40)
        store.put_once(manual_scope.result_key(scope, "123"), canonical({"action": "pause", "status": "paused"}))
        run = {"id": 123, "run_attempt": 1, "head_sha": "c" * 40, "head_branch": "main", "event": "workflow_dispatch",
               "path": workflow, "status": "completed", "conclusion": "failure",
               "repository": {"id": core.artifact.REPOSITORY_ID}, "head_repository": {"id": core.artifact.REPOSITORY_ID}}
        job = {"id": 456, "name": "checkpoint", "run_id": 123, "run_attempt": 1, "head_sha": "c" * 40,
               "status": "completed", "steps": [{"name": "Run one explicitly selected production checkpoint",
                                                 "status": "completed", "conclusion": "failure"}]}
        def query(url, token):
            return {"total_count": 1, "jobs": [job]} if "/jobs?" in url else dict(run)
        with patch.object(core, "historical_manual_source_review", return_value={"revision": "c" * 40}), \
                patch.object(terminal.artifact, "_get_json", side_effect=query), \
                patch.object(core, "scheduled_review_document", return_value=({}, "0" * 64)):
            env = {"SUBS_BOT_BACKUP_SCHEDULE_SCOPE_GENESIS_SHA256": genesis,
                   "SUBS_BOT_BACKUP_COORDINATOR_GENESIS_SHA256": target_genesis, "SUBS_BOT_BACKUP_GENESIS_SHA256": "1" * 64}
            plan = terminal.plan_manual_result_reconciliation(store, self.target, anchor, "synthetic",
                env, "123")
            self.assertTrue(plan["requiresFullScopeInventory"])
            self.assertEqual(plan["scopeState"], "active")
            self.assertTrue(plan["scopeInventory"]["requiresHistoricalTerminalVerification"])
            prior = terminal.verify_manual_prior_history(store, AppStore(), self.target, anchor, "synthetic", env,
                                                        "123", "1" * 64, target_genesis, self.policy)
            self.assertTrue(prior["historicalVerificationComplete"])
            self.assertFalse(prior["mutationAuthorized"])
            def attempts_hidden_read(view, *_args, **_kwargs):
                view.get(manual_scope.start_key(scope, "123"))
            with patch.object(terminal, "verify_prior_history", side_effect=attempts_hidden_read):
                with self.assertRaises(ValueError):
                    terminal.verify_manual_prior_history(store, AppStore(), self.target, anchor, "synthetic", env,
                                                         "123", "1" * 64, target_genesis, self.policy)
            orphan = schedule.BASE + scope + "/manual/999-start.json"
            store.values[orphan] = b"{}"
            with self.assertRaises(ValueError):
                terminal.plan_manual_result_reconciliation(store, self.target, anchor, "synthetic",
                    {"SUBS_BOT_BACKUP_SCHEDULE_SCOPE_GENESIS_SHA256": genesis}, "123")
            del store.values[orphan]
            run["run_attempt"] = 2
            with self.assertRaises(ValueError):
                terminal.plan_manual_result_reconciliation(store, self.target, anchor, "synthetic",
                    {"SUBS_BOT_BACKUP_SCHEDULE_SCOPE_GENESIS_SHA256": genesis}, "123")
            run["run_attempt"] = 1
            anchor.release("123-1")
            _idle, idle_raw, _etag = anchor.read()
            result_raw = store.values[manual_scope.result_key(scope, "123")]
            done = {"version": 1, "kind": "manual-backup-scope-complete", "scopeSha256": scope,
                    "startSha256": sha256(canonical(start)).hexdigest(), "idleAnchorSha256": sha256(idle_raw).hexdigest(),
                    "resultSha256": sha256(result_raw).hexdigest(), "writerRunId": "123", "writerAttempt": "1"}
            store.put_once(manual_scope.complete_key(scope, "123"), canonical(done))
            with patch.object(terminal, "_verify_job_marker", return_value=True), patch.object(store, "put_once") as writer:
                observed = terminal.inspect_manual_completion(store, self.target, anchor, "synthetic",
                    {"SUBS_BOT_BACKUP_SCHEDULE_SCOPE_GENESIS_SHA256": genesis}, "123")
                self.assertEqual(observed["kind"], "manual-completion-readback")
                self.assertTrue(observed["requiresFullScopeInventory"])
                prior = terminal.verify_manual_prior_history(store, AppStore(), self.target, anchor, "synthetic", env,
                                                            "123", "1" * 64, target_genesis, self.policy)
                self.assertTrue(prior["historicalVerificationComplete"])
                self.assertFalse(prior["mutationAuthorized"])
                writer.assert_not_called()

    def test_target_genesis_absence_only_allows_exact_initialization_context(self):
        store = Store()
        scope = schedule.logical_scope(self.target)
        scope_store = core.CoordinatorStore(store, scope)
        seed = core.ScheduleScopeAnchor(scope_store, scope, "0" * 64,
                                        self.target.data["backupBucketName"], self.target.data["backupBucketCreatedAt"])
        genesis = sha256(seed.initial_material()[1]).hexdigest()
        scope_anchor = core.ScheduleScopeAnchor(scope_store, scope, genesis,
                                                self.target.data["backupBucketName"], self.target.data["backupBucketCreatedAt"])
        scope_anchor.initialize()
        target_seed = transaction.Anchor(core.CoordinatorStore(store, self.target.digest), self.target.digest, "0" * 64)
        target_genesis = sha256(target_seed.initial_material()[1]).hexdigest()
        with self.assertRaises(ValueError):
            terminal.scope_inventory(store, self.target, scope_anchor, target_genesis)
        env = {"GITHUB_REPOSITORY": core.artifact.REPOSITORY, "GITHUB_REPOSITORY_ID": str(core.artifact.REPOSITORY_ID),
               "GITHUB_REF": core.artifact.MAIN_REF, "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_RUN_ATTEMPT": "1",
               "RUNNER_ENVIRONMENT": "github-hosted", "GITHUB_WORKFLOW_REF": core.artifact.REPOSITORY +
               "/.github/workflows/worker-production-backup-coordinator.yml@" + core.artifact.MAIN_REF,
               "BACKUP_COORDINATOR_ACTION": "initialize", "SUBS_BOT_BACKUP_COORDINATOR_GENESIS_SHA256": target_genesis}
        self.assertEqual(terminal.scope_inventory(store, self.target, scope_anchor, target_genesis, env=env)["historyCount"], 0)
        store.values[core.BASE + self.target.digest + "/123/start-intent.json"] = b"{}"
        with self.assertRaises(ValueError):
            terminal.scope_inventory(store, self.target, scope_anchor, target_genesis, env=env)

    def test_scope_inventory_reconstructs_old_target_after_configuration_rotation(self):
        import production_target as contract
        from test_production_control import fixture
        original, _ = fixture()
        data = dict(original.data)
        data.update(environment="production", workerName=contract.NAMES["production"][0],
                    d1Name=contract.NAMES["production"][0], bucketName=contract.NAMES["production"][0],
                    backupBucketName=contract.NAMES["production"][1], hostname=contract.NAMES["production"][2],
                    botId="92001", botUsername="SyntheticProdBot")
        old_target = contract.validate_target(data)
        new_target = contract.validate_target({**data, "generation": data["generation"] + 1})
        self.assertNotEqual(old_target.digest, new_target.digest)
        scope = schedule.logical_scope(old_target)
        self.assertEqual(scope, schedule.logical_scope(new_target))
        objects = Store()
        scope_store = core.CoordinatorStore(objects, scope)
        seed = core.ScheduleScopeAnchor(scope_store, scope, "0" * 64, data["backupBucketName"], data["backupBucketCreatedAt"])
        scope_genesis = sha256(seed.initial_material()[1]).hexdigest()
        scope_anchor = core.ScheduleScopeAnchor(scope_store, scope, scope_genesis, data["backupBucketName"], data["backupBucketCreatedAt"])
        scope_anchor.initialize()
        def initialize_target(target):
            store = core.CoordinatorStore(objects, target.digest)
            seed = transaction.Anchor(store, target.digest, "0" * 64)
            genesis = sha256(seed.initial_material()[1]).hexdigest()
            anchor = transaction.Anchor(store, target.digest, genesis)
            anchor.initialize()
            return anchor, genesis
        old_anchor, old_genesis = initialize_target(old_target)
        policy = self.policy
        authority = {**self.authority, "targetSha256": old_target.digest,
            "configurationSha256": old_target.configuration_digest, "scopeSha256": scope,
            "resourcePins": schedule.resource_pins(old_target), "ledgerGenesisSha256": scope_genesis,
            "targetCoordinatorGenesisSha256": old_genesis,
            "applicationGenesisSha256": sha256(transaction.Anchor(None, old_target.digest, "0" * 64).initial_material()[1]).hexdigest()}
        def anticipated(anchor):
            previous, raw, _ = anchor.read()
            value = {"version": 1, "targetSha256": anchor.target_sha256, "generation": previous["generation"] + 1,
                     "previousSha256": sha256(raw).hexdigest(), "state": "active", "session": "123-1",
                     "day": "2026/11/18", "controlRevision": "c" * 40}
            return sha256(raw).hexdigest(), sha256(canonical(value)).hexdigest()
        scope_before, scope_active = anticipated(scope_anchor)
        target_before, target_active = anticipated(old_anchor)
        slot = schedule.slot_intent(authority, digest(authority), "2026-11-18", target=old_target, policy=policy,
            session="123", scope_anchor_sha256=scope_active, anchor_sha256=target_active, writer_run_id="123", writer_attempt="1")
        slot_sha = sha256(canonical(slot)).hexdigest()
        start = {"version": 1, "action": "run", "targetSha256": old_target.digest, "controlRevision": "c" * 40,
                 "session": "123", "sourceCheckpointId": "e" * 32, "sourceManifestSha256": "f" * 64,
                 "anchorSha256": target_before, "scopePredecessorSha256": scope_before,
                 "policySha256": digest(policy), "writerRunId": "123", "writerAttempt": "1", "profile": "production",
                 "candidateRevision": "c" * 40, "validationSha256": None, "authoritySha256": digest(authority),
                 "slotDay": "2026-11-18", "slotSha256": slot_sha}
        scope_start = schedule.scope_start(authority, "2026-11-18", session="123", scope_predecessor_sha256=scope_before,
            target_predecessor_sha256=target_before, scope_anchor_sha256=scope_active, coordinator_anchor_sha256=target_active,
            slot_sha256=slot_sha, target_start_sha256=sha256(canonical(start)).hexdigest(), writer_run_id="123", writer_attempt="1")
        objects.put_once(schedule.scope_start_key(scope, "123"), canonical(scope_start))
        objects.put_once(core.BASE + old_target.digest + "/123/start-intent.json", canonical(start))
        scope_anchor.acquire("123-1", "2026/11/18", "c" * 40)
        old_anchor.acquire("123-1", "2026/11/18", "c" * 40)
        objects.put_once(schedule.slot_key(scope, "2026-11-18"), canonical(slot))
        old_anchor.release("123-1")
        scope_anchor.release("123-1")
        _new_anchor, new_genesis = initialize_target(new_target)
        inventory = terminal.scope_inventory(objects, new_target, scope_anchor, new_genesis)
        self.assertEqual(inventory["historyCount"], 1)
        self.assertEqual(inventory["records"][0]["target"].digest, old_target.digest)
        self.assertEqual(schedule.slot_key(schedule.logical_scope(new_target), "2026-11-18"),
                         schedule.slot_key(scope, "2026-11-18"))

    def test_seven_consecutive_scope_claims_retain_all_history(self):
        import production_target as contract
        from test_production_control import fixture
        original, _ = fixture()
        data = {**original.data, "environment": "production", "workerName": contract.NAMES["production"][0],
                "d1Name": contract.NAMES["production"][0], "bucketName": contract.NAMES["production"][0],
                "backupBucketName": contract.NAMES["production"][1], "hostname": contract.NAMES["production"][2],
                "botId": "92001", "botUsername": "SyntheticProdBot"}
        target = contract.validate_target(data)
        objects, scope = Store(), schedule.logical_scope(target)
        scope_store = core.CoordinatorStore(objects, scope)
        seed = core.ScheduleScopeAnchor(scope_store, scope, "0" * 64, data["backupBucketName"], data["backupBucketCreatedAt"])
        scope_genesis = sha256(seed.initial_material()[1]).hexdigest()
        scope_anchor = core.ScheduleScopeAnchor(scope_store, scope, scope_genesis, data["backupBucketName"], data["backupBucketCreatedAt"])
        scope_anchor.initialize()
        target_store = core.CoordinatorStore(objects, target.digest)
        target_seed = transaction.Anchor(target_store, target.digest, "0" * 64)
        target_genesis = sha256(target_seed.initial_material()[1]).hexdigest()
        target_anchor = transaction.Anchor(target_store, target.digest, target_genesis)
        target_anchor.initialize()
        authority = {**self.authority, "targetSha256": target.digest, "configurationSha256": target.configuration_digest,
            "scopeSha256": scope, "resourcePins": schedule.resource_pins(target), "ledgerGenesisSha256": scope_genesis,
            "targetCoordinatorGenesisSha256": target_genesis,
            "applicationGenesisSha256": sha256(transaction.Anchor(None, target.digest, "0" * 64).initial_material()[1]).hexdigest()}
        def anticipated(anchor, session, day):
            previous, raw, _ = anchor.read()
            value = {"version": 1, "targetSha256": anchor.target_sha256, "generation": previous["generation"] + 1,
                     "previousSha256": sha256(raw).hexdigest(), "state": "active", "session": session + "-1",
                     "day": day.replace("-", "/"), "controlRevision": "c" * 40}
            return sha256(raw).hexdigest(), sha256(canonical(value)).hexdigest()
        for offset in range(7):
            session, day = str(123 + offset), "2026-11-" + str(18 + offset)
            scope_before, scope_active = anticipated(scope_anchor, session, day)
            target_before, target_active = anticipated(target_anchor, session, day)
            slot = schedule.slot_intent(authority, digest(authority), day, target=target, policy=self.policy, session=session,
                scope_anchor_sha256=scope_active, anchor_sha256=target_active, writer_run_id=session, writer_attempt="1")
            slot_sha = sha256(canonical(slot)).hexdigest()
            start = {"version": 1, "action": "run", "targetSha256": target.digest, "controlRevision": "c" * 40,
                "session": session, "sourceCheckpointId": "e" * 32, "sourceManifestSha256": "f" * 64,
                "anchorSha256": target_before, "scopePredecessorSha256": scope_before, "policySha256": digest(self.policy),
                "writerRunId": session, "writerAttempt": "1", "profile": "production", "candidateRevision": "c" * 40,
                "validationSha256": None, "authoritySha256": digest(authority), "slotDay": day, "slotSha256": slot_sha}
            scope_start = schedule.scope_start(authority, day, session=session, scope_predecessor_sha256=scope_before,
                target_predecessor_sha256=target_before, scope_anchor_sha256=scope_active, coordinator_anchor_sha256=target_active,
                slot_sha256=slot_sha, target_start_sha256=sha256(canonical(start)).hexdigest(), writer_run_id=session, writer_attempt="1")
            objects.put_once(schedule.scope_start_key(scope, session), canonical(scope_start))
            objects.put_once(core.BASE + target.digest + "/" + session + "/start-intent.json", canonical(start))
            scope_anchor.acquire(session + "-1", day.replace("-", "/"), "c" * 40)
            target_anchor.acquire(session + "-1", day.replace("-", "/"), "c" * 40)
            objects.put_once(schedule.slot_key(scope, day), canonical(slot))
            target_anchor.release(session + "-1")
            scope_anchor.release(session + "-1")
        inventory = terminal.scope_inventory(objects, target, scope_anchor, target_genesis)
        self.assertEqual(inventory["historyCount"], 7)
        self.assertTrue(all(record["kind"] == "scheduled-needs-verification" for record in inventory["records"]))
        # This fixture exercises cumulative claims only; it does not fabricate seven successful backups.


if __name__ == "__main__":
    unittest.main()
