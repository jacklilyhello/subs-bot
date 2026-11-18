"""Synthetic tests for protected recurring backup policy; no cloud access."""
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import production_backup_schedule as schedule
import production_backup_transaction as transaction
import production_backup_fresh_github as fresh
from production_target import canonical, digest


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


class Objects:
    def __init__(self, body):
        self.body = body

    def get(self, key):
        return self.body, '"' + "0" * 32 + '"'


class TestScheduledPolicy(unittest.TestCase):
    def setUp(self):
        self.target = Target()
        self.start = int(datetime(2026, 11, 18, tzinfo=timezone.utc).timestamp())
        self.policy = {"frequencyHours": 24, "windowStartUtc": "01:00", "windowMinutes": 60,
                       "maximumPauseSeconds": 1800}
        self.authority = {"version": 1, "kind": "production-backup-schedule", "environment": "production",
            "targetSha256": self.target.digest, "configurationSha256": self.target.configuration_digest,
            "controlRevision": "c" * 40, "sourceRevision": "d" * 40, "sourceCheckpointId": "e" * 32,
            "sourceManifestSha256": "f" * 64, "policySha256": digest(self.policy), "validFrom": self.start,
            "validUntil": self.start + 7 * 86400, "frequencyHours": 24, "maxExecutions": 7,
            "recoveryGraceSeconds": 3600, "ledgerGenesisSha256": "1" * 64,
            "scopeSha256": schedule.logical_scope(self.target), "resourcePins": schedule.resource_pins(self.target),
            "targetCoordinatorGenesisSha256": "4" * 64,
            "applicationGenesisSha256": schedule._hash(transaction.Anchor(None, self.target.digest, "0" * 64).initial_material()[1]),
            "readerLogRetentionDays": 90, "readerLogWarningDays": 7, "readerLogStopBeforeDays": 2,
            "actions": list(schedule.ACTIONS), "authorization": "approved-recurring-backup-only"}

    def validated(self, value=None, pin=None):
        raw = canonical(self.authority if value is None else value)
        return schedule.authority_document(raw, pin or schedule._hash(raw), target=self.target,
            control_revision="c" * 40, source_revision="d" * 40, source_checkpoint_id="e" * 32,
            source_manifest_sha256="f" * 64, policy=self.policy, target_genesis_sha256="4" * 64,
            application_genesis_sha256=self.authority["applicationGenesisSha256"])

    def test_exact_pin_target_and_canonical_encoding_are_required(self):
        self.assertEqual(self.validated(), self.authority)
        for key, bad in (("targetSha256", "2" * 64), ("configurationSha256", "2" * 64),
                         ("controlRevision", "2" * 40), ("sourceRevision", "2" * 40),
                         ("sourceManifestSha256", "2" * 64), ("policySha256", "2" * 64),
                         ("actions", ["pause", "deploy"])):
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.validated({**self.authority, key: bad})
        with self.assertRaises(ValueError):
            self.validated(pin="2" * 64)
        with self.assertRaises(ValueError):
            schedule.authority_document(canonical(self.authority) + b" ", schedule._hash(canonical(self.authority) + b" "),
                target=self.target, control_revision="c" * 40, source_revision="d" * 40,
                source_checkpoint_id="e" * 32, source_manifest_sha256="f" * 64, policy=self.policy,
                target_genesis_sha256="4" * 64, application_genesis_sha256=self.authority["applicationGenesisSha256"])

    def test_bounds_and_exact_integer_types(self):
        for key, bad in (("validFrom", True), ("frequencyHours", 25), ("maxExecutions", 0),
                         ("recoveryGraceSeconds", 86401), ("validUntil", self.start + 32 * 86400)):
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.validated({**self.authority, key: bad})

    def test_rehearsal_authority_requires_distinct_registration_and_dispatcher(self):
        class RehearsalTarget(Target):
            environment = "rehearsal"
            data = {**Target.data, "environment": "rehearsal"}
        target = RehearsalTarget()
        app_genesis = schedule._hash(transaction.Anchor(None, target.digest, "0" * 64).initial_material()[1])
        spec = {"version": 1, "pr": "302", "headSha": "c" * 40, "registrationSha256": "8" * 64,
                "sourceCheckpointId": "e" * 32, "sourceManifestSha256": "f" * 64,
                "genesisSha256": app_genesis,
                "checkpointId": schedule.checkpoint_id(target.digest, "2026-11-18", profile="rehearsal")}
        validation = canonical(spec).decode()
        value = {**self.authority, "kind": "rehearsal-backup-schedule", "environment": "rehearsal",
                 "authorization": "approved-isolated-recurring-backup-only", "dispatcherRevision": "9" * 40,
                 "registrationSha256": "8" * 64, "validationSha256": schedule._hash(validation.encode()),
                 "scopeSha256": schedule.logical_scope(target), "targetSha256": target.digest,
                 "configurationSha256": target.configuration_digest, "applicationGenesisSha256": app_genesis}
        raw = canonical(value)
        kwargs = {"target": target, "control_revision": "c" * 40, "source_revision": "d" * 40,
                  "source_checkpoint_id": "e" * 32, "source_manifest_sha256": "f" * 64,
                  "policy": self.policy, "profile": "rehearsal", "dispatcher_revision": "9" * 40,
                  "registration_sha256": "8" * 64, "validation_json": validation}
        kwargs["target_genesis_sha256"] = "4" * 64
        kwargs["application_genesis_sha256"] = value["applicationGenesisSha256"]
        self.assertEqual(schedule.authority_document(raw, schedule._hash(raw), **kwargs), value)
        for changed in ({"registration_sha256": "7" * 64}, {"dispatcher_revision": "7" * 40},
                        {"control_revision": "9" * 40}, {"target": self.target}):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                schedule.authority_document(raw, schedule._hash(raw), **{**kwargs, **changed})
        with self.assertRaises(ValueError):
            schedule.authority_document(raw, schedule._hash(raw), target=self.target, control_revision="c" * 40,
                source_revision="d" * 40, source_checkpoint_id="e" * 32, source_manifest_sha256="f" * 64,
                policy=self.policy)
        self.assertNotEqual(schedule.slot_key(value["scopeSha256"], "2026-11-18", profile="rehearsal"),
                            schedule.slot_key(self.authority["scopeSha256"], "2026-11-18", profile="production"))
        self.assertNotEqual(schedule.checkpoint_contract(value, target, "2026-11-18")["checkpointId"],
                            schedule.checkpoint_contract(self.authority, self.target, "2026-11-18")["checkpointId"])
        slot = schedule.slot_intent(value, schedule._hash(raw), "2026-11-18", target=target, policy=self.policy, session="123",
            scope_anchor_sha256="5" * 64, anchor_sha256="2" * 64, writer_run_id="123", writer_attempt="1", validation_json=validation)
        self.assertEqual(slot["validationJson"], validation)
        with self.assertRaises(ValueError):
            schedule.slot_intent(value, schedule._hash(raw), "2026-11-19", target=target, policy=self.policy, session="123",
                scope_anchor_sha256="5" * 64, anchor_sha256="2" * 64, writer_run_id="123", writer_attempt="1", validation_json=validation)

    def test_daily_window_and_expiry(self):
        policy = self.validated()
        self.assertIsNone(schedule.eligible_slot(policy, self.policy, self.start + 59 * 60))
        self.assertEqual(schedule.eligible_slot(policy, self.policy, self.start + 3600), "2026-11-18")
        self.assertIsNone(schedule.eligible_slot(policy, self.policy, self.start + 7200))
        self.assertIsNone(schedule.eligible_slot(policy, self.policy, policy["validUntil"]))

    def test_seven_distinct_daily_slots_without_extending_authority(self):
        authority = self.validated()
        slots = [schedule.eligible_slot(authority, self.policy, self.start + day * 86400 + 3600)
                 for day in range(7)]
        self.assertEqual(slots, ["2026-11-18", "2026-11-19", "2026-11-20", "2026-11-21",
                                 "2026-11-22", "2026-11-23", "2026-11-24"])
        self.assertEqual(len({schedule.slot_key(self.authority["scopeSha256"], day) for day in slots}), 7)
        self.assertIsNone(schedule.eligible_slot(authority, self.policy, self.start + 7 * 86400 + 3600))

    def test_frequency_and_window_crossing_midnight(self):
        self.policy.update(frequencyHours=48, windowStartUtc="23:30", windowMinutes=60)
        self.authority.update(frequencyHours=48, policySha256=digest(self.policy))
        authority = self.validated()
        self.assertEqual(schedule.eligible_slot(authority, self.policy, self.start + 24 * 3600 + 10 * 60),
                         "2026-11-18")
        self.assertIsNone(schedule.eligible_slot(authority, self.policy, self.start + 47 * 3600 + 45 * 60))
        self.assertEqual(schedule.eligible_slot(authority, self.policy, self.start + 71 * 3600 + 45 * 60),
                         "2026-11-20")

    def test_fixed_slot_independent_of_policy_and_independent_recovery_names(self):
        value = self.validated()
        slot = schedule.slot_key(self.authority["scopeSha256"], "2026-11-18")
        self.assertEqual(slot, schedule.slot_key(self.authority["scopeSha256"], "2026-11-18"))
        first = schedule.checkpoint_contract(value, self.target, "2026-11-18")
        second = schedule.checkpoint_contract(value, self.target, "2026-11-19")
        self.assertNotEqual(first["checkpointId"], second["checkpointId"])
        self.assertNotEqual(first["databaseName"], first["objectsName"])
        self.assertEqual(first["purpose"], "baseline")

    def test_logical_scope_survives_target_configuration_and_resource_rotation(self):
        class ChangedTarget(Target):
            digest = "9" * 64
            configuration_digest = "8" * 64
            data = {**Target.data, "workerId": "7" * 32, "d1Id": "6" * 32, "botId": "98765"}
        changed = ChangedTarget()
        self.assertEqual(schedule.logical_scope(self.target), schedule.logical_scope(changed))
        self.assertNotEqual(schedule.resource_pins(self.target), schedule.resource_pins(changed))

    def test_scope_start_binds_both_anchor_predecessors_and_one_writer(self):
        value = schedule.scope_start(self.authority, "2026-11-18", session="123", writer_run_id="123", writer_attempt="1",
            scope_predecessor_sha256="1" * 64, target_predecessor_sha256="2" * 64,
            scope_anchor_sha256="3" * 64, coordinator_anchor_sha256="4" * 64,
            slot_sha256="5" * 64, target_start_sha256="6" * 64)
        self.assertEqual(value["scopeSha256"], schedule.logical_scope(self.target))
        self.assertEqual(value["scopeAnchorSha256"], "3" * 64)
        with self.assertRaises(ValueError):
            schedule.scope_start(self.authority, "2026-11-18", session="123", writer_run_id="124", writer_attempt="1",
                scope_predecessor_sha256="1" * 64, target_predecessor_sha256="2" * 64,
                scope_anchor_sha256="3" * 64, coordinator_anchor_sha256="4" * 64,
                slot_sha256="5" * 64, target_start_sha256="6" * 64)

    def test_pause_requires_live_exact_slot_and_sufficient_authority(self):
        authority = self.validated()
        raw = canonical(authority)
        pin = schedule._hash(raw)
        slot = schedule.slot_intent(authority, pin, "2026-11-18", target=self.target, policy=self.policy, session="123", scope_anchor_sha256="5" * 64, anchor_sha256="2" * 64,
                                    writer_run_id="123", writer_attempt="1")
        env = {"SUBS_BOT_PRODUCTION_BACKUP_SCHEDULE_AUTHORITY_JSON": raw.decode(),
               "SUBS_BOT_PRODUCTION_BACKUP_SCHEDULE_AUTHORITY_SHA256": pin,
               "SUBS_BOT_BACKUP_COORDINATOR_GENESIS_SHA256": "4" * 64,
               "SUBS_BOT_BACKUP_GENESIS_SHA256": authority["applicationGenesisSha256"],
               "SUBS_BOT_PRODUCTION_BACKUP_SCHEDULE_ENABLED": "true"}
        with self.assertRaises(ValueError):
            schedule.ScheduledApproval(env=env, objects=Objects(canonical(slot)), target=self.target,
                policy=self.policy, authority=authority, authority_sha256=pin, slot=slot, step="pause", action="pause",
                predecessor="3" * 64, fresh_client=object())
        grant = schedule.ScheduledApproval(env=env, objects=Objects(canonical(slot)), target=self.target,
            policy=self.policy, authority=authority, authority_sha256=pin, slot=slot, step="pause", action="pause", predecessor="3" * 64,
            fresh_client=fresh.FreshConditionalJSON())
        with patch.object(schedule.time, "time", return_value=self.start + 3600), \
                patch("production_backup_cli.verify_claimed_schedule_phase", return_value=True) as verify_phase:
            self.assertTrue(grant.verify(self.target, "pause", "d" * 40, "c" * 40, "3" * 64))
            verify_phase.assert_called_once_with(env, self.target, grant.objects, self.policy, slot, "pause", "3" * 64,
                                                 authority, pin, "pause", grant.fresh_client)
            with self.assertRaises(ValueError):
                grant.verify(self.target, "freeze", "d" * 40, "c" * 40, "3" * 64)
            grant.objects.body = b"{}"
            with self.assertRaises(ValueError):
                grant.verify(self.target, "pause", "d" * 40, "c" * 40, "3" * 64)
            grant.objects.body = canonical(slot)
            verify_phase.return_value = False
            with self.assertRaises(ValueError):
                grant.verify(self.target, "pause", "d" * 40, "c" * 40, "3" * 64)
            verify_phase.return_value = True
            env["SUBS_BOT_PRODUCTION_BACKUP_SCHEDULE_ENABLED"] = "false"
            with self.assertRaises(ValueError):
                grant.verify(self.target, "pause", "d" * 40, "c" * 40, "3" * 64)
            env["SUBS_BOT_PRODUCTION_BACKUP_SCHEDULE_ENABLED"] = "true"
            env["SUBS_BOT_PRODUCTION_BACKUP_SCHEDULE_AUTHORITY_SHA256"] = "9" * 64
            with self.assertRaises(ValueError):
                grant.verify(self.target, "pause", "d" * 40, "c" * 40, "3" * 64)
            env["SUBS_BOT_PRODUCTION_BACKUP_SCHEDULE_AUTHORITY_SHA256"] = pin
        grant.objects.body = canonical(slot)
        with patch.object(schedule.time, "time", return_value=authority["validUntil"] - 60):
            with self.assertRaises(ValueError):
                grant.verify(self.target, "pause", "d" * 40, "c" * 40, "3" * 64)

    def test_pause_near_expiry_rejected_within_window(self):
        self.authority["validUntil"] = self.start + 4500
        authority = self.validated()
        raw = canonical(authority)
        pin = schedule._hash(raw)
        slot = schedule.slot_intent(authority, pin, "2026-11-18", target=self.target, policy=self.policy, session="123", scope_anchor_sha256="5" * 64, anchor_sha256="2" * 64,
                                    writer_run_id="123", writer_attempt="1")
        env = {"SUBS_BOT_PRODUCTION_BACKUP_SCHEDULE_AUTHORITY_JSON": raw.decode(),
               "SUBS_BOT_PRODUCTION_BACKUP_SCHEDULE_AUTHORITY_SHA256": pin,
               "SUBS_BOT_BACKUP_COORDINATOR_GENESIS_SHA256": "4" * 64,
               "SUBS_BOT_BACKUP_GENESIS_SHA256": authority["applicationGenesisSha256"],
               "SUBS_BOT_PRODUCTION_BACKUP_SCHEDULE_ENABLED": "true"}
        grant = schedule.ScheduledApproval(env=env, objects=Objects(canonical(slot)), target=self.target,
            policy=self.policy, authority=authority, authority_sha256=pin, slot=slot, step="pause", action="pause", predecessor="3" * 64,
            fresh_client=fresh.FreshConditionalJSON())
        with patch.object(schedule.time, "time", return_value=self.start + 3600), \
                patch("production_backup_cli.verify_claimed_schedule_phase", return_value=True) as verify_phase:
            with self.assertRaises(ValueError):
                grant.verify(self.target, "pause", "d" * 40, "c" * 40, "3" * 64)
            verify_phase.assert_not_called()

    def test_only_exact_step_and_deterministic_contract_scope_are_granted(self):
        authority = self.validated()
        raw = canonical(authority)
        pin = schedule._hash(raw)
        slot = schedule.slot_intent(authority, pin, "2026-11-18", target=self.target, policy=self.policy, session="123",
                                    scope_anchor_sha256="5" * 64, anchor_sha256="2" * 64, writer_run_id="123", writer_attempt="1")
        env = {"SUBS_BOT_PRODUCTION_BACKUP_SCHEDULE_AUTHORITY_JSON": raw.decode(),
               "SUBS_BOT_PRODUCTION_BACKUP_SCHEDULE_AUTHORITY_SHA256": pin,
               "SUBS_BOT_BACKUP_COORDINATOR_GENESIS_SHA256": "4" * 64,
               "SUBS_BOT_BACKUP_GENESIS_SHA256": authority["applicationGenesisSha256"],
               "SUBS_BOT_PRODUCTION_BACKUP_SCHEDULE_ENABLED": "true"}
        contract_sha = digest(schedule.checkpoint_contract(authority, self.target, slot["slotDay"]))
        cases = (("preflight", "backup-preflight:" + contract_sha),
                 ("capture", "recovery-prepare:" + contract_sha),
                 ("capture", "recovery-capture:" + contract_sha),
                 ("verify", "backup-verify:" + contract_sha),
                 ("begin", "backup-begin:" + "6" * 64))
        with patch.object(schedule.time, "time", return_value=self.start + 3600), \
                patch("production_backup_cli.verify_claimed_schedule_phase", return_value=True) as verifier:
            for step, action in cases:
                grant = schedule.ScheduledApproval(env=env, objects=Objects(canonical(slot)), target=self.target,
                    policy=self.policy, authority=authority, authority_sha256=pin, slot=slot,
                    step=step, action=action, predecessor="3" * 64, fresh_client=fresh.FreshConditionalJSON())
                self.assertTrue(grant.verify(self.target, action, "d" * 40, "c" * 40, "3" * 64))
            self.assertEqual(verifier.call_count, len(cases))
            for step, action in (("capture", "recovery-capture:" + "8" * 64),
                                 ("capture", "recovery-restore-objects:" + contract_sha),
                                 ("verify", "backup-begin:" + "6" * 64)):
                grant = schedule.ScheduledApproval(env=env, objects=Objects(canonical(slot)), target=self.target,
                    policy=self.policy, authority=authority, authority_sha256=pin, slot=slot,
                    step=step, action=action, predecessor="3" * 64, fresh_client=fresh.FreshConditionalJSON())
                with self.assertRaises(ValueError):
                    grant.verify(self.target, action, "d" * 40, "c" * 40, "3" * 64)

    def test_earlier_slot_same_day_not_reissued_and_terminal_binds_intent(self):
        authority = self.validated()
        pin = schedule._hash(canonical(authority))
        slot = schedule.slot_intent(authority, pin, "2026-11-18", target=self.target, policy=self.policy, session="123", scope_anchor_sha256="5" * 64, anchor_sha256="2" * 64,
                                    writer_run_id="123", writer_attempt="1")
        terminal = schedule.terminal_record(slot, chain_sha256="3" * 64,
                                             scope_idle_anchor_sha256="4" * 64,
                                             coordinator_idle_anchor_sha256="6" * 64, result="success")
        self.assertEqual(slot["authority"], authority)
        self.assertEqual(slot["policy"], self.policy)
        self.assertEqual(terminal["intentSha256"], schedule._hash(canonical(slot)))
        changed = {**slot, "authoritySha256": "5" * 64}
        self.assertNotEqual(terminal["intentSha256"], schedule._hash(canonical(changed)))
        self.assertEqual(schedule.slot_key(slot["scopeSha256"], slot["slotDay"]),
                         schedule.slot_key(changed["scopeSha256"], changed["slotDay"]))
        with self.assertRaises(ValueError):
            schedule.slot_intent(authority, pin, "2026-11-18", target=self.target, policy=self.policy, session="123", scope_anchor_sha256="5" * 64, anchor_sha256="2" * 64,
                                 writer_run_id="123", writer_attempt="2")
        with self.assertRaises(ValueError):
            schedule.slot_intent(authority, pin, "2026-11-18", target=self.target, policy={**self.policy, "windowMinutes": 1},
                                 session="123", scope_anchor_sha256="5" * 64, anchor_sha256="2" * 64, writer_run_id="123", writer_attempt="1")


if __name__ == "__main__":
    unittest.main()
