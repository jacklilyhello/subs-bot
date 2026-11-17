"""Hosted checks for the real isolated D1 capacity fixture contract."""
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import production_backup_capacity_fixture as fixture
import native_restore_rehearsal as native
from production_target import ContractError
from test_production_backup_transaction import Store


class FixtureStore(Store):
    put_once = Store.put_exclusive


class CapacityFixtureTests(unittest.TestCase):
    def test_seed_is_bound_to_every_table_count_and_only_appends_finished_rows(self):
        counts = {"subs_bot_production_invocations": 0, "subscriptions": 3}
        plan = fixture.seed_plan(target_sha256="a" * 64, database_id="00000000-0000-4000-8000-000000000001", counts=counts, desired=16000)
        sql = fixture.seed_sql(plan, counts)
        self.assertEqual(plan["seedRows"], 15997)
        self.assertIn('(SELECT count(*) FROM "subscriptions")=3', sql)
        self.assertIn("'finished'", sql)
        self.assertNotIn("DELETE", sql.upper())
        with self.assertRaises(ContractError):
            fixture.seed_sql(plan, {**counts, "subscriptions": 4})

    def test_unknown_or_preexisting_intent_never_reissues_seed(self):
        api, store, source = Mock(), Mock(), Mock()
        source.migrations = [None] * 56
        api.fixture_rows_verified.return_value = True
        observation = {"tableCounts": {"subs_bot_production_invocations": 0, "subs_bot_schema_migrations": 56},
                       "rowStatus": "normal", "objectStatus": "normal", "objectBytesStatus": "normal"}
        store.get.return_value = b"previous"
        with patch.object(fixture.capacity, "observe", return_value=observation), self.assertRaises(ContractError):
            fixture.seed_once(api, store, source, target_sha256="a" * 64,
                database_id="00000000-0000-4000-8000-000000000001", desired=16000, now=1, run_id="123", guard=lambda: None, controller_revision="b" * 40, dispatcher_revision="c" * 40)
        api.seed_fixture.assert_not_called()
        store.put_once.assert_not_called()
        store.get.return_value = None
        store.put_once.side_effect = RuntimeError("lost response")
        with patch.object(fixture.capacity, "observe", return_value=observation), self.assertRaises(RuntimeError):
            fixture.seed_once(api, store, source, target_sha256="a" * 64,
                database_id="00000000-0000-4000-8000-000000000001", desired=16000, now=1, run_id="123", guard=lambda: None, controller_revision="b" * 40, dispatcher_revision="c" * 40)
        api.seed_fixture.assert_not_called()
        store.put_once.assert_called_once()

    def test_non_fixture_business_record_prevents_any_intent_or_d1_write(self):
        api, store, source = Mock(), Mock(), Mock()
        source.migrations = [None] * 56
        observation = {"tableCounts": {"subs_bot_production_invocations": 0,
            "subs_bot_schema_migrations": 56, "subscriptions": 1}, "rowStatus": "normal", "objectStatus": "normal", "objectBytesStatus": "normal"}
        with patch.object(fixture.capacity, "observe", return_value=observation), self.assertRaises(ContractError):
            fixture.seed_once(api, store, source, target_sha256="a" * 64,
                database_id="00000000-0000-4000-8000-000000000001", desired=16000, now=1, run_id="123", guard=lambda: None, controller_revision="b" * 40, dispatcher_revision="c" * 40)
        store.put_once.assert_not_called()
        api.seed_fixture.assert_not_called()

    def test_shared_gate_refuses_over_limit_and_unverified_objects(self):
        for value in ({"rowStatus": "over-limit", "objectStatus": "not-checked", "objectBytesStatus": "unknown"},
                      {"rowStatus": "normal", "objectStatus": "unverified", "objectBytesStatus": "unknown"}):
            with self.assertRaises(native.RehearsalError):
                fixture.capacity.require_within_limits(value)

    def test_exact_real_over_limit_result_uses_the_shared_pre_pause_gate(self):
        api, source, store = Mock(), Mock(), FixtureStore()
        source.migrations = [None] * 56
        api.fixture_rows_verified.return_value = True
        before = {"tableCounts": {"subs_bot_production_invocations": 19944, "subs_bot_schema_migrations": 56}, "rowStatus": "warning",
                  "objectStatus": "normal", "objectBytesStatus": "normal"}
        after = {"rows": 20001, "rowStatus": "over-limit", "objectStatus": "not-checked",
                 "tableCounts": {"subs_bot_production_invocations": 19945, "subs_bot_schema_migrations": 56}}
        with patch.object(fixture.capacity, "observe", side_effect=[before, after]):
            result = fixture.seed_once(api, store, source, target_sha256="a" * 64,
                database_id="00000000-0000-4000-8000-000000000001", desired=20001, now=1, run_id="123", guard=lambda: None, controller_revision="b" * 40, dispatcher_revision="c" * 40)
        self.assertTrue(result["prePauseRejected"])
        self.assertFalse(result["pausePerformed"])
        api.seed_fixture.assert_called_once()
        import prepare_isolation_artifact as github
        run = {"id": 123, "run_attempt": 1, "workflow_id": 8, "head_sha": "c" * 40,
               "head_branch": "main", "event": "workflow_dispatch", "status": "completed", "conclusion": "success",
               "repository": {"id": github.REPOSITORY_ID}, "head_repository": {"id": github.REPOSITORY_ID}}
        # A missing independent workflow identity is rejected before reading D1.
        with patch.object(github, "_github_token", return_value="synthetic"), \
             patch.object(github, "_get_json", side_effect=[run, {"id": 8, "path": ".github/workflows/worker-backup-reviewed-head.yml"},
                                                            {"total_count": 0, "jobs": []}]), \
             self.assertRaises(ContractError):
            fixture.verify_seed(api, store, source, target_sha256="a" * 64, desired=20001,
                                controller_revision="b" * 40, dispatcher_revision="c" * 40, guard=lambda: None)

    def test_independent_fixture_pins_reject_old_or_bound_database(self):
        from hashlib import sha256
        from production_target import ACCOUNT, canonical
        registration = {"version": 1, "accountId": ACCOUNT, "databaseId": "00000000-0000-4000-8000-000000000001",
                        "databaseName": "subs-bot-cf-backup-capacity-20261118", "createdAt": "2026-11-18T00:00:00Z",
                        "bucketName": "subs-bot-cf-dev-01", "bucketCreatedAt": "2026-11-18T00:00:00Z"}
        witness = {"version": 1, "accountId": ACCOUNT, "databaseId": registration["databaseId"], "observedAt": 1000,
                   "workerBindingCount": 0}
        pin = sha256(canonical(registration)).hexdigest()
        witness_pin = sha256(canonical(witness)).hexdigest()
        self.assertEqual(fixture.validate_registration(registration, pin, witness, witness_pin, now=1100, excluded_database_ids=[]), pin)
        with self.assertRaises(ContractError):
            fixture.validate_registration(registration, pin, witness, witness_pin, now=2000, excluded_database_ids=[])
        with self.assertRaises(ContractError):
            fixture.validate_registration(registration, pin, witness, witness_pin, now=1100,
                                          excluded_database_ids=[registration["databaseId"]])
