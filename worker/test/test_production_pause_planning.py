"""Hosted pause planning checks with actual changing invocation/outbox rows."""
from copy import deepcopy
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock

WORKER = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WORKER / "tools"))
import production_control as control
import production_target as contract
import test_production_control as fixtures


class PausePlanningTests(unittest.TestCase):
    def setUp(self):
        fixtures.ProductionControllerTests.setUp(self)
        self.controller.initialize()
        self.api.db.execute("UPDATE subs_bot_production_control SET admission='open',workers='run'")

    def invocation(self, identity):
        self.api.db.execute("""INSERT INTO subs_bot_production_invocations
            VALUES(?,?,?,1,'scheduled',unixepoch(),unixepoch()+960,'running',NULL)""",
            (identity, self.target.digest, self.target.data["botId"]))

    def approve_pause(self, plan):
        return fixtures.approval(self.target, "pause", plan["stateSha256"])

    def test_pause_under_load_uses_stable_approval_and_keeps_accepted_work(self):
        self.invocation("a" * 32)
        planned = self.controller.plan_pause()
        self.assertEqual(planned["work"]["invocations"], 1)
        self.assertEqual(set(planned["approvalState"]), {"planAction", "targetSha256", "configurationSha256", "release", "control", "migrationCount"})
        self.assertEqual(planned["approvalState"]["planAction"], "pause")
        self.assertEqual(planned["stateSha256"], contract.digest(planned["approvalState"]))
        self.invocation("b" * 32)
        observed = self.controller.plan_pause()
        self.assertEqual(observed["work"]["invocations"], 2)
        self.assertEqual(observed["stateSha256"], planned["stateSha256"])
        paused = self.controller.transition("pause", self.approve_pause(planned), planned["stateSha256"])
        self.assertEqual(paused["control"]["admission"], "closed")
        self.assertEqual(paused["control"]["workers"], "run")
        self.assertEqual(paused["work"]["invocations"], 2)
        for action in ("freeze", "activate"):
            with self.assertRaises(contract.ContractError):
                self.controller.transition(action, fixtures.approval(self.target, action, paused["stateSha256"]), paused["stateSha256"])
        self.assertEqual(self.api.db.execute("SELECT count(*) FROM subs_bot_production_invocations WHERE state='running'").fetchone()[0], 2)

    def test_finished_and_unknown_terminal_changes_remain_visible_without_blocking_pause(self):
        self.invocation("a" * 32)
        planned = self.controller.plan_pause()
        self.api.db.execute("UPDATE subs_bot_production_invocations SET state='finished',finished_at=unixepoch()")
        finished = self.controller.plan_pause()
        self.assertEqual(finished["work"]["invocations"], 0)
        self.assertEqual(finished["stateSha256"], planned["stateSha256"])
        self.invocation("b" * 32)
        self.api.db.execute("UPDATE subs_bot_production_invocations SET state='uncertain',finished_at=unixepoch() WHERE invocation_id=?", ("b" * 32,))
        observed = self.controller.plan_pause()
        self.assertEqual(observed["work"]["invocations"], 0)
        self.assertEqual(observed["terminal"]["unknownInvocations"], 1)
        self.assertEqual(observed["stateSha256"], planned["stateSha256"])
        paused = self.controller.transition("pause", self.approve_pause(planned), planned["stateSha256"])
        self.assertEqual(paused["terminal"]["unknownInvocations"], 1)
        self.assertEqual(self.api.db.execute("SELECT state FROM subs_bot_production_invocations WHERE invocation_id=?", ("b" * 32,)).fetchone()[0], "uncertain")
        frozen = self.controller.transition("freeze", fixtures.approval(self.target, "freeze", paused["stateSha256"]), paused["stateSha256"])
        self.assertEqual(frozen["control"]["workers"], "frozen")
        with self.assertRaises(contract.ContractError):
            self.controller.plan_activate()

    def test_ordinary_inspect_hash_is_not_a_pause_approval_and_stops_before_guard(self):
        observed = self.controller.inspect()
        self.controller.guard = Mock()
        with self.assertRaises(control.StalePredecessorError):
            self.controller.transition("pause", fixtures.approval(self.target, "pause", observed["stateSha256"]), observed["stateSha256"])
        self.controller.guard.assert_not_called()
        self.assertEqual(self.api.db.execute("SELECT admission,epoch FROM subs_bot_production_control").fetchone()[:], ("open", 1))

    def test_control_epoch_change_stops_before_any_guard_or_pause_sql(self):
        planned = self.controller.plan_pause()
        self.api.db.execute("UPDATE subs_bot_production_control SET epoch=epoch+1")
        self.controller.guard = Mock()
        with self.assertRaises(control.StalePredecessorError):
            self.controller.transition("pause", self.approve_pause(planned), planned["stateSha256"])
        self.controller.guard.assert_not_called()
        self.assertEqual(self.api.db.execute("SELECT admission,epoch FROM subs_bot_production_control").fetchone()[:], ("open", 2))

    def test_configuration_or_version_change_cannot_reuse_pause_approval(self):
        planned = self.controller.plan_pause()
        raw = deepcopy(self.target.data)
        raw["features"]["githubSearch"] = True
        changed = control.Controller(contract.validate_target(raw), self.api, self.api, self.bundle, self.manifest, secrets=self.secrets)
        self.api.controller = changed
        changed.guard = Mock()
        with self.assertRaises(control.StalePredecessorError):
            changed.transition("pause", self.approve_pause(planned), planned["stateSha256"])
        changed.guard.assert_not_called()
        self.api.controller = self.controller
        original = self.controller.active
        self.controller.active = Mock(side_effect=lambda **options: {**original(**options),
            "versionId": "40000000-0000-4000-8000-000000000001"})
        self.controller.guard = Mock()
        with self.assertRaises(control.StalePredecessorError):
            self.controller.transition("pause", self.approve_pause(planned), planned["stateSha256"])
        self.controller.guard.assert_not_called()
        self.assertEqual(self.api.db.execute("SELECT admission,epoch FROM subs_bot_production_control").fetchone()[:], ("open", 1))

    def test_control_race_inside_sql_cas_is_not_a_retryable_stale_plan(self):
        planned = self.controller.plan_pause()
        def race(sql):
            if "SET admission='closed'" not in sql:
                return
            self.api.before_guarded_mutation = None
            self.api.db.execute("UPDATE subs_bot_production_control SET epoch=epoch+1")
        self.api.before_guarded_mutation = race
        self.controller.guard = Mock()
        with self.assertRaises(control.OperationError) as caught:
            self.controller.transition("pause", self.approve_pause(planned), planned["stateSha256"])
        self.assertNotIsInstance(caught.exception, control.StalePredecessorError)
        self.controller.guard.assert_called_once_with()
        self.assertEqual(self.api.db.execute("SELECT admission,epoch FROM subs_bot_production_control").fetchone()[:], ("open", 2))


if __name__ == "__main__":
    unittest.main()
