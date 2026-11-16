"""Hosted-only actual SQLite and deployment protocol interruption regressions."""

import base64
from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
from hashlib import sha256
import io
import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, patch

WORKER = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WORKER / "tools"))
import production_control as control
import production_deploy_readback as readback
import production_target as contract
import test_production_control as fixtures

NEW_REVISION = "e" * 40
CONTROL_REVISION = "f" * 40
NEW_VERSION = "10000000-0000-4000-8000-000000000002"
OTHER_VERSION = "10000000-0000-4000-8000-000000000003"
NEW_DEPLOYMENT = "20000000-0000-4000-8000-000000000002"
OTHER_DEPLOYMENT = "20000000-0000-4000-8000-000000000003"
CRON = [{"cron": "* * * * *"}]
SECRET = "synthetic-secret-marker-never-expose"
REAL_WAIT = readback.wait_for_deployment


class ReleaseAPI(fixtures.StatefulAPI):
    """A mutable Worker API around the shared real transactional SQLite fixture."""

    def __init__(self, target):
        super().__init__(target)
        self.versions = {}
        self.active_pair = (fixtures.VERSION, fixtures.DEPLOYMENT)
        self.cron = deepcopy(CRON)
        self.uploads, self.traffic_posts, self.schedule_puts = 0, 0, 0
        self.control_batches = []
        self.stale_after_traffic = 0
        self.stale_remaining = 0
        self.traffic_result = {"id": NEW_DEPLOYMENT}
        self.traffic_pair = None
        self.fail_schedule = False
        self.ignore_schedule_put = False
        self.after_schedule_put = None
        self.active_read_error = None
        self.upload_binding_error = False

    def add_version(self, version_id, controller):
        self.versions[version_id] = {"id": version_id, "main_module": "index.js", "usage_model": "standard",
            "compatibility_date": controller.manifest["compatibilityDate"],
            "modules": [{"name": "index.js", "content_type": "application/javascript+module",
                "content_base64": base64.b64encode(fixtures.MODULE).decode()}],
            "bindings": controller.expected_bindings()}

    def query(self, sql):
        if "UPDATE subs_bot_production_control" in sql:
            self.control_batches.append(sql)
        return super().query(sql)

    def __call__(self, method, path, payload=None, **kwargs):
        if method == "GET" and path == self.script + "/deployments":
            self.requests.append((method, path, None))
            if self.traffic_posts and self.active_read_error is not None:
                raise self.active_read_error
            if self.stale_remaining:
                self.stale_remaining -= 1
                version, deployment = fixtures.VERSION, fixtures.DEPLOYMENT
            else:
                version, deployment = self.active_pair
            return {"deployments": [{"id": deployment, "strategy": "percentage",
                "versions": [{"version_id": version, "percentage": 100}]}]}
        if method == "GET" and path.startswith(self.worker_path + "/versions/"):
            self.requests.append((method, path, None))
            version = path.removeprefix(self.worker_path + "/versions/").removesuffix("?include=modules")
            return deepcopy(self.versions[version])
        if method == "GET" and path == self.script + "/schedules":
            self.requests.append((method, path, None))
            return {"schedules": deepcopy(self.cron)}
        if method == "POST" and path == self.worker_path + "/versions?deploy=false":
            self.requests.append((method, path, deepcopy(payload)))
            self.uploads += 1
            observed = deepcopy(payload)
            observed["id"] = NEW_VERSION
            observed["bindings"] = [{key: value for key, value in binding.items()
                if key != "text" or binding["type"] != "secret_text"} for binding in payload["bindings"]]
            if self.upload_binding_error:
                observed["bindings"].append({"name": "UNKNOWN", "type": "plain_text", "text": SECRET})
            self.versions[NEW_VERSION] = observed
            return {"id": NEW_VERSION}
        if method == "POST" and path == self.script + "/deployments":
            self.requests.append((method, path, deepcopy(payload)))
            self.traffic_posts += 1
            self.active_pair = self.traffic_pair or (NEW_VERSION, NEW_DEPLOYMENT)
            self.stale_remaining = self.stale_after_traffic
            return deepcopy(self.traffic_result)
        if method == "PUT" and path == self.script + "/schedules":
            self.requests.append((method, path, deepcopy(payload)))
            self.schedule_puts += 1
            if self.fail_schedule:
                raise OSError(SECRET)
            if not self.ignore_schedule_put:
                self.cron = deepcopy(payload)
            if self.after_schedule_put is not None:
                self.after_schedule_put()
            return {"schedules": deepcopy(self.cron)}
        return super().__call__(method, path, payload, **kwargs)


class DeploymentReconciliationTests(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.bundle = Path(directory.name)
        (self.bundle / "index.js").write_bytes(fixtures.MODULE)
        original_manifest = {"version": 2, "revision": fixtures.REVISION, "compatibilityDate": "2026-07-30",
            "bundleSha256": sha256(fixtures.MODULE).hexdigest(), "migrations": []}
        for path in sorted((WORKER / "migrations").glob("*.sql")):
            raw = path.read_bytes()
            (self.bundle / path.name).write_bytes(raw)
            original_manifest["migrations"].append({"name": path.name, "sha256": sha256(raw).hexdigest()})
        self.target, self.secrets = fixtures.fixture()
        self.api = ReleaseAPI(self.target)
        self.addCleanup(self.api.db.close)
        self.old = control.Controller(self.target, self.api, self.api, self.bundle, original_manifest,
            secrets=self.secrets, control_revision=CONTROL_REVISION)
        self.api.controller = self.old
        self.api.add_version(fixtures.VERSION, self.old)
        self.old.initialize()
        self.api.insert_business()
        self.before = self.old.inspect()
        manifest = {**original_manifest, "revision": NEW_REVISION}
        self.checkpoints = []
        self.new = control.Controller(self.target, self.api, self.api, self.bundle, manifest,
            secrets=self.secrets, telegram=Mock(), control_revision=CONTROL_REVISION,
            deployment_checkpoint=self.checkpoints.append)
        self.api.add_version(NEW_VERSION, self.new)
        self.api.add_version(OTHER_VERSION, self.new)
        self.api.control_batches.clear()
        self.api.requests.clear()

    def approval(self, action, state):
        return {"schemaVersion": 1, "environment": self.target.environment,
            "targetSha256": self.target.digest, "configurationSha256": self.target.configuration_digest,
            "controlRevision": CONTROL_REVISION, "revision": NEW_REVISION,
            "action": action, "stateSha256": state,
            "authorization": "approve " + action + " for " + self.target.data["workerName"]}

    def activate_new(self):
        self.api.active_pair = (NEW_VERSION, NEW_DEPLOYMENT)
        return self.new.active()

    def control_row(self):
        return dict(self.api.db.execute("SELECT * FROM subs_bot_production_control").fetchone())

    def make_successor(self, *, cron=None):
        self.activate_new()
        self.api.db.execute("UPDATE subs_bot_production_control SET release_revision=?,epoch=epoch+1", (NEW_REVISION,))
        self.api.db.execute("UPDATE telegram_general_policy SET release_revision=?", (NEW_REVISION,))
        self.api.cron = deepcopy(CRON if cron is None else cron)
        self.api.control_batches.clear()
        return self.new.active()

    def deploy(self):
        plan = self.new.plan_deploy(self.old)
        pause = Mock()
        with patch("production_deploy_readback.wait_for_deployment",
                side_effect=lambda *args, **kwargs: REAL_WAIT(*args, pause=pause, **kwargs)):
            result = self.new.deploy(self.approval("deploy", plan["stateSha256"]), plan["stateSha256"], self.old)
        return result, pause

    def test_real_deploy_waits_only_for_exact_previous_and_posts_traffic_once(self):
        self.api.stale_after_traffic = 2
        result, pause = self.deploy()
        self.assertEqual([call.args for call in pause.call_args_list], [(1,), (3,)])
        self.assertEqual((self.api.uploads, self.api.traffic_posts), (1, 1))
        self.assertEqual(result["release"]["versionId"], NEW_VERSION)
        self.assertEqual(result["release"]["deploymentId"], NEW_DEPLOYMENT)
        self.assertEqual(result["control"]["release_revision"], NEW_REVISION)
        self.assertEqual(result["control"]["epoch"], self.before["control"]["epoch"] + 1)
        self.assertEqual(self.api.db.execute("SELECT count(*) FROM subscriptions").fetchone()[0], 1)
        self.assertEqual([event["phase"] for event in self.checkpoints],
                         ["upload-confirmed", "traffic-intent", "traffic-confirmed", "active-confirmed"])
        for event in self.checkpoints:
            self.assertEqual(event["sourceRevision"], NEW_REVISION)
            self.assertEqual(event["targetSha256"], self.target.digest)
            self.assertNotIn(SECRET, json.dumps(event))

    def test_changed_full_predecessor_is_rejected_before_upload(self):
        plan = self.new.plan_deploy(self.old)
        original = self.new.expected_bindings
        def changed(*args, **kwargs):
            if kwargs.get("include_secrets"):
                self.api.active_pair = (OTHER_VERSION, OTHER_DEPLOYMENT)
            return original(*args, **kwargs)
        with patch.object(self.new, "expected_bindings", side_effect=changed), self.assertRaises(contract.ContractError):
            self.new.deploy(self.approval("deploy", plan["stateSha256"]), plan["stateSha256"], self.old)
        self.assertEqual((self.api.uploads, self.api.traffic_posts, self.api.schedule_puts), (0, 0, 0))
        self.assertEqual(self.api.control_batches, [])
        self.assertEqual(self.control_row(), self.before["control"])

    def test_malformed_current_deployment_identity_is_rejected_before_any_upload(self):
        self.api.active_pair = (fixtures.VERSION, "unconfirmed-deployment-id")
        with self.assertRaises(contract.ContractError):
            self.new.plan_deploy(self.old)
        self.assertEqual((self.api.uploads, self.api.traffic_posts, self.api.schedule_puts), (0, 0, 0))
        self.assertEqual(self.api.control_batches, [])
        self.assertEqual(self.control_row(), self.before["control"])

    def test_third_posttraffic_deployment_is_unknown_and_does_not_reconcile_sql(self):
        self.api.traffic_pair = (OTHER_VERSION, OTHER_DEPLOYMENT)
        with self.assertRaises(control.DeploymentReconciliationRequired) as caught:
            self.deploy()
        self.assertEqual(caught.exception.phase, "active-readback")
        self.assertTrue(caught.exception.uncertain)
        self.assertEqual((self.api.uploads, self.api.traffic_posts), (1, 1))
        self.assertEqual(self.api.control_batches, [])
        self.assertEqual(self.control_row(), self.before["control"])

    def test_third_release_after_successful_wait_is_rejected_before_reconciliation_sql(self):
        def checkpoint(event):
            self.checkpoints.append(event)
            if event["phase"] == "active-confirmed":
                self.api.active_pair = (OTHER_VERSION, OTHER_DEPLOYMENT)
        self.new.deployment_checkpoint = checkpoint
        with self.assertRaises(control.DeploymentReconciliationRequired) as caught:
            self.deploy()
        self.assertEqual(caught.exception.phase, "reconcile")
        self.assertEqual((self.api.uploads, self.api.traffic_posts), (1, 1))
        self.assertEqual(self.api.control_batches, [])
        self.assertEqual(self.api.schedule_puts, 0)
        self.assertEqual(self.control_row(), self.before["control"])

    def assert_unconfirmed_deployment_response(self, response):
        self.api.traffic_result = response
        output, error = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(error), self.assertRaises(control.DeploymentReconciliationRequired) as caught:
            self.deploy()
        self.assertEqual(caught.exception.phase, "traffic")
        self.assertTrue(caught.exception.safe_details()["mutationAttempted"])
        self.assertIsNone(caught.exception.safe_details()["deploymentSha256"])
        self.assertNotIn(SECRET, str(caught.exception) + json.dumps(caught.exception.safe_details()))
        self.assertEqual(output.getvalue() + error.getvalue(), "")
        self.assertEqual(self.api.control_batches, [])
        self.assertEqual((self.api.uploads, self.api.traffic_posts), (1, 1))

    def test_missing_deployment_response_does_not_retry_or_leak(self):
        self.assert_unconfirmed_deployment_response({})

    def test_bad_deployment_response_does_not_retry_or_leak(self):
        self.assert_unconfirmed_deployment_response({"id": SECRET})

    def test_postmutation_read_exception_is_fixed_uncertain_without_raw_text(self):
        self.api.active_read_error = OSError(SECRET)
        with self.assertRaises(control.DeploymentReconciliationRequired) as caught:
            self.deploy()
        self.assertEqual(caught.exception.phase, "active-readback")
        self.assertNotIn(SECRET, str(caught.exception) + json.dumps(caught.exception.safe_details()))
        self.assertEqual((self.api.uploads, self.api.traffic_posts), (1, 1))
        self.assertEqual(self.api.control_batches, [])

    def test_staged_wrong_binding_never_changes_traffic(self):
        self.api.upload_binding_error = True
        with self.assertRaises(control.DeploymentReconciliationRequired) as caught:
            self.deploy()
        self.assertEqual(caught.exception.phase, "staged-readback")
        self.assertNotIn(SECRET, str(caught.exception))
        self.assertEqual((self.api.uploads, self.api.traffic_posts), (1, 0))
        self.assertEqual(self.api.control_batches, [])

    def test_checkpoint_failure_after_upload_is_unknown_without_second_mutation(self):
        self.new.deployment_checkpoint = Mock(side_effect=OSError(SECRET))
        with self.assertRaises(control.DeploymentReconciliationRequired) as caught:
            self.deploy()
        self.assertEqual(caught.exception.phase, "staged-readback")
        self.assertEqual((self.api.uploads, self.api.traffic_posts), (1, 0))
        self.assertNotIn(SECRET, str(caught.exception))

    def test_full_expected_active_rejects_third_version_with_same_module_and_configuration_before_sql(self):
        expected = self.activate_new()
        self.api.active_pair = (OTHER_VERSION, OTHER_DEPLOYMENT)
        third = self.new.active()
        self.assertEqual(third["moduleSha256"], expected["moduleSha256"])
        self.assertEqual(third["bindings"], expected["bindings"])
        with self.assertRaises(contract.ContractError):
            self.new.reconcile_deployment(self.before, expected_active=expected)
        self.assertEqual(self.api.control_batches, [])
        self.assertEqual(self.api.schedule_puts, 0)
        self.assertEqual(self.control_row(), self.before["control"])

    def test_policy_drift_is_rejected_before_any_control_mutation(self):
        expected = self.activate_new()
        self.api.db.execute("UPDATE telegram_general_policy SET release_revision=?", ("c" * 40,))
        before = list(self.api.db.iterdump())
        with self.assertRaises(contract.ContractError):
            self.new.reconcile_deployment(self.before, expected_active=expected)
        self.assertEqual(self.api.control_batches, [])
        self.assertEqual(self.api.schedule_puts, 0)
        self.assertEqual(list(self.api.db.iterdump()), before)

    def test_policy_drift_between_preflight_and_sql_is_rejected_by_real_atomic_guard(self):
        expected = self.activate_new()
        def drift(sql):
            if "UPDATE subs_bot_production_control" in sql:
                self.api.before_guarded_mutation = None
                self.api.db.execute("UPDATE telegram_general_policy SET release_revision=?", ("c" * 40,))
        self.api.before_guarded_mutation = drift
        with self.assertRaises(control.DeploymentReconciliationRequired) as caught:
            self.new.reconcile_deployment(self.before, expected_active=expected)
        self.assertEqual(caught.exception.phase, "reconcile")
        self.assertEqual(self.control_row(), self.before["control"])
        self.assertEqual(self.api.db.execute("SELECT release_revision FROM telegram_general_policy").fetchone()[0], "c" * 40)
        self.assertEqual(self.api.schedule_puts, 0)

    def test_exact_successor_repeat_is_read_only(self):
        expected = self.activate_new()
        first = self.new.reconcile_deployment(self.before, expected_active=expected)
        self.api.control_batches.clear()
        self.api.schedule_puts = 0
        preserved = list(self.api.db.iterdump())
        again = self.new.reconcile_deployment(self.before, expected_active=expected)
        self.assertEqual(again, first)
        self.assertEqual(self.api.control_batches, [])
        self.assertEqual(self.api.schedule_puts, 0)
        self.assertEqual(list(self.api.db.iterdump()), preserved)

    def test_sql_success_cron_failure_needs_new_approved_empty_plan_and_repairs_only_cron(self):
        expected = self.activate_new()
        self.api.cron = []
        self.api.fail_schedule = True
        with self.assertRaises(control.DeploymentReconciliationRequired):
            self.new.reconcile_deployment(self.before, expected_active=expected)
        successor = self.control_row()
        self.assertEqual(successor["epoch"], self.before["control"]["epoch"] + 1)
        self.assertEqual(successor["release_revision"], NEW_REVISION)
        self.api.control_batches.clear()
        self.api.schedule_puts = 0
        self.api.fail_schedule = False
        preserved = list(self.api.db.iterdump())
        plan = self.new.plan_reconcile_deploy()
        self.assertEqual(plan["reconcileCron"], [])
        envelope = self.approval("reconcile-deploy", plan["stateSha256"])
        fixed = self.new.reconcile_deploy(envelope, plan["stateSha256"], predecessor=self.before, expected_active=expected)
        self.assertEqual(fixed["control"], successor)
        self.assertEqual(self.api.cron, CRON)
        self.assertEqual(self.api.control_batches, [])
        self.assertEqual(self.api.schedule_puts, 1)
        self.assertEqual(list(self.api.db.iterdump()), preserved)
        with self.assertRaises(contract.ContractError):
            self.new.reconcile_deploy(envelope, plan["stateSha256"], predecessor=self.before, expected_active=expected)
        fresh = self.new.plan_reconcile_deploy()
        self.api.schedule_puts = 0
        repeated = self.new.reconcile_deploy(self.approval("reconcile-deploy", fresh["stateSha256"]),
            fresh["stateSha256"], predecessor=self.before, expected_active=expected)
        self.assertEqual(repeated["control"], successor)
        self.assertEqual(self.api.schedule_puts, 0)
        self.assertEqual(self.api.control_batches, [])

    def test_empty_successor_without_new_approval_does_not_write_cron(self):
        expected = self.make_successor(cron=[])
        with self.assertRaises(contract.ContractError):
            self.new.reconcile_deployment(self.before, expected_active=expected)
        self.assertEqual(self.api.schedule_puts, 0)
        self.assertEqual(self.api.control_batches, [])

    def test_public_already_coherent_plan_repairs_only_explicit_empty_cron_without_epoch_change(self):
        self.make_successor(cron=[])
        preserved = list(self.api.db.iterdump())
        expected_control = self.control_row()
        plan = self.new.plan_reconcile_deploy()
        self.assertEqual(plan["reconcileMode"], "already-coherent")
        self.assertEqual(plan["reconcilePolicyRevision"], NEW_REVISION)
        self.assertEqual(plan["reconcileCron"], [])
        repaired = self.new.reconcile_deploy(self.approval("reconcile-deploy", plan["stateSha256"]), plan["stateSha256"])
        self.assertEqual(repaired["control"], expected_control)
        self.assertEqual(self.api.control_batches, [])
        self.assertEqual(self.api.schedule_puts, 1)
        self.assertEqual(self.api.cron, CRON)
        self.assertEqual(list(self.api.db.iterdump()), preserved)
        fresh = self.new.plan_reconcile_deploy()
        self.api.schedule_puts = 0
        again = self.new.reconcile_deploy(self.approval("reconcile-deploy", fresh["stateSha256"]), fresh["stateSha256"])
        self.assertEqual(again["control"], expected_control)
        self.assertEqual(self.api.control_batches, [])
        self.assertEqual(self.api.schedule_puts, 0)

    def test_public_coherent_planner_rejects_wrong_policy_without_any_mutation(self):
        self.make_successor(cron=[])
        self.api.db.execute("UPDATE telegram_general_policy SET release_revision=?", ("c" * 40,))
        preserved = list(self.api.db.iterdump())
        with self.assertRaises(contract.ContractError):
            self.new.plan_reconcile_deploy()
        self.assertEqual(self.api.control_batches, [])
        self.assertEqual(self.api.schedule_puts, 0)
        self.assertEqual(list(self.api.db.iterdump()), preserved)

    def test_public_coherent_approval_cannot_accept_a_third_active_release(self):
        self.make_successor(cron=[])
        plan = self.new.plan_reconcile_deploy()
        self.api.active_pair = (OTHER_VERSION, OTHER_DEPLOYMENT)
        with self.assertRaises(contract.ContractError):
            self.new.reconcile_deploy(self.approval("reconcile-deploy", plan["stateSha256"]), plan["stateSha256"])
        self.assertEqual(self.api.control_batches, [])
        self.assertEqual(self.api.schedule_puts, 0)

    def test_unknown_or_extra_cron_is_never_planned_or_overwritten(self):
        self.activate_new()
        for cron in ([{"cron": "0 * * * *"}], [*CRON, {"cron": "0 * * * *"}],
                     [{"cron": "* * * * *", "other": "unknown"}], [{"cron": True}]):
            self.api.cron = cron
            with self.subTest(cron=cron), self.assertRaises(contract.ContractError):
                self.new.plan_reconcile_deploy()
            self.assertEqual(self.api.schedule_puts, 0)
            self.assertEqual(self.api.control_batches, [])

    def test_approved_cron_change_or_metadata_drift_requires_new_plan_without_mutation(self):
        expected = self.make_successor(cron=[])
        plan = self.new.plan_reconcile_deploy()
        self.api.cron = deepcopy(CRON)
        with self.assertRaises(contract.ContractError):
            self.new.reconcile_deploy(self.approval("reconcile-deploy", plan["stateSha256"]),
                plan["stateSha256"], predecessor=self.before, expected_active=expected)
        plan = self.new.plan_reconcile_deploy()
        self.api.cron = [{"cron": "* * * * *", "modified_on": "2026-11-16T00:00:01Z"}]
        with self.assertRaises(contract.ContractError):
            self.new.reconcile_deploy(self.approval("reconcile-deploy", plan["stateSha256"]),
                plan["stateSha256"], predecessor=self.before, expected_active=expected)
        self.assertEqual(self.api.schedule_puts, 0)
        self.assertEqual(self.api.control_batches, [])

    def test_postput_empty_or_changed_release_or_changed_control_remains_uncertain(self):
        expected = self.make_successor(cron=[])
        plan = self.new.plan_reconcile_deploy()
        self.api.ignore_schedule_put = True
        with self.assertRaises(control.DeploymentReconciliationRequired):
            self.new.reconcile_deploy(self.approval("reconcile-deploy", plan["stateSha256"]),
                plan["stateSha256"], predecessor=self.before, expected_active=expected)
        self.assertEqual(self.api.control_batches, [])
        self.assertEqual(self.api.schedule_puts, 1)
        self.assertEqual(self.control_row()["epoch"], self.before["control"]["epoch"] + 1)

    def test_postput_third_release_is_not_reported_success(self):
        expected = self.make_successor(cron=[])
        plan = self.new.plan_reconcile_deploy()
        self.api.after_schedule_put = lambda: setattr(self.api, "active_pair", (OTHER_VERSION, OTHER_DEPLOYMENT))
        with self.assertRaises(control.DeploymentReconciliationRequired):
            self.new.reconcile_deploy(self.approval("reconcile-deploy", plan["stateSha256"]),
                plan["stateSha256"], predecessor=self.before, expected_active=expected)
        self.assertEqual(self.api.control_batches, [])
        self.assertEqual(self.api.schedule_puts, 1)

    def test_postput_control_epoch_drift_is_not_reported_success(self):
        expected = self.make_successor(cron=[])
        plan = self.new.plan_reconcile_deploy()
        self.api.after_schedule_put = lambda: self.api.db.execute("UPDATE subs_bot_production_control SET epoch=epoch+1")
        with self.assertRaises(control.DeploymentReconciliationRequired):
            self.new.reconcile_deploy(self.approval("reconcile-deploy", plan["stateSha256"]),
                plan["stateSha256"], predecessor=self.before, expected_active=expected)
        self.assertEqual(self.api.control_batches, [])
        self.assertEqual(self.api.schedule_puts, 1)

    def test_changed_successor_control_or_policy_is_rejected_without_overwrite(self):
        expected = self.make_successor()
        self.api.db.execute("UPDATE subs_bot_production_control SET epoch=epoch+1")
        with self.assertRaises(contract.ContractError):
            self.new.reconcile_deployment(self.before, expected_active=expected)
        self.assertEqual(self.api.control_batches, [])
        self.assertEqual(self.api.schedule_puts, 0)
        self.api.db.execute("UPDATE subs_bot_production_control SET epoch=epoch-1")
        self.api.db.execute("UPDATE telegram_general_policy SET release_revision=?", ("c" * 40,))
        with self.assertRaises(contract.ContractError):
            self.new.reconcile_deployment(self.before, expected_active=expected)
        self.assertEqual(self.api.control_batches, [])
        self.assertEqual(self.api.schedule_puts, 0)


if __name__ == "__main__":
    unittest.main()
