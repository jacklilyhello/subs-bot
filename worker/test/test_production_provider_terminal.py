"""Hosted-only forced-terminal evidence checks; failures never become smoke passes."""

from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import production_provider as control
import production_provider_terminal as terminal
import test_production_provider as fixtures

ACTOR = "6" * 64
START = "2026-11-16T00:00:01.000Z"
END = "2026-11-16T00:00:04.000Z"


class ForcedTerminalTests(unittest.TestCase):
    def setUp(self):
        self.config = fixtures.config(active=True)
        self.api = Mock(config=deepcopy(self.config))
        self.output = {"ok": True, "stopped": True, "revision": fixtures.REVISION,
            "imageSha256": fixtures.BUILD["ociManifestSha256"], "healthRevision": self.config["smoke"]["healthRevision"],
            "healthSha256": self.config["smoke"]["healthSha256"], "healthBytes": self.config["smoke"]["healthBytes"],
            "blockedPrivateTargets": 3, "rpcVerified": True}
        self.workflow = {"status": "complete", "success": True, "versionId": self.config["workflow"]["versionId"],
            "params": control.smoke_params(self.config), "trigger": {"source": "api"}, "schedule": None,
            "error": None, "start": START, "end": END, "output": deepcopy(self.output)}
        self.instance = {"id": ACTOR, "application_id": fixtures.NS, "image": control.image_reference(self.config),
            "status": {"state": "failed", "exit_code": 137, "updated_at": "2026-11-16T00:00:03.000Z"},
            "started_at": "2026-11-16T00:00:02.000Z"}
        self.actor = {"id": ACTOR, "hasStoredData": True}
        self.worker = fixtures.worker_profile(self.config)
        self.worker["deployed_on"] = START
        self.inventory, self.detail, self.actors, self.active = [deepcopy(self.instance)], deepcopy(self.instance), [deepcopy(self.actor)], []
        self.after_read = None
        self.snapshots = 0
        self.observed_activation = deepcopy(self.config["activation"])
        self.observed_workflow = deepcopy(self.config["workflow"])

        def request(path, **options):
            self.assertEqual(options.get("method"), "GET")
            self.assertIsNone(options.get("body"))
            if path in ("/workers/workers/" + self.config["service"], "/workers/workers/" + fixtures.WORKER_ID):
                result = deepcopy(self.worker)
            elif path == "/containers/applications/" + fixtures.NS + "/instances-v2?per_page=2":
                result = deepcopy(self.inventory)
            elif path == "/containers/applications/" + fixtures.NS + "/instances-v2?per_page=2&state=active":
                result = deepcopy(self.active)
                self.snapshots += 1
                if self.after_read is not None:
                    self.after_read(self.snapshots)
            elif path == "/containers/applications/" + fixtures.NS + "/instances/" + ACTOR:
                result = deepcopy(self.detail)
            elif path == "/workers/durable_objects/namespaces/" + fixtures.NS + "/objects?limit=10":
                return {"success": True, "result": deepcopy(self.actors), "result_info": {"count": len(self.actors)}}
            else:
                raise AssertionError("Unexpected read-only fixture route.")
            return {"success": True, "result": result, "result_info": {}}
        self.api._request.side_effect = request

    def verify(self, current_config=None, *, evidence_sink=None):
        # Leave observe's Worker privacy, consumer, namespace and resource-pin
        # comparisons real; existing provider tests cover its exact module reads.
        selected = self.config if current_config is None else current_config
        active_version = selected["versionId"] if selected["activation"] is not None \
            and self.observed_activation == selected["activation"] else self.config["versionId"]
        with patch.object(terminal.GETOnlyProviderAPI, "versions", return_value=[{"id": self.config["versionId"]}]), \
             patch.object(terminal.GETOnlyProviderAPI, "deployment", return_value={"id": self.observed_activation["deploymentId"],
                 "versions": [{"version_id": active_version, "percentage": 100}]}), \
             patch.object(terminal.GETOnlyProviderAPI, "version", return_value=fixtures.NS), \
             patch.object(terminal.GETOnlyProviderAPI, "container", side_effect=lambda _namespace: deepcopy(self.config["container"])), \
             patch.object(terminal.GETOnlyProviderAPI, "workflow", side_effect=lambda: deepcopy(self.observed_workflow)), \
             patch.object(terminal.GETOnlyProviderAPI, "smoke_instance", side_effect=lambda release, _workflow:
                 deepcopy(self.workflow) if release["revision"] == self.config["build"]["revision"] else None), \
             patch.object(control, "public_denied"):
            return terminal.verify_forced_terminal(self.api, self.config, current_config=current_config, evidence_sink=evidence_sink)

    def forward_config(self, *, activated=False):
        current = deepcopy(self.config)
        current["build"]["revision"] = "7" * 40
        current["versionId"] = "33333333-4444-5555-6666-777777777777" if activated else None
        current["activation"] = {"deploymentId": "44444444-5555-6666-7777-888888888888", "namespaceId": fixtures.NS} if activated else None
        current["workflow"] = {**self.config["workflow"], "versionId": "55555555-6666-7777-8888-999999999999"} if activated else None
        current["previous"] = deepcopy(self.config)
        return current

    def test_exact_failed_137_is_preserved_as_not_complete_using_only_gets(self):
        result = self.verify()
        self.assertEqual(result, {"status": "failed-terminal-preserved", "completion": "not-complete",
            "targetSha256": control.digest(self.config), "sourceRevision": fixtures.REVISION,
            "instanceIdSha256": sha256(ACTOR.encode()).hexdigest(), "exitCode": 137, "state": "failed",
            "processSha256": control.digest({"id": ACTOR, "image": self.instance["image"],
                "startedAt": self.instance["started_at"], "status": self.instance["status"]})})
        self.assertEqual(self.snapshots, 2)
        self.assertNotIn(ACTOR, json.dumps(result))
        self.api.trigger.assert_not_called()
        self.api.stopped.assert_not_called()
        self.api.deploy.assert_not_called()
        self.assertTrue(all(item.kwargs["method"] == "GET" for item in self.api._request.call_args_list))

    def test_closed_string_output_is_supported_without_relaxing_exact_schema(self):
        self.workflow["output"] = control.canonical(self.output).decode("ascii")
        self.assertEqual(self.verify()["completion"], "not-complete")
        self.workflow["output"] = self.workflow["output"].replace('"ok":true', '"ok":true,"ok":true')
        with self.assertRaises(ValueError):
            self.verify()

    def test_preserved_readback_contains_complete_fixed_terminal_fields_without_unknown_messages(self):
        captured = []
        self.detail["untrustedMessage"] = "synthetic-private-error"
        result = self.verify(evidence_sink=captured.append)
        self.assertEqual(len(captured), 1)
        self.assertEqual(captured[0]["summarySha256"], control.digest(result))
        self.assertEqual(captured[0]["inventory"]["exitCode"], 137)
        self.assertEqual(captured[0]["detail"]["state"], "failed")
        self.assertEqual(captured[0]["workflowResult"]["namedRpcVerified"], True)
        self.assertEqual(captured[0]["activeCount"], 0)
        self.assertNotIn("synthetic-private-error", control.canonical(captured).decode())

    def test_stale_listing_cannot_hide_a_later_failed_process_in_detail(self):
        self.detail["started_at"] = "2026-11-16T00:00:05.000Z"
        self.detail["status"]["updated_at"] = "2026-11-16T00:00:06.000Z"
        with self.assertRaises(ValueError):
            self.verify()

    def test_workflow_failure_wrong_source_or_missing_named_rpc_never_authorizes_forward(self):
        cases = [{"status": "running"}, {"success": False}, {"versionId": fixtures.VERSION},
            {"params": {**control.smoke_params(self.config), "providerRevision": "7" * 40}},
            {"trigger": {"source": "cron"}}, {"schedule": {"cron": "* * * * *"}},
            {"error": {"message": "synthetic-private-detail"}}, {"end": fixtures.STAMP}]
        for changed in cases:
            before = deepcopy(self.workflow)
            self.workflow.update(changed)
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                self.verify()
            self.workflow = before
        for changed in ({"ok": False}, {"stopped": False}, {"rpcVerified": False}, {"ok": 1}, {"stopped": 1},
                        {"rpcVerified": 1}, {"extra": True},
                        {"healthSha256": "9" * 64}, {"imageSha256": "8" * 64}):
            self.workflow["output"] = {**self.output, **changed}
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                self.verify()

    def test_container_state_exit_image_time_and_detail_must_all_match(self):
        changes = [{"id": "7" * 64}, {"application_id": "9" * 32}, {"image": None}, {"image": "foreign-image"},
            {"started_at": fixtures.STAMP}, {"status": {"state": "stopped", "exit_code": 137, "updated_at": END}},
            {"status": {"state": "failed", "exit_code": 0, "updated_at": END}},
            {"status": {"state": "failed", "exit_code": True, "updated_at": END}},
            {"status": {"state": "failed", "exit_code": 137, "updated_at": fixtures.STAMP}}]
        for side in ("inventory", "detail"):
            for changed in changes:
                self.inventory, self.detail = [deepcopy(self.instance)], deepcopy(self.instance)
                (self.inventory[0] if side == "inventory" else self.detail).update(changed)
                with self.subTest(side=side, changed=changed), self.assertRaises(ValueError):
                    self.verify()

    def test_extra_actor_instance_or_active_work_is_never_hidden(self):
        for field, value in (("inventory", []), ("inventory", [self.instance, self.instance]),
                ("actors", []), ("actors", [self.actor, self.actor]),
                ("actors", [{**self.actor, "hasStoredData": False}]),
                ("actors", [{**self.actor, "id": "7" * 64}]), ("active", [self.instance])):
            before = deepcopy(getattr(self, field))
            setattr(self, field, deepcopy(value))
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                self.verify()
            setattr(self, field, before)

    def test_live_consumer_or_privacy_change_is_rejected_by_ordinary_observation(self):
        for changed in ({"references": {**self.worker["references"], "workers": [{"id": "5" * 32, "name": "foreign"}]}},
                        {"subdomain": {"enabled": True, "previews_enabled": False}}, {"id": "5" * 32}):
            before = deepcopy(self.worker)
            self.worker.update(changed)
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                self.verify()
            self.worker = before

    def test_stable_double_read_is_required_even_when_both_snapshots_are_failed_137(self):
        def drift(count):
            if count == 1:
                self.detail["status"]["updated_at"] = END
        self.after_read = drift
        with self.assertRaisesRegex(control.ProviderError, "changed during read-only reconciliation"):
            self.verify()

    def test_unconfirmed_read_does_not_retry_or_produce_terminal_evidence(self):
        self.api._request.side_effect = control.ProviderError("The independent read was not confirmed.")
        with self.assertRaises(control.ProviderError):
            self.verify()
        self.assertEqual(self.api._request.call_count, 1)
        self.api.trigger.assert_not_called()

    def test_forward_context_can_read_old_terminal_before_staging_and_after_pinned_activation(self):
        expected = self.verify()
        for activated in (False, True):
            current = self.forward_config(activated=activated)
            self.api.config = deepcopy(current)
            self.observed_activation = deepcopy(current["activation"] if activated else self.config["activation"])
            self.observed_workflow = deepcopy(current["workflow"] if activated else self.config["workflow"])
            with self.subTest(activated=activated):
                self.assertEqual(self.verify(current), expected)
        self.api.trigger.assert_not_called()
        self.api.upload.assert_not_called()

    def test_forward_context_refuses_new_identity_bound_caller_or_different_previous(self):
        for field, changed in (("worker", {**self.config["worker"], "workerId": "9" * 32}),
                ("container", {**self.config["container"], "createdAt": START}),
                ("activation", {"deploymentId": fixtures.DEPLOYMENT, "namespaceId": "9" * 32}),
                ("workflow", {**self.config["workflow"], "workflowId": "66666666-7777-8888-9999-aaaaaaaaaaaa"}),
                ("caller", {"id": "5" * 32, "name": "subs-bot-cf-control-drill-01"})):
            current = self.forward_config(activated=True)
            current[field] = changed
            self.api.config = deepcopy(current)
            with self.subTest(field=field), self.assertRaises(ValueError):
                terminal.verify_forced_terminal(self.api, self.config, current_config=current)
        current = self.forward_config()
        current["previous"]["smoke"]["healthSha256"] = "9" * 64
        self.api.config = deepcopy(current)
        with self.assertRaises(ValueError):
            terminal.verify_forced_terminal(self.api, self.config, current_config=current)
        self.api._request.assert_not_called()

    def test_forward_context_cannot_adopt_unpinned_activation_or_workflow_versions(self):
        current = self.forward_config()
        self.api.config = deepcopy(current)
        for field, changed in (("observed_activation", {**self.config["activation"],
                    "deploymentId": "44444444-5555-6666-7777-888888888888"}),
                ("observed_workflow", {**self.config["workflow"], "versionId": "55555555-6666-7777-8888-999999999999"})):
            self.observed_activation = deepcopy(self.config["activation"])
            self.observed_workflow = deepcopy(self.config["workflow"])
            setattr(self, field, changed)
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.verify(current)

    def test_unpinned_bound_or_mismatched_target_is_rejected_before_network(self):
        for key in ("worker", "versionId", "activation", "container", "workflow"):
            value = deepcopy(self.config)
            value[key] = None
            with self.subTest(key=key), self.assertRaises(ValueError):
                terminal.verify_forced_terminal(self.api, value)
        value = deepcopy(self.config)
        value["caller"] = {"id": "5" * 32, "name": "subs-bot-cf-control-drill-01"}
        with self.assertRaises(ValueError):
            terminal.verify_forced_terminal(self.api, value)
        value = deepcopy(self.config)
        value["smoke"]["healthSha256"] = "9" * 64
        with self.assertRaises(ValueError):
            terminal.verify_forced_terminal(self.api, value)
        self.api._request.assert_not_called()

    def test_read_only_adapter_rejects_all_mutations_and_generic_stopped_proof(self):
        reader = terminal.GETOnlyProviderAPI(self.api, self.config)
        for method, args in (("create", ()), ("upload", (b"module",)), ("deploy", ({},)),
                ("create_container", (fixtures.NS,)), ("create_workflow", ()), ("trigger", ({},)),
                ("_write", ("/workflows/foreign", {})), ("stopped", (fixtures.NS, START, "f" * 64))):
            with self.subTest(method=method), self.assertRaises(control.ProviderError):
                getattr(reader, method)(*args)
        for method in ("POST", "PUT", "PATCH", "DELETE"):
            with self.subTest(method=method), self.assertRaises(control.ProviderError):
                reader._request("/containers/applications", method=method, body={})
        with self.assertRaises(control.ProviderError):
            control.verify_smoke(reader, {"instance": self.workflow})
        self.api._request.assert_not_called()


if __name__ == "__main__":
    unittest.main()
