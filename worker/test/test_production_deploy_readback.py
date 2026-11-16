"""Hosted-only tests for strict bounded deployment visibility readback."""

from copy import deepcopy
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from production_deploy_readback import ReadbackError, wait_for_deployment


OLD_VERSION = "10000000-0000-4000-8000-000000000001"
NEW_VERSION = "10000000-0000-4000-8000-000000000002"
OTHER_VERSION = "10000000-0000-4000-8000-000000000003"
OLD_DEPLOYMENT = "20000000-0000-4000-8000-000000000001"
NEW_DEPLOYMENT = "20000000-0000-4000-8000-000000000002"
OTHER_DEPLOYMENT = "20000000-0000-4000-8000-000000000003"


def active(version=OLD_VERSION, deployment=OLD_DEPLOYMENT):
    return {"revision": "a" * 40, "moduleSha256": "b" * 64, "versionId": version,
            "deploymentId": deployment, "compatibilityDate": "2026-07-30",
            "bindings": {
                "DB": {"name": "DB", "type": "d1", "database_id": "c" * 32},
                "NODES": {"name": "NODES", "type": "r2_bucket", "bucket_name": "synthetic-rehearsal"},
                "BUILD_REVISION": {"name": "BUILD_REVISION", "type": "plain_text", "text": "a" * 40},
                "SYNTHETIC_SECRET": {"name": "SYNTHETIC_SECRET", "type": "secret_text"},
            }}


def empty():
    return {"revision": None, "moduleSha256": None, "versionId": None, "deploymentId": None,
            "bindings": {}, "compatibilityDate": None}


class ReadbackTests(unittest.TestCase):
    def invoke(self, sequence, *, previous=None, verifier=None, pause=None, **kwargs):
        read = Mock(side_effect=sequence)
        verify = Mock(return_value=None) if verifier is None else verifier
        sleeper = Mock() if pause is None else pause
        result = wait_for_deployment(read, previous=active() if previous is None else previous,
            desired_version=NEW_VERSION, desired_deployment=NEW_DEPLOYMENT,
            verify_desired=verify, pause=sleeper, **kwargs)
        return result, read, verify, sleeper

    def test_immediate_exact_desired_is_verified_without_pause(self):
        desired = active(NEW_VERSION, NEW_DEPLOYMENT)
        result, read, verify, pause = self.invoke([desired])
        self.assertEqual(result, desired)
        self.assertIsNot(result, desired)
        read.assert_called_once_with()
        verify.assert_called_once_with(desired)
        pause.assert_not_called()

    def test_only_full_verified_previous_may_settle_twice(self):
        desired = active(NEW_VERSION, NEW_DEPLOYMENT)
        result, read, verify, pause = self.invoke([active(), active(), desired])
        self.assertEqual(result, desired)
        self.assertEqual(read.call_count, 3)
        self.assertEqual([call.args for call in pause.call_args_list], [(1,), (3,)])
        verify.assert_called_once_with(desired)

    def test_first_empty_deployment_requires_the_exact_empty_snapshot(self):
        desired = active(NEW_VERSION, NEW_DEPLOYMENT)
        _, read, verify, pause = self.invoke([empty(), desired], previous=empty())
        self.assertEqual(read.call_count, 2)
        pause.assert_called_once_with(1)
        verify.assert_called_once_with(desired)
        bad = empty()
        bad["bindings"] = {"UNKNOWN": {"name": "UNKNOWN", "type": "plain_text", "text": "unknown"}}
        with self.assertRaises(ReadbackError):
            self.invoke([bad, desired], previous=empty())

    def test_old_visibility_exhausts_three_reads_without_retrying_mutations(self):
        read, verify, pause = Mock(side_effect=[active()] * 3), Mock(), Mock()
        with self.assertRaises(ReadbackError) as caught:
            wait_for_deployment(read, previous=active(), desired_version=NEW_VERSION,
                desired_deployment=NEW_DEPLOYMENT, verify_desired=verify, pause=pause)
        self.assertEqual(caught.exception.kind, "previous-still-visible")
        self.assertEqual(caught.exception.attempts, 3)
        self.assertEqual(read.call_count, 3)
        self.assertEqual([call.args for call in pause.call_args_list], [(1,), (3,)])
        verify.assert_not_called()

    def test_third_version_or_wrong_deployment_never_waits(self):
        for version, deployment in ((OTHER_VERSION, NEW_DEPLOYMENT), (NEW_VERSION, OLD_DEPLOYMENT),
                                    (NEW_VERSION, OTHER_DEPLOYMENT), (OLD_VERSION, OTHER_DEPLOYMENT)):
            with self.subTest(version=version, deployment=deployment):
                read, verify, pause = Mock(return_value=active(version, deployment)), Mock(), Mock()
                with self.assertRaises(ReadbackError) as caught:
                    wait_for_deployment(read, previous=active(), desired_version=NEW_VERSION,
                        desired_deployment=NEW_DEPLOYMENT, verify_desired=verify, pause=pause)
                self.assertEqual(caught.exception.kind, "unexpected-deployment")
                self.assertEqual(read.call_count, 1)
                verify.assert_not_called()
                pause.assert_not_called()

    def test_same_version_with_a_new_explicit_deployment_is_not_ambiguous(self):
        desired = active(OLD_VERSION, NEW_DEPLOYMENT)
        read, verify, pause = Mock(side_effect=[active(), desired]), Mock(return_value=None), Mock()
        self.assertEqual(wait_for_deployment(read, previous=active(), desired_version=OLD_VERSION,
            desired_deployment=NEW_DEPLOYMENT, verify_desired=verify, pause=pause), desired)
        verify.assert_called_once_with(desired)

    def test_previous_binding_module_configuration_or_compatibility_drift_is_not_transient(self):
        mutations = [
            lambda value: value.update(revision="d" * 40),
            lambda value: value.update(moduleSha256="d" * 64),
            lambda value: value.update(compatibilityDate="2026-07-31"),
            lambda value: value["bindings"]["DB"].update(database_id="d" * 32),
            lambda value: value["bindings"]["NODES"].update(bucket_name="another-project"),
            lambda value: value["bindings"]["BUILD_REVISION"].update(text="d" * 40),
            lambda value: value["bindings"].pop("SYNTHETIC_SECRET"),
            lambda value: value["bindings"].update(EXTRA={"name": "EXTRA", "type": "plain_text", "text": "extra"}),
        ]
        for mutate in mutations:
            observed = active()
            mutate(observed)
            with self.subTest(snapshot=observed):
                read, verify, pause = Mock(return_value=observed), Mock(), Mock()
                with self.assertRaises(ReadbackError) as caught:
                    wait_for_deployment(read, previous=active(), desired_version=NEW_VERSION,
                        desired_deployment=NEW_DEPLOYMENT, verify_desired=verify, pause=pause)
                self.assertEqual(caught.exception.kind, "unexpected-deployment")
                self.assertEqual(read.call_count, 1)
                verify.assert_not_called()
                pause.assert_not_called()

    def test_canonical_previous_does_not_equate_boolean_with_integer(self):
        previous = active()
        previous["bindings"]["DB"]["synthetic_metadata"] = True
        observed = deepcopy(previous)
        observed["bindings"]["DB"]["synthetic_metadata"] = 1
        self.assertEqual(previous, observed)  # Python's loose equality is insufficient.
        with self.assertRaises(ReadbackError) as caught:
            self.invoke([observed], previous=previous)
        self.assertEqual(caught.exception.kind, "unexpected-deployment")

    def test_previous_is_frozen_before_reader_or_pause_can_mutate_callers_object(self):
        previous = active()
        def reader():
            previous["bindings"]["DB"]["database_id"] = "d" * 32
            return previous
        with self.assertRaises(ReadbackError) as caught:
            wait_for_deployment(reader, previous=previous, desired_version=NEW_VERSION,
                desired_deployment=NEW_DEPLOYMENT, verify_desired=Mock(), pause=Mock())
        self.assertEqual(caught.exception.kind, "unexpected-deployment")

    def test_read_and_verifier_errors_are_never_caught_or_retried(self):
        for error in (OSError("synthetic secret must not be logged"), ValueError("invalid response")):
            read, verify, pause = Mock(side_effect=error), Mock(), Mock()
            with self.assertRaises(type(error)) as caught:
                wait_for_deployment(read, previous=active(), desired_version=NEW_VERSION,
                    desired_deployment=NEW_DEPLOYMENT, verify_desired=verify, pause=pause)
            self.assertIs(caught.exception, error)
            self.assertEqual(read.call_count, 1)
            verify.assert_not_called()
            pause.assert_not_called()
        for error in (ValueError("wrong module"), RuntimeError("wrong dependency caller")):
            read, verify, pause = Mock(return_value=active(NEW_VERSION, NEW_DEPLOYMENT)), Mock(side_effect=error), Mock()
            with self.assertRaises(type(error)) as caught:
                wait_for_deployment(read, previous=active(), desired_version=NEW_VERSION,
                    desired_deployment=NEW_DEPLOYMENT, verify_desired=verify, pause=pause)
            self.assertIs(caught.exception, error)
            self.assertEqual(read.call_count, 1)
            self.assertEqual(verify.call_count, 1)
            pause.assert_not_called()

    def test_verifier_must_confirm_by_returning_none(self):
        for result in (False, True, {}, "synthetic-secret-value"):
            verify = Mock(return_value=result)
            with self.assertRaises(ReadbackError) as caught:
                self.invoke([active(NEW_VERSION, NEW_DEPLOYMENT)], verifier=verify)
            self.assertEqual(caught.exception.kind, "invalid-verification-result")
            self.assertNotIn("synthetic-secret-value", str(caught.exception))

    def test_invalid_or_ambiguous_contract_never_reads(self):
        cases = [
            {"desired_version": "latest"}, {"desired_deployment": None},
            {"desired_version": OLD_VERSION, "desired_deployment": OLD_DEPLOYMENT},
            {"previous": {"versionId": OLD_VERSION, "deploymentId": OLD_DEPLOYMENT}},
            {"previous": {**active(), "unexpected": "synthetic secret"}},
            {"previous": {**active(), "compatibilityDate": "2026-02-30"}},
            {"previous": {**active(), "bindings": []}},
        ]
        for changes in cases:
            read = Mock()
            kwargs = {"previous": active(), "desired_version": NEW_VERSION,
                "desired_deployment": NEW_DEPLOYMENT, "verify_desired": Mock(), "pause": Mock()}
            kwargs.update(changes)
            with self.subTest(changes=changes), self.assertRaises(ReadbackError) as caught:
                wait_for_deployment(read, **kwargs)
            self.assertEqual(caught.exception.kind, "invalid-contract")
            read.assert_not_called()

    def test_malformed_or_sensitive_observation_fails_without_pause(self):
        secret = active()
        secret["bindings"]["SYNTHETIC_SECRET"]["text"] = "synthetic-secret-value"
        for observed in (None, [], {**active(), "bindings": []}, secret,
                         {**active(), "revision": "not-a-revision"},
                         {**active(), "compatibilityDate": "2026-13-01"},
                         {**active(), "extra": "synthetic-secret-value"}):
            read, pause = Mock(return_value=observed), Mock()
            with self.subTest(observed=observed), self.assertRaises(ReadbackError) as caught:
                wait_for_deployment(read, previous=active(), desired_version=NEW_VERSION,
                    desired_deployment=NEW_DEPLOYMENT, verify_desired=Mock(), pause=pause)
            self.assertEqual(caught.exception.kind, "invalid-observation")
            self.assertNotIn("synthetic-secret-value", str(caught.exception))
            self.assertEqual(read.call_count, 1)
            pause.assert_not_called()

    def test_callback_outputs_are_not_printed(self):
        from contextlib import redirect_stderr, redirect_stdout
        import io
        output, error = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(error):
            self.invoke([active(), active(NEW_VERSION, NEW_DEPLOYMENT)])
            with self.assertRaises(ReadbackError):
                self.invoke([active(OTHER_VERSION, OTHER_DEPLOYMENT)])
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(error.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
