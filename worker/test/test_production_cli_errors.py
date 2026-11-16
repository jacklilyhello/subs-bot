"""Hosted-only checks that lifecycle entry points never publish unknown failures."""

from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import json
from pathlib import Path
import runpy
import sys
import unittest
from unittest.mock import patch

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))
import production_control as control
import production_provider as provider
import production_target as contract

SCRIPTS = ("production_control.py", "production_provision.py")
SAFE_REASON = "An unexpected lifecycle failure occurred. Inspect the target state before retrying."
PRIVATE_DETAILS = "sentinelSecret /home/runner/private/target.json https://private.invalid/recover?token=sentinelSecret"


class LifecycleCliErrorTests(unittest.TestCase):
    def invoke(self, script, error):
        stdout, stderr = StringIO(), StringIO()
        with patch.object(contract, "validate_target", side_effect=error), redirect_stdout(stdout), redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as stopped:
                runpy.run_path(str(TOOLS / script), run_name="__main__")
        self.assertEqual(stopped.exception.code, 1)
        self.assertEqual(stderr.getvalue(), "")
        lines = stdout.getvalue().splitlines()
        self.assertEqual(len(lines), 1)
        return json.loads(lines[0]), stdout.getvalue()

    def test_unknown_failures_are_sanitized_and_uncertain_for_both_entry_points(self):
        for script in SCRIPTS:
            for failure in (provider.ProviderError, OSError, KeyError, RuntimeError):
                with self.subTest(script=script, failure=failure.__name__):
                    result, output = self.invoke(script, failure(PRIVATE_DETAILS))
                    self.assertEqual(result, {"status": "stopped", "reason": SAFE_REASON, "uncertain": True})
                    for private_detail in ("sentinelSecret", "/home/runner/private", "https://private.invalid", "Traceback"):
                        self.assertNotIn(private_detail, output)

    def test_sanitized_contract_and_artifact_reasons_are_preserved(self):
        for script in SCRIPTS:
            for error in (contract.ContractError("The explicit target is unavailable."),
                          control.artifact.ArtifactError("The reviewed artifact is unavailable.")):
                with self.subTest(script=script, error=type(error).__name__):
                    result, _output = self.invoke(script, error)
                    self.assertEqual(result, {"status": "stopped", "reason": str(error), "uncertain": False})

    def test_provision_preserves_known_operation_uncertainty(self):
        # Provisioning imports the shared class; runpy defines a distinct local
        # OperationError class when it loads the control script as __main__.
        error = control.OperationError("Mutation outcome requires inspection.", uncertain=True)
        result, _output = self.invoke("production_provision.py", error)
        self.assertEqual(result, {"status": "stopped", "reason": str(error), "uncertain": True})


if __name__ == "__main__":
    unittest.main()
