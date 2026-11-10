"""Protected Grep cohort replay and failure checks with no external requests."""

from datetime import datetime, timezone
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import grep_outcome_isolation as probe


COHORT = "a" * 32
OTHER = "b" * 32
NOW = 2_100_000_000
PIN = {"revision": "1" * 40, "versionId": "2" * 8 + "-2222-2222-2222-" + "2" * 12,
       "deploymentId": "3" * 8 + "-3333-3333-3333-" + "3" * 12, "compatibilityDate": "2026-07-30",
       "moduleSha256": "4" * 64, "policySha256": "5" * 64, "scopeSha256": "6" * 64}


class Objects:
    def __init__(self):
        self.objects = {}
        self.writes = []
        self.fail = None

    def get(self, key, *, prior_control=False):
        return self.objects.get(key)

    def write(self, key, body, previous):
        if self.objects.get(key) != previous:
            raise AssertionError("Missing conditional fence")
        self.writes.append(key)
        if self.fail == key:
            raise probe.ProofError("Synthetic unknown write")
        self.objects[key] = (body, f'"{len(self.writes):032x}"')


def report(role, state="empty"):
    return probe.canonical({"version": 1, "cohort": COHORT, "revision": PIN["revision"], "role": role,
        "receiptId": 21 if role == "admin" else 22, "remainingMs": 8000, "repositoryStatus": 200,
        "repositoryState": "empty", "grep": {"phase": "complete", "initializeStatus": 200, "initializedStatus": 202,
        "toolStatus": 200, "timedOut": False, "contentBlocks": 2}, "candidates": 2, "codeTimedOut": False,
        "verifiedFiles": 0 if state == "empty" else 2,
        "visibility": [{"status": 403 if state == "empty" else 200,
                        "outcome": "unconfirmed" if state == "empty" else "public"}], "settled": state})


class ProtectedOutcomeTests(unittest.TestCase):
    def setUp(self):
        self.objects = Objects()
        self.receipt = Mock(return_value="sent")
        self.guard = Mock()

    def phase(self, action, now=NOW, cohort=COHORT, pin=PIN):
        return probe.operate(self.objects, action, cohort, pin, now, 20, self.receipt, self.guard)

    def seed_results(self):
        for role in probe.ROLES:
            raw = report(role, "empty" if role == "admin" else "found")
            self.objects.objects[probe.result_key(COHORT, role)] = (raw, f'"{"7" * 32}"')

    def test_resume_inspect_and_retire_with_no_payload_retention(self):
        self.assertEqual(self.phase("arm")["phase"], "armed")
        self.assertEqual(self.phase("arm")["phase"], "armed")
        self.assertEqual(len(self.objects.writes), 2)
        self.seed_results()
        result = self.phase("inspect")["outcomes"]
        self.assertEqual([(item["role"], item["settled"], item["delivery"]) for item in result],
                         [("admin", "empty", "sent"), ("member", "found", "sent")])
        self.assertTrue(all("receiptId" not in item for item in result))
        with self.assertRaises(probe.ProofError):
            self.phase("retire")
        self.assertEqual(len(self.objects.writes), 2)
        self.assertTrue(self.phase("retire", NOW + probe.WINDOW)["armRetired"])
        self.assertTrue(self.phase("retire", NOW + probe.WINDOW)["armRetired"])
        self.assertEqual(len(self.objects.writes), 5)
        for key in (probe.ARM, *(probe.result_key(COHORT, role) for role in probe.ROLES)):
            retired = probe.parsed(self.objects.objects[key][0])
            self.assertEqual(retired["state"], "retired")
            self.assertNotIn("receiptId", retired)
            self.assertNotIn("grep", retired)
        self.assertEqual(self.phase("arm", NOW + probe.WINDOW, OTHER)["phase"], "armed")

    def test_unknown_arm_is_not_reissued_and_foreign_arm_is_never_replaced(self):
        self.objects.fail = probe.ARM
        with self.assertRaises(probe.ProofError):
            self.phase("arm")
        self.objects.fail = None
        with self.assertRaisesRegex(probe.ProofError, "unconfirmed"):
            self.phase("arm")
        self.assertEqual(self.objects.writes, [probe.control_key(COHORT), probe.ARM])
        self.objects.objects[probe.ARM] = (probe.canonical({"cohort": OTHER, "state": "foreign"}), f'"{"8" * 32}"')
        with self.assertRaises(probe.ProofError):
            self.phase("arm", cohort=OTHER)
        self.assertEqual(len(self.objects.writes), 2)

    def test_partial_retire_resumes_only_exact_control_and_preserves_mismatch(self):
        self.phase("arm")
        self.seed_results()
        self.objects.fail = probe.result_key(COHORT, "member")
        with self.assertRaises(probe.ProofError):
            self.phase("retire", NOW + probe.WINDOW)
        self.assertEqual(self.objects.writes.count(probe.result_key(COHORT, "admin")), 1)
        self.objects.fail = None
        with self.assertRaises(probe.ProofError):
            self.phase("retire", NOW + probe.WINDOW, pin={**PIN, "moduleSha256": "9" * 64})
        self.assertTrue(self.phase("retire", NOW + probe.WINDOW)["armRetired"])
        self.assertEqual(self.objects.writes.count(probe.result_key(COHORT, "admin")), 1)

    def test_read_only_inspection_refuses_incomplete_delivery_and_raw_projection(self):
        self.phase("arm")
        self.seed_results()
        self.receipt.return_value = "pending"
        with self.assertRaisesRegex(probe.ProofError, "not confirmed sent"):
            self.phase("inspect")
        key = probe.result_key(COHORT, "admin")
        bad = probe.parsed(report("admin")) | {"query": "untrusted"}
        self.objects.objects[key] = (probe.canonical(bad), f'"{"8" * 32}"')
        with self.assertRaises(probe.ProofError):
            self.phase("inspect")
        self.assertEqual(len(self.objects.writes), 2)

    def test_sigv4_conditions_are_mutually_exclusive(self):
        args = ("test.r2.cloudflarestorage.com", "/fixture/item", "a" * 32, "synthetic-token", b"body",
                {"custom": {}, "http": {}}, datetime.fromtimestamp(NOW, timezone.utc))
        create = probe.signed_put_headers(*args)
        replace = probe.signed_put_headers(*args, if_match=f'"{"9" * 32}"')
        self.assertEqual(create.get("if-none-match"), "*")
        self.assertNotIn("if-match", create)
        self.assertEqual(replace.get("if-match"), f'"{"9" * 32}"')
        self.assertNotIn("if-none-match", replace)
        self.assertIn(";if-match;", replace["Authorization"])
