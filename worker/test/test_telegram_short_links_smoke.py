"""Synthetic hosted coverage for the read-only short link evidence."""

from contextlib import contextmanager
from copy import deepcopy
from io import BytesIO
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import telegram_short_links_smoke as smoke


CHALLENGE = "0123456789abcdef"
KEY = bytes(range(32))
POLICY = {"botId": "900", "adminId": "111", "memberId": "222"}
NONCES = {"admin": "AAAAAAAAAAAAAAAAAAAAAA", "member": "AQAAAAAAAAAAAAAAAAAAAA"}


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.history = []
        self.links = []
        self.cohort = smoke.Cohort(self.read, POLICY, CHALLENGE, KEY)
        self.calls = []
        self.link_reads = []

    def read(self, sql, *_params):
        self.assertTrue(sql.startswith("SELECT "))
        if "highWater" in sql:
            return [{"highWater": 10}]
        if "FROM telegram_auth" in sql:
            return [{"allowed": 1, "message_date": 50, "message_id": 5}]
        if "FROM telegram_inbox" in sql:
            return deepcopy(self.history)
        if "FROM normal_short_links AS l" in sql:
            self.link_reads.append(_params)
            retired = "l.target_url IS NULL" in sql
            self.assertEqual(sql.count("l.code_sha256=? AND l.owner_id=? AND"), 2)
            self.assertEqual(len(_params), 5 if retired else 7)
            step = 2 if retired else 3
            selected = []
            for offset in range(1, len(_params), step):
                code_hash, actor = _params[offset:offset + 2]
                target = None if retired else _params[offset + 2]
                selected.extend(row for row in self.links if (row["code_sha256"], row["owner_id"], row["target_url"])
                                == (code_hash, actor, target) and (row["revoked_at"] is not None) == retired)
            return deepcopy(selected)
        if "FROM normal_short_links" in sql:
            return [{field: row[field] for field in ("code_sha256", "owner_id", "target_url")}
                    for row in sorted(self.links, key=lambda row: row["code_sha256"])
                    if row["revoked_at"] is None and row["target_url"] in _params[3:]]
        self.fail("Unexpected query")

    def add_action(self, role, kind, code_hash):
        actor = self.cohort.actors[role]
        row_id = 11 + len(self.history)
        date, message = (0, 0) if role == "admin" else (50, 5)
        self.history.append({"receipt_id": row_id, "actor_id": actor, "chat_id": actor, "chat_type": "private",
            "thread_id": None, "message_id": row_id, "message_date": 80, "command": "help", "state": "sent", "attempts": 1,
            "sent_message_id": row_id + 100, "result": kind, "code_sha256": code_hash, "auth_message_date": date,
            "auth_message_id": message, "receipt_nonce": smoke.MARKER})
        return row_id

    def issue(self, prepared, other_target=False):
        for role, actor in self.cohort.actors.items():
            code = smoke.derive_code(KEY, POLICY["botId"], actor, NONCES[role])
            code_hash = smoke.digest(code.encode("ascii"))
            row_id = self.add_action(role, "issued", code_hash)
            self.links.append({"code_sha256": code_hash, "code_length": 22, "owner_id": actor, "origin_receipt_id": row_id,
                "nonce": NONCES[role], "key_version": 1, "target_url": ("https://unrelated.example/" if other_target
                    and role == "member" else self.cohort.targets[role]), "created_at": 80,
                "revoked_at": None, "collision": 0})
        return smoke.run_checkpoint(self.cohort, "issued", "identity", prepared, {}, self.probe)[0]

    def probe(self, code, destination, *, active):
        self.calls.append((smoke.digest(code.encode("ascii")), destination, active))
        status = 302 if active else 404
        return {"GET": status, "HEAD": status}

    def test_exact_private_issue_and_retirement_preserve_history(self):
        prepared, report = smoke.run_checkpoint(self.cohort, "prepare", "identity", None, {}, self.probe)
        self.assertEqual(report, {"phase": "prepare", "activeChallengeCount": 0})
        self.assertEqual(smoke.open_checkpoint(KEY, smoke.seal(KEY, prepared), "issued", "identity"), prepared)
        issued = self.issue(prepared)
        hashes = issued["codeSha256"]
        self.add_action("admin", "missing", None)
        for role, link in zip(smoke.ROLES, self.links, strict=True):
            self.add_action(role, "revoked", hashes[role])
            link.update(target_url=None, revoked_at=90)
        proof = {**hashes, "foreignTarget": hashes["member"]}
        final, evidence = smoke.run_checkpoint(self.cohort, "retired", "identity", issued, proof, self.probe)
        self.assertEqual(evidence["sentForeignMissingCount"], 1)
        self.assertEqual(evidence["retainedTombstoneCount"], 2)
        self.assertEqual(evidence["http"], {role: {"GET": 404, "HEAD": 404} for role in smoke.ROLES})
        self.assertEqual(len(self.history), 5)
        self.assertEqual([active for _, _, active in self.calls], [True, True, False, False])
        for link in self.links:
            self.assertNotIn(link["nonce"], repr(final))
        with self.assertRaises(smoke.FixtureError):
            smoke.run_checkpoint(self.cohort, "retired", "identity", issued, {**proof, "foreignTarget": hashes["admin"]}, self.probe)

    def test_unrelated_issuance_never_fetches_derivation_metadata(self):
        prepared = self.cohort.prepare("identity")
        with self.assertRaisesRegex(smoke.FixtureError, "exact active target inventory differs"):
            self.issue(prepared, other_target=True)
        self.assertEqual(self.link_reads, [])
        self.assertEqual(self.calls, [])

    def test_scope_signature_and_exact_reserved_targets(self):
        expected = {"admin": f"https://example.com/subs-bot-normal-short/{CHALLENGE}/admin",
                    "member": f"https://example.org/subs-bot-normal-short/{CHALLENGE}/member"}
        self.assertEqual(self.cohort.targets, expected)
        document = smoke.seal(KEY, self.cohort.prepare("identity"))
        with self.assertRaises(smoke.FixtureError):
            smoke.open_checkpoint(KEY, {**document, "afterReceiptId": 11}, "issued", "identity")
        with self.assertRaises(smoke.FixtureError):
            smoke.open_checkpoint(KEY, document, "issued", "different identity")

    def test_probe_only_requests_own_code_path_and_rejects_wrong_location(self):
        code = smoke.derive_code(KEY, POLICY["botId"], POLICY["adminId"], NONCES["admin"])
        destination = self.cohort.targets["admin"]
        calls = []

        @contextmanager
        def response(method, path, _deadline, _label):
            calls.append((method, path))
            stream = BytesIO()
            stream.status = 302
            headers = {"Location": destination, "Cache-Control": "private, no-store", "Referrer-Policy": "no-referrer",
                       "X-Content-Type-Options": "nosniff"}
            stream.getheader = headers.get
            yield stream

        with patch.object(smoke, "_request", response):
            self.assertEqual(smoke.probe_code(code, destination, active=True), {"GET": 302, "HEAD": 302})
            self.assertEqual(calls, [("GET", f"/s/{code}"), ("HEAD", f"/s/{code}")])
            with self.assertRaises(smoke.FixtureError):
                smoke.probe_code(code, self.cohort.targets["member"], active=True)


if __name__ == "__main__":
    unittest.main()
