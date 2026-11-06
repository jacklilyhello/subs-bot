"""Exercise the protected claim fixture plan using SQLite and a private R2 fake."""

from hashlib import sha256
from pathlib import Path
import sqlite3
import sys
import unittest
from unittest.mock import Mock, patch
from uuid import UUID

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import telegram_claim_fixtures as claim


POLICY = {"botId": "1000", "adminId": "1001", "memberId": "1002"}
COHORT = "claimfixture0001"
OTHER = "claimfixture0002"
PATH = "/accounts/synthetic/d1/database/synthetic"
DIGESTS = {case: sha256(case.encode()).hexdigest() for case in claim.CASES}
OTHER_DIGESTS = {case: sha256((case + "2").encode()).hexdigest() for case in claim.CASES}


class FixtureTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:", isolation_level=None)
        self.addCleanup(self.db.close)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys = ON")
        for migration in sorted((Path(__file__).resolve().parents[1] / "migrations").glob("*.sql")):
            self.db.executescript(migration.read_text(encoding="utf-8"))
        self.objects = {}
        self.d1_writes = 0
        self.r2_writes = []
        self.lose_batch = False
        self.fail_batch = False
        self.lose_put = False
        self.lose_delete = False
        self.before_batch = None
        self.guard = Mock()
        self.fixtures = claim.plan(POLICY, COHORT, DIGESTS)
        self.cases = {fixture.case: fixture for fixture in self.fixtures.values()}

    def api(self, method, path, payload):
        self.assertEqual((method, path), ("POST", PATH + "/query"))

        def execute(statement):
            sql = statement["sql"]
            self.assertLessEqual(len(statement["params"]), 100)
            self.assertNotIn(COHORT, sql)
            self.assertNotIn(POLICY["adminId"], sql)
            return {"success": True, "results": [dict(row) for row in self.db.execute(sql, statement["params"])]}

        if "batch" not in payload:
            return [execute(payload)]
        self.d1_writes += 1
        if self.fail_batch:
            raise claim.CloudflareError("Synthetic batch failure.")
        if self.before_batch is not None:
            callback, self.before_batch = self.before_batch, None
            callback()
        try:
            self.db.execute("BEGIN")
            results = [execute(statement) for statement in payload["batch"]]
            self.db.commit()
        except sqlite3.DatabaseError:
            self.db.rollback()
            raise claim.CloudflareError("Synthetic batch rolled back.") from None
        if self.lose_batch:
            self.lose_batch = False
            raise claim.CloudflareError("Synthetic batch response lost.", uncertain=True)
        return results

    def request(self, method, key, body=None):
        if method == "GET":
            return self.objects.get(key)
        self.r2_writes.append((method, key))
        if method == "PUT":
            self.assertNotIn(key, self.objects)
            self.objects[key] = body
            if self.lose_put:
                self.lose_put = False
                raise claim.CloudflareError("Synthetic upload response lost.")
        elif method == "DELETE":
            identifier = key.removeprefix("private-shares/").removesuffix(".txt")
            self.assertIsNone(self.db.execute("SELECT id FROM private_shares WHERE payload_id=?", (identifier,)).fetchone())
            del self.objects[key]
            if self.lose_delete:
                self.lose_delete = False
                raise claim.CloudflareError("Synthetic deletion response lost.")
        else:
            self.fail("Unexpected R2 method")

    def manage(self, action, cohort=COHORT, digests=DIGESTS):
        fixtures = claim.plan(POLICY, cohort, digests)
        return claim.manage(self.api, PATH, self, action, POLICY, cohort, fixtures, self.guard)

    def add_claim(self, case, actor):
        self.db.execute("INSERT INTO private_share_claims (share_id, actor_id, claimed_at) "
                        "SELECT id, ?, unixepoch() FROM private_shares WHERE payload_id = ?",
                        (actor, self.cases[case].payload_id))

    def test_exact_plan_and_repeatable_retirement_preserve_other_cohort(self):
        self.assertEqual(len(self.cases["document"].body), 65536)
        self.assertTrue(self.cases["document"].body.decode("utf-8").endswith("\n"))
        self.assertTrue(all(UUID(fixture.payload_id).version == 8 for fixture in self.fixtures.values()))
        self.assertEqual(self.cases["targeted"].target, POLICY["memberId"])
        self.assertEqual(self.cases["document"].target, POLICY["adminId"])
        self.assertEqual(self.manage("seed")["activeShares"], 4)
        self.assertEqual(self.db.execute("SELECT count(*) FROM private_shares WHERE expire_at < unixepoch()").fetchone()[0], 1)
        self.assertEqual(self.manage("seed")["verifiedObjectsPresent"], 4)
        self.assertEqual((self.d1_writes, len(self.r2_writes)), (1, 4))
        self.manage("seed", OTHER, OTHER_DIGESTS)
        self.add_claim("targeted", POLICY["memberId"])
        self.add_claim("race", POLICY["adminId"])
        self.assertEqual(self.manage("retire"), {"activeShares": 0, "retiredShares": 4, "retiredClaims": 2,
                                                 "verifiedObjectsPresent": 0, "verifiedObjectsAbsent": 4})
        self.assertEqual(self.manage("retire")["retiredShares"], 0)
        self.assertEqual(self.db.execute("SELECT count(*) FROM private_shares").fetchone()[0], 4)
        self.assertEqual(set(self.objects), {item.key for item in claim.plan(POLICY, OTHER, OTHER_DIGESTS).values()})
        self.assertEqual(self.db.execute("PRAGMA foreign_key_check").fetchall(), [])

    def test_lost_write_responses_reconcile_through_exact_readback(self):
        self.lose_put = self.lose_batch = True
        self.assertEqual(self.manage("seed")["activeShares"], 4)
        self.lose_delete = self.lose_batch = True
        self.assertEqual(self.manage("retire")["retiredShares"], 4)
        self.assertFalse(self.objects)

    def test_failed_publish_leaves_only_exact_orphans_for_retirement(self):
        self.fail_batch = True
        with self.assertRaisesRegex(claim.FixtureError, "D1 cohort operation"):
            self.manage("seed")
        self.assertEqual(len(self.objects), 4)
        self.assertEqual(self.db.execute("SELECT count(*) FROM private_shares").fetchone()[0], 0)
        self.fail_batch = False
        self.assertEqual(self.manage("retire")["retiredShares"], 0)
        self.assertFalse(self.objects)

    def test_wrong_map_claim_or_payload_leaves_cohort_intact(self):
        self.manage("seed")
        with self.assertRaisesRegex(claim.FixtureError, "ownership or row state"):
            self.manage("retire", digests=OTHER_DIGESTS)
        self.add_claim("targeted", POLICY["adminId"])
        with self.assertRaisesRegex(claim.FixtureError, "unexpected claim"):
            self.manage("retire")
        self.db.execute("DELETE FROM private_share_claims")
        self.objects[self.cases["targeted"].key] = b"unrelated object"
        with self.assertRaisesRegex(claim.FixtureError, "different bytes"):
            self.manage("retire")
        self.assertEqual((self.d1_writes, len(self.r2_writes)), (1, 4))

    def test_concurrent_new_claim_aborts_whole_retirement_and_can_be_retried(self):
        self.manage("seed")
        self.before_batch = lambda: self.add_claim("race", POLICY["memberId"])
        with self.assertRaisesRegex(claim.FixtureError, "D1 cohort operation"):
            self.manage("retire")
        self.assertEqual(self.db.execute("SELECT count(*) FROM private_shares").fetchone()[0], 4)
        self.assertEqual(len(self.objects), 4)
        self.assertEqual(self.manage("retire")["retiredClaims"], 1)

    def test_retirement_preserves_receipts_and_used_digests_cannot_reactivate(self):
        self.manage("seed")
        self.db.execute("INSERT INTO telegram_inbox (bot_id, update_id, actor_id, chat_id, chat_type, "
                        "message_id, message_date, command, receipt_nonce) "
                        "VALUES (?, 1, ?, ?, 'private', 1, unixepoch(), 'help', 'claim:v1')",
                        (POLICY["botId"], POLICY["adminId"], POLICY["adminId"]))
        self.db.execute("INSERT INTO telegram_private_claim (receipt_id, code_sha256) "
                        "SELECT receipt_id, ? FROM telegram_inbox", (DIGESTS["targeted"],))
        self.manage("retire")
        self.assertEqual(self.db.execute("SELECT count(*) FROM telegram_private_claim").fetchone()[0], 1)
        with self.assertRaisesRegex(claim.FixtureError, "prior receipt"):
            self.manage("seed")
        self.assertEqual((self.d1_writes, len(self.r2_writes)), (2, 8))

    def test_invalid_plan_and_object_request_fail_before_network(self):
        for digests in (DIGESTS | {"extra": "a" * 64}, DIGESTS | {"targeted": "raw-code"},
                        DIGESTS | {"targeted": DIGESTS["race"]}):
            with self.assertRaisesRegex(claim.FixtureError, "SHA-256 fixture digests"):
                claim.plan(POLICY, COHORT, digests)
        client = claim.ClaimObjects("a" * 32, "synthetic-test-token", self.fixtures)
        with patch.object(client.opener, "open") as network:
            with self.assertRaisesRegex(claim.FixtureError, "Invalid scoped"):
                client.request("DELETE", "private-shares/unrelated.txt")
            with self.assertRaisesRegex(claim.FixtureError, "Invalid scoped"):
                client.request("PUT", self.cases["targeted"].key, b"wrong content")
        network.assert_not_called()
