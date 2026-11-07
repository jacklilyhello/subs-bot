"""Hosted SQLite fixtures for the protected harness, independent of real Telegram."""

from copy import deepcopy
import json
import unittest

from test_telegram_aggregate_smoke import COHORT, IDENTITY, KEY, POLICY, RELEASE_PIN, REVISION, STAMP, FakeResources

import telegram_bulk_trash_smoke as smoke
from telegram_view_fixtures import FixtureError


class BulkTrashCheckpointTests(unittest.TestCase):
    def setUp(self):
        self.cloud = FakeResources()
        self.addCleanup(self.cloud.db.close)
        self.now = STAMP
        self.cloud.db.create_function("unixepoch", 0, lambda: self.now)
        self.cohort = smoke.BulkCohort(self.cloud, POLICY, COHORT, KEY, IDENTITY)
        self.update = 100

    def seed(self):
        return smoke.seed(self.cohort, REVISION, RELEASE_PIN, lambda: None)

    def receipt(self, role, kind, targets=None, origin=None):
        actor = POLICY[smoke.ROLES[role]]
        self.update += 1
        with self.cloud.db:
            receipt = self.cloud.db.execute("""INSERT INTO telegram_inbox
                (bot_id,update_id,actor_id,chat_id,chat_type,message_id,message_date,command,receipt_nonce,received_at)
                VALUES(?,?,?,?,'private',?,?,'help',?,?) RETURNING receipt_id""",
                (POLICY["botId"], self.update, actor, actor, origin or self.update, self.now, smoke.MARKER, self.now)).fetchone()[0]
            self.cloud.db.execute("INSERT INTO telegram_outbox(receipt_id,state,attempts,sent_message_id) VALUES(?,'sent',1,?)",
                                  (receipt, self.update + 5000))
            self.cloud.db.execute("""INSERT INTO telegram_bulk_trash
                (receipt_id,kind,target_count,targets,actor_role,auth_message_date,auth_message_id,token_sha256,origin_attempt,expires_at)
                VALUES(?,?,?,?,?,0,0,?,?,?)""", (receipt, kind, len(targets) if targets is not None else 16,
                smoke.canonical(targets) if targets is not None else None, role, f"{receipt:064x}" if targets else None,
                1 if targets else None, self.now + 600 if targets else None))
        return receipt, self.update + 5000

    def previews(self, checkpoint, *, member=True):
        admin = self.receipt("admin", "preview", [[checkpoint["fixtures"][label]["id"], 0, 0] for label in smoke.LABELS[:-1]])
        if member:
            self.receipt("member", "preview", [[checkpoint["fixtures"]["M01"]["id"], 0, 0]])
        return admin

    def move(self, checkpoint, admin):
        original, message = admin
        confirmation, _ = self.receipt("admin", "trashed", origin=message)
        with self.cloud.db:
            self.cloud.db.execute("UPDATE telegram_bulk_trash SET confirmed_by_receipt_id=? WHERE receipt_id=?",
                                  (confirmation, original))
            for label in smoke.LABELS[:-1]:
                sub_id = checkpoint["fixtures"][label]["id"]
                self.cloud.db.execute(f"""INSERT INTO subscription_trash ({smoke.SUBSCRIPTION_FIELDS},deleted_at,lifecycle_revision)
                    SELECT {smoke.SUBSCRIPTION_FIELDS},?,1 FROM subscriptions WHERE id=?""", (self.now, sub_id))
                self.cloud.db.execute("DELETE FROM subscriptions WHERE id=?", (sub_id,))
                self.cloud.db.execute("INSERT INTO subscription_lifecycle VALUES(?,1)", (sub_id,))

    def test_exact_cap_source_only_and_names_redaction_and_historical_retirement(self):
        self.cloud.failure = "committed"
        checkpoint = self.seed()
        self.assertEqual(checkpoint, self.seed())
        rows, _ = self.cohort.subscriptions()
        self.assertEqual(sum(self.cohort.needle in row["name"] for label, row in rows.items() if label != "M01"), 15)
        self.assertEqual([label for label, row in rows.items() if self.cohort.needle in row["source_url"]], ["A16"])
        self.assertNotIn(self.cohort.needle, rows["A16"]["name"])
        self.assertEqual([label for label, row in rows.items() if row["owner_id"] == POLICY["memberId"]], ["M01"])

        admin = self.previews(checkpoint)
        self.now += 1
        self.move(checkpoint, admin)
        verified = smoke.verify(self.cohort, checkpoint)
        signed = self.cohort.signed(verified)
        body = json.dumps(signed)
        for secret in (*POLICY.values(), *self.cohort.tokens.values(), self.cohort.prefix, self.cohort.needle, KEY):
            self.assertNotIn(f'"{secret}"', body)
        self.assertNotIn(self.cohort.prefix, body)
        self.assertNotIn(self.cohort.needle, body)
        self.assertEqual(len(verified["receipts"]), 3)
        later = {**RELEASE_PIN, "revision": "d" * 40, "moduleSha256": "e" * 64}
        verified = self.cohort.checkpoint(signed, "retire", REVISION, later)

        with self.assertRaisesRegex(FixtureError, "unconsumed preview"):
            smoke.retire(self.cohort, verified, later, lambda: None)
        self.assertEqual(len(self.cohort.subscriptions()[0]), 17)
        self.now += 600
        self.cloud.failure = "committed"
        retired = smoke.retire(self.cohort, verified, later, lambda: None)
        self.assertEqual(retired, smoke.retire(self.cohort, verified, later, lambda: None))
        self.assertEqual(retired["releasePin"], RELEASE_PIN)
        self.assertEqual(retired["retiredAtReleasePin"], later)
        for table in ("subscriptions", "subscription_trash", "subscription_lifecycle"):
            self.assertEqual(self.cloud.query(f"SELECT count(*) AS n FROM {table}", ()), [{"n": 0}])
        for table in ("telegram_inbox", "telegram_outbox", "telegram_bulk_trash"):
            self.assertEqual(self.cloud.query(f"SELECT count(*) AS n FROM {table}", ()), [{"n": 3}])
        self.assertEqual((self.cloud.puts, self.cloud.deleted), ([], []))

    def test_seed_rejection_and_exact_guarded_recovery(self):
        self.cloud.failure = "uncommitted"
        with self.assertRaisesRegex(FixtureError, "seed could not be confirmed"):
            self.seed()
        checkpoint = self.seed()
        admin = self.previews(checkpoint, member=False)
        self.move(checkpoint, admin)
        with self.assertRaisesRegex(FixtureError, "receipt inventory"):
            smoke.verify(self.cohort, checkpoint)
        self.assertEqual(smoke.retire(self.cohort, checkpoint, RELEASE_PIN, lambda: None)["phase"], "retired")
        self.assertEqual(self.cloud.query("SELECT count(*) AS n FROM telegram_inbox", ()), [{"n": 2}])

    def test_wrong_scope_forged_checkpoint_and_release_drift_fail_closed(self):
        checkpoint = self.seed()
        signed = self.cohort.signed(checkpoint)
        tampered = deepcopy(signed)
        tampered["payload"]["fixtures"]["A01"]["id"] += 100
        with self.assertRaisesRegex(FixtureError, "signature"):
            self.cohort.checkpoint(tampered, "retire", REVISION, RELEASE_PIN)
        redeployed = {**RELEASE_PIN, "versionId": "00000000-0000-4000-8000-000000000002"}
        with self.assertRaisesRegex(FixtureError, "release changed"):
            self.cohort.checkpoint(signed, "verify", REVISION, redeployed)

        before, _ = self.cohort.subscriptions()
        with self.cloud.db:
            self.cloud.db.execute("UPDATE subscriptions SET owner_id=? WHERE id=?", (POLICY["memberId"], before["A01"]["id"]))
        with self.assertRaisesRegex(FixtureError, "metadata"):
            smoke.retire(self.cohort, checkpoint, RELEASE_PIN, lambda: None)
        self.assertEqual(self.cloud.query("SELECT count(*) AS n FROM subscriptions", ()), [{"n": 17}])

    def test_retirement_cas_preserves_all_rows_and_pending_evidence(self):
        checkpoint = self.seed()

        def stale():
            with self.cloud.db:
                self.cloud.db.execute("UPDATE subscriptions SET name='changed' WHERE id=?",
                                      (checkpoint["fixtures"]["A02"]["id"],))

        with self.assertRaisesRegex(FixtureError, "metadata"):
            smoke.retire(self.cohort, checkpoint, RELEASE_PIN, stale)
        self.assertEqual(self.cloud.query("SELECT count(*) AS n FROM subscriptions", ()), [{"n": 17}])

    def test_pending_preview_or_wrong_origin_does_not_qualify(self):
        checkpoint = self.seed()
        admin = self.previews(checkpoint)
        self.move(checkpoint, admin)
        with self.cloud.db:
            self.cloud.db.execute("UPDATE telegram_outbox SET state='pending',sent_message_id=NULL WHERE receipt_id=?", (admin[0],))
        with self.assertRaisesRegex(FixtureError, "in-flight"):
            smoke.retire(self.cohort, checkpoint, RELEASE_PIN, lambda: None)
        with self.cloud.db:
            self.cloud.db.execute("UPDATE telegram_outbox SET state='sent',sent_message_id=? WHERE receipt_id=?",
                                  (admin[1] + 1, admin[0]))
        with self.assertRaisesRegex(FixtureError, "sent admin preview"):
            smoke.verify(self.cohort, checkpoint)

    def test_workflow_retirement_requires_exact_confirmation_and_source_revision(self):
        inputs = {"action": "retire", "cohort": COHORT, "purpose": "bulk-trash", "source_run_id": "123",
                  "source_revision": REVISION, "confirm_retire": f"retire {COHORT}"}
        self.assertEqual(smoke.parse_inputs({"inputs": inputs}), ("retire", COHORT, "123", REVISION))
        for field in ("source_run_id", "source_revision", "confirm_retire"):
            with self.assertRaises(FixtureError):
                smoke.parse_inputs({"inputs": {**inputs, field: ""}})
