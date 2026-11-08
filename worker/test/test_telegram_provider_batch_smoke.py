"""Hosted synthetic tests for read-only batch acceptance evidence."""

import unittest
from unittest.mock import Mock, patch

from test_telegram_aggregate_smoke import POLICY, STAMP, FakeResources
import telegram_provider_batch_smoke as smoke
from telegram_view_fixtures import FixtureError


COHORT = "0123456789abcdef"
OTHER = "fedcba9876543210"


class BatchAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.cloud = FakeResources()
        self.addCleanup(self.cloud.db.close)
        self.now = STAMP + 60
        self.cloud.db.create_function("unixepoch", 0, lambda: self.now)
        self.update = 0
        self.acceptance = smoke.Acceptance(self.cloud, POLICY, COHORT, {
            "positive": {"cohort": COHORT}, "negative": {"cohort": OTHER},
        })
        self.auth = {"admin": (0, 0), "member": (STAMP - 1, 37)}
        self.prior = {"watermark": self.inbox("admin", None), "observedAt": STAMP, "imports": {}}
        self.batches = {}
        for role, offset in (("admin", 10), ("member", 20)):
            self.batches[role] = self.batch(role, offset)
        self.cloud.db.commit()
        self.now += 60

    def inbox(self, role, marker, message=None, *, group=False):
        self.update += 1
        actor = POLICY[role + "Id"]
        return self.cloud.db.execute("""INSERT INTO telegram_inbox
          (bot_id,update_id,actor_id,chat_id,chat_type,message_id,message_date,command,receipt_nonce)
          VALUES (?,?,?,?,?,?,unixepoch(),'help',?) RETURNING receipt_id""",
          (POLICY["botId"], self.update, actor, "-100881004" if group else actor,
           "supergroup" if group else "private", message or self.update, marker)).fetchone()[0]

    def batch(self, role, offset):
        db = self.cloud.db
        actor = POLICY[role + "Id"]
        preview = self.inbox(role, smoke.MARKERS[0])
        sent_preview = 1000 + preview
        batch = self.inbox(role, smoke.MARKERS[1], sent_preview)
        status = self.inbox(role, smoke.MARKERS[2])
        targets = []
        for ordinal, kind in enumerate(smoke.KINDS, 1):
            sid = offset + ordinal
            source = f"{sid:064x}"
            self.prior["imports"][f"{role}-{kind}"] = {"id": sid, "sourceSha256": source}
            targets.append([sid, 1, 0, source])
        db.execute("""INSERT INTO telegram_provider_batches
            (batch_id,preview_receipt_id,origin_attempt,bot_id,actor_id,actor_role,auth_message_date,auth_message_id,
             admission_nonce,target_count,skipped_count,created_at,expires_at,finished_at,saved_count,failed_count,stale_count,expired_count)
            VALUES (?,?,1,?,?,?,?,?,?,2,1,unixepoch(),unixepoch()+2700,unixepoch()+20,1,1,0,0)""",
            (batch, preview, POLICY["botId"], actor, role, *self.auth[role], str(batch)))
        db.execute("""INSERT INTO telegram_provider_batch_interactions
            (receipt_id,kind,actor_role,auth_message_date,auth_message_id,ready_at,targets,skipped_count,token_sha256,origin_attempt,
             expires_at,used_by_receipt_id) VALUES (?,'preview',?,?,?,unixepoch(),?,1,?,1,unixepoch()+600,?)""",
            (preview, role, *self.auth[role], smoke.canonical(targets), f"{preview:064x}", batch))
        for receipt, kind, ready, message in ((preview, None, self.now, sent_preview),
                                              (batch, "terminal", self.now + 20, 1000 + batch),
                                              (status, "status", self.now, 1000 + status)):
            if kind:
                db.execute("""INSERT INTO telegram_provider_batch_interactions
                    (receipt_id,kind,batch_id,actor_role,auth_message_date,auth_message_id,ready_at) VALUES (?,?,?,?,?,?,?)""",
                    (receipt, kind, batch, role, *self.auth[role], ready))
            db.execute("INSERT INTO telegram_outbox (receipt_id,state,attempts,sent_message_id) VALUES (?,'sent',1,?)", (receipt, message))
        for ordinal, (sid, _, _, source) in enumerate(targets, 1):
            result, failure = ("saved", None) if ordinal == 1 else ("fetch-rejected", "fetch-rejected")
            db.execute("""INSERT INTO telegram_provider_batch_jobs
                (batch_id,ordinal,owner_id,request_key,kind,subscription_id,source_sha256,expected_generation,expected_lifecycle_revision,
                 state,created_at,due_at,expires_at,attempts,result_code,failure_code,finished_at)
                VALUES (?,?,?,?,'refresh',?,?,1,0,'done',unixepoch(),unixepoch(),unixepoch()+2700,1,?,?,unixepoch()+20)""",
                (batch, ordinal, actor, f"{sid + 100:064x}", sid, source, result, failure))
        return batch

    def test_verifies_both_private_parent_child_graphs_and_sent_status(self):
        proofs, watermark = self.acceptance.terminal(self.prior, self.auth)
        self.assertEqual(set(proofs), {"admin", "member"})
        for proof in proofs.values():
            self.assertEqual({key: proof[key] for key in ("saved", "failed", "stale", "expired", "statusReply")},
                             {"saved": 1, "failed": 1, "stale": 0, "expired": 0, "statusReply": True})
        self.assertEqual(watermark["watermark"] - self.prior["watermark"], 6)

    def test_wrong_owner_or_extra_group_batch_receipt_fails_closed(self):
        batch = self.batches["member"]
        with self.cloud.db:
            self.cloud.db.execute("UPDATE telegram_provider_batch_jobs SET owner_id=? WHERE batch_id=? AND ordinal=1",
                                  (POLICY["adminId"], batch))
        with self.assertRaises(FixtureError):
            self.acceptance.terminal(self.prior, self.auth)
        with self.cloud.db:
            self.cloud.db.execute("UPDATE telegram_provider_batch_jobs SET owner_id=? WHERE batch_id=? AND ordinal=1",
                                  (POLICY["memberId"], batch))
        self.inbox("admin", smoke.MARKERS[0], group=True)
        with self.assertRaises(FixtureError):
            self.acceptance.terminal(self.prior, self.auth)

    def test_negative_pointer_must_equal_preflight_including_object_digest(self):
        prior = {label: {"id": i, "generation": 1, "snapshotId": f"before-{i}", "nodeCount": 1, "tokenSha256": "fixture",
                         "sourceSha256": "source", "importReceipt": i, "objectsSha256": "unchanged"}
                 for i, label in enumerate(self.prior["imports"], 1)}
        rows = {label: {"last_error": "provider-refresh-failed" if label.endswith("-negative") else None} for label in prior}
        after = {label: dict(item) if label.endswith("-negative") else {**item, "generation": 2, "snapshotId": "new"}
                 for label, item in prior.items()}

        def snapshot(_row, role, kind, _auth, _watermark):
            return after[f"{role}-{kind}"]

        with (patch.object(self.acceptance, "inventory", return_value=rows),
              patch.object(self.acceptance, "snapshot", side_effect=snapshot)):
            self.assertEqual(self.acceptance.snapshots(self.auth, 1, prior), after)
            after["member-negative"]["objectsSha256"] = "changed"
            with self.assertRaises(FixtureError):
                self.acceptance.snapshots(self.auth, 1, prior)


class SafetyTests(unittest.TestCase):
    def test_no_cloud_write_method_or_other_query_target_reaches_client(self):
        client = Mock()
        read = smoke.read_only_api(client, "/owned/query")
        read("GET", "/owned/resource")
        read("POST", "/owned/query", {"sql": "SELECT 1"})
        for method, path, payload in (
            ("POST", "/foreign/query", {"sql": "SELECT 1"}),
            ("POST", "/owned/query", {"sql": "SELECT 1; DELETE FROM subscriptions"}),
            ("POST", "/owned/query", {"sql": "UPDATE subscriptions SET name='changed'"}),
            ("DELETE", "/owned/resource", None),
        ):
            with self.assertRaises(FixtureError):
                read(method, path, payload)
        self.assertEqual(client.call_count, 2)

    def test_action_inputs_accept_only_exact_protected_predecessors(self):
        preflight = {"action": "preflight", "cohort": COHORT, "positive_document_run_id": "10", "negative_document_run_id": "11"}
        self.assertEqual(smoke.parse_inputs({"inputs": preflight}), ("preflight", COHORT, {"positive": "10", "negative": "11"}, ""))
        self.assertEqual(smoke.parse_inputs({"inputs": {"action": "capture", "cohort": COHORT, "source_run_id": "12"}})[-1], "12")
        for patch_ in ({"source_run_id": "12"}, {"negative_document_run_id": "10"}, {"capability": "synthetic-secret"}):
            with self.assertRaises(FixtureError):
                smoke.parse_inputs({"inputs": preflight | patch_})


if __name__ == "__main__":
    unittest.main()
