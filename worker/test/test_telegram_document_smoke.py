from io import BytesIO
import json
from pathlib import Path
import sqlite3
import sys
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit
from uuid import uuid4
from zipfile import ZipFile

WORKER = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WORKER / "tools"))

import telegram_document_smoke as smoke
from cloudflare_isolation import CloudflareError
from telegram_view_fixtures import FixtureError


COHORT = "0123456789abcdef"
REVISION = "a" * 40
IDENTITY = "b" * 64
POLICY = {"botId": "881001", "memberId": "881002", "adminId": "881003"}
TOKEN = {"member": "1" * 32, "admin": "2" * 32}
STAMP = 1_800_000_000


class FakeResources:
    database = "/test/db"
    bucket = "/test/bucket"

    def __init__(self, database):
        self.db = database
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys=ON")
        for migration in sorted((WORKER / "migrations").glob("*.sql")):
            self.db.executescript(migration.read_text("utf-8"))
        self.objects = self
        self.data = {}
        self.deleted = []
        self.failure = None
        self.fail_after_delete = None

    def query(self, sql, params):
        return [dict(row) for row in self.db.execute(sql, params).fetchall()]

    def api(self, method, path, payload=None):
        if method == "GET":
            parsed = urlsplit(path)
            assert parsed.path == self.bucket + "/objects"
            prefix, = parse_qs(parsed.query)["prefix"]
            per_page, = parse_qs(parsed.query)["per_page"]
            return [{"key": key, "size": len(body)} for key, body in sorted(self.data.items())
                    if key.startswith(prefix)][:int(per_page)]
        assert method == "POST" and path == self.database + "/query"
        failure, self.failure = self.failure, None
        if failure == "uncommitted":
            raise CloudflareError("Synthetic D1 response lost.", uncertain=True)
        try:
            with self.db:
                results = [{"success": True, "results": self.query(item["sql"], item["params"])} for item in payload["batch"]]
        except sqlite3.Error:
            raise CloudflareError("Synthetic D1 transaction rejected.") from None
        if failure == "committed":
            raise CloudflareError("Synthetic committed D1 response lost.", uncertain=True)
        return results

    def request(self, method, key):
        if method == "GET":
            return self.data.get(key)
        assert method == "DELETE"
        if self.fail_after_delete == len(self.deleted):
            raise CloudflareError("Synthetic R2 request lost.", uncertain=True)
        self.deleted.append(key)
        self.data.pop(key, None)


class DocumentSmokeTests(unittest.TestCase):
    def setUp(self):
        self.cloud = FakeResources(sqlite3.connect(":memory:"))
        self.addCleanup(self.cloud.db.close)
        self.cohort = smoke.Cohort(self.cloud, POLICY, COHORT)
        self.checkpoint = {"version": 1, "phase": "prepared", "cohort": COHORT, "revision": REVISION, "identity": IDENTITY,
                           "afterReceiptId": 0, "snapshots": {}, "receipts": {"member": [], "admin": []}, "negativeReceiptBound": False}
        self.probed = []

    def job(self, role, message, *, saved_nodes=None):
        actor = self.cohort.actors[role]
        receipt, = self.cloud.db.execute("""INSERT INTO telegram_inbox
            (bot_id,update_id,actor_id,chat_id,chat_type,message_id,message_date,command,receipt_nonce)
            VALUES (?,?,?,?, 'private',?,?,'help',?) RETURNING receipt_id
        """, (POLICY["botId"], message, actor, actor, message, STAMP, smoke.MARKER)).fetchone()
        result = "saved" if saved_nodes is not None else "invalid-document"
        self.cloud.db.execute("""INSERT INTO telegram_document_jobs
            (receipt_id,bot_id,actor_id,auth_message_date,auth_message_id,state,due_at,expires_at,attempts,result_code,finished_at)
            VALUES (?,?,?,0,0,'done',?,?,1,?,?)""", (receipt, POLICY["botId"], actor, STAMP, STAMP + 600, result, STAMP + 2))
        self.cloud.db.execute("INSERT INTO telegram_outbox (receipt_id,state,sent_message_id) VALUES (?,'sent',?)",
                              (receipt, message + 100))
        if saved_nodes is not None:
            self.cloud.db.execute("INSERT INTO telegram_document_saved_counts (receipt_id,node_count,name_sha256) VALUES (?,?,?)",
                                  (receipt, saved_nodes, smoke.digest(self.cohort.name.encode("ascii"))))
        self.cloud.db.commit()

    def publish(self, version, message):
        role, generation, _ = smoke.VERSIONS[version]
        identifier = 1 if role == "member" else 2
        shares = smoke.share_lines(COHORT, version)
        snapshot_id = str(uuid4())
        chunk = "".join(json.dumps({"share": share}) + "\n" for share in shares).encode()
        manifest = json.dumps({"version": 1, "chunks": [{"bytes": len(chunk), "sha256": smoke.digest(chunk),
                                                        "count": len(shares)}]}).encode()
        prefix = f"subscriptions/{identifier}/{snapshot_id}/"
        self.cloud.data[prefix + "0.ndjson"] = chunk
        self.cloud.data[prefix + "manifest.json"] = manifest
        self.cloud.db.execute("""INSERT INTO subscriptions
            (id,owner_id,name,source_url,token,created_at,updated_at,generation,snapshot_id,manifest_sha256,node_count)
            VALUES (?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET generation=excluded.generation,
            updated_at=excluded.updated_at,snapshot_id=excluded.snapshot_id,manifest_sha256=excluded.manifest_sha256,
            node_count=excluded.node_count""", (identifier, self.cohort.actors[role], self.cohort.name, smoke.UPLOADED,
                TOKEN[role], STAMP, STAMP + generation, generation, snapshot_id, smoke.digest(manifest), len(shares)))
        self.job(role, message, saved_nodes=len(shares))
        return prefix

    def capture(self, action, negative=None):
        smoke.validate_checkpoint(self.checkpoint, action, COHORT, REVISION, IDENTITY)
        self.checkpoint = smoke.capture(self.cohort, self.checkpoint, action, negative,
                                        lambda token, shares: self.probed.append((token, shares)))
        return self.checkpoint

    def created(self):
        self.publish("member-first", 1)
        self.publish("admin-first", 2)
        return self.capture("capture-created")

    def verified(self, negative=True):
        self.created()
        self.publish("member-second", 3)
        self.job("member", 4)
        return self.capture("verify-replaced", 4 if negative else None)

    def test_captures_both_owners_and_keeps_the_replaced_generation_in_a_safe_checkpoint(self):
        checkpoint = self.verified()
        self.assertTrue(checkpoint["negativeReceiptBound"])
        self.assertEqual(len(checkpoint["receipts"]["member"]), 2)
        self.assertEqual(len(checkpoint["receipts"]["admin"]), 1)
        self.assertEqual(len(self.probed), 4)
        self.assertEqual(self.probed[-1], (TOKEN["member"], smoke.share_lines(COHORT, "member-second")))
        for private in (*TOKEN.values(), *POLICY.values(), "ss://", "file_id"):
            self.assertNotIn('"' + private + '"', json.dumps(checkpoint))
        self.assertNotIn("ss://", json.dumps(checkpoint))
        smoke.validate_checkpoint(checkpoint, "retire", COHORT, REVISION, IDENTITY)

    def test_unbound_negative_does_not_fabricate_a_receipt_and_unknown_object_fails_closed(self):
        checkpoint = self.verified(negative=False)
        self.assertFalse(checkpoint["negativeReceiptBound"])
        prefix = next(key.rsplit("/", 1)[0] for key in self.cloud.data)
        self.cloud.data[prefix + "/unrelated"] = b"unexpected"
        with self.assertRaisesRegex(FixtureError, "inventory differs|Unknown document snapshot object"):
            smoke.retire(self.cohort, checkpoint, lambda: None)
        self.assertEqual(self.cloud.deleted, [])
        self.assertEqual(len(self.cohort.subscriptions()), 2)

    def test_retirement_reconciles_ambiguous_d1_then_retries_exact_remaining_objects(self):
        checkpoint = self.verified()
        self.cloud.data["unrelated"] = b"untouched"
        self.cloud.failure = "uncommitted"
        with self.assertRaisesRegex(FixtureError, "D1 retirement could not be confirmed"):
            smoke.retire(self.cohort, checkpoint, lambda: None)
        self.assertEqual(self.cloud.deleted, [])
        self.assertEqual(len(self.cohort.subscriptions()), 2)

        self.cloud.failure = "committed"
        self.cloud.fail_after_delete = 2
        with self.assertRaisesRegex(CloudflareError, "Synthetic R2 request lost"):
            smoke.retire(self.cohort, checkpoint, lambda: None)
        self.assertEqual(self.cohort.subscriptions(), {})
        self.assertEqual(len(self.cloud.deleted), 2)
        self.cloud.fail_after_delete = None
        self.assertEqual(smoke.retire(self.cohort, checkpoint, lambda: None)["phase"], "retired")
        self.assertEqual(len(set(self.cloud.deleted)), 6)
        self.assertEqual(self.cloud.data, {"unrelated": b"untouched"})
        for table, count in [("telegram_inbox", 4), ("telegram_document_jobs", 4), ("telegram_outbox", 4),
                             ("telegram_document_saved_counts", 3)]:
            self.assertEqual(self.cloud.db.execute(f"SELECT count(*) FROM {table}").fetchone()[0], count)

    def test_refuses_active_job_or_owner_pointer_drift(self):
        checkpoint = self.created()
        actor = POLICY["memberId"]
        receipt, = self.cloud.db.execute("""INSERT INTO telegram_inbox
            (bot_id,update_id,actor_id,chat_id,chat_type,message_id,message_date,command,receipt_nonce)
            VALUES (?,3,?,?,'private',3,?,'help',?) RETURNING receipt_id""",
            (POLICY["botId"], actor, actor, STAMP, smoke.MARKER)).fetchone()
        self.cloud.db.execute("""INSERT INTO telegram_document_jobs
            (receipt_id,bot_id,actor_id,auth_message_date,auth_message_id,state,due_at,expires_at,file_id,name,suffix)
            VALUES (?,?,?,0,0,'pending',?,?,'synthetic-file-id',?,'txt')""",
            (receipt, POLICY["botId"], actor, STAMP, STAMP + 100, self.cohort.name))
        self.cloud.db.commit()
        with self.assertRaisesRegex(FixtureError, "live job or a protected reference"):
            smoke.retire(self.cohort, checkpoint, lambda: None)
        self.cloud.db.execute("DELETE FROM telegram_document_jobs WHERE receipt_id=?", (receipt,))
        self.cloud.db.execute("UPDATE subscriptions SET updated_at=updated_at+1 WHERE id=1")
        self.cloud.db.commit()
        with self.assertRaisesRegex(FixtureError, "pointer differs"):
            smoke.retire(self.cohort, checkpoint, lambda: None)
        self.assertEqual(self.cloud.deleted, [])
        self.assertEqual(len(self.cohort.subscriptions()), 2)

    def test_requires_literal_confirmation_and_rejects_checkpoint_archive_drift(self):
        inputs = {"action": "retire", "cohort": COHORT, "source_run_id": "123", "confirm_retire": f"retire {COHORT}"}
        self.assertEqual(smoke.parse_inputs({"inputs": inputs}), ("retire", COHORT, "123", None))
        with self.assertRaises(FixtureError):
            smoke.parse_inputs({"inputs": {**inputs, "confirm_retire": "yes"}})
        raw = BytesIO()
        with ZipFile(raw, "w") as archive:
            archive.writestr(smoke.CHECKPOINT, json.dumps(self.checkpoint))
        with patch.object(smoke, "_get_json", return_value={"id": 42, "path": f".github/workflows/{smoke.WORKFLOW}"}), \
             patch.object(smoke, "select_main_artifact", return_value=("1", "2", smoke.digest(raw.getvalue()))) as select, \
             patch.object(smoke, "_download", return_value=raw.getvalue()) as download:
            self.assertEqual(smoke.read_checkpoint("123", REVISION, "fixture"), self.checkpoint)
            select.assert_called_once_with("123", REVISION, "fixture", workflow_id=42,
                workflow_path=f".github/workflows/{smoke.WORKFLOW}", artifact_prefix=smoke.ARTIFACT_PREFIX,
                workflow_label="Telegram document checkpoint")
            download.return_value = raw.getvalue() + b"unexpected"
            with self.assertRaisesRegex(FixtureError, "archive digest"):
                smoke.read_checkpoint("123", REVISION, "fixture")


if __name__ == "__main__":
    unittest.main()
