"""Hosted-only acceptance tool tests with SQLite and no Telegram or Cloudflare calls."""

from base64 import urlsafe_b64decode, urlsafe_b64encode
from copy import deepcopy
from hashlib import sha256
import hmac
import json
import unittest

from test_telegram_aggregate_smoke import COHORT, IDENTITY, KEY, POLICY as BASE_POLICY, RELEASE_PIN, REVISION, FakeResources
import telegram_selected_smoke as smoke
from telegram_view_fixtures import FixtureError


POLICY = {**BASE_POLICY, "groupId": "-100881004"}


class SelectedAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.cloud = FakeResources()
        self.addCleanup(self.cloud.db.close)
        self.cohort = smoke.SelectedCohort(self.cloud, POLICY, COHORT, KEY, IDENTITY)
        self.checkpoint = smoke.prepare(self.cohort, REVISION, RELEASE_PIN, lambda: None)
        self.sequence = 0
        self.issued = {}
        self.probed = []

    def inbox(self, role, marker, *, group=False, origin=None):
        self.sequence += 1
        actor = self.cohort.actors[role]
        message_id = origin or self.sequence
        receipt, date = self.cloud.db.execute("""INSERT INTO telegram_inbox
          (bot_id,update_id,actor_id,chat_id,chat_type,message_id,message_date,command,receipt_nonce)
          VALUES (?,?,?,?,?,?,unixepoch(),'help',?) RETURNING receipt_id,message_date""",
          (POLICY["botId"], self.sequence, actor, POLICY["groupId"] if group else actor,
           "supergroup" if group else "private", message_id, marker)).fetchone()
        reply = self.sequence + 100
        self.cloud.db.execute("INSERT INTO telegram_outbox(receipt_id,state,attempts,sent_message_id) VALUES (?,'sent',1,?)",
                              (receipt, reply))
        return receipt, date, message_id, reply

    def paste(self):
        receipt, date, message, _ = self.inbox("admin", "temp:v1")
        self.cloud.db.execute("INSERT INTO telegram_temp_reply(receipt_id,kind,node_count,total_count) VALUES (?,'added',1,1)", (receipt,))
        node = self.cohort.node("temp")
        raw = smoke.canonical([{key: node[key] for key in ("name", "type", "share")}])
        self.cloud.db.execute("INSERT INTO telegram_temp_batch VALUES (?,?,?,?,?,?,?,?)",
            (receipt, POLICY["botId"], POLICY["adminId"], date, message, raw, 1, len(raw.encode("ascii"))))
        self.cloud.db.commit()

    def clear(self):
        receipt, date, message, _ = self.inbox("admin", "temp:v1")
        self.cloud.db.execute("INSERT INTO telegram_temp_reply(receipt_id,kind,node_count,total_count) VALUES (?,'cleared',1,0)", (receipt,))
        self.cloud.db.execute("DELETE FROM telegram_temp_batch")
        self.cloud.db.execute("INSERT INTO telegram_temp_clear_fence VALUES (?,?,?,?)", (POLICY["botId"], POLICY["adminId"], date, message))
        self.cloud.db.commit()

    def issue(self, label):
        role = label.split("-", 1)[0]
        actor = self.cohort.actors[role]
        receipt, _, _, reply = self.inbox(role, smoke.MARKER)
        nonce = urlsafe_b64encode(bytes([self.sequence]) * 16).decode().rstrip("=")
        ids = [self.checkpoint["snapshots"][item]["id"] for item in smoke.MEMBERS[label]]
        ids_text = json.dumps(ids, separators=(",", ":"))
        # Match the runtime's string-valued final HMAC field, not a JSON array.
        fields = ["subs-bot/telegram-aggregate/selected", 1, smoke.ORIGIN, POLICY["botId"], actor, nonce, ids_text]
        material = json.dumps(fields, separators=(",", ":")).encode()
        raw = hmac.digest(urlsafe_b64decode(KEY + "="), material, "sha256")[:16]
        code = urlsafe_b64encode(raw).decode().rstrip("=")
        code_hash = sha256(code.encode()).hexdigest()
        self.cloud.db.execute("INSERT INTO aggregate_links(code_sha256,owner_id,kind,selected_ids) VALUES (?,?,'selected',?)",
                              (code_hash, actor, ids_text))
        self.cloud.db.execute("INSERT INTO telegram_selected_links VALUES (?,?,?,?,?,1,?)",
                              (code_hash, POLICY["botId"], actor, receipt, nonce, smoke.canonical([[i, 1, 0] for i in ids])))
        self.cloud.db.execute("INSERT INTO telegram_selected_actions VALUES (?,'issued',?,0,0)", (receipt, code_hash))
        self.cloud.db.execute("""INSERT INTO telegram_selected_revoke_ticket
          (token_sha256,origin_receipt_id,code_sha256,origin_attempt,expires_at) VALUES (?,?,?,1,unixepoch()+600)""",
          (sha256(f"synthetic-ticket-{receipt}".encode()).hexdigest(), receipt, code_hash))
        self.cloud.db.commit()
        self.issued[label] = (code, code_hash, reply)
        return code_hash

    def revoke(self, label, *, wrong_origin=False):
        _, code_hash, origin = self.issued[label]
        role = label.split("-", 1)[0]
        receipt, _, _, _ = self.inbox(role, smoke.MARKER, origin=origin + int(wrong_origin))
        self.cloud.db.execute("INSERT INTO telegram_selected_actions VALUES (?,'revoked',?,0,0)", (receipt, code_hash))
        self.cloud.db.execute("UPDATE aggregate_links SET revoked_at=unixepoch() WHERE code_sha256=?", (code_hash,))
        self.cloud.db.execute("UPDATE telegram_selected_revoke_ticket SET used_by_receipt_id=? WHERE code_sha256=?", (receipt, code_hash))
        self.cloud.db.commit()

    def probe(self, code, code_hash, exports, label, *, active):
        self.assertEqual((code, code_hash), self.issued[label][:2])
        self.assertEqual(set(exports), {"clash", "base64"})
        self.assertNotIn(b"temp-node", exports["clash"])
        self.assertNotIn(b"admin-miss", exports["clash"])
        self.probed.append((label, active, sha256(exports["clash"]).hexdigest()))
        return {"status": 200 if active else 404}

    def capture(self, action, hashes):
        smoke.validate_checkpoint(self.checkpoint, action, COHORT, REVISION, IDENTITY, RELEASE_PIN)
        self.checkpoint, _ = smoke.capture(self.cohort, self.checkpoint, action, hashes, lambda: None, self.probe)

    def first(self):
        self.paste()
        self.inbox("admin", None, group=True)
        hashes = {label: self.issue(label) for label in ("admin-first", "member-first")}
        self.capture("capture-first-and-extend", hashes)

    def independent(self):
        self.first()
        second = self.issue("admin-second")
        self.revoke("admin-first")
        self.capture("capture-independence", {"admin-second": second})

    def test_complete_cohort_preserves_receipts_and_link_tombstones(self):
        self.independent()
        first = [item for item in self.probed if item[0] == "admin-first" and item[1]]
        self.assertEqual(len(first), 2)
        self.assertEqual(first[0], first[1])
        self.assertTrue(any(label == "admin-first" and not active for label, active, _ in self.probed))
        self.assertTrue(any(label == "admin-second" and active and wire != first[0][2] for label, active, wire in self.probed))
        self.revoke("admin-second")
        self.revoke("member-first")
        self.clear()
        # The timer may already have reaped a consumed ticket. Durable receipts still bind its origin.
        self.cloud.db.execute("DELETE FROM telegram_selected_revoke_ticket WHERE used_by_receipt_id IS NOT NULL")
        self.cloud.db.commit()
        self.cloud.fail_delete = 2
        with self.assertRaisesRegex(FixtureError, "R2 retirement"):
            smoke.retire(self.cohort, self.checkpoint, lambda: None, self.probe)
        self.assertFalse(self.cohort.subscriptions())
        self.cloud.fail_delete = None
        retired, _ = smoke.retire(self.cohort, self.checkpoint, lambda: None, self.probe)
        self.assertEqual(retired["phase"], "retired")
        self.assertEqual(len(retired["tombstones"]), 3)
        self.assertEqual(len(set(self.cloud.deleted)), 10)
        self.assertEqual(self.cloud.data, {})
        for table, count in (("telegram_inbox", 9), ("telegram_outbox", 9), ("telegram_selected_actions", 6),
                             ("telegram_selected_links", 3), ("aggregate_links", 3), ("telegram_temp_clear_fence", 1)):
            self.assertEqual(self.cloud.db.execute(f"SELECT count(*) FROM {table}").fetchone()[0], count)
        artifact = json.dumps(retired)
        for value in (KEY, *POLICY.values(), *(row[0] for row in self.issued.values()), "Straße", "ss://"):
            self.assertNotIn(json.dumps(value), artifact)

    def test_bad_browser_digest_expired_ticket_or_group_selected_receipt_prevents_extension(self):
        self.paste()
        self.inbox("admin", None, group=True)
        hashes = {label: self.issue(label) for label in ("admin-first", "member-first")}
        with self.assertRaisesRegex(FixtureError, "browser capability digest"):
            self.capture("capture-first-and-extend", {**hashes, "member-first": "0" * 64})
        self.cloud.db.execute("UPDATE telegram_selected_revoke_ticket SET expires_at=unixepoch()-1")
        self.cloud.db.commit()
        with self.assertRaisesRegex(FixtureError, "ticket expired"):
            self.capture("capture-first-and-extend", hashes)
        self.cloud.db.execute("UPDATE telegram_selected_revoke_ticket SET expires_at=unixepoch()+600")
        self.inbox("admin", smoke.MARKER, group=True)
        self.cloud.db.commit()
        with self.assertRaises(FixtureError):
            self.capture("capture-first-and-extend", hashes)
        self.assertEqual(set(self.cohort.subscriptions()), set(smoke.FIRST_SEEDS))
        self.assertEqual(len(self.cloud.puts), 8)

    def test_revocation_requires_exact_original_sent_message_and_same_active_module(self):
        self.first()
        second = self.issue("admin-second")
        self.revoke("admin-first", wrong_origin=True)
        with self.assertRaisesRegex(FixtureError, "original sent IAB button"):
            self.capture("capture-independence", {"admin-second": second})
        changed = {**RELEASE_PIN, "moduleSha256": "d" * 64}
        with self.assertRaisesRegex(FixtureError, "active release"):
            smoke.validate_checkpoint(deepcopy(self.checkpoint), "capture-independence", COHORT, REVISION, IDENTITY, changed)
        self.assertEqual(self.cloud.deleted, [])

    def test_only_digest_inputs_and_exact_owned_fixture_rows_are_accepted(self):
        query = f"{COHORT}-STRAẞE-Aς".lower()
        matches = [label for label in smoke.SEEDS
                   if query in " ".join(self.cohort.fixture(label)[1:3]).lower()]
        self.assertEqual(matches, ["admin-name", "admin-url", "member-name", "admin-late"])
        event = {"inputs": {"action": "capture-first-and-extend", "cohort": COHORT, "source_run_id": "123",
                            "browser_hashes": json.dumps({"admin-first": "a" * 64, "member-first": "b" * 64})}}
        self.assertEqual(set(smoke.parse_inputs(event)[3]), {"admin-first", "member-first"})
        event["inputs"]["browser_hashes"] = json.dumps({"admin-first": "fake-url", "member-first": "b" * 64})
        with self.assertRaisesRegex(FixtureError, "exact capability digests"):
            smoke.parse_inputs(event)
        self.cloud.db.execute("UPDATE subscriptions SET name='unrelated edit' WHERE id=?",
                              (self.checkpoint["snapshots"]["admin-name"]["id"],))
        self.cloud.db.commit()
        with self.assertRaisesRegex(FixtureError, "fixture identity"):
            smoke.prepare(self.cohort, REVISION, RELEASE_PIN, lambda: None)
        self.assertEqual(len(self.cloud.puts), 8)
