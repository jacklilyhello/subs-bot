"""Hosted SQLite faults for the versioned full general isolation control plane."""

from hashlib import sha256
import json
from pathlib import Path
import sqlite3
import sys
from uuid import UUID
from unittest import TestCase
from unittest.mock import patch

WORKER = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WORKER / "tools"))
import cloudflare_isolation as cloudflare
from d1_migrations import LEDGER_SQL, _statements
import general_isolation_window as window
import general_read_rehearsal as reads
from test_general_read_rehearsal import ARTIFACT, BOT, DEPLOYMENT, MODULE, REVISION, Scope
from test_page_jump_control import PATH, TARGET

CONFIG = json.dumps({"botId": BOT, "adminId": "456", "memberId": "789", "groupId": "-42"})


class Data:
    def __init__(self):
        self.db = sqlite3.connect(":memory:")
        self.db.row_factory = sqlite3.Row
        self.db.executescript(LEDGER_SQL + ";")
        for file in sorted((WORKER / "migrations").glob("*.sql")):
            self.db.executescript(file.read_text())
            self.db.execute("INSERT INTO subs_bot_schema_migrations(position,name,sha256,mode) VALUES(?,?,?,'applied')",
                (int(file.name[:4]), file.name, sha256(file.read_bytes()).hexdigest()))
        self.db.commit()
        self.fault, self.before_write, self.writes = None, None, 0

    def __call__(self, method, path, payload):
        assert method == "POST" and path == PATH and set(payload) == {"sql"}
        sql = payload["sql"]
        write = sql.startswith("SELECT CASE WHEN")
        fault = None
        if write:
            fault, self.fault = self.fault, None
            self.writes += 1
            if fault == "drop":
                raise cloudflare.CloudflareError("synthetic lost request", uncertain=True)
            hook, self.before_write = self.before_write, None
            if hook:
                hook()
        try:
            with self.db:
                if write:
                    self.db.execute("BEGIN")
                result = [{"success": True, "results": [dict(row) for row in self.db.execute(part).fetchall()]}
                    for part in (_statements(sql) if write else (sql,))]
        except sqlite3.Error:
            raise cloudflare.CloudflareError("synthetic transaction rejected") from None
        if write and fault == "lost":
            raise cloudflare.CloudflareError("synthetic lost acknowledgment", uncertain=True)
        return result


class FullWindowTests(TestCase):
    def setUp(self):
        self.api = Data()
        self.addCleanup(self.api.db.close)
        self.scope = Scope(self.api)
        self.scope.version_pin = cloudflare._Version(*ARTIFACT, None, sha256(CONFIG.encode()).hexdigest())
        health = patch.object(window, "_verify_health")
        health.start()
        self.addCleanup(health.stop)

    def action(self, action="inspect", before=None, artifact=ARTIFACT):
        return window.run(self.scope, CONFIG, lambda: True, action=action, artifact=artifact,
            expected_active=before["activeSha256"] if before else "",
            expected_state=before["stateSha256"] if before else "")

    def card(self, state, *, attempts=0, active_lease=False, expired_lease=False):
        receipt = self.api.db.execute("""INSERT INTO telegram_inbox
            (bot_id,update_id,actor_id,chat_id,chat_type,message_id,message_date,command,receipt_nonce)
            VALUES (?,(SELECT COALESCE(max(update_id),0)+1 FROM telegram_inbox),'456','456','private',1,1,'help','share-create:v1')""", (BOT,)).lastrowid
        payload = str(UUID(int=receipt + 20, version=4))
        self.api.db.execute("""INSERT INTO private_shares(id,bot_id,code_sha256,sender_id,sender_name,payload_id,payload_sha256,
            payload_bytes,max_claims,target_user_id,expire_at,created_at) VALUES (?, ?,?,'456','synthetic',?,?,1,1,NULL,61,1)""",
            (receipt, BOT, f"{receipt:064x}", payload, sha256(b"x").hexdigest()))
        self.api.db.execute("""INSERT INTO telegram_private_share_creations(receipt_id,bot_id,actor_id,message_date,message_id,
            auth_message_date,auth_message_id,state,payload_id,payload_sha256,payload_bytes,sender_name,max_claims,target_user_id,
            duration_minutes,installation,key_version,reservation_expires_at,next_check_at,cleanup_after,share_id)
            VALUES (?,?,'456',1,1,0,0,'published',?,?,1,'synthetic',1,NULL,1,'isolation',1,5,5,6,?)""",
            (receipt, BOT, payload, sha256(b"x").hexdigest(), receipt))
        lease = str(UUID(int=receipt + 100, version=4)) if active_lease or expired_lease else None
        until = self.api.db.execute("SELECT unixepoch()+900").fetchone()[0] if active_lease else 1 if expired_lease else None
        self.api.db.execute("""INSERT INTO telegram_group_share_cards
            (receipt_id,group_id,state,due_at,attempts,message_id,lease_id,lease_until,shown) VALUES (?,'-42',?,1,?,?,?,?,0)""",
            (receipt, state, attempts, receipt if state == "sent" else None, lease, until))
        self.api.db.commit()
        return receipt

    def test_close_open_drain_restore_preserves_business_data_and_history(self):
        self.api.db.execute("INSERT INTO subscriptions(owner_id,name,source_url,token,created_at,updated_at) VALUES('789','existing','https://example.invalid/source','test-preserve-token',1,1)")
        self.api.db.commit()
        baseline = self.action()
        self.assertEqual(baseline["profile"], "full-v1")
        closed = self.action("close", baseline)
        with self.assertRaises(cloudflare.CloudflareError):
            reads.require_general_read_lane_clear(self.scope)
        with self.assertRaises(cloudflare.CloudflareError):
            reads.run(self.scope, CONFIG, lambda: True, action="inspect", expected_active="", expected_state="", artifact=ARTIFACT)
        opened = self.action("open", closed)
        self.assertEqual((opened["mode"], opened["epoch"], opened["generation"]), ("general", 2, 1))
        self.assertEqual([tuple(row) for row in self.api.db.execute("SELECT actor_id,role FROM telegram_general_actors ORDER BY actor_id")], [("456", "admin"), ("789", "member")])
        self.assertEqual(tuple(self.api.db.execute("SELECT chat_id,chat_type FROM telegram_general_groups").fetchone()), ("-42", "group"))
        closed = self.action("close", self.action(), artifact=None)
        drained = self.action("drain", closed, artifact=None)
        restored = self.action("restore", drained, artifact=None)
        self.assertEqual(restored["mode"], "isolated")
        self.assertEqual(self.api.db.execute("SELECT count(*) FROM subscriptions").fetchone()[0], 1)
        self.assertEqual(self.api.db.execute("SELECT count(*) FROM telegram_general_actors").fetchone()[0], 2)
        self.assertEqual(self.api.db.execute("SELECT count(*) FROM telegram_general_isolation_window").fetchone()[0], 0)
        reads.require_general_read_lane_clear(self.scope)

    def test_stale_predecessor_and_lost_acknowledgment_do_not_repeat_transition(self):
        baseline = self.action()
        # The hook changes the exact predecessor immediately before the atomic batch.
        self.api.before_write = lambda: self.api.db.execute("INSERT INTO telegram_general_read_lane(bot_id,epoch,mode) VALUES('123',7,'isolated')")
        with self.assertRaises(cloudflare.CloudflareError):
            self.action("close", baseline)
        self.assertEqual(self.api.db.execute("SELECT count(*) FROM telegram_general_isolation_window").fetchone()[0], 0)
        self.api.db.rollback()
        before = self.action()
        self.api.fault = "lost"
        closed = self.action("close", before)
        self.assertEqual(closed["mode"], "closed")
        writes = self.api.writes
        with self.assertRaises(cloudflare.CloudflareError):
            self.action("close", before)
        self.assertEqual(self.api.writes, writes)

    def test_classified_work_prevents_restore_even_with_no_pending_outbox(self):
        closed = self.action("close", self.action())
        opened = self.action("open", closed)
        closed = self.action("close", self.action())
        self.api.db.execute("INSERT INTO telegram_inbox(bot_id,update_id,actor_id,chat_id,chat_type,message_id,message_date,command,receipt_nonce) VALUES('123',900,'789','789','private',900,1,'help','general-read:v1')")
        receipt = self.api.db.execute("SELECT max(receipt_id) FROM telegram_inbox").fetchone()[0]
        self.api.db.execute("INSERT INTO telegram_github_search(receipt_id,bot_id,actor_id,auth_message_date,auth_message_id,state,started_at,lookup_nonce,lookup_until) VALUES(?,'123','789',0,0,'looking',unixepoch(),'synthetic',unixepoch()+30)", (receipt,))
        self.api.db.commit()
        observed = self.action()
        self.assertEqual(observed["work"]["outbox"], 0)
        self.assertEqual(observed["work"]["searches"], 1)
        for action in ("drain", "restore"):
            with self.assertRaises(cloudflare.CloudflareError):
                self.action(action, observed, artifact=None)

    def test_profile_requires_its_exact_migration_and_compiled_marker(self):
        migrations = [{}] * 51 + [{"name": window.MIGRATION, "sha256": window.MIGRATION_SHA256}]
        self.assertTrue(window.general_window_artifact(window.MARKER, {"migrations": migrations}))
        for module, chain in ((b"", migrations), (window.MARKER, migrations[:-1])):
            with self.assertRaises(cloudflare.CloudflareError):
                window.general_window_artifact(module, {"migrations": chain})

    def test_terminal_group_card_failures_are_preserved_as_nonblocking_evidence(self):
        self.action("open", self.action("close", self.action()))
        self.action("close", self.action())
        self.card("uncertain", attempts=1, expired_lease=True)
        self.card("sent", attempts=4)
        self.card("failed", attempts=1)
        original = [tuple(row) for row in self.api.db.execute("SELECT * FROM telegram_group_share_cards ORDER BY receipt_id")]
        observed = self.action()
        self.assertEqual(observed["work"]["groupCards"], 0)
        self.assertEqual(observed["terminalCards"], {"terminalUnknown": 1, "terminalEditFailure": 1, "terminalDeliveryFailure": 1})
        drained = self.action("drain", observed, artifact=None)
        restored = self.action("restore", drained, artifact=None)
        self.assertEqual(restored["terminalCards"], observed["terminalCards"])
        self.assertEqual(restored["terminalCardPolicy"], "retained-without-automatic-retry")
        self.assertEqual([tuple(row) for row in self.api.db.execute("SELECT * FROM telegram_group_share_cards ORDER BY receipt_id")], original)

    def test_active_card_leases_and_retryable_sent_cards_still_block_restore(self):
        self.action("open", self.action("close", self.action()))
        self.action("close", self.action())
        unknown = self.card("uncertain", attempts=1, active_lease=True)
        editable = self.card("sent", attempts=0)
        exhausted = self.card("sent", attempts=4, active_lease=True)
        observed = self.action()
        self.assertEqual(observed["work"]["groupCards"], 3)
        self.assertEqual(observed["terminalCards"], {"terminalUnknown": 0, "terminalEditFailure": 0, "terminalDeliveryFailure": 0})
        for action in ("drain", "restore"):
            with self.assertRaises(cloudflare.CloudflareError):
                self.action(action, observed, artifact=None)
        self.api.db.execute("UPDATE telegram_group_share_cards SET lease_until=1 WHERE receipt_id IN (?,?)", (unknown, exhausted))
        self.api.db.commit()
        observed = self.action()
        self.assertEqual(observed["work"]["groupCards"], 1)
        self.assertEqual(observed["terminalCards"], {"terminalUnknown": 1, "terminalEditFailure": 1, "terminalDeliveryFailure": 0})
        self.api.db.execute("UPDATE telegram_group_share_cards SET attempts=4 WHERE receipt_id=?", (editable,))
        self.api.db.commit()
        observed = self.action()
        self.assertEqual(observed["work"]["groupCards"], 0)
        self.assertEqual(observed["terminalCards"]["terminalEditFailure"], 2)
