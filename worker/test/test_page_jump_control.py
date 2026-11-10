"""Hosted SQLite fault tests for isolated page-jump control."""

from pathlib import Path
import sqlite3
import sys
import unittest

WORKER = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WORKER / "tools"))

import cloudflare_isolation as cloudflare
import page_jump_control as controls


BOT = "123"
TARGET = {
    "accountId": "a" * 32,
    "workerId": "b" * 32,
    "workerCreatedOn": "2026-07-30T00:00:00.001Z",
    "d1Id": "00000000-0000-4000-8000-000000000001",
    "d1CreatedAt": "2026-07-30T00:00:00.002Z",
    "r2CreatedOn": "2026-07-30T00:00:00.003Z",
    "namespace": cloudflare.NAMESPACE,
}
PATH = f"/accounts/{TARGET['accountId']}/d1/database/{TARGET['d1Id']}/query"


def current():
    return True


class MemoryD1:
    def __init__(self):
        self.db = sqlite3.connect(":memory:")
        self.db.row_factory = sqlite3.Row
        self.before_write = None
        self.fault = None
        self.writes = 0
        for name in ("0002_telegram.sql", cloudflare.PAGE_JUMP_MIGRATION, cloudflare.PAGE_JUMP_CONTROL_MIGRATION):
            self.db.executescript((WORKER / "migrations" / name).read_text(encoding="utf-8"))
        self.db.execute("CREATE TABLE subs_bot_schema_migrations(position INTEGER PRIMARY KEY,name TEXT,sha256 TEXT,mode TEXT)")
        self.db.executemany("INSERT INTO subs_bot_schema_migrations VALUES (?,?,?,'applied')", [
            (42, cloudflare.PAGE_JUMP_MIGRATION, cloudflare.PAGE_JUMP_MIGRATION_SHA256),
            (43, cloudflare.PAGE_JUMP_CONTROL_MIGRATION, cloudflare.PAGE_JUMP_CONTROL_MIGRATION_SHA256),
        ])
        self.db.commit()

    def __call__(self, method, path, payload):
        assert method == "POST" and path == PATH
        sql = payload["sql"]
        write = sql.startswith(("INSERT ", "UPDATE "))
        if write:
            self.writes += 1
            hook, self.before_write = self.before_write, None
            if hook:
                hook()
            if self.fault == "drop":
                self.fault = None
                raise cloudflare.CloudflareError("synthetic transport failure", uncertain=True)
        with self.db:
            rows = self.db.execute(sql, payload["params"]).fetchall()
        if write and self.fault == "lost":
            self.fault = None
            raise cloudflare.CloudflareError("synthetic transport failure", uncertain=True)
        return [{"success": True, "results": [dict(row) for row in rows]}]

    def receipt(self, *, bot=BOT, marker="view-jump:v2", state=None):
        seq = self.db.execute("SELECT COALESCE((SELECT seq FROM sqlite_sequence WHERE name='telegram_inbox'),0)").fetchone()[0]
        with self.db:
            receipt = self.db.execute("""INSERT INTO telegram_inbox
                (bot_id,update_id,actor_id,chat_id,chat_type,message_id,message_date,command,receipt_nonce)
                VALUES (?,?,'456','456','private',?,1,'help',?)""", (bot, seq + 1, seq + 1, marker)).lastrowid
            if state is not None:
                lease = f"fixture-{receipt}" if state in ("leased", "sending", "uncertain") else None
                deadline = 1 if state in ("leased", "sending") else None
                self.db.execute("""INSERT INTO telegram_outbox(receipt_id,state,attempts,lease_id,lease_until,sent_message_id)
                    VALUES (?,?,1,?,?,?)""", (receipt, state, lease, deadline, receipt if state == "sent" else None))
        return receipt


class PageJumpControlTests(unittest.TestCase):
    def setUp(self):
        self.api = MemoryD1()
        self.addCleanup(self.api.db.close)
        self.control = controls.PageJumpControl(cloudflare._Isolation(None, self.api, TARGET), BOT)

    def test_reserve_requires_a_newer_exact_run_and_recovers_lost_ack(self):
        self.assertEqual(self.control.observe(), controls.PageJumpObservation(None, False))
        for run in (True, 0, controls.MAX_SAFE_INTEGER + 1):
            with self.subTest(run=run), self.assertRaisesRegex(cloudflare.CloudflareError, "protected run ID"):
                self.control.reserve(None, run, current)
        self.assertEqual(self.api.writes, 0)
        self.api.fault = "lost"
        reserved = self.control.reserve(None, 100, current)
        self.assertEqual(reserved, controls.PageJumpGate(100, False, 0))
        self.assertEqual(self.control.reserve(None, 100, current), reserved)
        with self.assertRaisesRegex(cloudflare.CloudflareError, "stale"):
            self.control.reserve(None, 101, current)
        with self.assertRaisesRegex(cloudflare.CloudflareError, "protected run ID"):
            self.control.reserve(reserved, 99, current)
        self.assertEqual(self.api.writes, 1)

    def test_open_pins_autoincrement_watermark_and_rerun_keeps_it(self):
        reserved = self.control.reserve(None, 100, current)
        self.api.receipt()
        removed = self.api.receipt()
        with self.api.db:
            self.api.db.execute("DELETE FROM telegram_inbox WHERE receipt_id=?", (removed,))
        self.api.fault = "lost"
        opened = self.control.open(reserved, current)
        self.assertEqual(opened, controls.PageJumpGate(100, True, removed))
        self.api.receipt()
        self.assertEqual(self.control.open(reserved, current), opened)
        with self.assertRaisesRegex(cloudflare.CloudflareError, "stale"):
            self.control.reserve(opened, 101, current)
        self.assertEqual(self.api.writes, 2)

    def test_pause_fences_delayed_open_even_if_gate_was_closed(self):
        reserved = self.control.reserve(None, 100, current)
        self.api.before_write = lambda: self.control.pause(reserved, 101, current)
        with self.assertRaisesRegex(cloudflare.CloudflareError, "could not be confirmed") as error:
            self.control.open(reserved, current)
        self.assertTrue(error.exception.uncertain)
        paused = self.control.observe().gate
        self.assertEqual(paused, controls.PageJumpGate(101, False, 0))
        with self.assertRaisesRegex(cloudflare.CloudflareError, "stale"):
            self.control.open(reserved, current)
        self.assertEqual(self.control.verify_drained(paused, current), paused)

    def test_pause_handles_open_winning_the_race_and_lost_pause_ack(self):
        reserved = self.control.reserve(None, 100, current)
        last = self.api.receipt()

        def racing_open():
            self.control.open(reserved, current)
            self.api.fault = "lost"

        self.api.before_write = racing_open
        paused = self.control.pause(reserved, 101, current)
        self.assertEqual(paused, controls.PageJumpGate(101, False, last))
        self.assertEqual(self.control.pause(reserved, 101, current), paused)
        self.assertEqual(self.api.writes, 3)

    def test_drain_is_exact_bot_marker_and_closed_checkpoint(self):
        paused = self.control.pause(None, 100, current)
        self.api.receipt(bot="789", state="pending")
        self.api.receipt(marker="view:v1", state="pending")
        self.api.receipt(marker="view-jump:v1", state="sending")
        self.api.receipt(state="uncertain")
        self.assertEqual(self.control.verify_drained(paused, current), paused)
        for state in ("pending", "leased", "sending"):
            receipt = self.api.receipt(state=state)
            with self.subTest(state=state), self.assertRaisesRegex(cloudflare.CloudflareError, "have not drained"):
                self.control.verify_drained(paused, current)
            with self.api.db:
                self.api.db.execute("UPDATE telegram_outbox SET state='failed',lease_id=NULL,lease_until=NULL WHERE receipt_id=?", (receipt,))
        self.control.reserve(paused, 101, current)
        with self.assertRaisesRegex(cloudflare.CloudflareError, "stale"):
            self.control.verify_drained(paused, current)

    def test_guard_pin_and_dropped_write_fail_closed(self):
        with self.assertRaisesRegex(cloudflare.CloudflareError, "release checkpoint"):
            self.control.reserve(None, 100, lambda: False)
        self.assertEqual(self.api.writes, 0)
        self.api.fault = "drop"
        with self.assertRaisesRegex(cloudflare.CloudflareError, "could not be confirmed") as error:
            self.control.reserve(None, 100, current)
        self.assertTrue(error.exception.uncertain)
        self.assertIsNone(self.control.observe().gate)

        def invalidate_pin():
            with self.api.db:
                self.api.db.execute("UPDATE subs_bot_schema_migrations SET sha256=? WHERE position=43", ("0" * 64,))

        self.api.before_write = invalidate_pin
        with self.assertRaisesRegex(cloudflare.CloudflareError, "transition could not be confirmed"):
            self.control.reserve(None, 100, current)
        self.assertEqual(self.api.db.execute("SELECT count(*) FROM telegram_page_jump_controls").fetchone()[0], 0)
