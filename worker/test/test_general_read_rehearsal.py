"""Synthetic SQLite and immutable Worker tests for protected private read rehearsal."""

from dataclasses import asdict, dataclass, replace
from hashlib import sha256
import json
import sqlite3
from unittest import TestCase
from unittest.mock import patch

from test_page_jump_control import BOT, PATH, TARGET, WORKER, MemoryD1

import cloudflare_isolation as cloudflare
from d1_migrations import _statements
import general_read_rehearsal as rehearsal


ADMIN, MEMBER = "456", "789"
CONFIG = json.dumps({"botId": BOT, "adminId": ADMIN, "memberId": MEMBER})
REVISION, MODULE = "a" * 40, "b" * 64
DEPLOYMENT = cloudflare._Deployment("00000000-0000-4000-8000-000000000001",
                                   "00000000-0000-4000-8000-000000000002", None)
ARTIFACT = (REVISION, MODULE, "2026-07-30")


class Data(MemoryD1):
    def __init__(self):
        super().__init__()
        for name in ("0044_telegram_general_runtime.sql", "0046_telegram_general_receipts.sql",
                     "0047_telegram_general_groups.sql", rehearsal.MIGRATION):
            self.db.executescript((WORKER / "migrations" / name).read_text(encoding="utf-8"))
        self.db.execute("INSERT INTO subs_bot_schema_migrations VALUES (49,?,?,'applied')",
                        (rehearsal.MIGRATION, rehearsal.MIGRATION_SHA256))
        self.db.commit()

    def __call__(self, method, path, payload):
        assert method == "POST" and path == PATH and set(payload) == {"sql"}
        sql = payload["sql"]
        if not sql.startswith("SELECT CASE WHEN"):
            return super().__call__(method, path, payload)
        self.writes += 1
        fault, self.fault = self.fault, None
        if fault == "drop":
            raise cloudflare.CloudflareError("synthetic timeout", uncertain=True)
        if self.before_write:
            self.before_write()
        try:
            with self.db:
                self.db.execute("BEGIN")
                result = [{"success": True, "results": [dict(row) for row in self.db.execute(part).fetchall()]}
                          for part in _statements(sql)]
        except sqlite3.Error:
            raise cloudflare.CloudflareError("synthetic D1 rollback") from None
        if fault == "lost":
            raise cloudflare.CloudflareError("synthetic timeout", uncertain=True)
        return result


class Scope(cloudflare._Isolation):
    def __init__(self, data):
        super().__init__(None, data, TARGET)
        self.capable = True
        self.version_pin = cloudflare._Version(*ARTIFACT, None, sha256(CONFIG.encode()).hexdigest())
        self.deployment = DEPLOYMENT

    def worker_config(self):
        return ("private scope",)

    def verify_resources(self):
        pass

    def cron_enabled(self):
        return True

    def active(self):
        return self.deployment

    def version(self, version_id, *, with_general_read_lane):
        assert version_id == self.deployment.version and with_general_read_lane is True
        return self.version_pin, self.capable


class GeneralReadRehearsalTests(TestCase):
    def setUp(self):
        self.api = Data()
        self.addCleanup(self.api.db.close)
        self.scope = Scope(self.api)
        self.guard = lambda: True
        self.health = patch.object(rehearsal, "_verify_health")
        self.health.start()
        self.addCleanup(self.health.stop)

    def action(self, mode="inspect", before=None, *, artifact=ARTIFACT):
        return rehearsal.run(self.scope, CONFIG, self.guard, action=mode, artifact=artifact,
                             expected_active=before["activeSha256"] if before else "",
                             expected_state=before["stateSha256"] if before else "")

    def test_verified_transition_chain_preserves_the_role_fence_until_restored(self):
        baseline = self.action()
        rehearsal.require_general_read_lane_clear(self.scope, required=True)
        with self.api.db:
            self.api.db.execute("INSERT INTO telegram_auth VALUES (?,?,1,31,41)", (BOT, MEMBER))
        with self.assertRaises(cloudflare.CloudflareError):
            self.action("close", baseline)
        self.assertEqual(self.api.writes, 0)
        baseline = self.action()
        self.api.fault = "lost"
        closed = self.action("close", baseline)
        self.assertEqual((closed["mode"], closed["epoch"], closed["generation"]), ("closed", 1, None))
        self.assertEqual(self.api.writes, 1, "a committed timeout reconciles without another CAS")
        with self.assertRaisesRegex(cloudflare.CloudflareError, "Close and drain"):
            rehearsal.require_general_read_lane_clear(self.scope)
        self.api.fault = "drop"
        with self.assertRaises(cloudflare.CloudflareError):
            self.action("open", closed)
        self.assertEqual(self.action()["epoch"], 1)
        opened = self.action("open", self.action())
        self.assertEqual((opened["mode"], opened["epoch"], opened["generation"]), ("general", 2, 1))
        self.assertEqual(tuple(self.api.db.execute(f"SELECT member_date,member_message FROM {rehearsal.TABLE}").fetchone()),
                         (31, 41))
        self.assertEqual([tuple(row) for row in self.api.db.execute(
            "SELECT actor_id,role,effective_at FROM telegram_general_actors ORDER BY actor_id")],
            [(ADMIN, "admin", opened["cutoverAt"]), (MEMBER, "member", opened["cutoverAt"])])
        with self.api.db:
            self.api.db.execute("INSERT INTO telegram_inbox VALUES (1,?,1,?,?,'private',1,1,NULL,'help',1,'general-read:v1')",
                                (BOT, MEMBER, MEMBER))
            self.api.db.execute("INSERT INTO telegram_general_receipt VALUES (1,1,1,'member',?, ?, ?)",
                                (REVISION, self.api.db.execute("SELECT activation_sha256 FROM telegram_general_policy").fetchone()[0],
                                 opened["cutoverAt"]))
            self.api.db.execute("INSERT INTO telegram_outbox(receipt_id) VALUES (1)")
        closing = self.action("close", self.action("inspect", opened, artifact=None), artifact=None)
        self.assertEqual((closing["mode"], closing["generation"], closing["generalPending"]), ("closed", 1, 1))
        with self.assertRaises(cloudflare.CloudflareError):
            self.action("restore", closing, artifact=None)
        with self.api.db:
            self.api.db.execute("UPDATE telegram_outbox SET state='failed' WHERE receipt_id=1")
        restored = self.action("restore", self.action("inspect", closing, artifact=None), artifact=None)
        self.assertEqual((restored["mode"], restored["epoch"], restored["generation"]), ("isolated", 4, None))
        rehearsal.require_general_read_lane_clear(self.scope)
        self.assertEqual(self.api.db.execute("SELECT active FROM telegram_general_policy").fetchone()[0], 0)
        self.assertEqual(self.api.db.execute("SELECT count(*) FROM telegram_general_actors").fetchone()[0], 2)
        self.assertEqual(self.api.db.execute("SELECT count(*) FROM telegram_general_receipt").fetchone()[0], 1)

    def test_atomic_open_refuses_scope_change_between_observation_and_d1(self):
        closed = self.action("close", self.action())
        def revoke():
            with self.api.db:
                self.api.db.execute("INSERT INTO telegram_auth VALUES (?,?,0,31,41)", (BOT, MEMBER))
        self.api.before_write = revoke
        with self.assertRaises(cloudflare.CloudflareError):
            self.action("open", closed)
        self.assertEqual(self.action()["mode"], "closed")
        self.assertEqual(self.api.db.execute("SELECT count(*) FROM telegram_general_policy").fetchone()[0], 0)

    def test_recovery_keeps_exact_active_pin_across_version_reader_changes(self):
        closed = self.action("close", self.action())
        opened = self.action("open", closed)

        @dataclass(frozen=True)
        class FutureVersion(cloudflare._Version):
            future_feature_flag: bool = True

        self.scope.version_pin = FutureVersion(**asdict(self.scope.version_pin))
        self.scope.version_pin = replace(self.scope.version_pin, digest="c" * 64)
        with self.assertRaises(cloudflare.CloudflareError):
            self.action("inspect", opened, artifact=None)
        self.scope.version_pin = replace(self.scope.version_pin, digest=MODULE)
        current = self.action("inspect", opened, artifact=None)
        self.assertEqual(current["activeSha256"], opened["activeSha256"])
        closed = self.action("close", current, artifact=None)
        self.assertEqual(closed["activeSha256"], opened["activeSha256"])
        restored = self.action("restore", closed, artifact=None)
        self.assertEqual(restored["mode"], "isolated")

    def test_manifest_requires_exact_position_and_compiled_capability(self):
        prior = [{}] * 48
        exact = {"name": rehearsal.MIGRATION, "sha256": rehearsal.MIGRATION_SHA256}
        self.assertFalse(rehearsal.general_read_artifact(b"", {"migrations": prior}))
        self.assertTrue(rehearsal.general_read_artifact(rehearsal.MARKER, {"migrations": [*prior, exact]}))
        for body, migrations in ((b"", [*prior, exact]), (rehearsal.MARKER, prior),
                                 (rehearsal.MARKER, [*prior, {**exact, "sha256": "e" * 64}])):
            with self.assertRaisesRegex(cloudflare.CloudflareError, "verified Worker artifact"):
                rehearsal.general_read_artifact(body, {"migrations": migrations})

    def test_wrong_build_ledger_and_partial_absence_are_closed(self):
        self.scope.capable = False
        with self.assertRaises(cloudflare.CloudflareError):
            self.action()
        self.scope.capable = True
        with self.assertRaises(cloudflare.CloudflareError):
            self.action(artifact=("d" * 40, MODULE, ARTIFACT[2]))
        with self.api.db:
            self.api.db.execute(f"DROP TABLE {rehearsal.TABLE}")
        with self.assertRaises(cloudflare.CloudflareError):
            rehearsal.require_general_read_lane_clear(self.scope)
        self.assertEqual(self.api.writes, 0)
