"""Hosted-only synthetic evidence for polling acknowledgements and dispatch boundaries."""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

from telegram import Chat, Message, Update
from telegram.ext import Application, ExtBot, TypeHandler

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from legacy_handoff import HandoffApplication, HandoffBot, HandoffError, HandoffLedger, ledger_from_environment

with tempfile.TemporaryDirectory(prefix="legacy-handoff-config-") as config_dir:
    with patch.dict(os.environ, {"BOT_TOKEN": "123456:TEST", "DATA_DIR": config_dir}, clear=True):
        import bot as legacy_bot


REVISION = "b" * 40
BOT_ID = 123456
PRIVATE = "private-body-and-credential-fixture-must-never-enter-ledger"


def update(update_id):
    return Update(update_id, message=Message(1, datetime.now(timezone.utc), Chat(123, "private"), text=PRIVATE))


class LedgerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="legacy-handoff-test-")
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "handoff.db"
        self.ledger = HandoffLedger(self.path, BOT_ID, REVISION)
        self.addCleanup(self.ledger.close)

    def returned(self, offset, ids):
        poll = self.ledger.begin_poll(offset)
        self.ledger.poll_returned(poll, [update(item) for item in ids])

    def test_offset_ack_is_separate_from_handler_completion_and_sparse_ids(self):
        self.returned(0, [101, 103])
        self.ledger.processing_started(update(101))
        self.ledger.processing_finished(update(101))
        self.returned(104, [])
        summary = self.ledger.summary()
        self.assertEqual(summary["confirmedOffset"], 104)
        self.assertEqual(summary["handlerReturned"], 1)
        self.assertEqual(summary["fetchedNotStarted"], 1)
        self.assertEqual(summary["fetchedNotStartedConfirmed"], 1)
        self.assertFalse(summary["businessSuccessProven"])
        self.assertFalse(summary["replayAvailable"])
        # No synthetic row for the unobserved gap 102, and no raw message/credentials.
        self.assertEqual(self.ledger.db.execute("SELECT update_id FROM updates ORDER BY update_id").fetchall(), [(101,), (103,)])
        self.assertNotIn(PRIVATE.encode(), self.path.read_bytes())

    def test_timeout_and_shutdown_cleanup_responses_remain_distinguishable(self):
        self.returned(0, [10])
        poll = self.ledger.begin_poll(11)
        self.ledger.poll_unknown(poll)
        self.assertIsNone(self.ledger.summary()["confirmedOffset"])
        self.assertEqual(self.ledger.summary()["unconfirmedAckPolls"], 1)
        # PTB's final cleanup can return newer updates without dispatching them.
        self.returned(11, [12])
        summary = self.ledger.summary()
        self.assertEqual(summary["unknownPollOutcomes"], 1)
        self.assertEqual(summary["unconfirmedAckPolls"], 0)
        self.assertEqual(summary["fetchedNotStarted"], 2)
        self.assertEqual(summary["fetchedNotStartedConfirmed"], 1)

    def test_errors_aborts_and_duplicate_dispatches_are_never_erased_by_later_return(self):
        self.returned(0, [1])
        self.ledger.processing_started(update(1))
        self.ledger.handler_error(update(1))
        self.ledger.processing_finished(update(1))
        self.ledger.processing_started(update(1))
        self.ledger.processing_finished(update(1), aborted=True)
        self.ledger.processing_started(update(1))
        self.ledger.processing_finished(update(1))
        summary = self.ledger.summary()
        self.assertEqual(summary["handlerErrorUpdates"], 1)
        self.assertEqual(summary["aborted"], 1)
        self.assertEqual(summary["duplicateDispatches"], 2)
        self.assertEqual(summary["handlerReturned"], 1)

    def test_full_commits_private_file_and_unclosed_run_survive_reopen(self):
        self.assertEqual(self.ledger.db.execute("PRAGMA synchronous").fetchone(), (2,))
        self.assertEqual(self.ledger.db.execute("PRAGMA journal_mode").fetchone(), ("delete",))
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        self.returned(0, [11])
        self.ledger.processing_started(update(11))
        old_run = self.ledger.run_id
        self.ledger.close()  # Simulate process loss without a finished lifecycle record.
        self.ledger = HandoffLedger(self.path, BOT_ID, REVISION)
        self.addCleanup(self.ledger.close)
        self.assertEqual(self.ledger.summary()["priorUnclosedRuns"], 1)
        self.assertEqual(self.ledger.db.execute("SELECT state FROM updates WHERE run_id=?", (old_run,)).fetchone(), ("started",))

    def test_process_lock_and_existing_foreign_database_are_rejected(self):
        with self.assertRaises(HandoffError):
            HandoffLedger(self.path, BOT_ID, REVISION)
        other = Path(self.directory.name) / "business.db"
        with sqlite3.connect(other) as db:
            db.execute("CREATE TABLE original(value TEXT)")
        other.chmod(0o600)
        before = other.read_bytes()
        with self.assertRaises(HandoffError):
            HandoffLedger(other, BOT_ID, REVISION)
        self.assertEqual(other.read_bytes(), before)
        linked = Path(self.directory.name) / "linked.db"
        linked.symlink_to(self.path)
        with self.assertRaises(HandoffError):
            HandoffLedger(linked, BOT_ID, REVISION)

    def test_finished_summary_keeps_private_offset_out_of_safe_log_projection(self):
        self.returned(150, [])
        safe = self.ledger.finish(polling_started=True, failures=[])
        self.assertTrue(safe["lifecycleComplete"])
        self.assertNotIn("confirmedOffset", safe)
        private = json.loads(self.ledger.db.execute("SELECT summary_json FROM runs").fetchone()[0])
        self.assertEqual(private["confirmedOffset"], 150)
        self.assertEqual(private["scope"], "observed-run-only")

    def test_disabled_configuration_and_explicit_preserve_boundary(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(ledger_from_environment("123456:TEST", "unused"))
        for setting in (None, "0", "true"):
            env = {"TELEGRAM_HANDOFF_LEDGER_PATH": str(self.path)}
            if setting is not None:
                env["TELEGRAM_PRESERVE_PENDING_UPDATES"] = setting
            with patch.dict(os.environ, env, clear=True), self.assertRaises(HandoffError):
                ledger_from_environment("123456:TEST", "unused")


class AdapterTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="legacy-handoff-adapter-")
        self.addCleanup(self.directory.cleanup)
        self.ledger = HandoffLedger(Path(self.directory.name) / "ledger.db", BOT_ID, REVISION)
        self.addCleanup(self.ledger.close)
        self.bot = HandoffBot("123456:TEST", handoff=self.ledger)

    async def test_poll_records_before_return_and_does_not_claim_timeout_ack(self):
        value = update(55)
        with patch.object(ExtBot, "get_updates", new=AsyncMock(return_value=(value,))):
            self.assertEqual(await self.bot.get_updates(offset=0), (value,))
        self.assertEqual(self.ledger.summary()["fetchedNotStarted"], 1)
        with patch.object(ExtBot, "get_updates", new=AsyncMock(side_effect=TimeoutError(PRIVATE))):
            with self.assertRaises(TimeoutError):
                await self.bot.get_updates(offset=56)
        self.assertIsNone(self.ledger.summary()["confirmedOffset"])
        self.assertEqual(self.ledger.summary()["unconfirmedAckPolls"], 1)

    async def test_negative_offset_stops_observer_before_network(self):
        self.ledger.stop_event = asyncio.Event()
        with patch.object(ExtBot, "get_updates", new=AsyncMock()) as network:
            with self.assertRaises(HandoffError):
                await self.bot.get_updates(offset=-1)
            network.assert_not_awaited()
        self.assertTrue(self.ledger.stop_event.is_set())

    async def test_persistence_failure_stops_before_network_and_uses_safe_error(self):
        self.ledger.stop_event = asyncio.Event()
        self.ledger.db.close()
        with patch.object(ExtBot, "get_updates", new=AsyncMock()) as network:
            with self.assertRaises(HandoffError) as caught:
                await self.bot.get_updates(offset=0)
            network.assert_not_awaited()
        self.assertTrue(self.ledger.stop_event.is_set())
        self.assertNotIn(self.directory.name, str(caught.exception))

    async def test_opt_in_legacy_builder_preserves_preview_defaults_and_uses_sidecar(self):
        ledger_path = Path(self.directory.name) / "builder.db"
        env = {"TELEGRAM_HANDOFF_LEDGER_PATH": str(ledger_path),
               "TELEGRAM_HANDOFF_REVISION": REVISION, "TELEGRAM_PRESERVE_PENDING_UPDATES": "1"}
        with patch.dict(os.environ, env, clear=True), patch.object(legacy_bot, "BOT_TOKEN", "123456:TEST"):
            app = legacy_bot.build_app()
        self.addCleanup(app.handoff.close)
        self.assertIsInstance(app, HandoffApplication)
        self.assertIsInstance(app.bot, HandoffBot)
        self.assertTrue(app.bot.defaults.link_preview_options.is_disabled)
        self.assertTrue(app.handlers)

    async def test_framework_caught_handler_error_is_recorded_without_false_return_success(self):
        app = (Application.builder().bot(self.bot)
               .application_class(HandoffApplication, kwargs={"handoff": self.ledger}).build())
        app._initialized = True

        async def handler(_update, _context):
            raise RuntimeError(PRIVATE)

        async def consume_error(_update, _context):
            pass

        app.add_handler(TypeHandler(Update, handler))
        app.add_error_handler(consume_error)
        value = update(61)
        poll = self.ledger.begin_poll(0)
        self.ledger.poll_returned(poll, [value])
        await app.process_update(value)
        self.assertEqual(self.ledger.summary()["handlerErrorUpdates"], 1)
        self.assertEqual(self.ledger.summary()["handlerReturned"], 0)
        self.assertEqual(self.ledger.db.execute("SELECT state FROM updates").fetchone(), ("handler-error",))
        self.assertNotIn(PRIVATE.encode(), (Path(self.directory.name) / "ledger.db").read_bytes())

    async def test_success_and_cancellation_are_separate_and_async_handlers_are_rejected(self):
        app = (Application.builder().bot(self.bot)
               .application_class(HandoffApplication, kwargs={"handoff": self.ledger}).build())
        app._initialized = True
        callback = AsyncMock()
        app.add_handler(TypeHandler(Update, callback))
        with self.assertRaises(HandoffError):
            app.add_handler(TypeHandler(Update, callback, block=False))
        for value in (update(70), update(71)):
            poll = self.ledger.begin_poll(0)
            self.ledger.poll_returned(poll, [value])
        await app.process_update(update(70))
        callback.side_effect = asyncio.CancelledError
        with self.assertRaises(asyncio.CancelledError):
            await app.process_update(update(71))
        self.assertEqual(self.ledger.summary()["handlerReturned"], 1)
        self.assertEqual(self.ledger.summary()["aborted"], 1)


if __name__ == "__main__":
    unittest.main()
