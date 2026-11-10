"""Exercise legacy shutdown with local doubles for Telegram, HTTP and SQLite."""
from __future__ import annotations

import asyncio
import os
import signal
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
with tempfile.TemporaryDirectory(prefix="subs-drain-config-") as config_dir:
    with patch.dict(os.environ, {"BOT_TOKEN": "0:TEST", "DATA_DIR": config_dir}, clear=True):
        import bot


class GracefulDrainTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.steps = []
        self.updater = SimpleNamespace(
            start_polling=AsyncMock(), stop=self.cleanup_step("polling"),
        )
        self.app = SimpleNamespace(
            updater=self.updater, bot=SimpleNamespace(get_me=AsyncMock(return_value=None)),
            initialize=AsyncMock(), start=AsyncMock(), stop=self.cleanup_step("application"),
            shutdown=self.cleanup_step("telegram"),
        )
        self.start_http = AsyncMock(return_value=SimpleNamespace(cleanup=self.cleanup_step("http")))
        self.store = SimpleNamespace(init=AsyncMock(), close=self.cleanup_step("sqlite"))
        patches = patch.multiple(
            bot, build_app=Mock(return_value=self.app), store=self.store,
            start_http=self.start_http, close_session=self.cleanup_step("provider-session"),
        )
        patches.start()
        self.addCleanup(patches.stop)

    def cleanup_step(self, name):
        async def cleanup():
            self.steps.append(name)

        return AsyncMock(side_effect=cleanup)

    async def test_sigterm_waits_for_application_drain_before_closing_resources(self):
        polling, draining, release = asyncio.Event(), asyncio.Event(), asyncio.Event()

        async def start_polling(**_):
            polling.set()

        async def stop_application():
            draining.set()
            await release.wait()
            self.steps.append("application")

        self.updater.start_polling.side_effect = start_polling
        self.app.stop.side_effect = stop_application
        loop = asyncio.get_running_loop()
        with patch.object(loop, "add_signal_handler") as install, \
                patch.object(loop, "remove_signal_handler") as remove, \
                self.assertLogs(bot.log, level="INFO") as logs:
            task = asyncio.create_task(bot.run())
            try:
                await asyncio.wait_for(polling.wait(), 2)
                self.assertEqual(install.call_args.args[0], signal.SIGTERM)
                install.call_args.args[1]()
                await asyncio.wait_for(draining.wait(), 2)
                self.assertEqual(self.steps, ["polling"])
                self.assertFalse(task.done())
                self.assertFalse(any("outcome=complete" in entry for entry in logs.output))
            finally:
                release.set()
                await asyncio.wait_for(task, 2)
        remove.assert_called_once_with(signal.SIGTERM)
        self.assertEqual(self.steps, ["polling", "application", "telegram", "http", "sqlite", "provider-session"])
        self.assertEqual(logs.output.count("INFO:subs-bot:legacy-drain:v1 outcome=complete"), 1)

    async def test_failed_stage_keeps_cleanup_running_and_proof_incomplete(self):
        stop = asyncio.Event()

        async def start_polling(**_):
            stop.set()

        self.updater.start_polling.side_effect = start_polling
        self.updater.stop.side_effect = RuntimeError("private exception fixture")
        with self.assertLogs(bot.log, level="INFO") as logs:
            await bot.amain(stop)
        self.assertEqual(self.steps, ["application", "telegram", "http", "sqlite", "provider-session"])
        self.assertIn("WARNING:subs-bot:legacy-drain:v1 outcome=incomplete stages=polling", logs.output)
        self.assertFalse(any("outcome=complete" in entry or "private exception fixture" in entry for entry in logs.output))

    async def test_stop_during_startup_skips_polling_and_emits_no_completion(self):
        stop = asyncio.Event()

        async def initialize():
            stop.set()

        self.app.initialize.side_effect = initialize
        with self.assertLogs(bot.log, level="INFO") as logs:
            await bot.amain(stop)
        self.updater.start_polling.assert_not_awaited()
        self.assertIn("WARNING:subs-bot:legacy-drain:v1 outcome=incomplete stages=startup", logs.output)
        self.assertFalse(any("outcome=complete" in entry for entry in logs.output))


if __name__ == "__main__":
    unittest.main()
