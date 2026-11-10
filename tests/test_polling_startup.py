"""Legacy polling startup uses only synthetic configuration and an updater double."""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
with tempfile.TemporaryDirectory(prefix="subs-polling-startup-") as config_dir:
    with patch.dict(os.environ, {
        "BOT_TOKEN": "0:TEST",
        "DATA_DIR": config_dir,
        "DB_PATH": str(Path(config_dir) / "test.db"),
    }, clear=True):
        import bot


ENV = "TELEGRAM_PRESERVE_PENDING_UPDATES"


class PollingStartupTests(unittest.IsolatedAsyncioTestCase):
    async def test_startup_passes_explicit_drop_setting(self):
        class PollingStarted(Exception):
            pass

        for value, drop in ((None, True), ("0", True), ("1", False)):
            with self.subTest(value=value):
                updater = SimpleNamespace(start_polling=AsyncMock(side_effect=PollingStarted), stop=AsyncMock())
                app = SimpleNamespace(
                    updater=updater, bot=SimpleNamespace(get_me=AsyncMock(return_value=None)),
                    initialize=AsyncMock(), start=AsyncMock(), stop=AsyncMock(), shutdown=AsyncMock(),
                )
                runner = SimpleNamespace(cleanup=AsyncMock())
                store = SimpleNamespace(init=AsyncMock(), close=AsyncMock())
                env = {} if value is None else {ENV: value}
                with patch.dict(os.environ, env, clear=True), patch.multiple(
                    bot, build_app=Mock(return_value=app), store=store,
                    start_http=AsyncMock(return_value=runner), close_session=AsyncMock(),
                ), self.assertRaises(PollingStarted):
                    await bot.amain()
                updater.start_polling.assert_awaited_once_with(
                    drop_pending_updates=drop, allowed_updates=bot.Update.ALL_TYPES,
                )

    async def test_invalid_setting_stops_before_application_startup(self):
        for value in ("", " ", "true", "01", "invalid-private-fixture"):
            with self.subTest(value=value), patch.dict(os.environ, {ENV: value}, clear=True), \
                 patch.object(bot, "build_app") as build_app:
                with self.assertRaises(SystemExit) as caught:
                    await bot.amain()
                self.assertEqual(str(caught.exception), "TELEGRAM_PRESERVE_PENDING_UPDATES 只接受 0 或 1。")
                build_app.assert_not_called()


if __name__ == "__main__":
    unittest.main()
