"""Hysteria 2 import feedback through Telegram handlers, with only synthetic credentials."""
from __future__ import annotations

import base64
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import AsyncMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
with tempfile.TemporaryDirectory(prefix="subs-hysteria2-config-") as config_dir:
    with patch.dict(os.environ, {
        "BOT_TOKEN": "0:TEST",
        "DATA_DIR": config_dir,
        "DB_PATH": str(Path(config_dir) / "test.db"),
    }):
        import bot
        from db import Store, nodes_of


OWNER = 42
REJECTED_AUTH = "fixture-hidden-auth"
INNER_URL = "https://embedded.example.invalid/do-not-fetch"
BAD = f"hy2://{REJECTED_AUTH}@invalid.example.invalid:70000/?unsupported={INNER_URL}#Rejected"
GOOD_HY2 = "hy2://fixture-valid-auth@valid.example.invalid#Accepted"
GOOD_VLESS = "vless://11111111-1111-1111-1111-111111111111@vless.example.invalid:443#Kept"
SOURCE = "https://provider.example.invalid/subscription"


class Hysteria2BotImportTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        temp = tempfile.TemporaryDirectory(prefix="subs-hysteria2-tests-")
        self.addCleanup(temp.cleanup)
        self.store = Store(str(Path(temp.name) / "test.db"))
        patches = patch.multiple(bot, store=self.store, deny=AsyncMock(return_value=False))
        patches.start()
        self.addCleanup(patches.stop)
        self.addAsyncCleanup(self.store.close)

    def update(self, *, text="", document=None):
        status = NS(edit_text=AsyncMock())
        message = NS(text=text, document=document, reply_text=AsyncMock(return_value=status), reply_html=AsyncMock())
        update = NS(effective_user=NS(id=OWNER), effective_chat=NS(id=OWNER, type="private"),
                    effective_message=message, callback_query=None)
        return update, status

    def assert_rejection(self, text):
        self.assertIn("跳过 1 条", text)
        self.assertIn("Hysteria 2", text)
        self.assertNotIn(REJECTED_AUTH, text)
        self.assertNotIn(INNER_URL, text)
        self.assertNotIn("invalid.example.invalid", text)

    async def upload(self, text, name="mixed.txt"):
        raw = text.encode("utf-8")
        update, status = self.update(document=NS(file_name=name, file_size=len(raw), file_id="test-document"))
        file = NS(download_as_bytearray=AsyncMock(return_value=bytearray(raw)))
        await bot.handle_document(update, NS(bot=NS(get_file=AsyncMock(return_value=file))))
        status.edit_text.assert_awaited_once()
        return status.edit_text.await_args.args[0]

    async def test_temporary_input_rejects_bad_hysteria2_and_keeps_neighbors(self):
        update, _ = self.update(text=f"{GOOD_HY2}\n{BAD}\n{GOOD_VLESS}")
        with patch.object(bot, "fetch_subscription", AsyncMock()) as fetch:
            await bot.handle_text(update, NS(user_data={}))
            fetch.assert_not_awaited()
        rows = await self.store.list_temp(OWNER)
        self.assertEqual([row["url"] for row in rows], [GOOD_HY2, GOOD_VLESS])
        reply = update.effective_message.reply_text.await_args.args[0]
        self.assertIn("已加入临时列表 2 条", reply)
        self.assert_rejection(reply)

    async def test_malformed_node_cannot_trigger_named_url_import(self):
        update, _ = self.update(text=f"{BAD}|{SOURCE}")
        with patch.object(bot, "fetch_subscription", AsyncMock()) as fetch:
            await bot.handle_text(update, NS(user_data={}))
            fetch.assert_not_awaited()
        self.assertEqual(await self.store.list_subs(OWNER), [])
        self.assertEqual(await self.store.list_temp(OWNER), [])
        reply = update.effective_message.reply_text.await_args.args[0]
        self.assertNotIn("已加入临时列表", reply)
        self.assert_rejection(reply)

    async def test_upload_keeps_neighbors_but_does_not_fetch_inside_rejected_uri(self):
        remote_nodes = [bot.parse_share_link(GOOD_VLESS)]
        with patch.object(bot, "fetch_subscription", AsyncMock(return_value=(remote_nodes, {}, None))) as fetch:
            reply = await self.upload(f"{BAD}\n{GOOD_VLESS}\n{SOURCE}")
            fetch.assert_awaited_once_with(SOURCE)
            self.assert_rejection(reply)

            wrapped = base64.b64encode(f"{BAD}\n{GOOD_HY2}".encode()).decode()
            self.assert_rejection(await self.upload(wrapped, name="wrapped.txt"))
            fetch.assert_awaited_once_with(SOURCE)

        rows = {row["name"]: row for row in await self.store.list_subs(OWNER)}
        self.assertEqual([node["share"] for node in nodes_of(rows["mixed"])], [GOOD_VLESS])
        self.assertEqual([node["share"] for node in nodes_of(rows["wrapped"])], [GOOD_HY2])

    async def test_refresh_warning_is_ephemeral_and_all_bad_keeps_last_good_nodes(self):
        sub = await self.store.add_sub(OWNER, "Synthetic", SOURCE)
        update, _ = self.update()
        callback = NS(data=f"sub:refresh:{sub['id']}:0", answer=AsyncMock(), edit_message_text=AsyncMock())
        update.callback_query = callback
        nodes = [bot.parse_share_link(GOOD_VLESS)]
        with patch.object(bot, "fetch_subscription", AsyncMock(return_value=(nodes, {"rejected_hysteria2": 1}, None))):
            await bot.on_callback(update, NS())
        self.assert_rejection(callback.edit_message_text.await_args.args[0])
        stored = await self.store.get_sub(OWNER, sub["id"])
        self.assertEqual(nodes_of(stored), nodes)
        self.assertIsNone(stored["last_error"])
        self.assertNotIn("rejected_hysteria2", stored)

        update, _ = self.update(text=f"Synthetic|{SOURCE}")
        parse_error = "订阅中没有可导入的 Hysteria 2 节点。"
        with patch.object(bot, "fetch_subscription", AsyncMock(return_value=([], {"rejected_hysteria2": 1}, parse_error))):
            await bot.handle_text(update, NS(user_data={}))
        reply = update.effective_message.reply_text.await_args.args[0]
        self.assertIn("未更新", reply)
        self.assert_rejection(reply)
        stored = await self.store.get_sub(OWNER, sub["id"])
        self.assertEqual(nodes_of(stored), nodes)
        self.assertEqual(stored["last_error"], parse_error)


if __name__ == "__main__":
    unittest.main()
