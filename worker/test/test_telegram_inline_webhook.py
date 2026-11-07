"""Hosted-only doubles for the isolated inline webhook configuration path."""

from collections import deque
from contextlib import nullcontext
from io import BytesIO
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from urllib.error import HTTPError

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import telegram_inline_webhook as webhook


TOKEN = "123456:" + "T" * 36
SECRET = "S" * 36
POLICY = {"botId": "123456", "botUsername": webhook.BOT_USERNAME, "webhookSecret": SECRET}
ME = {"id": 123456, "username": webhook.BOT_USERNAME, "is_bot": True, "supports_inline_queries": True}
BASE = ["message", "callback_query"]
WITH_INLINE = ["message", "inline_query", "callback_query"]
VERSION = SimpleNamespace(revision="a" * 40, telegram_inline_search=False)
DIGEST = "a" * 64


def info(allowed=BASE, **changes):
    return {"url": webhook.WEBHOOK_URL, "has_custom_certificate": False, "max_connections": 4,
            "pending_update_count": 7, "allowed_updates": allowed, "ip_address": "192.0.2.4", **changes}


def telegram_fixture(*observations, bot=ME, write=True):
    remaining = deque(observations)
    calls = []

    def call(method, payload=None):
        calls.append((method, payload))
        if method == "getMe":
            return bot
        result = remaining.popleft() if method == "getWebhookInfo" else write
        if isinstance(result, Exception):
            raise result
        return result

    return call, calls


class OperationTests(unittest.TestCase):
    def operation(self, telegram, *, mode="append", confirmation=webhook.CONFIRM_APPEND, before_write=None):
        return webhook.maintain(telegram, POLICY, mode, confirmation, Mock(return_value=VERSION),
                                before_write if before_write is not None else Mock(), pause=Mock())

    def test_append_one_exact_write_and_confirm_canonical_readback(self):
        telegram, calls = telegram_fixture(info(), info(), info(WITH_INLINE, ip_address="192.0.2.5", pending_update_count=5))
        result = self.operation(telegram)
        self.assertEqual([method for method, _ in calls], ["getMe", "getWebhookInfo", "getWebhookInfo", "setWebhook", "getWebhookInfo"])
        self.assertEqual(calls[3][1], {"url": webhook.WEBHOOK_URL, "secret_token": SECRET, "max_connections": 4,
            "allowed_updates": ["message", "callback_query", "inline_query"], "drop_pending_updates": False})
        self.assertTrue(result["supportsInlineQueries"])
        self.assertTrue(result["inlineQuerySubscribed"])
        self.assertTrue(result["writeAcknowledged"])
        self.assertEqual(result["allowedUpdates"], WITH_INLINE)
        self.assertEqual(result["allowedUpdateCount"], 3)
        self.assertFalse(result["workerInlineSearchEnabled"])
        self.assertNotIn(SECRET, json.dumps(result))
        self.assertNotIn("192.0.2.", json.dumps(result))

    def test_inspection_and_already_subscribed_only_read(self):
        for mode, confirmation, updates in (("inspect", "", BASE), ("append", webhook.CONFIRM_APPEND, WITH_INLINE)):
            with self.subTest(mode=mode):
                telegram, calls = telegram_fixture(info(updates))
                before_write = Mock()
                result = self.operation(telegram, mode=mode, confirmation=confirmation, before_write=before_write)
                self.assertEqual([method for method, _ in calls], ["getMe", "getWebhookInfo"])
                self.assertFalse(result["writeAttempted"])
                self.assertEqual(result["inlineQuerySubscribed"], "inline_query" in updates)
                before_write.assert_not_called()

    def test_ambiguous_write_is_reconciled_with_reads_only(self):
        failure = webhook.TelegramRequestError("Synthetic unavailable response")
        telegram, calls = telegram_fixture(info(), info(), failure, info(), info(WITH_INLINE), write=failure)
        result = self.operation(telegram)
        self.assertTrue(result["inlineQuerySubscribed"])
        self.assertFalse(result["writeAcknowledged"])
        self.assertEqual(sum(method == "setWebhook" for method, _ in calls), 1)

    def test_missing_provenance_and_stale_baseline_fail_before_write(self):
        telegram, calls = telegram_fixture(info(), info())
        missing = Mock(side_effect=webhook.InlineWebhookError("Historical configuration was unavailable."))
        with self.assertRaisesRegex(webhook.InlineWebhookError, "Historical configuration"):
            self.operation(telegram, before_write=missing)
        self.assertNotIn("setWebhook", [method for method, _ in calls])

        telegram, calls = telegram_fixture(info(), info(list(reversed(BASE))))
        with self.assertRaisesRegex(webhook.InlineWebhookError, "changed before append"):
            self.operation(telegram)
        self.assertNotIn("setWebhook", [method for method, _ in calls])

    def test_fails_closed_for_wrong_bot_url_settings_updates_and_confirmation(self):
        for bot, observation, confirmation in (
            ({**ME, "username": "different_bot"}, info(), webhook.CONFIRM_APPEND),
            ({**ME, "supports_inline_queries": False}, info(), webhook.CONFIRM_APPEND),
            (ME, info(url="https://foreign.example.invalid/"), webhook.CONFIRM_APPEND),
            (ME, info(has_custom_certificate=True), webhook.CONFIRM_APPEND),
            (ME, info(max_connections=5), webhook.CONFIRM_APPEND),
            (ME, info(pending_update_count=True), webhook.CONFIRM_APPEND),
            (ME, info(["message", "callback_query", "chosen_inline_result"]), webhook.CONFIRM_APPEND),
            (ME, info(["message", "message"]), webhook.CONFIRM_APPEND),
            (ME, info(), "append"),
        ):
            telegram, calls = telegram_fixture(observation, bot=bot)
            with self.assertRaises(webhook.InlineWebhookError):
                self.operation(telegram, confirmation=confirmation)
            self.assertNotIn("setWebhook", [method for method, _ in calls])

    def test_unconfirmed_write_never_retries_or_accepts_other_changes(self):
        telegram, calls = telegram_fixture(info(), info(), *(info() for _ in webhook.READBACK_DELAYS))
        with self.assertRaisesRegex(webhook.InlineWebhookError, "Inspect before any retry"):
            self.operation(telegram)
        self.assertEqual(sum(method == "setWebhook" for method, _ in calls), 1)

        telegram, calls = telegram_fixture(info(), info(), info(["callback_query", "message", "inline_query"]))
        with self.assertRaisesRegex(webhook.InlineWebhookError, "original update ordering"):
            self.operation(telegram)
        self.assertEqual(sum(method == "setWebhook" for method, _ in calls), 1)


class TransportAndTargetTests(unittest.TestCase):
    def test_client_uses_fixed_api_methods_with_redirect_and_proxy_disabled(self):
        class Response(BytesIO):
            status = 200

        with patch.object(webhook, "build_opener") as build:
            client = webhook.TelegramClient(TOKEN)
            handlers = build.call_args.args
            self.assertEqual(handlers[0].proxies, {})
            self.assertIsNone(handlers[1].redirect_request(None, None, 307, "", {}, "https://foreign.example.invalid/"))
            opener = build.return_value
            opener.open.return_value = nullcontext(Response(b'{"ok":true,"result":true}'))
            self.assertIs(client("getMe"), True)
            request = opener.open.call_args.args[0]
            self.assertEqual(request.full_url, f"https://api.telegram.org/bot{TOKEN}/getMe")
            self.assertEqual(request.get_method(), "GET")

            with self.assertRaises(webhook.InlineWebhookError):
                client("getUpdates")
            with self.assertRaises(webhook.InlineWebhookError):
                client("setWebhook", {"url": "https://foreign.example.invalid/"})
            self.assertEqual(opener.open.call_count, 1)

            rejection = HTTPError(request.full_url, 307, TOKEN, {}, BytesIO(SECRET.encode()))
            opener.open.side_effect = rejection
            with self.assertRaises(webhook.TelegramRequestError) as failure:
                client("getWebhookInfo")
            self.assertNotIn(TOKEN, str(failure.exception))
            self.assertNotIn(SECRET, str(failure.exception))
            self.assertEqual(opener.open.call_count, 2)

    def test_owned_release_and_historical_config_require_the_same_secret_digest(self):
        scope = Mock()
        version = SimpleNamespace(revision=VERSION.revision, telegram_config_sha256=DIGEST)
        scope.active.return_value = SimpleNamespace(version="active")
        scope.version.return_value = version
        scope.cron_enabled.return_value = True
        with patch.object(webhook, "_verify_health") as health:
            self.assertEqual(webhook.release_snapshot(scope, POLICY, DIGEST)[2], version)
            scope.verify_resources.assert_called_once_with()
            scope.verify_inline_search.assert_called_once_with(POLICY["botId"])
            health.assert_called_once_with(VERSION.revision)
            with self.assertRaisesRegex(webhook.InlineWebhookError, "configuration or Cron differs"):
                webhook.release_snapshot(scope, POLICY, "b" * 64)
        with self.assertRaisesRegex(webhook.InlineWebhookError, "original isolated DNS webhook"):
            webhook.verify_historical_config(scope, DIGEST)
        scope.version.return_value = SimpleNamespace(revision=webhook.BASELINE_REVISION, telegram_config_sha256=DIGEST)
        webhook.verify_historical_config(scope, DIGEST)
        scope.version.assert_called_with(webhook.BASELINE_VERSION)
        with self.assertRaisesRegex(webhook.InlineWebhookError, "original isolated DNS webhook"):
            webhook.verify_historical_config(scope, "b" * 64)
