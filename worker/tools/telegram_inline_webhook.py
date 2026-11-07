"""Inspect or append inline delivery for the owned isolation Bot webhook."""

from dataclasses import dataclass
from hashlib import sha256
from http.client import HTTPException
import json
import os
import re
import sys
from time import sleep
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener

from cloudflare_isolation import (
    CloudflareClient, CloudflareError, ORIGIN, READBACK_DELAYS, REVISION, _Isolation, _NoRedirect, _verify_health,
)
from prepare_isolation_artifact import ArtifactError, MAIN_REF, REPOSITORY, _parse_object, require_current_main
from release_isolation import telegram_release_config


WORKFLOW = ".github/workflows/worker-isolation-telegram-inline-webhook.yml"
BOT_USERNAME = "test_cfsubs_bot"
BOT_API = "https://api.telegram.org"
WEBHOOK_URL = ORIGIN + "/telegram/webhook"
MAX_CONNECTIONS = 4
BASE_TYPES = frozenset(("message", "callback_query"))
INLINE_TYPE = "inline_query"
INLINE_TYPES = BASE_TYPES | {INLINE_TYPE}
CONFIRM_APPEND = "append inline_query for @test_cfsubs_bot using verified DNS webhook"
MAX_RESPONSE = 16 * 1024
# The reviewed callback setup used DNS, no certificate, and the config from this release.
BASELINE_REVISION = "124d674060b5fcd6a9d8e75738a3d1cc58cae45e"
BASELINE_VERSION = "51f28e37-60de-4c57-9b62-615c91970651"


class InlineWebhookError(RuntimeError):
    """Use fixed messages that omit Telegram credentials and response bodies."""


class TelegramRequestError(InlineWebhookError):
    """An API response could not be confirmed."""


def require(condition, message):
    if not condition:
        raise InlineWebhookError(message)


class TelegramClient:
    def __init__(self, token):
        require(isinstance(token, str) and re.fullmatch(r"[1-9][0-9]{0,15}:[A-Za-z0-9_-]{30,80}", token),
                "The isolated Telegram credential is invalid.")
        self._origin = f"{BOT_API}/bot{token}/"
        self._opener = build_opener(ProxyHandler({}), _NoRedirect())

    def __call__(self, method, payload=None):
        require((method in ("getMe", "getWebhookInfo") and payload is None)
                or (method == "setWebhook" and isinstance(payload, dict)), "Invalid isolated Telegram method.")
        if payload is not None:
            require(set(payload) == {"url", "secret_token", "max_connections", "allowed_updates", "drop_pending_updates"}
                    and payload["url"] == WEBHOOK_URL and payload["drop_pending_updates"] is False
                    and type(payload["max_connections"]) is int and payload["max_connections"] == MAX_CONNECTIONS
                    and isinstance(payload["secret_token"], str) and re.fullmatch(r"[A-Za-z0-9_-]{32,256}", payload["secret_token"])
                    and isinstance(payload["allowed_updates"], list)
                    and tuple(payload["allowed_updates"]) in (
                        ("message", "callback_query", INLINE_TYPE), ("callback_query", "message", INLINE_TYPE)),
                    "Invalid isolated Telegram append payload.")
        error = f"The isolated Telegram {method} request could not be confirmed."
        try:
            headers = {"Accept": "application/json", "Cache-Control": "no-cache"}
            body = None
            if payload is not None:
                headers["Content-Type"] = "application/json"
                body = json.dumps(payload, separators=(",", ":"), allow_nan=False).encode("ascii")
            request = Request(self._origin + method, data=body, headers=headers, method="POST" if body else "GET")
            with self._opener.open(request, timeout=15) as response:
                raw = response.read(MAX_RESPONSE + 1)
                if response.status != 200 or len(raw) > MAX_RESPONSE:
                    raise TelegramRequestError(error)
            envelope = _parse_object(raw, error)
            if envelope.get("ok") is not True or "result" not in envelope:
                raise TelegramRequestError(error)
            return envelope["result"]
        except HTTPError as rejected:
            rejected.close()
            raise TelegramRequestError(error) from None
        except (ArtifactError, HTTPException, OSError, TypeError, ValueError, RecursionError):
            raise TelegramRequestError(error) from None


@dataclass(frozen=True)
class WebhookInfo:
    allowed: tuple[str, ...]
    ip_reported: bool


def checked_webhook(telegram):
    info = telegram("getWebhookInfo")
    require(isinstance(info, dict) and info.get("url") == WEBHOOK_URL
            and info.get("has_custom_certificate") is False
            and type(info.get("max_connections")) is int and info["max_connections"] == MAX_CONNECTIONS
            and type(info.get("pending_update_count")) is int and info["pending_update_count"] >= 0,
            "The exact isolation webhook URL, certificate, connection limit, or queue metadata differs.")
    allowed = info.get("allowed_updates")
    require(isinstance(allowed, list) and len(allowed) in (2, 3) and all(isinstance(kind, str) for kind in allowed)
            and len(set(allowed)) == len(allowed) and frozenset(allowed) in (BASE_TYPES, INLINE_TYPES),
            "The isolation webhook update inventory differs from the verified configuration.")
    # Telegram reports a delivery address here. Historical setWebhook evidence establishes DNS mode.
    return WebhookInfo(tuple(allowed), "ip_address" in info)


def maintain(telegram, policy, mode, confirmation, verify_release, before_write, *, pause=sleep):
    require((mode == "inspect" and confirmation == "") or (mode == "append" and confirmation == CONFIRM_APPEND),
            "The isolation webhook mode or verified DNS confirmation differs.")
    active_version = verify_release()
    me = telegram("getMe")
    require(isinstance(me, dict) and type(me.get("id")) is int and str(me["id"]) == policy["botId"]
            and me.get("username") == BOT_USERNAME and policy["botUsername"] == BOT_USERNAME and me.get("is_bot") is True,
            "Telegram did not confirm the exact isolated Bot identity.")
    require(me.get("supports_inline_queries") is True, "The isolated Bot does not report inline mode enabled.")
    before = checked_webhook(telegram)
    attempted, acknowledged = False, None
    after = before
    if mode == "append" and INLINE_TYPE not in before.allowed:
        verify_release()
        current = checked_webhook(telegram)
        require(current.allowed == before.allowed, "The isolation webhook update inventory changed before append.")
        before_write()
        attempted = True
        try:
            acknowledged = telegram("setWebhook", {
                "url": WEBHOOK_URL, "secret_token": policy["webhookSecret"], "max_connections": MAX_CONNECTIONS,
                "allowed_updates": [*before.allowed, INLINE_TYPE], "drop_pending_updates": False,
            }) is True
        except TelegramRequestError:
            acknowledged = False
        for delay in READBACK_DELAYS:
            if delay:
                pause(delay)
            try:
                after = checked_webhook(telegram)
            except TelegramRequestError:
                continue
            if INLINE_TYPE in after.allowed:
                require(tuple(kind for kind in after.allowed if kind != INLINE_TYPE) == before.allowed,
                        "The isolation webhook changed the original update ordering.")
                break
            require(after.allowed == before.allowed, "The isolation webhook changed during append verification.")
        else:
            raise InlineWebhookError("The isolation webhook append could not be confirmed. Inspect before any retry.")
    verify_release()
    return {"mode": mode, "writeAttempted": attempted, "writeAcknowledged": acknowledged,
            "supportsInlineQueries": True, "inlineQuerySubscribed": INLINE_TYPE in after.allowed,
            "allowedUpdates": list(after.allowed), "allowedUpdateCount": len(after.allowed),
            "maxConnections": MAX_CONNECTIONS, "currentIpReported": after.ip_reported,
            "workerInlineSearchEnabled": active_version.telegram_inline_search, "workerRevision": active_version.revision}


def release_snapshot(scope, policy, expected_digest):
    config = scope.worker_config()
    scope.verify_resources()
    active = scope.active()
    version = scope.version(active.version)
    require(scope.cron_enabled() and version.telegram_config_sha256 == expected_digest,
            "The isolated Worker Telegram configuration or Cron differs.")
    scope.verify_inline_search(policy["botId"])
    _verify_health(version.revision)
    return config, active, version


def verify_historical_config(scope, expected_digest):
    historical = scope.version(BASELINE_VERSION)
    require(historical.revision == BASELINE_REVISION and historical.telegram_config_sha256 == expected_digest,
            "The original isolated DNS webhook configuration could not be verified.")


def run():
    revision = os.environ.get("GITHUB_SHA", "")
    require(REVISION.fullmatch(revision) and os.environ.get("GITHUB_REPOSITORY") == REPOSITORY
            and os.environ.get("GITHUB_REF") == MAIN_REF and os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
            and os.environ.get("GITHUB_WORKFLOW_REF") == f"{REPOSITORY}/{WORKFLOW}@{MAIN_REF}"
            and os.environ.get("GITHUB_WORKFLOW_SHA") == revision,
            "The inline webhook operation requires the trusted manual main workflow.")
    mode = os.environ.get("SUBS_BOT_INLINE_WEBHOOK_MODE", "")
    confirmation = os.environ.get("SUBS_BOT_INLINE_WEBHOOK_CONFIRMATION", "")
    raw = telegram_release_config({"migrations": [{"name": "0002_telegram.sql"}]})
    policy = _parse_object(raw, "The isolated Telegram configuration is invalid.")
    target = _parse_object(os.environ.get("SUBS_BOT_CF_ISOLATION_TARGET_JSON", ""), "The isolated Cloudflare target is invalid.")
    data, deploy = (os.environ.get(key) for key in ("SUBS_BOT_CF_BOOTSTRAP_TOKEN", "SUBS_BOT_CF_DEPLOY_TOKEN"))
    require(data and deploy and data != deploy, "Separate scoped Cloudflare credentials are required.")
    scope = _Isolation(CloudflareClient(deploy), CloudflareClient(data), target)
    digest = sha256(raw.encode("utf-8")).hexdigest()
    pinned = None

    def verify_release():
        nonlocal pinned
        require_current_main(revision)
        current = release_snapshot(scope, policy, digest)
        require(current[2].revision == revision, "The isolated Worker is running a different reviewed main revision.")
        require(pinned is None or current == pinned, "The isolated Worker deployment changed during webhook verification.")
        if pinned is None:
            verify_historical_config(scope, digest)
        pinned = current
        return pinned[2]

    def before_write():
        verify_historical_config(scope, digest)
        require(pinned is not None and scope.active() == pinned[1], "The isolated Worker deployment changed before webhook append.")
        require_current_main(revision)

    result = maintain(TelegramClient(policy["botToken"]), policy, mode, confirmation, verify_release, before_write)
    print(json.dumps(result, sort_keys=True), flush=True)


if __name__ == "__main__":
    try:
        run()
    except (ArtifactError, CloudflareError, InlineWebhookError) as error:
        sys.exit(str(error))
    except Exception:
        sys.exit("The isolated Telegram inline webhook could not be verified.")
