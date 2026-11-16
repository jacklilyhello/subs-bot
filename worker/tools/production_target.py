"""Explicit production/rehearsal contracts. No environment or identity fallback.

This module is deliberately network free. A validated contract is not approval;
each mutation additionally requires a protected action-specific approval envelope.
"""
from dataclasses import dataclass
from hashlib import sha256
import json
import re

ACCOUNT = "9431815bdb8beb2272f6668e06b7d3be"
ZONE = "07c83547944da720e03b31a406fdcd55"
HEX = r"[0-9a-f]{32}"
UUID = r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}"
SHA = r"[0-9a-f]{64}"
REV = r"[0-9a-f]{40}"
STAMP = r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z"
FEATURES = {
    "inlineSearch", "providerUrlImport", "providerUrlDocuments", "mixedDocuments",
    "providerRefresh", "providerBatch", "subscriptionShorts", "externalShortlinks",
    "groupShareCards", "githubSearch", "apiStatus",
}
TEST_ACTORS = {"8813701954", "8653767757"}
TEST_GROUP = "-5114255828"
NAMES = {
    "production": ("subs-bot-cf-prod-01", "subs-bot-cf-prod-backup-01", "subs-bot.lilyya.top"),
    "rehearsal": ("subs-bot-cf-control-drill-01", "subs-bot-cf-control-drill-backup-01",
                  "subs-bot-cf-control-drill-01.lilyya.workers.dev"),
}


class ContractError(ValueError):
    """Messages contain no untrusted input or credentials."""


def require(condition, message="The explicit subs-bot target contract is invalid."):
    if not condition:
        raise ContractError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()


def digest(value):
    return sha256(canonical(value)).hexdigest()


def matches(pattern, value):
    return isinstance(value, str) and re.fullmatch(pattern, value) is not None


def _unique(pairs):
    result = dict(pairs)
    require(len(result) == len(pairs), "Duplicate contract keys are forbidden.")
    return result


def parsed(raw):
    require(isinstance(raw, (str, bytes)) and 0 < len(raw) <= 65536, "An explicit bounded target is required.")
    try:
        value = json.loads(raw, object_pairs_hook=_unique)
    except (ValueError, RecursionError):
        raise ContractError("The target must be valid unique-key JSON.") from None
    require(isinstance(value, dict))
    return value


def actor(value):
    return matches(r"[1-9][0-9]{0,15}", value) and int(value) < 2**52


@dataclass(frozen=True)
class Target:
    data: dict

    @property
    def digest(self):
        # Resource/Bot/authorization generation identity remains stable across a
        # reviewed feature or dependency release. Approval separately binds the
        # full configuration, so changing a flag cannot reuse its old approval.
        return digest({k: v for k, v in self.data.items() if k not in {"features", "provider", "keyDigests", "webhook"}})

    @property
    def configuration_digest(self):
        return digest(self.data)

    @property
    def account_id(self):
        return self.data["accountId"]

    @property
    def d1_id(self):
        return self.data["d1Id"]

    @property
    def environment(self):
        return self.data["environment"]


BASE_KEYS = {"schemaVersion", "environment", "accountId", "zoneId", "namespace", "workerName",
    "workerId", "workerCreatedOn", "d1Id", "d1Name", "d1CreatedAt", "bucketName", "bucketCreatedAt",
    "backupBucketName", "backupBucketCreatedAt", "hostname", "botId", "botUsername", "generation",
    "admins", "members", "groups", "defaultAccess", "features", "provider", "webhook", "keyDigests"}
PINS = {"workerId": HEX, "workerCreatedOn": STAMP, "d1Id": UUID, "d1CreatedAt": STAMP,
        "bucketCreatedAt": STAMP, "backupBucketCreatedAt": STAMP}


def validate_target(raw, *, draft=False):
    value = parsed(raw) if isinstance(raw, (str, bytes)) else raw
    require(isinstance(value, dict) and set(value) == BASE_KEYS)
    value = json.loads(canonical(value))  # disconnect caller-owned mutable structures
    env = value["environment"]
    require(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1 and env in NAMES)
    service, backup, hostname = NAMES[env]
    require(value["accountId"] == ACCOUNT and value["zoneId"] == ZONE and value["namespace"] == "lilyya")
    require(value["workerName"] == value["d1Name"] == value["bucketName"] == service
            and value["backupBucketName"] == backup and value["hostname"] == hostname)
    for key, pattern in PINS.items():
        require((draft and value[key] is None) or matches(pattern, value[key]), "Resource registration pins are missing or malformed.")
    require(actor(value["botId"]) and matches(r"[A-Za-z][A-Za-z0-9_]{4,31}", value["botUsername"]))
    require(type(value["generation"]) is int and 1 <= value["generation"] <= 9007199254740991)
    require(value["defaultAccess"] == "deny", "First release requires explicit allowlisted access.")
    for field in ("admins", "members"):
        ids = value[field]
        require(isinstance(ids, list) and len(ids) <= 100 and ids == sorted(set(ids)) and all(actor(i) for i in ids))
    require(value["admins"] and not set(value["admins"]) & set(value["members"])
            and value["botId"] not in value["admins"] + value["members"])
    groups = value["groups"]
    require(isinstance(groups, list) and len(groups) <= 20)
    seen = set()
    for group in groups:
        require(isinstance(group, dict) and set(group) == {"chatId", "chatType"}
                and matches(r"-[1-9][0-9]{0,15}", group["chatId"]) and -int(group["chatId"]) < 2**52
                and group["chatType"] in ("group", "supergroup") and group["chatId"] not in seen)
        seen.add(group["chatId"])
    # Existing runtime has a single group destination; reject unsupported scope rather than truncate.
    require(len(groups) <= 1, "The current group-card runtime supports at most one explicit group.")
    if env == "production":
        require(value["botUsername"].lower() != "test_cfsubs_bot"
                and not TEST_ACTORS & set(value["admins"] + value["members"]) and TEST_GROUP not in seen,
                "Test identities cannot become implicit production identities.")
    else:
        require(value["botUsername"] == "test_cfsubs_bot" and value["admins"] == ["8813701954"]
                and value["members"] == ["8653767757"] and seen <= {TEST_GROUP}, "Rehearsal identity is outside the authorized scope.")
    flags = value["features"]
    require(isinstance(flags, dict) and set(flags) == FEATURES and all(type(x) is bool for x in flags.values()))
    require(flags["apiStatus"] is False, "API status is disabled for the first production release.")
    require(not flags["groupShareCards"] or len(groups) == 1)
    require(not flags["providerUrlDocuments"] or flags["providerUrlImport"])
    require(not flags["mixedDocuments"] or flags["providerUrlDocuments"])
    needs_provider = any(flags[k] for k in ("providerUrlImport", "providerRefresh", "providerBatch"))
    require(not needs_provider or isinstance(value["provider"], dict), "An independently pinned ProviderFetch dependency is required.")
    require(value["provider"] is None or isinstance(value["provider"], dict))
    if value["provider"] is not None:
        provider = value["provider"]
        expected_service = "subs-bot-provider-fetch-prod-01" if env == "production" else "subs-bot-provider-fetch-control-drill-01"
        require(provider.get("environment") == env and provider.get("accountId") == value["accountId"]
                and provider.get("service") == expected_service, "ProviderFetch belongs to a different environment or account.")
        if not draft:
            require(provider.get("caller") == {"id": value["workerId"], "name": value["workerName"]},
                    "ProviderFetch must explicitly register this exact application caller.")
        from production_provider import validate_config
        validate_config(provider)
    webhook = value["webhook"]
    require(isinstance(webhook, dict) and set(webhook) == {"allowedUpdates", "maxConnections"}
            and isinstance(webhook["allowedUpdates"], list) and webhook["allowedUpdates"]
            and len(webhook["allowedUpdates"]) == len(set(webhook["allowedUpdates"]))
            and set(webhook["allowedUpdates"]) <= {"message", "callback_query", "inline_query"}
            and type(webhook["maxConnections"]) is int and 1 <= webhook["maxConnections"] <= 40)
    require({"message", "callback_query"} <= set(webhook["allowedUpdates"])
            and (not flags["inlineSearch"] or "inline_query" in webhook["allowedUpdates"]),
            "Webhook update categories must cover the configured runtime features.")
    keys = value["keyDigests"]
    require(isinstance(keys, dict) and set(keys) == {"aggregate", "privateShare", "webhook", "shortlink"})
    for key in keys:
        require((key == "shortlink" and not flags["externalShortlinks"] and keys[key] is None) or matches(SHA, keys[key]),
                "Fresh explicit secret digests are required; no secret fallback is permitted.")
    require(keys["aggregate"] != keys["privateShare"] != keys["webhook"] and keys["aggregate"] != keys["webhook"])
    return Target(value)


def approve(target, envelope, action, revision, state_sha256, *, control_revision=None):
    """Approval is supplied only by the selected protected workflow environment."""
    value = parsed(envelope) if isinstance(envelope, (str, bytes)) else envelope
    control_revision = revision if control_revision is None else control_revision
    require(isinstance(value, dict) and type(value.get("schemaVersion")) is int)
    require(isinstance(value, dict) and set(value) == {"schemaVersion", "environment", "targetSha256", "configurationSha256", "revision", "controlRevision", "action", "stateSha256", "authorization"},
            "An action-specific approval envelope is required.")
    require(value == {"schemaVersion": 1, "environment": target.environment, "targetSha256": target.digest,
            "configurationSha256": target.configuration_digest,
            "revision": revision, "controlRevision": control_revision, "action": action, "stateSha256": state_sha256,
            "authorization": "approve " + action + " for " + target.data["workerName"]},
            "Approval does not match this exact target, configuration, revision, action and predecessor state.")
    require(matches(REV, revision) and matches(REV, control_revision) and matches(SHA, state_sha256))
    return True
