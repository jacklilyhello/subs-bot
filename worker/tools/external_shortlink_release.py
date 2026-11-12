"""Exact caller-only shortlink RPC configuration for the protected isolation release."""
from hashlib import sha256
import re

SERVICE = "shortlink-new"
ENTRYPOINT = "ShortlinkService"
SERVICE_BINDING = "SHORTLINK"
SECRET_BINDING = "SHORTLINK_BUSINESS_TOKEN"
DIGEST_BINDING = "SHORTLINK_BUSINESS_TOKEN_SHA256"
BASE_TAG_BINDING = "SHORTLINK_RELEASE_BASE_TAG"
ENABLE_BINDING = "TELEGRAM_EXTERNAL_SHORTLINKS"
REQUIRED_BINDINGS = {SERVICE_BINDING, SECRET_BINDING, DIGEST_BINDING, BASE_TAG_BINDING}
ALL_BINDINGS = REQUIRED_BINDINGS | {ENABLE_BINDING}
MARKER = b"subs-bot:external-shortlinks:v1"
MIGRATION = "0053_external_shortlinks.sql"
TOKEN = re.compile(r"sl_[A-Za-z0-9_-]{32,128}")
DIGEST = re.compile(r"[0-9a-f]{64}")
BASE_TAG = re.compile(r"[a-z0-9-]{1,96}")


def _require(condition, message):
    from cloudflare_isolation import CloudflareError
    if not condition:
        raise CloudflareError(message)


def release_tag(base_tag, token_digest, enabled):
    if token_digest is None:
        return base_tag
    _require(isinstance(base_tag, str) and BASE_TAG.fullmatch(base_tag) and DIGEST.fullmatch(token_digest)
             and type(enabled) is bool, "Invalid isolated shortlink release identity.")
    # Preserve established capability prefixes (notably provider-batch/batch-ready).
    prefix = base_tag[:-64] if len(base_tag) > 64 and base_tag[-65] == "-" and DIGEST.fullmatch(base_tag[-64:]) else "external-sl-"
    value = f"{base_tag}:shortlink-rpc-v1:{SERVICE}:{ENTRYPOINT}:gfw.mom:{token_digest}:{int(enabled)}"
    return prefix + sha256(value.encode("ascii")).hexdigest()


def read_bindings(bindings, tag):
    names = set(bindings) & ALL_BINDINGS
    if not names:
        _require(not isinstance(tag, str) or not tag.startswith("external-sl-"), "The isolated shortlink release identity is incomplete.")
        return None, False, None
    _require(REQUIRED_BINDINGS <= names, "The isolated shortlink binding identity is incomplete.")
    service = bindings[SERVICE_BINDING]
    secret = bindings[SECRET_BINDING]
    digest = bindings[DIGEST_BINDING]
    base = bindings[BASE_TAG_BINDING]
    enabled = ENABLE_BINDING in bindings
    _require(set(service) <= {"name", "type", "service", "entrypoint", "environment"}
             and service.get("type") == "service" and service.get("service") == SERVICE
             and service.get("entrypoint") == ENTRYPOINT and service.get("environment") in (None, "production"),
             "The isolated shortlink binding differs from the reviewed named RPC service.")
    _require(secret.get("type") == "secret_text" and set(secret) <= {"name", "type", "text"}
             and set(digest) == {"name", "type", "text"} and digest.get("type") == "plain_text"
             and isinstance(digest.get("text"), str) and DIGEST.fullmatch(digest["text"])
             and set(base) == {"name", "type", "text"} and base.get("type") == "plain_text"
             and isinstance(base.get("text"), str) and BASE_TAG.fullmatch(base["text"]),
             "The isolated shortlink secret identity is invalid.")
    _require(not enabled or bindings[ENABLE_BINDING] == {"name": ENABLE_BINDING, "type": "plain_text", "text": "1"},
             "The isolated shortlink admission flag is invalid.")
    _require(tag == release_tag(base["text"], digest["text"], enabled), "The isolated shortlink release tag differs.")
    return digest["text"], enabled, base["text"]


def upload_bindings(token, token_digest, base_tag, enabled):
    _require(isinstance(token, str) and TOKEN.fullmatch(token)
             and sha256(token.encode("ascii")).hexdigest() == token_digest,
             "The protected isolated shortlink secret is missing or differs from the pinned credential.")
    rows = [{"type": "service", "name": SERVICE_BINDING, "service": SERVICE, "entrypoint": ENTRYPOINT},
            {"type": "secret_text", "name": SECRET_BINDING, "text": token},
            {"type": "plain_text", "name": DIGEST_BINDING, "text": token_digest},
            {"type": "plain_text", "name": BASE_TAG_BINDING, "text": base_tag}]
    if enabled:
        rows.append({"type": "plain_text", "name": ENABLE_BINDING, "text": "1"})
    return rows


def artifact_capable(module, manifest):
    entries = [entry for entry in manifest.get("migrations", []) if isinstance(entry, dict) and entry.get("name") == MIGRATION]
    marked = MARKER in module
    if not entries and not marked:
        return False
    _require(marked and entries == [{"name": MIGRATION, "sha256": MIGRATION_SHA256}],
             "The isolated shortlink artifact or migration identity is invalid.")
    return True


def target(active, requested, token, *, capable, telegram_digest, aggregate_digest):
    _require(requested is None or type(requested) is bool, "The isolated shortlink release mode is invalid.")
    enabled = active.telegram_external_shortlinks if requested is None else requested
    configured = active.external_shortlink_token_sha256 is not None or enabled
    if not configured:
        return None, False
    _require(capable and telegram_digest is not None and aggregate_digest is not None,
             "The isolated shortlink configuration requires verified recovery, Telegram and local-link issuance.")
    _require(isinstance(token, str) and TOKEN.fullmatch(token), "The protected isolated shortlink business secret is unavailable.")
    digest = sha256(token.encode("ascii")).hexdigest()
    _require(active.external_shortlink_token_sha256 in (None, digest),
             "Changing the isolated shortlink business credential requires a separate reviewed operation.")
    return digest, enabled


def verify_schema(scope):
    path = f"{scope.account}/d1/database/{scope.target['d1Id']}/query"
    error = "The isolated shortlink schema or migration ledger could not be verified."
    result = scope.data_api("POST", path, {"sql": """
      SELECT name,sha256,mode,(SELECT sql FROM sqlite_schema WHERE type='table'
        AND name='telegram_external_shortlinks') AS tableSql,
        (SELECT count(*) FROM sqlite_schema WHERE sql IS NOT NULL AND tbl_name='telegram_external_shortlinks') AS schemaCount
      FROM subs_bot_schema_migrations WHERE position=53
    """})
    _require(isinstance(result, list) and len(result) == 1 and result[0].get("success") is True
             and isinstance(result[0].get("results"), list) and len(result[0]["results"]) == 1, error)
    row = result[0]["results"][0]
    _require(isinstance(row, dict) and set(row) == {"name", "sha256", "mode", "tableSql", "schemaCount"}
             and (row["name"], row["sha256"], row["mode"]) == (MIGRATION, MIGRATION_SHA256, "applied")
             and row["schemaCount"] == 1 and type(row["schemaCount"]) is int and isinstance(row["tableSql"], str)
             and sha256(row["tableSql"].encode("ascii")).hexdigest() == TABLE_SHA256, error)


# Digests pin the reviewed additive schema; no business credential is stored here.
MIGRATION_SHA256 = "662960669e1ce0da7e74132cfa1c3643a706d79ef03df577b88f5b7e6c0631f8"
TABLE_SHA256 = "c75372e32afed40f706f6f363156a285fe676f0c3549cb01baf1a2fccc72e82e"
