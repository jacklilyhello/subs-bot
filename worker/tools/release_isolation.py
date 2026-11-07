"""Release only the verified main artifact to the dedicated isolation resources."""

import json
import os
import re
import sys
from pathlib import Path

from cloudflare_isolation import (
    CloudflareClient, CloudflareError, WORKER_NAME, release_worker, validate_aggregate_key, validate_private_share_key,
    verify_worker_target,
)
from d1_migrations import MigrationError, apply_migrations
from prepare_isolation_artifact import ArtifactError, require_current_main
from provider_binding_gate import CONFIG_ENV, load_provider_gate


def telegram_release_config(manifest):
    if not any(item["name"] == "0002_telegram.sql" for item in manifest["migrations"]):
        return None
    raw = os.environ.get("SUBS_BOT_TELEGRAM_TEST_CONFIG", "")
    if not raw or len(raw) > 2048:
        raise CloudflareError("This revision requires the isolated Telegram configuration.")
    try:
        policy = json.loads(raw)
        bot_id, admin, member, group = (policy[key] for key in ("botId", "adminId", "memberId", "groupId"))
        if (set(policy) != {"botId", "botUsername", "botToken", "webhookSecret", "adminId", "memberId", "groupId"}
                or policy["botUsername"] != "test_cfsubs_bot"
                or len({bot_id, admin, member}) != 3
                or not all(re.fullmatch(r"[1-9][0-9]{0,15}", value) and int(value) < 2**52
                           for value in (bot_id, admin, member))
                or not re.fullmatch(r"-[1-9][0-9]{0,15}", group) or -int(group) >= 2**52
                or not re.fullmatch(re.escape(bot_id) + r":[A-Za-z0-9_-]{30,80}", policy["botToken"])
                or not re.fullmatch(r"[A-Za-z0-9_-]{32,256}", policy["webhookSecret"])):
            raise ValueError()
    except (KeyError, ValueError, TypeError):
        raise CloudflareError("The isolated Telegram configuration is invalid.") from None
    return raw


def inline_search_release_mode():
    mode = os.environ.get("SUBS_BOT_INLINE_SEARCH_MODE", "preserve")
    confirmation = os.environ.get("SUBS_BOT_INLINE_SEARCH_CONFIRMATION", "")
    if mode == "preserve" and confirmation == "":
        return None
    if mode in ("enable", "disable") and confirmation == f"{mode} inline search for {WORKER_NAME}":
        return mode == "enable"
    raise CloudflareError("The isolated inline search release mode or confirmation is invalid.")


def release():
    revision = os.environ.get("GITHUB_SHA", "")
    if (os.environ.get("GITHUB_REPOSITORY") != "jacklilyhello/subs-bot"
            or os.environ.get("GITHUB_EVENT_NAME") != "workflow_dispatch"
            or os.environ.get("GITHUB_REF") != "refs/heads/main"
            or not re.fullmatch(r"[0-9a-f]{40}", revision)):
        raise ValueError("The isolation workflow must run for the project's main branch.")

    inline_search = inline_search_release_mode()
    bundle = Path(os.environ["RUNNER_TEMP"]) / "subs-bot-verified"
    manifest = json.loads((bundle / "isolation.json").read_text(encoding="utf-8"))
    if manifest.get("version") != 2 or manifest.get("revision") != revision:
        raise ValueError("The verified artifact does not match this release.")
    telegram_config = telegram_release_config(manifest)
    aggregate_key = None
    if any(item["name"] == "0014_telegram_aggregate_issuance.sql" for item in manifest["migrations"]):
        aggregate_key = os.environ.get("SUBS_BOT_TELEGRAM_AGGREGATE_KEY", "")
        validate_aggregate_key(aggregate_key)
    private_share_key = None
    # Optional until first activation; thereafter the active digest below prevents dropping or rotating it.
    if any(item["name"] == "0016_telegram_private_share_creation.sql" for item in manifest["migrations"]):
        private_share_key = os.environ.get("SUBS_BOT_TELEGRAM_PRIVATE_SHARE_CREATION_KEY") or None
        if private_share_key is not None:
            validate_private_share_key(private_share_key)
            if private_share_key == aggregate_key:
                raise CloudflareError("The isolated private share key must be distinct from the aggregate key.")
    target = json.loads(os.environ.get("SUBS_BOT_CF_ISOLATION_TARGET_JSON", "null"))
    if not isinstance(target, dict) or set(target) != {
        "accountId", "workerId", "workerCreatedOn", "d1Id", "d1CreatedAt", "r2CreatedOn", "namespace",
    }:
        raise ValueError("The isolation environment must contain the reviewed resource identities.")
    data_token = os.environ.get("SUBS_BOT_CF_BOOTSTRAP_TOKEN")
    deploy_token = os.environ.get("SUBS_BOT_CF_DEPLOY_TOKEN")
    if not data_token or not deploy_token or data_token == deploy_token:
        raise ValueError("Separate Cloudflare data and deployment credentials are required.")

    def guard():
        require_current_main(revision)

    data_api = CloudflareClient(data_token)
    worker_api = CloudflareClient(deploy_token)
    guard()
    provider_gate = load_provider_gate(os.environ.get(CONFIG_ENV, ""), target, deploy_token)
    provider_binding = provider_gate.binding if provider_gate is not None else None
    first_provider_proof = provider_gate.verify_first_binding if provider_gate is not None else None
    historical_application_revision = provider_gate.historical_application_revision if provider_gate is not None else None
    starting = verify_worker_target(worker_api, data_api, target, aggregate_key=aggregate_key, private_share_key=private_share_key,
                                    provider_binding=provider_binding, release_revision=revision,
                                    provider_first_binding_guard=first_provider_proof,
                                    historical_application_revision=historical_application_revision, release_manifest=manifest,
                                    telegram_config=telegram_config, inline_search=inline_search)
    if provider_gate is not None:
        provider_gate.verify()
    migrations = apply_migrations(data_api, target, bundle, manifest, guard)
    print(f"Verified {len(migrations)} isolated D1 migration records.", flush=True)
    result = release_worker(worker_api, data_api, target, bundle, manifest, guard,
                            expected_active=starting, telegram_config=telegram_config, aggregate_key=aggregate_key,
                            private_share_key=private_share_key, provider_binding=provider_binding,
                            provider_guard=provider_gate.verify if provider_gate is not None else None,
                            provider_first_binding_guard=first_provider_proof,
                            historical_application_revision=historical_application_revision, inline_search=inline_search)
    guard()
    print(json.dumps(result, sort_keys=True), flush=True)


if __name__ == "__main__":
    try:
        release()
    except (ArtifactError, CloudflareError, MigrationError) as error:
        sys.exit(str(error))
    except Exception:
        # Do not print an exception repr, request, path or environment value.
        sys.exit("Isolation release failed validation or verification. Check the preceding stage and live state before retrying.")
