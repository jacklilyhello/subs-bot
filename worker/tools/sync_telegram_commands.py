"""Prepare command features for an exact verified main artifact, without exporting CF credentials."""
import json
import os
from pathlib import Path

from cloudflare_isolation import CloudflareError, _require, _verify_health
from prepare_isolation_artifact import ArtifactError, prepare, require_current_main
from release_isolation import isolated_telegram_config

ERROR = "Isolated Telegram command-menu preparation could not be verified."
FLAG_NAMES = {"inlineSearch", "providerUrlImport", "providerBatch", "apiStatus"}


def command_features(migrations, flags):
    _require(isinstance(flags, dict) and set(flags) == FLAG_NAMES and all(type(v) is bool for v in flags.values()), ERROR)
    names = {entry["name"] for entry in migrations}
    return {
        "management": True, "subscriptionRead": "0018_telegram_subscription_reads.sql" in names,
        "temp": True, "tempRawDefault": True, "path": True, "aggregate": True, "selected": True,
        "short": "0019_telegram_short_links.sql" in names, "share": True,
        "batchRefresh": flags["providerBatch"], "batchStatus": "0032_telegram_provider_batch_controls.sql" in names,
        "inline": flags["inlineSearch"], "inlineTemp": flags["inlineSearch"],
        "inlineSort": "0020_telegram_inline_sort.sql" in names,
        "bulkTrash": "0024_telegram_bulk_trash.sql" in names,
        "github": "0027_telegram_github_search.sql" in names, "apiStatus": flags["apiStatus"],
        "authorization": True, "authorizationScope": "fixed",
        "displayTimezone": "0051_telegram_display_settings.sql" in names,
        "documentImport": True, "providerImport": flags["providerUrlImport"],
    }


def main(env):
    _require(env.get("GITHUB_WORKFLOW_REF") ==
        "jacklilyhello/subs-bot/.github/workflows/worker-isolation-command-menu.yml@refs/heads/main"
        and env.get("GITHUB_REPOSITORY") == "jacklilyhello/subs-bot"
        and env.get("GITHUB_EVENT_NAME") == "workflow_dispatch" and env.get("GITHUB_REF") == "refs/heads/main"
        and env.get("RUNNER_ENVIRONMENT") == "github-hosted", ERROR)
    revision = env.get("GITHUB_SHA", "")
    require_current_main(revision)
    prepare()
    directory = Path(env["RUNNER_TEMP"]) / "subs-bot-verified"
    manifest = json.loads((directory / "isolation.json").read_text())
    _require(manifest.get("revision") == revision and len(manifest["migrations"]) >= 50, ERROR)
    _verify_health(revision)
    policy = json.loads(isolated_telegram_config())
    _require((policy["adminId"], policy["memberId"], policy["groupId"]) == ("8813701954", "8653767757", "-5114255828"), ERROR)
    features = command_features(manifest["migrations"], json.loads(env.get("SUBS_BOT_MENU_FLAGS", "null")))
    features["authorizationMemberId"] = policy["memberId"]
    require_current_main(revision)
    (Path(env["RUNNER_TEMP"]) / "subs-bot-command-features.json").write_text(json.dumps(features))
    print("Verified exact main artifact and live health; supplied feature flags require independent read-only CF readback.")


if __name__ == "__main__":
    try:
        os.umask(0o077)
        main(os.environ)
    except (ArtifactError, CloudflareError, OSError, ValueError, TypeError, KeyError):
        raise SystemExit(ERROR) from None
