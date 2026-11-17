"""Read-only complete inventory of the three isolated Provider journal prefixes."""

import json
import os

import archive_production_provider as archive
import production_provider as provider
from evidence_archive import verify_lifecycle

WORKFLOW = ".github/workflows/worker-provider-isolated-inventory.yml"
PREFIXES = ("maintenance/provider-isolated-source/", "maintenance/provider-digest-rehearsal/",
            "maintenance/provider-private-mutation/")


def inspect():
    revision = os.environ.get("GITHUB_SHA", "")
    provider.require(os.environ.get("GITHUB_REPOSITORY") == provider.github.REPOSITORY
                     and os.environ.get("GITHUB_REPOSITORY_ID") == str(provider.github.REPOSITORY_ID)
                     and os.environ.get("GITHUB_REF") == provider.github.MAIN_REF
                     and os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
                     and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
                     and os.environ.get("GITHUB_WORKFLOW_REF") == f"{provider.github.REPOSITORY}/{WORKFLOW}@{provider.github.MAIN_REF}"
                     and os.environ.get("GITHUB_WORKFLOW_SHA") == revision
                     and os.environ.get("GITHUB_RUN_ATTEMPT") == "1"
                     and provider.match(provider.provider.REVISION, revision)
                     and provider.match(provider.provider.DECIMAL, os.environ.get("GITHUB_RUN_ID", "")))
    provider.github.require_current_main(revision)
    target = provider.github._parse_object(os.environ.get("SUBS_BOT_PROVIDER_ARCHIVE_TARGET_JSON", ""), archive.ERROR)
    reader = archive.PrivateProofStore(target, "", os.environ["GITHUB_RUN_ID"], "1")
    reader.verify()
    objects = reader.objects
    provider.require(objects is not None and objects.write_credential is None)
    lifecycle = reader.metadata_api("GET", reader.base + "/lifecycle")
    counts = {}
    for prefix in PREFIXES:
        verify_lifecycle(lifecycle, prefix)
        counts[prefix] = len(objects.list(prefix))
    provider.github.require_current_main(revision)
    return {"status": "complete-read-only-inventory", "controllerRevision": revision,
            "runId": os.environ["GITHUB_RUN_ID"], "prefixCounts": counts,
            "allEmpty": all(count == 0 for count in counts.values()), "productionMutation": False}


if __name__ == "__main__":
    try:
        print(json.dumps(inspect(), sort_keys=True))
    except Exception:
        raise SystemExit("The isolated Provider inventory was not confirmed; do not initialize an empty ledger.") from None
