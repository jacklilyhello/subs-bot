"""Adapter for the separately reviewed trusted-main isolation workflow.

The caller's main workflow, protected environments and fresh-job boundaries are
the authority. This adapter never alters GitHub's SHA or workflow identity. It
only verifies archived source closure; it cannot publish or mutate evidence.
"""

import os
from pathlib import Path
import tempfile

import production_provider as control
import production_provider_encrypted_publish as publish
import provider_durable_source as durable
import provider_private_handoff as handoff


ACTIONS = {
    "verify_sources": {"verify-archived-chain"},
}


def verify_archived_chain():
    target = publish.config()
    durable.restore()
    control.guard_sources(target)
    control.prepare_durable(target["build"])
    with tempfile.TemporaryDirectory(prefix=".reviewed-provider-chain-", dir=os.environ["RUNNER_TEMP"]) as temporary:
        control.verify_previous_archives(target, Path(temporary))
    control.guard_sources(target)
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="ascii") as output:
        output.write("target_sha256=" + control.digest(target) + "\n")


def run():
    handoff.context()
    control.require(handoff.workflow_path() == handoff.REVIEWED_WORKFLOW_PATH)
    action = os.environ.get("SUBS_BOT_PROVIDER_REVIEWED_ACTION", "")
    control.require(action in ACTIONS.get(os.environ.get("GITHUB_JOB", ""), set()))
    verify_archived_chain()


if __name__ == "__main__":
    try:
        run()
    except (ValueError, KeyError, OSError, TypeError, RuntimeError):
        raise SystemExit("Reviewed Provider rehearsal stopped; preserve evidence and do not retry an unknown operation.") from None
