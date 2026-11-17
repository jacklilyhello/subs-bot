"""Adapter for the separately reviewed trusted-main isolation workflow.

The caller's main workflow, protected environments and fresh-job boundaries are
the authority. This adapter never alters GitHub's SHA or workflow identity. It
only verifies archived source closure; it cannot publish or mutate evidence.
"""

from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import tempfile
import traceback

import archive_production_provider as archive
import production_provider as control
import production_provider_encrypted_publish as publish
import provider_durable_source as durable
import provider_private_handoff as handoff


ACTIONS = {
    "verify_sources": {"verify-archived-chain"},
    "verify_faults": {"verify-source-fault"},
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
    approvals = {operation: control.digest({"operation": operation, "target": target})
                 for operation in ("prepare-image", "stage", "activate", "smoke")}
    print(json.dumps({"status": "isolated-operation-approval-digests", "targetSha256": control.digest(target),
                      "approvals": approvals, "authorizationGranted": False, "providerMutation": False}, sort_keys=True))


def verify_source_fault_case():
    """Fault one already-read R2 object in memory; this job has no write credential."""
    scenario = os.environ.get("SUBS_BOT_PROVIDER_FAULT_SCENARIO", "")
    control.require(scenario in {f"{fault}-{where}" for fault in ("missing", "corrupt", "digest", "identity")
                                 for where in ("current", "previous")})
    fault, where = scenario.split("-", 1)
    target = publish.config()
    refs = json.loads(os.environ["SUBS_BOT_PROVIDER_ARCHIVE_REFS"], object_pairs_hook=control.github._unique_json_object)
    index = 0 if where == "current" else 1
    control.require(isinstance(refs, list) and len(refs) > index and len(control.releases(target)) > index)
    selected = refs[index]
    control.require(selected["kind"] in {"isolated-source", "complete", "partial"})
    if fault == "identity":
        print(json.dumps({"scenario": scenario, "phase": "restore-started"}), flush=True)
        durable.restore()
        print(json.dumps({"scenario": scenario, "phase": "restore-complete"}), flush=True)
        control.guard_sources(target)
        print(json.dumps({"scenario": scenario, "phase": "original-chain-confirmed"}), flush=True)
        wrong = deepcopy(target)
        release = control.releases(wrong)[index]
        old = release["smoke"]["healthSha256"]
        release["smoke"]["healthSha256"] = ("0" if old[0] != "0" else "1") + old[1:]
        try:
            print(json.dumps({"scenario": scenario, "phase": "mutated-guard-started"}), flush=True)
            control.guard_sources(wrong)
        except control.ProviderError as error:
            category = {
                "The archived Provider target identity does not match the requested release.": "identity",
                "The frozen provider source is not an exact reviewed main ancestor.": "ancestor",
                "The private Provider original digest differs.": "source-digest",
                "The frozen source CI attempt or archive digest changed.": "source-ci",
            }.get(str(error), "other")
            print(json.dumps({"scenario": scenario, "phase": "mutated-guard-rejected", "category": category}), flush=True)
            control.require(str(error) == "The archived Provider target identity does not match the requested release.")
        else:
            raise control.ProviderError("A simulated Provider identity mismatch was not rejected.")
    else:
        original_read = archive.PrivateProofStore.read
        observed = {"realGet": False, "injected": False}
        manifest_name = {"isolated-source": "source-manifest.json", "complete": "manifest.json", "partial": "partial-manifest.json"}[selected["kind"]]

        def faulted_read(store, relative):
            raw = original_read(store, relative)
            if store.run_id != selected["runId"] or store.attempt != selected["runAttempt"]:
                return raw
            if fault == "digest" and relative == manifest_name:
                control.require(isinstance(raw, bytes) and sha256(raw).hexdigest() == selected["manifestSha256"])
                observed["realGet"] = True
            elif fault in {"missing", "corrupt"} and relative.startswith("blobs/") and not observed["injected"]:
                control.require(isinstance(raw, bytes) and len(raw) > 0 and sha256(raw).hexdigest() == relative[6:])
                observed.update(realGet=True, injected=True)
                return None if fault == "missing" else bytes([raw[0] ^ 1]) + raw[1:]
            return raw

        old_refs = os.environ["SUBS_BOT_PROVIDER_ARCHIVE_REFS"]
        if fault == "digest":
            altered = deepcopy(refs)
            digest = selected["manifestSha256"]
            altered[index]["manifestSha256"] = ("0" if digest[0] != "0" else "1") + digest[1:]
            os.environ["SUBS_BOT_PROVIDER_ARCHIVE_REFS"] = json.dumps(altered)
            observed["injected"] = True
        archive.PrivateProofStore.read = faulted_read
        try:
            try:
                durable.restore()
            except control.ProviderError as error:
                frames = traceback.extract_tb(error.__traceback__)
                if fault in {"missing", "corrupt"}:
                    control.require(any(frame.name in {"verify_archive", "verify_partial", "read_record"}
                                        and 'sha256(body).hexdigest() == chunk["sha256"]' in (frame.line or "") for frame in frames))
                elif selected["kind"] == "isolated-source":
                    control.require(any(frame.name == "restore" and "isolated_inventory" in (frame.line or "") for frame in frames))
                else:
                    control.require(any(frame.name in {"verify_archive", "verify_partial"}
                                        and "expected_manifest" in (frame.line or "") for frame in frames))
                control.require(observed == {"realGet": True, "injected": True})
            else:
                raise control.ProviderError("A simulated Provider archive fault was not rejected.")
        finally:
            archive.PrivateProofStore.read = original_read
            os.environ["SUBS_BOT_PROVIDER_ARCHIVE_REFS"] = old_refs
    print(json.dumps({"status": "simulated-source-fault-rejected", "scenario": scenario,
                      "source": "actual-private-r2-get", "faultInjection": "memory-only",
                      "actionsArtifacts": "simulated-unavailable", "providerWrites": False}, sort_keys=True))


def verify_source_fault():
    scenario = os.environ.get("SUBS_BOT_PROVIDER_FAULT_SCENARIO", "")
    if scenario != "all":
        return verify_source_fault_case()
    original_temp = os.environ["RUNNER_TEMP"]
    try:
        for fault in ("missing", "corrupt", "digest", "identity"):
            for where in ("current", "previous"):
                with tempfile.TemporaryDirectory(prefix=".provider-fault-", dir=original_temp) as scratch:
                    os.environ["RUNNER_TEMP"] = scratch
                    os.environ["SUBS_BOT_PROVIDER_FAULT_SCENARIO"] = fault + "-" + where
                    verify_source_fault_case()
        with tempfile.TemporaryDirectory(prefix=".provider-origin-", dir=original_temp) as scratch:
            os.environ["RUNNER_TEMP"] = scratch
            verify_archived_transport_fixture()
    finally:
        os.environ["RUNNER_TEMP"] = original_temp
        os.environ["SUBS_BOT_PROVIDER_FAULT_SCENARIO"] = scenario


def verify_archived_transport_fixture():
    """Exercise production's source-only transport on the real isolated R2 original."""
    import provider_isolated_source as isolated
    target = publish.config()
    refs = json.loads(os.environ["SUBS_BOT_PROVIDER_ARCHIVE_REFS"], object_pairs_hook=control.github._unique_json_object)
    bucket = control.github._parse_object(os.environ["SUBS_BOT_PROVIDER_ARCHIVE_TARGET_JSON"], control.ERROR)
    control.require(isinstance(refs, list) and refs and refs[0]["kind"] == "isolated-source")
    ref = refs[0]
    record = isolated.ledger().get(ref["runId"])
    control.require(isinstance(record, dict))
    origin = {"version": 1, "kind": "isolated-source", "runId": ref["runId"], "runAttempt": ref["runAttempt"],
              "manifestSha256": ref["manifestSha256"], "targetSha256": ref["targetSha256"],
              "bucketSha256": control.digest(bucket), "ledgerRecordSha256": control.digest(record)}
    durable.prepare_archived_transport({"build": target["build"]}, origin, Path(os.environ["RUNNER_TEMP"]))
    print(json.dumps({"status": "private-origin-transport-verified", "source": "actual-private-r2-get",
                      "actionsArtifacts": "simulated-unavailable", "productionTarget": "not-evaluated",
                      "productionSeal": False, "providerWrites": False}, sort_keys=True))


def run():
    handoff.context()
    control.require(handoff.workflow_path() == handoff.REVIEWED_WORKFLOW_PATH)
    action = os.environ.get("SUBS_BOT_PROVIDER_REVIEWED_ACTION", "")
    control.require(action in ACTIONS.get(os.environ.get("GITHUB_JOB", ""), set()))
    if action == "verify-archived-chain":
        verify_archived_chain()
    else:
        verify_source_fault()


if __name__ == "__main__":
    try:
        run()
    except (ValueError, KeyError, OSError, TypeError, RuntimeError):
        raise SystemExit("Reviewed Provider rehearsal stopped; preserve evidence and do not retry an unknown operation.") from None
