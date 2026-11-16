"""Explicitly reconcile one immutable interrupted binding, without re-uploading."""
from copy import deepcopy
from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory

import prepare_control_artifact
import prepare_isolation_artifact as artifact
import production_application_provider_drill as app
from production_control import API, Controller
from production_deploy_readback import wait_for_deployment
from production_target import canonical, digest, matches, parsed, require, validate_target, REV, SHA, UUID

PROOF = {"revision", "runId", "runAttempt", "artifactId", "archiveSha256"}


def parameters(raw):
    value = parsed(raw)
    require(isinstance(value, dict) and set(value) == {"runId", "runAttempt", "intentSha256", "versionId", "deploymentId"}
        and matches(r"[1-9][0-9]{0,19}", value["runId"]) and matches(r"[1-9][0-9]{0,5}", value["runAttempt"])
        and matches(SHA, value["intentSha256"]) and matches(UUID, value["versionId"])
        and matches(UUID, value["deploymentId"]), "Exact interrupted binding and independently observed release pins are required.")
    return value


def proof(value):
    require(isinstance(value, dict) and set(value) == PROOF and matches(REV, value["revision"])
        and matches(SHA, value["archiveSha256"]) and all(matches(r"[1-9][0-9]{0,19}", value[key])
            for key in ("runId", "runAttempt", "artifactId")), "An immutable reviewed source proof is required.")
    return value


def original_release(runner, original, intent, before):
    selected = proof(intent["sourceProof"])
    with TemporaryDirectory(prefix="binding-original-reviewed-", dir=runner.env["RUNNER_TEMP"]) as directory:
        observed = prepare_control_artifact.prepare("inspect", run_id=selected["runId"], directory=directory)
        require({key: str(observed[key]) for key in PROOF} == selected,
                "The original source CI artifact differs from the immutable admission.")
        bundle = Path(directory) / artifact.VERIFIED_DIRECTORY
        manifest = parsed((bundle / "isolation.json").read_bytes())
        old = Controller(original, API(original, runner.env["SUBS_BOT_CF_BOOTSTRAP_TOKEN"]),
            API(original, runner.env["SUBS_BOT_CF_DEPLOY_TOKEN"]), bundle, manifest,
            guard=runner.guard, secrets=runner.secrets, control_revision=runner.revision)
        release = old.version(before["release"]["versionId"], deployment_id=before["release"]["deploymentId"])
        old.verify_bindings(release)
        require(canonical({key: value for key, value in release.items() if key != "bindings"}) == canonical(before["release"]),
                "The complete original version differs from the immutable deployment predecessor.")
        return release


def run(runner, wire, *, reconcile_only=False):
    pin = parameters(runner.env.get("DRILL_PROVIDER_BINDING_RESUME_JSON", ""))
    require(type(reconcile_only) is bool and ((reconcile_only and runner.human_window == 0) or (
        not reconcile_only and runner.env.get("DRILL_PROVIDER_READY_ACK") == app.READY and 60 <= runner.human_window <= 540))
        and runner.attempt == "1" and not runner.baseline_checkpoint
        and runner.env.get("SUBS_BOT_CF_DEPENDENCY_READ_TOKEN"),
        "Explicit IAB readiness and a fresh, independently approved reconciliation are required.")
    # The runtime source remains the reviewed interrupted source. Current main
    # authorizes only the control code and does not replace that source pin.
    bundle, manifest = runner.prepare(active=True)
    desired_proof = proof(deepcopy(runner.proof))
    original = runner.registration()
    loaded = app.load_provider(runner, runner.env.get("DRILL_PROVIDER_RUN_ID", ""),
        runner.env.get("DRILL_PROVIDER_RUN_ATTEMPT", ""), runner.env.get("DRILL_PROVIDER_MANIFEST_SHA256", ""))
    target = app.desired_target(original, loaded["config"])
    key = runner.prefix + "provider-binding/" + app.provider.digest(loaded["config"]) + "/" + manifest["revision"] + "/admission.json"
    raw = runner.store.get(key)
    require(sha256(raw).hexdigest() == pin["intentSha256"], "The immutable binding admission digest differs.")
    intent = parsed(raw)
    require(canonical(intent) == raw and intent.get("runId") == pin["runId"] and intent.get("runAttempt") == pin["runAttempt"]
        and set(intent) == {"runId", "runAttempt", "sourceTarget", "desiredTarget", "sourceProof", "desiredProof", "before", "providerEvidence"}
        and runner.store.get(runner.prefix + pin["runId"] + "-" + pin["runAttempt"] + "-provider-binding-on-intent.json") == raw,
        "The shared admission and original run intent must be identical immutable records.")
    require(canonical(validate_target(intent["sourceTarget"]).data) == canonical(original.data)
        and canonical(validate_target(intent["desiredTarget"]).data) == canonical(target.data)
        and proof(intent["desiredProof"]) == desired_proof and canonical(intent["providerEvidence"]) == canonical(loaded["evidence"]),
        "The interrupted resources, configuration or reviewed source differ from this reconciliation.")
    before = intent["before"]
    require(isinstance(before, dict) and before.get("stateSha256") == digest({key: value for key, value in before.items() if key != "stateSha256"})
        and before.get("targetSha256") == target.digest and before.get("configurationSha256") == target.configuration_digest
        and before.get("migrationCount") == len(manifest["migrations"])
        and before["release"]["revision"] == proof(intent["sourceProof"])["revision"]
        and before["control"]["release_revision"] == before["release"]["revision"], "The original approved predecessor is not exact.")
    app.closed(before)
    control = before["control"]
    require(set(control) == {"singleton", "target_sha256", "bot_id", "generation", "epoch", "release_revision", "admission", "workers"}
        and type(control["singleton"]) is int and control["singleton"] == 1 and type(control["epoch"]) is int and 1 <= control["epoch"] <= 2**53 - 1
        and type(control["generation"]) is int and control["generation"] == target.data["generation"]
        and control["target_sha256"] == target.digest and control["bot_id"] == target.data["botId"],
        "The immutable control predecessor types and identity must be exact.")
    require(not any(before["terminal"].get(name, 0) for name in app.UNKNOWN))
    previous = original_release(runner, original, intent, before)
    dependency = app.DependencyReadOnly(target, runner.env["SUBS_BOT_CF_DEPENDENCY_READ_TOKEN"], target.data["provider"])
    on, off = app.controllers(runner, wire, original, target, bundle, manifest, dependency)
    def read():
        on.resources()
        return on.active(allow_empty=True)
    expected_active = wait_for_deployment(read, previous=previous, desired_version=pin["versionId"], desired_deployment=pin["deploymentId"],
        verify_desired=lambda value: on.verify_bindings(value, verify_dependency=True))
    current = on.plan_reconcile_deploy()
    app.closed(current)
    require(current["release"]["versionId"] == pin["versionId"] and current["release"]["deploymentId"] == pin["deploymentId"]
        and current["migrationCount"] == before["migrationCount"] and not any(current["terminal"].get(name, 0) for name in app.UNKNOWN))
    successor = {**before["control"], "epoch": before["control"]["epoch"] + 1, "release_revision": manifest["revision"]}
    require(canonical(current["control"]) in (canonical(before["control"]), canonical(successor)),
        "Only the exact predecessor or its single reconciled successor is permitted.")
    runner.report.update(activeSourceProof=intent["sourceProof"], applicationProvider={
        "providerEvidence": loaded["evidence"], "validatedConfigurationSha256": target.configuration_digest,
        "originalConfigurationSha256": original.configuration_digest, "oneShotIntentSha256": pin["intentSha256"],
        "resumedFrom": pin}, fixture={"preservedFromInterruptedRun": True})
    runner.save("provider-binding-reconcile-plan", {"resume": pin, "observed": current, "runtimeSourceProof": desired_proof,
        "originalSourceProof": intent["sourceProof"]})
    reconciled = on.reconcile_deploy(wire["approval"](target, "reconcile-deploy", on.revision, current["stateSha256"]),
        current["stateSha256"], predecessor=before, expected_active=expected_active)
    app.closed(reconciled)
    require(runner.store.get(key) == raw, "The original one-shot admission changed; preserve the exact evidence.")
    runner.save("provider-binding-on-reconciled", reconciled)
    runner.controller = on
    if reconcile_only:
        runner.report.update(status="reconciled-closed-only", humanAcceptance=False, state=reconciled,
            configurationSha256=target.configuration_digest, releaseRevision=manifest["revision"], ciProof=desired_proof,
            reconciliationOnly=True, providerBusinessAcceptance={"urlImport": "not-run", "humanRefresh": "not-run",
                "offRelease": "not-run", "latestOffBackup": "not-run"})
        runner.save("provider-binding-reconciled-closed", {"intentSha256": pin["intentSha256"],
            "stateSha256": reconciled["stateSha256"], "status": "reconciled-closed-only"})
        return
    status, expected = wire["public_readback"](wire["public_request"](wire["origin"] + "/sub/" + app.SMALL_TOKEN + "/base64"), 64 * 1024)
    wire["expect_status"](status, 200, "provider-source")
    snapshot = manifest["snapshots"][0]
    require(len(expected) == snapshot["bodyBytes"] and sha256(expected).hexdigest() == snapshot["bodySha256"],
        "The preserved source fixture differs from the exact reviewed CI source.")
    return app.complete_binding(runner, wire, original, target, dependency, on, off, expected)
