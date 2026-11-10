"""Plan or upload a closed page-jump version without changing the active deployment."""

from dataclasses import asdict, replace
from hashlib import sha256
import json
import os
import re
import stat

from cloudflare_isolation import (
    CloudflareError, WORKER_NAME, _Isolation, _api_status_tag, _artifact, _page_jump_tag,
    _require, _telegram_feature_tag, _verify_health, version_evidence,
)
from d1_migrations import _load_migrations, _read_state
from page_jump_control import MAX_SAFE_INTEGER, PageJumpControl, PageJumpGate

WORKFLOW_REF = "jacklilyhello/subs-bot/.github/workflows/worker-isolation-deploy.yml@refs/heads/main"
EVIDENCE_NAME = "subs-bot-page-jump-evidence.json"
ARTIFACT_PROOF_NAME = "subs-bot-isolation-artifact-proof.json"
PIN = re.compile(r"[a-f0-9]{64}")
RUN = re.compile(r"[1-9][0-9]{0,15}")
INVALID = "Invalid isolated page-jump stage inputs."


def _digest(value):
    return sha256(_canonical(value)).hexdigest()


def _canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"


def _unique_fields(pairs):
    value = dict(pairs)
    _require(len(value) == len(pairs), INVALID)
    return value


def stage_inputs(mode, confirmation, raw):
    if mode == "preserve" and confirmation == raw == "":
        return mode, None
    if mode == "plan" and confirmation == raw == "":
        return mode, None
    _require(mode == "stage" and confirmation == f"stage page jump for {WORKER_NAME}"
             and isinstance(raw, str) and 0 < len(raw) <= 512, INVALID)
    try:
        value = json.loads(raw, object_pairs_hook=_unique_fields)
        _require(isinstance(value, dict) and set(value) == {"activeSha256", "gateSha256", "priorEpoch"}, INVALID)
        _require(all(isinstance(value[key], str) and PIN.fullmatch(value[key]) for key in ("activeSha256", "gateSha256"))
                 and (value["priorEpoch"] is None or type(value["priorEpoch"]) is int
                      and 1 <= value["priorEpoch"] <= MAX_SAFE_INTEGER), INVALID)
        return mode, value
    except (ValueError, TypeError, RecursionError):
        raise CloudflareError(INVALID) from None


def hosted_run(env):
    _require(env.get("GITHUB_WORKFLOW_REF") == WORKFLOW_REF and env.get("RUNNER_ENVIRONMENT") == "github-hosted",
             "The protected page-jump stage requires its exact GitHub workflow.")
    values = (env.get("GITHUB_RUN_ID", ""), env.get("GITHUB_RUN_ATTEMPT", ""))
    _require(all(RUN.fullmatch(value) and int(value) <= MAX_SAFE_INTEGER for value in values), INVALID)
    return tuple(map(int, values))


def artifact_proof(directory, manifest):
    error = "The page-jump stage requires exact verified Worker CI artifact evidence."
    try:
        with os.fdopen(os.open(directory / ARTIFACT_PROOF_NAME, os.O_RDONLY | os.O_NOFOLLOW), "rb") as stream:
            info = os.fstat(stream.fileno())
            _require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and not info.st_mode & 0o077
                     and 0 < info.st_size <= 1024, error)
            raw = stream.read(1025)
        proof = json.loads(raw, object_pairs_hook=_unique_fields)
        _require(isinstance(proof, dict) and set(proof) == {"revision", "runId", "runAttempt", "artifactId", "archiveSha256"}
                 and all(proof[key] == manifest[key] for key in ("revision", "runId", "runAttempt"))
                 and isinstance(proof["artifactId"], str) and RUN.fullmatch(proof["artifactId"])
                 and isinstance(proof["archiveSha256"], str) and PIN.fullmatch(proof["archiveSha256"]), error)
        return proof
    except (CloudflareError, OSError, ValueError, KeyError, TypeError, RecursionError):
        raise CloudflareError(error) from None


def _ordinary_tag(base, active):
    return _telegram_feature_tag(
        _api_status_tag(base.tag, active.api_status_binding, active.telegram_api_status),
        active.telegram_inline_search, active.telegram_provider_url_import, active.telegram_provider_refresh,
        active.legacy_subscription_shorts, active.telegram_provider_batch,
        active.digest if active.telegram_provider_batch_capable else None,
        url_documents=active.telegram_provider_url_documents,
        url_documents_module_sha256=active.digest if active.telegram_provider_url_documents_capable else None,
        mixed_documents=active.telegram_mixed_documents if active.telegram_mixed_documents_capable else None,
        group_share_cards=active.telegram_group_share_cards if active.telegram_group_share_cards_capable else None,
        subscription_shorts=active.telegram_subscription_shorts if active.telegram_subscription_shorts_capable else None,
        short_module_sha256=active.digest if active.telegram_subscription_shorts_capable else None,
    )


def _gate_document(gate):
    return asdict(gate) if gate else None


def prepare_stage(worker_api, data_api, target, bundle, manifest, telegram_config, aggregate_key, private_share_key,
                  guard, *, run_id, attempt, expected=None):
    """Read a plan when expected is absent. Otherwise reserve and stage that exact checkpoint."""
    from general_read_rehearsal import require_general_read_lane_clear
    from page_jump_activation import MIGRATION, require_clear_for_release

    proof = artifact_proof(bundle.parent, manifest)
    scope = _Isolation(worker_api, data_api, target)
    scope.verify_resources()
    settings = scope.worker_config()
    _require(scope.cron_enabled(), "The isolated page-jump baseline requires the existing Telegram Cron.")
    deployment = scope.active()
    active = scope.version(deployment.version)
    module, base = _artifact(bundle, manifest, telegram_config, aggregate_key, private_share_key, active.provider_binding)
    _require(base.telegram_page_jump_control_capable and active.telegram_page_jump_control_capable
             and base.telegram_config_sha256 is not None
             and (base.revision, base.digest, base.compatibility, base.telegram_config_sha256,
                  base.telegram_aggregate_key_sha256, base.telegram_private_share_key_sha256)
             == (active.revision, active.digest, active.compatibility, active.telegram_config_sha256,
                 active.telegram_aggregate_key_sha256, active.telegram_private_share_key_sha256)
             and active.tag == _ordinary_tag(base, active),
             "Stage page jump from the exact healthy dormant Worker artifact and configuration.")
    bot_id = json.loads(telegram_config)["botId"]
    control = PageJumpControl(scope, bot_id)
    migrations = _load_migrations(bundle, manifest)
    state, history = _read_state(data_api, control.path.removesuffix("/query"), migrations)
    _require(state == "managed" and len(history) == len(migrations), "Apply and verify the full isolated migration chain before staging.")
    require_clear_for_release(scope, required=any(entry["name"] == MIGRATION for entry in manifest["migrations"]))
    require_general_read_lane_clear(scope)
    _verify_health(active.revision)

    def current_release():
        guard()
        return scope.active() == deployment and scope.version(deployment.version) == active

    active_pin = _digest({"scope": target, "deployment": asdict(deployment), "version": version_evidence(active)})
    observed = control.observe()
    current = observed.gate
    _require((current is None or not current.enabled) and not observed.unsettled,
             "The isolated page-jump baseline must be closed and drained.")
    evidence = {"version": 1, "revision": base.revision, "bundleSha256": base.digest,
                "ciManifestSha256": sha256((bundle / "isolation.json").read_bytes()).hexdigest(),
                "ciRunId": manifest["runId"], "ciRunAttempt": manifest["runAttempt"],
                "ciArtifactId": proof["artifactId"], "ciArchiveSha256": proof["archiveSha256"],
                "operationRunId": run_id, "operationRunAttempt": attempt}
    if expected is None:
        _require(current_release(), "The isolated page-jump baseline changed.")
        return {**evidence, "phase": "planned", "checkpoint": {
            "activeSha256": active_pin, "gateSha256": _digest(_gate_document(current)),
            "priorEpoch": current.epoch if current else None,
        }}

    _require(expected["activeSha256"] == active_pin, "The isolated page-jump stage baseline changed.")
    resumed = current is not None and current.epoch == run_id
    prior = current
    if resumed:
        prior = (None if expected["priorEpoch"] is None else
                 PageJumpGate(expected["priorEpoch"], False, current.origin_after_receipt))
        _require(prior is not None or current.origin_after_receipt == 0, "The isolated page-jump stage checkpoint differs.")
    _require(expected["priorEpoch"] == (prior.epoch if prior else None)
             and expected["gateSha256"] == _digest(_gate_document(prior)), "The isolated page-jump stage checkpoint differs.")
    desired = replace(active, tag=_page_jump_tag(active.tag, run_id, active.digest), telegram_page_jump_epoch=run_id)
    candidate = scope.staged(desired)
    if resumed:
        _require(candidate is not None, "The reserved stage has no verified candidate. Start a fresh protected stage.")
    else:
        _require(candidate is None, "An unreserved isolated page-jump candidate already exists.")
    reserved = control.reserve(prior, run_id, current_release)
    if candidate is None:
        _require(current_release() and control.observe().gate == reserved, "The isolated closed stage changed before upload.")
        candidate = scope.upload(module, desired, telegram_config, aggregate_key, private_share_key)
    _require(current_release() and scope.worker_config() == settings and scope.cron_enabled(),
             "The isolated active release changed during page-jump staging.")
    control.verify_drained(reserved, current_release)
    return {**evidence, "phase": "staged", "checkpoint": expected, "epoch": run_id,
            "reservedGateSha256": _digest(_gate_document(reserved)),
            "candidateSha256": _digest({"versionId": candidate, "version": version_evidence(desired)})}


def write_evidence(directory, value):
    with os.fdopen(os.open(directory / EVIDENCE_NAME,
                           os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "wb") as output:
        output.write(_canonical(value))
