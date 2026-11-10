"""Pause an isolated page-jump release and restore its exact predecessor once."""

from dataclasses import asdict, replace

from cloudflare_isolation import _page_jump_tag, _require
from page_jump_activation import (
    ActivationIntent, _deploy_once, _reconcile, _release, _reverses,
)
from page_jump_control import _integer
from page_jump_recovery import read_source
from stage_page_jump_isolation import _digest, _gate_document

STALE = "The isolated page-jump recovery checkpoint changed."


def _active_sha(scope, deployment, version):
    return _digest({"scope": scope.target, "deployment": asdict(deployment), "version": asdict(version)})


def _active_activation(scope, journal, policy_sha256, current, epoch, stage_sha256, *, allow_unconfirmed=False):
    record = journal.read(epoch)
    _require(record is not None and record.intent.restores_epoch is None and record.intent.stage_sha256 == stage_sha256,
             STALE)
    intent = record.intent
    active = scope.active()
    if (active.version == intent.candidate_version_id and active.message == intent.message
            and active.id != intent.prior_deployment_id
            and (record.deployment_id == active.id or allow_unconfirmed and record.deployment_id is None)):
        version = scope.version(active.version, page_jump_epoch=epoch)
        _require(_digest({"versionId": active.version, "version": asdict(version)}) == intent.candidate_sha256, STALE)
    else:
        _require(allow_unconfirmed and record.deployment_id is None
                 and (active.id, active.version) == (intent.prior_deployment_id, intent.prior_version_id), STALE)
        version = scope.version(active.version)
        _require(_active_sha(scope, active, version) == intent.prior_sha256, STALE)
    _require(version.telegram_config_sha256 == policy_sha256, STALE)

    def unchanged():
        return (current() and scope.active() == active and journal.read(epoch) == record
                and scope.version(active.version, page_jump_epoch=version.telegram_page_jump_epoch) == version)

    return record, active, version, unchanged


def pause_durable(scope, telegram_config, guard, *, epoch, stage_sha256, revision, run_id, attempt):
    """Close admission even when the active release is unhealthy or its stage artifact expired."""
    journal, policy_sha256, current = _release(scope, telegram_config, guard)
    _, active, version, unchanged = _active_activation(
        scope, journal, policy_sha256, current, epoch, stage_sha256, allow_unconfirmed=True)
    gate = journal.control.observe().gate
    _require(_integer(run_id, 1) and run_id > epoch and gate is not None and gate.epoch >= epoch
             and (gate.epoch == epoch or not gate.enabled), STALE)
    if gate.epoch != run_id:
        gate = journal.control.pause(gate, run_id, unchanged)
    _require(gate.epoch == run_id and not gate.enabled and unchanged() and journal.control.observe().gate == gate, STALE)
    return {"version": 1, "phase": "paused-durable", "revision": revision,
            "operationRunId": run_id, "operationRunAttempt": attempt, "epoch": gate.epoch,
            "stageEpoch": epoch, "stageSha256": stage_sha256, "pausedGateSha256": _digest(_gate_document(gate)),
            "activeSha256": _active_sha(scope, active, version)}


def rollback_once(scope, source, telegram_config, guard, *, run_id):
    """Use trusted pause evidence and a fresh exact drain check before a single rollback POST."""
    paused = read_source(source, "pause-durable")
    epoch, stage_sha256 = paused["stageEpoch"], paused["stageSha256"]
    journal, policy_sha256, current = _release(scope, telegram_config, guard)
    record = journal.read(paused["epoch"])
    if record is not None:
        _require(record.intent.restores_epoch == epoch and record.intent.stage_sha256 == stage_sha256
                 and record.intent.prior_sha256 == paused["activeSha256"], STALE)
        return _reconcile(scope, journal, record, policy_sha256, current)

    original, active, version, unchanged = _active_activation(scope, journal, policy_sha256, current, epoch, stage_sha256)
    _require(_active_sha(scope, active, version) == paused["activeSha256"], STALE)
    previous = original.intent.prior_version_id
    predecessor = scope.version(previous)
    _require(replace(predecessor, tag=_page_jump_tag(predecessor.tag, epoch, predecessor.digest),
                     telegram_page_jump_epoch=epoch) == version, STALE)
    observed = journal.control.observe()
    gate = observed.gate
    _require(gate is not None and not gate.enabled and gate.epoch == paused["epoch"]
             and _digest(_gate_document(gate)) == paused["pausedGateSha256"], STALE)
    journal.control.verify_drained(gate, unchanged)
    intent = ActivationIntent(gate.epoch, run_id, stage_sha256, paused["activeSha256"],
                              _digest({"versionId": previous, "version": asdict(predecessor)}),
                              active.id, active.version, previous, restores_epoch=epoch)
    _require(_reverses(intent, original), STALE)
    return _deploy_once(scope, journal, intent, observed, active, policy_sha256, unchanged)
