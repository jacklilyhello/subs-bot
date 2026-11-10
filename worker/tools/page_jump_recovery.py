"""Read exact protected stage evidence and pause or verify drain in isolation."""

from dataclasses import asdict
from hashlib import sha256
from io import BytesIO
import json
import re
import stat
from zipfile import BadZipFile, ZIP_DEFLATED, ZIP_STORED, ZipFile
import zlib

from cloudflare_isolation import CloudflareError, WORKER_NAME, _Isolation, _require
from page_jump_control import MAX_SAFE_INTEGER, PageJumpControl, PageJumpGate
from prepare_isolation_artifact import _download, _get_json, _github_token, _parse_object, select_main_artifact
from stage_page_jump_isolation import EVIDENCE_NAME, PIN, RUN, _canonical, _digest, _gate_document, _unique_fields

WORKFLOW = ".github/workflows/worker-isolation-deploy.yml"
REVISION = re.compile(r"[a-f0-9]{40}")
PROOF_ERROR = "The exact protected page-jump source artifact could not be verified."
RECOVERY_ERROR = "Invalid isolated page-jump recovery inputs."
MAX_ZIP = 64 * 1024
MAX_DOCUMENT = 4096
SOURCE_FIELDS = {"runId", "runAttempt", "revision", "archiveSha256"}
COMMON_FIELDS = {"version", "phase", "revision", "bundleSha256", "ciManifestSha256", "ciRunId", "ciRunAttempt",
                 "ciArtifactId", "ciArchiveSha256", "operationRunId", "operationRunAttempt"}
STAGE_BUILD_FIELDS = ("bundleSha256", "ciManifestSha256", "ciRunId", "ciRunAttempt", "ciArtifactId", "ciArchiveSha256")


def _matches(pattern, value):
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def _source(value):
    return (isinstance(value, dict) and set(value) == SOURCE_FIELDS and _matches(REVISION, value["revision"])
            and _matches(PIN, value["archiveSha256"])
            and all(_matches(RUN, value[key]) and int(value[key]) <= MAX_SAFE_INTEGER for key in ("runId", "runAttempt")))


def recovery_inputs(mode, confirmation, raw):
    _require(mode in ("pause", "drain") and confirmation == f"{mode} page jump for {WORKER_NAME}"
             and isinstance(raw, str) and 0 < len(raw) <= 1024, RECOVERY_ERROR)
    try:
        inputs = json.loads(raw, object_pairs_hook=_unique_fields)
    except (ValueError, TypeError, RecursionError, CloudflareError):
        raise CloudflareError(RECOVERY_ERROR) from None
    keys = {"stage", "pause"} if mode == "drain" else {"stage"}
    _require(isinstance(inputs, dict) and set(inputs) == keys and all(_source(item) for item in inputs.values()), RECOVERY_ERROR)
    return inputs


def _unpack(raw):
    _require(0 < len(raw) <= MAX_ZIP, PROOF_ERROR)
    try:
        with ZipFile(BytesIO(raw)) as archive:
            files = archive.infolist()
            _require(len(files) == 1, PROOF_ERROR)
            item = files[0]
            _require(item.orig_filename == EVIDENCE_NAME and not item.is_dir()
                     and stat.S_IFMT(item.external_attr >> 16) in (0, stat.S_IFREG)
                     and not item.flag_bits & 1 and item.compress_type in (ZIP_STORED, ZIP_DEFLATED)
                     and 0 < item.file_size <= MAX_DOCUMENT, PROOF_ERROR)
            with archive.open(item) as stream:
                body = stream.read(MAX_DOCUMENT + 1)
            _require(len(body) == item.file_size, PROOF_ERROR)
        value = _parse_object(body, PROOF_ERROR)
        _require(_canonical(value) == body, PROOF_ERROR)
        return value
    except (BadZipFile, OSError, RuntimeError, ValueError, OverflowError, zlib.error):
        raise CloudflareError(PROOF_ERROR) from None


def _validate_source(value, source, kind):
    if kind == "pause-durable":
        _require(set(value) == {"version", "phase", "revision", "operationRunId", "operationRunAttempt",
                                "epoch", "stageEpoch", "stageSha256", "pausedGateSha256", "activeSha256"}
                 and type(value["version"]) is int and value["version"] == 1 and value["phase"] == "paused-durable"
                 and value["revision"] == source["revision"]
                 and all(type(value[key]) is int for key in ("operationRunId", "operationRunAttempt", "epoch", "stageEpoch"))
                 and value["epoch"] == value["operationRunId"] == int(source["runId"])
                 and value["operationRunAttempt"] == int(source["runAttempt"])
                 and 0 < value["stageEpoch"] < value["epoch"]
                 and all(_matches(PIN, value[key]) for key in ("stageSha256", "pausedGateSha256", "activeSha256")), PROOF_ERROR)
        return value
    fields = ({"checkpoint", "epoch", "reservedGateSha256", "candidateSha256"} if kind == "stage" else
              {"stage", "epoch", "pausedGateSha256", "activeSha256"})
    _require(set(value) == COMMON_FIELDS | fields and type(value["version"]) is int and value["version"] == 1
             and value["phase"] == ("staged" if kind == "stage" else "paused")
             and value["revision"] == source["revision"]
             and all(type(value[key]) is int for key in ("operationRunId", "operationRunAttempt", "epoch"))
             and value["operationRunId"] == value["epoch"] == int(source["runId"])
             and value["operationRunAttempt"] == int(source["runAttempt"])
             and all(_matches(PIN, value[key]) for key in ("bundleSha256", "ciManifestSha256", "ciArchiveSha256"))
             and all(_matches(RUN, value[key]) for key in ("ciRunId", "ciRunAttempt", "ciArtifactId")), PROOF_ERROR)
    if kind == "stage":
        checkpoint = value["checkpoint"]
        _require(isinstance(checkpoint, dict) and set(checkpoint) == {"activeSha256", "gateSha256", "priorEpoch"}
                 and all(_matches(PIN, checkpoint[key]) for key in ("activeSha256", "gateSha256"))
                 and (checkpoint["priorEpoch"] is None or type(checkpoint["priorEpoch"]) is int
                      and 0 < checkpoint["priorEpoch"] < value["epoch"])
                 and all(_matches(PIN, value[key]) for key in ("reservedGateSha256", "candidateSha256")), PROOF_ERROR)
    else:
        _require(_source(value["stage"]) and all(_matches(PIN, value[key]) for key in ("pausedGateSha256", "activeSha256")),
                 PROOF_ERROR)
    return value


def read_source(source, kind):
    _require(_source(source) and kind in ("stage", "pause", "pause-durable"), PROOF_ERROR)
    token = _github_token()
    workflow = _get_json("/actions/workflows/worker-isolation-deploy.yml", token)
    workflow_id = workflow.get("id")
    _require(workflow.get("path") == WORKFLOW and workflow.get("state") == "active"
             and type(workflow_id) is int and workflow_id > 0, PROOF_ERROR)

    def selected():
        return select_main_artifact(source["runId"], source["revision"], token, workflow_id=workflow_id,
            workflow_path=WORKFLOW, artifact_prefix=f"subs-bot-page-jump-{kind}-{source['runId']}",
            workflow_label="isolated page-jump", events=("workflow_dispatch",), revision_in_name=False,
            run_attempt=source["runAttempt"])

    attempt, artifact_id, digest = selected()
    _require((attempt, digest) == (source["runAttempt"], source["archiveSha256"]), PROOF_ERROR)
    raw = _download(artifact_id, token)
    _require(sha256(raw).hexdigest() == digest and selected() == (attempt, artifact_id, digest), PROOF_ERROR)
    return _validate_source(_unpack(raw), source, kind)


def prepare_recovery(worker_api, data_api, target, revision, telegram_config, guard,
                     *, mode, sources, run_id, attempt):
    """Pause or prove drain, even if the exact staged Worker is no longer healthy."""
    _require(mode in ("pause", "drain") and _matches(REVISION, revision), RECOVERY_ERROR)
    stage = read_source(sources["stage"], "stage")
    paused = read_source(sources["pause"], "pause") if mode == "drain" else None
    _require(paused is None or (paused["stage"] == sources["stage"] and paused["epoch"] > stage["epoch"]
             and all(paused[key] == stage[key] for key in STAGE_BUILD_FIELDS)), PROOF_ERROR)
    scope = _Isolation(worker_api, data_api, target)
    scope.verify_resources()
    settings = scope.worker_config()
    had_cron = scope.cron_enabled()
    deployment = scope.active()
    try:
        active = scope.version(deployment.version, page_jump_epoch=stage["epoch"])
    except CloudflareError:
        active = scope.version(deployment.version)
    active_pin = _digest({"scope": target, "deployment": asdict(deployment), "version": asdict(active)})
    if active.telegram_page_jump_epoch is None:
        _require(active_pin == stage["checkpoint"]["activeSha256"], "The isolated dormant predecessor differs from the stage.")
    else:
        _require(_digest({"versionId": deployment.version, "version": asdict(active)}) == stage["candidateSha256"],
                 "The isolated active page-jump version differs from the stage.")
    _require(telegram_config is not None and sha256(telegram_config.encode("utf-8")).hexdigest() == active.telegram_config_sha256,
             "The isolated Telegram policy differs from the staged release.")
    control = PageJumpControl(scope, json.loads(telegram_config)["botId"])

    def current_release():
        guard()
        return (scope.active() == deployment and scope.version(deployment.version, page_jump_epoch=active.telegram_page_jump_epoch) == active
                and scope.worker_config() == settings and scope.cron_enabled() == had_cron)

    if paused is None:
        # The stage's unique run ID identifies the old epoch. Its allocator floor may
        # have advanced if open committed before this pause reached D1.
        gate = control.pause(PageJumpGate(stage["epoch"], False, 0), run_id, current_release)
    else:
        _require(active_pin == paused["activeSha256"], "The isolated deployment changed after page-jump pause.")
        gate = control.observe().gate
        _require(gate is not None and gate.epoch == paused["epoch"] and not gate.enabled
                 and _digest(_gate_document(gate)) == paused["pausedGateSha256"], "The isolated paused gate changed.")
        control.verify_drained(gate, current_release)
    return {"version": 1, "phase": "paused" if paused is None else "drained", "revision": revision,
            **{key: stage[key] for key in STAGE_BUILD_FIELDS}, "operationRunId": run_id, "operationRunAttempt": attempt,
            "stage": sources["stage"], "epoch": gate.epoch, "activeSha256": active_pin, "pausedGateSha256": _digest(_gate_document(gate)),
            **({"pause": sources["pause"]} if paused is not None else {})}
