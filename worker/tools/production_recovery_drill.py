"""Actual registered-isolation rehearsal of the production recovery code path.

The caller supplies an already deployed, drained and frozen lifecycle controller
and the original verified CI ZIP. No fixed-dev recovery script is invoked.
"""

from __future__ import annotations

from copy import deepcopy
import os
from pathlib import Path
from secrets import token_hex
import tempfile

from production_control import _mutate_sql, rows
import production_recovery as recovery


def resume_parameters(raw):
    if raw in (None, ""):
        return None
    if isinstance(raw, str):
        try:
            raw = raw.encode("utf-8")
        except UnicodeError:
            raise recovery.RecoveryError() from None
    value = recovery.native.parsed(raw, 4096) if isinstance(raw, bytes) else raw
    recovery.require(isinstance(value, dict) and set(value) == {"version", "checkpointId", "manifestSha256", "journalSha256"}
                     and type(value["version"]) is int and value["version"] == 1
                     and recovery.matches(recovery.CHECKPOINT, value["checkpointId"])
                     and all(recovery.matches(recovery.DIGEST, value[key]) for key in ("manifestSha256", "journalSha256")),
                     "Recovery resumption requires the exact sealed G0 and independently read latest journal pins.")
    return deepcopy(value)


def resume_baseline(engine, pins):
    """Reconcile an owned G0 before claiming it; never capture or create targets."""
    pins = resume_parameters(pins)
    api, source, journal = engine.api, engine.source, engine.journal
    recovery.require(pins is not None and api.cohort == pins["checkpointId"]
                     and api.contract["purpose"] == "baseline" and "sessionId" not in api.contract
                     and journal.value is not None and not journal.poisoned and isinstance(journal.raw, bytes)
                     and recovery.digest(journal.raw) == pins["journalSha256"],
                     "The preserved G0 journal changed; no recovery resumption is authorized.")
    value = journal.value
    raw_value = recovery.native.parsed(journal.raw, recovery.native.JOURNAL_BYTES)
    recovery.require(recovery.canonical(raw_value.get("value")) == recovery.canonical(value)
                     and raw_value.get("generation") == journal.generation
                     and value.get("phase") in {"captured", "restoring-objects", "objects-restored", "imported", "verified"}
                     and isinstance(value.get("backup"), dict) and value["backup"].get("manifestSha256") == pins["manifestSha256"]
                     and value.get("scopeSha256") == source.scope_sha256
                     and set(value.get("resources", {})) == {"database", "objects"}
                     and all(isinstance(record, dict) and set(record) == {"pin", "intent"}
                             and isinstance(record.get("pin"), dict) and isinstance(record.get("intent"), dict)
                             and record["intent"].get("state") == "confirmed" for record in value["resources"].values()),
                     "Resumption requires the original sealed G0 and both confirmed immutable target pins.")
    source.verify(capture=False)
    engine.verify_resources(all_required=True)
    engine.verify_preservation()
    api.consumer_proof()
    source.before_write()
    # Claim only after all source, archive, ownership and no-consumer checks.
    journal.claim()
    return {"checkpointId": api.cohort, "manifestSha256": pins["manifestSha256"],
            "previousJournalSha256": pins["journalSha256"], "resourcePinsSha256": recovery.digest(recovery.canonical(value["resources"])),
            "captureRepeated": False, "resourcesCreated": False}


def safe_failure(error, action, api):
    recovery.require(action in {"resume-g0", "prepare", "capture", "verify-backup", "create-database", "create-objects",
                               "restore-objects", "start-import", "verify-restore", "prepare-restore"})
    result = {"action": action, "uncertain": bool(getattr(error, "uncertain", True))}
    status = getattr(error, "http_status", None)
    if type(status) is int and 100 <= status <= 599:
        result["httpStatus"] = status
    phase = getattr(api, "consumer_stage", None)
    if phase in {"services-list", "scripts-list", "script-settings", "service-environments", "service-settings"}:
        result["consumerPhase"] = phase
    return result


def timezone_fixture(controller):
    """Synthetic new write on the dedicated rehearsal D1; never a live-user test."""
    t, literal = controller.target.data, recovery.migrations._literal
    state = controller.inspect()
    recovery.require(t["environment"] == "rehearsal" and t["workerName"] == "subs-bot-cf-control-drill-01"
                     and state["control"]["admission"] == "closed" and state["control"]["workers"] == "frozen"
                     and not any(state["work"].values()))
    bot = literal(t["botId"])
    original = rows(controller.data, controller.database,
                    "SELECT * FROM telegram_bot_display_settings WHERE bot_id=" + bot)
    recovery.require(len(original) <= 1 and (not original or original[0]["timezone"] == "UTC"),
                     "The rehearsal timezone must be UTC before the identifiable recovery fixture.")
    controller.guard()
    if original:
        _mutate_sql(controller.data, controller.database,
                    ["UPDATE telegram_bot_display_settings SET timezone='Europe/London' WHERE bot_id=" + bot + " AND timezone='UTC'"])
    else:
        _mutate_sql(controller.data, controller.database, [
            "INSERT INTO telegram_bot_display_settings(bot_id,timezone,update_id,message_date,updated_by) VALUES("
            + bot + ",'Europe/London',1,1," + literal(t["admins"][0]) + ")"])
    recovery.require(rows(controller.data, controller.database,
        "SELECT timezone FROM telegram_bot_display_settings WHERE bot_id=" + bot) == [{"timezone": "Europe/London"}])

    def cleanup():
        current = controller.inspect()
        recovery.require(current["control"]["admission"] == "closed" and current["control"]["workers"] == "frozen"
                         and not any(current["work"].values()))
        controller.guard()
        _mutate_sql(controller.data, controller.database, [
            "UPDATE telegram_bot_display_settings SET timezone='UTC' WHERE bot_id=" + bot + " AND timezone='Europe/London'"])
        recovery.require(rows(controller.data, controller.database,
            "SELECT timezone FROM telegram_bot_display_settings WHERE bot_id=" + bot) == [{"timezone": "UTC"}])

    return cleanup


def run_recovery_drill(controller, archive_body, code_proof, data_token, *, mutate_current=timezone_fixture, evidence=None, resume=None):
    """Return safe counters/pins; any failed checkpoint raises, never reports success.

    The caller runs production-restored-links.ts for both fixed replay directory
    names after this function, using the no-egress hosted workflow sandbox.
    """
    env = os.environ
    target = controller.target
    recovery.require(target.environment == "rehearsal" and target.data["workerName"] == "subs-bot-cf-control-drill-01"
                     and env.get("RUNNER_ENVIRONMENT") == "github-hosted"
                     and env.get("GITHUB_REPOSITORY") == "jacklilyhello/subs-bot"
                     and env.get("GITHUB_REF") == "refs/heads/main",
                     "Recovery drill may only execute against the registered project rehearsal identity on a hosted runner.")
    recovery.require(isinstance(archive_body, bytes) and recovery.digest(archive_body) == code_proof.get("archiveSha256"))
    resume = resume_parameters(resume)
    root = Path(env["RUNNER_TEMP"])
    owner = env["GITHUB_RUN_ID"] + "/" + env["GITHUB_RUN_ATTEMPT"]
    report = {"version": 1, "status": "running", "targetSha256": target.digest, "stages": [],
              "newWriteKind": "synthetic-dedicated-rehearsal-timezone-fixture", "humanAcceptance": False,
              "sourceConsumerSwitch": False, "automaticReplay": False}

    def publish():
        if evidence is not None:
            evidence(deepcopy(report))

    def contract(purpose):
        checkpoint = token_hex(16)
        name = "subs-bot-cf-restore-control-" + checkpoint[:16]
        return {"version": 1, "checkpointId": checkpoint, "databaseName": name, "objectsName": name, "purpose": purpose}

    def setup(value):
        api = recovery.RecoveryAPI(target.data, data_token, controller.worker, value)
        source = recovery.RecoverySource(api, target.data, controller.bundle, controller.manifest, controller.inspect, controller.guard)
        source.archive_body, source.code_proof = archive_body, code_proof
        journal = recovery.RecoveryJournal(api, owner, guard=controller.guard)
        journal.load()
        return api, source, journal

    def run(action, context, *, validation=None):
        api, source, journal = context
        api.consumer_stage = None
        try:
            with tempfile.TemporaryDirectory(prefix="production-recovery-checkpoint-", dir=root) as temporary:
                engine = recovery.RecoveryEngine(api, source, journal, Path(temporary), validation_directory=validation)
                result = recovery.run_action(action, engine)
        except Exception as error:
            report["failure"] = safe_failure(error, action, api)
            raise
        report["stages"].append(result)
        publish()
        return result

    cleanup = None
    contexts = []
    try:
        if resume is not None:
            checkpoint = resume["checkpointId"]
            name = "subs-bot-cf-restore-control-" + checkpoint[:16]
            g0_contract = {"version": 1, "checkpointId": checkpoint, "databaseName": name, "objectsName": name, "purpose": "baseline"}
        else:
            g0_contract = contract("baseline")
        g0 = setup(g0_contract)
        contexts.append(g0)
        if resume is not None:
            try:
                with tempfile.TemporaryDirectory(prefix="production-recovery-resume-", dir=root) as temporary:
                    engine = recovery.RecoveryEngine(*g0[:2], g0[2], Path(temporary))
                    report["resumedFrom"] = resume_baseline(engine, resume)
            except Exception as error:
                report["failure"] = safe_failure(error, "resume-g0", g0[0])
                raise
            publish()
            initial = ("verify-backup", "restore-objects", "start-import")
        else:
            initial = ("prepare", "capture", "verify-backup", "create-database", "create-objects", "restore-objects", "start-import")
        for action in initial:
            run(action, g0)
        baseline = run("verify-restore", g0, validation=root / "production-recovery-drill-g0-links")
        recovery.require(baseline["backup"]["objectCount"] >= 1,
                         "The recovery drill requires referenced R2 fixture bytes; an empty-object backup is insufficient.")
        cleanup = mutate_current(controller)
        recovery.require(callable(cleanup), "The synthetic fixture must return an explicit settings cleanup.")
        # Reuse of the old baseline after a new write is refused before target I/O.
        stale_rejected = False
        with tempfile.TemporaryDirectory(prefix="production-recovery-stale-", dir=root) as temporary:
            stale = recovery.RecoveryEngine(*g0[:2], g0[2], Path(temporary))
            g0[1].verify(capture=False)
            try:
                stale.before_target_write()
            except recovery.RecoveryError:
                stale_rejected = True
        recovery.require(stale_rejected, "A stale baseline unexpectedly passed the source preservation gate.")
        report["staleBaselineRejected"] = True
        g1_contract = contract("incident")
        g1 = setup(g1_contract)
        contexts.append(g1)
        for action in ("prepare", "capture", "verify-backup"):
            incident = run(action, g1)
        recovery.require(incident["backup"]["dataSha256"] != baseline["backup"]["dataSha256"],
                         "The G1 drill did not preserve an actual data change.")
        session = token_hex(16)
        name = "subs-bot-cf-restore-control-" + session[:16]
        recovery_contract = {**g0_contract, "purpose": "recovery", "databaseName": name, "objectsName": name,
            "sessionId": session, "sourceManifestSha256": baseline["backup"]["manifestSha256"],
            "preservedG1": {"checkpointId": g1_contract["checkpointId"], "manifestSha256": incident["backup"]["manifestSha256"]}}
        missing = {key: value for key, value in recovery_contract.items() if key != "preservedG1"}
        try:
            recovery.recovery_contract(recovery.canonical(missing), target.data)
        except recovery.RecoveryError:
            report["missingG1Rejected"] = True
        recovery.require(report.get("missingG1Rejected"))
        # A wrong G1 digest is tested against actual private R2, before creating
        # a session journal or any destination resources.
        bad = deepcopy(recovery_contract)
        bad["preservedG1"]["manifestSha256"] = "0" * 64
        bad_context = setup(bad)
        with tempfile.TemporaryDirectory(prefix="production-recovery-wrong-g1-", dir=root) as temporary:
            engine = recovery.RecoveryEngine(*bad_context[:2], bad_context[2], Path(temporary))
            bad_context[1].verify(capture=False)
            try:
                engine.prepare_restore()
            except recovery.RecoveryError:
                report["wrongG1Rejected"] = bad_context[2].value is None
        recovery.require(report.get("wrongG1Rejected"))
        restored = setup(recovery_contract)
        contexts.append(restored)
        for action in ("prepare-restore", "create-database", "create-objects", "restore-objects", "start-import"):
            run(action, restored)
        final = run("verify-restore", restored, validation=root / "production-recovery-drill-recovered-links")
        recovery.require(final["restoredDataSha256"] == baseline["backup"]["dataSha256"]
                         and controller.inspect()["control"]["admission"] == "closed")
        report.update(baselineCheckpointId=g0_contract["checkpointId"],
            baselineManifestSha256=baseline["backup"]["manifestSha256"],
            preservedG1CheckpointId=g1_contract["checkpointId"], preservedG1ManifestSha256=incident["backup"]["manifestSha256"],
            recoverySessionId=session, restoredDataSha256=final["restoredDataSha256"],
            newWritesPreservedInG1=True, privateR2CodeArchive=True)
        module = root / "production-recovery-drill-module"
        module.mkdir(mode=0o700)
        with recovery.native.private_file(module / "index.js") as stream:
            stream.write((controller.bundle / "index.js").read_bytes())
        cleanup()
        cleanup = None
        report.update(status="recovery-verified-http-pending", effectiveTimezoneRestored="UTC", httpReplay="pending-hosted-no-egress-step")
        publish()
        return report
    except Exception:
        report["status"] = "stopped"
        publish()
        raise
    finally:
        if cleanup is not None:
            cleanup()
        for _api, _source, journal in contexts:
            journal.release()
