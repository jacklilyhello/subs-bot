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


def run_recovery_drill(controller, archive_body, code_proof, data_token, *, mutate_current=timezone_fixture, evidence=None):
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
        with tempfile.TemporaryDirectory(prefix="production-recovery-checkpoint-", dir=root) as temporary:
            engine = recovery.RecoveryEngine(api, source, journal, Path(temporary), validation_directory=validation)
            result = recovery.run_action(action, engine)
        report["stages"].append(result)
        publish()
        return result

    cleanup = None
    contexts = []
    try:
        g0_contract = contract("baseline")
        g0 = setup(g0_contract)
        contexts.append(g0)
        for action in ("prepare", "capture", "verify-backup", "create-database", "create-objects", "restore-objects", "start-import"):
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
