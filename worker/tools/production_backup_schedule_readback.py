"""Independent private witness for one completed scheduled backup."""
from hashlib import sha256
import os

import prepare_isolation_artifact as artifact
import production_backup_cli as backup
import production_backup_coordinator as coordinator
import production_backup_schedule as schedule
import production_backup_schedule_terminal as terminal
import production_backup_transaction as maintenance
from production_target import canonical, parsed, require, validate_target
from production_control import API, privacy
from production_storage import PrivateStore
import scoped_r2


def write_witness(env, target, objects, app_store, scope_anchor, target_anchor, slot, token):
    """Read the complete evidence on a fresh runner, then write one fixed witness."""
    require(target.environment == "production" and type(objects) is scoped_r2.ScopedR2
            and objects.bucket == target.data["backupBucketName"]
            and objects.host == target.account_id + ".r2.cloudflarestorage.com" and isinstance(slot, dict)
            and slot.get("targetSha256") == target.digest and slot.get("session") == slot.get("writerRunId")
            and slot.get("writerAttempt") == "1"
            and type(scope_anchor) is coordinator.ScheduleScopeAnchor and type(target_anchor) is maintenance.Anchor
            and scope_anchor.target_sha256 == schedule.logical_scope(target)
            and scope_anchor.store.objects is objects and target_anchor.store.objects is objects
            and scope_anchor.bucket_name == target.data["backupBucketName"]
            and scope_anchor.bucket_created_at == target.data["backupBucketCreatedAt"]
            and target_anchor.target_sha256 == target.digest and objects.write_credential is not None)
    continuation = coordinator.scheduled_continuation(objects, slot)
    writer_id = slot["writerRunId"] if continuation is None else continuation["writerRunId"]
    require(writer_id == env.get("GITHUB_RUN_ID"))
    def verify_parent():
        if continuation is None:
            return coordinator.verify_scheduled_parent(env, slot, mode="fresh-reader")
        require(coordinator.scheduled_continuation(objects, slot) == continuation)
        return coordinator.verify_scheduled_parent(env, slot, mode="fresh-reader", continuation=continuation)
    authority, pin = slot["authority"], slot["authoritySha256"]
    require(env.get("SUBS_BOT_PRODUCTION_BACKUP_SCHEDULE_AUTHORITY_SHA256") == pin
            and backup.settings(env.get("SUBS_BOT_BACKUP_POLICY_JSON", "")) == slot["policy"])
    fresh = schedule.authority_document(env.get("SUBS_BOT_PRODUCTION_BACKUP_SCHEDULE_AUTHORITY_JSON", ""), pin,
        target=target, control_revision=env.get("GITHUB_SHA", ""), source_revision=authority["sourceRevision"],
        source_checkpoint_id=authority["sourceCheckpointId"], source_manifest_sha256=authority["sourceManifestSha256"],
        policy=slot["policy"], target_genesis_sha256=env.get("SUBS_BOT_BACKUP_COORDINATOR_GENESIS_SHA256", ""),
        application_genesis_sha256=env.get("SUBS_BOT_BACKUP_GENESIS_SHA256", ""))
    require(fresh == authority and authority["ledgerGenesisSha256"] == scope_anchor.genesis_sha256
            == env.get("SUBS_BOT_BACKUP_SCHEDULE_SCOPE_GENESIS_SHA256")
            and authority["targetCoordinatorGenesisSha256"] == target_anchor.genesis_sha256)
    schedule.read_slot(objects, authority, pin, slot["slotDay"], slot)
    terminal_raw, _ = objects.get(schedule.terminal_key(slot["scopeSha256"], slot["slotDay"]), limit=terminal.MAX_RECORD)
    done = parsed(terminal_raw)
    require(canonical(done) == terminal_raw and done == schedule.terminal_record(slot,
        chain_sha256=done.get("chainSha256"), scope_idle_anchor_sha256=done.get("scopeIdleAnchorSha256"),
        coordinator_idle_anchor_sha256=done.get("coordinatorIdleAnchorSha256"), result=done.get("result")))

    def verify_anchors():
        scope_value, scope_raw, _ = scope_anchor.read()
        target_value, target_raw, _ = target_anchor.read()
        require(scope_value.get("state") == target_value.get("state") == "idle"
                and sha256(scope_raw).hexdigest() == done["scopeIdleAnchorSha256"]
                and sha256(target_raw).hexdigest() == done["coordinatorIdleAnchorSha256"]
                and terminal._coordinator_release(scope_anchor, slot["session"], slot["slotDay"].replace("-", "/"),
                    env["GITHUB_SHA"], slot["scopeAnchorSha256"]) == done["scopeIdleAnchorSha256"]
                and terminal._coordinator_release(target_anchor, slot["session"], slot["slotDay"].replace("-", "/"),
                    env["GITHUB_SHA"], slot["coordinatorAnchorSha256"]) == done["coordinatorIdleAnchorSha256"])

    verify_anchors()
    parent = verify_parent()
    review, review_pin = coordinator.scheduled_review_document(env)
    parent["sourceReview"] = coordinator.scheduled_source_review(env, env["GITHUB_SHA"])
    require(parent["sourceReview"].get("reviewSha256") == review_pin)
    phase = terminal.collect_phase_evidence(objects, target, slot, token)
    require(terminal.verify_phase_evidence(objects, target, slot, phase) == done["chainSha256"])
    app = terminal.collect_app_terminal(objects, app_store, target, slot, phase, authority["applicationGenesisSha256"])
    witness = {"version": 1, "kind": "scheduled-backup-independent-witness", "scopeSha256": slot["scopeSha256"],
        "targetSha256": target.digest, "slotDay": slot["slotDay"], "session": slot["session"],
        "slotSha256": sha256(canonical(slot)).hexdigest(), "terminalSha256": sha256(terminal_raw).hexdigest(),
        "reviewSha256": sha256(canonical(review)).hexdigest(), "review": review, "parent": parent,
        "phaseEvidence": phase, "appTerminal": app}
    body = canonical(witness)
    require(0 < len(body) <= terminal.MAX_WITNESS)
    key = terminal.witness_key(slot["scopeSha256"], slot["slotDay"])
    before, _ = objects.get(key, absent=True)
    require(before is None, "An existing witness requires independent inspection, not another write.")
    import time
    rate = coordinator.bootstrap_rate_limit(token)
    core = rate.get("resources", {}).get("core", {})
    # The final three GH reads may each use the standard reader's bounded
    # three attempts; leave a further 100 requests for concurrent use.
    require(type(core.get("remaining")) is int and core["remaining"] >= 109
            and type(core.get("reset")) is int and core["reset"] > int(time.time()),
            "Insufficient GitHub read quota for independent witness creation.")
    verify_anchors()
    require(verify_parent() == {key: value for key, value in parent.items() if key != "sourceReview"}
            and terminal.collect_app_terminal(objects, app_store, target, slot, phase, authority["applicationGenesisSha256"]) == app,
            "The independently observed parent or transaction changed before witness creation.")
    terminal_again, _ = objects.get(schedule.terminal_key(slot["scopeSha256"], slot["slotDay"]), limit=terminal.MAX_RECORD)
    require(terminal_again == terminal_raw, "The scheduled terminal changed before witness creation.")
    objects.put_once(key, body)
    observed, _ = objects.get(key, limit=terminal.MAX_WITNESS)
    require(observed == body, "The exact independent witness was not read back.")
    witness_sha = sha256(body).hexdigest()
    print("SCHEDULE_WITNESS_SHA256=" + witness_sha, flush=True)
    return {"status": "confirmed", "witnessSha256": witness_sha}


def main(env=None):
    env = os.environ if env is None else env
    revision = coordinator.verify_context(env)
    require(env.get("GITHUB_EVENT_NAME") in {"schedule", "workflow_dispatch"} and env.get("SCHEDULE_READBACK_MODE") == "fresh")
    target = validate_target(env.get("SUBS_BOT_TARGET_JSON", ""))
    require(target.environment == "production")
    metadata = API(target, env.get("SUBS_BOT_CF_R2_METADATA_READ_TOKEN", ""))
    privacy(metadata, metadata.root, target.data["backupBucketName"], target.data["backupBucketCreatedAt"])
    objects = scoped_r2.from_environment(target.account_id, target.data["backupBucketName"], env)
    require(objects is not None and objects.write_credential is not None)
    scope = schedule.logical_scope(target)
    day = env.get("SCHEDULE_SLOT_DAY", "")
    raw, _ = objects.get(schedule.slot_key(scope, day), limit=terminal.MAX_RECORD)
    slot = parsed(raw)
    require(canonical(slot) == raw)
    scope_anchor = coordinator.ScheduleScopeAnchor(coordinator.CoordinatorStore(objects, scope), scope,
        env.get("SUBS_BOT_BACKUP_SCHEDULE_SCOPE_GENESIS_SHA256", ""), target.data["backupBucketName"], target.data["backupBucketCreatedAt"])
    target_anchor = maintenance.Anchor(coordinator.CoordinatorStore(objects, target.digest), target.digest,
                                       env.get("SUBS_BOT_BACKUP_COORDINATOR_GENESIS_SHA256", ""))
    app_store = PrivateStore(metadata, target.data["backupBucketName"])
    app_store.objects = objects
    return write_witness(env, target, objects, app_store,
                         scope_anchor, target_anchor, slot, artifact._github_token())


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("::error::The independent scheduled-backup witness is unconfirmed; retain its private evidence.")
        raise SystemExit(1) from None
