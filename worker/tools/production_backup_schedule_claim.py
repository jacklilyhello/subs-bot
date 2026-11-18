"""Read-only preparation for one independently protected scheduled backup slot.

Claiming is deliberately disabled until its complete guarded write path and
request budget have passed review and hosted validation. No production
authority is created or inferred by this module.
"""
import time
from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory

import production_backup_coordinator as coordinator
import production_backup_schedule as schedule
import production_backup_schedule_terminal as terminal
import production_backup_transaction as transaction
import scoped_r2
from production_storage import PrivateStore
from production_target import canonical, require, validate_target


def _source_original(env, target, authority):
    """Read the exact sealed source through the independent D1 read credential."""
    from production_release_evidence import load_release

    root = Path(env.get("RUNNER_TEMP", ""))
    token = env.get("SUBS_BOT_CF_BACKUP_MONITOR_READ_TOKEN", "")
    require(isinstance(token, str) and token and root.is_absolute() and root.is_dir()
            and not root.is_symlink() and root.resolve() == root)
    with TemporaryDirectory(prefix="subs-bot-scheduled-source-", dir=root) as directory:
        saved = load_release(target, token, authority["sourceCheckpointId"], authority["sourceManifestSha256"], Path(directory))
        require(saved["sourceTarget"].digest == target.digest
                and saved["sourceTarget"].configuration_digest == target.configuration_digest
                and saved["proof"].get("revision") == saved["manifest"].get("revision") == authority["sourceRevision"])
        return {"targetSha256": target.digest, "configurationSha256": target.configuration_digest,
                "sourceCheckpointId": authority["sourceCheckpointId"], "sourceManifestSha256": authority["sourceManifestSha256"],
                "sourceRevision": authority["sourceRevision"]}


def plan_start(env, target, objects, app_store, scope_anchor, target_anchor, policy, authority, authority_sha256, token):
    """Observe one due slot and its full immutable predecessor evidence."""
    require(validate_target(target.data) == target and target.environment == "production"
            and type(objects) is scoped_r2.ScopedR2 and objects.bucket == target.data["backupBucketName"]
            and objects.host == target.account_id + ".r2.cloudflarestorage.com"
            and type(app_store) is PrivateStore and app_store.bucket == target.data["backupBucketName"]
            and app_store.api.target == target.data and type(scope_anchor) is coordinator.ScheduleScopeAnchor
            and type(scope_anchor.store) is coordinator.CoordinatorStore and scope_anchor.store.objects is objects
            and scope_anchor.target_sha256 == schedule.logical_scope(target)
            and scope_anchor.bucket_name == target.data["backupBucketName"]
            and scope_anchor.bucket_created_at == target.data["backupBucketCreatedAt"]
            and type(target_anchor) is transaction.Anchor and type(target_anchor.store) is coordinator.CoordinatorStore
            and target_anchor.store.objects is objects and target_anchor.target_sha256 == target.digest
            and isinstance(policy, dict) and isinstance(authority, dict)
            and env.get("SUBS_BOT_PRODUCTION_BACKUP_SCHEDULE_ENABLED") == "true"
            and env.get("SUBS_BOT_PRODUCTION_BACKUP_SCHEDULE_AUTHORITY_JSON") == canonical(authority).decode()
            and env.get("SUBS_BOT_PRODUCTION_BACKUP_SCHEDULE_AUTHORITY_SHA256") == authority_sha256)
    revision = env.get("GITHUB_SHA", "")
    verified = schedule.authority_document(canonical(authority), authority_sha256, target=target,
        control_revision=revision, source_revision=authority.get("sourceRevision"),
        source_checkpoint_id=authority.get("sourceCheckpointId"), source_manifest_sha256=authority.get("sourceManifestSha256"),
        policy=policy, target_genesis_sha256=env.get("SUBS_BOT_BACKUP_COORDINATOR_GENESIS_SHA256", ""),
        application_genesis_sha256=env.get("SUBS_BOT_BACKUP_GENESIS_SHA256", ""))
    require(verified == authority and scope_anchor.genesis_sha256 == authority["ledgerGenesisSha256"]
            == env.get("SUBS_BOT_BACKUP_SCHEDULE_SCOPE_GENESIS_SHA256")
            and target_anchor.genesis_sha256 == authority["targetCoordinatorGenesisSha256"])
    day = schedule.eligible_slot(authority, policy, int(time.time()))
    if day is None:
        return {"version": 1, "status": "not-due", "mutationAuthorized": False}
    require(coordinator.verify_context(env) == revision)
    source_review = coordinator.scheduled_source_review(env, revision)
    source = _source_original(env, target, authority)
    app_store.verify()
    app_anchor = transaction.Anchor(app_store, target.digest, authority["applicationGenesisSha256"])
    app, app_raw, _ = app_anchor.read()
    scope, scope_raw, _ = scope_anchor.read()
    target_pointer, target_raw, _ = target_anchor.read()
    require(app["state"] == scope["state"] == target_pointer["state"] == "idle",
            "An active backup or coordination anchor requires explicit reconciliation.")
    history = terminal.verify_prior_history(objects, app_store, target, scope_anchor, token, env, authority_sha256,
        authority["applicationGenesisSha256"], authority["targetCoordinatorGenesisSha256"], policy)
    require(history["historyCount"] < 200 and history["authorityExecutions"] < authority["maxExecutions"]
            and not history["readerLogStopRequired"])
    session = env.get("GITHUB_RUN_ID", "")
    material = coordinator.scheduled_start_material(target, policy, authority, authority_sha256, day, session,
                                                      scope, scope_raw, target_pointer, target_raw)
    # A prior slot or orphan is unknown, even if this process did not create it.
    for key in (schedule.scope_start_key(authority["scopeSha256"], session),
                coordinator.BASE + target.digest + "/" + session + "/start-intent.json",
                schedule.slot_key(authority["scopeSha256"], day)):
        raw, _ = objects.get(key, absent=True)
        require(raw is None, "The scheduled slot already has evidence and cannot be dispatched again.")
    parent_job_id = coordinator.scheduled_running_parent(env, material["slot"], token)
    app_after, app_after_raw, _ = app_anchor.read()
    scope_after, scope_after_raw, _ = scope_anchor.read()
    target_after, target_after_raw, _ = target_anchor.read()
    require((app_after, app_after_raw) == (app, app_raw) and (scope_after, scope_after_raw) == (scope, scope_raw)
            and (target_after, target_after_raw) == (target_pointer, target_raw),
            "An anchor changed during scheduled preparation.")
    return {"version": 1, "status": "observed", "day": day, "targetSha256": target.digest,
            "authoritySha256": authority_sha256, "appAnchorSha256": sha256(app_raw).hexdigest(),
            "scopeAnchorSha256": sha256(scope_raw).hexdigest(), "targetAnchorSha256": sha256(target_raw).hexdigest(),
            "scopeKeysSha256": history["scopeKeysSha256"], "coordinatorKeysSha256": history["coordinatorKeysSha256"],
            "historyCount": history["historyCount"], "authorityExecutions": history["authorityExecutions"],
            "parentJobId": str(parent_job_id), "sourceReviewSha256": sha256(canonical(source_review)).hexdigest(),
            "sourceSha256": sha256(canonical(source)).hexdigest(),
            "materialSha256": sha256(canonical(material)).hexdigest(), "mutationAuthorized": False}


def claim_once(env, target, objects, app_store, scope_anchor, target_anchor, policy, authority, authority_sha256, token):
    """Reject writes until guarded claim, failure recovery and budget are reviewed."""
    require(False, "Scheduled scope claiming remains disabled pending complete guard and budget validation.")
