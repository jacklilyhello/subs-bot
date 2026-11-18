"""One-shot claim for an independently protected production backup slot.

The workflow is opt-in. This module never creates, infers or extends production authority.
"""
import time
import re
from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory

import production_backup_coordinator as coordinator
import production_backup_cli as backup
import prepare_isolation_artifact as github
import production_backup_schedule as schedule
import production_backup_schedule_terminal as terminal
import production_backup_transaction as transaction
import scoped_r2
from production_storage import PrivateStore
from production_target import canonical, require, validate_target


class _BoundedAnchorReadCache:
    """Re-read inventory and pointer; retain only content-addressed history bytes."""
    def __init__(self, store, target_sha256):
        self.store, self.target_sha256, self.cache = store, target_sha256, {}

    def get(self, key, *, absent=False):
        prefix = "maintenance/production-control/evidence/daily-backup-anchor/" + self.target_sha256 + "/"
        match = re.fullmatch(re.escape(prefix) + r"[0-9]{12}-([a-f0-9]{64})\.json", key or "")
        if match is None:
            return self.store.get(key, absent=absent)
        if key not in self.cache:
            raw = self.store.get(key, absent=absent)
            if raw is None:
                return None
            require(isinstance(raw, bytes) and sha256(raw).hexdigest() == match.group(1))
            self.cache[key] = raw
        raw = self.cache[key]
        require(isinstance(raw, bytes) and sha256(raw).hexdigest() == match.group(1))
        return raw

    def get_with_etag(self, key):
        return self.store.get_with_etag(key)

    def list_backup_anchor_history(self, target_sha256):
        require(target_sha256 == self.target_sha256)
        keys = self.store.list_backup_anchor_history(target_sha256)
        require(isinstance(keys, list) and len(keys) <= 401 and len(keys) == len(set(keys)),
                "The fixed anchor history limit was exceeded.")
        return keys


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
    app_store.verify()
    app_anchor = transaction.Anchor(app_store, target.digest, authority["applicationGenesisSha256"])
    app, app_raw, _ = app_anchor.read()
    scope, scope_raw, _ = scope_anchor.read()
    target_pointer, target_raw, _ = target_anchor.read()
    require(app["state"] == scope["state"] == target_pointer["state"] == "idle",
            "An active backup or coordination anchor requires explicit reconciliation.")
    history = terminal.verify_prior_history(objects, app_store, target, scope_anchor, token, env, authority_sha256,
        authority["applicationGenesisSha256"], authority["targetCoordinatorGenesisSha256"], policy)
    if history.get("readerLogExpiryWarning"):
        print("::warning::A required original backup reader log is approaching its retention deadline.", flush=True)
    if history.get("rotationWarning"):
        print("::warning::The project backup history is approaching its reviewed capacity.", flush=True)
    # The */15 trigger can observe the same date more than once. Only the
    # full prior-history proof can classify an existing date as satisfied.
    slot_key = schedule.slot_key(authority["scopeSha256"], day)
    raw_slot, _ = objects.get(slot_key, absent=True)
    if raw_slot is not None:
        require(slot_key in history["scopeKeys"]
                and terminal.witness_key(authority["scopeSha256"], day) in history["scopeKeys"],
                "The current slot is not independently complete; inspect its original evidence.")
        return {"version": 1, "status": "not-due", "mutationAuthorized": False}
    require(history["historyCount"] < 200 and history["authorityExecutions"] < authority["maxExecutions"]
            and not history["readerLogStopRequired"],
            "Scheduled execution or history limit reached; no new slot was claimed.")
    source = _source_original(env, target, authority)
    from production_backup_live_capacity import alerts, sample
    capacity = sample(target, env.get("SUBS_BOT_CF_BACKUP_MONITOR_READ_TOKEN", ""), authority["sourceCheckpointId"],
                      authority["sourceManifestSha256"], warning_percent=policy["warningPercent"],
                      root=env["RUNNER_TEMP"], guard=lambda: github.require_current_main(revision), require_open=True)
    for alert in alerts(capacity):
        print("::warning::" + alert, flush=True)
    backup.capacity.require_within_limits(capacity)
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
    """Claim one pre-reviewed slot; every uncertain write stops without replay."""
    from production_backup_fresh_github import FreshConditionalJSON

    plan = plan_start(env, target, objects, app_store, scope_anchor, target_anchor,
                      policy, authority, authority_sha256, token)
    if plan["status"] == "not-due":
        return plan
    require(plan["status"] == "observed" and plan["mutationAuthorized"] is False
            and token == github._github_token() and objects.write_credential is not None
            and type(app_store.objects) is scoped_r2.ScopedR2
            and app_store.objects.bucket == objects.bucket and app_store.objects.host == objects.host
            and backup.settings(env.get("SUBS_BOT_BACKUP_POLICY_JSON", "")) == policy)
    scope, scope_raw, _ = scope_anchor.read()
    current, target_raw, _ = target_anchor.read()
    app_anchor = transaction.Anchor(_BoundedAnchorReadCache(app_store, target.digest), target.digest,
                                    authority["applicationGenesisSha256"])
    scope_reader = coordinator.ScheduleScopeAnchor(_BoundedAnchorReadCache(scope_anchor.store, scope_anchor.target_sha256),
        scope_anchor.target_sha256, scope_anchor.genesis_sha256, scope_anchor.bucket_name, scope_anchor.bucket_created_at)
    target_reader = transaction.Anchor(_BoundedAnchorReadCache(target_anchor.store, target.digest), target.digest,
                                       target_anchor.genesis_sha256)
    app, app_raw, _ = app_anchor.read()
    require(all(node["state"] == "idle" for node in (scope, current, app))
            and sha256(scope_raw).hexdigest() == plan["scopeAnchorSha256"]
            and sha256(target_raw).hexdigest() == plan["targetAnchorSha256"]
            and sha256(app_raw).hexdigest() == plan["appAnchorSha256"])
    day, session = plan["day"], env["GITHUB_RUN_ID"]
    material = coordinator.scheduled_start_material(target, policy, authority, authority_sha256, day, session,
                                                     scope, scope_raw, current, target_raw)
    require(sha256(canonical(material)).hexdigest() == plan["materialSha256"])
    slot, scope_start, target_start = material["slot"], material["scopeStart"], material["targetStart"]
    scope_active, target_active = canonical(material["scopeActive"]), canonical(material["targetActive"])
    scope_key = schedule.scope_start_key(authority["scopeSha256"], session)
    target_key = coordinator.BASE + target.digest + "/" + session + "/start-intent.json"
    slot_key = schedule.slot_key(authority["scopeSha256"], day)
    scope_history = scope_anchor.history_key(material["scopeActive"]["generation"], scope_active)
    target_history = target_anchor.history_key(material["targetActive"]["generation"], target_active)
    scope_history_key = scope_anchor.store._key(scope_history)
    target_history_key = target_anchor.store._key(target_history)
    scope_prefix = schedule.BASE + authority["scopeSha256"] + "/"
    scope_keys = objects.list(scope_prefix, maximum=10000)
    coordinator_keys = objects.list(coordinator.BASE, maximum=10000)
    require(len(scope_keys) < 10000 and len(coordinator_keys) < 10000
            and len(scope_keys) == len(set(scope_keys)) and len(coordinator_keys) == len(set(coordinator_keys))
            and sha256(canonical(sorted(scope_keys))).hexdigest() == plan["scopeKeysSha256"]
            and sha256(canonical(sorted(coordinator_keys))).hexdigest() == plan["coordinatorKeysSha256"]
            and not set((scope_key, slot_key)).intersection(scope_keys)
            and not set((target_key, scope_history_key, target_history_key)).intersection(coordinator_keys))
    parent_id = int(plan["parentJobId"])
    require(parent_id > 0 and coordinator.scheduled_running_parent(env, slot, token) == parent_id)
    # Seven single-write guards, one final verification, then the owner's own
    # main/job guard: each uses at most two actual GH requests, even for 304.
    quota = coordinator.bootstrap_rate_limit(token).get("resources", {}).get("core", {})
    require(type(quota.get("remaining")) is int and quota["remaining"] >= 118
            and type(quota.get("reset")) is int and quota["reset"] > int(time.time()),
            "Insufficient GitHub quota for the guarded scope claim; no write was attempted.")
    client = FreshConditionalJSON()
    expected_scope_keys, expected_coordinator_keys = set(scope_keys), set(coordinator_keys)
    expected_scope, expected_target = scope_raw, target_raw
    written = {}

    def guard():
        require(env.get("SUBS_BOT_PRODUCTION_BACKUP_SCHEDULE_ENABLED") == "true"
                and env.get("SUBS_BOT_PRODUCTION_BACKUP_SCHEDULE_AUTHORITY_JSON") == canonical(authority).decode()
                and env.get("SUBS_BOT_PRODUCTION_BACKUP_SCHEDULE_AUTHORITY_SHA256") == authority_sha256
                and sha256(canonical(authority)).hexdigest() == authority_sha256
                and validate_target(target.data) == target and target.environment == "production"
                and target.digest == authority["targetSha256"]
                and target.configuration_digest == authority["configurationSha256"]
                and backup.settings(env.get("SUBS_BOT_BACKUP_POLICY_JSON", "")) == policy
                and schedule.eligible_slot(authority, policy, int(time.time())) == day
                and _source_original(env, target, authority) == {"targetSha256": target.digest,
                    "configurationSha256": target.configuration_digest,
                    "sourceCheckpointId": authority["sourceCheckpointId"],
                    "sourceManifestSha256": authority["sourceManifestSha256"], "sourceRevision": authority["sourceRevision"]},
                "The approved scheduled source or time window changed.")
        app_store.verify()
        a, raw_a, _ = app_anchor.read()
        s, raw_s, s_etag = scope_reader.read(allow_future=True)
        t, raw_t, t_etag = target_reader.read(allow_future=True)
        require(a == app and raw_a == app_raw and raw_s == expected_scope and raw_t == expected_target
                and s == (scope if expected_scope == scope_raw else material["scopeActive"])
                and t == (current if expected_target == target_raw else material["targetActive"]),
                "A scheduled claim predecessor changed.")
        scope_now = objects.list(scope_prefix, maximum=10000)
        coordinator_now = objects.list(coordinator.BASE, maximum=10000)
        require(len(scope_now) < 10000 and len(coordinator_now) < 10000
                and len(scope_now) == len(set(scope_now)) and len(coordinator_now) == len(set(coordinator_now))
                and set(scope_now) == expected_scope_keys and set(coordinator_now) == expected_coordinator_keys,
                "A scheduled claim inventory changed or has an unconfirmed candidate.")
        for key, body in written.items():
            require(objects.get(key)[0] == body, "A scheduled claim original changed.")
        # Check liveness after potentially lengthy R2/source inspection, as
        # close as possible to the next single conditional write.
        backup.scheduled_main_guard(env["GITHUB_SHA"], client)
        client.get("/actions/jobs/" + str(parent_id),
                   verify=lambda value: coordinator.scheduled_running_job(value, session, env["GITHUB_SHA"], parent_id))
        require(schedule.eligible_slot(authority, policy, int(time.time())) == day
                and env.get("SUBS_BOT_PRODUCTION_BACKUP_SCHEDULE_ENABLED") == "true")
        return s_etag, t_etag

    def put(key, body, *, scope_object):
        guard()
        objects.put_once(key, body)
        require(objects.get(key)[0] == body, "A one-shot claim write was not independently confirmed.")
        written[key] = body
        (expected_scope_keys if scope_object else expected_coordinator_keys).add(key)

    put(scope_key, canonical(scope_start), scope_object=True)
    put(target_key, canonical(target_start), scope_object=False)
    put(scope_history_key, scope_active, scope_object=False)
    scope_etag, _ = guard()
    scope_anchor.store.compare_and_put(scope_anchor.key, scope_raw, scope_etag, scope_active)
    expected_scope = scope_active
    require(scope_anchor.read()[1] == scope_active, "The project scope claim was not confirmed.")
    put(target_history_key, target_active, scope_object=False)
    _, target_etag = guard()
    target_anchor.store.compare_and_put(target_anchor.key, target_raw, target_etag, target_active)
    expected_target = target_active
    require(target_anchor.read()[1] == target_active, "The target scope claim was not confirmed.")
    put(slot_key, canonical(slot), scope_object=True)
    guard()
    owner = coordinator.ScheduledScopeOwner(env, target, objects, scope_anchor, target_anchor,
                                             material, sorted(expected_scope_keys), parent_id)
    owner.guard()
    return owner


def protected_authority(env, target, policy):
    """Load the configured production authority and immutable source pins."""
    raw = env.get("SUBS_BOT_PRODUCTION_BACKUP_SCHEDULE_AUTHORITY_JSON", "")
    pin = env.get("SUBS_BOT_PRODUCTION_BACKUP_SCHEDULE_AUTHORITY_SHA256", "")
    supplied = coordinator.parsed(raw)
    require(isinstance(supplied, dict) and env.get("SUBS_BOT_PRODUCTION_BACKUP_SCHEDULE_ENABLED") == "true")
    authority = schedule.authority_document(raw, pin, target=target, control_revision=env["GITHUB_SHA"],
        source_revision=supplied.get("sourceRevision", ""),
        source_checkpoint_id=env.get("BACKUP_SOURCE_CHECKPOINT_ID", ""),
        source_manifest_sha256=env.get("BACKUP_SOURCE_MANIFEST_SHA256", ""), policy=policy,
        target_genesis_sha256=env.get("SUBS_BOT_BACKUP_COORDINATOR_GENESIS_SHA256", ""),
        application_genesis_sha256=env.get("SUBS_BOT_BACKUP_GENESIS_SHA256", ""))
    require(authority["ledgerGenesisSha256"] == env.get("SUBS_BOT_BACKUP_SCHEDULE_SCOPE_GENESIS_SHA256"))
    return authority, pin


def run_scheduled(env, target, objects, app_store, target_anchor, policy, token):
    """Claim and drive one due slot. A stalled writer leaves its evidence intact."""
    require(env.get("GITHUB_EVENT_NAME") == "schedule" and env.get("BACKUP_COORDINATOR_ACTION") == "scheduled-run")
    authority, pin = protected_authority(env, target, policy)
    scope = authority["scopeSha256"]
    anchor = coordinator.ScheduleScopeAnchor(coordinator.CoordinatorStore(objects, scope), scope,
        authority["ledgerGenesisSha256"], target.data["backupBucketName"], target.data["backupBucketCreatedAt"])
    owner = claim_once(env, target, objects, app_store, anchor, target_anchor, policy, authority, pin, token)
    if isinstance(owner, dict):
        require(owner.get("status") == "not-due")
        return owner
    return run_owned_schedule(owner, app_store, token)


def run_owned_schedule(owner, app_store, token):
    """Use the fixed phase engine and publish only a verified terminal."""
    slot, env = owner.material["slot"], owner.env
    policy, authority = slot["policy"], slot["authority"]
    coordinator.run_sequence(owner.objects, owner.target_anchor, owner.target.digest, slot["session"], env["GITHUB_SHA"],
        authority["sourceCheckpointId"], authority["sourceManifestSha256"], token,
        deadline=time.monotonic() + 5 * 3600, pause_limit=backup.maximum_pause(policy),
        pause_alarm_seconds=policy["pauseLimitSeconds"], writer_run_id=env["GITHUB_RUN_ID"], scope_owner=owner)
    return coordinator.finish_scheduled_sequence(owner, app_store, token)
