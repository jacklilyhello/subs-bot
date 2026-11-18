"""Bounded, explicitly approved authority for scheduled production backups.

No authority is issued by this module. A protected canonical document and its
independent digest must both be configured by an operator. The scheduler and
controller must separately prove their coordinator, journal and current state.
"""
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import re
import time

import prepare_isolation_artifact as artifact
from production_target import Target, canonical, digest, parsed, require
from production_recovery import recovery_contract

HEX = re.compile(r"[0-9a-f]{64}")
REV = re.compile(r"[0-9a-f]{40}")
CHECKPOINT = re.compile(r"[0-9a-f]{32}")
SESSION = re.compile(r"[1-9][0-9]{0,19}")
DAY = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
ACTIONS = ("begin", "preflight", "pause", "freeze", "capture", "verify", "activate",
           "resume-failed", "reconcile-transition")
BASE = "maintenance/production-control/evidence/scheduled-backup/"
REHEARSAL_BASE = "maintenance/production-control/evidence/rehearsal-scheduled-backup/"


def _base(profile):
    require(profile in {"production", "rehearsal"})
    return BASE if profile == "production" else REHEARSAL_BASE


RESOURCE_FIELDS = ("accountId", "workerId", "workerName", "workerCreatedOn", "d1Id", "d1Name", "d1CreatedAt",
                   "bucketName", "bucketCreatedAt", "backupBucketName", "backupBucketCreatedAt", "botId")


def scope_id(account_id, profile):
    require(profile in {"production", "rehearsal"} and isinstance(account_id, str)
            and re.fullmatch(r"[a-f0-9]{32}", account_id))
    return digest({"version": 1, "kind": "subs-bot-production-backup" if profile == "production"
                   else "subs-bot-rehearsal-backup", "repositoryId": artifact.REPOSITORY_ID,
                   "accountId": account_id, "environment": profile})


def logical_scope(target):
    """One project-wide admission identity survives target configuration changes."""
    require(isinstance(target.data, dict))
    return scope_id(target.data.get("accountId"), target.environment)


def resource_pins(target):
    require(isinstance(target.data, dict) and all(isinstance(target.data.get(key), str) and target.data[key]
                                                 for key in RESOURCE_FIELDS))
    return {key: target.data[key] for key in RESOURCE_FIELDS}


def _hash(raw):
    return sha256(raw).hexdigest()


def _integer(value, low, high):
    return type(value) is int and low <= value <= high


def _day(value):
    require(isinstance(value, str) and DAY.fullmatch(value))
    try:
        result = datetime.strptime(value, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        require(False, "The scheduled slot date is invalid.")
    require(result.strftime("%Y-%m-%d") == value)
    return result


def authority_document(raw, protected_sha256, *, target, control_revision, source_revision,
                       source_checkpoint_id, source_manifest_sha256, policy, profile="production",
                       dispatcher_revision=None, registration_sha256=None, validation_json=None,
                       target_genesis_sha256=None, application_genesis_sha256=None):
    """Validate the entire protected authority against independently observed inputs."""
    value = parsed(raw)
    raw_bytes = raw.encode("utf-8") if isinstance(raw, str) else raw
    require(raw_bytes == canonical(value) and HEX.fullmatch(protected_sha256 or "")
            and _hash(raw_bytes) == protected_sha256, "The independent schedule authority pin differs.")
    fields = {"version", "kind", "environment", "targetSha256", "configurationSha256", "controlRevision",
              "sourceRevision", "sourceCheckpointId", "sourceManifestSha256", "policySha256", "validFrom",
              "validUntil", "frequencyHours", "maxExecutions", "recoveryGraceSeconds", "ledgerGenesisSha256",
              "actions", "authorization", "scopeSha256", "resourcePins", "targetCoordinatorGenesisSha256",
              "applicationGenesisSha256", "readerLogRetentionDays", "readerLogWarningDays", "readerLogStopBeforeDays"}
    require(profile in {"production", "rehearsal"})
    if profile == "rehearsal":
        fields |= {"dispatcherRevision", "registrationSha256", "validationSha256"}
        require(REV.fullmatch(dispatcher_revision or "") and HEX.fullmatch(registration_sha256 or "")
                and value.get("dispatcherRevision") == dispatcher_revision
                and value.get("registrationSha256") == registration_sha256
                and isinstance(validation_json, str) and 0 < len(validation_json.encode("utf-8")) <= 16384,
                "The isolated registration and trusted dispatcher pins are required.")
        spec = parsed(validation_json)
        require(canonical(spec).decode("utf-8") == validation_json
                and _hash(validation_json.encode("utf-8")) == value.get("validationSha256")
                and set(spec) == {"version", "pr", "headSha", "registrationSha256", "sourceCheckpointId",
                                  "sourceManifestSha256", "genesisSha256", "checkpointId"}
                and type(spec.get("version")) is int and spec["version"] == 1
                and re.fullmatch(r"[1-9][0-9]{0,9}", spec.get("pr", ""))
                and spec.get("headSha") == control_revision and spec.get("registrationSha256") == registration_sha256
                and spec.get("sourceCheckpointId") == source_checkpoint_id
                and spec.get("sourceManifestSha256") == source_manifest_sha256
                and spec.get("genesisSha256") == application_genesis_sha256
                and HEX.fullmatch(spec.get("genesisSha256", "")) and CHECKPOINT.fullmatch(spec.get("checkpointId", ""))
                and spec["checkpointId"] != source_checkpoint_id,
                "The exact isolated validation specification is invalid.")
    else:
        require(dispatcher_revision is None and registration_sha256 is None and validation_json is None)
    kind = "production-backup-schedule" if profile == "production" else "rehearsal-backup-schedule"
    authorization = "approved-recurring-backup-only" if profile == "production" else "approved-isolated-recurring-backup-only"
    require(set(value) == fields and type(value["version"]) is int and value["version"] == 1
            and value["kind"] == kind and value["environment"] == profile
            and value["authorization"] == authorization
            and target.environment == profile and value["targetSha256"] == target.digest
            and value["scopeSha256"] == logical_scope(target) and value["resourcePins"] == resource_pins(target)
            and HEX.fullmatch(target_genesis_sha256 or "")
            and value["targetCoordinatorGenesisSha256"] == target_genesis_sha256
            and HEX.fullmatch(application_genesis_sha256 or "")
            and value["applicationGenesisSha256"] == application_genesis_sha256
            and value["configurationSha256"] == target.configuration_digest
            and value["controlRevision"] == control_revision and REV.fullmatch(control_revision or "")
            and value["sourceRevision"] == source_revision and REV.fullmatch(source_revision or "")
            and value["sourceCheckpointId"] == source_checkpoint_id and CHECKPOINT.fullmatch(source_checkpoint_id or "")
            and value["sourceManifestSha256"] == source_manifest_sha256 and HEX.fullmatch(source_manifest_sha256 or "")
            and value["policySha256"] == digest(policy) and HEX.fullmatch(value["ledgerGenesisSha256"] or "")
            and value["actions"] == list(ACTIONS), "The schedule authority does not match its production scope.")
    start, end = value["validFrom"], value["validUntil"]
    require(_integer(start, 1, 2**53) and _integer(end, 1, 2**53) and 0 < end - start <= 31 * 86400
            and _integer(value["frequencyHours"], 24, 168) and value["frequencyHours"] % 24 == 0
            and value["frequencyHours"] == policy.get("frequencyHours")
            and _integer(value["maxExecutions"], 1, 31)
            and _integer(value["recoveryGraceSeconds"], 0, 86400)
            and _integer(value["readerLogRetentionDays"], 14, 400)
            and _integer(value["readerLogStopBeforeDays"], 1, 30)
            and _integer(value["readerLogWarningDays"], value["readerLogStopBeforeDays"] + 1,
                         value["readerLogRetentionDays"] - 1)
            and isinstance(policy.get("windowStartUtc"), str)
            and re.fullmatch(r"(?:[01][0-9]|2[0-3]):[0-5][0-9]", policy["windowStartUtc"])
            and _integer(policy.get("windowMinutes"), 1, 720), "The schedule bounds are invalid.")
    # datetime cannot represent arbitrary JSON integers, and validFrom anchors UTC dates.
    try:
        datetime.fromtimestamp(start, timezone.utc)
        datetime.fromtimestamp(end, timezone.utc)
    except (ValueError, OverflowError, OSError):
        require(False, "The schedule period is outside the supported UTC range.")
    return value


def eligible_slot(authority, policy, now):
    """Return the UTC slot date only while the approved window is open."""
    require(_integer(now, 1, 2**53))
    if not authority["validFrom"] <= now < authority["validUntil"]:
        return None
    stamp = datetime.fromtimestamp(now, timezone.utc)
    hour, minute = map(int, policy["windowStartUtc"].split(":"))
    midnight = stamp.replace(hour=0, minute=0, second=0, microsecond=0)
    opened = midnight + timedelta(hours=hour, minutes=minute)
    if stamp < opened:
        opened -= timedelta(days=1)
    if stamp >= opened + timedelta(minutes=policy["windowMinutes"]):
        return None
    first = datetime.fromtimestamp(authority["validFrom"], timezone.utc).date()
    days = (opened.date() - first).days
    if days < 0 or days % (authority["frequencyHours"] // 24):
        return None
    return opened.strftime("%Y-%m-%d")


def checkpoint_id(target_sha256, day, *, profile="production"):
    _day(day)
    require(HEX.fullmatch(target_sha256 or "") and profile in {"production", "rehearsal"})
    return digest({"kind": "scheduled-backup-checkpoint", "profile": profile,
                   "targetSha256": target_sha256, "slotDay": day})[:32]


def checkpoint_contract(authority, target, day):
    _day(day)
    require(target.environment in {"production", "rehearsal"} and authority["environment"] == target.environment
            and target.digest == authority["targetSha256"]
            and target.configuration_digest == authority["configurationSha256"])
    checkpoint = checkpoint_id(target.digest, day, profile=target.environment)
    stem = "subs-bot-cf-restore-sched-" + checkpoint[:16]
    contract = {"version": 1, "checkpointId": checkpoint, "databaseName": stem + "-d",
                "objectsName": stem + "-o", "purpose": "baseline"}
    return recovery_contract(canonical(contract), target.data)


def slot_key(scope_sha256, day, *, profile="production"):
    require(HEX.fullmatch(scope_sha256 or ""))
    _day(day)
    return _base(profile) + scope_sha256 + "/slots/" + day + "-intent.json"


def terminal_key(scope_sha256, day, *, profile="production"):
    return slot_key(scope_sha256, day, profile=profile).replace("-intent.json", "-terminal.json")


def scope_start_key(scope_sha256, session, *, profile="production"):
    require(HEX.fullmatch(scope_sha256 or "") and SESSION.fullmatch(session or ""))
    return _base(profile) + scope_sha256 + "/sessions/" + session + "-start.json"


def scope_start(authority, day, *, session, scope_predecessor_sha256, target_predecessor_sha256,
                scope_anchor_sha256, coordinator_anchor_sha256, slot_sha256, target_start_sha256,
                writer_run_id, writer_attempt):
    _day(day)
    require(isinstance(authority, dict) and authority.get("environment") in {"production", "rehearsal"}
            and HEX.fullmatch(authority.get("scopeSha256", "")) and HEX.fullmatch(authority.get("targetSha256", ""))
            and REV.fullmatch(authority.get("controlRevision", ""))
            and SESSION.fullmatch(session or "") and writer_run_id == session and writer_attempt == "1"
            and all(HEX.fullmatch(value or "") for value in (scope_predecessor_sha256, target_predecessor_sha256,
                    scope_anchor_sha256, coordinator_anchor_sha256, slot_sha256, target_start_sha256)))
    return {"version": 1, "kind": "scheduled-backup-scope-start", "profile": authority["environment"],
            "scopeSha256": authority["scopeSha256"], "targetSha256": authority["targetSha256"],
            "session": session, "day": day, "controlRevision": authority["controlRevision"],
            "scopePredecessorSha256": scope_predecessor_sha256, "targetPredecessorSha256": target_predecessor_sha256,
            "scopeAnchorSha256": scope_anchor_sha256, "coordinatorAnchorSha256": coordinator_anchor_sha256,
            "slotSha256": slot_sha256, "targetStartSha256": target_start_sha256,
            "writerRunId": writer_run_id, "writerAttempt": writer_attempt}


def terminal_record(slot, *, chain_sha256, scope_idle_anchor_sha256, coordinator_idle_anchor_sha256, result):
    """Describe a terminal proof; callers must independently verify that proof."""
    fields = {"version", "kind", "targetSha256", "scopeSha256", "resourcePins", "targetDocument", "authoritySha256", "authority", "policy", "slotDay",
              "session", "scopeAnchorSha256", "coordinatorAnchorSha256", "writerRunId", "writerAttempt"}
    require(isinstance(slot, dict) and set(slot) in (fields, fields | {"validationJson"})
            and type(slot["version"]) is int and slot["version"] == 1 and slot["kind"] == "scheduled-backup-slot"
            and HEX.fullmatch(slot["targetSha256"] or "") and HEX.fullmatch(slot["authoritySha256"] or "")
            and HEX.fullmatch(slot["scopeSha256"] or "") and slot["scopeSha256"] == slot["authority"].get("scopeSha256")
            and slot["resourcePins"] == slot["authority"].get("resourcePins")
            and isinstance(slot["targetDocument"], dict) and Target(slot["targetDocument"]).digest == slot["targetSha256"]
            and Target(slot["targetDocument"]).configuration_digest == slot["authority"].get("configurationSha256")
            and Target(slot["targetDocument"]).environment == slot["authority"].get("environment")
            and logical_scope(Target(slot["targetDocument"])) == slot["scopeSha256"]
            and resource_pins(Target(slot["targetDocument"])) == slot["resourcePins"]
            and HEX.fullmatch(slot["scopeAnchorSha256"] or "")
            and isinstance(slot["authority"], dict) and _hash(canonical(slot["authority"])) == slot["authoritySha256"]
            and slot["authority"].get("targetSha256") == slot["targetSha256"]
            and isinstance(slot["policy"], dict) and digest(slot["policy"]) == slot["authority"].get("policySha256")
            and ((slot["authority"].get("environment") == "production" and "validationJson" not in slot)
                 or (slot["authority"].get("environment") == "rehearsal" and isinstance(slot.get("validationJson"), str)
                     and _hash(slot["validationJson"].encode("utf-8")) == slot["authority"].get("validationSha256")))
            and HEX.fullmatch(slot["coordinatorAnchorSha256"] or "") and SESSION.fullmatch(slot["session"] or "")
            and SESSION.fullmatch(slot["writerRunId"] or "") and slot["writerAttempt"] == "1"
            and HEX.fullmatch(chain_sha256 or "")
            and HEX.fullmatch(scope_idle_anchor_sha256 or "")
            and HEX.fullmatch(coordinator_idle_anchor_sha256 or "") and result == "success")
    _day(slot["slotDay"])
    return {"version": 1, "kind": "scheduled-backup-terminal", "targetSha256": slot["targetSha256"], "scopeSha256": slot["scopeSha256"],
            "slotDay": slot["slotDay"], "intentSha256": _hash(canonical(slot)),
            "session": slot["session"], "chainSha256": chain_sha256,
            "scopeIdleAnchorSha256": scope_idle_anchor_sha256,
            "coordinatorIdleAnchorSha256": coordinator_idle_anchor_sha256, "result": result}


def slot_intent(authority, authority_sha256, day, *, target, policy, session, scope_anchor_sha256, anchor_sha256, writer_run_id, writer_attempt,
                validation_json=None):
    _day(day)
    require(isinstance(authority, dict) and HEX.fullmatch(authority_sha256 or "")
            and authority.get("environment") in {"production", "rehearsal"}
            and isinstance(authority.get("resourcePins"), dict) and set(authority["resourcePins"]) == set(RESOURCE_FIELDS)
            and authority.get("scopeSha256") == scope_id(authority["resourcePins"].get("accountId"), authority["environment"])
            and target.environment == authority["environment"] and target.digest == authority.get("targetSha256")
            and target.configuration_digest == authority.get("configurationSha256") and resource_pins(target) == authority["resourcePins"]
            and _hash(canonical(authority)) == authority_sha256 and isinstance(policy, dict)
            and digest(policy) == authority.get("policySha256") and HEX.fullmatch(anchor_sha256 or "")
            and HEX.fullmatch(scope_anchor_sha256 or "")
            and SESSION.fullmatch(session or "") and SESSION.fullmatch(writer_run_id or "")
            and writer_attempt == "1")
    if authority["environment"] == "rehearsal":
        require(isinstance(validation_json, str) and _hash(validation_json.encode("utf-8")) == authority.get("validationSha256"))
        spec = parsed(validation_json)
        require(canonical(spec).decode("utf-8") == validation_json
                and spec.get("checkpointId") == checkpoint_id(authority["targetSha256"], day, profile="rehearsal"),
                "The isolated slot must use its exact approved daily checkpoint.")
    else:
        require(validation_json is None)
    value = {"version": 1, "kind": "scheduled-backup-slot", "targetSha256": authority["targetSha256"],
            "scopeSha256": authority["scopeSha256"], "resourcePins": authority["resourcePins"],
            "targetDocument": target.data,
            "authoritySha256": authority_sha256, "authority": authority, "policy": policy, "slotDay": day, "session": session,
            "scopeAnchorSha256": scope_anchor_sha256, "coordinatorAnchorSha256": anchor_sha256,
            "writerRunId": writer_run_id, "writerAttempt": writer_attempt}
    if validation_json is not None:
        value["validationJson"] = validation_json
    return value


def read_slot(objects, authority, authority_sha256, day, expected):
    key = slot_key(authority["scopeSha256"], day, profile=authority["environment"])
    raw, _ = objects.get(key)
    require(isinstance(raw, bytes) and raw == canonical(expected)
            and expected == slot_intent(authority, authority_sha256, day, target=Target(expected.get("targetDocument")),
                                        policy=expected.get("policy"), session=expected.get("session"),
                                        scope_anchor_sha256=expected.get("scopeAnchorSha256"),
                                        anchor_sha256=expected.get("coordinatorAnchorSha256"),
                                        writer_run_id=expected.get("writerRunId"), writer_attempt=expected.get("writerAttempt"),
                                        validation_json=expected.get("validationJson")),
            "The exact scheduled slot claim is missing or differs.")
    return _hash(raw)


class ScheduledApproval:
    """A per-phase capability; valid only in the reviewed backup call path."""
    def __init__(self, *, env, objects, target, policy, authority, authority_sha256, slot, step, action, predecessor,
                 fresh_client):
        from production_backup_fresh_github import FreshConditionalJSON
        require(step in {"begin", "preflight", "pause", "freeze", "capture", "verify", "activate"}
                and isinstance(action, str) and HEX.fullmatch(predecessor or "") and type(fresh_client) is FreshConditionalJSON)
        self.env, self.objects, self.target, self.policy = env, objects, target, policy
        self.authority, self.approval_sha256, self.slot = authority, authority_sha256, slot
        self.step, self.action, self.predecessor = step, action, predecessor
        self.fresh_client = fresh_client

    def verify(self, target, action, source_revision, control_revision, predecessor):
        require(action == self.action and predecessor == self.predecessor and target.environment == "production"
                and target.digest == self.target.digest and target.configuration_digest == self.target.configuration_digest)
        fresh = authority_document(self.env.get("SUBS_BOT_PRODUCTION_BACKUP_SCHEDULE_AUTHORITY_JSON", ""),
            self.env.get("SUBS_BOT_PRODUCTION_BACKUP_SCHEDULE_AUTHORITY_SHA256", ""), target=target,
            control_revision=control_revision, source_revision=source_revision,
            source_checkpoint_id=self.authority["sourceCheckpointId"],
            source_manifest_sha256=self.authority["sourceManifestSha256"], policy=self.policy,
            target_genesis_sha256=self.env.get("SUBS_BOT_BACKUP_COORDINATOR_GENESIS_SHA256", ""),
            application_genesis_sha256=self.env.get("SUBS_BOT_BACKUP_GENESIS_SHA256", ""))
        now = int(time.time())
        require(fresh == self.authority
                and self.approval_sha256 == self.env.get("SUBS_BOT_PRODUCTION_BACKUP_SCHEDULE_AUTHORITY_SHA256")
                and self.env.get("SUBS_BOT_PRODUCTION_BACKUP_SCHEDULE_ENABLED") == "true"
                and fresh["validFrom"] <= now < fresh["validUntil"],
                "The scheduled phase authority is disabled or expired.")
        contract_sha = digest(checkpoint_contract(fresh, target, self.slot["slotDay"]))
        expected = {"preflight": {"backup-preflight:" + contract_sha},
                    "capture": {"recovery-prepare:" + contract_sha, "recovery-capture:" + contract_sha},
                    "verify": {"backup-verify:" + contract_sha},
                    "pause": {"pause"}, "freeze": {"freeze"}, "activate": {"activate"}}
        require((self.step == "begin" and re.fullmatch(r"backup-begin:[a-f0-9]{64}", action) is not None)
                or (self.step in expected and action in expected[self.step]),
                "The scheduled approval is outside its exact backup phase.")
        if self.step == "pause":
            maximum = self.policy.get("maximumPauseSeconds", 1800)
            require(_integer(maximum, 300, 21600) and now + maximum <= fresh["validUntil"]
                    and eligible_slot(fresh, self.policy, now) == self.slot["slotDay"],
                    "The remaining approved window cannot cover a new pause.")
        read_slot(self.objects, fresh, self.approval_sha256, self.slot["slotDay"], self.slot)
        # This is a fixed verifier, not an injected caller callback. It rechecks
        # the claimed child, its exact nonce and live scheduled parent each time.
        from production_backup_cli import verify_claimed_schedule_phase
        require(verify_claimed_schedule_phase(self.env, target, self.objects, self.policy, self.slot,
                                              self.step, predecessor, fresh, self.approval_sha256, action,
                                              self.fresh_client) is True,
                "The scheduled child or its parent is not independently confirmed.")
        return True
