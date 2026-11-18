"""Single-use project-wide lock for separately approved manual backup work."""
from datetime import datetime, timezone
from hashlib import sha256
import re

import prepare_isolation_artifact as artifact
import production_backup_coordinator as coordinator
import production_backup_schedule as schedule
from production_target import approve, canonical, parsed, require

WORKFLOWS = {".github/workflows/worker-production-backup.yml",
             ".github/workflows/worker-production-backup-coordinator.yml",
             ".github/workflows/worker-production-recovery.yml"}


def start_key(scope, run_id):
    require(schedule.HEX.fullmatch(scope or "") and schedule.SESSION.fullmatch(run_id or ""))
    return schedule.BASE + scope + "/manual/" + run_id + "-start.json"


def complete_key(scope, run_id):
    return start_key(scope, run_id).replace("-start.json", "-complete.json")


def result_key(scope, run_id):
    return start_key(scope, run_id).replace("-start.json", "-result.json")


def reader_log_policy(env):
    raw = env.get("SUBS_BOT_BACKUP_READER_LOG_POLICY_JSON", "")
    pin = env.get("SUBS_BOT_BACKUP_READER_LOG_POLICY_SHA256", "")
    value = parsed(raw)
    require(isinstance(raw, str) and canonical(value).decode() == raw and schedule.HEX.fullmatch(pin or "")
            and sha256(raw.encode()).hexdigest() == pin and isinstance(value, dict)
            and set(value) == {"version", "retentionDays", "warningDays", "stopBeforeDays"}
            and type(value["version"]) is int and value["version"] == 1
            and all(type(value[k]) is int for k in ("retentionDays", "warningDays", "stopBeforeDays"))
            and 14 <= value["retentionDays"] <= 400
            and 1 <= value["stopBeforeDays"] <= 30
            and value["stopBeforeDays"] < value["warningDays"] < value["retentionDays"],
            "An independently pinned reader-log retention policy is required.")
    return value, pin


class ManualScope:
    """Acquisition follows the actual action approval; unknown writes stay locked."""

    def __init__(self, env, target, objects, revision, *, policy, app_store):
        self.env, self.target, self.objects, self.revision = env, target, objects, revision
        self.policy, self.app_store = policy, app_store
        self.scope = schedule.logical_scope(target)
        require(target.environment == "production" and self.scope != target.digest
                and env.get("GITHUB_REPOSITORY") == artifact.REPOSITORY
                and env.get("GITHUB_REPOSITORY_ID") == str(artifact.REPOSITORY_ID)
                and env.get("GITHUB_REF") == artifact.MAIN_REF and env.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
                and env.get("RUNNER_ENVIRONMENT") == "github-hosted" and env.get("GITHUB_RUN_ATTEMPT") == "1"
                and env.get("GITHUB_WORKFLOW_SHA") == revision and env.get("GITHUB_SHA") == revision
                and schedule.SESSION.fullmatch(env.get("GITHUB_RUN_ID", ""))
                and any(env.get("GITHUB_WORKFLOW_REF") == artifact.REPOSITORY + "/" + path + "@" + artifact.MAIN_REF
                        for path in WORKFLOWS), "The exact manual scope writer is required.")
        genesis = env.get("SUBS_BOT_BACKUP_SCHEDULE_SCOPE_GENESIS_SHA256", "")
        self.anchor = coordinator.ScheduleScopeAnchor(coordinator.CoordinatorStore(objects, self.scope), self.scope,
            genesis, target.data["backupBucketName"], target.data["backupBucketCreatedAt"])
        self.anchor.read()  # No implicit initialization or fallback.
        self.start = self.active_sha = self.scope_keys = None

    def acquire(self, action, approval_action, approval_raw, predecessor, source_revision):
        require(isinstance(action, str) and re.fullmatch(r"[a-z-]{1,64}", action)
                and isinstance(approval_action, str) and 0 < len(approval_action) <= 256
                and isinstance(approval_raw, str) and 0 < len(approval_raw.encode()) <= 16384
                and schedule.HEX.fullmatch(predecessor or ""))
        approve(self.target, approval_raw, approval_action, source_revision, predecessor, control_revision=self.revision)
        return self._acquire(action, approval_action, approval_raw, predecessor, source_revision)

    def acquire_coordinator_initialization(self, target_genesis):
        """Accept only the existing independently pinned coordinator initialization approval."""
        import production_backup_transaction as maintenance
        require(self.env.get("BACKUP_COORDINATOR_ACTION") == "initialize"
                and self.env.get("GITHUB_WORKFLOW_REF") == artifact.REPOSITORY +
                    "/.github/workflows/worker-production-backup-coordinator.yml@" + artifact.MAIN_REF)
        seed = maintenance.Anchor(coordinator.CoordinatorStore(self.objects, self.target.digest), self.target.digest, "0" * 64)
        expected = sha256(seed.initial_material()[1]).hexdigest()
        require(target_genesis == expected == self.env.get("SUBS_BOT_BACKUP_COORDINATOR_GENESIS_SHA256")
                == self.env.get("BACKUP_COORDINATOR_APPROVAL_SHA256"),
                "The exact target coordinator genesis approval is required.")
        return self._acquire("initialize", "coordinator-initialize", expected, expected, self.revision)

    def acquire_coordinator(self, action, plan):
        """Bind the project scope to the coordinator's independently approved plan."""
        require(action in {"run", "resume", "abort", "reconcile"} and self.env.get("BACKUP_COORDINATOR_ACTION") == action
                and self.env.get("GITHUB_WORKFLOW_REF") == artifact.REPOSITORY +
                    "/.github/workflows/worker-production-backup-coordinator.yml@" + artifact.MAIN_REF
                and isinstance(plan, dict) and plan.get("action") == action and plan.get("targetSha256") == self.target.digest
                and plan.get("controlRevision") == self.revision and schedule.SESSION.fullmatch(plan.get("session", ""))
                and self.env.get("BACKUP_COORDINATOR_SESSION") == plan["session"]
                and schedule.HEX.fullmatch(plan.get("anchorSha256", "")))
        raw = canonical(plan)
        require(self.env.get("BACKUP_COORDINATOR_APPROVAL_SHA256") == sha256(raw).hexdigest(),
                "The exact coordinator plan approval is required.")
        return self._acquire(action, "coordinator-" + action, raw.decode(), plan["anchorSha256"], None)

    def _acquire(self, action, approval_action, approval_raw, predecessor, source_revision):
        if self.start is not None:
            require(self.start["action"] == action and self.start["predecessorSha256"] == predecessor
                    and self.start["sourceRevision"] == source_revision,
                    "A different manual action cannot reuse this scope claim.")
            self.guard()
            return
        retention, retention_sha = reader_log_policy(self.env)
        import production_backup_schedule_terminal as terminal
        history = terminal.verify_prior_history(self.objects, self.app_store, self.target, self.anchor,
            artifact._github_token(), self.env, None, self.env.get("SUBS_BOT_BACKUP_GENESIS_SHA256", ""),
            self.env.get("SUBS_BOT_BACKUP_COORDINATOR_GENESIS_SHA256", ""), self.policy)
        if history.get("readerLogExpiryWarning"):
            print("::warning::A required historical reader log is approaching its configured retention limit.", flush=True)
        if history.get("readerLogStopRequired"):
            print("::warning::Scheduled starts must stop; manual recovery is proceeding only after the original logs were verified.", flush=True)
        if history.get("rotationWarning"):
            print("::warning::The reviewed project scope history is approaching its fixed capacity.", flush=True)
        require(history["historyCount"] < 200, "The reviewed manual scope history limit was reached.")
        artifact.require_current_main(self.revision)
        prior, prior_raw, prior_etag = self.anchor.read()
        session = self.env["GITHUB_RUN_ID"] + "-1"
        require(prior["state"] == "idle" and prior["session"] != session,
                "A prior scope owner requires independent reconciliation.")
        day = datetime.now(timezone.utc).strftime("%Y/%m/%d")
        expected = {"version": 1, "targetSha256": self.scope, "generation": prior["generation"] + 1,
                    "previousSha256": sha256(prior_raw).hexdigest(), "state": "active", "session": session,
                    "day": day, "controlRevision": self.revision}
        active_sha = sha256(canonical(expected)).hexdigest()
        start = {"version": 1, "kind": "manual-backup-scope-start", "scopeSha256": self.scope,
                 "targetSha256": self.target.digest, "configurationSha256": self.target.configuration_digest,
                 "targetDocument": self.target.data,
                 "policy": self.policy, "policySha256": sha256(canonical(self.policy)).hexdigest(),
                 "readerLogPolicy": retention, "readerLogPolicySha256": retention_sha,
                 "priorScopeKeysSha256": sha256(canonical(history["scopeKeys"])).hexdigest(),
                 "targetCoordinatorGenesisSha256": self.env.get("SUBS_BOT_BACKUP_COORDINATOR_GENESIS_SHA256", ""),
                 "applicationGenesisSha256": self.env.get("SUBS_BOT_BACKUP_GENESIS_SHA256", ""),
                 "action": action, "approvalActionSha256": sha256(approval_action.encode()).hexdigest(),
                 "approvalSha256": sha256(approval_raw.encode()).hexdigest(), "predecessorSha256": predecessor,
                 "scopePredecessorSha256": sha256(prior_raw).hexdigest(), "scopeAnchorSha256": active_sha,
                 "coordinatorSession": (self.env.get("BACKUP_COORDINATOR_SESSION", "")
                     if self.env["GITHUB_WORKFLOW_REF"].endswith("/worker-production-backup-coordinator.yml@" + artifact.MAIN_REF)
                        and action in {"run", "resume", "abort", "reconcile"} else None),
                 "writerRunId": self.env["GITHUB_RUN_ID"], "writerAttempt": "1", "day": day,
                 "workflowRef": self.env["GITHUB_WORKFLOW_REF"], "controlRevision": self.revision,
                 "sourceRevision": source_revision}
        key = start_key(self.scope, self.env["GITHUB_RUN_ID"])
        existing, _ = self.objects.get(key, absent=True)
        require(existing is None, "A manual scope intent already exists; inspect it without retrying.")
        require(isinstance(history.get("scopeKeys"), list) and len(history["scopeKeys"]) == len(set(history["scopeKeys"])))
        self.objects.put_once(key, canonical(start))
        saved, _ = self.objects.get(key)
        require(saved == canonical(start))
        artifact.require_current_main(self.revision)
        self.anchor._advance(prior, prior_raw, prior_etag, state="active", session=session, day=day, revision=self.revision)
        self.start, self.active_sha = start, active_sha
        self.scope_keys = set(history["scopeKeys"]) | {key}
        self.guard()

    def guard(self):
        require(isinstance(self.start, dict) and schedule.HEX.fullmatch(self.active_sha or ""),
                "A confirmed manual scope claim is required before a write.")
        artifact.require_current_main(self.revision)
        value, raw, _etag = self.anchor.read()
        require(value["state"] == "active" and value["session"] == self.env["GITHUB_RUN_ID"] + "-1"
                and value["controlRevision"] == self.revision and sha256(raw).hexdigest() == self.active_sha)
        saved, _ = self.objects.get(start_key(self.scope, self.env["GITHUB_RUN_ID"]))
        require(saved == canonical(self.start), "The manual scope start changed.")
        keys = self.objects.list(schedule.BASE + self.scope + "/", maximum=10000)
        require(isinstance(keys, list) and len(keys) < 10000 and len(keys) == len(set(keys))
                and set(keys) == self.scope_keys, "The complete scope inventory changed during the manual action.")

    def finish(self, result, *, journal=None):
        self.guard()
        require(isinstance(result, dict))
        self.confirmed_result(result, journal=journal)
        result_raw = canonical(result)
        require(0 < len(result_raw) <= 256 * 1024)
        result_path = result_key(self.scope, self.env["GITHUB_RUN_ID"])
        prior, _ = self.objects.get(result_path, absent=True)
        require(prior is None, "The manual result already exists; inspect without retrying.")
        self.objects.put_once(result_path, result_raw)
        observed, _ = self.objects.get(result_path)
        require(observed == result_raw, "The private manual result is not independently confirmed.")
        self.scope_keys.add(result_path)
        self.guard()
        self.anchor.release(self.env["GITHUB_RUN_ID"] + "-1")
        idle, raw, _etag = self.anchor.read()
        require(idle["state"] == "idle" and idle["session"] == self.env["GITHUB_RUN_ID"] + "-1"
                and idle["previousSha256"] == self.active_sha)
        done = {"version": 1, "kind": "manual-backup-scope-complete", "scopeSha256": self.scope,
                "startSha256": sha256(canonical(self.start)).hexdigest(), "idleAnchorSha256": sha256(raw).hexdigest(),
                "resultSha256": sha256(result_raw).hexdigest(), "writerRunId": self.env["GITHUB_RUN_ID"],
                "writerAttempt": "1"}
        key = complete_key(self.scope, self.env["GITHUB_RUN_ID"])
        prior, _ = self.objects.get(key, absent=True)
        require(prior is None, "The manual completion already exists; inspect without retrying.")
        self.objects.put_once(key, canonical(done))
        observed, _ = self.objects.get(key)
        require(observed == canonical(done), "The manual completion is not independently confirmed.")
        print("SCHEDULE_MANUAL_COMPLETE_SHA256=" + sha256(canonical(done)).hexdigest(), flush=True)

    def confirmed_result(self, result, *, journal=None):
        """Only confirmed action outcomes may release the project-wide lock."""
        action = self.start["action"]
        workflow = self.start["workflowRef"]
        if workflow.endswith("/worker-production-backup.yml@" + artifact.MAIN_REF):
            expected = {"initialize-anchor": "initialized", "begin": "started", "abort-unstarted": "aborted-before-pause",
                        "preflight": "observed", "abort-preflight": "aborted-before-pause", "pause": "paused",
                        "freeze": "frozen", "fingerprint": "frozen-data-confirmed", "capture": "captured-unverified",
                        "poll-export": "captured-unverified", "verify": "verified", "activate": "resumed",
                        "reconcile-transition": "reconciled", "resume-failed": "resumed-after-failure",
                        "anchor-reconcile": "anchor-release-reconciled"}
            require(action in expected and result.get("action") == action and result.get("status") == expected[action])
            return True
        if workflow.endswith("/worker-production-backup-coordinator.yml@" + artifact.MAIN_REF):
            require((action == "initialize" and result.get("status") == "initialized" and result.get("mutationPerformed") is True)
                    or (action in {"run", "resume"} and result.get("status") == "completed"
                        and result.get("verifiedCheckpoints") == len(coordinator.STEPS))
                    or (action == "abort" and result.get("status") == "abandoned-after-confirmed-terminal")
                    or (action == "reconcile" and result.get("status") == "reconciled"))
            return True
        import production_recovery as recovery
        require(workflow.endswith("/worker-production-recovery.yml@" + artifact.MAIN_REF)
                and type(journal) is recovery.RecoveryJournal and not journal.poisoned
                and result.get("action") == action)
        value = journal.load()
        require(isinstance(value, dict) and value.get("phase") in {"prepared", "captured", "objects-restored", "imported", "verified"}
                and value.get("lease") == {"owner": None, "until": 0}
                and result.get("phase") == value["phase"]
                and (value.get("export") is None or isinstance(value["export"], dict) and value["export"].get("state") == "complete")
                and (value.get("importState") is None or isinstance(value["importState"], dict)
                     and value["importState"].get("state") in {"complete", "verified"})
                and isinstance(value.get("resources"), dict) and set(value["resources"]) == {"database", "objects"})
        require(all(isinstance(row, dict) and (row.get("intent") is None or
                    isinstance(row["intent"], dict) and row["intent"].get("state") == "confirmed" and row.get("pin") is not None)
                    for row in value["resources"].values()), "A recovery resource outcome remains unknown.")
        return True
