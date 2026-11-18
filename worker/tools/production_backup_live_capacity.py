"""Read-only periodic capacity estimates for an independently pinned source.

This observes a changing database and cannot establish a consistent backup.
It uses the same table and object-closure checks as backup preflight.
"""
from pathlib import Path
import re
import time
from tempfile import TemporaryDirectory

import production_backup_capacity as capacity
import production_recovery as recovery
from production_release_evidence import ReadOnlyRecoveryAPI, load_release
from production_target import require


def _control(api, target, revision):
    rows = api.rows(target.data["d1Id"], "SELECT target_sha256,bot_id,release_revision,generation,epoch,admission,workers FROM subs_bot_production_control WHERE singleton=1")
    require(len(rows) == 1 and set(rows[0]) == {"target_sha256", "bot_id", "release_revision", "generation", "epoch", "admission", "workers"})
    row = rows[0]
    require(row["target_sha256"] == target.digest and row["bot_id"] == target.data["botId"]
            and row["release_revision"] == revision and row["generation"] == target.data["generation"]
            and type(row["epoch"]) is int and row["epoch"] > 0
            and row["admission"] in {"open", "closed"} and row["workers"] in {"run", "frozen"})
    return row


def sample(target, token, checkpoint_id, manifest_sha256, *, warning_percent, root, guard, require_open=False):
    """Scan every D1 table and every recoverable referenced object without writes."""
    require(target.environment in {"rehearsal", "production"} and callable(guard) and type(require_open) is bool
            and re.fullmatch(r"[a-f0-9]{32}", checkpoint_id or "")
            and re.fullmatch(r"[a-f0-9]{64}", manifest_sha256 or "")
            and type(warning_percent) is int and 1 <= warning_percent <= 99)
    started_at = int(time.time())
    root = Path(root)
    require(root.is_absolute() and root.is_dir() and not root.is_symlink())
    guard()
    with TemporaryDirectory(prefix="subs-bot-capacity-observe-", dir=root) as temporary:
        source = load_release(target, token, checkpoint_id, manifest_sha256, Path(temporary))
        require(source["sourceTarget"].configuration_digest == target.configuration_digest)
        name = "subs-bot-cf-restore-evidence-" + checkpoint_id[:16]
        contract = {"version": 1, "checkpointId": checkpoint_id, "databaseName": name,
                    "objectsName": name, "purpose": "baseline"}
        api = ReadOnlyRecoveryAPI(target.data, token, None, contract)
        identity = api.json("GET", api.source)
        require((identity.get("uuid"), identity.get("name"), identity.get("created_at")) ==
                (target.data["d1Id"], target.data["d1Name"], target.data["d1CreatedAt"]))
        api.verify_backup()
        api.verify_bucket(target.data["bucketName"], target.data["bucketCreatedAt"])
        before = _control(api, target, source["manifest"]["revision"])
        if require_open:
            require((before["admission"], before["workers"]) == ("open", "run"),
                    "A scheduled backup cannot claim a slot while production is paused or frozen.")
        schema = recovery.RecoverySource(api, target.data, source["bundle"], source["manifest"], lambda: None, guard)
        observed = capacity.observe(api, schema, warning_percent=warning_percent)
        counts = observed.get("tableCounts")
        if isinstance(counts, dict):
            again = {}
            for table in schema.tables:
                require(re.fullmatch(r"[a-z][a-z0-9_]*", table))
                rows = api.rows(target.data["d1Id"], 'SELECT count(*) AS n FROM "' + table + '"')
                require(len(rows) == 1 and set(rows[0]) == {"n"} and type(rows[0]["n"]) is int and rows[0]["n"] >= 0)
                again[table] = rows[0]["n"]
            if counts != again:
                observed.update(rowStatus="unknown", objectStatus="unverified", objectBytesStatus="unknown",
                                failureReason="source-changed-during-scan")
        schema.schema()
        if _control(api, target, source["manifest"]["revision"]) != before:
            observed.update(rowStatus="unknown", objectStatus="unverified", objectBytesStatus="unknown",
                            failureReason="source-changed-during-scan")
        api.verify_bucket(target.data["bucketName"], target.data["bucketCreatedAt"])
        guard()
        # Per-table data and target identity never enter public Actions artifacts.
        observed.update(sampleStartedAt=started_at, sampleCompletedAt=int(time.time()))
        return {key: value for key, value in observed.items() if key != "tableCounts"}


def alerts(observed):
    """Map partial or invalid observations to an explicit operational alert."""
    require(isinstance(observed, dict))
    states = [observed.get(key) for key in ("rowStatus", "objectStatus", "objectBytesStatus")]
    found = set()
    if "warning" in states:
        found.add("live-capacity-near-limit")
    if "over-limit" in states:
        found.add("live-capacity-over-limit")
    if any(value not in {"normal", "warning", "over-limit"} for value in states):
        found.add("live-capacity-unknown")
    return sorted(found)


def due(event, schedule, interval):
    """A fixed four-cron calendar supports operator-selected 15/30/60 minutes."""
    require(type(interval) is int and interval in {15, 30, 60})
    if event == "workflow_dispatch":
        return True
    require(event == "schedule" and schedule in {"3 * * * *", "18 * * * *", "33 * * * *", "48 * * * *"})
    return interval == 15 or interval == 30 and schedule in {"3 * * * *", "33 * * * *"} or interval == 60 and schedule == "3 * * * *"
