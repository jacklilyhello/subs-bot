"""Read-only proof for closing a completed reviewed phase-coordinator run.

This module never changes an anchor, application state, or webhook. Any
missing, ambiguous, duplicated, or still-running child prevents cleanup.
"""
from datetime import datetime, timezone
from hashlib import sha256
from io import BytesIO
import re
from urllib.parse import quote
from zipfile import BadZipFile, ZipFile

import prepare_isolation_artifact as github
from production_target import canonical, parsed, require

BASE = "maintenance/production-control/evidence/backup-coordinator/"
CHILD = ".github/workflows/worker-backup-phase-rehearsal.yml"
STEPS = ("plan-begin", "begin", "preflight", "plan-pause", "pause", "drain", "freeze", "capture", "verify", "plan-activate", "activate")
HEX = re.compile(r"[a-f0-9]{64}")
DECIMAL = re.compile(r"[1-9][0-9]{0,19}")


class PrefixedReadStore:
    """Map the independent coordinator anchor to the existing full-chain reader."""
    def __init__(self, store, target):
        require(store.objects is not None and HEX.fullmatch(target or ""))
        self.inner = store
        self.prefix = BASE + target + "/coordination/"
        self.objects = self

    def verify(self):
        return self.inner.verify()

    def get(self, key, *, absent=False):
        require(isinstance(key, str) and key.startswith("maintenance/production-control/")
                and not any(part in {".", ".."} for part in key.split("/")))
        return self.inner.get(self.prefix + key, absent=absent)

    def list(self, prefix, *, maximum=10000):
        mapped = self.prefix + prefix
        values = self.inner.objects.list(mapped, maximum=maximum)
        require(all(value.startswith(mapped) for value in values))
        return [value[len(self.prefix):] for value in values]


def coordinator_anchor(store, target, session, candidate, genesis):
    from production_backup_admission_recovery import idle_anchor
    require(DECIMAL.fullmatch(session or "") and HEX.fullmatch(genesis or ""))
    return idle_anchor(PrefixedReadStore(store, target.digest), target, session + "-1", candidate,
                       genesis, verify_session=False)


def child_evidence(store, target_sha, session, main_sha, candidate_sha, token, *, source_checkpoint,
                   source_manifest, validation_json, policy, writer_run_id, parent_receipt):
    """Validate private intent/claim/receipt and every observed matching run."""
    require(store.objects is not None and HEX.fullmatch(target_sha or "") and DECIMAL.fullmatch(session or ""))
    prefix = BASE + target_sha + "/" + session + "/"
    require(re.fullmatch(r"[a-f0-9]{32}", source_checkpoint or "") and HEX.fullmatch(source_manifest or "")
            and isinstance(validation_json, str) and 0 < len(validation_json) <= 16384
            and isinstance(policy, dict) and type(policy.get("pauseLimitSeconds")) is int
            and 1 <= policy["pauseLimitSeconds"] <= 900 and DECIMAL.fullmatch(writer_run_id or ""))
    pause_limit = policy.get("maximumPauseSeconds", 1800)
    require(type(pause_limit) is int and 300 <= pause_limit <= 21600 and pause_limit >= policy["pauseLimitSeconds"])
    start_raw, _ = store.objects.get(prefix + "start-intent.json")
    start = parsed(start_raw)
    require(canonical(start) == start_raw and start.get("version") == 1 and start.get("action") == "run"
            and start.get("targetSha256") == target_sha and start.get("session") == session
            and start.get("controlRevision") == main_sha and start.get("candidateRevision") == candidate_sha
            and start.get("profile") == "rehearsal" and start.get("validationSha256") == sha256(validation_json.encode()).hexdigest()
            and start.get("sourceCheckpointId") == source_checkpoint and start.get("sourceManifestSha256") == source_manifest
            and start.get("policySha256") == sha256(canonical(policy)).hexdigest()
            and start.get("writerRunId") == writer_run_id and start.get("writerAttempt") == "1")
    workflow = github._get_json("/actions/workflows/worker-backup-phase-rehearsal.yml", token)
    require(workflow.get("path") == CHILD and type(workflow.get("id")) is int)
    rows, titles, earliest, results, pause_until = [], set(), None, [], None
    for sequence, action in enumerate(STEPS, 1):
        root = prefix + str(sequence).zfill(2)
        intent_raw, _ = store.objects.get(root + "-intent.json")
        claim_raw, _ = store.objects.get(root + "-child-claim.json")
        receipt_raw, _ = store.objects.get(root + "-receipt.json")
        intent, claim, receipt = (parsed(value) for value in (intent_raw, claim_raw, receipt_raw))
        require(all(canonical(value) == raw for value, raw in ((intent, intent_raw), (claim, claim_raw), (receipt, receipt_raw))))
        require(set(intent) == {"version", "kind", "targetSha256", "session", "sequence", "action", "controllerRevision",
                                "candidateRevision", "profile", "nonce", "inputSha256", "createdAt", "writerRunId", "writerAttempt"}
                and type(intent.get("version")) is int and intent["version"] == 1 and intent.get("kind") == "backup-dispatch-intent"
                and intent.get("targetSha256") == target_sha and intent.get("session") == session
                and type(intent.get("sequence")) is int and intent["sequence"] == sequence and intent.get("action") == action
                and intent.get("profile") == "rehearsal" and intent.get("controllerRevision") == main_sha
                and intent.get("candidateRevision") == candidate_sha and HEX.fullmatch(intent.get("nonce", ""))
                and intent.get("writerRunId") == writer_run_id and intent.get("writerAttempt") == "1"
                and type(intent.get("createdAt")) is int and intent["createdAt"] > 0)
        intent_sha = sha256(intent_raw).hexdigest()
        inputs = {"action": action, "source_checkpoint_id": source_checkpoint, "source_manifest_sha256": source_manifest}
        if results:
            first = results[0]
            require(first.get("status") == "plan-only" and re.fullmatch(r"[1-9][0-9]{0,19}-1", first.get("session", ""))
                    and re.fullmatch(r"[0-9]{4}/[0-9]{2}/[0-9]{2}", first.get("day", "")))
            inputs.update(session=first["session"], session_day=first["day"])
        predecessor_index = {"begin": 0, "preflight": 0, "pause": 3, "freeze": 5,
                             "capture": 6, "verify": 6, "activate": 9}.get(action)
        if predecessor_index is not None:
            state = results[predecessor_index].get("stateSha256", "")
            require(HEX.fullmatch(state or ""))
            inputs["state_sha256"] = state
        if action == "pause":
            pause_until = intent["createdAt"] + pause_limit
        inputs.update(dispatch_nonce=intent["nonce"], coordinator_session=session,
                      dispatch_deadline=str(pause_until or 0), validation_json=validation_json)
        require(sha256(canonical(inputs)).hexdigest() == intent.get("inputSha256"),
                "A child intent is not bound to its verified predecessor and source.")
        require(claim == {"version": 1, "kind": "backup-dispatch-child-claim", "intentSha256": intent_sha,
                "targetSha256": target_sha, "session": session, "sequence": sequence, "nonce": intent["nonce"],
                "profile": "rehearsal", "controllerRevision": main_sha, "candidateRevision": candidate_sha,
                "childRunId": claim.get("childRunId"), "childAttempt": "1"}
                and DECIMAL.fullmatch(claim.get("childRunId", "")) and receipt.get("runId") == claim["childRunId"]
                and receipt.get("runAttempt") == "1" and receipt.get("intentSha256") == intent_sha
                and set(receipt) == {"version", "kind", "intentSha256", "runId", "runAttempt", "resultSha256", "result", "artifactId", "artifactSha256"}
                and type(receipt.get("version")) is int and receipt["version"] == 1
                and receipt.get("kind") == "backup-dispatch-receipt" and DECIMAL.fullmatch(receipt.get("artifactId", ""))
                and HEX.fullmatch(receipt.get("artifactSha256", "")) and HEX.fullmatch(receipt.get("resultSha256", ""))
                and isinstance(receipt.get("result"), dict) and sha256(canonical(receipt["result"])).hexdigest() == receipt["resultSha256"])
        result = receipt["result"]
        require(result.get("action") == action and result.get("targetSha256") == target_sha
                and result.get("controlRevision") == candidate_sha and result.get("dispatcherRevision") == main_sha
                and result.get("consumerSwitch") == "not-authorized" and result.get("automaticReplay") is False)
        expected_status = {"plan-begin": "plan-only", "begin": "started", "preflight": "observed", "pause": "paused",
                           "drain": "drained", "freeze": "frozen", "capture": "captured-unverified",
                           "verify": "verified", "activate": "resumed"}.get(action)
        require(expected_status is None or result.get("status") == expected_status)
        archive, _ = store.objects.get(root + "-result.zip")
        require(isinstance(archive, bytes) and len(archive) <= 2 * 1024 * 1024
                and sha256(archive).hexdigest() == receipt["artifactSha256"])
        try:
            with ZipFile(BytesIO(archive)) as zipped:
                members = zipped.infolist()
                require(len(members) == 1 and members[0].filename == "production-backup-result.json"
                        and members[0].filename == members[0].orig_filename and not members[0].is_dir()
                        and not members[0].flag_bits & (1 | 64) and members[0].file_size <= 65536
                        and zipped.read(members[0]) == canonical(result))
        except (BadZipFile, OSError, RuntimeError, ValueError):
            require(False, "The retained child result archive is invalid.")
        title = "Rehearsal backup " + action + " at " + main_sha + " candidate " + candidate_sha + " #" + intent["nonce"]
        require(title not in titles)
        titles.add(title)
        rows.append((title, claim["childRunId"]))
        results.append(result)
        earliest = intent["createdAt"] if earliest is None else min(earliest, intent["createdAt"])
    # Explicit pagination and a time window avoid assuming the workflow's whole
    # history is short. Any duplicate with the same nonce must also have ended.
    start_epoch, end_epoch = earliest - 120, int(datetime.now(timezone.utc).timestamp()) + 120
    start = datetime.fromtimestamp(start_epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    end = datetime.fromtimestamp(end_epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    interval = quote(start + ".." + end, safe="")
    found, total = [], None
    for page in range(1, 7):
        response = github._get_json("/actions/workflows/worker-backup-phase-rehearsal.yml/runs?per_page=100&page="
                                    + str(page) + "&created=" + interval, token)
        batch, count = response.get("workflow_runs"), response.get("total_count")
        require(isinstance(batch, list) and type(count) is int and 0 <= count < 500 and len(batch) <= 100
                and (total is None or total == count))
        total = count
        found.extend(batch)
        if len(batch) < 100:
            break
    else:
        require(False, "The child workflow inventory exceeds its safe bound.")
    require(len(found) == total and len({row.get("id") for row in found if isinstance(row, dict)}) == len(found))
    matched = {title: [] for title in titles}
    for run in found:
        require(isinstance(run, dict) and isinstance(run.get("display_title"), str))
        created = run.get("created_at", "")
        require(isinstance(created, str) and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", created))
        stamp = int(datetime.strptime(created, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp())
        require(start_epoch <= stamp <= end_epoch)
        title = run["display_title"]
        if title not in matched:
            continue
        require(run.get("path") in (CHILD, CHILD + "@main", CHILD + "@refs/heads/main")
                and run.get("workflow_id") == workflow["id"] and run.get("head_sha") == main_sha and run.get("head_branch") == "main"
                and run.get("event") == "workflow_dispatch" and run.get("run_attempt") == 1
                and run.get("status") == "completed"
                and all(isinstance(run.get(k), dict) and run[k].get("id") == github.REPOSITORY_ID
                        for k in ("repository", "head_repository")))
        matched[title].append(run)
    for title, run_id in rows:
        claimed = [run for run in matched[title] if str(run.get("id")) == run_id]
        require(len(claimed) == 1 and claimed[0].get("conclusion") == "success",
                "A claimed child has not independently completed successfully.")
        latest = github._get_json("/actions/runs/" + run_id, token)
        jobs = github._get_json("/actions/runs/" + run_id + "/attempts/1/jobs?per_page=100", token)
        require(str(latest.get("id")) == run_id and latest.get("run_attempt") == 1 and latest.get("status") == "completed"
                and isinstance(jobs.get("jobs"), list) and type(jobs.get("total_count")) is int
                and jobs["total_count"] == len(jobs["jobs"]) < 100)
        selected = [job for job in jobs["jobs"] if isinstance(job, dict) and job.get("name") == "phase"]
        require(len(selected) == 1 and str(selected[0].get("run_id")) == run_id and selected[0].get("run_attempt") == 1
                and selected[0].get("head_sha") == main_sha and selected[0].get("status") == "completed"
                and selected[0].get("conclusion") == "success" and isinstance(selected[0].get("steps"), list))
        for name in ("Verify trusted phase identity before candidate checkout", "Verify exact reviewed phase checkout",
                     "Verify isolated test Bot identity", "Execute one reviewed rehearsal phase"):
            steps = [step for step in selected[0]["steps"] if isinstance(step, dict) and step.get("name") == name]
            require(len(steps) == 1 and (steps[0].get("status"), steps[0].get("conclusion")) == ("completed", "success"))
    require(isinstance(parent_receipt, dict) and results[0].get("session") == rows[0][1] + "-1"
            and results[0].get("session") == parent_receipt.get("planBeginSession")
            and results[0].get("day") == parent_receipt.get("planBeginDay")
            and results[8].get("checkpointId") == parent_receipt.get("checkpointId")
            and results[8].get("manifestSha256") == parent_receipt.get("manifestSha256")
            and results[10].get("pauseSeconds") == parent_receipt.get("pauseSeconds")
            and results[10].get("pauseLimitExceeded") == parent_receipt.get("pauseLimitExceeded"))
    return sha256(canonical({"session": session, "children": rows})).hexdigest()
