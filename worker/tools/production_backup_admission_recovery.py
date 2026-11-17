"""Trusted-main one-shot close/drain/freeze after a reviewed open backup.

Only the dedicated rehearsal can be modified. Every control write has an
exclusive durable intent; an existing or unknown intent is never retried.
"""
from contextlib import closing
from copy import deepcopy
from datetime import datetime, timezone
from hashlib import sha256
import hmac
from http.client import HTTPSConnection, HTTPException
import json
import os
from pathlib import Path
import re
import tempfile
from time import monotonic, sleep
from urllib.parse import quote, urlencode
import xml.etree.ElementTree as ET

import prepare_isolation_artifact as github
from production_backup_webhook_recovery import context, source_run, open_store, claim_intent_once, inspect as inspect_webhook
from production_control import API, Controller, Telegram
from production_lifecycle_drill import SERVICE, ORIGINAL_ORIGIN, approval
from production_release_evidence import load_release
from production_storage import PrivateStore
from production_target import TEST_BOT_ID, canonical, parsed, require, validate_target


def list_history(store, target_sha, *, prefix=None):
    """Use S3 IsTruncated/continuation to prove a complete bounded inventory."""
    require(re.fullmatch(r"[0-9a-f]{64}", target_sha or "") is not None)
    prefix = prefix or "maintenance/production-control/evidence/daily-backup-anchor/" + target_sha + "/"
    store.verify()
    if store.objects is not None:
        return store.objects.list(prefix, maximum=10000)
    try:
        token = store.api("GET", store.api.root + "/tokens/verify")
    except Exception as error:
        # Only documented account-token access failures may use user-token verification.
        require(getattr(error, "http_status", None) in {400, 401, 403, 404})
        token = store.api("GET", "/user/tokens/verify")
    require(isinstance(token, dict) and token.get("status") == "active"
            and re.fullmatch(r"[0-9a-f]{32}", token.get("id", "")) is not None)
    host, path = store.api.target["accountId"] + ".r2.cloudflarestorage.com", "/" + quote(store.bucket, safe="-_.~")
    keys, seen_cursors, cursor = [], set(), None
    while True:
        query = {"list-type": "2", "max-keys": "1000", "prefix": prefix}
        if cursor is not None:
            query["continuation-token"] = cursor
        encoded = urlencode(sorted(query.items()), quote_via=quote, safe="-_.~")
        now = datetime.now(timezone.utc)
        stamp, day, payload = now.strftime("%Y%m%dT%H%M%SZ"), now.strftime("%Y%m%d"), sha256(b"").hexdigest()
        signed = "host;x-amz-content-sha256;x-amz-date"
        headers_text = "host:" + host + "\nx-amz-content-sha256:" + payload + "\nx-amz-date:" + stamp + "\n"
        request = "\n".join(("GET", path, encoded, headers_text, signed, payload))
        scope = day + "/auto/s3/aws4_request"
        message = "\n".join(("AWS4-HMAC-SHA256", stamp, scope, sha256(request.encode("ascii")).hexdigest()))
        key = ("AWS4" + sha256(store.api.token.encode("ascii")).hexdigest()).encode("ascii")
        for part in (day, "auto", "s3", "aws4_request"):
            key = hmac.digest(key, part.encode("ascii"), "sha256")
        signature = hmac.digest(key, message.encode("ascii"), "sha256").hex()
        headers = {"Host": host, "x-amz-date": stamp, "x-amz-content-sha256": payload,
                   "Authorization": "AWS4-HMAC-SHA256 Credential=" + token["id"] + "/" + scope
                       + ", SignedHeaders=" + signed + ", Signature=" + signature}
        try:
            with closing(HTTPSConnection(host, timeout=30)) as connection:
                connection.request("GET", path + "?" + encoded, headers=headers)
                with closing(connection.getresponse()) as response:
                    require(response.status == 200)
                    raw = response.read(2 * 1024 * 1024 + 1)
        except (OSError, HTTPException, ValueError):
            require(False, "The private anchor inventory is not confirmed.")
        require(len(raw) <= 2 * 1024 * 1024 and b"<!DOCTYPE" not in raw.upper())
        try:
            root = ET.fromstring(raw)
        except ET.ParseError:
            require(False, "The private anchor inventory is malformed.")
        ns = "{http://s3.amazonaws.com/doc/2006-03-01/}"
        require(root.tag == ns + "ListBucketResult" and all(len(root.findall(ns + field)) == 1
                for field in ("Name", "Prefix", "IsTruncated")) and len(root.findall(ns + "NextContinuationToken")) <= 1
                and root.findtext(ns + "Name") == store.bucket and root.findtext(ns + "Prefix") == prefix)
        truncated = root.findtext(ns + "IsTruncated")
        require(truncated in {"true", "false"})
        contents = root.findall(ns + "Contents")
        require(len(contents) <= 1000 and all(len(item.findall(ns + "Key")) == 1 for item in contents))
        page = [item.findtext(ns + "Key") for item in contents]
        require(all(isinstance(item, str) and item.startswith(prefix) for item in page))
        keys.extend(page)
        require(len(keys) <= 10000 and len(keys) == len(set(keys)))
        next_cursor = root.findtext(ns + "NextContinuationToken")
        if truncated == "false":
            require(next_cursor is None)
            return sorted(keys)
        require(isinstance(next_cursor, str) and 0 < len(next_cursor) <= 4096 and next_cursor not in seen_cursors and page)
        seen_cursors.add(next_cursor)
        cursor = next_cursor


def idle_anchor(store, target, session, candidate, expected_genesis, *, verify_session=True):
    require(re.fullmatch(r"[0-9a-f]{64}", expected_genesis or "") is not None)
    prefix = "maintenance/production-control/registrations/"
    genesis_raw = store.get(prefix + "daily-backup-genesis-" + target.digest + ".json")
    require(sha256(genesis_raw).hexdigest() == expected_genesis)
    genesis = parsed(genesis_raw)
    require(canonical(genesis) == genesis_raw and set(genesis) == {"version", "targetSha256", "initialAnchorSha256"}
            and genesis["version"] == 1 and genesis["targetSha256"] == target.digest)
    anchor_raw = store.get(prefix + "daily-backup-anchor-" + target.digest + ".json")
    anchor = parsed(anchor_raw)
    require(canonical(anchor) == anchor_raw and anchor.get("targetSha256") == target.digest
            and anchor.get("state") == "idle" and anchor.get("session") == session
            and anchor.get("controlRevision") == candidate and type(anchor.get("generation")) is int
            and 2 <= anchor["generation"] <= 10000)
    keys = list_history(store, target.digest)
    require(len(keys) == anchor["generation"], "An anchor history fork or missing generation requires reconciliation.")
    base = "maintenance/production-control/evidence/daily-backup-anchor/" + target.digest + "/"
    require(all(re.fullmatch(re.escape(base) + r"[0-9]{12}-[a-f0-9]{64}\.json", item)
                and int(item.rsplit("/", 1)[1][:12]) <= anchor["generation"] for item in keys))
    current, raw = anchor, anchor_raw
    while True:
        require(set(current) == {"version", "targetSha256", "generation", "previousSha256", "state", "session", "day", "controlRevision"}
                and type(current["version"]) is int and current["version"] == 1
                and current["state"] in {"idle", "active"}
                and re.fullmatch(r"[1-9][0-9]{0,19}-[1-9][0-9]{0,19}", current.get("session", ""))
                and re.fullmatch(r"[0-9]{4}/[0-9]{2}/[0-9]{2}", current.get("day", ""))
                and re.fullmatch(r"[a-f0-9]{40}", current.get("controlRevision", "")))
        key = base + str(current["generation"]).zfill(12) + "-" + sha256(raw).hexdigest() + ".json"
        require(key in keys and store.get(key) == raw)
        if current["generation"] == 1:
            require(current.get("state") == "idle" and current.get("previousSha256") is None
                    and sha256(raw).hexdigest() == genesis.get("initialAnchorSha256"))
            break
        prior_sha = current.get("previousSha256")
        require(re.fullmatch(r"[0-9a-f]{64}", prior_sha or "") is not None)
        previous_key = base + str(current["generation"] - 1).zfill(12) + "-" + prior_sha + ".json"
        require(previous_key in keys)
        prior_raw = store.get(previous_key)
        require(sha256(prior_raw).hexdigest() == prior_sha)
        previous = parsed(prior_raw)
        require(canonical(previous) == prior_raw and previous.get("targetSha256") == target.digest
                and previous.get("generation") == current["generation"] - 1
                and ((current["state"] == "idle" and previous.get("state") == "active"
                      and all(current.get(field) == previous.get(field) for field in ("session", "day", "controlRevision")))
                     or (current["state"] == "active" and previous.get("state") == "idle"
                         and current.get("session") != previous.get("session"))))
        current, raw = previous, prior_raw
    if verify_session:
        verified_journal(store, target.digest, session, candidate, anchor["day"])
    return sha256(anchor_raw).hexdigest()


def verified_journal(store, target_sha, session, candidate, day):
    """Prove every journal generation and accept only unambiguous terminal paths."""
    prefix = "maintenance/production-control/evidence/daily-backup/" + day + "/" + session + "/"
    keys = list_history(store, target_sha, prefix=prefix)
    require(2 <= len(keys) < 64, "The complete backup session journal is missing or exceeds its bound.")
    events, previous = [], None
    for index, key in enumerate(keys, 1):
        require(key == prefix + str(index).zfill(4) + ".json", "The backup journal has a gap or unknown key.")
        raw = store.get(key)
        event = parsed(raw)
        require(canonical(event) == raw and set(event) == {"version", "session", "targetSha256", "controlRevision",
                "sequence", "previousSha256", "timestamp", "stage", "details"}
                and type(event["version"]) is int and event["version"] == 1 and event["session"] == session
                and event["targetSha256"] == target_sha and event["controlRevision"] == candidate
                and type(event["sequence"]) is int and event["sequence"] == index
                and event["previousSha256"] == previous and type(event["timestamp"]) is int and event["timestamp"] > 0
                and isinstance(event["details"], dict) and (not events or event["timestamp"] >= events[-1]["timestamp"]))
        previous = sha256(raw).hexdigest()
        events.append(event)
    stages = [event["stage"] for event in events]
    completed_open = ["started", "preflight", "pause-intent", "paused", "freeze-intent", "frozen",
                      "frozen-data", "capture-intent", "verified", "resume-intent", "resumed"]
    completed_frozen = ["started", "preflight", "frozen", "frozen-data", "capture-intent", "verified", "preserved-frozen"]
    no_export = stages in (["started", "failed"], ["started", "preflight", "failed"])
    require(no_export or stages in (completed_open, completed_frozen),
            "The released anchor does not have an independently confirmed safe terminal journal.")
    if not no_export:
        verified = next(event["details"] for event in events if event["stage"] == "verified")
        require(re.fullmatch(r"[a-f0-9]{32}", verified.get("checkpointId", ""))
                and re.fullmatch(r"[a-f0-9]{64}", verified.get("manifestSha256", "")))
    return previous


def _unknown(state):
    return any(state["terminal"].get(key, 0) for key in
               ("uncertain", "terminalUnknown", "terminalEditFailure", "unknownInvocations", "unknownUpdates"))


def aborted_plan_or_execute(env, *, execute):
    """Reconcile only an ended source whose own backup anchor is confirmed released.

    A plan is read-only. Execution requires the exact plan digest and rechecks all
    observations before claiming either write intent. Ambiguous writes never retry.
    """
    require(context(env) is False, "Aborted recovery is only available in the manual trusted workflow.")
    run_id, attempt, candidate = source_run(env, False)
    require(re.fullmatch(r"[0-9a-f]{64}", env.get("WEBHOOK_SNAPSHOT_SHA256", "")) is not None)
    observed = inspect_webhook(env)
    require(observed.get("status") == "observed" and observed.get("intentPresent") is False
            and observed.get("completionPresent") is False)
    draft, secrets, previous, store, prefix = open_store(env)
    raw = store.get(prefix + "registration.json")
    require(sha256(raw).hexdigest() == env.get("WEBHOOK_REGISTRATION_SHA256"))
    registered = parsed(raw)
    target = validate_target(registered.get("target"))
    desired = deepcopy(draft.data)
    for key in ("workerId", "workerCreatedOn", "d1Id", "d1CreatedAt", "bucketCreatedAt", "backupBucketCreatedAt"):
        desired[key] = target.data[key]
    require(target.environment == "rehearsal" and target.data["workerName"] == SERVICE
            and target.data["botId"] == previous["botId"] == TEST_BOT_ID
            and target.data["botUsername"] == "test_cfsubs_bot"
            and registered.get("draftSha256") == draft.digest and registered.get("targetSha256") == target.digest
            and registered.get("configurationSha256") == target.configuration_digest
            and validate_target(desired).configuration_digest == target.configuration_digest)
    session = run_id + "-" + attempt
    evidence = prefix + "backup-admission-" + session + "-"
    for stage in ("pause-intent", "pause-confirmed", "freeze-intent", "freeze-confirmed"):
        require(store.get(evidence + stage + ".json", absent=True) is None,
                "An earlier admission write may have started; do not repeat it.")
    token = env.get("SUBS_BOT_CF_BOOTSTRAP_TOKEN", "")
    backup_store = PrivateStore(API(target, token), target.data["backupBucketName"])
    anchor = idle_anchor(backup_store, target, session, candidate, env.get("BACKUP_GENESIS_SHA256", ""))
    with tempfile.TemporaryDirectory(prefix="trusted-aborted-admission-", dir=env["RUNNER_TEMP"]) as directory:
        archived = load_release(target, token, env.get("BACKUP_SOURCE_CHECKPOINT_ID", ""),
                                env.get("BACKUP_SOURCE_MANIFEST_SHA256", ""), Path(directory))
        require(archived["sourceTarget"].configuration_digest == target.configuration_digest)
        guard = lambda: github.require_current_main(env["GITHUB_SHA"])
        ctl = Controller(target, API(target, token), API(target, env.get("SUBS_BOT_CF_DEPLOY_TOKEN", "")),
            archived["bundle"], archived["manifest"], guard=guard,
            telegram=Telegram(target, secrets, rehearsal_previous_url=ORIGINAL_ORIGIN + "/telegram/webhook"),
            secrets=secrets, control_revision=env["GITHUB_SHA"])
        state = ctl.plan_pause()
        require(state["control"]["admission"] == "open" and state["control"]["workers"] == "run"
                and not any(state["work"].values()) and not _unknown(state),
                "Only a quiet open state with no unknown external result can be planned.")
        plan = {"version": 1, "kind": "aborted-isolation-admission", "session": session,
                "targetSha256": target.digest, "sourceMainSha": env["WEBHOOK_SOURCE_MAIN_SHA"],
                "candidateRevision": candidate, "snapshotSha256": env["WEBHOOK_SNAPSHOT_SHA256"],
                "checkpointId": env.get("BACKUP_SOURCE_CHECKPOINT_ID", ""),
                "manifestSha256": env.get("BACKUP_SOURCE_MANIFEST_SHA256", ""),
                "anchorSha256": anchor, "predecessorSha256": state["stateSha256"]}
        plan_sha = sha256(canonical(plan)).hexdigest()
        if not execute:
            return {"status": "read-only-plan", "planSha256": plan_sha, "targetSha256": target.digest}
        require(env.get("BACKUP_APPROVED_PLAN_SHA256") == plan_sha,
                "The exact current read-only plan was not independently approved.")
        intent = {"version": 1, "targetSha256": target.digest, "session": session, "candidateRevision": candidate,
                  "readySha256": plan_sha, "anchorSha256": anchor, "predecessorSha256": state["stateSha256"]}
        guard()
        require(idle_anchor(backup_store, target, session, candidate, env.get("BACKUP_GENESIS_SHA256", "")) == anchor)
        claim_intent_once(store, evidence + "pause-intent.json", canonical(intent))
        require(idle_anchor(backup_store, target, session, candidate, env.get("BACKUP_GENESIS_SHA256", "")) == anchor)
        paused = ctl.transition("pause", approval(target, "pause", ctl.revision, state["stateSha256"]), state["stateSha256"])
        confirmed = {"version": 1, "intentSha256": sha256(canonical(intent)).hexdigest(), "stateSha256": paused["stateSha256"]}
        store.put(evidence + "pause-confirmed.json", canonical(confirmed))
        drained = ctl.inspect()
        require(drained["control"] == paused["control"] and drained["release"] == state["release"]
                and drained["configurationSha256"] == target.configuration_digest
                and not any(drained["work"].values()) and not _unknown(drained),
                "The target is paused but work or an external outcome is unresolved.")
        require(idle_anchor(backup_store, target, session, candidate, env.get("BACKUP_GENESIS_SHA256", "")) == anchor)
        freeze_intent = {"version": 1, "targetSha256": target.digest, "session": session,
                         "pauseConfirmationSha256": sha256(canonical(confirmed)).hexdigest(),
                         "predecessorSha256": drained["stateSha256"]}
        guard()
        claim_intent_once(store, evidence + "freeze-intent.json", canonical(freeze_intent))
        frozen = ctl.transition("freeze", approval(target, "freeze", ctl.revision, drained["stateSha256"]), drained["stateSha256"])
        require(frozen["control"]["admission"] == "closed" and frozen["control"]["workers"] == "frozen"
                and not any(frozen["work"].values()) and not _unknown(frozen))
        completion = {"version": 1, "intentSha256": sha256(canonical(freeze_intent)).hexdigest(),
                      "stateSha256": frozen["stateSha256"], "targetSha256": target.digest,
                      "configurationSha256": target.configuration_digest, "control": frozen["control"],
                      "release": frozen["release"], "candidateRevision": candidate,
                      "dispatcherRevision": env["WEBHOOK_SOURCE_MAIN_SHA"]}
        store.put(evidence + "freeze-confirmed.json", canonical(completion))
        return {"status": "closed-and-frozen", "stateSha256": frozen["stateSha256"],
                "freezeConfirmationSha256": sha256(canonical(completion)).hexdigest(), "targetSha256": target.digest}


def run(env):
    automatic = context(env)
    run_id, attempt, candidate = source_run(env, automatic)
    if not automatic:
        require(re.fullmatch(r"[0-9a-f]{64}", env.get("WEBHOOK_SNAPSHOT_SHA256", "")) is not None,
                "Manual admission cleanup requires the independently pinned original webhook snapshot.")
    webhook = inspect_webhook(env)
    require(webhook.get("status") == "observed" and webhook.get("intentPresent") is False
            and webhook.get("completionPresent") is False,
            "A webhook restoration may have started; do not close admission.")
    draft, secrets, previous, store, prefix = open_store(env)
    registration_raw = store.get(prefix + "registration.json")
    require(sha256(registration_raw).hexdigest() == env.get("WEBHOOK_REGISTRATION_SHA256"))
    registration = parsed(registration_raw)
    target = validate_target(registration.get("target"))
    desired = deepcopy(draft.data)
    for key in ("workerId", "workerCreatedOn", "d1Id", "d1CreatedAt", "bucketCreatedAt", "backupBucketCreatedAt"):
        desired[key] = target.data[key]
    require(target.environment == "rehearsal" and target.data["workerName"] == SERVICE
            and target.data["botId"] == previous["botId"] == TEST_BOT_ID
            and target.data["botUsername"] == "test_cfsubs_bot"
            and validate_target(desired).configuration_digest == target.configuration_digest
            and registration.get("draftSha256") == draft.digest and registration.get("targetSha256") == target.digest
            and registration.get("configurationSha256") == target.configuration_digest)
    token = env.get("SUBS_BOT_CF_BOOTSTRAP_TOKEN", "")
    backup_store = PrivateStore(API(target, token), target.data["backupBucketName"])
    session = run_id + "-" + attempt
    ready_raw = store.get(prefix + session + "-open-backup-ready-for-cleanup.json")
    ready = parsed(ready_raw)
    require(canonical(ready) == ready_raw and set(ready) == {"state"} and isinstance(ready["state"], dict))
    state = ready["state"]
    require(state.get("targetSha256") == target.digest and state.get("configurationSha256") == target.configuration_digest
            and state.get("control", {}).get("admission") == "open" and state["control"].get("workers") == "run"
            and not any(state.get("work", {}).values()) and not _unknown(state))
    jobs = github._get_json("/actions/runs/" + run_id + "/attempts/1/jobs?per_page=100", github._github_token())
    require(isinstance(jobs.get("jobs"), list) and type(jobs.get("total_count")) is int
            and jobs["total_count"] == len(jobs["jobs"]) < 100)
    phase_source = env.get("WEBHOOK_SOURCE_KIND", "reviewed-head") == "phase-coordinator"
    expected_step = "Coordinate reviewed isolated backup phases" if phase_source else "Run the reviewed candidate against only dedicated isolation"
    steps = [step for job in jobs["jobs"] for step in job.get("steps", []) if step.get("name") == expected_step]
    require(len(steps) == 1 and steps[0].get("status") == "completed" and steps[0].get("conclusion") == "success",
            "The exact original candidate step is not independently confirmed successful.")
    receipt_raw = store.get(prefix + session + "-backup-head-acceptance.json")
    receipt = parsed(receipt_raw)
    require(canonical(receipt) == receipt_raw and receipt.get("version") == 1
            and receipt.get("status") == "candidate-complete-before-trusted-cleanup"
            and receipt.get("runId") == run_id and receipt.get("runAttempt") == attempt
            and receipt.get("controllerRevision") == candidate and receipt.get("dispatcherRevision") == env.get("WEBHOOK_SOURCE_MAIN_SHA")
            and receipt.get("targetSha256") == target.digest and receipt.get("readySha256") == sha256(ready_raw).hexdigest()
            and receipt.get("admissionRestored") is True and receipt.get("authorizationUnchanged") is True
            and receipt.get("confirmedReceiptsNotRepeated") is True,
            "The private candidate acceptance receipt is missing or differs.")
    if phase_source:
        selected = [job for job in jobs["jobs"] if isinstance(job, dict) and job.get("name") == "coordinate"]
        require(len(selected) == 1 and str(selected[0].get("run_id")) == run_id and selected[0].get("run_attempt") == 1
                and selected[0].get("head_sha") == env.get("WEBHOOK_SOURCE_MAIN_SHA")
                and (selected[0].get("status"), selected[0].get("conclusion")) == ("completed", "success")
                and receipt.get("snapshotSha256") == webhook.get("snapshotSha256")
                and receipt.get("sourceCheckpointId") == env.get("BACKUP_SOURCE_CHECKPOINT_ID")
                and receipt.get("sourceManifestSha256") == env.get("BACKUP_SOURCE_MANIFEST_SHA256")
                and re.fullmatch(r"[1-9][0-9]{0,19}", receipt.get("coordinatorSession", ""))
                and re.fullmatch(r"[1-9][0-9]{0,19}-1", receipt.get("planBeginSession", ""))
                and re.fullmatch(r"[0-9]{4}/[0-9]{2}/[0-9]{2}", receipt.get("planBeginDay", "")))
    def observe_anchors():
        app_session = receipt["planBeginSession"] if phase_source else session
        app = idle_anchor(backup_store, target, app_session, candidate, env.get("BACKUP_GENESIS_SHA256", ""))
        if not phase_source:
            return {"app": app}
        import trusted_backup_phase_cleanup as phase
        policy = parsed(env.get("SUBS_BOT_BACKUP_POLICY_JSON", ""))
        require(isinstance(policy, dict) and type(policy.get("pauseLimitSeconds")) is int)
        coordinator = phase.coordinator_anchor(backup_store, target, receipt["coordinatorSession"], candidate,
                                               env.get("SUBS_BOT_BACKUP_COORDINATOR_GENESIS_SHA256", ""))
        children = phase.child_evidence(backup_store, target.digest, receipt["coordinatorSession"],
            env["WEBHOOK_SOURCE_MAIN_SHA"], candidate, github._github_token(),
            source_checkpoint=env.get("BACKUP_SOURCE_CHECKPOINT_ID", ""),
            source_manifest=env.get("BACKUP_SOURCE_MANIFEST_SHA256", ""), validation_json=env.get("HEAD_VALIDATION_JSON", ""),
            policy=policy, writer_run_id=run_id, parent_receipt=receipt)
        return {"app": app, "coordinator": coordinator, "children": children}
    observed_anchors = observe_anchors()
    anchor_sha = sha256(canonical(observed_anchors)).hexdigest() if phase_source else observed_anchors["app"]
    root = Path(env["RUNNER_TEMP"])
    with tempfile.TemporaryDirectory(prefix="trusted-admission-source-", dir=root) as directory:
        archived = load_release(target, token, env.get("BACKUP_SOURCE_CHECKPOINT_ID", ""),
                                env.get("BACKUP_SOURCE_MANIFEST_SHA256", ""), Path(directory))
        require(archived["sourceTarget"].configuration_digest == target.configuration_digest)
        data = API(target, token)
        worker = API(target, env.get("SUBS_BOT_CF_DEPLOY_TOKEN", ""))
        guard = lambda: github.require_current_main(env["GITHUB_SHA"])
        ctl = Controller(target, data, worker, archived["bundle"], archived["manifest"], guard=guard,
            telegram=Telegram(target, secrets, rehearsal_previous_url=ORIGINAL_ORIGIN + "/telegram/webhook"),
            secrets=secrets, control_revision=env["GITHUB_SHA"])
        current = ctl.inspect()
        require(current["control"] == state["control"] and current["release"] == state["release"]
                and current["configurationSha256"] == state["configurationSha256"] and not _unknown(current))
        pause = ctl.plan_pause()
        require(pause["control"] == state["control"] and pause["release"] == state["release"] and not _unknown(pause))
        intent_key = prefix + "backup-admission-" + session + "-pause-intent.json"
        confirmed_key = prefix + "backup-admission-" + session + "-pause-confirmed.json"
        intent = {"version": 1, "targetSha256": target.digest, "session": session, "candidateRevision": candidate,
                  "readySha256": sha256(ready_raw).hexdigest(), "anchorSha256": anchor_sha,
                  "predecessorSha256": pause["stateSha256"]}
        guard()
        require(observe_anchors() == observed_anchors)
        claim_intent_once(store, intent_key, canonical(intent))
        require(observe_anchors() == observed_anchors)
        after = ctl.transition("pause", approval(target, "pause", ctl.revision, pause["stateSha256"]), pause["stateSha256"])
        confirmed = {"version": 1, "intentSha256": sha256(canonical(intent)).hexdigest(), "stateSha256": after["stateSha256"]}
        store.put(confirmed_key, canonical(confirmed))
        deadline = monotonic() + 180
        while True:
            drained = ctl.inspect()
            require(drained["control"] == after["control"] and drained["release"] == state["release"]
                    and drained["configurationSha256"] == state["configurationSha256"] and not _unknown(drained),
                    "The confirmed paused control or release changed while work was draining.")
            if not any(drained["work"].values()):
                break
            require(monotonic() < deadline, "Accepted work has not drained; keep the target closed and alert.")
            sleep(2)
        require(observe_anchors() == observed_anchors)
        freeze_key = prefix + "backup-admission-" + session + "-freeze-intent.json"
        freeze_confirmed = prefix + "backup-admission-" + session + "-freeze-confirmed.json"
        freeze_intent = {"version": 1, "targetSha256": target.digest, "session": session,
                         "pauseConfirmationSha256": sha256(canonical(confirmed)).hexdigest(),
                         "predecessorSha256": drained["stateSha256"]}
        guard()
        claim_intent_once(store, freeze_key, canonical(freeze_intent))
        frozen = ctl.transition("freeze", approval(target, "freeze", ctl.revision, drained["stateSha256"]), drained["stateSha256"])
        require(frozen["control"]["admission"] == "closed" and frozen["control"]["workers"] == "frozen"
                and not any(frozen["work"].values()) and not _unknown(frozen))
        completion = {"version": 1, "intentSha256": sha256(canonical(freeze_intent)).hexdigest(),
                      "stateSha256": frozen["stateSha256"], "targetSha256": target.digest,
                      "configurationSha256": target.configuration_digest, "control": frozen["control"],
                      "release": frozen["release"], "candidateRevision": candidate,
                      "dispatcherRevision": env["WEBHOOK_SOURCE_MAIN_SHA"]}
        store.put(freeze_confirmed, canonical(completion))
        return {"status": "closed-and-frozen", "stateSha256": frozen["stateSha256"],
                "freezeConfirmationSha256": sha256(canonical(completion)).hexdigest(), "targetSha256": target.digest}


if __name__ == "__main__":
    try:
        os.umask(0o077)
        action = os.environ.get("BACKUP_ADMISSION_ACTION", "complete")
        require(action in {"complete", "plan-aborted", "execute-aborted"})
        result = run(os.environ) if action == "complete" else aborted_plan_or_execute(os.environ, execute=action == "execute-aborted")
        print(json.dumps(result, sort_keys=True))
        if os.environ.get("GITHUB_OUTPUT"):
            with open(os.environ["GITHUB_OUTPUT"], "a", encoding="ascii") as output:
                if "freezeConfirmationSha256" in result:
                    output.write("freeze_confirmation_sha256=" + result["freezeConfirmationSha256"] + "\n")
                if "planSha256" in result:
                    output.write("plan_sha256=" + result["planSha256"] + "\n")
    except Exception:
        print(json.dumps({"status": "unknown", "reason": "Admission cleanup is not confirmed; retain all private intents and inspect before retry."}))
        raise SystemExit(1) from None
