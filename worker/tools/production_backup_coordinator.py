"""Single-use dispatch journal for approved production backup checkpoints.

This module never fabricates a production approval. Its caller must validate the
protected main workflow, pinned configuration and every checkpoint result. An
unconfirmed dispatch is intentionally not retried.
"""
from hashlib import sha256
import re

import prepare_isolation_artifact as artifact
from production_target import canonical, parsed, require

HEX = re.compile(r"[a-f0-9]{64}")
REVISION = re.compile(r"[a-f0-9]{40}")
DECIMAL = re.compile(r"[1-9][0-9]{0,19}")
STEPS = ("plan-begin", "begin", "preflight", "plan-pause", "pause", "drain", "freeze", "capture", "verify", "plan-activate", "activate")
BASE = "maintenance/production-control/evidence/backup-coordinator/"


def valid_target(target):
    require(isinstance(target, str) and HEX.fullmatch(target) is not None)
    return target


def event_key(target, session, sequence):
    valid_target(target)
    require(DECIMAL.fullmatch(session or "") and type(sequence) is int and 1 <= sequence <= len(STEPS))
    return f"{BASE}{target}/{session}/{sequence:02d}-intent.json"


def receipt_key(target, session, sequence):
    return event_key(target, session, sequence).replace("-intent.json", "-receipt.json")


def result_archive_key(target, session, sequence):
    return event_key(target, session, sequence).replace("-intent.json", "-result.zip")


def dispatch_intent(*, target, session, sequence, revision, nonce, input_sha256, created_at):
    valid_target(target)
    require(DECIMAL.fullmatch(session or "") and type(sequence) is int and 1 <= sequence <= len(STEPS)
            and REVISION.fullmatch(revision or "") and HEX.fullmatch(nonce or "") and HEX.fullmatch(input_sha256 or "")
            and type(created_at) is int and created_at > 0)
    return {"version": 1, "kind": "production-backup-dispatch-intent", "targetSha256": target,
            "session": session, "sequence": sequence, "action": STEPS[sequence - 1],
            "controllerRevision": revision, "nonce": nonce, "inputSha256": input_sha256, "createdAt": created_at}


def write_dispatch_once(store, intent):
    """Claim a single stage; callers must not dispatch unless readback succeeds."""
    require(isinstance(intent, dict) and intent == dispatch_intent(target=intent.get("targetSha256"),
        session=intent.get("session"), sequence=intent.get("sequence"), revision=intent.get("controllerRevision"),
        nonce=intent.get("nonce"), input_sha256=intent.get("inputSha256"), created_at=intent.get("createdAt")))
    key = event_key(intent["targetSha256"], intent["session"], intent["sequence"])
    existing, _ = store.get(key, absent=True)
    require(existing is None, "A dispatch intent already exists; inspect it rather than reissue it.")
    raw = canonical(intent)
    store.put_once(key, raw)
    observed, _ = store.get(key)
    require(observed == raw, "The exact dispatch intent was not independently confirmed.")
    return sha256(raw).hexdigest()


def receipt(intent, run_id, result, artifact_id, archive_sha256):
    require(DECIMAL.fullmatch(run_id or "") and DECIMAL.fullmatch(artifact_id or "")
            and HEX.fullmatch(archive_sha256 or "") and isinstance(result, dict))
    raw = canonical(result)
    require(0 < len(raw) <= 65536)
    return {"version": 1, "kind": "production-backup-dispatch-receipt", "intentSha256": sha256(canonical(intent)).hexdigest(),
            "runId": run_id, "runAttempt": "1", "resultSha256": sha256(raw).hexdigest(), "result": result,
            "artifactId": artifact_id, "artifactSha256": archive_sha256}


def inspect_stage(store, target, session, sequence):
    """Only classify evidence; neither an absent receipt nor a 404 authorizes replay."""
    raw, _ = store.get(event_key(target, session, sequence), absent=True)
    result, _ = store.get(receipt_key(target, session, sequence), absent=True)
    original, _ = store.get(result_archive_key(target, session, sequence), absent=True)
    if raw is None:
        require(result is None and original is None, "A result without its dispatch intent is invalid.")
        return {"status": "not-recorded", "dispatchPermitted": False}
    intent = parsed(raw)
    require(canonical(intent) == raw and intent == dispatch_intent(target=target, session=session, sequence=sequence,
        revision=intent.get("controllerRevision"), nonce=intent.get("nonce"), input_sha256=intent.get("inputSha256"),
        created_at=intent.get("createdAt")))
    if result is None:
        return {"status": "unknown", "intentSha256": sha256(raw).hexdigest(), "dispatchPermitted": False}
    value = parsed(result)
    require(canonical(value) == result and value == receipt(intent, value.get("runId"), value.get("result"),
                                                             value.get("artifactId"), value.get("artifactSha256"))
            and isinstance(original, bytes) and sha256(original).hexdigest() == value["artifactSha256"]
            and archive_result(original) == value["result"])
    return {"status": "receipt-needs-independent-run-verification", "intentSha256": sha256(raw).hexdigest(),
            "runId": value["runId"], "dispatchPermitted": False}


class CoordinatorStore:
    """Give the coordinator an independent namespace in the fixed private bucket."""
    def __init__(self, objects, target):
        self.objects = objects
        self.prefix = BASE + valid_target(target) + "/coordination/"

    def _key(self, key):
        require(isinstance(key, str) and key.startswith("maintenance/production-control/")
                and not any(part in {".", ".."} for part in key.split("/")))
        return self.prefix + key

    def get(self, key, *, absent=False):
        raw, _ = self.objects.get(self._key(key), absent=absent)
        return raw

    def get_with_etag(self, key):
        return self.objects.get(self._key(key), absent=True)

    def put(self, key, body):
        self.objects.put_once(self._key(key), body)
        return sha256(body).hexdigest()

    def compare_and_put(self, key, expected_body, expected_etag, body):
        return self.objects.compare_and_put(self._key(key), expected_body, expected_etag, body)

    def _list(self, prefix):
        mapped = self._key(prefix)
        keys = self.objects.list(mapped)
        require(all(key.startswith(self.prefix) for key in keys))
        return [key[len(self.prefix):] for key in keys]

    def list_backup_anchor_history(self, target_sha256):
        require(HEX.fullmatch(target_sha256 or ""))
        return self._list("maintenance/production-control/evidence/daily-backup-anchor/" + target_sha256 + "/")

    def list_backup_journals(self):
        # Initialization cannot mistake old stage intents for a fresh ledger.
        root = BASE + self.prefix[len(BASE):].split("/", 1)[0] + "/"
        keys = self.objects.list(root)
        return [key for key in keys if "/coordination/" not in key]

    def list_backup_session(self, prefix):
        return self._list(prefix)


def require_completed_receipt(intent, value, run, workflow_id, result):
    """Authenticate an exact dispatch before any later checkpoint can run."""
    require(isinstance(intent, dict) and isinstance(value, dict) and isinstance(run, dict) and isinstance(result, dict))
    require(value == receipt(intent, str(run.get("id")), result, value.get("artifactId"), value.get("artifactSha256")))
    expected = "Production backup " + intent["action"] + " at " + intent["controllerRevision"] + " #" + intent["nonce"]
    require(run.get("display_title") == expected and run.get("run_attempt") == 1
            and run.get("workflow_id") == workflow_id and run.get("head_branch") == "main"
            and run.get("head_sha") == intent["controllerRevision"] and run.get("event") == "workflow_dispatch"
            and (run.get("status"), run.get("conclusion")) == ("completed", "success")
            and all(isinstance(run.get(key), dict) and run[key].get("id") == artifact.REPOSITORY_ID
                    for key in ("repository", "head_repository")),
            "The unique original checkpoint run did not finish successfully.")
    require(result.get("action") == intent["action"] and result.get("targetSha256") == intent["targetSha256"]
            and result.get("controlRevision") == intent["controllerRevision"]
            and result.get("consumerSwitch") == "not-authorized" and result.get("automaticReplay") is False)
    return True


def matching_run(rows, intent, workflow_id):
    """Find only the unique nonce-bound run; absence or ambiguity is not success."""
    require(isinstance(rows, list) and type(workflow_id) is int)
    title = "Production backup " + intent["action"] + " at " + intent["controllerRevision"] + " #" + intent["nonce"]
    matches = [row for row in rows if isinstance(row, dict) and row.get("display_title") == title]
    require(len(matches) == 1, "The unique dispatched run is unavailable or ambiguous.")
    run = matches[0]
    require(type(run.get("id")) is int and run["id"] > 0 and run.get("run_attempt") == 1
            and run.get("workflow_id") == workflow_id and run.get("head_sha") == intent["controllerRevision"]
            and run.get("head_branch") == "main" and run.get("event") == "workflow_dispatch"
            and all(isinstance(run.get(k), dict) and run[k].get("id") == artifact.REPOSITORY_ID
                    for k in ("repository", "head_repository")))
    return run


def dispatch_once(token, intent, inputs, store):
    """Persist an exclusive intent then make exactly one workflow-dispatch POST."""
    import json
    from urllib.request import Request
    require(isinstance(inputs, dict) and inputs.get("action") == intent["action"]
            and inputs.get("dispatch_nonce") == intent["nonce"]
            and sha256(canonical(inputs)).hexdigest() == intent["inputSha256"])
    write_dispatch_once(store, intent)
    artifact.require_current_main(intent["controllerRevision"])
    body = json.dumps({"ref": "main", "inputs": inputs}, separators=(",", ":")).encode("utf-8")
    request = Request(artifact.API_ROOT + "/actions/workflows/worker-production-backup.yml/dispatches", data=body,
                      headers={"Authorization": "Bearer " + token, "Accept": "application/vnd.github+json",
                               "Content-Type": "application/json", "X-GitHub-Api-Version": "2022-11-28"}, method="POST")
    # No retries: an exception or non-204 response is an unknown dispatch and
    # leaves the immutable intent as the reconciliation barrier.
    with artifact._OPENER.open(request, timeout=30) as response:
        require(response.status == 204 and not response.read(1), "The dispatch outcome is not confirmed.")


def selected_result(run_id, revision, action, token):
    """Read one bounded GitHub artifact tied to the successful original run."""
    require(DECIMAL.fullmatch(run_id or "") and REVISION.fullmatch(revision or "") and action in STEPS)
    listing = artifact._get_json("/actions/runs/" + run_id + "/artifacts?per_page=100", token)
    entries = listing.get("artifacts")
    require(isinstance(entries, list) and type(listing.get("total_count")) is int
            and listing["total_count"] == len(entries) < 100)
    name = "subs-bot-production-backup-" + action + "-" + run_id + "-1"
    selected = [item for item in entries if isinstance(item, dict) and item.get("name") == name]
    require(len(selected) == 1)
    item = selected[0]
    source = item.get("workflow_run")
    sha = item.get("digest", "")
    require(type(item.get("id")) is int and item["id"] > 0 and item.get("expired") is False
            and type(item.get("size_in_bytes")) is int and 0 < item["size_in_bytes"] <= 2 * 1024 * 1024
            and isinstance(sha, str) and re.fullmatch(r"sha256:[a-f0-9]{64}", sha)
            and isinstance(source, dict) and str(source.get("id")) == run_id and source.get("head_sha") == revision
            and source.get("head_branch") == "main" and source.get("repository_id") == artifact.REPOSITORY_ID
            and source.get("head_repository_id") == artifact.REPOSITORY_ID)
    raw = artifact._download(str(item["id"]), token)
    require(sha256(raw).hexdigest() == sha[7:])
    return archive_result(raw), {"artifactId": str(item["id"]), "artifactSha256": sha[7:]}, raw


def archive_result(raw):
    """Validate a retained original result archive without GitHub artifact access."""
    from io import BytesIO
    from zipfile import ZipFile
    require(isinstance(raw, bytes) and 0 < len(raw) <= 2 * 1024 * 1024)
    with ZipFile(BytesIO(raw)) as archive:
        members = archive.infolist()
        require(len(members) == 1 and members[0].filename == "production-backup-result.json"
                and members[0].filename == members[0].orig_filename and members[0].file_size <= 65536
                and not members[0].is_dir() and not members[0].flag_bits & (1 | 64))
        body = archive.read(members[0])
    value = parsed(body)
    require(canonical(value) == body and isinstance(value, dict))
    return value


def next_inputs(results, *, source_checkpoint_id, source_manifest_sha256):
    """Derive only the next fixed checkpoint from verified preceding results."""
    require(isinstance(results, list) and len(results) < len(STEPS)
            and all(isinstance(value, dict) and value.get("action") == STEPS[i] for i, value in enumerate(results))
            and re.fullmatch(r"[a-f0-9]{32}", source_checkpoint_id or "")
            and HEX.fullmatch(source_manifest_sha256 or ""))
    expected = {"plan-begin": "plan-only", "begin": "started", "preflight": "observed", "pause": "paused",
                "drain": "drained", "freeze": "frozen", "capture": "captured-unverified", "verify": "verified",
                "activate": "resumed"}
    require(all(value.get("status") == expected[value["action"]] for value in results if value["action"] in expected),
            "A prior checkpoint did not reach its expected terminal result.")
    action = STEPS[len(results)]
    inputs = {"action": action, "source_checkpoint_id": source_checkpoint_id, "source_manifest_sha256": source_manifest_sha256}
    if results:
        first = results[0]
        require(first.get("status") == "plan-only" and re.fullmatch(r"[1-9][0-9]{0,19}-1", first.get("session", ""))
                and re.fullmatch(r"[0-9]{4}/[0-9]{2}/[0-9]{2}", first.get("day", "")))
        inputs.update(session=first["session"], session_day=first["day"])
    predecessor_index = {"begin": 0, "preflight": 0, "pause": 3, "freeze": 5,
                         "capture": 6, "verify": 6, "activate": 9}.get(action)
    if predecessor_index is not None:
        predecessor = results[predecessor_index].get("stateSha256", "")
        require(HEX.fullmatch(predecessor or ""), "The exact predecessor was not returned by its plan.")
        inputs["state_sha256"] = predecessor
    return inputs


def stage_inputs(results, source_checkpoint_id, source_manifest_sha256, session, intent, pause_limit, pause_until):
    """Reconstruct the exact input digest from verified predecessors."""
    require(intent["sequence"] == len(results) + 1 and intent["action"] == STEPS[len(results)])
    if intent["action"] == "pause":
        pause_until = pause_deadline(intent, pause_limit, now=int(__import__("time").time()))
    inputs = next_inputs(results, source_checkpoint_id=source_checkpoint_id, source_manifest_sha256=source_manifest_sha256)
    inputs.update(dispatch_nonce=intent["nonce"], coordinator_session=session,
                  dispatch_deadline=str(pause_until or 0))
    return inputs, pause_until


def completed_results(store, target, session, revision, token, source_checkpoint_id, source_manifest_sha256, pause_limit, *, stop_before=None):
    """Revalidate the complete ordered receipt chain against GitHub and original artifacts."""
    workflow = artifact._get_json("/actions/workflows/worker-production-backup.yml", token)
    require(workflow.get("path") == ".github/workflows/worker-production-backup.yml" and type(workflow.get("id")) is int)
    values, pause_until = [], None
    for sequence in range(1, len(STEPS) + 1):
        if stop_before is not None and sequence == stop_before:
            break
        status = inspect_stage(store, target, session, sequence)
        if status["status"] == "not-recorded":
            # No later stage can be silently skipped or adopted.
            require(all(inspect_stage(store, target, session, later)["status"] == "not-recorded"
                        for later in range(sequence + 1, len(STEPS) + 1)))
            break
        require(status["status"] == "receipt-needs-independent-run-verification",
                "An earlier dispatch is unknown; inspect and explicitly reconcile it without reissuing.")
        raw, _ = store.get(event_key(target, session, sequence))
        raw_receipt, _ = store.get(receipt_key(target, session, sequence))
        intent, proof = parsed(raw), parsed(raw_receipt)
        require(intent["controllerRevision"] == revision)
        inputs, pause_until = stage_inputs(values, source_checkpoint_id, source_manifest_sha256, session, intent, pause_limit, pause_until)
        require(sha256(canonical(inputs)).hexdigest() == intent["inputSha256"],
                "The dispatched inputs do not match verified predecessor results.")
        run = artifact._get_json("/actions/runs/" + status["runId"] + "/attempts/1", token)
        latest = artifact._get_json("/actions/runs/" + status["runId"], token)
        require(str(latest.get("id")) == status["runId"] and latest.get("run_attempt") == 1
                and latest.get("status") == "completed", "A later checkpoint attempt requires reconciliation.")
        result = proof.get("result")
        original, _ = store.get(result_archive_key(target, session, sequence))
        require(isinstance(original, bytes) and sha256(original).hexdigest() == proof.get("artifactSha256")
                and archive_result(original) == result, "The privately retained original checkpoint result differs.")
        require_completed_receipt(intent, proof, run, workflow["id"], result)
        values.append(result)
    return values, pause_until


def confirm_stage(store, intent, run, workflow_id, result, source, original):
    """Record a verified completion exactly once; a prior receipt is never replaced."""
    key = receipt_key(intent["targetSha256"], intent["session"], intent["sequence"])
    existing, _ = store.get(key, absent=True)
    require(existing is None, "An existing receipt requires independent inspection.")
    require(isinstance(source, dict) and set(source) == {"artifactId", "artifactSha256"}
            and isinstance(original, bytes) and sha256(original).hexdigest() == source["artifactSha256"]
            and archive_result(original) == result)
    proof = receipt(intent, str(run.get("id")), result, source["artifactId"], source["artifactSha256"])
    require_completed_receipt(intent, proof, run, workflow_id, result)
    original_key = result_archive_key(intent["targetSha256"], intent["session"], intent["sequence"])
    saved, _ = store.get(original_key, absent=True)
    if saved is None:
        store.put_once(original_key, original)
        saved, _ = store.get(original_key)
    require(saved == original, "The original checkpoint result was not independently retained.")
    raw = canonical(proof)
    store.put_once(key, raw)
    observed, _ = store.get(key)
    require(observed == raw)
    return proof


def verify_context(env):
    """Only a separately protected main dispatcher can use the coordinator."""
    workflow = artifact.REPOSITORY + "/.github/workflows/worker-production-backup-coordinator.yml@" + artifact.MAIN_REF
    revision = env.get("GITHUB_SHA", "")
    require(env.get("GITHUB_REPOSITORY") == artifact.REPOSITORY
            and env.get("GITHUB_REPOSITORY_ID") == str(artifact.REPOSITORY_ID)
            and env.get("GITHUB_REF") == artifact.MAIN_REF and env.get("GITHUB_WORKFLOW_REF") == workflow
            and env.get("GITHUB_EVENT_NAME") in {"workflow_dispatch", "schedule"}
            and env.get("RUNNER_ENVIRONMENT") == "github-hosted" and env.get("GITHUB_RUN_ATTEMPT") == "1"
            and env.get("SUBS_BOT_CONTROL_ENVIRONMENT") == "subs-bot-production-backup-coordinator"
            and REVISION.fullmatch(revision or "") and DECIMAL.fullmatch(env.get("GITHUB_RUN_ID", "")))
    artifact.require_current_main(revision)
    return revision


def finished_controller(objects, target, session, revision, source_checkpoint, source_sha, policy_sha):
    raw, _ = objects.get(BASE + target + "/" + session + "/start-intent.json")
    start = parsed(raw)
    require(canonical(start) == raw and set(start) == {"version", "action", "targetSha256", "controlRevision", "session",
            "sourceCheckpointId", "sourceManifestSha256", "anchorSha256", "policySha256", "writerRunId", "writerAttempt"}
            and start.get("version") == 1 and start.get("action") == "run"
            and HEX.fullmatch(start.get("anchorSha256", "")) and start.get("targetSha256") == target and start.get("session") == session
            and start.get("sourceCheckpointId") == source_checkpoint and start.get("sourceManifestSha256") == source_sha
            and start.get("controlRevision") == revision and start.get("policySha256") == policy_sha
            and DECIMAL.fullmatch(start.get("writerRunId", ""))
            and start.get("writerAttempt") == "1")
    run = artifact._get_json("/actions/runs/" + start["writerRunId"] + "/attempts/1", artifact._github_token())
    path = ".github/workflows/worker-production-backup-coordinator.yml"
    require(str(run.get("id")) == start["writerRunId"] and run.get("head_sha") == revision
            and run.get("path") in {path, path + "@main", path + "@refs/heads/main"}
            and run.get("display_title") == "Production backup coordinator run at " + revision
            and run.get("event") == "workflow_dispatch" and run.get("head_branch") == "main"
            and run.get("status") == "completed" and run.get("run_attempt") == 1
            and all(isinstance(run.get(key), dict) and run[key].get("id") == artifact.REPOSITORY_ID
                    for key in ("repository", "head_repository")), "The original coordinator run is not confirmed stopped.")
    latest = artifact._get_json("/actions/runs/" + start["writerRunId"], artifact._github_token())
    require(str(latest.get("id")) == start["writerRunId"] and latest.get("run_attempt") == 1
            and latest.get("status") == "completed", "A later coordinator run attempt requires independent reconciliation.")
    prefix = BASE + target + "/" + session + "/writers/"
    keys = objects.list(prefix, maximum=128)
    require(len(keys) < 128)
    previous, writers = sha256(raw).hexdigest(), []
    for position, key in enumerate(keys, 1):
        require(key == prefix + str(position).zfill(4) + ".json")
        body, _ = objects.get(key)
        value = parsed(body)
        require(canonical(value) == body and set(value) == {"version", "targetSha256", "session", "controlRevision",
                "position", "previousSha256", "writerRunId", "writerAttempt", "action"}
                and value["version"] == 1 and value["targetSha256"] == target and value["session"] == session
                and value["controlRevision"] == revision and value["position"] == position
                and value["action"] in {"resume", "abort"}
                and value["previousSha256"] == previous and DECIMAL.fullmatch(value["writerRunId"] or "")
                and value["writerAttempt"] == "1")
        observed = artifact._get_json("/actions/runs/" + value["writerRunId"] + "/attempts/1", artifact._github_token())
        require(str(observed.get("id")) == value["writerRunId"] and observed.get("head_sha") == revision
                and observed.get("path") in {path, path + "@main", path + "@refs/heads/main"}
                and observed.get("display_title") == "Production backup coordinator " + value["action"] + " at " + revision
                and observed.get("event") == "workflow_dispatch" and observed.get("head_branch") == "main"
                and observed.get("status") == "completed" and observed.get("run_attempt") == 1
                and all(isinstance(observed.get(k), dict) and observed[k].get("id") == artifact.REPOSITORY_ID
                        for k in ("repository", "head_repository")), "A prior coordinator writer has not finished.")
        latest = artifact._get_json("/actions/runs/" + value["writerRunId"], artifact._github_token())
        require(str(latest.get("id")) == value["writerRunId"] and latest.get("run_attempt") == 1
                and latest.get("status") == "completed", "A later coordinator run attempt requires independent reconciliation.")
        previous = sha256(body).hexdigest()
        writers.append(value)
    return {"startSha256": sha256(raw).hexdigest(), "lastSha256": previous, "writers": writers}


def claim_resume_writer(objects, target, session, revision, history, run_id, *, action="resume"):
    """A single immutable slot serializes concurrent continuation attempts."""
    require(action in {"resume", "abort"} and DECIMAL.fullmatch(run_id or "") and isinstance(history, dict) and isinstance(history.get("writers"), list)
            and len(history["writers"]) < 127 and HEX.fullmatch(history.get("lastSha256", "")))
    position = len(history["writers"]) + 1
    value = {"version": 1, "targetSha256": target, "session": session, "controlRevision": revision,
             "position": position, "previousSha256": history["lastSha256"], "writerRunId": run_id, "writerAttempt": "1", "action": action}
    key = BASE + target + "/" + session + "/writers/" + str(position).zfill(4) + ".json"
    existing, _ = objects.get(key, absent=True)
    require(existing is None, "A continuation writer already owns this slot.")
    raw = canonical(value)
    objects.put_once(key, raw)
    observed, _ = objects.get(key)
    require(observed == raw, "The continuation claim was not independently confirmed.")
    return value


def abort_observation(objects, app_store, target, session, revision, source_checkpoint, source_sha, pause_limit, genesis):
    """Only abandon coordination after all child runs and application state are known."""
    import production_backup_transaction as maintenance
    token = artifact._github_token()
    workflow = artifact._get_json("/actions/workflows/worker-production-backup.yml", token)
    require(workflow.get("path") == ".github/workflows/worker-production-backup.yml" and type(workflow.get("id")) is int)
    verified, children, pause_until, stopped = [], [], None, False
    for sequence in range(1, len(STEPS) + 1):
        status = inspect_stage(objects, target.digest, session, sequence)
        if status["status"] == "not-recorded":
            require(all(inspect_stage(objects, target.digest, session, later)["status"] == "not-recorded"
                        for later in range(sequence + 1, len(STEPS) + 1)))
            break
        require(not stopped, "A later child exists after an unresolved result.")
        raw, _ = objects.get(event_key(target.digest, session, sequence))
        intent = parsed(raw)
        require(intent["controllerRevision"] == revision)
        inputs, pause_until = stage_inputs(verified, source_checkpoint, source_sha, session, intent, pause_limit, pause_until)
        require(sha256(canonical(inputs)).hexdigest() == intent["inputSha256"])
        run = discover_run(intent, workflow["id"], token)
        require(run.get("status") == "completed" and isinstance(run.get("conclusion"), str),
                "A dispatched child is not independently confirmed stopped.")
        children.append({"sequence": sequence, "runId": str(run["id"]), "conclusion": run["conclusion"],
                         "intentSha256": sha256(raw).hexdigest()})
        if status["status"] == "unknown":
            stopped = True
        else:
            body, _ = objects.get(receipt_key(target.digest, session, sequence))
            proof = parsed(body)
            result = proof.get("result")
            original, _ = objects.get(result_archive_key(target.digest, session, sequence))
            require(isinstance(original, bytes) and sha256(original).hexdigest() == proof.get("artifactSha256")
                    and archive_result(original) == result)
            require_completed_receipt(intent, proof, run, workflow["id"], result)
            verified.append(result)
    pin, raw_pin, _ = maintenance.Anchor(app_store, target.digest, genesis).read()
    require(pin["state"] == "idle", "The application backup anchor must first reach a confirmed safe terminal state.")
    terminal = "no-mutating-child"
    if len(children) > 1:
        require(verified and verified[0].get("action") == "plan-begin")
        first = verified[0]
        require(pin["session"] == first["session"] and pin["day"] == first["day"]
                and pin["controlRevision"] == revision)
        events = maintenance.Transaction(app_store, pin["session"], pin["day"], target.digest, revision).load()
        require(events and (events[-1]["stage"] in {"resumed", "preserved-frozen"}
                or (events[-1]["stage"] == "failed" and len(events) >= 2
                    and events[-2]["stage"] in {"started", "preflight"}
                    and events[-1]["details"].get("uncertain") is False)),
                "The application transaction lacks a confirmed safe terminal state.")
        terminal = events[-1]["stage"]
    return {"children": children, "applicationAnchorSha256": sha256(raw_pin).hexdigest(), "terminal": terminal}


def discover_run(intent, workflow_id, token):
    from urllib.parse import urlencode
    from datetime import datetime, timedelta, timezone
    # A child can only belong to this one-shot dispatch if its creation falls
    # near the immutable intent. The bounded 24-hour window avoids making an
    # hourly monitor's entire lifetime history a prerequisite. Anything outside
    # it remains unknown and cannot be re-dispatched automatically.
    created = datetime.fromtimestamp(intent["createdAt"], tz=timezone.utc)
    start = (created - timedelta(minutes=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
    end = (created + timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ")
    rows, total = [], None
    for page in range(1, 7):
        query = urlencode({"branch": "main", "created": start + ".." + end, "per_page": 100, "page": page})
        response = artifact._get_json("/actions/workflows/worker-production-backup.yml/runs?" + query, token)
        batch, count = response.get("workflow_runs"), response.get("total_count")
        require(isinstance(batch, list) and len(batch) <= 100 and type(count) is int and 0 <= count <= 500
                and (total is None or total == count))
        for row in batch:
            require(isinstance(row, dict) and isinstance(row.get("created_at"), str))
            try:
                timestamp = datetime.strptime(row["created_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
            except ValueError:
                require(False, "A checkpoint run has an invalid creation timestamp.")
            require(created - timedelta(minutes=2) <= timestamp <= created + timedelta(hours=24),
                    "The checkpoint run inventory did not honor its bounded creation window.")
        total = count
        rows.extend(batch)
        require(len(rows) <= total)
        if len(rows) == total:
            return matching_run(rows, intent, workflow_id)
        require(len(batch) == 100)
    require(False, "The complete checkpoint workflow history could not be enumerated.")


def wait_for_run(intent, token, *, deadline):
    import time
    workflow = artifact._get_json("/actions/workflows/worker-production-backup.yml", token)
    require(workflow.get("path") == ".github/workflows/worker-production-backup.yml" and type(workflow.get("id")) is int)
    while time.monotonic() < deadline:
        try:
            run = discover_run(intent, workflow["id"], token)
        except Exception:
            # An unavailable or ambiguous run never authorizes a second POST.
            time.sleep(15)
            continue
        if run.get("status") == "completed":
            require(run.get("conclusion") == "success", "The dispatched checkpoint did not complete successfully.")
            return run, workflow["id"]
        require(run.get("status") in {"queued", "in_progress", "waiting", "pending", "requested"})
        time.sleep(15)
    print("::error::A backup checkpoint did not complete within its allowed window; inspect its private intent before any recovery.", flush=True)
    require(False, "The checkpoint did not complete within the coordinator window; inspect its immutable intent.")


def pause_deadline(intent, pause_limit, *, now):
    """Use the pre-dispatch intent time, a conservative bound before pause starts."""
    require(isinstance(intent, dict) and intent.get("action") == "pause" and type(intent.get("createdAt")) is int
            and type(pause_limit) is int and 60 <= pause_limit <= 900 and type(now) is int
            and 0 < intent["createdAt"] <= now + 60)
    return intent["createdAt"] + pause_limit


def run_sequence(store, anchor, target, session, revision, source_checkpoint_id, source_manifest_sha256, token, *, deadline, pause_limit):
    """Drive the fixed checkpoint sequence; unknown external writes are never replayed."""
    from secrets import token_hex
    import time
    pinned, _raw, _etag = anchor.read()
    require(pinned["state"] == "active" and pinned["session"] == session + "-1" and pinned["controlRevision"] == revision)
    results, pause_until = completed_results(store, target, session, revision, token, source_checkpoint_id,
                                             source_manifest_sha256, pause_limit)
    while len(results) < len(STEPS):
        artifact.require_current_main(revision)
        nonce = token_hex(32)
        now = int(time.time())
        provisional = dispatch_intent(target=target, session=session, sequence=len(results) + 1, revision=revision,
                                      nonce=nonce, input_sha256="0" * 64, created_at=now)
        inputs, pause_until = stage_inputs(results, source_checkpoint_id, source_manifest_sha256, session,
                                           provisional, pause_limit, pause_until)
        intent = {**provisional, "inputSha256": sha256(canonical(inputs)).hexdigest()}
        stage_deadline = deadline
        if pause_until is not None and intent["action"] in {"pause", "freeze", "capture"}:
            remaining = pause_until - now
            if remaining <= 0:
                print("::error::The approved pause limit elapsed; inspect the private journal and use the explicitly approved recovery plan.", flush=True)
                require(False, "The pause deadline elapsed; do not dispatch another checkpoint.")
            stage_deadline = min(deadline, time.monotonic() + remaining)
        dispatch_once(token, intent, inputs, store)
        print("::notice::A protected backup checkpoint was dispatched; exact action approval remains required.", flush=True)
        run, workflow_id = wait_for_run(intent, token, deadline=stage_deadline)
        result, source, original = selected_result(str(run["id"]), revision, intent["action"], token)
        confirm_stage(store, intent, run, workflow_id, result, source, original)
        results.append(result)
    require(results[-1].get("status") == "resumed" and results[-1].get("action") == "activate")
    anchor.release(session + "-1")
    return {"status": "completed", "verifiedCheckpoints": len(results), "productionApprovalSynthesized": False}


def main(env=None):
    import os
    import time
    from datetime import datetime, timezone
    import scoped_r2
    import production_backup_transaction as maintenance
    import production_backup_cli as backup_cli
    from production_control import API, privacy
    from production_storage import PrivateStore
    from production_target import validate_target, digest

    env = os.environ if env is None else env
    revision = verify_context(env)
    action = env.get("BACKUP_COORDINATOR_ACTION", "inspect")
    require(action in {"inspect", "plan-initialize", "initialize", "plan-run", "run", "plan-resume", "resume", "plan-reconcile", "reconcile", "plan-abort", "abort"})
    if env.get("GITHUB_EVENT_NAME") == "schedule":
        require(action == "inspect", "A scheduled coordinator cannot authorize production writes.")
    target = validate_target(env.get("SUBS_BOT_TARGET_JSON", ""))
    require(target.environment == "production")
    policy = backup_cli.settings(env.get("SUBS_BOT_BACKUP_POLICY_JSON", ""))
    metadata = API(target, env.get("SUBS_BOT_CF_R2_METADATA_READ_TOKEN", ""))
    privacy(metadata, metadata.root, target.data["backupBucketName"], target.data["backupBucketCreatedAt"])
    objects = scoped_r2.from_environment(target.data["accountId"], target.data["backupBucketName"], env)
    require(objects is not None, "A separately scoped private backup bucket reader is required.")
    genesis = env.get("SUBS_BOT_BACKUP_COORDINATOR_GENESIS_SHA256", "")
    seed = maintenance.Anchor(CoordinatorStore(objects, target.digest), target.digest, "0" * 64)
    expected = sha256(seed.initial_material()[1]).hexdigest()
    require(genesis == expected or action == "plan-initialize" and not genesis)
    anchor = maintenance.Anchor(CoordinatorStore(objects, target.digest), target.digest, expected)
    if action == "plan-initialize":
        return {"status": "planned", "genesisSha256": expected, "mutationPerformed": False}
    if action in {"initialize", "run", "resume", "reconcile", "abort"}:
        require(env.get("SUBS_BOT_PRODUCTION_BACKUP_COORDINATOR_ENABLED") == "true"
                and objects.write_credential is not None, "The production coordinator is disabled.")
    if action == "initialize":
        require(env.get("BACKUP_COORDINATOR_APPROVAL_SHA256") == expected)
        anchor.initialize()
        return {"status": "initialized", "mutationPerformed": True}
    pinned, raw, _etag = anchor.read()
    if action == "inspect":
        return {"status": "attention" if pinned["state"] == "active" else "observed",
                "phase": pinned["state"], "mutationPerformed": False,
                "notification": "github-check-only", "automaticReplay": False}
    source_checkpoint, source_sha = env.get("BACKUP_SOURCE_CHECKPOINT_ID", ""), env.get("BACKUP_SOURCE_MANIFEST_SHA256", "")
    require(re.fullmatch(r"[a-f0-9]{32}", source_checkpoint or "") and HEX.fullmatch(source_sha or ""))
    session = env["GITHUB_RUN_ID"] if action == "plan-run" else env.get("BACKUP_COORDINATOR_SESSION", "")
    require(DECIMAL.fullmatch(session or ""))
    normalized = {"plan-run": "run", "plan-resume": "resume", "plan-reconcile": "reconcile", "plan-abort": "abort"}.get(action, action)
    plan = {"version": 1, "action": normalized, "targetSha256": target.digest, "controlRevision": revision,
            "session": session, "sourceCheckpointId": source_checkpoint, "sourceManifestSha256": source_sha,
            "anchorSha256": sha256(raw).hexdigest(), "policySha256": digest(policy)}
    if action == "plan-run":
        require(pinned["state"] == "idle" and pinned["session"] != session + "-1")
        return {"status": "planned", "planSha256": digest(plan), "session": session, "mutationPerformed": False}
    if action == "plan-resume":
        require(pinned["state"] == "active" and pinned["session"] == session + "-1" and pinned["controlRevision"] == revision)
        history = finished_controller(objects, target.digest, session, revision, source_checkpoint, source_sha, digest(policy))
        plan["writerHistorySha256"] = digest(history)
        verified, _ = completed_results(objects, target.digest, session, revision, artifact._github_token(),
                                        source_checkpoint, source_sha, policy["pauseLimitSeconds"])
        return {"status": "planned", "planSha256": digest(plan), "session": session,
                "verifiedCheckpoints": len(verified), "mutationPerformed": False}
    if action in {"plan-abort", "abort"}:
        require(pinned["state"] == "active" and pinned["session"] == session + "-1" and pinned["controlRevision"] == revision)
        history = finished_controller(objects, target.digest, session, revision, source_checkpoint, source_sha, digest(policy))
        app_store = PrivateStore(metadata, target.data["backupBucketName"])
        app_genesis = env.get("SUBS_BOT_BACKUP_GENESIS_SHA256", "")
        observed = abort_observation(objects, app_store, target, session, revision, source_checkpoint, source_sha,
                                     policy["pauseLimitSeconds"], app_genesis)
        plan.update(writerHistorySha256=digest(history), abortObservationSha256=digest(observed))
        if action == "plan-abort":
            return {"status": "planned", "planSha256": digest(plan), "terminal": observed["terminal"], "mutationPerformed": False}
        require(env.get("BACKUP_COORDINATOR_APPROVAL_SHA256") == digest(plan))
        artifact.require_current_main(revision)
        require(finished_controller(objects, target.digest, session, revision, source_checkpoint, source_sha, digest(policy)) == history
                and abort_observation(objects, app_store, target, session, revision, source_checkpoint, source_sha,
                                      policy["pauseLimitSeconds"], app_genesis) == observed)
        claim_resume_writer(objects, target.digest, session, revision, history, env["GITHUB_RUN_ID"], action="abort")
        require(abort_observation(objects, app_store, target, session, revision, source_checkpoint, source_sha,
                                  policy["pauseLimitSeconds"], app_genesis) == observed)
        anchor.release(session + "-1")
        return {"status": "abandoned-after-confirmed-terminal", "terminal": observed["terminal"],
                "productionMutation": False, "dispatchRetried": False}
    if action in {"plan-reconcile", "reconcile"}:
        require(pinned["state"] == "active" and pinned["session"] == session + "-1" and pinned["controlRevision"] == revision)
        finished_controller(objects, target.digest, session, revision, source_checkpoint, source_sha, digest(policy))
        sequence = int(env.get("BACKUP_COORDINATOR_SEQUENCE", "0"))
        stage = inspect_stage(objects, target.digest, session, sequence)
        require(stage["status"] == "unknown", "Only an unresolved original dispatch can be reconciled.")
        prior, prior_pause = completed_results(objects, target.digest, session, revision, artifact._github_token(),
                                              source_checkpoint, source_sha, policy["pauseLimitSeconds"], stop_before=sequence)
        require(len(prior) == sequence - 1, "An earlier coordinator stage has not been independently verified.")
        intent_raw, _ = objects.get(event_key(target.digest, session, sequence))
        intent = parsed(intent_raw)
        expected_inputs, _ = stage_inputs(prior, source_checkpoint, source_sha, session, intent,
                                          policy["pauseLimitSeconds"], prior_pause)
        require(sha256(canonical(expected_inputs)).hexdigest() == intent["inputSha256"])
        token = artifact._github_token()
        workflow = artifact._get_json("/actions/workflows/worker-production-backup.yml", token)
        require(workflow.get("path") == ".github/workflows/worker-production-backup.yml" and type(workflow.get("id")) is int)
        run = discover_run(intent, workflow["id"], token)
        require((run.get("status"), run.get("conclusion")) == ("completed", "success"))
        result, source, original = selected_result(str(run["id"]), revision, intent["action"], token)
        proof = receipt(intent, str(run["id"]), result, source["artifactId"], source["artifactSha256"])
        require_completed_receipt(intent, proof, run, workflow["id"], result)
        plan.update(sequence=sequence, intentSha256=sha256(intent_raw).hexdigest(),
                    runId=str(run["id"]), resultSha256=proof["resultSha256"])
        if action == "plan-reconcile":
            return {"status": "planned", "planSha256": digest(plan), "mutationPerformed": False}
        require(env.get("BACKUP_COORDINATOR_APPROVAL_SHA256") == digest(plan))
        artifact.require_current_main(revision)
        confirm_stage(objects, intent, run, workflow["id"], result, source, original)
        return {"status": "reconciled", "mutationPerformed": True, "dispatchRetried": False}
    if action == "resume":
        history = finished_controller(objects, target.digest, session, revision, source_checkpoint, source_sha, digest(policy))
        plan["writerHistorySha256"] = digest(history)
    require(env.get("BACKUP_COORDINATOR_APPROVAL_SHA256") == digest(plan),
            "The exact independently approved coordinator plan is required.")
    if action == "run":
        require(pinned["state"] == "idle" and pinned["session"] != session + "-1")
        require(backup_cli.in_window(policy, datetime.now(timezone.utc)), "A new backup cannot start outside its approved UTC window.")
        original_plan = artifact._get_json("/actions/runs/" + session + "/attempts/1", artifact._github_token())
        require(str(original_plan.get("id")) == session and original_plan.get("head_sha") == revision
                and original_plan.get("display_title") == "Production backup coordinator plan-run at " + revision
                and original_plan.get("event") == "workflow_dispatch" and original_plan.get("head_branch") == "main"
                and original_plan.get("run_attempt") == 1 and (original_plan.get("status"), original_plan.get("conclusion")) == ("completed", "success")
                and all(isinstance(original_plan.get(key), dict) and original_plan[key].get("id") == artifact.REPOSITORY_ID
                        for key in ("repository", "head_repository")))
        start = {**plan, "writerRunId": env["GITHUB_RUN_ID"], "writerAttempt": "1"}
        key = BASE + target.digest + "/" + session + "/start-intent.json"
        existing, _ = objects.get(key, absent=True)
        require(existing is None, "A coordinator start intent already exists.")
        objects.put_once(key, canonical(start))
        artifact.require_current_main(revision)
        anchor.acquire(session + "-1", datetime.now(timezone.utc).strftime("%Y/%m/%d"), revision)
    else:
        require(action == "resume" and pinned["state"] == "active" and pinned["session"] == session + "-1"
                and pinned["controlRevision"] == revision)
        require(finished_controller(objects, target.digest, session, revision, source_checkpoint, source_sha, digest(policy)) == history)
        artifact.require_current_main(revision)
        claim_resume_writer(objects, target.digest, session, revision, history, env["GITHUB_RUN_ID"])
    result = run_sequence(objects, anchor, target.digest, session, revision, source_checkpoint, source_sha,
                          artifact._github_token(), deadline=time.monotonic() + 5 * 3600,
                          pause_limit=policy["pauseLimitSeconds"])
    return result


if __name__ == "__main__":
    import json
    import os
    from pathlib import Path
    try:
        os.umask(0o077)
        result = main()
        root = Path(os.environ["RUNNER_TEMP"])
        require(root.is_absolute() and root.is_dir() and not root.is_symlink())
        path = root / "production-backup-coordinator-result.json"
        with path.open("xb") as output:
            os.chmod(path, 0o600)
            output.write(canonical(result))
        print(json.dumps(result, sort_keys=True))
        if result.get("status") == "attention":
            print("::error::A coordinator session remains active; inspect its private journal and current backup state.")
            raise SystemExit(1)
    except Exception:
        print("::error::Backup coordination stopped; inspect the private intent and current state before continuing.")
        raise SystemExit(1) from None
