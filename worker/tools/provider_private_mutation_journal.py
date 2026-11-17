"""Append-only admission for isolated one-shot Provider Worker operations.

An unresolved intent is never converted into success and blocks subsequent
mutations. This module requires the trusted workflow's fresh-job DAG.
"""

from hashlib import sha256
import base64
import json
import os
from io import BytesIO
from pathlib import Path
import re
import stat
from zipfile import BadZipFile, ZIP_DEFLATED, ZIP_STORED, ZipFile

import archive_production_provider as sealed
import production_provider as control
import production_provider_rehearsal as rehearsal
import isolation_sealed_transfer as sealed_transfer
import provider_digest_journal as digest_journal
import provider_durable_source as durable
import provider_private_mutation as mutation
import provider_source_transfer as transfer

BASE = "maintenance/provider-private-mutation/"
MAX_HISTORY = 32
WORKFLOW = transfer.REVIEWED_OPERATION_WORKFLOW_PATH
RECONCILE_WORKFLOW = ".github/workflows/worker-provider-reviewed-operation-reconcile.yml"
JOBS = {"source": "Provider private source transfer", "preflight": "Provider mutation preflight", "intent-write": "Provider mutation intent archive",
        "intent-readback": "Provider mutation intent readback", "dispatch": "Provider mutation dispatch",
        "verify": "Provider mutation independent verification", "completion-write": "Provider mutation completion archive",
        "readback": "Provider mutation evidence readback", "failure-write": "Provider mutation failure evidence archive",
        "failure-readback": "Provider mutation failure evidence readback"}


class Store(sealed.PrivateProofStore):
    def __init__(self, target, run_id):
        super().__init__(target, "", run_id, "1")
        self.prefix = f"{BASE}{run_id}/1/"

    def key(self, relative):
        control.require(relative in {"intent.json", "response.age", "completion.json", "failure-observation.age"})
        return self.prefix + relative

    def put_once(self, relative, raw):
        control.require(isinstance(raw, bytes) and 0 < len(raw) <= sealed.CHUNK_BYTES and self.read(relative) is None)
        objects = self.objects
        control.require(objects is not None, "A bucket-scoped R2 credential is required.")
        objects.put_once(self.key(relative), raw,
                         metadata={"cache-control": "no-store, private", "content-type": "application/octet-stream"})
        control.require(self.read(relative) == raw)


def store(run_id=None):
    bucket = control.github._parse_object(os.environ.get("SUBS_BOT_PROVIDER_ARCHIVE_TARGET_JSON", ""), sealed.ERROR)
    return Store(bucket, run_id or os.environ["GITHUB_RUN_ID"])


def ledger():
    value = control.github._parse_object(os.environ.get("SUBS_BOT_PROVIDER_MUTATION_LEDGER_JSON", ""), sealed.ERROR)
    control.require(len(value) <= MAX_HISTORY)
    keys = {"intentSha256", "responseSha256", "completionSha256", "targetSha256", "controllerRevision", "candidateRevision",
            "reviewedPr", "operation", "readbackJobId", "readbackSha256"}
    for run_id, row in value.items():
        control.require(control.match(control.provider.DECIMAL, run_id) and isinstance(row, dict) and set(row) == keys
                        and all(control.match(control.provider.HEX, row[k]) for k in ("intentSha256", "responseSha256", "completionSha256", "targetSha256", "readbackSha256"))
                        and all(control.match(control.provider.REVISION, row[k]) for k in ("controllerRevision", "candidateRevision"))
                        and all(control.match(control.provider.DECIMAL, row[k]) for k in ("reviewedPr", "readbackJobId"))
                        and row["operation"] in mutation.OPERATIONS)
    return value


def controllers():
    rows = json.loads(os.environ.get("SUBS_BOT_PROVIDER_MUTATION_CONTROLLERS_JSON", ""), object_pairs_hook=control.github._unique_json_object)
    control.require(isinstance(rows, list) and 0 < len(rows) <= 16 and len(set(rows)) == len(rows)
                    and all(control.match(control.provider.REVISION, row) for row in rows) and os.environ["GITHUB_SHA"] in rows)
    return rows


def resolutions():
    value = control.github._parse_object(os.environ.get("SUBS_BOT_PROVIDER_MUTATION_RESOLUTIONS_JSON", ""), sealed.ERROR)
    control.require(len(value) <= MAX_HISTORY)
    fields = {"controllerRevision", "intentJobId", "dispatchJobId", "completionJobId", "failureJobId", "readbackSha256",
              "reconcileRunId", "reconcileRunAttempt", "reconcileRevision"}
    for run_id, row in value.items():
        control.require(control.match(control.provider.DECIMAL, run_id) and isinstance(row, dict) and set(row) == fields
                        and all(control.match(control.provider.DECIMAL, row[k]) for k in
                                ("intentJobId", "dispatchJobId", "completionJobId", "failureJobId", "reconcileRunId", "reconcileRunAttempt"))
                        and all(control.match(control.provider.REVISION, row[k]) for k in ("controllerRevision", "reconcileRevision"))
                        and control.match(control.provider.HEX, row["readbackSha256"]))
    return value


def inspect_readonly_run(reader, run_id, allowed):
    """Prove all writing jobs were skipped and the private prefix is empty."""
    control.require(control.match(control.provider.DECIMAL, run_id))
    token = control.github._github_token()
    run = control.github._get_json(f"/actions/runs/{run_id}/attempts/1", token)
    revision = run.get("head_sha")
    control.require(str(run.get("id")) == run_id and run.get("run_attempt") == 1 and revision in allowed
                    and run.get("path") in (WORKFLOW, WORKFLOW + "@main", WORKFLOW + "@refs/heads/main")
                    and run.get("head_branch") == "main" and run.get("event") == "workflow_dispatch"
                    and run.get("status") == "completed"
                    and run.get("conclusion") in {"success", "failure", "cancelled", "timed_out", "skipped"}
                    and all(isinstance(run.get(k), dict) and run[k].get("id") == control.github.REPOSITORY_ID
                            for k in ("repository", "head_repository")))
    durable.source_ancestor({"revision": revision}, token)
    response = control.github._get_json(f"/actions/runs/{run_id}/attempts/1/jobs?per_page=100", token)
    jobs = response.get("jobs")
    control.require(isinstance(jobs, list) and response.get("total_count") == len(jobs) == len(JOBS)
                    and all(isinstance(job, dict) and job.get("name") in JOBS.values() for job in jobs)
                    and len({job["name"] for job in jobs}) == len(JOBS))
    for job in jobs:
        control.require(str(job.get("run_id")) == run_id and job.get("run_attempt") == 1 and job.get("head_sha") == revision
                        and control.match(control.provider.DECIMAL, str(job.get("id"))) and job.get("status") == "completed"
                        and isinstance(job.get("conclusion"), str))
    writes = {}
    for key in ("intent-write", "dispatch", "completion-write", "failure-write"):
        job = next(row for row in jobs if row["name"] == JOBS[key])
        steps = job.get("steps")
        control.require(job.get("conclusion") == "skipped" and isinstance(steps, list)
                        and all(isinstance(step, dict) and (step.get("status"), step.get("conclusion")) == ("completed", "skipped")
                                for step in steps))
        writes[key] = str(job["id"])
    control.require(durable.list_private_keys(reader, BASE + run_id + "/1/") == [])
    return {"version": 1, "kind": "isolated-provider-mutation-readonly-resolution", "runId": run_id,
            "controllerRevision": revision, "runConclusion": run["conclusion"], "intentJobId": writes["intent-write"],
            "dispatchJobId": writes["dispatch"], "completionJobId": writes["completion-write"],
            "failureJobId": writes["failure-write"],
            "bucketSha256": control.digest(reader.target), "objectCount": 0}


def verify_resolution(reader, run_id, pin, allowed):
    control.require(pin["controllerRevision"] in allowed and pin["reconcileRevision"] in allowed)
    report = inspect_readonly_run(reader, run_id, allowed)
    control.require(report["controllerRevision"] == pin["controllerRevision"]
                    and all(report[k] == pin[k] for k in ("intentJobId", "dispatchJobId", "completionJobId", "failureJobId"))
                    and control.digest(report) == pin["readbackSha256"])
    token, reconciliation, attempt = control.github._github_token(), pin["reconcileRunId"], pin["reconcileRunAttempt"]
    run = control.github._get_json(f"/actions/runs/{reconciliation}/attempts/{attempt}", token)
    control.require(str(run.get("id")) == reconciliation and str(run.get("run_attempt")) == attempt
                    and run.get("path") in (RECONCILE_WORKFLOW, RECONCILE_WORKFLOW + "@main", RECONCILE_WORKFLOW + "@refs/heads/main")
                    and run.get("display_title") == "Inspect isolated Provider operation " + run_id
                    and run.get("head_sha") == pin["reconcileRevision"] and run.get("head_branch") == "main"
                    and run.get("event") == "workflow_dispatch" and (run.get("status"), run.get("conclusion")) == ("completed", "success")
                    and all(isinstance(run.get(k), dict) and run[k].get("id") == control.github.REPOSITORY_ID
                            for k in ("repository", "head_repository")))
    durable.source_ancestor({"revision": pin["reconcileRevision"]}, token)
    response = control.github._get_json(f"/actions/runs/{reconciliation}/attempts/{attempt}/jobs?per_page=100", token)
    jobs = response.get("jobs")
    control.require(isinstance(jobs, list) and response.get("total_count") == len(jobs) == 1)
    job = jobs[0]
    control.require(isinstance(job, dict) and job.get("name") == "Provider operation read-only reconciliation"
                    and str(job.get("run_id")) == reconciliation and str(job.get("run_attempt")) == attempt
                    and job.get("head_sha") == pin["reconcileRevision"] and (job.get("status"), job.get("conclusion")) == ("completed", "success")
                    and isinstance(job.get("steps"), list))
    steps = [step for step in job["steps"] if isinstance(step, dict) and step.get("name") == "Inspect skipped operation without writes"]
    control.require(len(steps) == 1 and (steps[0].get("status"), steps[0].get("conclusion")) == ("completed", "success"))


def projection(run_id, original, completion_sha, job_id):
    return {"version": 1, "kind": "isolated-provider-mutation-readback", "runId": run_id, "runAttempt": "1",
            "controllerRevision": original["controllerRevision"], "candidateRevision": original["candidateRevision"],
            "reviewedPr": original["reviewedPr"], "operation": original["operation"], "targetSha256": original["targetSha256"],
            "intentSha256": control.digest(original), "completionSha256": completion_sha, "readbackJobId": job_id}


def inventory(reader, *, current=None):
    grouped = {}
    for key in durable.list_private_keys(reader, BASE):
        match = re.fullmatch(re.escape(BASE) + r"([1-9][0-9]*)/1/(intent\.json|response\.age|completion\.json|failure-observation\.age)", key)
        control.require(match is not None)
        grouped.setdefault(match.group(1), set()).add(match.group(2))
    registered, allowed = ledger(), controllers()
    control.require(len(grouped) <= MAX_HISTORY and set(grouped) - ({current} if current else set()) == set(registered) - ({current} if current else set()),
                    "A prior private Provider mutation is unresolved; do not retry.")
    for run_id, pin in registered.items():
        if run_id == current:
            continue
        control.require(grouped[run_id] == {"intent.json", "response.age", "completion.json"} and pin["controllerRevision"] in allowed)
        prior = Store(reader.target, run_id)
        intent_raw, response_raw, done_raw = (prior.read(name) for name in ("intent.json", "response.age", "completion.json"))
        control.require(all(isinstance(raw, bytes) and sha256(raw).hexdigest() == pin[key] for raw, key in
                            ((intent_raw, "intentSha256"), (response_raw, "responseSha256"), (done_raw, "completionSha256"))))
        original = control.github._parse_object(intent_raw, sealed.ERROR)
        done = control.github._parse_object(done_raw, sealed.ERROR)
        control.require(intent_raw == control.canonical(original) and done_raw == control.canonical(done)
                        and original.get("kind") == "isolated-provider-mutation-intent" and original.get("status") == "started-unknown"
                        and original.get("runId") == run_id and original.get("runAttempt") == "1"
                        and all(original.get(key) == pin[key] for key in ("controllerRevision", "candidateRevision", "reviewedPr", "operation", "targetSha256"))
                        and done == {"version": 1, "kind": "isolated-provider-mutation-completion", "runId": run_id,
                                     "intentSha256": pin["intentSha256"], "responseSha256": pin["responseSha256"],
                                     "verification": done.get("verification")}
                        and isinstance(done.get("verification"), dict) and done["verification"].get("status") == "independently-verified"
                        and set(done["verification"]) == VERIFICATION_FIELDS
                        and done["verification"].get("operation") == pin["operation"]
                        and done["verification"].get("targetSha256") == pin["targetSha256"]
                        and all(control.match(control.provider.HEX, done["verification"].get(key)) for key in
                                VERIFICATION_HASH_FIELDS)
                        and control.digest(projection(run_id, original, pin["completionSha256"], pin["readbackJobId"])) == pin["readbackSha256"])
        digest_journal.workflow_job(run_id, pin["controllerRevision"], JOBS["readback"], job_id=pin["readbackJobId"])
    return grouped


def history(registered, reader):
    token, current, allowed = control.github._github_token(), os.environ["GITHUB_RUN_ID"], controllers()
    resolved = resolutions()
    control.require(not set(resolved) & set(registered) and current not in resolved)
    rows = []
    for page in range(1, 11):
        response = control.github._get_json(f"/actions/workflows/{WORKFLOW.rsplit('/', 1)[-1]}/runs?per_page=100&page={page}", token)
        batch = response.get("workflow_runs")
        control.require(isinstance(batch, list) and len(batch) <= 100 and type(response.get("total_count")) is int
                        and 0 <= response["total_count"] <= 1000)
        rows.extend(batch)
        if len(batch) < 100:
            break
    else:
        raise control.ProviderError("Private Provider mutation history exceeds its safe bound.")
    control.require(len(rows) == response["total_count"] and len({str(row.get("id")) for row in rows if isinstance(row, dict)}) == len(rows))
    seen, resolved_seen, found = set(), set(), False
    for row in rows:
        control.require(isinstance(row, dict) and row.get("path") in (WORKFLOW, WORKFLOW + "@main", WORKFLOW + "@refs/heads/main")
                        and row.get("head_sha") in allowed and row.get("head_branch") == "main" and row.get("event") == "workflow_dispatch"
                        and row.get("run_attempt") == 1 and all(isinstance(row.get(k), dict) and row[k].get("id") == control.github.REPOSITORY_ID
                                                                for k in ("repository", "head_repository")))
        durable.source_ancestor({"revision": row["head_sha"]}, token)
        run_id = str(row.get("id"))
        if run_id == current:
            control.require(not found and row.get("head_sha") == os.environ["GITHUB_SHA"])
            found = True
        else:
            if run_id in resolved:
                control.require(run_id not in resolved_seen and row.get("status") == "completed"
                                and row.get("head_sha") == resolved[run_id]["controllerRevision"])
                verify_resolution(reader, run_id, resolved[run_id], allowed)
                resolved_seen.add(run_id)
                continue
            control.require(run_id in registered and run_id not in seen and row.get("head_sha") == registered[run_id]["controllerRevision"]
                            and (row.get("status"), row.get("conclusion")) == ("completed", "success"),
                            "A prior private Provider mutation is unresolved; do not retry.")
            seen.add(run_id)
    control.require(found and seen == set(registered) and resolved_seen == set(resolved))


def inputs():
    transfer.context()
    control.require(transfer.workflow_path() == WORKFLOW)
    target, refs = transfer.target(), transfer.refs()
    operation = os.environ.get("SUBS_BOT_PROVIDER_MUTATION_OPERATION", "")
    control.require(operation in mutation.OPERATIONS and os.environ.get("SUBS_BOT_PROVIDER_MUTATION_APPROVAL") ==
                    control.digest({"operation": operation, "target": target}))
    return target, refs, operation


def planned():
    target, refs, operation = inputs()
    state = control.github._parse_object(os.environ.get("SUBS_BOT_PROVIDER_MUTATION_PRESTATE_JSON", ""), sealed.ERROR)
    return target, refs, operation, mutation.intent(target, refs, operation, state, os.environ["GITHUB_RUN_ID"], os.environ["GITHUB_SHA"])


def preflight():
    target, refs, operation = inputs()
    transfer.receive()
    control.guard_sources(target)
    import tempfile
    with tempfile.TemporaryDirectory(prefix=".provider-mutation-preflight-", dir=os.environ["RUNNER_TEMP"]) as directory:
        control.verify_previous_archives(target, Path(directory))
    state = mutation.observe(target, operation, os.environ.get("SUBS_BOT_CF_PROVIDER_WORKER_READ_TOKEN", ""),
                             os.environ.get("SUBS_BOT_CF_PROVIDER_CONTAINER_READ_TOKEN", ""))
    mutation.intent(target, refs, operation, state, os.environ["GITHUB_RUN_ID"], os.environ["GITHUB_SHA"])
    digest_journal.output("prestate_json", state)


def write_intent():
    _target, _refs, operation, value = planned()
    run_id, revision = os.environ["GITHUB_RUN_ID"], os.environ["GITHUB_SHA"]
    digest_journal.workflow_job(run_id, revision, JOBS["preflight"])
    writer = store()
    writer.verify()
    grouped = inventory(writer)
    control.require(len(grouped) < MAX_HISTORY and run_id not in grouped)
    registered = ledger()
    if operation == "stage":
        matches = [row for row in registered.values() if row["operation"] == "prepare-image"
                   and row["targetSha256"] == value["targetSha256"] and row["completionSha256"] == value["imagePreparationSha256"]]
        control.require(len(matches) == 1, "The exact image preparation lacks registered independent evidence.")
    history(registered, writer)
    raw = control.canonical(value)
    writer.put_once("intent.json", raw)
    digest_journal.output("intent_sha256", sha256(raw).hexdigest())


def read_intent():
    _target, _refs, _operation, value = planned()
    reader = store()
    reader.verify()
    control.require(inventory(reader, current=reader.run_id).get(reader.run_id) == {"intent.json"})
    expected, raw = os.environ.get("SUBS_BOT_PROVIDER_MUTATION_INTENT_SHA256", ""), reader.read("intent.json")
    control.require(control.match(control.provider.HEX, expected) and isinstance(raw, bytes)
                    and sha256(raw).hexdigest() == expected and raw == control.canonical(value))
    digest_journal.output("intent_sha256", expected)


def dispatch():
    target, refs, operation, value = planned()
    run_id, revision = os.environ["GITHUB_RUN_ID"], os.environ["GITHUB_SHA"]
    digest_journal.workflow_job(run_id, revision, JOBS["preflight"])
    digest_journal.workflow_job(run_id, revision, JOBS["intent-readback"])
    pinned = os.environ.get("SUBS_BOT_PROVIDER_MUTATION_INTENT_SHA256", "")
    control.require(control.match(control.provider.HEX, pinned) and control.digest(value) == pinned)
    transfer.receive()
    archive, evidence = control.publication._verified_input(Path(os.environ["RUNNER_TEMP"]), target["build"]["revision"], target["build"]["runId"])
    control.require(evidence == target["build"])
    module = control.provider.checked_file(archive.with_name(control.provider.WORKER), control.provider.MAX_WORKER).read_bytes()
    result = mutation.dispatch(target, refs, operation, value, pinned, archive, module)
    digest_journal.output("response_sha256", result)


def download_response(*, observation=False):
    artifact_id = os.environ.get("SUBS_BOT_PROVIDER_MUTATION_RESPONSE_ARTIFACT_ID", "")
    archive_sha = os.environ.get("SUBS_BOT_PROVIDER_MUTATION_RESPONSE_ARTIFACT_SHA256", "")
    cipher_sha = os.environ.get("SUBS_BOT_PROVIDER_MUTATION_RESPONSE_SHA256", "")
    control.require(control.match(control.provider.DECIMAL, artifact_id) and all(control.match(control.provider.HEX, x) for x in (archive_sha, cipher_sha))
                    and os.environ.get("SUBS_BOT_PROVIDER_MUTATION_TRUSTED_ARTIFACT_ID") == artifact_id
                    and os.environ.get("SUBS_BOT_PROVIDER_MUTATION_TRUSTED_ARTIFACT_SHA256") == archive_sha
                    and os.environ.get("SUBS_BOT_PROVIDER_MUTATION_TRUSTED_RESPONSE_SHA256") == cipher_sha)
    run_id, revision, token = os.environ["GITHUB_RUN_ID"], os.environ["GITHUB_SHA"], control.github._github_token()
    artifact = control.github._get_json("/actions/artifacts/" + artifact_id, token)
    origin = artifact.get("workflow_run")
    control.require(str(artifact.get("id")) == artifact_id and artifact.get("expired") is False
                    and artifact.get("name") == f"provider-mutation-{'observation' if observation else 'confirmed'}-{run_id}-1"
                    and artifact.get("digest") == "sha256:" + archive_sha and isinstance(origin, dict)
                    and str(origin.get("id")) == run_id and origin.get("head_branch") == "main" and origin.get("head_sha") == revision
                    and origin.get("repository_id") == origin.get("head_repository_id") == control.github.REPOSITORY_ID)
    run = control.github._get_json(f"/actions/runs/{run_id}/attempts/1", token)
    control.require(str(run.get("id")) == run_id and run.get("run_attempt") == 1
                    and run.get("path") in (WORKFLOW, WORKFLOW + "@main", WORKFLOW + "@refs/heads/main")
                    and run.get("head_sha") == revision and run.get("head_branch") == "main" and run.get("event") == "workflow_dispatch"
                    and all(isinstance(run.get(k), dict) and run[k].get("id") == control.github.REPOSITORY_ID
                            for k in ("repository", "head_repository")))
    if not observation:
        digest_journal.workflow_job(run_id, revision, JOBS["dispatch"])
    listing = control.github._get_json(f"/actions/runs/{run_id}/attempts/1/jobs?per_page=100", token)
    jobs = listing.get("jobs")
    control.require(isinstance(jobs, list) and listing.get("total_count") == len(jobs) < 100)
    matched = [job for job in jobs if isinstance(job, dict) and job.get("name") == JOBS["dispatch"]]
    control.require(len(matched) == 1 and isinstance(matched[0].get("steps"), list))
    if observation:
        job = matched[0]
        control.require(str(job.get("run_id")) == run_id and job.get("run_attempt") == 1 and job.get("head_sha") == revision
                        and job.get("status") == "completed"
                        and job.get("conclusion") in {"success", "failure", "cancelled", "timed_out"})
    upload_step = "Preserve encrypted response-only observation" if observation else "Upload encrypted confirmed response"
    steps = [step for step in matched[0]["steps"] if isinstance(step, dict) and step.get("name") == upload_step]
    control.require(len(steps) == 1 and (steps[0].get("status"), steps[0].get("conclusion")) == ("completed", "success"))
    request = control.github.artifact_storage_request(artifact_id, token)
    try:
        with control.provenance.STORAGE_OPENER.open(request, timeout=30) as response:
            control.require(response.status == 200 and response.headers.get("Content-Encoding", "identity") == "identity")
            raw = control.github._bounded_read(response, 2 * 1024 * 1024)
        control.require(sha256(raw).hexdigest() == archive_sha)
        with ZipFile(BytesIO(raw)) as archive:
            members = archive.infolist()
            name = "provider-mutation-observation.age" if observation else "provider-mutation-confirmed.age"
            control.require(len(members) == 1 and members[0].filename == members[0].orig_filename == name
                            and members[0].flag_bits & (1 | 64) == 0 and members[0].compress_type in (ZIP_STORED, ZIP_DEFLATED)
                            and stat.S_IFMT(members[0].external_attr >> 16) in (0, stat.S_IFREG)
                            and 0 < members[0].file_size <= 512 * 1024)
            cipher = archive.read(members[0])
        control.require(sha256(cipher).hexdigest() == cipher_sha)
    except (OSError, BadZipFile, RuntimeError, ValueError):
        raise control.ProviderError("The exact encrypted Provider response could not be verified.") from None
    return cipher


def verify():
    target, _refs, operation, value = planned()
    expected = os.environ.get("SUBS_BOT_PROVIDER_MUTATION_INTENT_SHA256", "")
    control.require(control.match(control.provider.HEX, expected) and control.digest(value) == expected)
    transfer.receive()
    cipher = download_response()
    root = Path(os.environ["RUNNER_TEMP"])
    encrypted, plaintext = root / "provider-mutation-verified.age", root / "provider-mutation-verified.json"
    with control.provenance._write_private(encrypted) as output:
        output.write(cipher)
    transfer.age_identity(["age", "--decrypt", "--identity", "{identity}"], encrypted, plaintext)
    record = control.github._parse_object(control.provider.checked_file(plaintext, 256 * 1024).read_bytes(), sealed.ERROR)
    control.require(set(record) == {"intentSha256", "target", "operation", "observation", "result"}
                    and record["intentSha256"] == expected and record["target"] == target and record["operation"] == operation
                    and isinstance(record["observation"], dict) and record["observation"].get("kind") == "response-only"
                    and isinstance(record["result"], dict))
    updated = rehearsal.confirmed_target(target, operation, record["result"])
    control.guard_sources(updated)
    api = control.ProviderAPI(updated, os.environ.get("SUBS_BOT_CF_PROVIDER_WORKER_READ_TOKEN", ""),
                              os.environ.get("SUBS_BOT_CF_PROVIDER_CONTAINER_READ_TOKEN", ""))
    actual = control.observe(api, need_smoke=operation == "smoke")
    expected_state = {key: record["result"].get(key) for key in ("activation", "container", "workflow", "instance")}
    control.require(actual == expected_state and control.caller_state(api, updated, allow_unbound=True) == "unbound"
                    and control.observe(api, need_smoke=operation == "smoke") == actual)
    if operation == "prepare-image":
        control.require(record["result"].get("imagePrepared") is True
                        and record["observation"].get("status") == "ready"
                        and record["observation"].get("imageManifestSha256") == target["build"]["ociManifestSha256"])
        import tempfile
        with tempfile.TemporaryDirectory(prefix=".provider-image-verify-", dir=os.environ["RUNNER_TEMP"]) as directory:
            control.PublishedImage(target, os.environ.get("SUBS_BOT_CF_PROVIDER_CONTAINER_READ_TOKEN", ""), Path(directory)).verify()
    next_sha = mutation.write_encrypted("next-target", {"target": updated, "sourceIntentSha256": expected})
    payloads = seal_next_target(updated)
    result = {"status": "independently-verified", "operation": operation, "targetSha256": control.digest(target),
              "nextTargetSha256": control.digest(updated), "resultSha256": control.digest(record["result"]),
              "nextTargetCipherSha256": next_sha, "nextTargetArchiveSha256": payloads["archive"], "nextTargetLiveSha256": payloads["live"],
              "nextDigestApprovalSha256": control.digest({"operation": "publish-digest", "target": updated}),
              "nextWitnessApprovalSha256": control.digest({"operation": "publish", "target": updated}),
              **{f"next{action.title().replace('-', '')}ApprovalSha256": control.digest({"operation": action, "target": updated})
                 for action in sorted(mutation.OPERATIONS)}}
    digest_journal.output("verification_json", result)


def seal_next_target(target):
    """Encrypt the verified next target to each independently pinned GH Environment key."""
    keys = control.github._parse_object(os.environ.get("SUBS_BOT_PROVIDER_NEXT_TARGET_KEYS_JSON", ""), sealed.ERROR)
    pins = control.github._parse_object(os.environ.get("SUBS_BOT_PROVIDER_NEXT_TARGET_KEY_PINS_JSON", ""), sealed.ERROR)
    control.require(set(keys) == set(pins) == {"archive", "live"})
    result = {}
    for name, environment in (("archive", "subs-bot-provider-archive-head-isolation"), ("live", "subs-bot-provider-head-isolation")):
        row = keys[name]
        control.require(isinstance(row, dict) and set(row) == {"environmentId", "keyId", "publicKey"}
                        and control.match(control.provider.DECIMAL, row["environmentId"])
                        and isinstance(row["keyId"], str) and re.fullmatch(r"[A-Za-z0-9_-]{1,128}", row["keyId"])
                        and isinstance(row["publicKey"], str) and len(row["publicKey"]) <= 128)
        public = base64.b64decode(row["publicKey"], validate=True)
        control.require(len(public) == 32 and base64.b64encode(public).decode("ascii") == row["publicKey"])
        pin = {"version": 1, "repositoryId": control.github.REPOSITORY_ID, "environment": environment,
               "environmentId": row["environmentId"], "keyId": row["keyId"], "publicKey": row["publicKey"]}
        control.require(control.match(control.provider.HEX, pins[name]) and control.digest(pin) == pins[name])
        ciphertext = sealed_transfer.seal(control.canonical(target), public)
        payload = control.canonical({"encrypted_value": base64.b64encode(ciphertext).decode("ascii"), "key_id": row["keyId"]})
        with control.provenance._write_private(Path(os.environ["RUNNER_TEMP"]) / ("provider-next-target-" + name + ".json")) as output:
            output.write(payload)
        result[name] = sha256(payload).hexdigest()
    return result


VERIFICATION_HASH_FIELDS = {"targetSha256", "nextTargetSha256", "resultSha256", "nextTargetCipherSha256",
                            "nextTargetArchiveSha256", "nextTargetLiveSha256", "nextDigestApprovalSha256",
                            "nextWitnessApprovalSha256",
                            "nextPrepareImageApprovalSha256", "nextStageApprovalSha256", "nextActivateApprovalSha256",
                            "nextSmokeApprovalSha256"}
VERIFICATION_FIELDS = VERIFICATION_HASH_FIELDS | {"status", "operation"}


def completion_value(value):
    verified = control.github._parse_object(os.environ.get("SUBS_BOT_PROVIDER_MUTATION_VERIFICATION_JSON", ""), sealed.ERROR)
    control.require(set(verified) == VERIFICATION_FIELDS
                    and verified["status"] == "independently-verified" and verified["operation"] == value["operation"]
                    and verified["targetSha256"] == value["targetSha256"]
                    and all(control.match(control.provider.HEX, verified[k]) for k in VERIFICATION_HASH_FIELDS))
    response_sha = os.environ.get("SUBS_BOT_PROVIDER_MUTATION_RESPONSE_SHA256", "")
    control.require(control.match(control.provider.HEX, response_sha))
    return {"version": 1, "kind": "isolated-provider-mutation-completion", "runId": value["runId"],
            "intentSha256": control.digest(value), "responseSha256": response_sha, "verification": verified}


def write_completion():
    _target, _refs, _operation, value = planned()
    run_id, revision = os.environ["GITHUB_RUN_ID"], os.environ["GITHUB_SHA"]
    digest_journal.workflow_job(run_id, revision, JOBS["verify"])
    writer = store()
    writer.verify()
    control.require(inventory(writer, current=run_id).get(run_id) == {"intent.json"})
    raw_intent = writer.read("intent.json")
    control.require(isinstance(raw_intent, bytes) and raw_intent == control.canonical(value)
                    and os.environ.get("SUBS_BOT_PROVIDER_MUTATION_INTENT_SHA256") == sha256(raw_intent).hexdigest())
    cipher = download_response()
    writer.put_once("response.age", cipher)
    raw = control.canonical(completion_value(value))
    writer.put_once("completion.json", raw)
    digest_journal.output("completion_sha256", sha256(raw).hexdigest())


def independent_readback():
    _target, _refs, _operation, value = planned()
    run_id, revision = os.environ["GITHUB_RUN_ID"], os.environ["GITHUB_SHA"]
    for name in ("intent-readback", "dispatch", "verify", "completion-write"):
        digest_journal.workflow_job(run_id, revision, JOBS[name])
    reader = store()
    reader.verify()
    control.require(inventory(reader, current=run_id).get(run_id) == {"intent.json", "response.age", "completion.json"})
    raw_intent, cipher, raw_done = (reader.read(name) for name in ("intent.json", "response.age", "completion.json"))
    control.require(isinstance(raw_intent, bytes) and raw_intent == control.canonical(value)
                    and sha256(raw_intent).hexdigest() == os.environ.get("SUBS_BOT_PROVIDER_MUTATION_INTENT_SHA256")
                    and isinstance(cipher, bytes) and sha256(cipher).hexdigest() == os.environ.get("SUBS_BOT_PROVIDER_MUTATION_RESPONSE_SHA256")
                    and isinstance(raw_done, bytes) and raw_done == control.canonical(completion_value(value))
                    and sha256(raw_done).hexdigest() == os.environ.get("SUBS_BOT_PROVIDER_MUTATION_COMPLETION_SHA256"))
    job_id = digest_journal.workflow_job(run_id, revision, JOBS["readback"], running=True)
    result = {"intentSha256": sha256(raw_intent).hexdigest(), "responseSha256": sha256(cipher).hexdigest(),
              "completionSha256": sha256(raw_done).hexdigest(), "targetSha256": value["targetSha256"],
              "controllerRevision": revision, "candidateRevision": value["candidateRevision"], "reviewedPr": value["reviewedPr"],
              "operation": value["operation"], "readbackJobId": job_id}
    result["readbackSha256"] = control.digest(projection(run_id, value, result["completionSha256"], job_id))
    print(json.dumps({"status": "independent-mutation-evidence-readback", "runId": run_id, "ledgerRecord": result,
                      "productionMutation": False, "simulatedActionsUnavailable": True}, sort_keys=True))


def failure_evidence(*, readback=False):
    """Preserve an observed response while keeping the operation unresolved."""
    _target, _refs, _operation, value = planned()
    run_id, revision = os.environ["GITHUB_RUN_ID"], os.environ["GITHUB_SHA"]
    reader = store()
    reader.verify()
    keys = inventory(reader, current=run_id).get(run_id)
    control.require(isinstance(keys, set) and "intent.json" in keys
                    and ("failure-observation.age" in keys) is readback
                    and keys <= {"intent.json", "response.age", "completion.json", "failure-observation.age"})
    raw = reader.read("intent.json")
    control.require(isinstance(raw, bytes) and raw == control.canonical(value)
                    and sha256(raw).hexdigest() == os.environ.get("SUBS_BOT_PROVIDER_MUTATION_INTENT_SHA256"))
    cipher = download_response(observation=True)
    if readback:
        digest_journal.workflow_job(run_id, revision, JOBS["failure-write"])
        control.require(reader.read("failure-observation.age") == cipher)
        print(json.dumps({"status": "failure-observation-independently-read", "runId": run_id,
                          "intentSha256": sha256(raw).hexdigest(), "observationSha256": sha256(cipher).hexdigest(),
                          "operationOutcome": "unknown", "retryAuthorized": False}, sort_keys=True))
    else:
        reader.put_once("failure-observation.age", cipher)
        digest_journal.output("observation_sha256", sha256(cipher).hexdigest())


def reconcile_readonly():
    revision = os.environ.get("GITHUB_SHA", "")
    control.require(os.environ.get("GITHUB_REPOSITORY") == control.github.REPOSITORY
                    and os.environ.get("GITHUB_REF") == control.github.MAIN_REF
                    and os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
                    and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
                    and os.environ.get("GITHUB_RUN_ATTEMPT") == "1"
                    and os.environ.get("GITHUB_WORKFLOW_SHA") == revision
                    and os.environ.get("GITHUB_WORKFLOW_REF") == f"{control.github.REPOSITORY}/{RECONCILE_WORKFLOW}@{control.github.MAIN_REF}")
    control.github.require_current_main(revision)
    reader = store()
    reader.verify()
    report = inspect_readonly_run(reader, os.environ.get("SUBS_BOT_PROVIDER_MUTATION_PRIOR_RUN_ID", ""), controllers())
    print(json.dumps({"status": "read-only-inspection", "report": report, "readbackSha256": control.digest(report),
                      "retryAuthorized": False}, sort_keys=True))


if __name__ == "__main__":
    try:
        {"preflight": preflight, "write-intent": write_intent, "read-intent": read_intent,
         "dispatch": dispatch, "verify": verify, "write-completion": write_completion,
         "independent-readback": independent_readback, "reconcile-readonly": reconcile_readonly,
         "failure-write": failure_evidence, "failure-readback": lambda: failure_evidence(readback=True)}[
             os.environ.get("SUBS_BOT_PROVIDER_MUTATION_ACTION", "")]()
    except Exception:
        raise SystemExit("Private Provider operation stopped; preserve the intent and do not retry an unknown write.") from None
