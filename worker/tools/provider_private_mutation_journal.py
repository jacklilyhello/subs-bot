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

PROVIDER_KEYLESS_EVIDENCE_PROTOCOL = 2
BASE = "maintenance/provider-private-mutation/"
MAX_HISTORY = 32
WORKFLOW = transfer.REVIEWED_OPERATION_WORKFLOW_PATH
RECONCILE_WORKFLOW = ".github/workflows/worker-provider-reviewed-operation-reconcile.yml"
JOBS = {"source": "Provider private source transfer", "preflight": "Provider mutation preflight", "intent-write": "Provider mutation intent archive",
        "intent-readback": "Provider mutation intent readback", "dispatch": "Provider mutation dispatch",
        "verify": "Provider mutation independent verification", "completion-write": "Provider mutation completion archive",
        "readback": "Provider mutation evidence readback", "failure-write": "Provider mutation failure evidence archive",
        "failure-readback": "Provider mutation failure evidence readback",
        "keyless-readback": "Provider mutation keyless evidence readback",
        "failure-keyless-readback": "Provider mutation failure keyless evidence readback"}

V1_FILES = {"intent.json", "response.age", "completion.json", "observation.age", "observation.json"}
V2_ORIGINALS = {"observation-plaintext.json", "response.json", "next-target.age", "next-target.json",
                "next-target-archive.json", "next-target-live.json", "recipient-keys.json"}
FAILURE_ORIGINALS = {"failure-target.json", "failure-observation-plaintext.json", "failure-confirmed.json",
                     "failure-next-target.age", "failure-next-target.json", "failure-next-target-archive.json",
                     "failure-next-target-live.json", "failure-recipient-keys.json"}


class Store(sealed.PrivateProofStore):
    def __init__(self, target, run_id):
        super().__init__(target, "", run_id, "1")
        self.prefix = f"{BASE}{run_id}/1/"

    def key(self, relative):
        control.require(relative in V1_FILES | V2_ORIGINALS | FAILURE_ORIGINALS |
                        {"failure-observation.age", "failure-observation.json", "failure-confirmed.age"}
                        or re.fullmatch(r"resolution-[1-9][0-9]*\.json", relative) is not None)
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
    keys = {"intentSha256", "responseSha256", "observationSha256", "observationPlaintextSha256", "completionSha256", "targetSha256", "controllerRevision", "candidateRevision",
            "reviewedPr", "operation", "readbackJobId", "readbackSha256"}
    for run_id, row in value.items():
        extra = {"evidenceVersion", "keyedReadbackJobId", "keyedReceiptSha256"}
        control.require(control.match(control.provider.DECIMAL, run_id) and isinstance(row, dict) and set(row) in (keys, keys | extra)
                        and all(control.match(control.provider.HEX, row[k]) for k in ("intentSha256", "responseSha256", "observationSha256", "observationPlaintextSha256", "completionSha256", "targetSha256", "readbackSha256"))
                        and all(control.match(control.provider.REVISION, row[k]) for k in ("controllerRevision", "candidateRevision"))
                        and control.match(control.provider.DECIMAL, row["readbackJobId"])
                        and transfer.valid_review_identity(row["reviewedPr"], row["candidateRevision"], row["controllerRevision"])
                        and (set(row) == keys or (type(row["evidenceVersion"]) is int and row["evidenceVersion"] == 2
                             and control.match(control.provider.DECIMAL, row["keyedReadbackJobId"])
                             and control.match(control.provider.HEX, row["keyedReceiptSha256"])))
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


def reconciled():
    value = control.github._parse_object(os.environ.get("SUBS_BOT_PROVIDER_MUTATION_RECONCILED_JSON", ""), sealed.ERROR)
    control.require(len(value) <= MAX_HISTORY)
    for run_id, record in value.items():
        control.require(control.match(control.provider.DECIMAL, run_id) and isinstance(record, dict)
                        and isinstance(record.get("pin"), dict) and record["pin"].get("originalRunId") == run_id)
    return value


def inspect_readonly_run(reader, run_id, allowed):
    """Prove all writing jobs were skipped and the private prefix is empty."""
    control.require(control.match(control.provider.DECIMAL, run_id))
    token = control.github._github_token()
    run = control.github._get_json(f"/actions/runs/{run_id}/attempts/1", token)
    latest = control.github._get_json(f"/actions/runs/{run_id}", token)
    revision = run.get("head_sha")
    control.require(str(run.get("id")) == str(latest.get("id")) == run_id
                    and run.get("run_attempt") == latest.get("run_attempt") == 1 and revision in allowed
                    and run.get("path") in (WORKFLOW, WORKFLOW + "@main", WORKFLOW + "@refs/heads/main")
                    and run.get("head_branch") == "main" and run.get("event") == "workflow_dispatch"
                    and run.get("status") == "completed"
                    and run.get("conclusion") in {"success", "failure", "cancelled", "timed_out", "skipped"}
                    and all(isinstance(run.get(k), dict) and run[k].get("id") == control.github.REPOSITORY_ID
                            for k in ("repository", "head_repository")))
    durable.source_ancestor({"revision": revision}, token)
    response = control.github._get_json(f"/actions/runs/{run_id}/attempts/1/jobs?per_page=100", token)
    jobs = response.get("jobs")
    old_names = set(JOBS.values()) - {JOBS["keyless-readback"], JOBS["failure-keyless-readback"]}
    names = {job.get("name") for job in jobs if isinstance(job, dict)} if isinstance(jobs, list) else set()
    control.require(isinstance(jobs, list) and response.get("total_count") == len(jobs)
                    and names in (old_names, set(JOBS.values())) and len(names) == len(jobs))
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
        match = re.fullmatch(re.escape(BASE) + r"([1-9][0-9]*)/1/([a-z0-9.-]+)", key)
        control.require(match is not None)
        relative = match.group(2)
        control.require(relative in V1_FILES | V2_ORIGINALS | FAILURE_ORIGINALS |
                        {"failure-observation.age", "failure-observation.json", "failure-confirmed.age"}
                        or re.fullmatch(r"resolution-[1-9][0-9]*\.json", relative) is not None)
        grouped.setdefault(match.group(1), set()).add(match.group(2))
    registered, recovered, allowed = ledger(), reconciled(), controllers()
    control.require(not set(registered) & set(recovered) and len(grouped) <= MAX_HISTORY
                    and set(grouped) - ({current} if current else set()) == (set(registered) | set(recovered)) - ({current} if current else set()),
                    "A prior private Provider mutation is unresolved; do not retry.")
    import provider_private_mutation_reconcile as recovery
    for run_id, record in recovered.items():
        if run_id == current:
            continue
        names = grouped[run_id]
        control.require({"intent.json", "failure-observation.age", "failure-observation.json",
                         "resolution-" + record["reconcileRunId"] + ".json"} <= names
                        and {name for name in names if name.startswith("resolution-")} == {"resolution-" + record["reconcileRunId"] + ".json"})
        recovery.verify_reconciled(reader, run_id, record, allowed, names)
    for run_id, pin in registered.items():
        if run_id == current:
            continue
        if pin.get("evidenceVersion") == 2:
            control.require(grouped[run_id] == V1_FILES | V2_ORIGINALS and pin["controllerRevision"] in allowed)
            prior = Store(reader.target, run_id)
            intent = canonical_object(prior.read("intent.json"))
            target, _next_target, raw, _done = keyless_bundle(prior, intent)
            control.require(intent.get("runId") == run_id and intent.get("runAttempt") == "1"
                            and intent.get("status") == "started-unknown" and intent.get("kind") == "isolated-provider-mutation-intent"
                            and all(intent.get(key) == pin[key] for key in ("controllerRevision", "candidateRevision", "reviewedPr", "operation", "targetSha256"))
                            and control.digest(target) == pin["targetSha256"]
                            and sha256(raw["intent.json"]).hexdigest() == pin["intentSha256"]
                            and sha256(raw["response.age"]).hexdigest() == pin["responseSha256"]
                            and sha256(raw["observation.age"]).hexdigest() == pin["observationSha256"]
                            and sha256(raw["observation.json"]).hexdigest() == pin["observationPlaintextSha256"]
                            and sha256(raw["completion.json"]).hexdigest() == pin["completionSha256"]
                            and control.digest(keyed_projection(run_id, intent, pin["completionSha256"], pin["keyedReadbackJobId"])) == pin["keyedReceiptSha256"]
                            and control.digest(keyless_projection(run_id, intent, pin["completionSha256"], pin["keyedReadbackJobId"],
                                                                 pin["keyedReceiptSha256"], pin["readbackJobId"])) == pin["readbackSha256"])
            digest_journal.workflow_job(run_id, pin["controllerRevision"], JOBS["readback"], job_id=pin["keyedReadbackJobId"])
            digest_journal.workflow_job(run_id, pin["controllerRevision"], JOBS["keyless-readback"], job_id=pin["readbackJobId"])
            continue
        control.require(grouped[run_id] == {"intent.json", "response.age", "observation.age", "observation.json", "completion.json"}
                        and pin["controllerRevision"] in allowed)
        prior = Store(reader.target, run_id)
        intent_raw, response_raw, obs_cipher, obs_plain, done_raw = (prior.read(name) for name in
                    ("intent.json", "response.age", "observation.age", "observation.json", "completion.json"))
        control.require(all(isinstance(raw, bytes) and sha256(raw).hexdigest() == pin[key] for raw, key in
                            ((intent_raw, "intentSha256"), (response_raw, "responseSha256"), (obs_cipher, "observationSha256"),
                             (obs_plain, "observationPlaintextSha256"), (done_raw, "completionSha256"))))
        original = control.github._parse_object(intent_raw, sealed.ERROR)
        done = control.github._parse_object(done_raw, sealed.ERROR)
        response_original_value = control.github._parse_object(obs_plain, sealed.ERROR)
        control.require(intent_raw == control.canonical(original) and done_raw == control.canonical(done)
                        and original.get("kind") == "isolated-provider-mutation-intent" and original.get("status") == "started-unknown"
                        and original.get("runId") == run_id and original.get("runAttempt") == "1"
                        and all(original.get(key) == pin[key] for key in ("controllerRevision", "candidateRevision", "reviewedPr", "operation", "targetSha256"))
                        and done == {"version": 1, "kind": "isolated-provider-mutation-completion", "runId": run_id,
                                     "intentSha256": pin["intentSha256"], "responseSha256": pin["responseSha256"],
                                     "observationSha256": pin["observationSha256"], "observationPlaintextSha256": pin["observationPlaintextSha256"],
                                     "verification": done.get("verification")}
                        and obs_plain == control.canonical(response_original_value)
                        and set(response_original_value) == {"version", "kind", "runId", "operation", "controllerRevision", "candidateRevision",
                                                             "reviewedPr", "targetSha256", "intentSha256", "observationCipherSha256",
                                                             "confirmedCipherSha256", "resultSha256", "observation"}
                        and type(response_original_value.get("version")) is int and response_original_value["version"] == 1
                        and response_original_value.get("kind") == "isolated-provider-response-only"
                        and response_original_value.get("runId") == run_id
                        and all(response_original_value.get(key) == pin[key] for key in
                                ("operation", "controllerRevision", "candidateRevision", "reviewedPr", "targetSha256"))
                        and isinstance(response_original_value.get("observation"), dict)
                        and response_original_value.get("intentSha256") == pin["intentSha256"]
                        and response_original_value.get("observationCipherSha256") == pin["observationSha256"]
                        and response_original_value.get("confirmedCipherSha256") == pin["responseSha256"]
                        and isinstance(done.get("verification"), dict) and done["verification"].get("status") == "independently-verified"
                        and set(done["verification"]) == VERIFICATION_FIELDS
                        and done["verification"].get("operation") == pin["operation"]
                        and done["verification"].get("targetSha256") == pin["targetSha256"]
                        and response_original_value.get("resultSha256") == done["verification"].get("resultSha256")
                        and all(control.match(control.provider.HEX, done["verification"].get(key)) for key in
                                VERIFICATION_HASH_FIELDS)
                        and control.digest(projection(run_id, original, pin["completionSha256"], pin["readbackJobId"])) == pin["readbackSha256"])
        digest_journal.workflow_job(run_id, pin["controllerRevision"], JOBS["readback"], job_id=pin["readbackJobId"])
    return grouped


def history(registered, reader):
    token, current, allowed = control.github._github_token(), os.environ["GITHUB_RUN_ID"], controllers()
    resolved, recovered = resolutions(), reconciled()
    control.require(not (set(resolved) & set(registered) or set(resolved) & set(recovered) or set(registered) & set(recovered))
                    and current not in resolved and current not in recovered)
    rows = durable.workflow_runs(WORKFLOW, token)
    seen, resolved_seen, recovered_seen, found = set(), set(), set(), False
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
            if run_id in recovered:
                control.require(run_id not in recovered_seen and row.get("status") == "completed"
                                and row.get("head_sha") == recovered[run_id]["pin"]["originalControllerRevision"]
                                and row.get("conclusion") in {"failure", "cancelled", "timed_out"})
                recovered_seen.add(run_id)
                continue
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
    control.require(found and seen == set(registered) and resolved_seen == set(resolved) and recovered_seen == set(recovered))


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


def download_response(*, observation=False, allow_failed=False):
    prefix = "SUBS_BOT_PROVIDER_MUTATION_OBSERVATION" if observation else "SUBS_BOT_PROVIDER_MUTATION_RESPONSE"
    trusted = "SUBS_BOT_PROVIDER_MUTATION_TRUSTED_OBSERVATION" if observation else "SUBS_BOT_PROVIDER_MUTATION_TRUSTED"
    artifact_id = os.environ.get(prefix + "_ARTIFACT_ID", "")
    archive_sha = os.environ.get(prefix + "_ARTIFACT_SHA256", "")
    cipher_sha = os.environ.get(prefix + "_SHA256", "")
    control.require(control.match(control.provider.DECIMAL, artifact_id) and all(control.match(control.provider.HEX, x) for x in (archive_sha, cipher_sha))
                    and os.environ.get(trusted + "_ARTIFACT_ID") == artifact_id
                    and os.environ.get(trusted + "_ARTIFACT_SHA256") == archive_sha
                    and os.environ.get(trusted + ("_SHA256" if observation else "_RESPONSE_SHA256")) == cipher_sha)
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
    if not observation and not allow_failed:
        digest_journal.workflow_job(run_id, revision, JOBS["dispatch"])
    listing = control.github._get_json(f"/actions/runs/{run_id}/attempts/1/jobs?per_page=100", token)
    jobs = listing.get("jobs")
    control.require(isinstance(jobs, list) and listing.get("total_count") == len(jobs) < 100)
    matched = [job for job in jobs if isinstance(job, dict) and job.get("name") == JOBS["dispatch"]]
    control.require(len(matched) == 1 and isinstance(matched[0].get("steps"), list))
    if observation or allow_failed:
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


NEXT_ARTIFACTS = {
    "age": ("provider-next-target-age", "provider-mutation-next-target.age", "Upload encrypted next target for durable retention", "nextTargetCipherSha256"),
    "archive": ("provider-next-target-archive", "provider-next-target-archive.json", "Upload encrypted next target for archive environment", "nextTargetArchiveSha256"),
    "live": ("provider-next-target-live", "provider-next-target-live.json", "Upload encrypted next target for live environment", "nextTargetLiveSha256"),
}


def download_next_artifact(kind, verification, *, allow_failed=False):
    """Authenticate ciphertext by direct needs output, original run and upload step."""
    control.require(kind in NEXT_ARTIFACTS and isinstance(verification, dict))
    prefix, member, upload_step, expected_field = NEXT_ARTIFACTS[kind]
    artifact_id = os.environ.get(f"SUBS_BOT_PROVIDER_NEXT_{kind.upper()}_ARTIFACT_ID", "")
    archive_sha = os.environ.get(f"SUBS_BOT_PROVIDER_NEXT_{kind.upper()}_ARTIFACT_SHA256", "")
    expected = verification.get(expected_field)
    control.require(control.match(control.provider.DECIMAL, artifact_id) and control.match(control.provider.HEX, archive_sha)
                    and (control.match(control.provider.HEX, expected) or (allow_failed and expected is None)))
    run_id, revision, token = os.environ["GITHUB_RUN_ID"], os.environ["GITHUB_SHA"], control.github._github_token()
    artifact = control.github._get_json("/actions/artifacts/" + artifact_id, token)
    origin = artifact.get("workflow_run")
    control.require(str(artifact.get("id")) == artifact_id and artifact.get("expired") is False
                    and artifact.get("name") == f"{prefix}-{run_id}-1" and artifact.get("digest") == "sha256:" + archive_sha
                    and isinstance(origin, dict) and str(origin.get("id")) == run_id and origin.get("head_sha") == revision
                    and origin.get("head_branch") == "main"
                    and origin.get("repository_id") == origin.get("head_repository_id") == control.github.REPOSITORY_ID)
    run = control.github._get_json(f"/actions/runs/{run_id}/attempts/1", token)
    control.require(str(run.get("id")) == run_id and run.get("run_attempt") == 1
                    and run.get("path") in (WORKFLOW, WORKFLOW + "@main", WORKFLOW + "@refs/heads/main")
                    and run.get("head_sha") == revision and run.get("head_branch") == "main" and run.get("event") == "workflow_dispatch"
                    and all(isinstance(run.get(key), dict) and run[key].get("id") == control.github.REPOSITORY_ID
                            for key in ("repository", "head_repository")))
    result = control.github._get_json(f"/actions/runs/{run_id}/attempts/1/jobs?per_page=100", token)
    jobs = result.get("jobs")
    control.require(isinstance(jobs, list) and result.get("total_count") == len(jobs) < 100)
    found = [job for job in jobs if isinstance(job, dict) and job.get("name") == JOBS["verify"]]
    control.require(len(found) == 1 and str(found[0].get("run_id")) == run_id and found[0].get("run_attempt") == 1
                    and found[0].get("head_sha") == revision and found[0].get("status") == "completed"
                    and (found[0].get("conclusion") in {"success", "failure", "cancelled", "timed_out"} if allow_failed
                         else found[0].get("conclusion") == "success") and isinstance(found[0].get("steps"), list))
    steps = [step for step in found[0]["steps"] if isinstance(step, dict) and step.get("name") == upload_step]
    control.require(len(steps) == 1 and (steps[0].get("status"), steps[0].get("conclusion")) == ("completed", "success"))
    request = control.github.artifact_storage_request(artifact_id, token)
    try:
        with control.provenance.STORAGE_OPENER.open(request, timeout=30) as response:
            control.require(response.status == 200 and response.headers.get("Content-Encoding", "identity") == "identity")
            raw = control.github._bounded_read(response, 2 * 1024 * 1024)
        control.require(sha256(raw).hexdigest() == archive_sha)
        with ZipFile(BytesIO(raw)) as archive:
            items = archive.infolist()
            control.require(len(items) == 1 and items[0].filename == items[0].orig_filename == member
                            and items[0].flag_bits & (1 | 64) == 0 and items[0].compress_type in (ZIP_STORED, ZIP_DEFLATED)
                            and stat.S_IFMT(items[0].external_attr >> 16) in (0, stat.S_IFREG)
                            and 0 < items[0].file_size <= 512 * 1024)
            cipher = archive.read(items[0])
        control.require(0 < len(cipher) <= 512 * 1024 and (expected is None or sha256(cipher).hexdigest() == expected))
        return cipher
    except (OSError, BadZipFile, RuntimeError, ValueError):
        raise control.ProviderError("The exact encrypted next-target artifact could not be read safely.") from None


def decrypt_record(cipher, label):
    """Decrypt only in a protected fresh job; never print raw private content."""
    import tempfile
    control.require(label in {"observation", "confirmed", "next-target"} and isinstance(cipher, bytes) and 0 < len(cipher) <= 512 * 1024)
    with tempfile.TemporaryDirectory(prefix=".provider-observation-", dir=os.environ["RUNNER_TEMP"]) as directory:
        source, target = Path(directory) / (label + ".age"), Path(directory) / (label + ".json")
        with control.provenance._write_private(source) as output:
            output.write(cipher)
        transfer.age_identity(["age", "--decrypt", "--identity", "{identity}"], source, target)
        raw = control.provider.checked_file(target, 256 * 1024).read_bytes()
        value = control.github._parse_object(raw, sealed.ERROR)
        control.require(raw == control.canonical(value))
        return value


def response_plaintexts(target, value, observation_cipher, confirmed_cipher=None):
    intent_sha = control.digest(value)
    observed = decrypt_record(observation_cipher, "observation")
    control.require(set(observed) == {"intentSha256", "observation"} and observed["intentSha256"] == intent_sha)
    observation = mutation.checked_observation(target, value["operation"], observed["observation"])
    confirmed = None
    if confirmed_cipher is not None:
        confirmed = decrypt_record(confirmed_cipher, "confirmed")
        control.require(set(confirmed) == {"intentSha256", "target", "operation", "observation", "result"}
                        and confirmed["intentSha256"] == intent_sha and confirmed["target"] == target
                        and confirmed["operation"] == value["operation"] and confirmed["observation"] == observation
                        and isinstance(confirmed["result"], dict))
        mutation.checked_result(target, value["operation"], confirmed["result"])
    return observed, confirmed


def response_original(target, value, observation_cipher, confirmed_cipher=None):
    intent_sha = control.digest(value)
    observed, confirmed = response_plaintexts(target, value, observation_cipher, confirmed_cipher)
    observation = observed["observation"]
    confirmed_sha = sha256(confirmed_cipher).hexdigest() if confirmed is not None else None
    result_sha = control.digest(confirmed["result"]) if confirmed is not None else None
    return {"version": 1, "kind": "isolated-provider-response-only", "runId": value["runId"], "operation": value["operation"],
            "controllerRevision": value["controllerRevision"], "candidateRevision": value["candidateRevision"],
            "reviewedPr": value["reviewedPr"], "targetSha256": value["targetSha256"], "intentSha256": intent_sha,
            "observationCipherSha256": sha256(observation_cipher).hexdigest(), "confirmedCipherSha256": confirmed_sha,
            "resultSha256": result_sha,
            "observation": observation}


def checked_next_plaintext(target, value, confirmed, next_cipher):
    next_record = decrypt_record(next_cipher, "next-target")
    expected = rehearsal.confirmed_target(target, value["operation"], confirmed["result"])
    control.require(set(next_record) == {"target", "sourceIntentSha256"} and next_record["target"] == expected
                    and next_record["sourceIntentSha256"] == control.digest(value))
    return next_record


def checked_next_payload(kind, raw, verification, *, key_material=None):
    """Check the exact GitHub sealed-box payload and independently pinned public key."""
    control.require(kind in {"archive", "live"} and isinstance(raw, bytes) and 0 < len(raw) <= 512 * 1024)
    if key_material is None:
        keys = control.github._parse_object(os.environ.get("SUBS_BOT_PROVIDER_NEXT_TARGET_KEYS_JSON", ""), sealed.ERROR)
        pins = control.github._parse_object(os.environ.get("SUBS_BOT_PROVIDER_NEXT_TARGET_KEY_PINS_JSON", ""), sealed.ERROR)
    else:
        control.require(isinstance(key_material, dict) and set(key_material) == {"keys", "pins"})
        keys, pins = key_material["keys"], key_material["pins"]
    control.require(set(keys) == set(pins) == {"archive", "live"})
    row, payload = keys[kind], control.github._parse_object(raw, sealed.ERROR)
    environment = "subs-bot-provider-archive-head-isolation" if kind == "archive" else "subs-bot-provider-head-isolation"
    control.require(isinstance(row, dict) and set(row) == {"environmentId", "keyId", "publicKey"}
                    and set(payload) == {"encrypted_value", "key_id"} and raw == control.canonical(payload)
                    and control.match(control.provider.DECIMAL, row["environmentId"])
                    and isinstance(row["keyId"], str) and re.fullmatch(r"[A-Za-z0-9_-]{1,128}", row["keyId"])
                    and isinstance(row["publicKey"], str) and len(row["publicKey"]) <= 128
                    and payload["key_id"] == row["keyId"] and isinstance(payload["encrypted_value"], str)
                    and len(payload["encrypted_value"]) <= 512 * 1024)
    public = base64.b64decode(row["publicKey"], validate=True)
    cipher = base64.b64decode(payload["encrypted_value"], validate=True)
    pin = {"version": 1, "repositoryId": control.github.REPOSITORY_ID, "environment": environment,
           "environmentId": row["environmentId"], "keyId": row["keyId"], "publicKey": row["publicKey"]}
    control.require(len(public) == 32 and base64.b64encode(public).decode("ascii") == row["publicKey"]
                    and 48 <= len(cipher) <= 256 * 1024 + 48 and base64.b64encode(cipher).decode("ascii") == payload["encrypted_value"]
                    and control.match(control.provider.HEX, pins[kind]) and control.digest(pin) == pins[kind]
                    and sha256(raw).hexdigest() == verification[NEXT_ARTIFACTS[kind][3]])
    return payload


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
    mutation.checked_observation(target, operation, record["observation"])
    mutation.checked_result(target, operation, record["result"])
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


def completion_value(value, original, *, originals=None):
    verified = control.github._parse_object(os.environ.get("SUBS_BOT_PROVIDER_MUTATION_VERIFICATION_JSON", ""), sealed.ERROR)
    control.require(set(verified) == VERIFICATION_FIELDS
                    and verified["status"] == "independently-verified" and verified["operation"] == value["operation"]
                    and verified["targetSha256"] == value["targetSha256"]
                    and all(control.match(control.provider.HEX, verified[k]) for k in VERIFICATION_HASH_FIELDS))
    response_sha = os.environ.get("SUBS_BOT_PROVIDER_MUTATION_RESPONSE_SHA256", "")
    control.require(control.match(control.provider.HEX, response_sha) and original["confirmedCipherSha256"] == response_sha
                    and original["resultSha256"] == verified["resultSha256"])
    completed = {"version": 1, "kind": "isolated-provider-mutation-completion", "runId": value["runId"],
            "intentSha256": control.digest(value), "responseSha256": response_sha,
            "observationSha256": original["observationCipherSha256"], "observationPlaintextSha256": control.digest(original),
            "verification": verified}
    if originals is not None:
        control.require(isinstance(originals, dict) and set(originals) == V2_ORIGINALS
                        and all(control.match(control.provider.HEX, item) for item in originals.values())
                        and originals["next-target.age"] == verified["nextTargetCipherSha256"]
                        and originals["next-target-archive.json"] == verified["nextTargetArchiveSha256"]
                        and originals["next-target-live.json"] == verified["nextTargetLiveSha256"])
        completed.update(version=2, originals=originals)
    return completed


def write_completion():
    target, _refs, _operation, value = planned()
    run_id, revision = os.environ["GITHUB_RUN_ID"], os.environ["GITHUB_SHA"]
    digest_journal.workflow_job(run_id, revision, JOBS["verify"])
    writer = store()
    writer.verify()
    control.require(inventory(writer, current=run_id).get(run_id) == {"intent.json"})
    raw_intent = writer.read("intent.json")
    control.require(isinstance(raw_intent, bytes) and raw_intent == control.canonical(value)
                    and os.environ.get("SUBS_BOT_PROVIDER_MUTATION_INTENT_SHA256") == sha256(raw_intent).hexdigest())
    cipher, observation = download_response(), download_response(observation=True)
    original = response_original(target, value, observation, cipher)
    observed, confirmed = response_plaintexts(target, value, observation, cipher)
    verification = control.github._parse_object(os.environ.get("SUBS_BOT_PROVIDER_MUTATION_VERIFICATION_JSON", ""), sealed.ERROR)
    next_cipher = download_next_artifact("age", verification)
    next_record = checked_next_plaintext(target, value, confirmed, next_cipher)
    archive_cipher, live_cipher = (download_next_artifact(kind, verification) for kind in ("archive", "live"))
    checked_next_payload("archive", archive_cipher, verification)
    checked_next_payload("live", live_cipher, verification)
    originals = {"observation-plaintext.json": control.canonical(observed), "response.json": control.canonical(confirmed),
                 "next-target.age": next_cipher, "next-target.json": control.canonical(next_record),
                 "next-target-archive.json": archive_cipher, "next-target-live.json": live_cipher,
                 "recipient-keys.json": control.canonical({
                     "keys": control.github._parse_object(os.environ.get("SUBS_BOT_PROVIDER_NEXT_TARGET_KEYS_JSON", ""), sealed.ERROR),
                     "pins": control.github._parse_object(os.environ.get("SUBS_BOT_PROVIDER_NEXT_TARGET_KEY_PINS_JSON", ""), sealed.ERROR)})}
    completed = completion_value(value, original, originals={name: sha256(raw).hexdigest() for name, raw in originals.items()})
    writer.put_once("observation.age", observation)
    writer.put_once("observation.json", control.canonical(original))
    writer.put_once("response.age", cipher)
    for name, raw in originals.items():
        writer.put_once(name, raw)
    raw = control.canonical(completed)
    writer.put_once("completion.json", raw)
    digest_journal.output("completion_sha256", sha256(raw).hexdigest())


def independent_readback():
    target, _refs, _operation, value = planned()
    run_id, revision = os.environ["GITHUB_RUN_ID"], os.environ["GITHUB_SHA"]
    for name in ("intent-readback", "dispatch", "verify", "completion-write"):
        digest_journal.workflow_job(run_id, revision, JOBS[name])
    reader = store()
    reader.verify()
    control.require(inventory(reader, current=run_id).get(run_id) == V1_FILES | V2_ORIGINALS)
    raw_intent, cipher, observation, raw_observation, raw_done = (reader.read(name) for name in
                       ("intent.json", "response.age", "observation.age", "observation.json", "completion.json"))
    original = response_original(target, value, observation, cipher)
    observed, confirmed = response_plaintexts(target, value, observation, cipher)
    originals = {name: reader.read(name) for name in V2_ORIGINALS}
    control.require(all(isinstance(raw, bytes) for raw in originals.values()))
    verification = control.github._parse_object(os.environ.get("SUBS_BOT_PROVIDER_MUTATION_VERIFICATION_JSON", ""), sealed.ERROR)
    next_record = checked_next_plaintext(target, value, confirmed, originals["next-target.age"])
    checked_next_payload("archive", originals["next-target-archive.json"], verification)
    checked_next_payload("live", originals["next-target-live.json"], verification)
    control.require(isinstance(raw_intent, bytes) and raw_intent == control.canonical(value)
                    and sha256(raw_intent).hexdigest() == os.environ.get("SUBS_BOT_PROVIDER_MUTATION_INTENT_SHA256")
                    and isinstance(cipher, bytes) and sha256(cipher).hexdigest() == os.environ.get("SUBS_BOT_PROVIDER_MUTATION_RESPONSE_SHA256")
                    and isinstance(observation, bytes) and sha256(observation).hexdigest() == os.environ.get("SUBS_BOT_PROVIDER_MUTATION_OBSERVATION_SHA256")
                    and isinstance(raw_observation, bytes) and raw_observation == control.canonical(original)
                    and originals["observation-plaintext.json"] == control.canonical(observed)
                    and originals["response.json"] == control.canonical(confirmed)
                    and originals["next-target.json"] == control.canonical(next_record)
                    and isinstance(raw_done, bytes) and raw_done == control.canonical(completion_value(value, original,
                        originals={name: sha256(raw).hexdigest() for name, raw in originals.items()}))
                    and sha256(raw_done).hexdigest() == os.environ.get("SUBS_BOT_PROVIDER_MUTATION_COMPLETION_SHA256"))
    job_id = digest_journal.workflow_job(run_id, revision, JOBS["readback"], running=True)
    receipt = keyed_projection(run_id, value, sha256(raw_done).hexdigest(), job_id)
    digest_journal.output("keyed_receipt_sha256", control.digest(receipt))
    print(json.dumps({"status": "keyed-evidence-readback-only", "runId": run_id,
                      "keyedReceiptSha256": control.digest(receipt), "ledgerRegistrationAllowed": False,
                      "productionMutation": False}, sort_keys=True))


def keyed_projection(run_id, value, completion_sha, job_id):
    return {"version": 2, "kind": "isolated-provider-keyed-readback", "runId": run_id, "runAttempt": "1",
            "intentSha256": control.digest(value), "completionSha256": completion_sha,
            "controllerRevision": value["controllerRevision"], "candidateRevision": value["candidateRevision"],
            "reviewedPr": value["reviewedPr"], "readbackJobId": job_id}


def canonical_object(raw):
    control.require(isinstance(raw, bytes) and 0 < len(raw) <= 256 * 1024)
    result = control.github._parse_object(raw, sealed.ERROR)
    control.require(raw == control.canonical(result))
    return result


def keyless_bundle(reader, value):
    """Reconstruct the complete allowlisted v2 originals without the age identity."""
    raw = {name: reader.read(name) for name in V1_FILES | V2_ORIGINALS}
    control.require(all(isinstance(item, bytes) and 0 < len(item) <= 512 * 1024 for item in raw.values()))
    intent, observed, confirmed, next_record, wrapped, done, key_material = (canonical_object(raw[name]) for name in
        ("intent.json", "observation-plaintext.json", "response.json", "next-target.json", "observation.json", "completion.json", "recipient-keys.json"))
    control.require(intent == value and set(confirmed) == {"intentSha256", "target", "operation", "observation", "result"}
                    and set(observed) == {"intentSha256", "observation"} and set(next_record) == {"target", "sourceIntentSha256"})
    intent_sha = control.digest(value)
    target = control.validate_config(confirmed["target"])
    control.require(control.digest(target) == value["targetSha256"] and confirmed["intentSha256"] == intent_sha
                    and confirmed["operation"] == value["operation"] and observed["intentSha256"] == intent_sha
                    and observed["observation"] == confirmed["observation"] and next_record["sourceIntentSha256"] == intent_sha)
    mutation.checked_observation(target, value["operation"], observed["observation"])
    mutation.checked_result(target, value["operation"], confirmed["result"])
    control.require(next_record["target"] == rehearsal.confirmed_target(target, value["operation"], confirmed["result"]))
    expected_wrapped = {"version": 1, "kind": "isolated-provider-response-only", "runId": value["runId"], "operation": value["operation"],
        "controllerRevision": value["controllerRevision"], "candidateRevision": value["candidateRevision"], "reviewedPr": value["reviewedPr"],
        "targetSha256": value["targetSha256"], "intentSha256": intent_sha, "observationCipherSha256": sha256(raw["observation.age"]).hexdigest(),
        "confirmedCipherSha256": sha256(raw["response.age"]).hexdigest(), "resultSha256": control.digest(confirmed["result"]),
        "observation": observed["observation"]}
    control.require(wrapped == expected_wrapped and isinstance(done.get("verification"), dict))
    verification = done["verification"]
    control.require(set(verification) == VERIFICATION_FIELDS and verification["status"] == "independently-verified"
                    and verification["operation"] == value["operation"] and verification["targetSha256"] == value["targetSha256"]
                    and verification["resultSha256"] == control.digest(confirmed["result"])
                    and verification["nextTargetSha256"] == control.digest(next_record["target"])
                    and all(control.match(control.provider.HEX, verification[key]) for key in VERIFICATION_HASH_FIELDS))
    checked_next_payload("archive", raw["next-target-archive.json"], verification, key_material=key_material)
    checked_next_payload("live", raw["next-target-live.json"], verification, key_material=key_material)
    originals = {name: sha256(raw[name]).hexdigest() for name in V2_ORIGINALS}
    expected_done = {"version": 2, "kind": "isolated-provider-mutation-completion", "runId": value["runId"],
        "intentSha256": intent_sha, "responseSha256": sha256(raw["response.age"]).hexdigest(),
        "observationSha256": sha256(raw["observation.age"]).hexdigest(),
        "observationPlaintextSha256": control.digest(wrapped), "verification": verification, "originals": originals}
    control.require(done == expected_done and originals["next-target.age"] == verification["nextTargetCipherSha256"])
    return target, next_record["target"], raw, done


def keyless_projection(run_id, value, completion_sha, keyed_job_id, keyed_receipt_sha, job_id):
    return {"version": 2, "kind": "isolated-provider-keyless-readback", "runId": run_id, "runAttempt": "1",
            "intentSha256": control.digest(value), "completionSha256": completion_sha,
            "controllerRevision": value["controllerRevision"], "candidateRevision": value["candidateRevision"],
            "reviewedPr": value["reviewedPr"], "keyedReadbackJobId": keyed_job_id,
            "keyedReceiptSha256": keyed_receipt_sha, "readbackJobId": job_id}


def verify_keyless_sources(target):
    """Re-read the source archive and full previous chain without an age key."""
    control.require(not os.environ.get("SUBS_BOT_PROVIDER_SOURCE_AGE_IDENTITY"))
    durable.restore()
    control.guard_sources(target)
    control.require(control.prepare_durable(target["build"]) == target["build"])
    import tempfile
    with tempfile.TemporaryDirectory(prefix=".provider-keyless-source-", dir=os.environ["RUNNER_TEMP"]) as scratch:
        control.verify_previous_archives(target, Path(scratch))
    control.guard_sources(target)


def keyless_readback():
    control.require(not os.environ.get("SUBS_BOT_PROVIDER_SOURCE_AGE_IDENTITY"))
    transfer.context()
    control.require(transfer.workflow_path() == WORKFLOW)
    run_id, revision = os.environ["GITHUB_RUN_ID"], os.environ["GITHUB_SHA"]
    reader = store()
    reader.verify()
    control.require(inventory(reader, current=run_id).get(run_id) == V1_FILES | V2_ORIGINALS)
    value = canonical_object(reader.read("intent.json"))
    target, _next_target, raw, done = keyless_bundle(reader, value)
    control.require(canonical_object(raw["recipient-keys.json"]) == {
        "keys": control.github._parse_object(os.environ.get("SUBS_BOT_PROVIDER_NEXT_TARGET_KEYS_JSON", ""), sealed.ERROR),
        "pins": control.github._parse_object(os.environ.get("SUBS_BOT_PROVIDER_NEXT_TARGET_KEY_PINS_JSON", ""), sealed.ERROR)})
    refs = transfer.refs()
    state = control.github._parse_object(os.environ.get("SUBS_BOT_PROVIDER_MUTATION_PRESTATE_JSON", ""), sealed.ERROR)
    expected = mutation.intent(target, refs, os.environ.get("SUBS_BOT_PROVIDER_MUTATION_OPERATION", ""), state, run_id, revision)
    intent_sha = os.environ.get("SUBS_BOT_PROVIDER_MUTATION_INTENT_SHA256", "")
    completion_sha = os.environ.get("SUBS_BOT_PROVIDER_MUTATION_COMPLETION_SHA256", "")
    control.require(value == expected and control.match(control.provider.HEX, intent_sha) and intent_sha == control.digest(value)
                    and os.environ.get("SUBS_BOT_PROVIDER_MUTATION_APPROVAL") == value["approvalSha256"]
                    and control.match(control.provider.HEX, completion_sha) and completion_sha == sha256(raw["completion.json"]).hexdigest()
                    and done["verification"] == control.github._parse_object(os.environ.get("SUBS_BOT_PROVIDER_MUTATION_VERIFICATION_JSON", ""), sealed.ERROR))
    verify_keyless_sources(target)
    for name in ("intent-readback", "dispatch", "verify", "completion-write"):
        digest_journal.workflow_job(run_id, revision, JOBS[name])
    keyed_id = digest_journal.workflow_job(run_id, revision, JOBS["readback"])
    keyed_sha = os.environ.get("SUBS_BOT_PROVIDER_MUTATION_KEYED_RECEIPT_SHA256", "")
    control.require(control.match(control.provider.HEX, keyed_sha)
                    and keyed_sha == control.digest(keyed_projection(run_id, value, completion_sha, keyed_id)))
    job_id = digest_journal.workflow_job(run_id, revision, JOBS["keyless-readback"], running=True)
    result = {"intentSha256": intent_sha, "responseSha256": sha256(raw["response.age"]).hexdigest(),
              "observationSha256": sha256(raw["observation.age"]).hexdigest(),
              "observationPlaintextSha256": sha256(raw["observation.json"]).hexdigest(),
              "completionSha256": completion_sha, "targetSha256": value["targetSha256"],
              "controllerRevision": revision, "candidateRevision": value["candidateRevision"], "reviewedPr": value["reviewedPr"],
              "operation": value["operation"], "readbackJobId": job_id, "evidenceVersion": 2,
              "keyedReadbackJobId": keyed_id, "keyedReceiptSha256": keyed_sha}
    result["readbackSha256"] = control.digest(keyless_projection(run_id, value, completion_sha, keyed_id, keyed_sha, job_id))
    print(json.dumps({"status": "independent-keyless-evidence-readback", "runId": run_id, "ledgerRecord": result,
                      "productionMutation": False, "simulatedActionsUnavailable": True}, sort_keys=True))


def failure_evidence(*, readback=False):
    """Preserve an observed response while keeping the operation unresolved."""
    target, _refs, _operation, value = planned()
    run_id, revision = os.environ["GITHUB_RUN_ID"], os.environ["GITHUB_SHA"]
    reader = store()
    reader.verify()
    keys = inventory(reader, current=run_id).get(run_id)
    failure_keys = {"failure-observation.age", "failure-observation.json", "failure-confirmed.age"} | FAILURE_ORIGINALS
    control.require(isinstance(keys, set) and "intent.json" in keys
                    and (bool(keys & failure_keys) is readback)
                    and keys <= V1_FILES | V2_ORIGINALS | failure_keys)
    raw = reader.read("intent.json")
    control.require(isinstance(raw, bytes) and raw == control.canonical(value)
                    and sha256(raw).hexdigest() == os.environ.get("SUBS_BOT_PROVIDER_MUTATION_INTENT_SHA256"))
    cipher = download_response(observation=True)
    if not readback:
        # Preserve the authenticated ciphertext even if its plaintext is malformed
        # or the temporary identity cannot decrypt it. The intent remains unknown.
        reader.put_once("failure-observation.age", cipher)
    confirmed = download_response(allow_failed=True) if os.environ.get("SUBS_BOT_PROVIDER_MUTATION_RESPONSE_ARTIFACT_ID", "") else None
    if not readback and confirmed is not None:
        reader.put_once("failure-confirmed.age", confirmed)
    raw_verification = os.environ.get("SUBS_BOT_PROVIDER_MUTATION_VERIFICATION_JSON", "")
    verification = control.github._parse_object(raw_verification, sealed.ERROR) if raw_verification else {}
    next_ciphers, cipher_files = {}, {}
    for kind in ("age", "archive", "live"):
        artifact_id = os.environ.get(f"SUBS_BOT_PROVIDER_NEXT_{kind.upper()}_ARTIFACT_ID", "")
        artifact_sha = os.environ.get(f"SUBS_BOT_PROVIDER_NEXT_{kind.upper()}_ARTIFACT_SHA256", "")
        control.require(bool(artifact_id) == bool(artifact_sha))
        if artifact_id:
            next_ciphers[kind] = download_next_artifact(kind, verification, allow_failed=True)
            name = "failure-next-target.age" if kind == "age" else "failure-next-target-" + kind + ".json"
            cipher_files[name] = next_ciphers[kind]
            if not readback:
                reader.put_once(name, next_ciphers[kind])
    observed, _ = response_plaintexts(target, value, cipher)
    core = {"failure-observation.age": cipher, "failure-observation-plaintext.json": control.canonical(observed),
            "failure-target.json": control.canonical(control.validate_config(target))}
    if not readback:
        for name, body in core.items():
            if name != "failure-observation.age":
                reader.put_once(name, body)
    original = response_original(target, value, cipher, confirmed)
    _observed, confirmed_value = response_plaintexts(target, value, cipher, confirmed)
    core["failure-observation.json"] = control.canonical(original)
    if confirmed is not None:
        core["failure-confirmed.age"] = confirmed
        core["failure-confirmed.json"] = control.canonical(confirmed_value)
    core.update(cipher_files)
    if "age" in next_ciphers:
        control.require(confirmed_value is not None)
        core["failure-next-target.json"] = control.canonical(checked_next_plaintext(target, value, confirmed_value, next_ciphers["age"]))
    if {"archive", "live"} & set(next_ciphers):
        material = {"keys": control.github._parse_object(os.environ.get("SUBS_BOT_PROVIDER_NEXT_TARGET_KEYS_JSON", ""), sealed.ERROR),
                    "pins": control.github._parse_object(os.environ.get("SUBS_BOT_PROVIDER_NEXT_TARGET_KEY_PINS_JSON", ""), sealed.ERROR)}
        for kind in ("archive", "live"):
            if kind in next_ciphers:
                observed_verification = {**verification, NEXT_ARTIFACTS[kind][3]: sha256(next_ciphers[kind]).hexdigest()}
                checked_next_payload(kind, next_ciphers[kind], observed_verification, key_material=material)
        core["failure-recipient-keys.json"] = control.canonical(material)
    if readback:
        digest_journal.workflow_job(run_id, revision, JOBS["failure-write"])
        control.require(keys & failure_keys == set(core) and all(reader.read(name) == body for name, body in core.items()))
        job_id = digest_journal.workflow_job(run_id, revision, JOBS["failure-readback"], running=True)
        receipt = failure_keyed_projection(run_id, value, core, job_id)
        digest_journal.output("keyed_receipt_sha256", control.digest(receipt))
        print(json.dumps({"status": "keyed-failure-evidence-readback-only", "runId": run_id,
                          "keyedReceiptSha256": control.digest(receipt), "operationOutcome": "unknown",
                          "retryAuthorized": False}, sort_keys=True))
    else:
        already = {"failure-observation.age", "failure-observation-plaintext.json", "failure-target.json", "failure-confirmed.age",
                   *({"failure-next-target.age"} if "age" in next_ciphers else set()),
                   *("failure-next-target-" + kind + ".json" for kind in ("archive", "live") if kind in next_ciphers)}
        for name, body in core.items():
            if name not in already:
                reader.put_once(name, body)
        digest_journal.output("observation_sha256", sha256(cipher).hexdigest())


def failure_keyed_projection(run_id, value, files, job_id):
    return {"version": 2, "kind": "isolated-provider-failure-keyed-readback", "runId": run_id, "runAttempt": "1",
            "intentSha256": control.digest(value), "controllerRevision": value["controllerRevision"],
            "candidateRevision": value["candidateRevision"], "reviewedPr": value["reviewedPr"],
            "files": {name: sha256(body).hexdigest() for name, body in files.items()}, "readbackJobId": job_id,
            "status": "unknown"}


def failure_keyless_projection(run_id, value, keyed_id, keyed_sha, job_id):
    return {"version": 2, "kind": "isolated-provider-failure-keyless-readback", "runId": run_id, "runAttempt": "1",
            "intentSha256": control.digest(value), "controllerRevision": value["controllerRevision"],
            "candidateRevision": value["candidateRevision"], "reviewedPr": value["reviewedPr"],
            "keyedReadbackJobId": keyed_id, "keyedReceiptSha256": keyed_sha, "readbackJobId": job_id, "status": "unknown"}


def failure_keyless_readback():
    control.require(not os.environ.get("SUBS_BOT_PROVIDER_SOURCE_AGE_IDENTITY"))
    transfer.context()
    control.require(transfer.workflow_path() == WORKFLOW)
    run_id, revision = os.environ["GITHUB_RUN_ID"], os.environ["GITHUB_SHA"]
    reader = store()
    reader.verify()
    keys = inventory(reader, current=run_id).get(run_id)
    failure_keys = {"failure-observation.age", "failure-observation.json", "failure-confirmed.age"} | FAILURE_ORIGINALS
    required = {"failure-target.json", "failure-observation.age", "failure-observation-plaintext.json", "failure-observation.json"}
    control.require(isinstance(keys, set) and required <= keys and keys <= V1_FILES | V2_ORIGINALS | failure_keys)
    files = {name: reader.read(name) for name in keys & failure_keys}
    control.require(all(isinstance(raw, bytes) and 0 < len(raw) <= 512 * 1024 for raw in files.values()))
    value, target = canonical_object(reader.read("intent.json")), control.validate_config(canonical_object(files["failure-target.json"]))
    observed, wrapped = canonical_object(files["failure-observation-plaintext.json"]), canonical_object(files["failure-observation.json"])
    intent_sha = control.digest(value)
    refs = transfer.refs()
    state = control.github._parse_object(os.environ.get("SUBS_BOT_PROVIDER_MUTATION_PRESTATE_JSON", ""), sealed.ERROR)
    expected = mutation.intent(target, refs, os.environ.get("SUBS_BOT_PROVIDER_MUTATION_OPERATION", ""), state, run_id, revision)
    control.require(value == expected and intent_sha == os.environ.get("SUBS_BOT_PROVIDER_MUTATION_INTENT_SHA256")
                    and value["approvalSha256"] == os.environ.get("SUBS_BOT_PROVIDER_MUTATION_APPROVAL")
                    and set(observed) == {"intentSha256", "observation"} and observed["intentSha256"] == intent_sha)
    mutation.checked_observation(target, value["operation"], observed["observation"])
    confirmed = None
    control.require(("failure-confirmed.age" in files) == ("failure-confirmed.json" in files))
    if "failure-confirmed.age" in files:
        confirmed = canonical_object(files["failure-confirmed.json"])
        control.require(set(confirmed) == {"intentSha256", "target", "operation", "observation", "result"}
                        and confirmed["intentSha256"] == intent_sha and confirmed["target"] == target
                        and confirmed["operation"] == value["operation"] and confirmed["observation"] == observed["observation"])
        mutation.checked_result(target, value["operation"], confirmed["result"])
    expected_wrapper = {"version": 1, "kind": "isolated-provider-response-only", "runId": run_id, "operation": value["operation"],
        "controllerRevision": revision, "candidateRevision": value["candidateRevision"], "reviewedPr": value["reviewedPr"],
        "targetSha256": value["targetSha256"], "intentSha256": intent_sha,
        "observationCipherSha256": sha256(files["failure-observation.age"]).hexdigest(),
        "confirmedCipherSha256": sha256(files["failure-confirmed.age"]).hexdigest() if confirmed is not None else None,
        "resultSha256": control.digest(confirmed["result"]) if confirmed is not None else None, "observation": observed["observation"]}
    control.require(wrapped == expected_wrapper and ("failure-next-target.age" in files) == ("failure-next-target.json" in files))
    if "failure-next-target.age" in files:
        next_record = canonical_object(files["failure-next-target.json"])
        control.require(confirmed is not None and set(next_record) == {"target", "sourceIntentSha256"}
                        and next_record["sourceIntentSha256"] == intent_sha
                        and next_record["target"] == rehearsal.confirmed_target(target, value["operation"], confirmed["result"]))
    sealed_names = {kind for kind in ("archive", "live") if "failure-next-target-" + kind + ".json" in files}
    control.require(bool(sealed_names) == ("failure-recipient-keys.json" in files))
    if sealed_names:
        material = canonical_object(files["failure-recipient-keys.json"])
        for kind in sealed_names:
            raw = files["failure-next-target-" + kind + ".json"]
            checked_next_payload(kind, raw, {NEXT_ARTIFACTS[kind][3]: sha256(raw).hexdigest()}, key_material=material)
    if "completion.json" in keys:
        control.require(V1_FILES | V2_ORIGINALS <= keys)
        prior_target, _, _, _ = keyless_bundle(reader, value)
        control.require(prior_target == target)
    verify_keyless_sources(target)
    keyed_id = digest_journal.workflow_job(run_id, revision, JOBS["failure-readback"])
    receipt = os.environ.get("SUBS_BOT_PROVIDER_MUTATION_KEYED_RECEIPT_SHA256", "")
    control.require(control.match(control.provider.HEX, receipt)
                    and receipt == control.digest(failure_keyed_projection(run_id, value, files, keyed_id)))
    job_id = digest_journal.workflow_job(run_id, revision, JOBS["failure-keyless-readback"], running=True)
    projection = failure_keyless_projection(run_id, value, keyed_id, receipt, job_id)
    print(json.dumps({"status": "independent-keyless-failure-evidence-readback", "runId": run_id,
                      "intentSha256": intent_sha, "keyedReadbackJobId": keyed_id, "keyedReceiptSha256": receipt,
                      "keylessReadbackJobId": job_id, "keylessReceiptSha256": control.digest(projection),
                      "operationOutcome": "unknown", "retryAuthorized": False, "productionMutation": False}, sort_keys=True))


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
         "keyless-readback": keyless_readback, "failure-write": failure_evidence,
         "failure-readback": lambda: failure_evidence(readback=True), "failure-keyless-readback": failure_keyless_readback}[
             os.environ.get("SUBS_BOT_PROVIDER_MUTATION_ACTION", "")]()
    except Exception:
        raise SystemExit("Private Provider operation stopped; preserve the intent and do not retry an unknown write.") from None
