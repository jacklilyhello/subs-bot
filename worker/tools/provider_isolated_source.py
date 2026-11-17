"""Append-only isolation archive for exact original Provider CI sources.

This is distinct from completed rehearsal proof and from the production bucket.
Only a separately pinned, independently read back source can enter a release chain.
"""

from hashlib import sha256
import json
import os
from pathlib import Path
import re
import tempfile

import archive_production_provider as sealed
import production_provider as control
import provider_durable_source as durable
import provider_source_transfer as transfer

BASE = "maintenance/provider-isolated-source/"
SEAL_WORKFLOW = ".github/workflows/worker-provider-isolated-source.yml"
READBACK_WORKFLOW = ".github/workflows/worker-provider-isolated-source-readback.yml"
REVIEWED_SEAL_WORKFLOW = transfer.REVIEWED_SOURCE_WORKFLOW_PATH
REVIEWED_READBACK_WORKFLOW = transfer.REVIEWED_SOURCE_READBACK_WORKFLOW_PATH
MAX_HISTORY = 32


class Store(durable.ProductionStore):
    def __init__(self, target, token, operation_id):
        sealed.PrivateProofStore.__init__(self, target, token, operation_id, "1")
        self.prefix = f"{BASE}{operation_id}/1/"


def context(workflow, *, write=False):
    ref = os.environ.get("GITHUB_WORKFLOW_REF", "")
    reviewed = REVIEWED_SEAL_WORKFLOW if workflow == SEAL_WORKFLOW else REVIEWED_READBACK_WORKFLOW
    actual = reviewed if ref == f"{control.github.REPOSITORY}/{reviewed}@{control.github.MAIN_REF}" else workflow
    durable.seal_context(actual, mutation=write)
    if actual == reviewed:
        control.require(transfer.execution_identity(os.environ["GITHUB_SHA"])["workflowPath"] == actual)
    control.require(os.environ.get("SUBS_BOT_PROVIDER_ISOLATED_SOURCE_ENABLED") == "true")


def reviewed_identity(workflow):
    ref = os.environ.get("GITHUB_WORKFLOW_REF", "")
    reviewed = REVIEWED_SEAL_WORKFLOW if workflow == SEAL_WORKFLOW else REVIEWED_READBACK_WORKFLOW
    if ref != f"{control.github.REPOSITORY}/{reviewed}@{control.github.MAIN_REF}":
        return {}
    return transfer.execution_identity(os.environ["GITHUB_SHA"])


def target_config():
    target = control.read_config(os.environ.get("SUBS_BOT_PROVIDER_CONTROL_TARGET_JSON", ""))
    control.require(target["environment"] == "rehearsal" and target["caller"] is None
                    and target["build"]["runId"] == os.environ.get("SUBS_BOT_PROVIDER_CI_RUN_ID"))
    return target


def store(token_name, operation_id):
    target = control.github._parse_object(os.environ.get("SUBS_BOT_PROVIDER_ARCHIVE_TARGET_JSON", ""), sealed.ERROR)
    return Store(target, os.environ.get(token_name, ""), operation_id)


def ledger():
    value = control.github._parse_object(os.environ.get("SUBS_BOT_PROVIDER_ISOLATED_SOURCE_LEDGER_JSON", ""), sealed.ERROR)
    control.require(len(value) <= MAX_HISTORY)
    for operation_id, row in value.items():
        standard = {"intentSha256", "manifestSha256", "runId", "controllerRevision", "targetSha256",
                    "readbackRunId", "readbackRunAttempt", "readbackControllerRevision", "readbackSha256"}
        extra = {"candidateRevision", "reviewedPr", "workflowPath", "readbackWorkflowPath"}
        control.require(control.match(control.provider.DECIMAL, operation_id) and isinstance(row, dict)
                        and set(row) in (standard, standard | extra)
                        and all(control.match(control.provider.HEX, row[k]) for k in ("intentSha256", "manifestSha256", "targetSha256", "readbackSha256"))
                        and all(control.match(control.provider.DECIMAL, row[k]) for k in ("runId", "readbackRunId", "readbackRunAttempt"))
                        and all(control.match(control.provider.REVISION, row[k]) for k in ("controllerRevision", "readbackControllerRevision"))
                        and (set(row) == standard or (control.match(control.provider.REVISION, row["candidateRevision"])
                            and control.match(control.provider.DECIMAL, row["reviewedPr"])
                            and row["workflowPath"] == REVIEWED_SEAL_WORKFLOW and row["readbackWorkflowPath"] == REVIEWED_READBACK_WORKFLOW)))
    return value


def controllers():
    values = json.loads(os.environ.get("SUBS_BOT_PROVIDER_ISOLATED_SOURCE_CONTROLLERS_JSON", ""),
                        object_pairs_hook=control.github._unique_json_object)
    control.require(isinstance(values, list) and 0 < len(values) <= 16 and len(set(values)) == len(values)
                    and all(control.match(control.provider.REVISION, item) for item in values)
                    and os.environ.get("GITHUB_SHA") in values)
    return values


def plan(target, bucket, operation_id, inventory, allowed):
    control.require(control.match(control.provider.DECIMAL, operation_id))
    return {"version": 1, "action": "seal-isolated-provider-source", "operationId": operation_id,
            "controllerRevision": os.environ["GITHUB_SHA"], "targetSha256": control.digest(target),
            "build": target["build"], "bucketSha256": control.digest(bucket), "prefixState": "intent-and-manifest-absent",
            "inventorySha256": control.digest(inventory), "controllersSha256": control.digest(allowed), **reviewed_identity(SEAL_WORKFLOW)}


def manifest(reader, expected):
    reader.verify()
    raw = reader.read("source-manifest.json")
    control.require(isinstance(raw, bytes) and len(raw) <= 65536 and sha256(raw).hexdigest() == expected)
    result = control.github._parse_object(raw, sealed.ERROR)
    standard = {"version", "kind", "runId", "runAttempt", "controllerRevision", "target", "files"}
    extra = {"candidateRevision", "reviewedPr", "workflowPath"}
    control.require(set(result) in (standard, standard | extra)
                    and type(result["version"]) is int and result["version"] == 1 and result["kind"] == "subs-bot-isolated-provider-source"
                    and result["runId"] == reader.run_id and result["runAttempt"] == "1"
                    and control.match(control.provider.REVISION, result["controllerRevision"])
                    and (set(result) == standard or (control.match(control.provider.REVISION, result["candidateRevision"])
                        and control.match(control.provider.DECIMAL, result["reviewedPr"]) and result["workflowPath"] == REVIEWED_SEAL_WORKFLOW))
                    and isinstance(result["files"], dict) and set(result["files"]) == {"provider-source-archive.zip"})
    target = control.validate_config(result["target"])
    control.require(target["environment"] == "rehearsal" and target["caller"] is None)
    entry = result["files"]["provider-source-archive.zip"]
    control.require(isinstance(entry, dict) and set(entry) == {"bytes", "sha256", "chunks"}
                    and type(entry["bytes"]) is int and 0 < entry["bytes"] <= control.provenance.MAX_ZIP
                    and entry["sha256"] == target["build"]["archiveSha256"]
                    and isinstance(entry["chunks"], list) and 0 < len(entry["chunks"]) <= sealed.MAX_CHUNKS)
    for chunk in entry["chunks"]:
        control.require(isinstance(chunk, dict) and set(chunk) == {"bytes", "sha256"}
                        and type(chunk["bytes"]) is int and 0 < chunk["bytes"] <= sealed.CHUNK_BYTES
                        and control.match(control.provider.HEX, chunk["sha256"]))
    return result, target


def inventory(reader):
    grouped = {}
    for key in durable.list_private_keys(reader, BASE):
        match = re.fullmatch(re.escape(BASE) + r"([1-9][0-9]*)/1/(source-intent\.json|source-manifest\.json|blobs/[0-9a-f]{64})", key)
        control.require(match is not None)
        grouped.setdefault(match.group(1), set())
        control.require(match.group(2) not in grouped[match.group(1)])
        grouped[match.group(1)].add(match.group(2))
    control.require(len(grouped) <= MAX_HISTORY)
    completed = {}
    for operation_id, keys in grouped.items():
        control.require({"source-intent.json", "source-manifest.json"} <= keys,
                        "An isolated source seal is incomplete or its result is unknown.")
        prior = Store(reader.target, reader.token, operation_id)
        intent_raw, manifest_raw = prior.read("source-intent.json"), prior.read("source-manifest.json")
        control.require(isinstance(intent_raw, bytes) and isinstance(manifest_raw, bytes))
        intent = control.github._parse_object(intent_raw, sealed.ERROR)
        manifest_sha = sha256(manifest_raw).hexdigest()
        value, target = manifest(prior, manifest_sha)
        details = intent.get("plan")
        fixed = plan(target, reader.target, operation_id, {}, [])
        for key in ("workflowPath", "candidateRevision", "reviewedPr"):
            fixed.pop(key, None)
            if key in value:
                fixed[key] = value[key]
        variable = {"controllerRevision", "inventorySha256", "controllersSha256"}
        control.require(set(intent) == {"version", "plan", "approvalSha256", "controllerRevision", "runId", "runAttempt", "status"}
                        and type(intent["version"]) is int and intent["version"] == 1
                        and isinstance(details, dict) and set(details) == set(fixed)
                        and {k: v for k, v in details.items() if k not in variable} == {k: v for k, v in fixed.items() if k not in variable}
                        and all(control.match(control.provider.HEX, details[k]) for k in ("inventorySha256", "controllersSha256"))
                        and details["controllerRevision"] == intent["controllerRevision"] == value["controllerRevision"]
                        and intent.get("approvalSha256") == control.digest(details)
                        and intent.get("status") == "started-unknown" and intent.get("runAttempt") == "1"
                        and control.match(control.provider.DECIMAL, intent.get("runId")))
        entry = value["files"]["provider-source-archive.zip"]
        control.require(keys == {"source-intent.json", "source-manifest.json", *("blobs/" + item["sha256"] for item in entry["chunks"])})
        with open(os.devnull, "wb") as output:
            control.require(sealed.read_record(prior, value, "provider-source-archive.zip", output) == target["build"]["archiveSha256"])
        completed[operation_id] = {"intentSha256": sha256(intent_raw).hexdigest(), "manifestSha256": manifest_sha,
                                   "runId": intent["runId"], "controllerRevision": value["controllerRevision"],
                                   **{key: value[key] for key in ("workflowPath", "candidateRevision", "reviewedPr") if key in value}}
    return completed


def history(operation_id, completed, allowed):
    import provider_digest_journal as digest_journal
    token, current = control.github._github_token(), os.environ["GITHUB_RUN_ID"]
    rows = []
    for path in (SEAL_WORKFLOW, REVIEWED_SEAL_WORKFLOW):
        if not digest_journal.workflow_has_main_history(path, os.environ["GITHUB_SHA"], token):
            control.require(not any(record.get("workflowPath", SEAL_WORKFLOW) == path for record in completed.values()))
            continue
        found_rows = []
        for page in range(1, 11):
            value = control.github._get_json(f"/actions/workflows/{path.rsplit('/', 1)[-1]}/runs?per_page=100&page={page}", token)
            batch = value.get("workflow_runs")
            control.require(isinstance(batch, list) and len(batch) <= 100 and type(value.get("total_count")) is int
                            and 0 <= value["total_count"] <= 1000)
            found_rows.extend(batch)
            if len(batch) < 100:
                break
        else:
            raise control.ProviderError("Isolated source seal history is too large to verify safely.")
        control.require(len(found_rows) == value["total_count"])
        rows.extend(found_rows)
    control.require(len({str(row.get("id")) for row in rows if isinstance(row, dict)}) == len(rows))
    seen, found = set(), False
    for row in rows:
        path = row.get("path", "").removesuffix("@refs/heads/main").removesuffix("@main") if isinstance(row, dict) else ""
        control.require(isinstance(row, dict) and row.get("head_sha") in allowed and row.get("head_branch") == "main"
                        and row.get("event") == "workflow_dispatch" and row.get("run_attempt") == 1
                        and path in {SEAL_WORKFLOW, REVIEWED_SEAL_WORKFLOW}
                        and all(isinstance(row.get(k), dict) and row[k].get("id") == control.github.REPOSITORY_ID
                                for k in ("repository", "head_repository")))
        durable.source_ancestor({"revision": row["head_sha"]}, token)
        title = row.get("display_title")
        control.require(isinstance(title, str) and re.fullmatch(r"Isolated Provider source (?:plan|seal) [1-9][0-9]*", title))
        if title.startswith("Isolated Provider source plan "):
            continue
        observed_id = title.removeprefix("Isolated Provider source seal ")
        if str(row.get("id")) == current:
            current_path = reviewed_identity(SEAL_WORKFLOW).get("workflowPath", SEAL_WORKFLOW)
            control.require(not found and path == current_path and observed_id == operation_id and row["head_sha"] == os.environ["GITHUB_SHA"])
            found = True
        else:
            control.require(observed_id != operation_id and observed_id not in seen and observed_id in completed
                            and path == completed[observed_id].get("workflowPath", SEAL_WORKFLOW)
                            and str(row.get("id")) == completed[observed_id]["runId"]
                            and row["head_sha"] == completed[observed_id]["controllerRevision"]
                            and (row.get("status"), row.get("conclusion")) == ("completed", "success"),
                            "An earlier isolated seal is unresolved; preserve it and do not retry.")
            seen.add(observed_id)
    control.require(found and seen == set(completed))


def verify_origin(operation_id, record):
    control.require(record["controllerRevision"] in controllers())
    run = control.github._get_json(f"/actions/runs/{record['runId']}/attempts/1", control.github._github_token())
    path = record.get("workflowPath", SEAL_WORKFLOW)
    control.require(path in {SEAL_WORKFLOW, REVIEWED_SEAL_WORKFLOW})
    control.require(str(run.get("id")) == record["runId"] and run.get("run_attempt") == 1
                    and run.get("path") in (path, path + "@main", path + "@refs/heads/main")
                    and run.get("event") == "workflow_dispatch" and run.get("display_title") == "Isolated Provider source seal " + operation_id
                    and (run.get("status"), run.get("conclusion")) == ("completed", "success")
                    and run.get("head_branch") == "main" and run.get("head_sha") == record["controllerRevision"]
                    and all(isinstance(run.get(key), dict) and run[key].get("id") == control.github.REPOSITORY_ID
                            for key in ("repository", "head_repository")))
    durable.source_ancestor({"revision": record["controllerRevision"]}, control.github._github_token())


def readback_projection(operation_id, source, target_sha, run_id, attempt, revision, readback_path=None):
    return {"version": 1, "kind": "isolated-provider-source-readback", "status": "source-original-verified",
            "rehearsalCompletion": "not-evaluated", "operationId": operation_id, "manifestSha256": source["manifestSha256"],
            "targetSha256": target_sha, "seal": source, "readbackRunId": run_id, "readbackRunAttempt": attempt,
            "readbackControllerRevision": revision,
            **({"readbackWorkflowPath": readback_path} if readback_path is not None else {})}


def verify_registered(reader, completed, registered, *, current=None):
    """Bind every sealed source to its separately registered independent readback."""
    control.require(set(completed) - ({current} if current else set()) == set(registered) - ({current} if current else set()))
    allowed = controllers()
    token = control.github._github_token()
    for operation_id, pin in registered.items():
        control.require(operation_id in completed)
        source = completed[operation_id]
        control.require(all(pin[key] == source[key] for key in ("intentSha256", "manifestSha256", "runId", "controllerRevision"))
                        and all(pin.get(key) == source.get(key) for key in ("workflowPath", "candidateRevision", "reviewedPr"))
                        and pin["controllerRevision"] in allowed and pin["readbackControllerRevision"] in allowed)
        prior = Store(reader.target, reader.token, operation_id)
        _, target = manifest(prior, pin["manifestSha256"])
        control.require(control.digest(target) == pin["targetSha256"])
        report = readback_projection(operation_id, source, pin["targetSha256"], pin["readbackRunId"],
                                     pin["readbackRunAttempt"], pin["readbackControllerRevision"], pin.get("readbackWorkflowPath"))
        control.require(control.digest(report) == pin["readbackSha256"])
        run_id, attempt = pin["readbackRunId"], pin["readbackRunAttempt"]
        path = pin.get("readbackWorkflowPath", READBACK_WORKFLOW)
        control.require(path in {READBACK_WORKFLOW, REVIEWED_READBACK_WORKFLOW})
        run = control.github._get_json(f"/actions/runs/{run_id}/attempts/{attempt}", token)
        expected_title = f"Read isolated source {operation_id} 1 {pin['manifestSha256']} {pin['targetSha256']}"
        control.require(str(run.get("id")) == run_id and str(run.get("run_attempt")) == attempt
                        and run.get("path") in (path, path + "@main", path + "@refs/heads/main")
                        and run.get("display_title") == expected_title and run.get("head_sha") == pin["readbackControllerRevision"]
                        and run.get("head_branch") == "main" and run.get("event") == "workflow_dispatch"
                        and (run.get("status"), run.get("conclusion")) == ("completed", "success")
                        and all(isinstance(run.get(k), dict) and run[k].get("id") == control.github.REPOSITORY_ID
                                for k in ("repository", "head_repository")))
        jobs_result = control.github._get_json(f"/actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100", token)
        jobs = jobs_result.get("jobs")
        control.require(isinstance(jobs, list) and jobs_result.get("total_count") == len(jobs) == 1)
        job = jobs[0]
        control.require(isinstance(job, dict) and job.get("name") == "readback" and str(job.get("run_id")) == run_id
                        and str(job.get("run_attempt")) == attempt and job.get("head_sha") == pin["readbackControllerRevision"]
                        and (job.get("status"), job.get("conclusion")) == ("completed", "success")
                        and isinstance(job.get("steps"), list))
        steps = [step for step in job["steps"] if isinstance(step, dict)
                 and step.get("name") == "Independently verify the pinned original from private R2"]
        control.require(len(steps) == 1 and (steps[0].get("status"), steps[0].get("conclusion")) == ("completed", "success"))
        durable.source_ancestor({"revision": pin["readbackControllerRevision"]}, token)


def verify_original(value, target, reader):
    build = target["build"]
    token = control.github._github_token()
    durable.source_ancestor(build, token)
    control.github.verify_main_run(build["runId"], build["revision"], token,
        workflow_id=control.provenance.WORKFLOW_ID, workflow_path=control.provenance.WORKFLOW_PATH,
        workflow_label="Provider Fetch CI", run_attempt=build["runAttempt"])
    with tempfile.TemporaryDirectory(prefix=".isolated-provider-source-", dir=os.environ["RUNNER_TEMP"]) as temporary:
        root = Path(temporary)
        original, staged = root / "source.zip", root / "verified"
        with control.provenance._write_private(original) as output:
            control.require(sealed.read_record(reader, value, "provider-source-archive.zip", output) == build["archiveSha256"])
        staged.mkdir(mode=0o700)
        control.provenance._unpack(original, staged)
        with control.provenance.source_requirements(build["revision"]) as requirements:
            release = control.provider.verify_release(staged, build["revision"], ref=control.github.MAIN_REF,
                run_id=build["runId"], run_attempt=build["runAttempt"], requirements=requirements)
        control.require(all(release[key] == build[key] for key in control.publication.MANIFEST_FIELDS))
    reader.verify()


def prepare():
    context(SEAL_WORKFLOW, write=True)
    target = target_config()
    durable.source_ancestor(target["build"], control.github._github_token())
    evidence = control.provenance.prepare(provider_revision=target["build"]["revision"], provider_attempt=target["build"]["runAttempt"])
    control.require(evidence == target["build"])
    root = Path(os.environ["RUNNER_TEMP"]) / "isolated-provider-source-input"
    root.mkdir(mode=0o700)
    control.provenance._download_zip(evidence["artifactId"], control.github._github_token(), evidence["archiveSha256"], root / "source.zip")
    with control.provenance._write_private(root / "target.sha256") as output:
        output.write((control.digest(target) + "\n").encode("ascii"))


def seal(write):
    context(SEAL_WORKFLOW, write=True)
    target = target_config()
    bucket = control.github._parse_object(os.environ.get("SUBS_BOT_PROVIDER_ARCHIVE_TARGET_JSON", ""), sealed.ERROR)
    operation_id = os.environ.get("SUBS_BOT_PROVIDER_ISOLATED_SOURCE_OPERATION_ID", "")
    reader = store("SUBS_BOT_CF_PROVIDER_ARCHIVE_WRITE_TOKEN" if write else "SUBS_BOT_CF_PROVIDER_ARCHIVE_READ_TOKEN", operation_id)
    reader.verify()
    completed, allowed = inventory(reader), controllers()
    verify_registered(reader, completed, ledger())
    control.require(reader.read("source-intent.json") is None and reader.read("source-manifest.json") is None)
    approved = plan(target, bucket, operation_id, completed, allowed)
    digest = control.digest(approved)
    if not write:
        print(json.dumps({"status": "plan-only", "approvalSha256": digest, "operationId": operation_id,
                          "targetSha256": approved["targetSha256"], "archiveCount": len(completed)}, sort_keys=True))
        return
    control.require(len(completed) < MAX_HISTORY and os.environ.get("SUBS_BOT_PROVIDER_ISOLATED_SOURCE_APPROVAL") == digest)
    history(operation_id, completed, allowed)
    source = Path(os.environ["RUNNER_TEMP"]) / "isolated-provider-source-input" / "source.zip"
    marker = source.with_name("target.sha256")
    control.require(control.provider.checked_file(marker, 128).read_bytes() == (control.digest(target) + "\n").encode("ascii"))
    control.provider.checked_file(source, control.provenance.MAX_ZIP)
    control.require(control.provider.checksum(source) == target["build"]["archiveSha256"])
    with tempfile.TemporaryDirectory(prefix=".isolated-source-verify-", dir=os.environ["RUNNER_TEMP"]) as temporary:
        staged = Path(temporary) / "verified"
        staged.mkdir(mode=0o700)
        control.provenance._unpack(source, staged)
        with control.provenance.source_requirements(target["build"]["revision"]) as requirements:
            release = control.provider.verify_release(staged, target["build"]["revision"], ref=control.github.MAIN_REF,
                run_id=target["build"]["runId"], run_attempt=target["build"]["runAttempt"], requirements=requirements)
        control.require(all(release[k] == target["build"][k] for k in control.publication.MANIFEST_FIELDS))
    control.github.require_current_main(os.environ["GITHUB_SHA"])
    reader.verify()
    control.require(reader.read("source-intent.json") is None and reader.read("source-manifest.json") is None)
    intent = control.canonical({"version": 1, "plan": approved, "approvalSha256": digest,
                                "controllerRevision": os.environ["GITHUB_SHA"], "runId": os.environ["GITHUB_RUN_ID"],
                                "runAttempt": "1", "status": "started-unknown"})
    reader.put("source-intent.json", intent)
    control.require(reader.read("source-intent.json") == intent)
    chunks, size, hashed = [], 0, sha256()
    with source.open("rb") as file:
        while body := file.read(sealed.CHUNK_BYTES):
            size += len(body)
            control.require(size <= control.provenance.MAX_ZIP and len(chunks) < sealed.MAX_CHUNKS)
            hashed.update(body)
            chunk_sha = sha256(body).hexdigest()
            reader.put("blobs/" + chunk_sha, body)
            chunks.append({"bytes": len(body), "sha256": chunk_sha})
    control.require(size > 0 and hashed.hexdigest() == target["build"]["archiveSha256"])
    value = {"version": 1, "kind": "subs-bot-isolated-provider-source", "runId": operation_id, "runAttempt": "1",
             "controllerRevision": os.environ["GITHUB_SHA"], "target": target,
             "files": {"provider-source-archive.zip": {"bytes": size, "sha256": hashed.hexdigest(), "chunks": chunks}},
             **reviewed_identity(SEAL_WORKFLOW)}
    raw = control.canonical(value)
    control.require(len(raw) <= 65536)
    reader.put("source-manifest.json", raw)
    manifest_sha = sha256(raw).hexdigest()
    recorded, _ = manifest(reader, manifest_sha)
    with open(os.devnull, "wb") as output:
        control.require(sealed.read_record(reader, recorded, "provider-source-archive.zip", output) == target["build"]["archiveSha256"])
    print(json.dumps({"status": "sealed", "manifestSha256": manifest_sha, "targetSha256": approved["targetSha256"],
                      "operationId": operation_id, "runAttempt": "1", "intentSha256": sha256(intent).hexdigest()}, sort_keys=True))


def readback():
    context(READBACK_WORKFLOW)
    operation_id = os.environ.get("SUBS_BOT_PROVIDER_ARCHIVE_RUN_ID", "")
    control.require(os.environ.get("SUBS_BOT_PROVIDER_ARCHIVE_RUN_ATTEMPT") == "1")
    expected = os.environ.get("SUBS_BOT_PROVIDER_ARCHIVE_MANIFEST_SHA256", "")
    target_sha = os.environ.get("SUBS_BOT_PROVIDER_ARCHIVE_TARGET_SHA256", "")
    control.require(control.match(control.provider.HEX, expected) and control.match(control.provider.HEX, target_sha))
    reader = store("SUBS_BOT_CF_PROVIDER_ARCHIVE_READ_TOKEN", operation_id)
    complete, registered = inventory(reader), ledger()
    verify_registered(reader, complete, registered, current=operation_id)
    control.require(operation_id in complete and complete[operation_id]["manifestSha256"] == expected)
    identity = reviewed_identity(READBACK_WORKFLOW)
    source = complete[operation_id]
    if identity:
        control.require(source.get("workflowPath") == REVIEWED_SEAL_WORKFLOW
                        and identity["candidateRevision"] == source.get("candidateRevision")
                        and identity["reviewedPr"] == source.get("reviewedPr"))
    else:
        control.require("workflowPath" not in source)
    verify_origin(operation_id, complete[operation_id])
    value, target = manifest(reader, expected)
    control.require(control.digest(target) == target_sha)
    verify_original(value, target, reader)
    control.github.require_current_main(os.environ["GITHUB_SHA"])
    readback_run, attempt, revision = os.environ["GITHUB_RUN_ID"], os.environ["GITHUB_RUN_ATTEMPT"], os.environ["GITHUB_SHA"]
    control.require(control.match(control.provider.DECIMAL, readback_run) and control.match(control.provider.DECIMAL, attempt)
                    and control.match(control.provider.REVISION, revision))
    projection = readback_projection(operation_id, complete[operation_id], target_sha, readback_run, attempt, revision,
                                     identity.get("workflowPath"))
    pin = {**complete[operation_id], "targetSha256": target_sha, "readbackRunId": readback_run,
           "readbackRunAttempt": attempt, "readbackControllerRevision": revision, "readbackSha256": control.digest(projection),
           **({"readbackWorkflowPath": identity["workflowPath"]} if identity else {})}
    print(json.dumps({**projection, "ledgerRecord": pin}, sort_keys=True))


if __name__ == "__main__":
    try:
        action = os.environ.get("SUBS_BOT_PROVIDER_ISOLATED_SOURCE_ACTION", "")
        {"prepare": prepare, "plan": lambda: seal(False), "seal": lambda: seal(True), "readback": readback}[action]()
    except Exception:
        raise SystemExit("Isolated Provider source stopped; preserve every intent and do not retry an unknown write.") from None
