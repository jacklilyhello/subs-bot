"""Read-only state comparison for an interrupted isolated Provider operation.

The caller must independently authenticate the original intent and response-only
R2 evidence. This helper never dispatches or retries a Provider write.
"""
from copy import deepcopy
from hashlib import sha256
import json
import os
import re
import tempfile
from pathlib import Path

import production_provider as control
import production_provider_rehearsal as rehearsal
import provider_private_mutation as mutation
import provider_private_mutation_journal as journal
import provider_digest_journal as digest_journal
import provider_durable_source as durable
import provider_source_transfer as transfer


class ReadOnlyAPI(control.ProviderAPI):
    def _request(self, path, *, container=False, method="GET", body=None, absent=None, limit=control.publication.HTTP_LIMIT):
        control.require(method == "GET" and body is None)
        return super()._request(path, container=container, method=method, body=body, absent=absent, limit=limit)

    def upload(self, _module):
        raise control.ProviderError("Reconciliation cannot issue Provider writes.")


def validate_pin(pin):
    keys = {"version", "originalRunId", "intentSha256", "observationSha256", "observationPlaintextSha256",
            "targetSha256", "originalControllerRevision", "originalCandidateRevision", "reviewedPr", "operation", "readbackJobId"}
    control.require(isinstance(pin, dict) and set(pin) == keys and type(pin["version"]) is int and pin["version"] == 1
                    and all(control.match(control.provider.DECIMAL, pin[k]) for k in ("originalRunId", "readbackJobId"))
                    and all(control.match(control.provider.REVISION, pin[k]) for k in ("originalControllerRevision", "originalCandidateRevision"))
                    and transfer.valid_review_identity(pin["reviewedPr"], pin["originalCandidateRevision"], pin["originalControllerRevision"])
                    and all(control.match(control.provider.HEX, pin[k]) for k in
                            ("intentSha256", "observationSha256", "observationPlaintextSha256", "targetSha256"))
                    and pin["operation"] in {"stage", "activate"})
    return pin


def protected_pin():
    raw = os.environ.get("SUBS_BOT_PROVIDER_RECONCILE_INPUT_JSON", "")
    pin = control.github._parse_object(raw, control.ERROR)
    trusted = control.github._parse_object(os.environ.get("SUBS_BOT_PROVIDER_RECONCILE_TRUSTED_PIN_JSON", ""), control.ERROR)
    control.require(pin == trusted)
    return validate_pin(pin)


def original_history(reader, original_id, registered, allowed):
    """Require every earlier mutation to be registered or this exact failed run."""
    token, resolved, recovered = control.github._github_token(), journal.resolutions(), journal.reconciled()
    control.require(not (set(registered) & set(resolved) or set(registered) & set(recovered) or set(resolved) & set(recovered))
                    and original_id not in registered and original_id not in resolved and original_id not in recovered)
    rows = []
    for page in range(1, 11):
        response = control.github._get_json(f"/actions/workflows/{journal.WORKFLOW.rsplit('/', 1)[-1]}/runs?per_page=100&page={page}", token)
        batch = response.get("workflow_runs")
        control.require(isinstance(batch, list) and len(batch) <= 100 and type(response.get("total_count")) is int
                        and 0 <= response["total_count"] <= 1000)
        rows.extend(batch)
        if len(batch) < 100:
            break
    else:
        raise control.ProviderError("Provider mutation history exceeds its safe bound.")
    control.require(len(rows) == response["total_count"] and len({str(row.get("id")) for row in rows if isinstance(row, dict)}) == len(rows))
    found, seen, skipped, recovered_seen = False, set(), set(), set()
    for row in rows:
        control.require(isinstance(row, dict) and row.get("path") in (journal.WORKFLOW, journal.WORKFLOW + "@main", journal.WORKFLOW + "@refs/heads/main")
                        and row.get("head_sha") in allowed and row.get("head_branch") == "main" and row.get("event") == "workflow_dispatch"
                        and row.get("run_attempt") == 1 and row.get("status") == "completed"
                        and all(isinstance(row.get(k), dict) and row[k].get("id") == control.github.REPOSITORY_ID
                                for k in ("repository", "head_repository")))
        durable.source_ancestor({"revision": row["head_sha"]}, token)
        run_id = str(row.get("id"))
        if run_id == original_id:
            control.require(not found and row.get("conclusion") in {"failure", "cancelled", "timed_out"})
            found = True
        elif run_id in resolved:
            journal.verify_resolution(reader, run_id, resolved[run_id], allowed)
            skipped.add(run_id)
        elif run_id in recovered:
            control.require(row.get("head_sha") == recovered[run_id]["pin"]["originalControllerRevision"]
                            and row.get("conclusion") in {"failure", "cancelled", "timed_out"})
            recovered_seen.add(run_id)
        else:
            control.require(run_id in registered and row.get("head_sha") == registered[run_id]["controllerRevision"]
                            and row.get("conclusion") == "success")
            seen.add(run_id)
    control.require(found and seen == set(registered) and skipped == set(resolved) and recovered_seen == set(recovered))


def original_evidence(target, pin, *, expected_resolution_id=None):
    run_id, token = pin["originalRunId"], control.github._github_token()
    candidate = os.environ.get("PROVIDER_HEAD_REVIEWED_SHA", "")
    control.require(control.match(control.provider.REVISION, candidate))
    if candidate != pin["originalCandidateRevision"]:
        comparison = control.github.compare_commits_metadata(pin["originalCandidateRevision"], candidate, token)
        control.require(comparison.get("status") == "ahead" and type(comparison.get("ahead_by")) is int
                        and comparison["ahead_by"] > 0 and type(comparison.get("behind_by")) is int and comparison["behind_by"] == 0
                        and all(isinstance(comparison.get(key), dict) and comparison[key].get("sha") == pin["originalCandidateRevision"]
                                for key in ("base_commit", "merge_base_commit")))
    reader = journal.store(run_id)
    reader.verify()
    grouped = journal.inventory(reader, current=run_id)
    keys = grouped.get(run_id)
    resolution_keys = {key for key in keys if key.startswith("resolution-")} if isinstance(keys, set) else set()
    expected_keys = set() if expected_resolution_id is None else {"resolution-" + expected_resolution_id + ".json"}
    control.require(isinstance(keys, set) and {"intent.json", "failure-observation.age", "failure-observation.json"} <= keys
                    and resolution_keys == expected_keys,
                    "An existing reconciliation must be independently reviewed; do not write another resolution.")
    original_history(reader, run_id, journal.ledger(), journal.controllers())
    current = control.github._get_json(f"/actions/runs/{run_id}", token)
    run = control.github._get_json(f"/actions/runs/{run_id}/attempts/1", token)
    control.require(str(current.get("id")) == run_id and current.get("run_attempt") == 1 and str(run.get("id")) == run_id
                    and run.get("run_attempt") == 1 and run.get("head_sha") == pin["originalControllerRevision"]
                    and run.get("path") in (journal.WORKFLOW, journal.WORKFLOW + "@main", journal.WORKFLOW + "@refs/heads/main")
                    and (run.get("status"), run.get("conclusion")) in {("completed", "failure"), ("completed", "cancelled"), ("completed", "timed_out")})
    digest_journal.workflow_job(run_id, pin["originalControllerRevision"], journal.JOBS["failure-readback"], job_id=pin["readbackJobId"])
    jobs_result = control.github._get_json(f"/actions/runs/{run_id}/attempts/1/jobs?per_page=100", token)
    jobs = jobs_result.get("jobs")
    control.require(isinstance(jobs, list) and jobs_result.get("total_count") == len(jobs) < 100)
    selected = [job for job in jobs if isinstance(job, dict) and str(job.get("id")) == pin["readbackJobId"]]
    control.require(len(selected) == 1 and isinstance(selected[0].get("steps"), list))
    steps = [step for step in selected[0]["steps"] if isinstance(step, dict) and step.get("name") == "Independently read encrypted failure evidence"]
    control.require(len(steps) == 1 and (steps[0].get("status"), steps[0].get("conclusion")) == ("completed", "success"))
    raw_intent, cipher, raw_observation = (reader.read(name) for name in ("intent.json", "failure-observation.age", "failure-observation.json"))
    control.require(all(isinstance(raw, bytes) and sha256(raw).hexdigest() == pin[key] for raw, key in
                        ((raw_intent, "intentSha256"), (cipher, "observationSha256"), (raw_observation, "observationPlaintextSha256"))))
    intent, original = (control.github._parse_object(raw, control.ERROR) for raw in (raw_intent, raw_observation))
    control.require(raw_intent == control.canonical(intent) and raw_observation == control.canonical(original)
                    and intent.get("runId") == run_id and intent.get("runAttempt") == "1"
                    and intent.get("controllerRevision") == pin["originalControllerRevision"]
                    and intent.get("candidateRevision") == pin["originalCandidateRevision"] and intent.get("reviewedPr") == pin["reviewedPr"]
                    and intent.get("workflowPath") == journal.WORKFLOW and intent.get("operation") == pin["operation"]
                    and intent.get("targetSha256") == pin["targetSha256"] == control.digest(target)
                    and set(original) == {"version", "kind", "runId", "operation", "controllerRevision", "candidateRevision", "reviewedPr",
                                          "targetSha256", "intentSha256", "observationCipherSha256", "confirmedCipherSha256", "resultSha256", "observation"}
                    and type(original["version"]) is int and original["version"] == 1
                    and original.get("kind") == "isolated-provider-response-only" and original.get("runId") == run_id
                    and original.get("controllerRevision") == pin["originalControllerRevision"]
                    and original.get("candidateRevision") == pin["originalCandidateRevision"]
                    and original.get("reviewedPr") == pin["reviewedPr"] and original.get("operation") == pin["operation"]
                    and original.get("targetSha256") == pin["targetSha256"]
                    and original.get("observationCipherSha256") == pin["observationSha256"]
                    and original.get("intentSha256") == pin["intentSha256"])
    if original["confirmedCipherSha256"] is not None:
        confirmed = reader.read("failure-confirmed.age")
        control.require(isinstance(confirmed, bytes) and sha256(confirmed).hexdigest() == original["confirmedCipherSha256"]
                        and control.match(control.provider.HEX, original["resultSha256"]))
    else:
        control.require(original["resultSha256"] is None and "failure-confirmed.age" not in keys)
    mutation.checked_observation(target, pin["operation"], original.get("observation"))
    return intent, original


def confirmed_candidate(target, intent, original, worker_token, container_token):
    target = control.validate_config(target)
    operation = intent.get("operation")
    control.require(operation in {"stage", "activate"} and target["environment"] == "rehearsal" and target["caller"] is None
                    and target.get("previous") is not None and intent.get("status") == "started-unknown"
                    and intent.get("targetSha256") == control.digest(target)
                    and original.get("intentSha256") == control.digest(intent)
                    and original.get("targetSha256") == control.digest(target) and original.get("operation") == operation)
    observation = mutation.checked_observation(target, operation, original.get("observation"))
    previous = target["previous"]
    if operation == "stage":
        control.require(target["versionId"] is None and target["activation"] is None)
        candidate = deepcopy(target)
        candidate["versionId"] = observation["identities"]["versionId"]
        candidate = control.validate_config(candidate)
        api = ReadOnlyAPI(candidate, worker_token, container_token)
        deployments = mutation.deployment_history(api)
        control.require(control.digest(deployments) == intent["prestate"]["deploymentHistorySha256"])
        state = control.observe(api)
        control.unbound_upgrade(api, state)
    else:
        control.require(target["versionId"] is not None and target["activation"] is None
                        and control.match(control.stage.VERSION_ID, observation["identities"].get("id")))
        api = ReadOnlyAPI(target, worker_token, container_token)
        deployments = mutation.deployment_history(api)
        matches = [row for row in deployments if row["id"] == observation["identities"]["id"]]
        control.require(len(matches) == 1 and deployments[0] == matches[0]
                        and control.digest([row for row in deployments if row["id"] != observation["identities"]["id"]])
                            == intent["prestate"]["deploymentHistorySha256"])
        state = control.observe(api)
        control.require(isinstance(state["activation"], dict) and state["activation"]["deploymentId"] == observation["identities"]["id"]
                        and state["container"] == previous["container"] and state["instance"] is None and isinstance(state["workflow"], dict)
                        and state["workflow"]["workflowId"] == previous["workflow"]["workflowId"]
                        and state["workflow"]["createdOn"] == previous["workflow"]["createdOn"])
        old_instance = api.smoke_instance({**previous["build"], "versionId": previous["versionId"]}, previous["workflow"])
        control.verify_previous_terminal(api, previous, old_instance)
        candidate = rehearsal.confirmed_target(target, "activate", state)
    control.require(control.caller_state(api, target, allow_unbound=True) == "unbound"
                    and control.observe(api) == state and mutation.deployment_history(api) == deployments
                    and control.caller_state(api, target, allow_unbound=True) == "unbound")
    if operation == "stage":
        control.unbound_upgrade(api, state)
    else:
        old_instance = api.smoke_instance({**previous["build"], "versionId": previous["versionId"]}, previous["workflow"])
        control.verify_previous_terminal(api, previous, old_instance)
    return candidate, {"status": "observed-by-read-only-reconciliation", "operation": operation,
                       "originalRunId": intent["runId"], "originalRunAttempt": intent["runAttempt"],
                       "intentSha256": control.digest(intent), "responseOriginalSha256": control.digest(original),
                       "targetSha256": control.digest(target), "nextTargetSha256": control.digest(candidate),
                       "stateSha256": control.digest(state), "deploymentHistorySha256": control.digest(deployments),
                       "callerState": "unbound", "originalRunConclusion": "not-success"}


def inspect():
    transfer.context()
    control.require(transfer.workflow_path() == transfer.REVIEWED_RECOVERY_WORKFLOW_PATH)
    target, refs, pin = transfer.target(), transfer.refs(), protected_pin()
    control.require(pin["targetSha256"] == control.digest(target))
    durable.restore()
    control.guard_sources(target)
    control.prepare_durable(target["build"])
    with tempfile.TemporaryDirectory(prefix=".provider-reconcile-chain-", dir=os.environ["RUNNER_TEMP"]) as directory:
        control.verify_previous_archives(target, Path(directory))
    intent, original = original_evidence(target, pin)
    next_target, observation = confirmed_candidate(target, intent, original,
        os.environ.get("SUBS_BOT_CF_PROVIDER_WORKER_READ_TOKEN", ""), os.environ.get("SUBS_BOT_CF_PROVIDER_CONTAINER_READ_TOKEN", ""))
    control.require(original_evidence(target, pin) == (intent, original))
    control.guard_sources(target)
    identity = transfer.execution_identity(os.environ["GITHUB_SHA"])
    plan = {"version": 1, "kind": "isolated-provider-reconciliation-plan", "pinSha256": control.digest(pin),
            "controllerRevision": os.environ["GITHUB_SHA"], "candidateRevision": identity["candidateRevision"],
            "reviewedPr": identity["reviewedPr"], "archiveRefsSha256": control.digest(refs), "observation": observation}
    approval = control.digest(plan)
    action = os.environ.get("SUBS_BOT_PROVIDER_RECONCILE_ACTION", "")
    control.require(action in {"plan", "commit"})
    if action == "commit":
        control.require(os.environ.get("SUBS_BOT_PROVIDER_RECONCILE_APPROVAL") == approval
                        and os.environ.get("SUBS_BOT_PROVIDER_RECONCILE_TRUSTED_APPROVAL") == approval)
        payloads = journal.seal_next_target(next_target)
        journal.digest_journal.output("archive_payload_sha256", payloads["archive"])
        journal.digest_journal.output("live_payload_sha256", payloads["live"])
        journal.digest_journal.output("next_digest_approval_sha256", control.digest({"operation": "publish-digest", "target": next_target}))
        journal.digest_journal.output("next_witness_approval_sha256", control.digest({"operation": "publish", "target": next_target}))
        for op in sorted(mutation.OPERATIONS):
            journal.digest_journal.output("next_" + op.replace("-", "_") + "_approval_sha256",
                                          control.digest({"operation": op, "target": next_target}))
    journal.digest_journal.output("plan_json", plan)
    journal.digest_journal.output("approval_sha256", approval)
    print(json.dumps({"status": "read-only-plan", "approvalSha256": approval, "plan": plan,
                      "originalRunConclusion": "not-success", "providerMutation": False}, sort_keys=True))


def approved_plan():
    transfer.context()
    control.require(transfer.workflow_path() == transfer.REVIEWED_RECOVERY_WORKFLOW_PATH)
    target, refs, pin = transfer.target(), transfer.refs(), protected_pin()
    plan = control.github._parse_object(os.environ.get("SUBS_BOT_PROVIDER_RECONCILE_PLAN_JSON", ""), control.ERROR)
    identity = transfer.execution_identity(os.environ["GITHUB_SHA"])
    approval = control.digest(plan)
    control.require(set(plan) == {"version", "kind", "pinSha256", "controllerRevision", "candidateRevision", "reviewedPr", "archiveRefsSha256", "observation"}
                    and type(plan["version"]) is int and plan["version"] == 1 and plan["kind"] == "isolated-provider-reconciliation-plan"
                    and plan["pinSha256"] == control.digest(pin) and plan["controllerRevision"] == os.environ["GITHUB_SHA"]
                    and plan["candidateRevision"] == identity["candidateRevision"] and plan["reviewedPr"] == identity["reviewedPr"]
                    and plan["archiveRefsSha256"] == control.digest(refs) and pin["targetSha256"] == control.digest(target)
                    and os.environ.get("SUBS_BOT_PROVIDER_RECONCILE_APPROVAL") == approval
                    and os.environ.get("SUBS_BOT_PROVIDER_RECONCILE_TRUSTED_APPROVAL") == approval)
    observed = plan["observation"]
    fields = {"status", "operation", "originalRunId", "originalRunAttempt", "intentSha256", "responseOriginalSha256",
              "targetSha256", "nextTargetSha256", "stateSha256", "deploymentHistorySha256", "callerState", "originalRunConclusion"}
    control.require(isinstance(observed, dict) and set(observed) == fields and observed["status"] == "observed-by-read-only-reconciliation"
                    and observed["operation"] == pin["operation"] and observed["originalRunId"] == pin["originalRunId"]
                    and observed["originalRunAttempt"] == "1" and observed["intentSha256"] == pin["intentSha256"]
                    and observed["responseOriginalSha256"] == pin["observationPlaintextSha256"]
                    and observed["targetSha256"] == pin["targetSha256"] and observed["callerState"] == "unbound"
                    and observed["originalRunConclusion"] == "not-success"
                    and all(control.match(control.provider.HEX, observed[k]) for k in ("nextTargetSha256", "stateSha256", "deploymentHistorySha256")))
    return target, pin, plan, approval


def receipt(plan, approval, pin):
    archive_sha = os.environ.get("SUBS_BOT_PROVIDER_RECONCILE_ARCHIVE_PAYLOAD_SHA256", "")
    live_sha = os.environ.get("SUBS_BOT_PROVIDER_RECONCILE_LIVE_PAYLOAD_SHA256", "")
    control.require(control.match(control.provider.HEX, archive_sha) and control.match(control.provider.HEX, live_sha))
    return {"version": 1, "kind": "isolated-provider-reconciliation-resolution", "plan": plan, "pin": pin, "approvalSha256": approval,
            "runId": os.environ["GITHUB_RUN_ID"], "runAttempt": "1", "controllerRevision": plan["controllerRevision"],
            "candidateRevision": plan["candidateRevision"], "reviewedPr": plan["reviewedPr"],
            "archivePayloadSha256": archive_sha, "livePayloadSha256": live_sha,
            "status": "independent-observation-not-original-success"}


def write_resolution():
    target, pin, plan, approval = approved_plan()
    run_id, revision = os.environ["GITHUB_RUN_ID"], os.environ["GITHUB_SHA"]
    digest_journal.workflow_job(run_id, revision, "Provider interrupted write independent inspection")
    original_evidence(target, pin)
    reader = journal.store(pin["originalRunId"])
    reader.verify()
    raw = control.canonical(receipt(plan, approval, pin))
    control.github.require_current_main(revision)
    reader.put_once("resolution-" + run_id + ".json", raw)
    digest_journal.output("resolution_sha256", sha256(raw).hexdigest())


def resolution_projection(pin, raw_sha, run_id, revision, candidate, reviewed_pr, readback_job_id):
    return {"version": 1, "kind": "isolated-provider-reconciliation-readback", "originalRunId": pin["originalRunId"],
            "intentSha256": pin["intentSha256"], "resolutionSha256": raw_sha, "reconcileRunId": run_id,
            "controllerRevision": revision, "candidateRevision": candidate, "reviewedPr": reviewed_pr,
            "readbackJobId": readback_job_id, "originalRunConclusion": "not-success"}


def verify_reconciled(reader, original_id, record, allowed):
    """Recheck immutable resolution, original failure evidence, and independent run."""
    fields = {"pin", "resolutionSha256", "reconcileRunId", "controllerRevision", "candidateRevision", "reviewedPr",
              "readbackJobId", "readbackSha256", "nextTargetSha256"}
    control.require(isinstance(record, dict) and set(record) == fields)
    pin = validate_pin(record["pin"])
    control.require(pin["originalRunId"] == original_id and record["controllerRevision"] in allowed
                    and pin["originalControllerRevision"] in allowed
                    and all(control.match(control.provider.DECIMAL, record[k]) for k in ("reconcileRunId", "readbackJobId"))
                    and transfer.valid_review_identity(record["reviewedPr"], record["candidateRevision"], record["controllerRevision"])
                    and all(control.match(control.provider.HEX, record[k]) for k in ("resolutionSha256", "readbackSha256", "nextTargetSha256")))
    prior = journal.Store(reader.target, original_id)
    intent_raw, obs_cipher, obs_raw, raw = (prior.read(name) for name in
        ("intent.json", "failure-observation.age", "failure-observation.json", "resolution-" + record["reconcileRunId"] + ".json"))
    control.require(all(isinstance(value, bytes) and sha256(value).hexdigest() == expected for value, expected in
                        ((intent_raw, pin["intentSha256"]), (obs_cipher, pin["observationSha256"]),
                         (obs_raw, pin["observationPlaintextSha256"]), (raw, record["resolutionSha256"]))))
    intent, original, resolved = (control.github._parse_object(value, control.ERROR) for value in (intent_raw, obs_raw, raw))
    control.require(all(raw_value == control.canonical(value) for raw_value, value in ((intent_raw, intent), (obs_raw, original), (raw, resolved)))
                    and set(resolved) == {"version", "kind", "plan", "pin", "approvalSha256", "runId", "runAttempt", "controllerRevision",
                                          "candidateRevision", "reviewedPr", "archivePayloadSha256", "livePayloadSha256", "status"}
                    and type(resolved["version"]) is int and resolved["version"] == 1
                    and resolved["kind"] == "isolated-provider-reconciliation-resolution"
                    and resolved["status"] == "independent-observation-not-original-success" and resolved["runAttempt"] == "1"
                    and resolved["runId"] == record["reconcileRunId"]
                    and all(resolved[key] == record[key] for key in ("controllerRevision", "candidateRevision", "reviewedPr"))
                    and all(control.match(control.provider.HEX, resolved[k]) for k in ("archivePayloadSha256", "livePayloadSha256"))
                    and isinstance(resolved["plan"], dict)
                    and set(resolved["plan"]) == {"version", "kind", "pinSha256", "controllerRevision", "candidateRevision", "reviewedPr", "archiveRefsSha256", "observation"}
                    and type(resolved["plan"].get("version")) is int and resolved["plan"]["version"] == 1
                    and resolved["plan"].get("kind") == "isolated-provider-reconciliation-plan"
                    and resolved.get("pin") == pin and resolved["plan"].get("pinSha256") == control.digest(pin)
                    and all(resolved["plan"].get(key) == record[key] for key in ("controllerRevision", "candidateRevision", "reviewedPr"))
                    and control.match(control.provider.HEX, resolved["plan"].get("archiveRefsSha256"))
                    and resolved["approvalSha256"] == control.digest(resolved["plan"])
                    and resolved["plan"].get("observation", {}).get("nextTargetSha256") == record["nextTargetSha256"]
                    and resolved["plan"].get("observation", {}).get("originalRunConclusion") == "not-success"
                    and resolved["plan"].get("observation", {}).get("intentSha256") == pin["intentSha256"]
                    and resolved["plan"].get("observation", {}).get("responseOriginalSha256") == pin["observationPlaintextSha256"]
                    and set(resolved["plan"].get("observation", {})) == {"status", "operation", "originalRunId", "originalRunAttempt", "intentSha256",
                         "responseOriginalSha256", "targetSha256", "nextTargetSha256", "stateSha256", "deploymentHistorySha256", "callerState", "originalRunConclusion"}
                    and resolved["plan"]["observation"].get("status") == "observed-by-read-only-reconciliation"
                    and resolved["plan"]["observation"].get("operation") == pin["operation"]
                    and resolved["plan"]["observation"].get("originalRunId") == original_id
                    and resolved["plan"]["observation"].get("originalRunAttempt") == "1"
                    and resolved["plan"]["observation"].get("targetSha256") == pin["targetSha256"]
                    and resolved["plan"]["observation"].get("callerState") == "unbound"
                    and all(control.match(control.provider.HEX, resolved["plan"]["observation"].get(key))
                            for key in ("stateSha256", "deploymentHistorySha256"))
                    and intent.get("runId") == original_id and intent.get("runAttempt") == "1"
                    and intent.get("status") == "started-unknown" and intent.get("targetSha256") == pin["targetSha256"]
                    and intent.get("candidateRevision") == pin["originalCandidateRevision"]
                    and intent.get("controllerRevision") == pin["originalControllerRevision"]
                    and original.get("intentSha256") == pin["intentSha256"]
                    and original.get("observationCipherSha256") == pin["observationSha256"])
    token, run_id = control.github._github_token(), record["reconcileRunId"]
    run = control.github._get_json(f"/actions/runs/{run_id}/attempts/1", token)
    current = control.github._get_json(f"/actions/runs/{run_id}", token)
    control.require(str(run.get("id")) == str(current.get("id")) == run_id and current.get("run_attempt") == run.get("run_attempt") == 1
                    and run.get("path") in (transfer.REVIEWED_RECOVERY_WORKFLOW_PATH,
                        transfer.REVIEWED_RECOVERY_WORKFLOW_PATH + "@main", transfer.REVIEWED_RECOVERY_WORKFLOW_PATH + "@refs/heads/main")
                    and run.get("display_title") == "Reconcile isolated Provider " + original_id
                    and run.get("head_sha") == record["controllerRevision"] and run.get("head_branch") == "main"
                    and run.get("event") == "workflow_dispatch" and (run.get("status"), run.get("conclusion")) == ("completed", "success")
                    and all(isinstance(run.get(k), dict) and run[k].get("id") == control.github.REPOSITORY_ID for k in ("repository", "head_repository")))
    durable.source_ancestor({"revision": record["controllerRevision"]}, token)
    failed = control.github._get_json(f"/actions/runs/{original_id}/attempts/1", token)
    failed_latest = control.github._get_json(f"/actions/runs/{original_id}", token)
    control.require(str(failed.get("id")) == str(failed_latest.get("id")) == original_id
                    and failed.get("run_attempt") == failed_latest.get("run_attempt") == 1
                    and failed.get("path") in (journal.WORKFLOW, journal.WORKFLOW + "@main", journal.WORKFLOW + "@refs/heads/main")
                    and failed.get("head_sha") == pin["originalControllerRevision"] and failed.get("head_branch") == "main"
                    and failed.get("event") == "workflow_dispatch" and failed.get("status") == "completed"
                    and failed.get("conclusion") in {"failure", "cancelled", "timed_out"}
                    and all(isinstance(failed.get(k), dict) and failed[k].get("id") == control.github.REPOSITORY_ID for k in ("repository", "head_repository")))
    digest_journal.workflow_job(run_id, record["controllerRevision"], "Provider independent reconciliation readback", job_id=record["readbackJobId"])
    digest_journal.workflow_job(original_id, pin["originalControllerRevision"], journal.JOBS["failure-readback"], job_id=pin["readbackJobId"])
    rows = control.github._get_json(f"/actions/runs/{run_id}/attempts/1/jobs?per_page=100", token)
    jobs = rows.get("jobs")
    control.require(isinstance(jobs, list) and rows.get("total_count") == len(jobs) < 100)
    selected = [job for job in jobs if isinstance(job, dict) and str(job.get("id")) == record["readbackJobId"]]
    control.require(len(selected) == 1 and isinstance(selected[0].get("steps"), list))
    steps = [step for step in selected[0]["steps"] if isinstance(step, dict) and step.get("name") == "Independently read original evidence and resolution"]
    control.require(len(steps) == 1 and (steps[0].get("status"), steps[0].get("conclusion")) == ("completed", "success"))
    projection = resolution_projection(pin, record["resolutionSha256"], run_id, record["controllerRevision"],
                                       record["candidateRevision"], record["reviewedPr"], record["readbackJobId"])
    control.require(control.digest(projection) == record["readbackSha256"])


def readback_resolution():
    target, pin, plan, approval = approved_plan()
    run_id, revision = os.environ["GITHUB_RUN_ID"], os.environ["GITHUB_SHA"]
    for name in ("Provider interrupted write independent inspection", "Provider reconciliation resolution archive"):
        digest_journal.workflow_job(run_id, revision, name)
    original_evidence(target, pin, expected_resolution_id=run_id)
    reader = journal.store(pin["originalRunId"])
    reader.verify()
    raw = reader.read("resolution-" + run_id + ".json")
    expected = os.environ.get("SUBS_BOT_PROVIDER_RECONCILE_RESOLUTION_SHA256", "")
    control.require(isinstance(raw, bytes) and raw == control.canonical(receipt(plan, approval, pin))
                    and control.match(control.provider.HEX, expected) and sha256(raw).hexdigest() == expected)
    job_id = digest_journal.workflow_job(run_id, revision, "Provider independent reconciliation readback", running=True)
    projection = resolution_projection(pin, expected, run_id, revision, plan["candidateRevision"], plan["reviewedPr"], job_id)
    record = {"pin": pin, "resolutionSha256": expected, "reconcileRunId": run_id, "controllerRevision": revision,
              "candidateRevision": plan["candidateRevision"], "reviewedPr": plan["reviewedPr"], "readbackJobId": job_id,
              "readbackSha256": control.digest(projection), "nextTargetSha256": plan["observation"]["nextTargetSha256"]}
    ledger = journal.reconciled()
    control.require(pin["originalRunId"] not in ledger and len(ledger) < journal.MAX_HISTORY)
    ledger[pin["originalRunId"]] = record
    payloads = journal.seal_next_target(ledger)
    digest_journal.output("ledger_sha256", control.digest(ledger))
    digest_journal.output("archive_ledger_payload_sha256", payloads["archive"])
    digest_journal.output("live_ledger_payload_sha256", payloads["live"])
    print(json.dumps({"status": "independent-reconciliation-readback", "ledgerSha256": control.digest(ledger),
                      "archiveLedgerPayloadSha256": payloads["archive"], "liveLedgerPayloadSha256": payloads["live"],
                      "originalRunConclusion": "not-success", "providerMutation": False}, sort_keys=True))


if __name__ == "__main__":
    try:
        {"plan": inspect, "commit": inspect, "write-resolution": write_resolution,
         "readback-resolution": readback_resolution}[os.environ.get("SUBS_BOT_PROVIDER_RECONCILE_ACTION", "")]()
    except Exception:
        raise SystemExit("Provider reconciliation remained unknown; preserve the original intent and do not repeat its write.") from None
