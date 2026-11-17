"""Append-only isolated digest rehearsal journal; no production resource access.

Only fixed hashes and status leave Provider jobs. Each external write is isolated
behind a one-shot, independently read back intent. An unknown attempt blocks all
later attempts until it is reconciled separately; this module never retries it.
"""

from hashlib import sha256
import json
import os
from pathlib import Path
import re

import archive_production_provider as sealed
import production_provider as control
import provider_durable_source as durable
import provider_digest_publish as digest
import provider_source_transfer as transfer

BASE = "maintenance/provider-digest-rehearsal/"
MAX_HISTORY = 32
JOBS = {"preflight": "Provider digest preflight", "intent-readback": "Provider digest intent readback",
        "publish": "Provider digest publish", "verify": "Provider digest independent OCI readback",
        "readback": "Provider digest evidence readback"}


class Store(durable.ProductionStore):
    def __init__(self, target, token, run_id):
        sealed.PrivateProofStore.__init__(self, target, token, run_id, "1")
        self.prefix = f"{BASE}{run_id}/1/"


def store(token_name, run_id=None):
    target = control.github._parse_object(os.environ.get("SUBS_BOT_PROVIDER_ARCHIVE_TARGET_JSON", ""), sealed.ERROR)
    return Store(target, os.environ.get(token_name, ""), run_id or os.environ["GITHUB_RUN_ID"])


def ledger():
    value = control.github._parse_object(os.environ.get("SUBS_BOT_PROVIDER_DIGEST_LEDGER_JSON", ""), sealed.ERROR)
    control.require(len(value) <= MAX_HISTORY)
    for run_id, row in value.items():
        control.require(control.match(control.provider.DECIMAL, run_id) and isinstance(row, dict)
                        and set(row) == {"intentSha256", "completionSha256", "targetSha256", "controllerRevision", "readbackJobId", "readbackSha256"}
                        and all(control.match(control.provider.HEX, row[k]) for k in ("intentSha256", "completionSha256", "targetSha256", "readbackSha256"))
                        and control.match(control.provider.REVISION, row["controllerRevision"])
                        and control.match(control.provider.DECIMAL, row["readbackJobId"]))
    return value


def controllers():
    values = json.loads(os.environ.get("SUBS_BOT_PROVIDER_DIGEST_CONTROLLERS_JSON", ""), object_pairs_hook=control.github._unique_json_object)
    control.require(isinstance(values, list) and 0 < len(values) <= 16 and len(set(values)) == len(values)
                    and all(control.match(control.provider.REVISION, item) for item in values)
                    and os.environ.get("GITHUB_SHA") in values)
    return values


def projection(run_id, source, completion_sha, job_id):
    return {"version": 1, "kind": "isolated-provider-digest-readback", "runId": run_id, "runAttempt": "1",
            "controllerRevision": source["controllerRevision"], "targetSha256": source["targetSha256"],
            "intentSha256": control.digest(source), "completionSha256": completion_sha, "readbackJobId": job_id}


def workflow_job(run_id, revision, name, *, job_id=None, running=False):
    token = control.github._github_token()
    response = control.github._get_json(f"/actions/runs/{run_id}/attempts/1/jobs?per_page=100", token)
    jobs = response.get("jobs")
    control.require(isinstance(jobs, list) and type(response.get("total_count")) is int and response["total_count"] == len(jobs) < 100)
    matches = [job for job in jobs if isinstance(job, dict) and job.get("name") == name]
    control.require(len(matches) == 1)
    job = matches[0]
    control.require(str(job.get("run_id")) == run_id and job.get("run_attempt") == 1 and job.get("head_sha") == revision
                    and control.match(control.provider.DECIMAL, str(job.get("id")))
                    and (job_id is None or str(job["id"]) == job_id))
    if running:
        control.require(job.get("status") in {"queued", "in_progress"} and job.get("conclusion") is None)
    else:
        control.require((job.get("status"), job.get("conclusion")) == ("completed", "success"))
    return str(job["id"])


def inventory(reader, *, current=None):
    grouped = {}
    for key in durable.list_private_keys(reader, BASE):
        match = re.fullmatch(re.escape(BASE) + r"([1-9][0-9]*)/1/(source-intent\.json|source-manifest\.json)", key)
        control.require(match is not None)
        grouped.setdefault(match.group(1), set())
        control.require(match.group(2) not in grouped[match.group(1)])
        grouped[match.group(1)].add(match.group(2))
    registered, allowed = ledger(), controllers()
    control.require(len(grouped) <= MAX_HISTORY
                    and set(grouped) - ({current} if current else set()) == set(registered) - ({current} if current else set()),
                    "An isolated digest publication has an unregistered or unknown outcome.")
    for run_id, pin in registered.items():
        if run_id == current:
            continue
        control.require(grouped[run_id] == {"source-intent.json", "source-manifest.json"} and pin["controllerRevision"] in allowed)
        prior = Store(reader.target, reader.token, run_id)
        raw_intent, raw_done = prior.read("source-intent.json"), prior.read("source-manifest.json")
        control.require(isinstance(raw_intent, bytes) and isinstance(raw_done, bytes)
                        and sha256(raw_intent).hexdigest() == pin["intentSha256"] and sha256(raw_done).hexdigest() == pin["completionSha256"])
        original = control.github._parse_object(raw_intent, sealed.ERROR)
        done = control.github._parse_object(raw_done, sealed.ERROR)
        control.require(raw_intent == control.canonical(original) and raw_done == control.canonical(done)
                        and set(original) == {"version", "kind", "operation", "runId", "runAttempt", "controllerRevision", "targetSha256",
                                              "archiveRefsSha256", "approvalSha256", "simulatedActionsUnavailable", "prestate", "status"}
                        and type(original["version"]) is int and original["version"] == 1 and original["operation"] == "publish-digest"
                        and type(original["simulatedActionsUnavailable"]) is bool
                        and all(control.match(control.provider.HEX, original[k]) for k in ("targetSha256", "archiveRefsSha256", "approvalSha256"))
                        and isinstance(original["prestate"], dict) and set(original["prestate"]) == {"dependencySha256", "manifestSha256"}
                        and control.match(control.provider.HEX, original["prestate"]["dependencySha256"])
                        and original["prestate"]["manifestSha256"] is None
                        and original.get("runId") == run_id and original.get("runAttempt") == "1"
                        and original.get("kind") == "isolated-provider-digest-intent" and original.get("status") == "started-unknown"
                        and original.get("controllerRevision") == pin["controllerRevision"] and original.get("targetSha256") == pin["targetSha256"]
                        and set(done) == {"version", "kind", "runId", "runAttempt", "controllerRevision", "intentSha256", "response", "verification"}
                        and type(done["version"]) is int and done["version"] == 1 and done["runAttempt"] == "1"
                        and done.get("kind") == "isolated-provider-digest-completion" and done.get("intentSha256") == pin["intentSha256"]
                        and done.get("runId") == run_id and done.get("controllerRevision") == pin["controllerRevision"]
                        and isinstance(done["response"], dict) and set(done["response"]) == {"status", "manifestSha256", "configSha256", "prestateSha256", "providerMutation", "registryMutation"}
                        and done["response"]["status"] == "published-digest" and done["response"]["providerMutation"] is False
                        and done["response"]["registryMutation"] is True and done["response"]["prestateSha256"] == control.digest(original["prestate"])
                        and all(control.match(control.provider.HEX, done["response"][k]) for k in ("manifestSha256", "configSha256"))
                        and done["verification"] == {"manifestSha256": done["response"]["manifestSha256"],
                                                     "configSha256": done["response"]["configSha256"],
                                                     "allReferencedBlobsVerified": True,
                                                     "dependencySha256": original["prestate"]["dependencySha256"]})
        control.require(control.digest(projection(run_id, original, pin["completionSha256"], pin["readbackJobId"])) == pin["readbackSha256"])
        workflow_job(run_id, pin["controllerRevision"], JOBS["readback"], job_id=pin["readbackJobId"])
    return grouped


def history(registered):
    token, current, allowed = control.github._github_token(), os.environ["GITHUB_RUN_ID"], controllers()
    rows = []
    for page in range(1, 11):
        response = control.github._get_json(f"/actions/workflows/{transfer.WORKFLOW_PATH.rsplit('/', 1)[-1]}/runs?per_page=100&page={page}", token)
        batch = response.get("workflow_runs")
        control.require(isinstance(batch, list) and len(batch) <= 100 and type(response.get("total_count")) is int
                        and 0 <= response["total_count"] <= 1000)
        rows.extend(batch)
        if len(batch) < 100:
            break
    else:
        raise control.ProviderError("Isolated digest history exceeds its safe bound.")
    control.require(len(rows) == response["total_count"] and len({str(r.get("id")) for r in rows if isinstance(r, dict)}) == len(rows))
    seen, current_seen = set(), False
    for row in rows:
        control.require(isinstance(row, dict) and row.get("path") in (transfer.WORKFLOW_PATH, transfer.WORKFLOW_PATH + "@main", transfer.WORKFLOW_PATH + "@refs/heads/main")
                        and row.get("head_sha") in allowed and row.get("head_branch") == "main" and row.get("event") == "workflow_dispatch"
                        and row.get("run_attempt") == 1 and all(isinstance(row.get(k), dict) and row[k].get("id") == control.github.REPOSITORY_ID
                                                                for k in ("repository", "head_repository")))
        run_id = str(row.get("id"))
        if run_id == current:
            control.require(not current_seen and row.get("head_sha") == os.environ["GITHUB_SHA"])
            current_seen = True
        else:
            control.require(run_id in registered and run_id not in seen and row.get("head_sha") == registered[run_id]["controllerRevision"]
                            and (row.get("status"), row.get("conclusion")) == ("completed", "success"),
                            "An earlier isolated digest attempt is unresolved; do not retry it.")
            seen.add(run_id)
    control.require(current_seen and seen == set(registered))


def parse_intent():
    target, refs = transfer.target(), transfer.refs()
    state = control.github._parse_object(os.environ.get("SUBS_BOT_PROVIDER_DIGEST_PRESTATE_JSON", ""), sealed.ERROR)
    return target, refs, digest.intent(target, refs, state, os.environ["GITHUB_RUN_ID"], os.environ["GITHUB_SHA"])


def output(name, value):
    control.require(re.fullmatch(r"[a-z_]+", name) is not None)
    text = value if isinstance(value, str) else control.canonical(value).decode("ascii")
    control.require("\n" not in text and "\r" not in text and len(text) <= 4096)
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="ascii") as file:
        file.write(name + "=" + text + "\n")


def preflight():
    transfer.context()
    target, refs = transfer.target(), transfer.refs()
    transfer.receive()
    state = digest.observe(target, os.environ.get("SUBS_BOT_CF_PROVIDER_WORKER_READ_TOKEN", ""),
                           os.environ.get("SUBS_BOT_CF_PROVIDER_CONTAINER_READ_TOKEN", ""))
    control.require(state["manifestSha256"] is None,
                    "This isolated write rehearsal requires an independently absent exact digest.")
    digest.intent(target, refs, state, os.environ["GITHUB_RUN_ID"], os.environ["GITHUB_SHA"])
    output("prestate_json", state)


def write_intent():
    transfer.context()
    _target, _refs, value = parse_intent()
    run_id, revision = os.environ["GITHUB_RUN_ID"], os.environ["GITHUB_SHA"]
    workflow_job(run_id, revision, JOBS["preflight"])
    reader = store("SUBS_BOT_CF_PROVIDER_ARCHIVE_WRITE_TOKEN")
    reader.verify()
    grouped = inventory(reader)
    control.require(len(grouped) < MAX_HISTORY and run_id not in grouped)
    history(ledger())
    raw = control.canonical(value)
    control.require(reader.read("source-intent.json") is None and reader.read("source-manifest.json") is None)
    reader.put("source-intent.json", raw)
    control.require(reader.read("source-intent.json") == raw)
    output("intent_sha256", sha256(raw).hexdigest())


def read_intent():
    transfer.context()
    _target, _refs, value = parse_intent()
    reader = store("SUBS_BOT_CF_PROVIDER_ARCHIVE_READ_TOKEN")
    reader.verify()
    control.require(inventory(reader, current=reader.run_id).get(reader.run_id) == {"source-intent.json"})
    expected = os.environ.get("SUBS_BOT_PROVIDER_DIGEST_INTENT_SHA256", "")
    raw = reader.read("source-intent.json")
    control.require(control.match(control.provider.HEX, expected) and isinstance(raw, bytes)
                    and sha256(raw).hexdigest() == expected and raw == control.canonical(value))
    output("intent_sha256", expected)


def publish():
    transfer.context()
    target, refs, value = parse_intent()
    run_id, revision = os.environ["GITHUB_RUN_ID"], os.environ["GITHUB_SHA"]
    workflow_job(run_id, revision, JOBS["preflight"])
    workflow_job(run_id, revision, JOBS["intent-readback"])
    pinned = os.environ.get("SUBS_BOT_PROVIDER_DIGEST_INTENT_SHA256", "")
    control.require(control.match(control.provider.HEX, pinned) and control.digest(value) == pinned)
    transfer.receive()
    root = Path(os.environ["RUNNER_TEMP"])
    archive, evidence = control.publication._verified_input(root, target["build"]["revision"], target["build"]["runId"])
    control.require(evidence == target["build"])
    result = digest.publish_once(target, refs, archive, value, pinned,
        os.environ.get("SUBS_BOT_CF_PROVIDER_WORKER_READ_TOKEN", ""),
        os.environ.get("SUBS_BOT_CF_PROVIDER_CONTAINER_READ_TOKEN", ""),
        os.environ.get("SUBS_BOT_CF_PROVIDER_CONTAINER_WRITE_TOKEN", ""))
    output("response_json", result)


def verify():
    transfer.context()
    target, _refs, value = parse_intent()
    workflow_job(os.environ["GITHUB_RUN_ID"], os.environ["GITHUB_SHA"], JOBS["publish"])
    state = digest.observe(target, os.environ.get("SUBS_BOT_CF_PROVIDER_WORKER_READ_TOKEN", ""),
                           os.environ.get("SUBS_BOT_CF_PROVIDER_CONTAINER_READ_TOKEN", ""))
    control.require(state["dependencySha256"] == value["prestate"]["dependencySha256"]
                    and state["manifestSha256"] == target["build"]["ociManifestSha256"])
    result = digest.verify_remote_closure(target, os.environ.get("SUBS_BOT_CF_PROVIDER_CONTAINER_READ_TOKEN", ""))
    control.require(digest.observe(target, os.environ.get("SUBS_BOT_CF_PROVIDER_WORKER_READ_TOKEN", ""),
                                   os.environ.get("SUBS_BOT_CF_PROVIDER_CONTAINER_READ_TOKEN", "")) == state)
    output("verification_json", {**result, "dependencySha256": state["dependencySha256"]})


def completion_value(value, target):
    response = control.github._parse_object(os.environ.get("SUBS_BOT_PROVIDER_DIGEST_RESPONSE_JSON", ""), sealed.ERROR)
    verify_result = control.github._parse_object(os.environ.get("SUBS_BOT_PROVIDER_DIGEST_VERIFICATION_JSON", ""), sealed.ERROR)
    expected_status = "published-digest" if value["prestate"]["manifestSha256"] is None else "verified-existing"
    control.require(response == {"status": expected_status, "manifestSha256": target["build"]["ociManifestSha256"],
                                 "configSha256": target["build"]["ociConfigSha256"], "prestateSha256": control.digest(value["prestate"]),
                                 "providerMutation": False, "registryMutation": expected_status == "published-digest"}
                    and verify_result == {"manifestSha256": target["build"]["ociManifestSha256"],
                                          "configSha256": target["build"]["ociConfigSha256"], "allReferencedBlobsVerified": True,
                                          "dependencySha256": value["prestate"]["dependencySha256"]})
    return {"version": 1, "kind": "isolated-provider-digest-completion", "runId": value["runId"], "runAttempt": "1",
            "controllerRevision": value["controllerRevision"], "intentSha256": control.digest(value),
            "response": response, "verification": verify_result}


def write_completion():
    transfer.context()
    target, _refs, value = parse_intent()
    run_id, revision = os.environ["GITHUB_RUN_ID"], os.environ["GITHUB_SHA"]
    workflow_job(run_id, revision, JOBS["publish"])
    workflow_job(run_id, revision, JOBS["verify"])
    reader = store("SUBS_BOT_CF_PROVIDER_ARCHIVE_WRITE_TOKEN")
    reader.verify()
    control.require(inventory(reader, current=reader.run_id).get(run_id) == {"source-intent.json"})
    raw_intent = reader.read("source-intent.json")
    control.require(isinstance(raw_intent, bytes) and raw_intent == control.canonical(value)
                    and os.environ.get("SUBS_BOT_PROVIDER_DIGEST_INTENT_SHA256") == sha256(raw_intent).hexdigest())
    raw = control.canonical(completion_value(value, target))
    control.require(reader.read("source-manifest.json") is None)
    reader.put("source-manifest.json", raw)
    control.require(reader.read("source-manifest.json") == raw)
    output("completion_sha256", sha256(raw).hexdigest())


def independent_readback():
    transfer.context()
    target, _refs, value = parse_intent()
    run_id, revision = os.environ["GITHUB_RUN_ID"], os.environ["GITHUB_SHA"]
    for name in ("intent-readback", "publish", "verify"):
        workflow_job(run_id, revision, JOBS[name])
    reader = store("SUBS_BOT_CF_PROVIDER_ARCHIVE_READ_TOKEN")
    reader.verify()
    control.require(inventory(reader, current=run_id).get(run_id) == {"source-intent.json", "source-manifest.json"})
    raw_intent, raw_done = reader.read("source-intent.json"), reader.read("source-manifest.json")
    control.require(isinstance(raw_intent, bytes) and raw_intent == control.canonical(value)
                    and os.environ.get("SUBS_BOT_PROVIDER_DIGEST_INTENT_SHA256") == sha256(raw_intent).hexdigest()
                    and isinstance(raw_done, bytes) and raw_done == control.canonical(completion_value(value, target))
                    and os.environ.get("SUBS_BOT_PROVIDER_DIGEST_COMPLETION_SHA256") == sha256(raw_done).hexdigest())
    job_id = workflow_job(run_id, revision, JOBS["readback"], running=True)
    result = {"intentSha256": sha256(raw_intent).hexdigest(), "completionSha256": sha256(raw_done).hexdigest(),
              "targetSha256": value["targetSha256"], "controllerRevision": revision, "readbackJobId": job_id}
    result["readbackSha256"] = control.digest(projection(run_id, value, result["completionSha256"], job_id))
    print(json.dumps({"status": "independent-digest-evidence-readback", "runId": run_id, "ledgerRecord": result,
                      "providerMutation": False, "productionMutation": False,
                      "simulatedActionsUnavailable": value["simulatedActionsUnavailable"]}, sort_keys=True))


if __name__ == "__main__":
    try:
        {"preflight": preflight, "write-intent": write_intent, "read-intent": read_intent,
         "publish": publish, "verify": verify, "write-completion": write_completion,
         "independent-readback": independent_readback}[os.environ.get("SUBS_BOT_PROVIDER_DIGEST_JOURNAL_ACTION", "")]()
    except Exception:
        raise SystemExit("Isolated digest rehearsal stopped; preserve intent and never retry an unknown write.") from None
