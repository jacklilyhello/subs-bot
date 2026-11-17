"""Bounded private Provider publish rehearsal; each external transition is one-shot.

This module is not a deployment entry point. The protected workflow must preserve
the job graph and pass artifact IDs and digests only from trusted `needs` outputs.
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
import provider_private_handoff as handoff

BASE = "maintenance/provider-encrypted-publish/"
RECORDS = {"intent.json", "response.json", "completion.json"}
MAX_HISTORY = 32


class Store(sealed.PrivateProofStore):
    def __init__(self, target, token, run_id):
        super().__init__(target, token, run_id, "1")
        self.prefix = f"{BASE}{run_id}/1/"

    def key(self, relative):
        control.require(relative in RECORDS)
        return self.prefix + relative


def store(token_name, run_id=None):
    target = control.github._parse_object(os.environ.get("SUBS_BOT_PROVIDER_ARCHIVE_TARGET_JSON", ""), sealed.ERROR)
    return Store(target, os.environ.get(token_name, ""), run_id or os.environ["GITHUB_RUN_ID"])


def config():
    handoff.context()
    value = control.read_config(os.environ.get("SUBS_BOT_PROVIDER_CONTROL_TARGET_JSON", ""))
    control.require(value["environment"] == "rehearsal" and value["caller"] is None
                    and os.environ.get("SUBS_BOT_PROVIDER_CONTROL_OPERATION") == "publish"
                    and os.environ.get("SUBS_BOT_PROVIDER_DURABLE_REQUIRED") == "1"
                    and os.environ.get("SUBS_BOT_PROVIDER_CI_RUN_ID") == value["build"]["runId"]
                    and os.environ.get("SUBS_BOT_PROVIDER_CONTROL_APPROVAL") == control.digest({"operation": "publish", "target": value}))
    return value


def refs():
    value = json.loads(os.environ.get("SUBS_BOT_PROVIDER_ARCHIVE_REFS", ""), object_pairs_hook=control.github._unique_json_object)
    control.require(isinstance(value, list) and 0 < len(value) <= 9)
    return value


def verify_sources(target):
    control.guard_sources(target)
    control.prepare_durable(target["build"])
    with tempfile.TemporaryDirectory(prefix=".encrypted-provider-chain-", dir=os.environ["RUNNER_TEMP"]) as temporary:
        control.verify_previous_archives(target, Path(temporary))
    control.guard_sources(target)


def live_state(target, token):
    api = control.ProviderAPI(target, os.environ.get("SUBS_BOT_CF_PROVIDER_WORKER_READ_TOKEN", ""), token)
    first = control.observe(api)
    if target.get("previous") is not None and target["activation"] is None:
        # The candidate may not have a version yet. Observe using the complete
        # candidate+previous chain, then prove the exact previous release is the
        # unbound stopped active dependency before publication.
        control.unbound_upgrade(api, first)
    else:
        control.require(target["activation"] is not None)
        control.verify_smoke(api, first, config=target)
    caller = control.caller_state(api, target, allow_unbound=True)
    control.require(caller == "unbound" and control.observe(api) == first
                    and control.caller_state(api, target, allow_unbound=True) == caller)
    if target.get("previous") is not None and target["activation"] is None:
        control.unbound_upgrade(api, first)
    registry = control.Registry(target, token)
    pull = registry.mint()
    tag = f"git-{target['build']['revision']}-{target['build']['ociManifestSha256'][:12]}"
    observed = registry.manifest(tag, pull, allow_missing=True)
    control.require(observed is None or observed == target["build"]["ociManifestSha256"])
    return {"dependencySha256": control.digest({"target": target, "state": first, "callerState": caller}),
            "tagManifestSha256": observed}


def write_cipher(phase, message):
    cipher = handoff.encrypt(message, phase)
    path = Path(os.environ["RUNNER_TEMP"]) / "payload.age"
    with control.provenance._write_private(path) as output:
        output.write(cipher)
    digest = sha256(cipher).hexdigest()
    # GITHUB_OUTPUT contains only a ciphertext digest; neither target nor source is printed.
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="ascii") as output:
        output.write("cipher_sha256=" + digest + "\n")


def preflight():
    target = config()
    verify_sources(target)
    state = live_state(target, os.environ.get("SUBS_BOT_CF_PROVIDER_CONTAINER_READ_TOKEN", ""))
    control.require(state["tagManifestSha256"] == target["build"]["ociManifestSha256"],
                    "A missing registry tag cannot be safely created without an independently proven create-only guarantee.")
    state["archiveRefs"] = refs()
    value = {"version": 1, "kind": "private-provider-encrypted-handoff", "phase": "intent",
             "runId": os.environ["GITHUB_RUN_ID"], "runAttempt": "1", "controllerRevision": os.environ["GITHUB_SHA"],
             "operation": "publish", "target": target, "targetSha256": control.digest(target),
             "approvalSha256": control.digest({"operation": "publish", "target": target}),
             "intentSha256": None, "state": state}
    write_cipher("intent", value)


def ledger():
    value = control.github._parse_object(os.environ.get("SUBS_BOT_PROVIDER_ENCRYPTED_LEDGER_JSON", ""), sealed.ERROR)
    control.require(len(value) <= MAX_HISTORY)
    for run_id, record in value.items():
        control.require(control.match(control.provider.DECIMAL, run_id) and isinstance(record, dict)
                        and set(record) == {"intentSha256", "responseSha256", "completionSha256", "targetSha256", "controllerRevision"}
                        and all(control.match(control.provider.HEX, record[key]) for key in
                                ("intentSha256", "responseSha256", "completionSha256", "targetSha256"))
                        and control.match(control.provider.REVISION, record["controllerRevision"]))
    return value


def inventory(reader, *, current=None):
    grouped = {}
    for key in durable.list_private_keys(reader, BASE):
        match = re.fullmatch(re.escape(BASE) + r"([1-9][0-9]*)/1/(intent\.json|response\.json|completion\.json)", key)
        control.require(match is not None)
        grouped.setdefault(match.group(1), set())
        control.require(match.group(2) not in grouped[match.group(1)])
        grouped[match.group(1)].add(match.group(2))
    registered = ledger()
    control.require(len(grouped) <= MAX_HISTORY and set(grouped) - ({current} if current else set()) == set(registered) - ({current} if current else set()),
                    "A private Provider publish attempt is unregistered, incomplete or unknown.")
    for run_id, expected in registered.items():
        if run_id == current:
            continue
        control.require(grouped[run_id] == RECORDS)
        prior = Store(reader.target, reader.token, run_id)
        values = {}
        for name, key in (("intent.json", "intentSha256"), ("response.json", "responseSha256"),
                          ("completion.json", "completionSha256")):
            raw = prior.read(name)
            control.require(isinstance(raw, bytes) and sha256(raw).hexdigest() == expected[key])
            values[name] = control.github._parse_object(raw, sealed.ERROR)
        intent, response, completion = values["intent.json"], values["response.json"], values["completion.json"]
        target = control.validate_config(intent.get("target"))
        control.require(target["environment"] == "rehearsal" and target["caller"] is None
                        and control.digest(target) == expected["targetSha256"]
                        and all(set(record) == {"version", "kind", "phase", "runId", "runAttempt", "controllerRevision",
                                                "operation", "target", "targetSha256", "approvalSha256", "intentSha256", "state"}
                                and type(record["version"]) is int and record["version"] == 1
                                and record["kind"] == "private-provider-encrypted-handoff" and record["runAttempt"] == "1"
                                and record["operation"] == "publish" and record["target"] == target
                                and record["approvalSha256"] == control.digest({"operation": "publish", "target": target})
                                for record in (intent, response, completion))
                        and (intent["phase"], response["phase"], completion["phase"]) == ("intent", "response", "completion")
                        and intent["intentSha256"] is None
                        and intent.get("runId") == response.get("runId") == completion.get("runId") == run_id
                        and intent.get("controllerRevision") == response.get("controllerRevision") == completion.get("controllerRevision") == expected["controllerRevision"]
                        and intent.get("targetSha256") == response.get("targetSha256") == completion.get("targetSha256") == expected["targetSha256"]
                        and response.get("intentSha256") == completion.get("intentSha256") == expected["intentSha256"]
                        and completion.get("state", {}).get("responseSha256") == expected["responseSha256"])
    return grouped


def controllers():
    value = json.loads(os.environ.get("SUBS_BOT_PROVIDER_ENCRYPTED_CONTROLLERS_JSON", ""),
                       object_pairs_hook=control.github._unique_json_object)
    control.require(isinstance(value, list) and 0 < len(value) <= 16 and all(control.match(control.provider.REVISION, item) for item in value)
                    and len(set(value)) == len(value) and os.environ["GITHUB_SHA"] in value)
    return value


def require_complete_history():
    """Unknown prior runs remain a blocker even if no private object is observable."""
    trusted, registered = controllers(), ledger()
    token, current = control.github._github_token(), os.environ["GITHUB_RUN_ID"]
    rows = []
    for page in range(1, 11):
        data = control.github._get_json(f"/actions/workflows/worker-production-provider-encrypted-rehearsal.yml/runs?per_page=100&page={page}", token)
        batch = data.get("workflow_runs")
        control.require(isinstance(batch, list) and len(batch) <= 100 and type(data.get("total_count")) is int
                        and 0 <= data["total_count"] <= 1000)
        rows.extend(batch)
        if len(batch) < 100:
            break
    else:
        raise control.ProviderError("Encrypted Provider rehearsal history exceeds its safe bound.")
    control.require(len(rows) == data["total_count"] and len({str(row.get("id")) for row in rows if isinstance(row, dict)}) == len(rows))
    seen, current_seen = set(), False
    for row in rows:
        control.require(isinstance(row, dict) and row.get("path") in (handoff.WORKFLOW_PATH, handoff.WORKFLOW_PATH + "@main",
                        handoff.WORKFLOW_PATH + "@refs/heads/main") and row.get("head_sha") in trusted
                        and row.get("head_branch") == "main" and row.get("event") == "workflow_dispatch" and row.get("run_attempt") == 1
                        and all(isinstance(row.get(key), dict) and row[key].get("id") == control.github.REPOSITORY_ID
                                for key in ("repository", "head_repository")))
        run_id = str(row.get("id"))
        if run_id == current:
            control.require(not current_seen and row.get("head_sha") == os.environ["GITHUB_SHA"])
            current_seen = True
        else:
            control.require(run_id in registered and run_id not in seen
                            and row.get("head_sha") == registered[run_id]["controllerRevision"]
                            and (row.get("status"), row.get("conclusion")) == ("completed", "success"),
                            "A prior Provider publish rehearsal is unresolved; do not dispatch a new write.")
            seen.add(run_id)
    control.require(current_seen and seen == set(registered))


def prepare_intent():
    handoff.context()
    value = handoff.decrypt("intent", os.environ.get("SUBS_BOT_PROVIDER_TRUSTED_UPSTREAM_ARTIFACT_ID", ""),
                            os.environ.get("SUBS_BOT_PROVIDER_TRUSTED_UPSTREAM_ARCHIVE_SHA256", ""),
                            os.environ.get("SUBS_BOT_PROVIDER_TRUSTED_UPSTREAM_CIPHER_SHA256", ""))
    state = value["state"]
    control.require(set(state) == {"dependencySha256", "tagManifestSha256", "archiveRefs"}
                    and control.match(control.provider.HEX, state["dependencySha256"])
                    and (state["tagManifestSha256"] is None or state["tagManifestSha256"] == value["target"]["build"]["ociManifestSha256"])
                    and isinstance(state["archiveRefs"], list) and 0 < len(state["archiveRefs"]) <= 9)
    control.require(state["archiveRefs"] == refs())
    # Independently re-read every referenced R2 source before acknowledging the intent.
    durable.restore()
    verify_sources(value["target"])
    reader = store("SUBS_BOT_CF_PROVIDER_ARCHIVE_READ_TOKEN")
    reader.verify()
    grouped = inventory(reader)
    control.require(len(grouped) < MAX_HISTORY and reader.run_id not in grouped)
    require_complete_history()
    path = Path(os.environ["RUNNER_TEMP"]) / "provider-encrypted-intent.json"
    with control.provenance._write_private(path) as output:
        output.write(control.canonical(value))


def persist_intent():
    handoff.context()
    path = Path(os.environ["RUNNER_TEMP"]) / "provider-encrypted-intent.json"
    raw = control.provider.checked_file(path, handoff.MAX_PLAINTEXT).read_bytes()
    value = handoff.envelope(control.github._parse_object(raw, sealed.ERROR), "intent")
    writer = store("SUBS_BOT_CF_PROVIDER_ARCHIVE_WRITE_TOKEN")
    writer.verify()
    control.require(writer.read("intent.json") is None and writer.read("response.json") is None and writer.read("completion.json") is None)
    writer.put("intent.json", raw)
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="ascii") as output:
        output.write("intent_sha256=" + sha256(raw).hexdigest() + "\n")


def read_intent():
    target = config()
    expected = os.environ.get("SUBS_BOT_PROVIDER_ENCRYPTED_INTENT_SHA256", "")
    control.require(control.match(control.provider.HEX, expected))
    reader = store("SUBS_BOT_CF_PROVIDER_ARCHIVE_READ_TOKEN")
    reader.verify()
    grouped = inventory(reader, current=reader.run_id)
    control.require(grouped.get(reader.run_id) == {"intent.json"})
    raw = reader.read("intent.json")
    control.require(isinstance(raw, bytes) and sha256(raw).hexdigest() == expected)
    value = handoff.envelope(control.github._parse_object(raw, sealed.ERROR), "intent")
    control.require(value["target"] == target and value["state"].get("archiveRefs") == refs())
    # Re-read and verify the whole source chain in this distinct Provider job.
    durable.restore()
    verify_sources(target)
    root = Path(os.environ["RUNNER_TEMP"])
    with control.provenance._write_private(root / "provider-provenance.json") as output:
        output.write(control.canonical(target["build"]))
    with control.provenance._write_private(root / "provider-encrypted-intent.json") as output:
        output.write(raw)


def dispatch():
    target = config()
    expected = os.environ.get("SUBS_BOT_PROVIDER_ENCRYPTED_INTENT_SHA256", "")
    root = Path(os.environ["RUNNER_TEMP"])
    raw = control.provider.checked_file(root / "provider-encrypted-intent.json", handoff.MAX_PLAINTEXT).read_bytes()
    control.require(sha256(raw).hexdigest() == expected)
    intent = handoff.envelope(control.github._parse_object(raw, sealed.ERROR), "intent")
    control.require(intent["target"] == target and intent["state"].get("archiveRefs") == refs())
    control.guard_sources(target)
    token = os.environ.get("SUBS_BOT_CF_PROVIDER_CONTAINER_READ_TOKEN", "")
    previous = live_state(target, token)
    control.require(previous == {key: intent["state"][key] for key in ("dependencySha256", "tagManifestSha256")},
                    "The exact private Provider or registry prestate changed before publication.")
    _archive, evidence = control.publication._verified_input(root, target["build"]["revision"], target["build"]["runId"])
    control.require(evidence == target["build"])
    registry = control.Registry(target, token)
    pull = registry.mint()
    build = target["build"]
    tag = f"git-{build['revision']}-{build['ociManifestSha256'][:12]}"
    observed = registry.manifest(tag, pull, allow_missing=True)
    control.require(observed == previous["tagManifestSha256"])
    control.require(observed == build["ociManifestSha256"],
                    "A missing registry tag cannot be safely created without an independently proven create-only guarantee.")
    response = {"version": 1, "kind": "private-provider-encrypted-handoff", "phase": "response",
                "runId": os.environ["GITHUB_RUN_ID"], "runAttempt": "1", "controllerRevision": os.environ["GITHUB_SHA"],
                "operation": "publish", "target": target, "targetSha256": control.digest(target),
                "approvalSha256": intent["approvalSha256"], "intentSha256": expected,
                "state": {"dispatchStatus": "already-present", "prestateSha256": control.digest(previous)}}
    write_cipher("response", response)


def read_record(reader, name, expected):
    control.require(name in RECORDS and control.match(control.provider.HEX, expected))
    raw = reader.read(name)
    control.require(isinstance(raw, bytes) and sha256(raw).hexdigest() == expected)
    return raw


def prepare_response():
    handoff.context()
    value = handoff.decrypt("response", os.environ.get("SUBS_BOT_PROVIDER_TRUSTED_UPSTREAM_ARTIFACT_ID", ""),
                            os.environ.get("SUBS_BOT_PROVIDER_TRUSTED_UPSTREAM_ARCHIVE_SHA256", ""),
                            os.environ.get("SUBS_BOT_PROVIDER_TRUSTED_UPSTREAM_CIPHER_SHA256", ""))
    reader = store("SUBS_BOT_CF_PROVIDER_ARCHIVE_READ_TOKEN")
    reader.verify()
    control.require(inventory(reader, current=reader.run_id).get(reader.run_id) == {"intent.json"})
    intent_sha = os.environ.get("SUBS_BOT_PROVIDER_ENCRYPTED_INTENT_SHA256", "")
    raw = read_record(reader, "intent.json", intent_sha)
    intent = handoff.envelope(control.github._parse_object(raw, sealed.ERROR), "intent")
    control.require(value["intentSha256"] == intent_sha and value["target"] == intent["target"]
                    and set(value["state"]) == {"dispatchStatus", "prestateSha256"}
                    and value["state"]["dispatchStatus"] == "already-present"
                    and value["state"]["prestateSha256"] == control.digest({key: intent["state"][key]
                        for key in ("dependencySha256", "tagManifestSha256")}))
    path = Path(os.environ["RUNNER_TEMP"]) / "provider-encrypted-response.json"
    with control.provenance._write_private(path) as output:
        output.write(control.canonical(value))


def persist_response():
    handoff.context()
    raw = control.provider.checked_file(Path(os.environ["RUNNER_TEMP"]) / "provider-encrypted-response.json", handoff.MAX_PLAINTEXT).read_bytes()
    value = handoff.envelope(control.github._parse_object(raw, sealed.ERROR), "response")
    writer = store("SUBS_BOT_CF_PROVIDER_ARCHIVE_WRITE_TOKEN")
    writer.verify()
    intent_sha = os.environ.get("SUBS_BOT_PROVIDER_ENCRYPTED_INTENT_SHA256", "")
    read_record(writer, "intent.json", intent_sha)
    control.require(value["intentSha256"] == intent_sha and writer.read("response.json") is None and writer.read("completion.json") is None)
    writer.put("response.json", raw)
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="ascii") as output:
        output.write("response_sha256=" + sha256(raw).hexdigest() + "\n")


def read_response():
    target = config()
    reader = store("SUBS_BOT_CF_PROVIDER_ARCHIVE_READ_TOKEN")
    reader.verify()
    control.require(inventory(reader, current=reader.run_id).get(reader.run_id) == {"intent.json", "response.json"})
    intent_sha = os.environ.get("SUBS_BOT_PROVIDER_ENCRYPTED_INTENT_SHA256", "")
    response_sha = os.environ.get("SUBS_BOT_PROVIDER_ENCRYPTED_RESPONSE_SHA256", "")
    intent_raw, response_raw = read_record(reader, "intent.json", intent_sha), read_record(reader, "response.json", response_sha)
    intent = handoff.envelope(control.github._parse_object(intent_raw, sealed.ERROR), "intent")
    response = handoff.envelope(control.github._parse_object(response_raw, sealed.ERROR), "response")
    control.require(intent["target"] == response["target"] == target and response["intentSha256"] == intent_sha
                    and intent["state"].get("archiveRefs") == refs())
    durable.restore()
    verify_sources(target)
    root = Path(os.environ["RUNNER_TEMP"])
    with control.provenance._write_private(root / "provider-encrypted-intent.json") as output:
        output.write(intent_raw)
    with control.provenance._write_private(root / "provider-encrypted-response.json") as output:
        output.write(response_raw)


def verify_publication():
    target = config()
    root = Path(os.environ["RUNNER_TEMP"])
    intent_sha = os.environ.get("SUBS_BOT_PROVIDER_ENCRYPTED_INTENT_SHA256", "")
    response_sha = os.environ.get("SUBS_BOT_PROVIDER_ENCRYPTED_RESPONSE_SHA256", "")
    intent_raw = control.provider.checked_file(root / "provider-encrypted-intent.json", handoff.MAX_PLAINTEXT).read_bytes()
    response_raw = control.provider.checked_file(root / "provider-encrypted-response.json", handoff.MAX_PLAINTEXT).read_bytes()
    control.require(sha256(intent_raw).hexdigest() == intent_sha and sha256(response_raw).hexdigest() == response_sha)
    intent = handoff.envelope(control.github._parse_object(intent_raw, sealed.ERROR), "intent")
    response = handoff.envelope(control.github._parse_object(response_raw, sealed.ERROR), "response")
    control.require(intent["target"] == response["target"] == target and response["intentSha256"] == intent_sha)
    control.guard_sources(target)
    token = os.environ.get("SUBS_BOT_CF_PROVIDER_CONTAINER_READ_TOKEN", "")
    observed = live_state(target, token)
    build = target["build"]
    control.require(observed == {"dependencySha256": intent["state"]["dependencySha256"],
                                 "tagManifestSha256": build["ociManifestSha256"]})
    registry = control.Registry(target, token)
    pull = registry.mint()
    with tempfile.TemporaryDirectory(prefix=".encrypted-provider-verify-", dir=root) as temporary:
        scratch = Path(temporary)
        auth = control.publication._write_auth(scratch / "pull-auth.json", pull, registry.repository)
        image = f"{control.publication.HOST}/{registry.repository}@sha256:{build['ociManifestSha256']}"
        control.require(registry.manifest("sha256:" + build["ociManifestSha256"], pull) == build["ociManifestSha256"]
                        and control.publication._config(scratch, image, auth) == build["ociConfigSha256"])
    control.guard_sources(target)
    completion = {"version": 1, "kind": "private-provider-encrypted-handoff", "phase": "completion",
                  "runId": os.environ["GITHUB_RUN_ID"], "runAttempt": "1", "controllerRevision": os.environ["GITHUB_SHA"],
                  "operation": "publish", "target": target, "targetSha256": control.digest(target),
                  "approvalSha256": intent["approvalSha256"], "intentSha256": intent_sha,
                  "state": {"responseSha256": response_sha, "dependencySha256": observed["dependencySha256"],
                            "ociManifestSha256": build["ociManifestSha256"], "ociConfigSha256": build["ociConfigSha256"]}}
    write_cipher("completion", completion)


def prepare_completion():
    handoff.context()
    value = handoff.decrypt("completion", os.environ.get("SUBS_BOT_PROVIDER_TRUSTED_UPSTREAM_ARTIFACT_ID", ""),
                            os.environ.get("SUBS_BOT_PROVIDER_TRUSTED_UPSTREAM_ARCHIVE_SHA256", ""),
                            os.environ.get("SUBS_BOT_PROVIDER_TRUSTED_UPSTREAM_CIPHER_SHA256", ""))
    reader = store("SUBS_BOT_CF_PROVIDER_ARCHIVE_READ_TOKEN")
    reader.verify()
    control.require(inventory(reader, current=reader.run_id).get(reader.run_id) == {"intent.json", "response.json"})
    intent_sha = os.environ.get("SUBS_BOT_PROVIDER_ENCRYPTED_INTENT_SHA256", "")
    response_sha = os.environ.get("SUBS_BOT_PROVIDER_ENCRYPTED_RESPONSE_SHA256", "")
    intent = handoff.envelope(control.github._parse_object(read_record(reader, "intent.json", intent_sha), sealed.ERROR), "intent")
    response = handoff.envelope(control.github._parse_object(read_record(reader, "response.json", response_sha), sealed.ERROR), "response")
    state = value["state"]
    control.require(intent["target"] == response["target"] == value["target"] and value["intentSha256"] == intent_sha
                    and response["intentSha256"] == intent_sha and set(state) == {"responseSha256", "dependencySha256", "ociManifestSha256", "ociConfigSha256"}
                    and state == {"responseSha256": response_sha, "dependencySha256": intent["state"]["dependencySha256"],
                                  "ociManifestSha256": value["target"]["build"]["ociManifestSha256"],
                                  "ociConfigSha256": value["target"]["build"]["ociConfigSha256"]})
    with control.provenance._write_private(Path(os.environ["RUNNER_TEMP"]) / "provider-encrypted-completion.json") as output:
        output.write(control.canonical(value))


def persist_completion():
    handoff.context()
    raw = control.provider.checked_file(Path(os.environ["RUNNER_TEMP"]) / "provider-encrypted-completion.json", handoff.MAX_PLAINTEXT).read_bytes()
    value = handoff.envelope(control.github._parse_object(raw, sealed.ERROR), "completion")
    writer = store("SUBS_BOT_CF_PROVIDER_ARCHIVE_WRITE_TOKEN")
    writer.verify()
    intent_sha = os.environ.get("SUBS_BOT_PROVIDER_ENCRYPTED_INTENT_SHA256", "")
    response_sha = os.environ.get("SUBS_BOT_PROVIDER_ENCRYPTED_RESPONSE_SHA256", "")
    read_record(writer, "intent.json", intent_sha)
    read_record(writer, "response.json", response_sha)
    control.require(value["intentSha256"] == intent_sha and value["state"].get("responseSha256") == response_sha
                    and writer.read("completion.json") is None)
    writer.put("completion.json", raw)
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="ascii") as output:
        output.write("completion_sha256=" + sha256(raw).hexdigest() + "\n")


def independent_readback():
    handoff.context()
    reader = store("SUBS_BOT_CF_PROVIDER_ARCHIVE_READ_TOKEN")
    reader.verify()
    control.require(inventory(reader, current=reader.run_id).get(reader.run_id) == RECORDS)
    pins = {"intentSha256": os.environ.get("SUBS_BOT_PROVIDER_ENCRYPTED_INTENT_SHA256", ""),
            "responseSha256": os.environ.get("SUBS_BOT_PROVIDER_ENCRYPTED_RESPONSE_SHA256", ""),
            "completionSha256": os.environ.get("SUBS_BOT_PROVIDER_ENCRYPTED_COMPLETION_SHA256", "")}
    values = {}
    for name, phase, key in (("intent.json", "intent", "intentSha256"), ("response.json", "response", "responseSha256"),
                             ("completion.json", "completion", "completionSha256")):
        values[phase] = handoff.envelope(control.github._parse_object(read_record(reader, name, pins[key]), sealed.ERROR), phase)
    intent, response, completion = values["intent"], values["response"], values["completion"]
    control.require(intent["target"] == response["target"] == completion["target"]
                    and response["intentSha256"] == completion["intentSha256"] == pins["intentSha256"]
                    and completion["state"].get("responseSha256") == pins["responseSha256"]
                    and intent["state"].get("archiveRefs") == refs())
    # Independent R2-only source closure; no Provider credentials are present here.
    durable.restore()
    verify_sources(intent["target"])
    result = {**pins, "targetSha256": intent["targetSha256"], "controllerRevision": os.environ["GITHUB_SHA"]}
    print(json.dumps({"status": "private-source-and-evidence-readback", "runId": reader.run_id,
                      "ledgerRecord": result, "productionMutation": False, "providerMutation": False,
                      "registryMutation": False, "priorProviderHistory": "not-evaluated"}, sort_keys=True))


def confirm_current(phase):
    """A separately credentialed step reads the exact just-written record."""
    handoff.context()
    names = {"intent": ("intent.json", "intent_sha256"), "response": ("response.json", "response_sha256"),
             "completion": ("completion.json", "completion_sha256")}
    control.require(phase in names)
    name, output_name = names[phase]
    expected = os.environ.get("SUBS_BOT_PROVIDER_ENCRYPTED_EXPECTED_SHA256", "")
    reader = store("SUBS_BOT_CF_PROVIDER_ARCHIVE_READ_TOKEN")
    reader.verify()
    required = {"intent": {"intent.json"}, "response": {"intent.json", "response.json"},
                "completion": RECORDS}[phase]
    control.require(inventory(reader, current=reader.run_id).get(reader.run_id) == required)
    raw = read_record(reader, name, expected)
    value = handoff.envelope(control.github._parse_object(raw, sealed.ERROR), phase)
    if phase != "intent":
        intent_sha = os.environ.get("SUBS_BOT_PROVIDER_ENCRYPTED_INTENT_SHA256", "")
        read_record(reader, "intent.json", intent_sha)
        control.require(value["intentSha256"] == intent_sha)
    if phase == "completion":
        response_sha = os.environ.get("SUBS_BOT_PROVIDER_ENCRYPTED_RESPONSE_SHA256", "")
        read_record(reader, "response.json", response_sha)
        control.require(value["state"].get("responseSha256") == response_sha)
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="ascii") as output:
        output.write(output_name + "=" + expected + "\n")


if __name__ == "__main__":
    try:
        action = os.environ.get("SUBS_BOT_PROVIDER_ENCRYPTED_ACTION", "")
        handlers = {"preflight": preflight, "prepare-intent": prepare_intent, "persist-intent": persist_intent,
                    "read-intent": read_intent, "dispatch": dispatch, "prepare-response": prepare_response,
                    "persist-response": persist_response, "read-response": read_response,
                    "verify-publication": verify_publication, "prepare-completion": prepare_completion,
                    "persist-completion": persist_completion, "independent-readback": independent_readback,
                    "confirm-intent": lambda: confirm_current("intent"),
                    "confirm-response": lambda: confirm_current("response"),
                    "confirm-completion": lambda: confirm_current("completion")}
        control.require(action in handlers)
        handlers[action]()
    except (ValueError, KeyError, OSError, TypeError, RuntimeError):
        raise SystemExit("Private Provider publication stopped; preserve any intent and do not retry an unknown operation.") from None
