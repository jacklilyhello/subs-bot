"""Independent read-only trusted-main verification of Provider archive and state."""

import base64
from hashlib import sha1, sha256
import json
import os
from pathlib import Path
import re
import resource
import subprocess
import tempfile

import archive_production_provider as archive
from cloudflare_isolation import CloudflareError
import production_provider as provider
import scoped_r2
import trusted_provider_head_gate as gate


JOB_STEPS = {"Reviewed Provider source verification": "Verify current and previous archived sources"}


def diagnosed(phase, action, *, index=None):
    """Emit fixed read stages and bounded numeric status, never request details."""
    provider.require(phase in {"context", "target", "archive-source", "archive-closure", "provider-api", "provider-state",
                               "previous-terminal", "caller-state", "stable-state", "previous-recheck", "registry-client", "registry"}
                     and (index is None or type(index) is int and 0 <= index <= 8))
    label = {"phase": phase, **({"sourceIndex": index} if index is not None else {})}
    print(json.dumps({**label, "status": "started"}), flush=True)
    try:
        result = action()
    except Exception as error:
        category = ("r2" if isinstance(error, (scoped_r2.ScopedR2Error, scoped_r2.ScopedR2ReadError)) else
                    "cloudflare" if isinstance(error, CloudflareError) else
                    "github" if isinstance(error, provider.github.ArtifactError) else
                    "provider" if isinstance(error, provider.ProviderError) else "other")
        diagnostic = getattr(error, "read_diagnostic", None)
        status = diagnostic.get("httpStatus") if isinstance(diagnostic, dict) else getattr(error, "http_status", None)
        report = {**label, "status": "rejected", "category": category}
        if type(status) is int and 100 <= status <= 599:
            report["httpStatus"] = status
        codes = diagnostic.get("cloudflareCodes") if isinstance(diagnostic, dict) else None
        if isinstance(codes, list) and len(codes) <= 8 and all(type(code) is int and 1000 <= code <= 999999 for code in codes):
            report["cloudflareCodes"] = codes
        print(json.dumps(report, sort_keys=True), flush=True)
        raise
    print(json.dumps({**label, "status": "confirmed"}), flush=True)
    return result


def checks():
    env = os.environ
    result = gate.validate(env)
    spec = gate.parsed(env["PROVIDER_HEAD_VALIDATION_JSON"])
    token, run_id = env["GH_TOKEN"], env.get("GITHUB_RUN_ID", "")
    provider.require(provider.match(provider.provider.DECIMAL, run_id))
    response = provider.github._get_json(f"/actions/runs/{run_id}/attempts/1/jobs?per_page=100", token)
    jobs = response.get("jobs")
    provider.require(isinstance(jobs, list) and type(response.get("total_count")) is int
                     and response["total_count"] == len(jobs) < 100)
    required = dict(JOB_STEPS)
    if env.get("PROVIDER_HEAD_PHASE") == "attest-provider":
        required["Trusted Provider R2 attestation"] = "Independently verify every private original"
    for name, step_name in required.items():
        matches = [job for job in jobs if isinstance(job, dict) and job.get("name") == name]
        provider.require(len(matches) == 1 and str(matches[0].get("run_id")) == run_id and matches[0].get("run_attempt") == 1
                         and matches[0].get("head_sha") == env["GITHUB_SHA"]
                         and (matches[0].get("status"), matches[0].get("conclusion")) == ("completed", "success")
                         and isinstance(matches[0].get("steps"), list))
        for wanted in ("Verify reviewed Provider head using trusted main", step_name):
            steps = [step for step in matches[0]["steps"] if isinstance(step, dict) and step.get("name") == wanted]
            provider.require(len(steps) == 1 and (steps[0].get("status"), steps[0].get("conclusion")) == ("completed", "success"))
    return result, spec


def source_run(build):
    run = provider.github._get_json(f"/actions/runs/{build['runId']}/attempts/{build['runAttempt']}", os.environ["GH_TOKEN"])
    provider.require(str(run.get("id")) == build["runId"] and str(run.get("run_attempt")) == build["runAttempt"]
                     and run.get("workflow_id") == provider.provenance.WORKFLOW_ID
                     and run.get("path") in (provider.provenance.WORKFLOW_PATH, provider.provenance.WORKFLOW_PATH + "@main",
                                             provider.provenance.WORKFLOW_PATH + "@refs/heads/main")
                     and run.get("event") in {"push", "workflow_dispatch"} and (run.get("status"), run.get("conclusion")) == ("completed", "success")
                     and run.get("head_branch") == "main" and run.get("head_sha") == build["revision"]
                     and all(isinstance(run.get(key), dict) and run[key].get("id") == provider.github.REPOSITORY_ID
                             for key in ("repository", "head_repository")))
    if build["revision"] != os.environ["GITHUB_SHA"]:
        value = provider.github.compare_commits_metadata(build["revision"], os.environ["GITHUB_SHA"], os.environ["GH_TOKEN"])
        provider.require(value.get("status") == "ahead" and value.get("behind_by") == 0
                         and all(isinstance(value.get(key), dict) and value[key].get("sha") == build["revision"]
                                 for key in ("base_commit", "merge_base_commit")))


def requirements(revision, root):
    value = provider.github._get_json(f"/contents/worker/provider_fetch/requirements.txt?ref={revision}", os.environ["GH_TOKEN"])
    provider.require(value.get("type") == "file" and value.get("path") == "worker/provider_fetch/requirements.txt"
                     and value.get("encoding") == "base64" and isinstance(value.get("content"), str)
                     and isinstance(value.get("sha"), str) and re.fullmatch(r"[0-9a-f]{40}", value["sha"]) is not None
                     and type(value.get("size")) is int and 0 < value["size"] <= provider.provider.MAX_METADATA)
    raw = base64.b64decode("".join(value["content"].splitlines()), validate=True)
    provider.require(len(raw) == value["size"] and sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest() == value["sha"])
    path = root / "requirements.txt"
    with provider.provenance._write_private(path) as output:
        output.write(raw)
    return path


def archive_run(ref, manifest):
    run = provider.github._get_json(f"/actions/runs/{ref['runId']}/attempts/{ref['runAttempt']}", os.environ["GH_TOKEN"])
    revision = manifest.get("controllerRevision")
    provider.require(str(run.get("id")) == ref["runId"] and str(run.get("run_attempt")) == ref["runAttempt"]
                     and run.get("path") in (provider.REHEARSAL_WORKFLOW_PATH, provider.REHEARSAL_WORKFLOW_PATH + "@main",
                                             provider.REHEARSAL_WORKFLOW_PATH + "@refs/heads/main")
                     and run.get("event") == "workflow_dispatch" and run.get("head_branch") == "main"
                     and run.get("status") == "completed" and isinstance(run.get("conclusion"), str)
                     and (ref["kind"] != "complete" or run.get("conclusion") == "success")
                     and provider.match(provider.provider.REVISION, revision) and run.get("head_sha") == revision
                     and all(isinstance(run.get(key), dict) and run[key].get("id") == provider.github.REPOSITORY_ID
                             for key in ("repository", "head_repository")))
    if revision != os.environ["GITHUB_SHA"]:
        comparison = provider.github.compare_commits_metadata(revision, os.environ["GITHUB_SHA"], os.environ["GH_TOKEN"])
        provider.require(comparison.get("status") == "ahead" and comparison.get("behind_by") == 0
                         and all(isinstance(comparison.get(key), dict) and comparison[key].get("sha") == revision
                                 for key in ("base_commit", "merge_base_commit")))


class IsolatedSourceStore(archive.PrivateProofStore):
    def __init__(self, target, token, operation_id):
        super().__init__(target, token, operation_id, "1")
        self.prefix = f"maintenance/provider-isolated-source/{operation_id}/1/"

    def key(self, relative):
        provider.require(isinstance(relative, str) and (relative in {"source-intent.json", "source-manifest.json"}
                         or re.fullmatch(r"blobs/[0-9a-f]{64}", relative) is not None))
        return self.prefix + relative


def independent_isolated_source(ref, bucket, token):
    """Verify the source and registered readback without executing candidate code."""
    ledger = gate.parsed(os.environ.get("SUBS_BOT_PROVIDER_ISOLATED_SOURCE_LEDGER_JSON", ""))
    allowed = json.loads(os.environ.get("SUBS_BOT_PROVIDER_ISOLATED_SOURCE_CONTROLLERS_JSON", ""),
                         object_pairs_hook=provider.github._unique_json_object)
    provider.require(len(ledger) <= 32 and isinstance(allowed, list) and 0 < len(allowed) <= 16
                     and len(set(allowed)) == len(allowed)
                     and all(provider.match(provider.provider.REVISION, item) for item in allowed)
                     and os.environ["GITHUB_SHA"] in allowed)
    record = ledger.get(ref["runId"])
    fields = {"intentSha256", "manifestSha256", "runId", "controllerRevision", "targetSha256",
              "readbackRunId", "readbackRunAttempt", "readbackControllerRevision", "readbackSha256"}
    extra = {"candidateRevision", "reviewedPr", "workflowPath", "readbackWorkflowPath"}
    provider.require(isinstance(record, dict) and set(record) in (fields, fields | extra)
                     and all(provider.match(provider.provider.HEX, record[k]) for k in ("intentSha256", "manifestSha256", "targetSha256", "readbackSha256"))
                     and all(provider.match(provider.provider.DECIMAL, record[k]) for k in ("runId", "readbackRunId", "readbackRunAttempt"))
                     and record["controllerRevision"] in allowed and record["readbackControllerRevision"] in allowed
                     and (set(record) == fields or (provider.match(provider.provider.REVISION, record["candidateRevision"])
                         and provider.match(provider.provider.DECIMAL, record["reviewedPr"])
                         and record["workflowPath"] == ".github/workflows/worker-provider-reviewed-isolated-source.yml"
                         and record["readbackWorkflowPath"] == ".github/workflows/worker-provider-reviewed-isolated-source-readback.yml"))
                     and record["manifestSha256"] == ref["manifestSha256"] and record["targetSha256"] == ref["targetSha256"]
                     and ref["runAttempt"] == "1")
    store = IsolatedSourceStore(bucket, token, ref["runId"])
    store.verify()
    intent_raw, manifest_raw = store.read("source-intent.json"), store.read("source-manifest.json")
    provider.require(isinstance(intent_raw, bytes) and isinstance(manifest_raw, bytes)
                     and 0 < len(intent_raw) <= 65536 and 0 < len(manifest_raw) <= 65536
                     and sha256(intent_raw).hexdigest() == record["intentSha256"]
                     and sha256(manifest_raw).hexdigest() == record["manifestSha256"])
    intent = provider.github._parse_object(intent_raw, archive.ERROR)
    manifest = provider.github._parse_object(manifest_raw, archive.ERROR)
    manifest_fields = {"version", "kind", "runId", "runAttempt", "controllerRevision", "target", "files"}
    identity_fields = {"candidateRevision", "reviewedPr", "workflowPath"}
    provider.require(set(manifest) == (manifest_fields | identity_fields if set(record) != fields else manifest_fields)
                     and type(manifest["version"]) is int and manifest["version"] == 1
                     and manifest["kind"] == "subs-bot-isolated-provider-source"
                     and manifest["runId"] == ref["runId"] and manifest["runAttempt"] == "1"
                     and manifest["controllerRevision"] == record["controllerRevision"]
                     and all(manifest[key] == record[key] for key in identity_fields if key in manifest)
                     and isinstance(manifest["files"], dict) and set(manifest["files"]) == {"provider-source-archive.zip"})
    target = provider.validate_config(manifest["target"])
    provider.require(target["environment"] == "rehearsal" and target["caller"] is None and provider.digest(target) == ref["targetSha256"])
    entry = manifest["files"]["provider-source-archive.zip"]
    provider.require(isinstance(entry, dict) and set(entry) == {"bytes", "sha256", "chunks"}
                     and type(entry["bytes"]) is int and 0 < entry["bytes"] <= provider.provenance.MAX_ZIP
                     and entry["sha256"] == target["build"]["archiveSha256"]
                     and isinstance(entry["chunks"], list) and 0 < len(entry["chunks"]) <= archive.MAX_CHUNKS
                     and all(isinstance(c, dict) and set(c) == {"bytes", "sha256"}
                             and type(c["bytes"]) is int and 0 < c["bytes"] <= archive.CHUNK_BYTES
                             and provider.match(provider.provider.HEX, c["sha256"]) for c in entry["chunks"]))
    plan = intent.get("plan")
    provider.require(set(intent) == {"version", "plan", "approvalSha256", "controllerRevision", "runId", "runAttempt", "status"}
                     and type(intent["version"]) is int and intent["version"] == 1 and intent["status"] == "started-unknown"
                     and intent["runId"] == record["runId"] and intent["runAttempt"] == "1"
                     and intent["controllerRevision"] == record["controllerRevision"] and isinstance(plan, dict)
                     and set(plan) == ({"version", "action", "operationId", "controllerRevision", "targetSha256", "build",
                                        "bucketSha256", "prefixState", "inventorySha256", "controllersSha256"}
                                       | (identity_fields if set(record) != fields else set()))
                     and type(plan["version"]) is int and plan["version"] == 1
                     and plan["prefixState"] == "intent-and-manifest-absent"
                     and all(provider.match(provider.provider.HEX, plan[k]) for k in ("inventorySha256", "controllersSha256"))
                     and plan.get("action") == "seal-isolated-provider-source" and plan.get("operationId") == ref["runId"]
                     and plan.get("controllerRevision") == record["controllerRevision"] and plan.get("targetSha256") == ref["targetSha256"]
                     and plan.get("bucketSha256") == provider.digest(bucket) and plan.get("build") == target["build"]
                     and all(plan[key] == record[key] for key in identity_fields if key in plan)
                     and intent["approvalSha256"] == provider.digest(plan))
    source = {k: record[k] for k in ("intentSha256", "manifestSha256", "runId", "controllerRevision")}
    source.update({key: record[key] for key in identity_fields if key in record})
    report = {"version": 1, "kind": "isolated-provider-source-readback", "status": "source-original-verified",
              "rehearsalCompletion": "not-evaluated", "operationId": ref["runId"], "manifestSha256": record["manifestSha256"],
              "targetSha256": record["targetSha256"], "seal": source, "readbackRunId": record["readbackRunId"],
              "readbackRunAttempt": record["readbackRunAttempt"], "readbackControllerRevision": record["readbackControllerRevision"],
              **({"readbackWorkflowPath": record["readbackWorkflowPath"]} if "readbackWorkflowPath" in record else {})}
    provider.require(provider.digest(report) == record["readbackSha256"])
    seal_path = record.get("workflowPath", ".github/workflows/worker-provider-isolated-source.yml")
    readback_path = record.get("readbackWorkflowPath", ".github/workflows/worker-provider-isolated-source-readback.yml")
    gh_token = os.environ["GH_TOKEN"]
    for run_id, attempt, revision, path, title in (
            (record["runId"], "1", record["controllerRevision"], seal_path, "Isolated Provider source seal " + ref["runId"]),
            (record["readbackRunId"], record["readbackRunAttempt"], record["readbackControllerRevision"], readback_path,
             f"Read isolated source {ref['runId']} 1 {record['manifestSha256']} {record['targetSha256']}")):
        run = provider.github._get_json(f"/actions/runs/{run_id}/attempts/{attempt}", gh_token)
        provider.require(str(run.get("id")) == run_id and str(run.get("run_attempt")) == attempt
                         and run.get("path") in (path, path + "@main", path + "@refs/heads/main")
                         and run.get("display_title") == title and run.get("head_sha") == revision and run.get("head_branch") == "main"
                         and run.get("event") == "workflow_dispatch" and (run.get("status"), run.get("conclusion")) == ("completed", "success")
                         and all(isinstance(run.get(k), dict) and run[k].get("id") == provider.github.REPOSITORY_ID for k in ("repository", "head_repository")))
        if revision != os.environ["GITHUB_SHA"]:
            comparison = provider.github.compare_commits_metadata(revision, os.environ["GITHUB_SHA"], gh_token)
            provider.require(comparison.get("status") == "ahead" and comparison.get("behind_by") == 0
                             and all(isinstance(comparison.get(k), dict) and comparison[k].get("sha") == revision for k in ("base_commit", "merge_base_commit")))
    run_id, attempt = record["readbackRunId"], record["readbackRunAttempt"]
    response = provider.github._get_json(f"/actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100", gh_token)
    jobs = response.get("jobs")
    provider.require(isinstance(jobs, list) and response.get("total_count") == len(jobs) == 1)
    job = jobs[0]
    provider.require(isinstance(job, dict) and job.get("name") == "readback" and str(job.get("run_id")) == run_id
                     and str(job.get("run_attempt")) == attempt and job.get("head_sha") == record["readbackControllerRevision"]
                     and (job.get("status"), job.get("conclusion")) == ("completed", "success") and isinstance(job.get("steps"), list))
    steps = [step for step in job["steps"] if isinstance(step, dict)
             and step.get("name") == "Independently verify the pinned original from private R2"]
    provider.require(len(steps) == 1 and (steps[0].get("status"), steps[0].get("conclusion")) == ("completed", "success"))
    return store, manifest, target


def source_ref(ref, target, token, root):
    bucket = gate.parsed(os.environ["SUBS_BOT_PROVIDER_ARCHIVE_TARGET_JSON"])
    if ref["kind"] == "isolated-source":
        store, manifest, archived = independent_isolated_source(ref, bucket, token)
        name = "provider-source-archive.zip"
    else:
        store = archive.PrivateProofStore(bucket, token, ref["runId"], ref["runAttempt"])
    if ref["kind"] == "complete":
        archive.verify_archive(store, ref["manifestSha256"])
        manifest = provider.github._parse_object(store.read("manifest.json"), archive.ERROR)
        proof = provider.github._parse_object(archive.read_record(store, manifest, "provider-rehearsal-proof.json"), archive.ERROR)
        archived = provider.validate_config(proof["target"])
        provider.require(proof.get("status") == "complete" and proof.get("productionMutation") is False
                         and proof.get("runId") == store.run_id and proof.get("runAttempt") == store.attempt
                         and provider.digest(proof) == manifest["proofSha256"]
                         and provider.github._parse_object(archive.read_record(store, manifest, "provider-rehearsal-target.json"), archive.ERROR) == archived)
        name = "provider-source-archive.zip"
    elif ref["kind"] == "partial":
        archive.verify_partial(store, ref["manifestSha256"])
        manifest = provider.github._parse_object(store.read("partial-manifest.json"), archive.ERROR)
        latest = manifest.get("latestCheckpoint")
        provider.require(isinstance(latest, dict))
        checkpoint = provider.github._parse_object(archive.read_record(store, manifest, latest["record"]), archive.ERROR)
        archived = provider.validate_config(checkpoint["target"])
        provider.require(checkpoint.get("version") == 2 and provider.digest(archived) == latest["targetSha256"]
                         and checkpoint["journal"].get("source") == archived["build"]
                         and checkpoint["journal"].get("targetSha256") == latest["targetSha256"]
                         and checkpoint["journal"].get("runId") == store.run_id and checkpoint["journal"].get("runAttempt") == store.attempt)
        name = f"subs-bot-provider-attempt-source-{store.run_id}-{store.attempt}/provider-source-archive.zip"
    if ref["kind"] != "isolated-source":
        archive_run(ref, manifest)
    provider.require(provider.digest(archived) == ref["targetSha256"] and archived["environment"] == "rehearsal" and archived["caller"] is None)
    builds = [item for item in provider.releases(target) if item["build"] == archived["build"]]
    provider.require(len(builds) == 1)
    requested = builds[0]
    provider.require(all(archived[key] == requested[key] for key in ("environment", "accountId", "service", "workersDevOrigin", "smoke"))
                     and all(archived[key] is None or archived[key] == requested[key]
                             for key in ("worker", "versionId", "activation", "container", "workflow")))
    build = archived["build"]
    source_run(build)
    original = root / "source.zip"
    with provider.provenance._write_private(original) as output:
        provider.require(archive.read_record(store, manifest, name, output) == build["archiveSha256"])
    extracted = root / "verified"
    extracted.mkdir(mode=0o700)
    provider.provenance._unpack(original, extracted)
    with provider.provider.checked_file(extracted / provider.provider.MANIFEST, provider.provider.MAX_METADATA).open("rb") as file:
        recorded = provider.provider.json_object(file)
    expected = provider.provider.release_manifest(extracted, build["revision"], requirements(build["revision"], root),
        ref=provider.github.MAIN_REF, run_id=build["runId"], run_attempt=build["runAttempt"])
    provider.require(recorded == expected and all(expected[key] == build[key] for key in provider.publication.MANIFEST_FIELDS))
    store.verify()
    return build["archiveSha256"]


def attest_r2():
    result, spec = diagnosed("context", checks)
    target = diagnosed("target", lambda: provider.read_config(os.environ.get("SUBS_BOT_PROVIDER_CONTROL_TARGET_JSON", "")))
    target_sha = provider.digest(target)
    provider.require(target_sha == os.environ.get("PROVIDER_HEAD_TARGET_SHA256")
                     and target["environment"] == "rehearsal" and target["caller"] is None
                     and target["build"]["runId"] == spec["providerCiRunId"]
                     and provider.digest({"operation": "publish", "target": target}) == spec["approvalSha256"])
    token = os.environ.get("SUBS_BOT_CF_PROVIDER_ARCHIVE_READ_TOKEN", "")
    found = set()
    for index, ref in enumerate(spec["archiveRefs"]):
        with tempfile.TemporaryDirectory(prefix=f".trusted-provider-source-{index}-", dir=os.environ["RUNNER_TEMP"]) as directory:
            found.add(diagnosed("archive-source", lambda: source_ref(ref, target, token, Path(directory)), index=index))
    def closure():
        provider.require(len(found) == len(spec["archiveRefs"]) == len(provider.releases(target))
                         and found == {release["build"]["archiveSha256"] for release in provider.releases(target)})
    diagnosed("archive-closure", closure)
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="ascii") as output:
        output.write("target_sha256=" + target_sha + "\n")
    print(json.dumps({**result, "status": "trusted-r2-readback", "providerMutation": False,
                      "registryMutation": False, "archiveMutation": False, "archiveReleases": len(found),
                      "simulatedArtifactUnavailability": True}, sort_keys=True))


def verify_registry(target, registry, mode):
    """Independently verify the immutable image; digest mode reads every blob."""
    provider.require(mode in {"tag", "digest-only"} and target["environment"] == "rehearsal" and target["caller"] is None)
    pull, build = registry.mint(), target["build"]
    digest_ref = "sha256:" + build["ociManifestSha256"]
    provider.require(registry.manifest(digest_ref, pull) == build["ociManifestSha256"])
    with tempfile.TemporaryDirectory(prefix=".trusted-provider-registry-", dir=os.environ["RUNNER_TEMP"]) as directory:
        scratch = Path(directory)
        auth = provider.publication._write_auth(scratch / "pull-auth.json", pull, registry.repository)
        image = f"{provider.publication.HOST}/{registry.repository}@{digest_ref}"
        if mode == "tag":
            tag = f"git-{build['revision']}-{build['ociManifestSha256'][:12]}"
            provider.require(registry.manifest(tag, pull) == build["ociManifestSha256"]
                             and provider.publication._config(scratch, image, auth) == build["ociConfigSha256"])
            return False
        output = scratch / "readback-oci.tar"
        def limit_file():
            resource.setrlimit(resource.RLIMIT_FSIZE, (provider.provider.MAX_IMAGE, provider.provider.MAX_IMAGE))
        try:
            subprocess.run([provider.publication.SKOPEO, "copy", "--quiet", "--preserve-digests", "--retry-times=0",
                            "--src-tls-verify=true", "--src-authfile", str(auth), "docker://" + image,
                            "oci-archive:" + str(output)], env=provider.publication._skopeo_env(scratch),
                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=900, check=True, preexec_fn=limit_file)
        except (OSError, subprocess.SubprocessError):
            raise provider.ProviderError("The independent OCI closure could not be read.") from None
        try:
            manifest, config = provider.provider.verify_image(output, build["revision"])
        except provider.provider.VERIFICATION_ERRORS:
            raise provider.ProviderError("The independent OCI closure did not match its source.") from None
        provider.require(manifest == build["ociManifestSha256"] and config == build["ociConfigSha256"])
        return True


def attest_provider():
    result, spec = diagnosed("context", checks)
    target = diagnosed("target", lambda: provider.read_config(os.environ.get("SUBS_BOT_PROVIDER_CONTROL_TARGET_JSON", "")))
    expected_target = os.environ.get("PROVIDER_HEAD_TARGET_SHA256", "")
    provider.require(provider.digest(target) == expected_target
                     and spec["approvalSha256"] == provider.digest({"operation": "publish", "target": target})
                     and target["environment"] == "rehearsal" and target["caller"] is None)
    api = diagnosed("provider-api", lambda: provider.ProviderAPI(target, os.environ.get("SUBS_BOT_CF_PROVIDER_WORKER_READ_TOKEN", ""),
                               os.environ.get("SUBS_BOT_CF_PROVIDER_CONTAINER_READ_TOKEN", "")))
    first = diagnosed("provider-state", lambda: provider.observe(api))
    if target.get("previous") is not None and target["activation"] is None:
        diagnosed("previous-terminal", lambda: provider.unbound_upgrade(api, first))
    else:
        provider.require(target["activation"] is not None)
        diagnosed("previous-terminal", lambda: provider.verify_smoke(api, first, config=target))
    caller = diagnosed("caller-state", lambda: provider.caller_state(api, target, allow_unbound=True))
    def stable():
        provider.require(caller == "unbound" and provider.observe(api) == first and provider.caller_state(api, target, allow_unbound=True) == caller)
    diagnosed("stable-state", stable)
    if target.get("previous") is not None and target["activation"] is None:
        diagnosed("previous-recheck", lambda: provider.unbound_upgrade(api, first))
    mode = os.environ.get("SUBS_BOT_PROVIDER_WITNESS_REGISTRY_MODE", "")
    registry = diagnosed("registry-client", lambda: provider.Registry(target, os.environ.get("SUBS_BOT_CF_PROVIDER_CONTAINER_READ_TOKEN", "")))
    all_blobs = diagnosed("registry", lambda: verify_registry(target, registry, mode))
    print(json.dumps({**result, "status": "trusted-provider-readback", "providerMutation": False,
                      "registryMutation": False, "registryMode": mode, "allReferencedBlobsVerified": all_blobs,
                      "simulatedArtifactUnavailability": True}, sort_keys=True))


if __name__ == "__main__":
    try:
        {"attest-r2": attest_r2, "attest-provider": attest_provider}[os.environ.get("PROVIDER_HEAD_PHASE", "")]()
    except Exception:
        print(json.dumps({"status": "stopped", "reason": "Trusted Provider evidence or isolated state did not independently verify."}))
        raise SystemExit(1) from None
