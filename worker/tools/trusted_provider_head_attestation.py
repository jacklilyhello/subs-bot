"""Independent read-only trusted-main verification of Provider archive and state."""

import base64
from hashlib import sha1
import json
import os
from pathlib import Path
import re
import tempfile

import archive_production_provider as archive
import production_provider as provider
import trusted_provider_head_gate as gate


JOB_STEPS = {"Reviewed Provider source verification": "Verify current and previous archived sources"}


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
        value = provider.github._get_json(f"/compare/{build['revision']}...{os.environ['GITHUB_SHA']}?per_page=1", os.environ["GH_TOKEN"])
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
        comparison = provider.github._get_json(f"/compare/{revision}...{os.environ['GITHUB_SHA']}?per_page=1", os.environ["GH_TOKEN"])
        provider.require(comparison.get("status") == "ahead" and comparison.get("behind_by") == 0
                         and all(isinstance(comparison.get(key), dict) and comparison[key].get("sha") == revision
                                 for key in ("base_commit", "merge_base_commit")))


def source_ref(ref, target, token, root):
    bucket = gate.parsed(os.environ["SUBS_BOT_PROVIDER_ARCHIVE_TARGET_JSON"])
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
    else:
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
    result, spec = checks()
    target = provider.read_config(os.environ.get("SUBS_BOT_PROVIDER_CONTROL_TARGET_JSON", ""))
    target_sha = provider.digest(target)
    provider.require(target_sha == os.environ.get("PROVIDER_HEAD_TARGET_SHA256")
                     and target["environment"] == "rehearsal" and target["caller"] is None
                     and target["build"]["runId"] == spec["providerCiRunId"]
                     and provider.digest({"operation": "publish", "target": target}) == spec["approvalSha256"])
    token = os.environ.get("SUBS_BOT_CF_PROVIDER_ARCHIVE_READ_TOKEN", "")
    found = set()
    for index, ref in enumerate(spec["archiveRefs"]):
        with tempfile.TemporaryDirectory(prefix=f".trusted-provider-source-{index}-", dir=os.environ["RUNNER_TEMP"]) as directory:
            found.add(source_ref(ref, target, token, Path(directory)))
    provider.require(len(found) == len(spec["archiveRefs"]) == len(provider.releases(target))
                     and found == {release["build"]["archiveSha256"] for release in provider.releases(target)})
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="ascii") as output:
        output.write("target_sha256=" + target_sha + "\n")
    print(json.dumps({**result, "status": "trusted-r2-readback", "providerMutation": False,
                      "registryMutation": False, "archiveMutation": False, "archiveReleases": len(found),
                      "simulatedArtifactUnavailability": True}, sort_keys=True))


def attest_provider():
    result, spec = checks()
    target = provider.read_config(os.environ.get("SUBS_BOT_PROVIDER_CONTROL_TARGET_JSON", ""))
    expected_target = os.environ.get("PROVIDER_HEAD_TARGET_SHA256", "")
    provider.require(provider.digest(target) == expected_target
                     and spec["approvalSha256"] == provider.digest({"operation": "publish", "target": target})
                     and target["environment"] == "rehearsal" and target["caller"] is None)
    api = provider.ProviderAPI(target, os.environ.get("SUBS_BOT_CF_PROVIDER_WORKER_READ_TOKEN", ""),
                               os.environ.get("SUBS_BOT_CF_PROVIDER_CONTAINER_READ_TOKEN", ""))
    first = provider.observe(api)
    if target.get("previous") is not None and target["activation"] is None:
        provider.unbound_upgrade(api, first)
    else:
        provider.require(target["activation"] is not None)
        provider.verify_smoke(api, first, config=target)
    caller = provider.caller_state(api, target, allow_unbound=True)
    provider.require(caller == "unbound" and provider.observe(api) == first and provider.caller_state(api, target, allow_unbound=True) == caller)
    if target.get("previous") is not None and target["activation"] is None:
        provider.unbound_upgrade(api, first)
    registry = provider.Registry(target, os.environ.get("SUBS_BOT_CF_PROVIDER_CONTAINER_READ_TOKEN", ""))
    pull = registry.mint()
    build = target["build"]
    tag = f"git-{build['revision']}-{build['ociManifestSha256'][:12]}"
    with tempfile.TemporaryDirectory(prefix=".trusted-provider-registry-", dir=os.environ["RUNNER_TEMP"]) as directory:
        scratch = Path(directory)
        auth = provider.publication._write_auth(scratch / "pull-auth.json", pull, registry.repository)
        image = f"{provider.publication.HOST}/{registry.repository}@sha256:{build['ociManifestSha256']}"
        provider.require(registry.manifest(tag, pull) == build["ociManifestSha256"]
                         and registry.manifest("sha256:" + build["ociManifestSha256"], pull) == build["ociManifestSha256"]
                         and provider.publication._config(scratch, image, auth) == build["ociConfigSha256"])
    print(json.dumps({**result, "status": "trusted-provider-readback", "providerMutation": False,
                      "registryMutation": False, "simulatedArtifactUnavailability": True}, sort_keys=True))


if __name__ == "__main__":
    try:
        {"attest-r2": attest_r2, "attest-provider": attest_provider}[os.environ.get("PROVIDER_HEAD_PHASE", "")]()
    except Exception:
        print(json.dumps({"status": "stopped", "reason": "Trusted Provider evidence or isolated state did not independently verify."}))
        raise SystemExit(1) from None
