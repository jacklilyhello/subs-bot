"""Isolation-only content-addressed Provider image publication primitives.

These helpers are not an entry point. A reviewed workflow must first persist and
independently read back an exact single-use intent, then invoke this code once in
a fresh runner. A failed/unknown result is never automatically retried.
"""

import os
from pathlib import Path
import resource
import subprocess
import tempfile

import production_provider as control


def verify_remote_closure(target, registry_token):
    """Download and verify every OCI blob in a fresh registry-read-only job."""
    target = control.validate_config(target)
    control.require(target["environment"] == "rehearsal" and target["caller"] is None)
    build = target["build"]
    registry = control.Registry(target, registry_token)
    pull = registry.mint()
    digest_ref = "sha256:" + build["ociManifestSha256"]
    control.require(registry.manifest(digest_ref, pull) == build["ociManifestSha256"])
    with tempfile.TemporaryDirectory(prefix=".provider-digest-closure-", dir=os.environ["RUNNER_TEMP"]) as temporary:
        scratch = Path(temporary)
        auth = control.publication._write_auth(scratch / "pull-auth.json", pull, registry.repository)
        reference = f"{control.publication.HOST}/{registry.repository}@{digest_ref}"
        output = scratch / "readback-oci.tar"
        def limit_file():
            resource.setrlimit(resource.RLIMIT_FSIZE, (control.provider.MAX_IMAGE, control.provider.MAX_IMAGE))
        try:
            subprocess.run([control.publication.SKOPEO, "copy", "--quiet", "--preserve-digests", "--retry-times=0",
                            "--src-tls-verify=true", "--src-authfile", str(auth), "docker://" + reference,
                            "oci-archive:" + str(output)], env=control.publication._skopeo_env(scratch),
                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=900, check=True, preexec_fn=limit_file)
        except (OSError, subprocess.SubprocessError):
            raise control.ProviderError("The independent OCI closure readback failed.") from None
        try:
            manifest, config = control.provider.verify_image(output, build["revision"])
        except control.provider.VERIFICATION_ERRORS:
            raise control.ProviderError("The independent OCI closure did not match its source.") from None
        control.require(manifest == build["ociManifestSha256"] and config == build["ociConfigSha256"])
    return {"manifestSha256": manifest, "configSha256": config, "allReferencedBlobsVerified": True}


def observe(target, worker_token, registry_token):
    control.require(target["environment"] == "rehearsal" and target["caller"] is None)
    api = control.ProviderAPI(target, worker_token, registry_token)
    first = control.observe(api)
    if target.get("previous") is not None and target["activation"] is None:
        control.unbound_upgrade(api, first)
    else:
        control.require(target["activation"] is not None)
        control.verify_smoke(api, first, config=target)
    caller = control.caller_state(api, target, allow_unbound=True)
    control.require(caller == "unbound" and control.observe(api) == first
                    and control.caller_state(api, target, allow_unbound=True) == caller)
    if target.get("previous") is not None and target["activation"] is None:
        control.unbound_upgrade(api, first)
    registry = control.Registry(target, registry_token)
    pull = registry.mint()
    expected = target["build"]["ociManifestSha256"]
    observed = registry.manifest("sha256:" + expected, pull, allow_missing=True)
    control.require(observed is None or observed == expected)
    return {"dependencySha256": control.digest({"target": target, "state": first, "callerState": caller}),
            "manifestSha256": observed}


def intent(target, refs, state, run_id, revision):
    simulation = os.environ.get("SUBS_BOT_PROVIDER_SIMULATE_ARTIFACT_UNAVAILABLE", "0")
    control.require(control.match(control.provider.DECIMAL, run_id) and control.match(control.provider.REVISION, revision)
                    and simulation in {"0", "1"}
                    and isinstance(state, dict) and set(state) == {"dependencySha256", "manifestSha256"}
                    and control.match(control.provider.HEX, state["dependencySha256"])
                    and (state["manifestSha256"] is None or state["manifestSha256"] == target["build"]["ociManifestSha256"]))
    return {"version": 1, "kind": "isolated-provider-digest-intent", "operation": "publish-digest",
            "runId": run_id, "runAttempt": "1", "controllerRevision": revision,
            "targetSha256": control.digest(target), "archiveRefsSha256": control.digest(refs),
            "approvalSha256": control.digest({"operation": "publish-digest", "target": target}),
            "simulatedActionsUnavailable": simulation == "1", "prestate": state, "status": "started-unknown"}


def publish_once(target, refs, archive, prior_intent, verified_intent_sha, worker_read, registry_read, registry_write):
    """One digest-only copy after a trusted workflow authenticates a persisted intent.

    The `verified_intent_sha` must be the exact direct output of a separate R2-only
    write-and-readback job. This helper never accepts a mutable tag destination.
    """
    target = control.validate_config(target)
    control.require(isinstance(prior_intent, dict) and isinstance(refs, list) and 0 < len(refs) <= 9)
    expected = intent(target, refs, prior_intent.get("prestate"), os.environ["GITHUB_RUN_ID"], os.environ["GITHUB_SHA"])
    control.require(prior_intent == expected and control.match(control.provider.HEX, verified_intent_sha)
                    and control.digest(prior_intent) == verified_intent_sha
                    and os.environ.get("SUBS_BOT_PROVIDER_DIGEST_APPROVAL") == expected["approvalSha256"]
                    and os.environ.get("GITHUB_RUN_ATTEMPT") == "1")
    control.guard_sources(target)
    state = observe(target, worker_read, registry_read)
    control.require(state == expected["prestate"], "The approved isolated prestate changed before publication.")
    build = target["build"]
    archive = control.provider.checked_file(Path(archive), control.provider.MAX_IMAGE)
    control.require(control.provider.checksum(archive) == build["ociArchiveSha256"])
    registry = control.Registry(target, registry_write)
    read = control.Registry(target, registry_read)
    pull = read.mint()
    digest_ref = "sha256:" + build["ociManifestSha256"]
    control.require(read.manifest(digest_ref, pull, allow_missing=True) == state["manifestSha256"])
    status = "verified-existing"
    with tempfile.TemporaryDirectory(prefix=".provider-digest-publication-", dir=os.environ["RUNNER_TEMP"]) as temporary:
        scratch = Path(temporary)
        reference = f"{control.publication.HOST}/{registry.repository}@{digest_ref}"
        if state["manifestSha256"] is None:
            push_auth = control.publication._write_auth(scratch / "push-auth.json", registry.mint(push=True), registry.repository)
            control.guard_sources(target)
            control.require(observe(target, worker_read, registry_read) == state)
            # This is the only external mutation. Any error leaves the durable
            # started-unknown intent in place and must not trigger another copy.
            control.publication._copy_image(scratch, archive, "docker://" + reference, push_auth, digest_ref)
            status = "published-digest"
        pull_auth = control.publication._write_auth(scratch / "pull-auth.json", pull, registry.repository)
        control.require(read.manifest(digest_ref, pull) == build["ociManifestSha256"]
                        and control.publication._config(scratch, reference, pull_auth) == build["ociConfigSha256"])
    return {"status": status, "manifestSha256": build["ociManifestSha256"], "configSha256": build["ociConfigSha256"],
            "prestateSha256": control.digest(state), "providerMutation": False, "registryMutation": status == "published-digest"}
