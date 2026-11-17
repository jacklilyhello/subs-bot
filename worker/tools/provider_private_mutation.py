"""One-shot isolated Provider mutations with encrypted response observations.

Not an entry point. A trusted workflow must persist an exact intent, independently
read it back, and pass its digest directly from the readback job. Failure or runner
loss leaves that intent unresolved; neither this module nor its caller retries it.
"""

from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import tempfile

import production_provider as control
import production_provider_rehearsal as rehearsal
import provider_private_handoff as handoff
import provider_source_transfer as transfer

OPERATIONS = {"prepare-image", "stage", "activate", "smoke"}


def intent(target, refs, operation, state, run_id, revision):
    preparation = os.environ.get("SUBS_BOT_PROVIDER_IMAGE_PREPARATION_SHA256", "") if operation == "stage" else None
    control.require(operation in OPERATIONS and isinstance(state, dict)
                    and set(state) == {"stateSha256", "callerState"}
                    and control.match(control.provider.HEX, state["stateSha256"]) and state["callerState"] == "unbound"
                    and control.match(control.provider.DECIMAL, run_id) and control.match(control.provider.REVISION, revision)
                    and (preparation is None or control.match(control.provider.HEX, preparation)))
    return {"version": 1, "kind": "isolated-provider-mutation-intent", "operation": operation,
            "runId": run_id, "runAttempt": "1", "controllerRevision": revision,
            "targetSha256": control.digest(target), "archiveRefsSha256": control.digest(refs),
            "approvalSha256": control.digest({"operation": operation, "target": target}),
            "imagePreparationSha256": preparation, "prestate": state, "status": "started-unknown", **transfer.execution_identity(revision)}


def observe(target, operation, worker_token, container_token):
    control.require(operation in OPERATIONS and target["environment"] == "rehearsal" and target["caller"] is None)
    api = control.ProviderAPI(target, worker_token, container_token)
    first = control.observe(api)
    if operation in {"prepare-image", "stage"}:
        control.require(target["versionId"] is None and target.get("previous") is not None)
        control.unbound_upgrade(api, first)
    elif operation == "activate":
        control.require(target["versionId"] is not None and target["activation"] is None and target.get("previous") is not None)
        control.unbound_upgrade(api, first)
    else:
        control.require(all(target[key] is not None for key in ("versionId", "activation", "container", "workflow"))
                        and first["instance"] is None)
    caller = control.caller_state(api, target, allow_unbound=True)
    control.require(caller == "unbound" and control.observe(api) == first
                    and control.caller_state(api, target, allow_unbound=True) == caller)
    return {"stateSha256": control.digest(first), "callerState": caller}


class PreparedImage(control.PublishedImage):
    """The image preparation was separately recorded and independently read back."""
    def prepare(self, guard):
        control.require(control.match(control.provider.HEX, os.environ.get("SUBS_BOT_PROVIDER_IMAGE_PREPARATION_SHA256", "")))
        guard()


class GuardedPreparation(control.PublishedImage):
    """Repeat only a confirmed pending preparation, rechecking before each POST."""
    def prepare(self, guard):
        body = json.dumps({"image": self.reference}, separators=(",", ":")).encode("ascii")
        deadline = control.stage.monotonic() + control.stage.PREPARE_SECONDS
        while control.stage.monotonic() < deadline:
            guard()
            status, envelope = control.stage._json_request(
                self._url, self._opener, self._token, control.stage.PREPARE_ERROR,
                content_type="application/json", body=body, statuses=(200, 202))
            result = envelope["result"]
            control.require(isinstance(result, dict) and result.get("image") == self.reference)
            if status == 200 and result.get("status") == "ready":
                digest = result.get("artifact_digest")
                control.require(digest is None or (isinstance(digest, str) and control.publication.MANIFEST_DIGEST.fullmatch(digest)))
                return
            control.require(status == 202 and result.get("status") == "pending")
            control.stage.sleep(4)
        raise control.ProviderError("Image preparation remained unresolved; do not retry.")


class GuardedObservedAPI(rehearsal.ObservedAPI):
    def __init__(self, target, sink, operation, guard):
        super().__init__(target, sink, operation)
        self.write_guard = guard

    def _write(self, path, body, *, container=False, method="POST"):
        self.write_guard()
        return super()._write(path, body, container=container, method=method)

    def upload(self, module):
        self.write_guard()
        return super().upload(module)


def recipient():
    value = os.environ.get("SUBS_BOT_PROVIDER_SOURCE_RECIPIENT", "")
    expected = os.environ.get("SUBS_BOT_PROVIDER_SOURCE_RECIPIENT_SHA256", "")
    control.require(control.match(control.provider.HEX, expected) and sha256(value.encode("ascii")).hexdigest() == expected)
    return transfer.recipient()


def write_encrypted(kind, value):
    control.require(kind in {"observation", "confirmed", "next-target"} and isinstance(value, dict))
    data = control.canonical(value)
    control.require(0 < len(data) <= handoff.MAX_PLAINTEXT)
    result = subprocess.run([str(handoff.age_binary("age")), "--encrypt", "--recipient", recipient()], input=data,
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=30, check=False,
                            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
    control.require(result.returncode == 0 and 0 < len(result.stdout) <= handoff.MAX_CIPHERTEXT)
    path = Path(os.environ["RUNNER_TEMP"]) / ("provider-mutation-" + kind + ".age")
    with control.provenance._write_private(path) as output:
        output.write(result.stdout)
    return sha256(result.stdout).hexdigest()


def dispatch(target, refs, operation, original, verified_intent_sha, archive, module):
    """Run one explicit operation after a trusted R2-only intent readback job."""
    target = control.validate_config(target)
    control.require(operation in OPERATIONS and target["environment"] == "rehearsal" and target["caller"] is None
                    and isinstance(original, dict) and isinstance(refs, list) and 0 < len(refs) <= 9)
    expected = intent(target, refs, operation, original.get("prestate"), os.environ["GITHUB_RUN_ID"], os.environ["GITHUB_SHA"])
    control.require(original == expected and control.match(control.provider.HEX, verified_intent_sha)
                    and control.digest(original) == verified_intent_sha and os.environ.get("GITHUB_RUN_ATTEMPT") == "1"
                    and os.environ.get("SUBS_BOT_PROVIDER_MUTATION_APPROVAL") == expected["approvalSha256"])
    control.guard_sources(target)
    worker = os.environ.get("SUBS_BOT_CF_PROVIDER_WORKER_TOKEN", "")
    container = os.environ.get("SUBS_BOT_CF_PROVIDER_CONTAINER_TOKEN", "")
    control.require(observe(target, operation, worker, container) == expected["prestate"],
                    "The isolated Provider prestate changed before mutation.")
    archive = control.provider.checked_file(Path(archive), control.provider.MAX_IMAGE)
    control.require(control.provider.checksum(archive) == target["build"]["ociArchiveSha256"]
                    and sha256(module).hexdigest() == target["build"]["workerSha256"])
    observations = []
    def sink(observation):
        control.require(not observations and isinstance(observation, dict) and observation.get("kind") == "response-only")
        observations.append(observation)
        # This must happen before run_operation performs any subsequent readback.
        write_encrypted("observation", {"intentSha256": verified_intent_sha, "observation": observation})
    def immediate_guard():
        control.guard_sources(target)
        control.require(observe(target, operation, worker, container) == expected["prestate"],
                        "The Provider caller or prior state changed before mutation.")
    api = GuardedObservedAPI(target, sink, operation, immediate_guard)
    with tempfile.TemporaryDirectory(prefix=".provider-private-mutation-", dir=os.environ["RUNNER_TEMP"]) as directory:
        scratch = Path(directory)
        control.verify_previous_archives(target, scratch)
        guard = lambda: control.guard_sources(target)
        if operation == "prepare-image":
            image = GuardedPreparation(target, container, scratch)
            image.verify()
            image.prepare(immediate_guard)
            sink({"kind": "response-only", "method": "POST", "path": "/containers/image-preparations",
                  "imageManifestSha256": target["build"]["ociManifestSha256"], "status": "ready"})
            result = {**control.observe(api), "imagePrepared": True}
        else:
            image = PreparedImage(target, container, scratch) if operation == "stage" else control.PublishedImage(target, container, scratch)
            result = control.run_operation(api, operation, module, image, guard)
    control.require(len(observations) == 1)
    return write_encrypted("confirmed", {"intentSha256": verified_intent_sha, "target": target,
                                         "operation": operation, "observation": observations[0], "result": result})
