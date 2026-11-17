"""Seal an isolated Provider upgrade target without exporting its plaintext."""

from copy import deepcopy
from hashlib import sha256
import base64
import json
import os
from pathlib import Path

import isolation_sealed_transfer as transfer
import prepare_provider_artifact as provenance
import production_provider as control


def candidate(old, build):
    old = control.validate_config(old)
    control.require(old["environment"] == "rehearsal" and old["caller"] is None
                    and all(old[key] is not None for key in ("worker", "versionId", "activation", "container", "workflow"))
                    and old["build"]["revision"] != build["revision"])
    value = deepcopy(old)
    value.pop("forwardRecovery", None)
    value.update({"build": build, "versionId": None, "activation": None, "workflow": None, "previous": old})
    value = control.validate_config(value)
    control.require(len(control.releases(value)) <= 9)
    return value


def create(env):
    approved = transfer.gate(env)
    control.require(approved["mapping"] in {"provider-archive-target", "provider-live-target"}
                    and env.get("GITHUB_WORKFLOW_REF") == transfer.CANDIDATE_WORKFLOW)
    attestation = transfer.attest_provider_source(env)
    old = control.read_config(env.get("SUBS_BOT_PROVIDER_CONTROL_TARGET_JSON", ""))
    control.require(control.digest(old) == attestation["targetSha256"]
                    and control.match(control.provider.DECIMAL, env.get("SUBS_BOT_PROVIDER_CI_RUN_ID", "")))
    build = provenance.prepare(provider_revision=env["GITHUB_SHA"])
    value = candidate(old, build)
    raw = control.canonical(value)
    control.require(0 < len(raw) <= transfer.MAX_SECRET)
    body = control.canonical({"encrypted_value": base64.b64encode(transfer.seal(raw, approved["publicKey"])).decode("ascii"),
                              "key_id": approved["keyId"]})
    root = Path(env.get("RUNNER_TEMP", ""))
    control.require(root.is_absolute() and root.is_dir() and not root.is_symlink())
    path = root / "provider-candidate-target.json"
    with path.open("xb") as output:
        os.chmod(path, 0o600)
        output.write(body)
    control.github.require_current_main(env["GITHUB_SHA"])
    return {"status": "sealed-candidate-only", "mapping": approved["mapping"], "runId": approved["runId"],
            "controllerRevision": approved["revision"], "sourceTargetSha256": attestation["targetSha256"],
            "candidateTargetSha256": control.digest(value), "approvalSha256": control.digest({"operation": "publish-digest", "target": value}),
            "witnessApprovalSha256": control.digest({"operation": "publish", "target": value}),
            "destinationKeyPinSha256": approved["keyPinSha256"], "ciphertextPayloadSha256": sha256(body).hexdigest(),
            "destinationWritten": False, "productionMutation": False}


if __name__ == "__main__":
    try:
        os.umask(0o077)
        print(json.dumps(create(os.environ), sort_keys=True))
    except Exception:
        raise SystemExit("Candidate target sealing stopped without a destination write.") from None
