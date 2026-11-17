"""Seal an isolated Provider upgrade target without exporting its plaintext."""

from copy import deepcopy
from hashlib import sha256
import base64
import json
import os
from pathlib import Path
import re
import subprocess

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
    control.require(approved["mapping"] in {"provider-archive-target", "provider-live-target", "provider-live-age-identity"}
                    and env.get("GITHUB_WORKFLOW_REF") == transfer.CANDIDATE_WORKFLOW)
    attestation = transfer.attest_provider_source(env)
    old = control.read_config(env.get("SUBS_BOT_PROVIDER_CONTROL_TARGET_JSON", ""))
    control.require(control.digest(old) == attestation["targetSha256"]
                    and control.match(control.provider.DECIMAL, env.get("SUBS_BOT_PROVIDER_CI_RUN_ID", "")))
    if approved["mapping"] == "provider-live-age-identity":
        return seal_age_identity(env, approved, attestation)
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


def seal_age_identity(env, approved, attestation):
    """Generate on the hosted runner and expose only public recipient and sealed identity."""
    root = Path(env.get("RUNNER_TEMP", ""))
    binary = root / "provider-age/usr/bin/age-keygen"
    control.require(root.is_absolute() and root.is_dir() and not root.is_symlink()
                    and binary.is_file() and not binary.is_symlink())
    archive_env = {**env, "TRANSFER_MAPPING": "provider-archive-age-identity",
                   "TRANSFER_DESTINATION_ENVIRONMENT": "subs-bot-provider-archive-head-isolation",
                   "TRANSFER_DESTINATION_ENVIRONMENT_ID": env.get("TRANSFER_AGE_ARCHIVE_ENVIRONMENT_ID", ""),
                   "TRANSFER_DESTINATION_KEY_PIN": env.get("TRANSFER_AGE_ARCHIVE_KEY_PIN", ""),
                   "TRANSFER_KEY_ID": env.get("TRANSFER_AGE_ARCHIVE_KEY_ID", ""),
                   "TRANSFER_PUBLIC_KEY": env.get("TRANSFER_AGE_ARCHIVE_PUBLIC_KEY", "")}
    archive_key = transfer.gate(archive_env)
    control.require(archive_key["mapping"] == "provider-archive-age-identity")
    options = {"stdout": subprocess.PIPE, "stderr": subprocess.DEVNULL, "timeout": 30,
               "check": False, "env": {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}}
    generated = subprocess.run([str(binary)], stdin=subprocess.DEVNULL, **options)
    control.require(generated.returncode == 0 and 0 < len(generated.stdout) <= 1024)
    identities = [line for line in generated.stdout.splitlines() if line.startswith(b"AGE-SECRET-KEY-1")]
    control.require(len(identities) == 1 and re.fullmatch(rb"AGE-SECRET-KEY-1[0-9A-Z]{20,100}", identities[0]))
    identity = identities[0]
    derived = subprocess.run([str(binary), "-y"], input=identity + b"\n", **options)
    control.require(derived.returncode == 0 and re.fullmatch(rb"age1[023456789acdefghjklmnpqrstuvwxyz]{58}\n", derived.stdout))
    recipient = derived.stdout[:-1].decode("ascii")
    body = control.canonical({"encrypted_value": base64.b64encode(transfer.seal(identity, approved["publicKey"])).decode("ascii"),
                              "key_id": approved["keyId"]})
    path = root / "provider-candidate-target.json"
    with path.open("xb") as output:
        os.chmod(path, 0o600)
        output.write(body)
    archive_body = control.canonical({"encrypted_value": base64.b64encode(transfer.seal(identity, archive_key["publicKey"])).decode("ascii"),
                                      "key_id": archive_key["keyId"]})
    archive_path = root / "provider-candidate-age-archive.json"
    with archive_path.open("xb") as output:
        os.chmod(archive_path, 0o600)
        output.write(archive_body)
    control.github.require_current_main(env["GITHUB_SHA"])
    return {"status": "sealed-age-identity-only", "mapping": approved["mapping"], "runId": approved["runId"],
            "controllerRevision": approved["revision"], "sourceTargetSha256": attestation["targetSha256"],
            "recipient": recipient, "recipientSha256": sha256(recipient.encode("ascii")).hexdigest(),
            "destinationKeyPinSha256": approved["keyPinSha256"], "ciphertextPayloadSha256": sha256(body).hexdigest(),
            "archiveKeyPinSha256": archive_key["keyPinSha256"], "archiveCiphertextPayloadSha256": sha256(archive_body).hexdigest(),
            "destinationWritten": False, "productionMutation": False}


if __name__ == "__main__":
    try:
        os.umask(0o077)
        print(json.dumps(create(os.environ), sort_keys=True))
    except Exception:
        raise SystemExit("Candidate target sealing stopped without a destination write.") from None
