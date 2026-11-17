"""Seal a fixed project-isolation configuration for one GitHub Environment.

The trusted-main source job validates the necessary source configurations and
seals only the selected value. The output contains ciphertext, not plaintext.
This tool does not create environments, tokens, or destination secrets.
"""
import base64
import ctypes
import hmac
from hashlib import sha256
from http.client import HTTPSConnection
import json
import os
from pathlib import Path
import re
from datetime import datetime, timezone
from urllib.parse import quote

import prepare_isolation_artifact as github
from production_target import TEST_BOT_ID, canonical, parsed, require

WORKFLOW = github.REPOSITORY + "/.github/workflows/worker-isolation-sealed-transfer.yml@" + github.MAIN_REF
MAX_SECRET = 48 * 1024
MAPPINGS = {
    "backup-target": ("subs-bot-isolation", "subs-bot-backup-head-isolation", "SUBS_BOT_CF_ISOLATION_TARGET_JSON", "SUBS_BOT_CF_ISOLATION_TARGET_JSON", False),
    "backup-keys": ("subs-bot-isolation", "subs-bot-backup-head-isolation", "SUBS_BOT_CONTROL_DRILL_KEYS", "SUBS_BOT_CONTROL_DRILL_KEYS", False),
    "backup-bot": ("subs-bot-isolation", "subs-bot-backup-head-isolation", "SUBS_BOT_TELEGRAM_TEST_CONFIG", "SUBS_BOT_TELEGRAM_TEST_CONFIG", False),
    "provider-archive-location": ("subs-bot-isolation", "subs-bot-provider-archive-head-isolation", "SUBS_BOT_CF_ISOLATION_TARGET_JSON", "SUBS_BOT_PROVIDER_ARCHIVE_TARGET_JSON", True),
    "provider-live-location": ("subs-bot-isolation", "subs-bot-provider-head-isolation", "SUBS_BOT_CF_ISOLATION_TARGET_JSON", "SUBS_BOT_PROVIDER_ARCHIVE_TARGET_JSON", True),
    "provider-archive-target": ("subs-bot-provider-isolation", "subs-bot-provider-archive-head-isolation", "SUBS_BOT_PROVIDER_CONTROL_TARGET_JSON", "SUBS_BOT_PROVIDER_CONTROL_TARGET_JSON", False),
    "provider-live-target": ("subs-bot-provider-isolation", "subs-bot-provider-head-isolation", "SUBS_BOT_PROVIDER_CONTROL_TARGET_JSON", "SUBS_BOT_PROVIDER_CONTROL_TARGET_JSON", False),
}


def key_plan(env):
    mapping = env.get("TRANSFER_MAPPING", "")
    require(mapping in MAPPINGS)
    source, destination, source_name, destination_name, _projection = MAPPINGS[mapping]
    revision, run_id = env.get("GITHUB_SHA", ""), env.get("GITHUB_RUN_ID", "")
    require(env.get("GITHUB_REPOSITORY") == github.REPOSITORY and env.get("GITHUB_REPOSITORY_ID") == str(github.REPOSITORY_ID)
            and env.get("GITHUB_REF") == github.MAIN_REF and env.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
            and env.get("RUNNER_ENVIRONMENT") == "github-hosted" and env.get("GITHUB_WORKFLOW_REF") == WORKFLOW
            and env.get("GITHUB_WORKFLOW_SHA") == revision and re.fullmatch(r"[a-f0-9]{40}", revision or "")
            and re.fullmatch(r"[1-9][0-9]{0,19}", run_id or "") and env.get("GITHUB_RUN_ATTEMPT") == "1")
    environment_id, key_id, encoded = env.get("TRANSFER_DESTINATION_ENVIRONMENT_ID", ""), env.get("TRANSFER_KEY_ID", ""), env.get("TRANSFER_PUBLIC_KEY", "")
    require(re.fullmatch(r"[1-9][0-9]{0,19}", environment_id or "")
            and re.fullmatch(r"[A-Za-z0-9_-]{1,128}", key_id or "") and isinstance(encoded, str) and len(encoded) <= 128)
    key = base64.b64decode(encoded, validate=True)
    require(len(key) == 32 and base64.b64encode(key).decode("ascii") == encoded)
    statement = {"version": 1, "repositoryId": github.REPOSITORY_ID, "environment": destination, "environmentId": environment_id,
                 "keyId": key_id, "publicKey": encoded}
    pin = sha256(canonical(statement)).hexdigest()
    github.require_current_main(revision)
    return {"mapping": mapping, "source": source, "destination": destination, "sourceName": source_name,
            "destinationName": destination_name, "environmentId": environment_id, "keyId": key_id, "publicKey": key,
            "keyPinSha256": pin, "revision": revision, "runId": run_id}


def gate(env):
    approved = key_plan(env)
    require(env.get("TRANSFER_SOURCE_ENVIRONMENT") == approved["source"]
            and env.get("TRANSFER_DESTINATION_ENVIRONMENT") == approved["destination"]
            and env.get("TRANSFER_SOURCE_NAME") == approved["sourceName"]
            and env.get("TRANSFER_DESTINATION_NAME") == approved["destinationName"]
            and re.fullmatch(r"[a-f0-9]{64}", env.get("TRANSFER_DESTINATION_KEY_PIN", "") or "")
            and env["TRANSFER_DESTINATION_KEY_PIN"] == approved["keyPinSha256"],
            "The independently protected destination public-key pin differs.")
    return approved


def operator_source_metadata(env, source, required, *, now=None):
    """Validate a short-lived operator attestation of GitHub metadata.

    The workflow token cannot list Environment secrets. The operator must
    independently re-read this metadata before the destination PUT as well.
    """
    raw = env.get("TRANSFER_SOURCE_METADATA_JSON", "")
    value = parsed(raw)
    require(set(value) == {"version", "repositoryId", "environment", "environmentId", "branchPolicies",
                           "environmentSecrets", "repositoryConflicts", "checkedAt"}
            and type(value["version"]) is int and value["version"] == 1
            and value["repositoryId"] == github.REPOSITORY_ID and value["environment"] == source
            and value["environmentId"] == env.get("TRANSFER_SOURCE_ENVIRONMENT_ID")
            and re.fullmatch(r"[1-9][0-9]{0,19}", value["environmentId"] or "")
            and value["branchPolicies"] == ["main"] and value["repositoryConflicts"] == []
            and isinstance(value["environmentSecrets"], list) and type(value["checkedAt"]) is int)
    names = {}
    for item in value["environmentSecrets"]:
        require(isinstance(item, dict) and set(item) == {"name", "updatedAt"}
                and isinstance(item["name"], str) and item["name"] not in names
                and isinstance(item["updatedAt"], str)
                and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", item["updatedAt"]))
        names[item["name"]] = item["updatedAt"]
    require(set(names) == set(required))
    timestamp = int(datetime.now(timezone.utc).timestamp()) if now is None else now
    require(value["checkedAt"] <= timestamp <= value["checkedAt"] + 1800,
            "The independently checked source metadata is stale.")
    digest = sha256(canonical(value)).hexdigest()
    require(re.fullmatch(r"[a-f0-9]{64}", env.get("TRANSFER_SOURCE_METADATA_SHA256", "") or "")
            and env["TRANSFER_SOURCE_METADATA_SHA256"] == digest,
            "The protected operator metadata attestation differs.")
    return digest


def operator_resource_evidence(env, original, registration_sha, *, now=None):
    """Validate a pinned operator observation; it is not a live D1/R2 check."""
    evidence = parsed(env.get("SUBS_BOT_SEALED_SOURCE_EVIDENCE_JSON", ""))
    timestamp = int(datetime.now(timezone.utc).timestamp()) if now is None else now
    require(set(evidence) == {"version", "checkedAt", "sourceTarget", "databaseName", "bucketName",
                              "bucketPublicAccessDisabled", "bucketDeletionRulesDisabled", "bucketJurisdiction", "registrationSha256"}
            and type(evidence["version"]) is int and evidence["version"] == 1
            and type(evidence["checkedAt"]) is int and evidence["checkedAt"] <= timestamp <= evidence["checkedAt"] + 1800
            and evidence["sourceTarget"] == original and evidence["databaseName"] == "subs-bot-cf-dev-01"
            and evidence["bucketName"] == "subs-bot-cf-dev-01" and evidence["bucketPublicAccessDisabled"] is True
            and evidence["bucketDeletionRulesDisabled"] is True and evidence["bucketJurisdiction"] == "default"
            and evidence["registrationSha256"] == registration_sha)
    pin = env.get("TRANSFER_SOURCE_EVIDENCE_SHA256", "")
    require(re.fullmatch(r"[a-f0-9]{64}", pin or "") and sha256(canonical(evidence)).hexdigest() == pin,
            "The independently protected operator resource evidence differs.")
    return pin


def read_isolation_registration(env, account_id, key):
    """One fixed-bucket S3 GET using only a bucket-scoped object-read key."""
    access = env.get("SUBS_BOT_SEALED_R2_ACCESS_KEY_ID", "")
    secret = env.get("SUBS_BOT_SEALED_R2_SECRET_ACCESS_KEY", "")
    require(re.fullmatch(r"[a-f0-9]{32}", access or "") and re.fullmatch(r"[a-f0-9]{64}", secret or "")
            and re.fullmatch(r"[a-f0-9]{32}", account_id or "")
            and re.fullmatch(r"maintenance/production-control/evidence/lifecycle-[a-f0-9]{64}/registration\.json", key or ""))
    host = account_id + ".r2.cloudflarestorage.com"
    path = "/subs-bot-cf-dev-01/" + quote(key, safe="/-_.~")
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    day, empty = timestamp[:8], sha256(b"").hexdigest()
    signed = "host;x-amz-content-sha256;x-amz-date"
    headers = {"host": host, "x-amz-content-sha256": empty, "x-amz-date": timestamp}
    canon_headers = "".join(f"{name}:{headers[name]}\n" for name in sorted(headers))
    request = "\n".join(("GET", path, "", canon_headers, signed, empty))
    scope = f"{day}/auto/s3/aws4_request"
    signing = "\n".join(("AWS4-HMAC-SHA256", timestamp, scope, sha256(request.encode("ascii")).hexdigest()))
    signing_key = ("AWS4" + secret).encode("ascii")
    for part in (day, "auto", "s3", "aws4_request"):
        signing_key = hmac.digest(signing_key, part.encode("ascii"), "sha256")
    signature = hmac.digest(signing_key, signing.encode("ascii"), "sha256").hex()
    headers["Authorization"] = f"AWS4-HMAC-SHA256 Credential={access}/{scope}, SignedHeaders={signed}, Signature={signature}"
    connection = HTTPSConnection(host, timeout=30)
    try:
        connection.request("GET", path, headers=headers)
        response = connection.getresponse()
        try:
            require(response.status == 200 and response.getheader("Content-Encoding", "identity") == "identity")
            raw = response.read(512 * 1024 + 1)
            require(0 < len(raw) <= 512 * 1024)
            return raw
        finally:
            response.close()
    finally:
        connection.close()


def attest_isolation_source(env):
    """Check live Worker and S3 object; compare D1/R2 metadata to operator evidence."""
    from production_control import API, Telegram
    from production_lifecycle_drill import configuration, ORIGINAL_SERVICE
    from production_target import validate_target
    source_names = ("SUBS_BOT_CF_ISOLATION_TARGET_JSON", "SUBS_BOT_CONTROL_DRILL_KEYS", "SUBS_BOT_TELEGRAM_TEST_CONFIG")
    required = (*source_names, "SUBS_BOT_SEALED_WORKER_READ_TOKEN", "SUBS_BOT_SEALED_R2_ACCESS_KEY_ID",
                "SUBS_BOT_SEALED_R2_SECRET_ACCESS_KEY", "SUBS_BOT_SEALED_SOURCE_EVIDENCE_JSON")
    metadata_sha = operator_source_metadata(env, "subs-bot-isolation", required)
    draft, secrets, previous, original = configuration(env)
    require(previous["botId"] == TEST_BOT_ID and previous["botUsername"] == "test_cfsubs_bot")
    target = {**draft.data, "d1Id": original["d1Id"], "d1Name": ORIGINAL_SERVICE,
              "backupBucketName": ORIGINAL_SERVICE, "backupBucketCreatedAt": original["r2CreatedOn"]}
    reader = API(target, env.get("SUBS_BOT_SEALED_WORKER_READ_TOKEN", ""))
    root = reader.root
    worker = reader("GET", root + "/workers/workers/" + original["workerId"])
    require((worker.get("id"), worker.get("name"), worker.get("created_on")) ==
            (original["workerId"], ORIGINAL_SERVICE, original["workerCreatedOn"]))
    pin = env.get("TRANSFER_REGISTRATION_SHA256", "")
    evidence_sha = operator_resource_evidence(env, original, pin)
    raw = read_isolation_registration(env, original["accountId"],
          "maintenance/production-control/evidence/lifecycle-" + draft.digest + "/registration.json")
    require(re.fullmatch(r"[a-f0-9]{64}", pin or "") and sha256(raw).hexdigest() == pin)
    registration = parsed(raw)
    target = validate_target(registration.get("target"))
    desired = dict(draft.data)
    for key in ("workerId", "workerCreatedOn", "d1Id", "d1CreatedAt", "bucketCreatedAt", "backupBucketCreatedAt"):
        desired[key] = target.data[key]
    require(target.environment == "rehearsal" and target.data["botId"] == TEST_BOT_ID
            and registration.get("draftSha256") == draft.digest and registration.get("targetSha256") == target.digest
            and registration.get("configurationSha256") == target.configuration_digest
            and validate_target(desired).configuration_digest == target.configuration_digest)
    Telegram(draft, secrets).identity()
    github.require_current_main(env["GITHUB_SHA"])
    return {"metadataSha256": metadata_sha, "registrationSha256": pin, "operatorResourceEvidenceSha256": evidence_sha,
            "sourceHashes": {name: sha256(env[name].encode("utf-8")).hexdigest() for name in source_names}}


def attest_provider_source(env):
    import production_provider
    name = "SUBS_BOT_PROVIDER_CONTROL_TARGET_JSON"
    metadata_sha = operator_source_metadata(env, "subs-bot-provider-isolation", (name,))
    value = env.get(name, "")
    target = production_provider.read_config(value)
    expected = env.get("TRANSFER_PROVIDER_TARGET_SHA256", "")
    require(target["environment"] == "rehearsal" and target["caller"] is None
            and re.fullmatch(r"[a-f0-9]{64}", expected or "") and production_provider.digest(target) == expected)
    github.require_current_main(env["GITHUB_SHA"])
    return {"metadataSha256": metadata_sha, "targetSha256": expected,
            "sourceHashes": {name: sha256(value.encode("utf-8")).hexdigest()}}


def seal(raw, public_key):
    require(isinstance(raw, bytes) and 0 < len(raw) <= MAX_SECRET and isinstance(public_key, bytes) and len(public_key) == 32)
    sodium = ctypes.CDLL("/usr/lib/x86_64-linux-gnu/libsodium.so.23")
    sodium.sodium_init.restype = ctypes.c_int
    require(sodium.sodium_init() >= 0)
    sodium.crypto_box_seal.argtypes = (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulonglong, ctypes.c_void_p)
    sodium.crypto_box_seal.restype = ctypes.c_int
    cipher = ctypes.create_string_buffer(len(raw) + 48)
    message, key = ctypes.create_string_buffer(raw, len(raw)), ctypes.create_string_buffer(public_key, len(public_key))
    require(sodium.crypto_box_seal(cipher, message, len(raw), key) == 0)
    return cipher.raw


def checked_source(mapping, secret):
    value = parsed(secret)
    if mapping in {"backup-target", "provider-archive-location", "provider-live-location"}:
        require(set(value) == {"accountId", "workerId", "workerCreatedOn", "d1Id", "d1CreatedAt", "r2CreatedOn", "namespace"}
                and value.get("accountId") == "9431815bdb8beb2272f6668e06b7d3be" and value.get("namespace") == "lilyya"
                and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z", value.get("r2CreatedOn", "")))
        if MAPPINGS[mapping][4]:
            return canonical({key: value[key] for key in ("accountId", "namespace", "r2CreatedOn")})
    elif mapping == "backup-keys":
        require(set(value) == {"aggregateKey", "privateShareKey", "webhookSecret"}
                and all(isinstance(value.get(key), str) and re.fullmatch(r"[A-Za-z0-9_-]{43}", value[key])
                        for key in ("aggregateKey", "privateShareKey"))
                and value["aggregateKey"] != value["privateShareKey"]
                and isinstance(value.get("webhookSecret"), str) and re.fullmatch(r"[A-Za-z0-9_-]{32,256}", value["webhookSecret"]))
    elif mapping == "backup-bot":
        require(set(value) == {"botId", "botUsername", "botToken", "webhookSecret", "adminId", "memberId", "groupId"}
                and value["botId"] == TEST_BOT_ID and value["botUsername"] == "test_cfsubs_bot"
                and value["adminId"] == "8813701954" and value["memberId"] == "8653767757" and value["groupId"] == "-5114255828"
                and isinstance(value["botToken"], str) and re.fullmatch(re.escape(TEST_BOT_ID) + r":[A-Za-z0-9_-]{20,128}", value["botToken"])
                and isinstance(value["webhookSecret"], str) and re.fullmatch(r"[A-Za-z0-9_-]{32,256}", value["webhookSecret"]))
    else:
        import production_provider
        target = production_provider.validate_config(value)
        require(target["environment"] == "rehearsal" and target["caller"] is None)
    return secret.encode("utf-8")


def payload(env):
    approved = gate(env)
    attestation = (attest_isolation_source(env) if approved["source"] == "subs-bot-isolation"
                   else attest_provider_source(env))
    require(attestation["metadataSha256"] == env.get("TRANSFER_ATTESTED_METADATA_SHA256")
            and attestation["sourceHashes"][approved["sourceName"]] == env.get("TRANSFER_ATTESTED_SOURCE_SHA256"),
            "The source identity changed after its independent attestation.")
    secret = env.get("TRANSFER_SOURCE_VALUE", "")
    require(isinstance(secret, str) and secret and len(secret.encode("utf-8")) <= MAX_SECRET)
    require(re.fullmatch(r"[a-f0-9]{64}", env.get("TRANSFER_ATTESTED_SOURCE_SHA256", "") or "")
            and sha256(secret.encode("utf-8")).hexdigest() == env["TRANSFER_ATTESTED_SOURCE_SHA256"],
            "The source value differs from the separately attested configuration.")
    raw = checked_source(approved["mapping"], secret)
    ciphertext = seal(raw, approved["publicKey"])
    body = canonical({"encrypted_value": base64.b64encode(ciphertext).decode("ascii"), "key_id": approved["keyId"]})
    root = Path(env.get("RUNNER_TEMP", ""))
    require(root.is_absolute() and root.is_dir() and not root.is_symlink())
    path = root / "isolation-sealed-transfer.json"
    with path.open("xb") as output:
        os.chmod(path, 0o600)
        output.write(body)
    github.require_current_main(approved["revision"])
    return {"status": "sealed-only", "mapping": approved["mapping"], "sourceEnvironment": approved["source"],
            "destinationEnvironment": approved["destination"], "destinationSecret": approved["destinationName"],
            "destinationKeyPinSha256": approved["keyPinSha256"], "ciphertextPayloadSha256": sha256(body).hexdigest(),
            "runId": approved["runId"], "controllerRevision": approved["revision"], "destinationWritten": False}


if __name__ == "__main__":
    try:
        os.umask(0o077)
        phase = os.environ.get("TRANSFER_PHASE", "")
        require(phase in {"plan", "gate", "attest", "seal"})
        if phase == "attest":
            approved = gate(os.environ)
            attestation = (attest_isolation_source(os.environ) if approved["source"] == "subs-bot-isolation"
                           else attest_provider_source(os.environ))
            with open(os.environ["GITHUB_OUTPUT"], "a", encoding="ascii") as output:
                output.write("metadata_sha256=" + attestation["metadataSha256"] + "\n")
                output.write("source_sha256=" + attestation["sourceHashes"][approved["sourceName"]] + "\n")
            result = {"status": "source-attested", "mapping": approved["mapping"], "controllerRevision": approved["revision"]}
        else:
            result = key_plan(os.environ) if phase == "plan" else gate(os.environ) if phase == "gate" else payload(os.environ)
        if phase in {"plan", "gate"}:
            result = {key: value for key, value in result.items() if key != "publicKey"}
        print(json.dumps(result, sort_keys=True))
    except Exception:
        print(json.dumps({"status": "stopped", "reason": "The fixed isolation transfer or destination-key pin was not confirmed."}))
        raise SystemExit(1) from None
