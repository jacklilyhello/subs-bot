"""Keep the V2 Container credential in a protected, GET-only release job."""

from hashlib import sha256
import os
from pathlib import Path
import stat
import sys
from time import time

from cloudflare_isolation import CloudflareClient, CloudflareError, PROVIDER_API_STATUS_SERVICE, _Isolation
from provider_binding_gate import activation, bootstrap, github, provider, publication


WORKFLOW = ".github/workflows/worker-isolation-deploy.yml"
ATTESTATION_ENV = "SUBS_BOT_API_STATUS_CONTAINER_ATTESTATION"
CONTAINER_TOKEN_ENV = "SUBS_BOT_CF_PROVIDER_API_STATUS_ATTEST_READ_TOKEN"
ACTIVATION_PIN_ENV = "SUBS_BOT_CF_PROVIDER_API_STATUS_ACTIVATION_JSON"
CONTAINER_PIN_ENV = "SUBS_BOT_CF_PROVIDER_API_STATUS_CONTAINER_IDENTITY_JSON"
ATTESTATION_MAX_AGE = 15 * 60
ERROR = "Fresh private API status V2 Container privacy could not be verified."


def _require(condition):
    if not condition:
        raise CloudflareError(ERROR)


def release_context():
    return activation._binding_proof_context(workflow_path=WORKFLOW)


def inspect_required(worker_api, target):
    scope = _Isolation(worker_api, None, target)
    scope.worker_config()
    active = scope.active()
    enabled = scope.version(active.version).telegram_api_status
    _require(scope.active() == active)
    return enabled


def observe_container(api, account, active, expected):
    _require(isinstance(account, str) and publication.ACCOUNT.fullmatch(account)
             and sha256(account.encode("ascii")).hexdigest() == publication.TARGET_ACCOUNT_SHA256
             and active is not None and expected is not None and active["namespaceId"] == expected["applicationId"])
    namespace = active["namespaceId"]
    _require(isinstance(namespace, str) and publication.ACCOUNT.fullmatch(namespace))
    observed = api("GET", f"/accounts/{account}/containers/applications/{namespace}")
    _require(isinstance(observed, dict) and observed.get("id") == namespace and observed.get("account_id") == account
             and observed.get("name") == PROVIDER_API_STATUS_SERVICE and observed.get("scheduling_policy") == "durable_object"
             and observed.get("durable_objects") == {"namespace_id": namespace}
             and observed.get("observability") == {"logs": {"enabled": False}}
             and observed["observability"]["logs"]["enabled"] is False)
    config = observed.get("configuration")
    _require(isinstance(config, dict) and set(config) <= {"authorized_keys", "wrangler_ssh"}
             and config.get("authorized_keys", []) == [])
    ssh = config.get("wrangler_ssh")
    _require(isinstance(ssh, dict) and set(ssh) <= {"enabled", "port"} and ssh.get("enabled") is False
             and ("port" not in ssh or (type(ssh["port"]) is int and 1 <= ssh["port"] <= 65535)))
    created = observed.get("created_at")
    bootstrap._timestamp(created)
    identity = {"applicationId": namespace, "createdAt": created}
    _require(identity == expected)
    return activation._fingerprint(identity)


def verify_attestation(raw, context, expected_account, expected_container, now):
    _require(isinstance(raw, str) and raw.isascii() and 0 < len(raw) <= 512)
    try:
        proof = github._parse_object(raw, ERROR)
    except github.ArtifactError:
        raise CloudflareError(ERROR) from None
    revision, run_id, attempt = context
    _require(set(proof) == {"version", "revision", "runId", "runAttempt", "observedAt", "accountSha256", "containerIdentitySha256"}
             and type(proof["version"]) is int and proof["version"] == 1
             and (proof["revision"], proof["runId"], proof["runAttempt"]) == (revision, run_id, attempt)
             and type(proof["observedAt"]) is int and 0 <= now - proof["observedAt"] <= ATTESTATION_MAX_AGE
             and proof["accountSha256"] == expected_account == publication.TARGET_ACCOUNT_SHA256
             and proof["containerIdentitySha256"] == expected_container
             and isinstance(expected_container, str) and provider.HEX.fullmatch(expected_container))


def _output(name, value):
    directory = Path(os.environ.get("RUNNER_TEMP", ""))
    path = Path(os.environ.get("GITHUB_OUTPUT", ""))
    _require(directory.is_absolute() and path.is_absolute() and path.parent.resolve().is_relative_to(directory.resolve()))
    flags = os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_NONBLOCK
    with os.fdopen(os.open(path, flags), "ab") as output:
        info = os.fstat(output.fileno())
        _require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid())
        output.write(f"{name}={value}\n".encode("ascii"))


def main(mode):
    revision, run_id, attempt = release_context()
    github.require_current_main(revision)
    if mode == "inspect":
        target = github._parse_object(os.environ.get("SUBS_BOT_CF_ISOLATION_TARGET_JSON", ""), ERROR)
        enabled = inspect_required(CloudflareClient(os.environ.get("SUBS_BOT_CF_DEPLOY_TOKEN")), target)
        github.require_current_main(revision)
        _output("required", "true" if enabled else "false")
        return
    _require(mode == "attest")
    account = os.environ.get("SUBS_BOT_CF_PROVIDER_ACCOUNT_ID", "")
    active = activation._pin(os.environ.get(ACTIVATION_PIN_ENV, ""), ("deploymentId", "namespaceId"))
    expected = activation._pin(os.environ.get(CONTAINER_PIN_ENV, ""), ("applicationId", "createdAt"))
    fingerprint = observe_container(CloudflareClient(os.environ.get(CONTAINER_TOKEN_ENV)), account, active, expected)
    observed_at = int(time())
    github.require_current_main(revision)
    evidence = {"version": 1, "revision": revision, "runId": run_id, "runAttempt": attempt,
                "observedAt": observed_at, "accountSha256": publication.TARGET_ACCOUNT_SHA256,
                "containerIdentitySha256": fingerprint}
    _output("attestation", activation._proof_bytes(evidence).decode("ascii").rstrip("\n"))


if __name__ == "__main__":
    try:
        main(sys.argv[1])
    except Exception:
        raise SystemExit(ERROR) from None
