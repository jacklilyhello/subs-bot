"""Verify a private provider release before binding the isolated application."""

from hashlib import sha256
from http.client import HTTPException
from io import BytesIO
from pathlib import PurePosixPath
from zipfile import BadZipFile, ZipFile
import zlib

import activate_provider_isolation as activation
from cloudflare_isolation import CloudflareError, PROVIDER_SERVICE, ProviderBinding, WORKER_NAME


github = activation.github
provider = activation.provider
publication = activation.publication
bootstrap = activation.bootstrap
CONFIG_ENV = "SUBS_BOT_CF_PROVIDER_BINDING_JSON"
PROOF_PREFIX = "subs-bot-provider-binding-proof"
MAX_ARCHIVE_BYTES = 16 * 1024
PIN_ERROR = "The isolated provider binding pin is invalid."
PROOF_ERROR = "The pinned provider activation proof could not be verified."
LIVE_ERROR = "The private provider no longer matches the verified binding proof."


def _require(condition, message):
    if not condition:
        raise CloudflareError(message)


def _match(pattern, value):
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def _read_pin(raw):
    _require(isinstance(raw, str) and 0 < len(raw) <= 4096, PIN_ERROR)
    pin = github._parse_object(raw, PIN_ERROR)
    _require(set(pin) == {"version", "proof", "worker", "activation"}
             and type(pin["version"]) is int and pin["version"] == 1, PIN_ERROR)
    proof, worker, active = pin["proof"], pin["worker"], pin["activation"]
    _require(isinstance(proof, dict) and set(proof) == {"revision", "runId", "runAttempt", "artifactId", "archiveSha256"}
             and _match(provider.REVISION, proof["revision"]) and _match(provider.HEX, proof["archiveSha256"])
             and all(_match(provider.DECIMAL, proof[key]) for key in ("runId", "runAttempt", "artifactId")), PIN_ERROR)
    _require(isinstance(worker, dict) and set(worker) == {"workerId", "workerCreatedOn"}
             and isinstance(active, dict) and set(active) == {"versionId", "deploymentId", "namespaceId"}
             and all(_match(activation.stage.VERSION_ID, active[key]) for key in ("versionId", "deploymentId"))
             and _match(publication.ACCOUNT, active["namespaceId"]), PIN_ERROR)
    return proof, bootstrap.Identity(worker["workerId"], worker["workerCreatedOn"]), active


def _download(artifact_id, token):
    # The signed storage request omits GitHub authorization. Neither request can follow redirects.
    request = github.artifact_storage_request(artifact_id, token)
    with github._OPENER.open(request, timeout=30) as response:
        _require(response.status == 200, PROOF_ERROR)
        return github._bounded_read(response, MAX_ARCHIVE_BYTES)


def _read_proof(pin, token):
    path = activation.WORKFLOW_PATH
    workflow = github._get_json(f"/actions/workflows/{PurePosixPath(path).name}", token)
    workflow_id = workflow.get("id")
    _require(workflow.get("path") == path and workflow.get("state") == "active"
             and type(workflow_id) is int and _match(provider.DECIMAL, str(workflow_id)), PROOF_ERROR)

    def selection():
        return github.select_main_artifact(pin["runId"], pin["revision"], token, workflow_id=workflow_id,
                                           workflow_path=path, artifact_prefix=PROOF_PREFIX,
                                           workflow_label="provider activation proof", events=("workflow_dispatch",))

    expected = (pin["runAttempt"], pin["artifactId"], pin["archiveSha256"])
    _require(selection() == expected, PROOF_ERROR)
    raw = _download(pin["artifactId"], token)
    _require(0 < len(raw) <= MAX_ARCHIVE_BYTES and sha256(raw).hexdigest() == pin["archiveSha256"], PROOF_ERROR)
    with ZipFile(BytesIO(raw)) as archive:
        members = github._zip_members(archive)
        name = activation.BINDING_PROOF_FILE
        _require(set(members) == {name} and 0 < members[name].file_size <= activation.MAX_BINDING_PROOF, PROOF_ERROR)
        proof = activation.parse_binding_proof(archive.read(members[name]), revision=pin["revision"],
                                               run_id=pin["runId"], run_attempt=pin["runAttempt"])
    _require(selection() == expected, PROOF_ERROR)
    return proof


class ProviderGate:
    def __init__(self, account, caller, deploy_token, identity, active, proof):
        account_sha = sha256(account.encode("ascii")).hexdigest()
        facts = proof["verification"]
        deployment = {key: active[key] for key in ("deploymentId", "namespaceId")}
        _require(proof["accountSha256"] == account_sha == publication.TARGET_ACCOUNT_SHA256
                 and facts["workerIdentitySha256"] == identity.fingerprint()
                 and facts["versionSha256"] == activation._hash(active["versionId"])
                 and facts["activationIdentitySha256"] == activation._fingerprint(deployment), PROOF_ERROR)
        self._api = activation.ProviderAPI(account, deploy_token, "", identity, worker_reads_only=True)
        self._identity = identity
        self._caller = caller
        self._active = active
        self._release = {**proof["providerBuild"], "versionId": active["versionId"]}
        fingerprint = activation._fingerprint({"account": account_sha, "worker": identity.fingerprint(),
            "release": self._release, "activation": deployment, "container": facts["containerIdentitySha256"],
            "workflow": facts["workflowIdentitySha256"]})
        self.binding = ProviderBinding(self._release["revision"], self._release["ociManifestSha256"], fingerprint)

    def verify(self):
        try:
            first = self._api.deployment(self._release)
            _require(isinstance(first, dict) and first.get("id") == self._active["deploymentId"], LIVE_ERROR)
            namespace = self._api.version(self._release, True)
            _require(namespace == self._active["namespaceId"], LIVE_ERROR)
            for worker in (self._api.worker.by_name(), self._api.worker.by_id(self._identity)):
                activation._private_profile(worker, self._identity, True, self._caller)
                activation._references(worker, self._identity, namespace)
            activation._public(activation.PROVIDER_URL)
            _require(self._api.deployment(self._release) == first, LIVE_ERROR)
        except Exception:
            # Keep dependency errors redacted and eligible for the application's guarded rollback.
            raise CloudflareError(LIVE_ERROR) from None


def load_provider_gate(raw, target, deploy_token):
    if raw == "":
        return None
    try:
        proof_pin, identity, active = _read_pin(raw)
        account, caller_id = target.get("accountId"), target.get("workerId")
        _require(provider.SERVICE == PROVIDER_SERVICE
                 and _match(publication.ACCOUNT, account) and _match(publication.ACCOUNT, caller_id)
                 and identity.worker_id != caller_id
                 and sha256(account.encode("ascii")).hexdigest() == publication.TARGET_ACCOUNT_SHA256, PIN_ERROR)
    except (CloudflareError, ValueError, AttributeError, KeyError, TypeError):
        raise CloudflareError(PIN_ERROR) from None
    try:
        proof = _read_proof(proof_pin, github._github_token())
        return ProviderGate(account, {"id": caller_id, "name": WORKER_NAME}, deploy_token, identity, active, proof)
    except (ValueError, BadZipFile, RuntimeError, OSError, HTTPException, zlib.error,
            AttributeError, KeyError, TypeError, EOFError):
        raise CloudflareError(PROOF_ERROR) from None
