"""Verify the independently deployed private API status V2 service before app binding."""

from hashlib import sha256
from io import BytesIO
from pathlib import PurePosixPath
from time import time
from zipfile import ZipFile

from attest_api_status_container import release_context, verify_attestation
from cloudflare_isolation import CloudflareError, PROVIDER_API_STATUS_SERVICE, ProviderApiStatusBinding, WORKER_NAME
from provider_binding_gate import MAX_ARCHIVE_BYTES, MAX_CAPSULE_BYTES, _download, _match, activation, bootstrap, github, provider, publication


CONFIG_ENV = "SUBS_BOT_CF_PROVIDER_API_STATUS_BINDING_JSON"
WORKFLOW = ".github/workflows/worker-provider-api-status-isolation-activate.yml"
PROOF_PREFIX = "subs-bot-provider-api-status-v2-binding-proof"
PROOF_FILE = "provider-api-status-v2-binding-proof.json"
PIN_ERROR = "The isolated API status V2 binding pin is invalid."
PROOF_ERROR = "The pinned private API status V2 activation proof could not be verified."
LIVE_ERROR = "The private API status V2 service no longer matches the verified binding proof."


def _require(condition, message):
    if not condition:
        raise CloudflareError(message)


def _parse_document(raw, pin):
    return activation.parse_binding_proof(raw, revision=pin["revision"], run_id=pin["runId"],
                                          run_attempt=pin["runAttempt"], profile=provider.API_STATUS_PROFILE)


def _read_proof(pin, token):
    workflow = github._get_json(f"/actions/workflows/{PurePosixPath(WORKFLOW).name}", token)
    workflow_id = workflow.get("id")
    _require(workflow.get("path") == WORKFLOW and workflow.get("state") == "active"
             and type(workflow_id) is int and _match(provider.DECIMAL, str(workflow_id)), PROOF_ERROR)

    def selection():
        return github.select_main_artifact(pin["runId"], pin["revision"], token, workflow_id=workflow_id,
                                           workflow_path=WORKFLOW, artifact_prefix=PROOF_PREFIX,
                                           workflow_label="private API status V2 activation proof", events=("workflow_dispatch",))

    expected = (pin["runAttempt"], pin["artifactId"], pin["archiveSha256"])
    _require(selection() == expected, PROOF_ERROR)
    raw = _download(pin["artifactId"], token)
    _require(0 < len(raw) <= MAX_ARCHIVE_BYTES and sha256(raw).hexdigest() == pin["archiveSha256"], PROOF_ERROR)
    with ZipFile(BytesIO(raw)) as archive:
        members = github._zip_members(archive)
        _require(set(members) == {PROOF_FILE} and 0 < members[PROOF_FILE].file_size <= activation.MAX_BINDING_PROOF,
                 PROOF_ERROR)
        proof = _parse_document(archive.read(members[PROOF_FILE]), pin)
    _require(selection() == expected, PROOF_ERROR)
    return proof


class ApiStatusGate:
    def __init__(self, account, caller, deploy_token, identity, active, proof_pin, proof, attestation):
        account_sha = sha256(account.encode("ascii")).hexdigest()
        facts = proof["verification"]
        deployment = {key: active[key] for key in ("deploymentId", "namespaceId")}
        _require(proof["accountSha256"] == account_sha == publication.TARGET_ACCOUNT_SHA256
                 and facts["workerIdentitySha256"] == identity.fingerprint()
                 and facts["versionSha256"] == activation._hash(active["versionId"])
                 and facts["activationIdentitySha256"] == activation._fingerprint(deployment), PROOF_ERROR)
        self._api = activation.ProviderAPI(account, deploy_token, "", identity, worker_reads_only=True,
                                           profile=provider.API_STATUS_PROFILE)
        self._identity = identity
        self._caller = caller
        self._active = active
        self._proof_pin = proof_pin
        self._proof_body = activation._proof_bytes(proof)
        self._container_attestation = attestation
        self._container_identity_sha256 = facts["containerIdentitySha256"]
        self._verified_application_revision = None
        self._release = {**proof["providerBuild"], "versionId": active["versionId"]}
        fingerprint = activation._fingerprint({"profile": provider.API_STATUS_PROFILE, "account": account_sha,
            "worker": identity.fingerprint(), "release": self._release, "activation": deployment,
            "proofArtifact": proof_pin, "proofSha256": sha256(self._proof_body).hexdigest()})
        self.binding = ProviderApiStatusBinding(self._release["revision"], self._release["ociManifestSha256"], fingerprint)

    def verify_first_binding(self, application_revision):
        if self._verified_application_revision is not None and self._verified_application_revision == application_revision:
            return
        try:
            token = github._github_token()
            revision = self._proof_pin["revision"]
            _require(_match(provider.REVISION, application_revision), PROOF_ERROR)
            proof = _read_proof(self._proof_pin, token)
            _require(activation._proof_bytes(proof) == self._proof_body, PROOF_ERROR)
            if revision != application_revision:
                comparison = github._get_json(f"/compare/{revision}...{application_revision}?per_page=1", token)
                ahead, behind = comparison.get("ahead_by"), comparison.get("behind_by")
                _require(comparison.get("status") == "ahead" and type(ahead) is int and ahead > 0
                         and type(behind) is int and behind == 0
                         and all(comparison.get(key, {}).get("sha") == revision
                                 for key in ("base_commit", "merge_base_commit")), PROOF_ERROR)
        except Exception:
            raise CloudflareError(PROOF_ERROR) from None
        self._verified_application_revision = application_revision

    def verify(self):
        context = release_context()
        verify_attestation(self._container_attestation, context, publication.TARGET_ACCOUNT_SHA256,
                           self._container_identity_sha256, int(time()))
        try:
            first = self._api.deployment(self._release)
            _require(isinstance(first, dict) and first.get("id") == self._active["deploymentId"], LIVE_ERROR)
            namespace = self._api.version(self._release, True)
            _require(namespace == self._active["namespaceId"], LIVE_ERROR)
            for worker in (self._api.by_name(), self._api.worker.by_id(self._identity)):
                activation._private_profile(worker, self._identity, True, self._caller, profile=provider.API_STATUS_PROFILE)
                activation._references(worker, self._identity, namespace, service=PROVIDER_API_STATUS_SERVICE)
            activation._public(f"https://{PROVIDER_API_STATUS_SERVICE}.lilyya.workers.dev/health")
            _require(self._api.deployment(self._release) == first, LIVE_ERROR)
        except Exception:
            raise CloudflareError(LIVE_ERROR) from None
        verify_attestation(self._container_attestation, context, publication.TARGET_ACCOUNT_SHA256,
                           self._container_identity_sha256, int(time()))


def load_api_status_gate(raw, target, deploy_token, attestation):
    if raw == "":
        return None
    try:
        _require(isinstance(raw, str) and raw.isascii() and 0 < len(raw) <= MAX_CAPSULE_BYTES, PIN_ERROR)
        pin = github._parse_object(raw, PIN_ERROR)
        _require(set(pin) == {"version", "proof", "proofDocument", "worker", "activation"}
                 and type(pin["version"]) is int and pin["version"] == 3, PIN_ERROR)
        proof_pin, worker, active = pin["proof"], pin["worker"], pin["activation"]
        _require(isinstance(proof_pin, dict)
                 and set(proof_pin) == {"revision", "runId", "runAttempt", "artifactId", "archiveSha256"}
                 and _match(provider.REVISION, proof_pin["revision"]) and _match(provider.HEX, proof_pin["archiveSha256"])
                 and all(_match(provider.DECIMAL, proof_pin[key]) for key in ("runId", "runAttempt", "artifactId")), PIN_ERROR)
        _require(isinstance(worker, dict) and set(worker) == {"workerId", "workerCreatedOn"}
                 and isinstance(active, dict) and set(active) == {"versionId", "deploymentId", "namespaceId"}
                 and all(_match(activation.stage.VERSION_ID, active[key]) for key in ("versionId", "deploymentId"))
                 and _match(publication.ACCOUNT, active["namespaceId"]), PIN_ERROR)
        identity = bootstrap.Identity(worker["workerId"], worker["workerCreatedOn"])
        account, caller = target.get("accountId"), target.get("workerId")
        _require(isinstance(pin["proofDocument"], dict) and provider.API_STATUS_SERVICE == PROVIDER_API_STATUS_SERVICE
                 and _match(publication.ACCOUNT, account) and _match(publication.ACCOUNT, caller)
                 and identity.worker_id != caller
                 and sha256(account.encode("ascii")).hexdigest() == publication.TARGET_ACCOUNT_SHA256, PIN_ERROR)
        proof = _parse_document(activation._proof_bytes(pin["proofDocument"]), proof_pin)
        return ApiStatusGate(account, {"id": caller, "name": WORKER_NAME}, deploy_token, identity, active, proof_pin, proof,
                             attestation)
    except Exception:
        raise CloudflareError(PIN_ERROR) from None
