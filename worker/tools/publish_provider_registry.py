"""Publish the exact verified Provider Fetch CI image to the isolated registry."""

from base64 import b64encode
from hashlib import sha256
from http.client import HTTPException
import json
import os
from pathlib import Path
import re
import resource
import stat
import subprocess
import tempfile
from time import monotonic
from urllib.error import HTTPError
from urllib.parse import urlencode, urlsplit
from urllib.request import ProxyHandler, Request, build_opener

import prepare_provider_artifact as provenance
import prepare_isolation_artifact as github

provider = provenance.provider
HOST = "registry.cloudflare.com"
API_ORIGIN = "https://api.cloudflare.com/client/v4"
EVIDENCE_FILE = "provider-provenance.json"
ACCOUNT = re.compile(r"[0-9a-f]{32}")
TARGET_ACCOUNT_SHA256 = "ffdbf3dd5d042c6edb68d7f628998a69a22320b0199775bfda9f97593136e508"
API_TOKEN = re.compile(r"[A-Za-z0-9_.-]{1,4096}")
USERNAME = re.compile(r"[A-Za-z0-9_.-]{1,128}")
JWT = re.compile(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")
BEARER = re.compile(r"[A-Za-z0-9_.~+/-]{1,8192}={0,2}")
CHALLENGE_PARAMETER = re.compile(r'([a-z]+)="([^"\\\x00-\x1f\x7f]{1,512})"')
TAG = re.compile(r"git-[0-9a-f]{40}-[0-9a-f]{12}")
MANIFEST_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
OCI_ERROR = "Cloudflare Registry did not return a conclusive manifest result."
HTTP_LIMIT = provider.MAX_METADATA
SKOPEO = "/usr/bin/skopeo"
MANIFEST_FIELDS = ("compatibilityDate", "workerSha256", "ociArchiveSha256", "ociManifestSha256", "ociConfigSha256")


class PublicationError(ValueError):
    """A publication failure with a message safe for the protected runner log."""


def _require(condition, message):
    if not condition:
        raise PublicationError(message)


def _private_path(path, mode, limit=None):
    info = path.lstat()
    expected_type = stat.S_IFREG if limit is not None else stat.S_IFDIR
    _require(stat.S_IFMT(info.st_mode) == expected_type and stat.S_IMODE(info.st_mode) == mode
             and info.st_uid == os.getuid() and (limit is None or 0 < info.st_size <= limit),
             "Verified provider files must be private runner files.")


def _verified_input(root, revision, run_id):
    evidence_path = root / EVIDENCE_FILE
    _private_path(evidence_path, 0o600, HTTP_LIMIT)
    with evidence_path.open("rb") as source:
        evidence = provider.json_object(source)
    keys = {"revision", "runId", "runAttempt", "artifactId", "archiveSha256", *MANIFEST_FIELDS}
    _require(set(evidence) == keys and (evidence["revision"], evidence["runId"]) == (revision, run_id)
             and all(isinstance(evidence[key], str) and provider.DECIMAL.fullmatch(evidence[key])
                     for key in ("runAttempt", "artifactId"))
             and all(isinstance(evidence[key], str) and provider.HEX.fullmatch(evidence[key])
                     for key in ("archiveSha256", "workerSha256", "ociArchiveSha256", "ociManifestSha256", "ociConfigSha256"))
             and evidence["compatibilityDate"] == provider.COMPATIBILITY,
             "The verified provider build evidence does not match the requested release.")

    directory = root / provenance.VERIFIED_DIRECTORY
    _private_path(directory, 0o700)
    _require({path.name for path in directory.iterdir()} == set(provenance.FILE_LIMITS),
             "The verified provider directory does not contain exactly the three release files.")
    for name, limit in provenance.FILE_LIMITS.items():
        _private_path(directory / name, 0o600, limit)
    try:
        manifest = provider.verify_release(directory, revision, ref=github.MAIN_REF, run_id=run_id,
                                           run_attempt=evidence["runAttempt"])
    except provider.VERIFICATION_ERRORS:
        raise PublicationError("The private provider release files no longer verify.") from None
    _require(all(evidence[key] == manifest[key] for key in MANIFEST_FIELDS),
             "The provider release digest differs from the verified GitHub artifact.")
    return directory / provider.IMAGE, evidence


def _guard_main(evidence):
    revision = evidence["revision"]
    actual = provenance._select_artifact(evidence["runId"], revision, github._github_token())
    _require(actual == (evidence["runAttempt"], evidence["artifactId"], evidence["archiveSha256"]),
             "The trusted Provider Fetch CI attempt or artifact changed.")
    github.require_current_main(revision)


def _response(request, opener, error):
    try:
        try:
            response = opener.open(request, timeout=15)
        except HTTPError as http_error:
            response = http_error
        with response:
            # Bound both bytes and time on slow successful or error bodies.
            deadline = monotonic() + 20
            data = bytearray()
            _require(response.headers.get("Content-Encoding", "identity").lower() == "identity", error)
            while monotonic() < deadline:
                chunk = response.read1(min(8192, HTTP_LIMIT + 1 - len(data)))
                if not chunk:
                    return response.code, response.headers, bytes(data)
                data.extend(chunk)
                _require(len(data) <= HTTP_LIMIT, error)
            raise PublicationError(error)
    except (OSError, ValueError, HTTPException):
        raise PublicationError(error) from None


def _basic(credentials):
    return b64encode(":".join(credentials).encode("ascii")).decode("ascii")


def _challenge(header, repository):
    _require(isinstance(header, str) and len(header) <= 2048, OCI_ERROR)
    scheme, _, remaining = header.partition(" ")
    fields = {}
    while remaining:
        match = CHALLENGE_PARAMETER.match(remaining.lstrip())
        _require(match is not None, OCI_ERROR)
        name, value = match.groups()
        _require(name not in fields, OCI_ERROR)
        fields[name] = value
        remaining = remaining.lstrip()[match.end():].lstrip()
        if remaining:
            _require(remaining.startswith(",") and remaining[1:].strip(), OCI_ERROR)
            remaining = remaining[1:]
    if scheme.lower() == "basic":
        _require(set(fields) == {"realm"}, OCI_ERROR)
        return None
    _require(scheme.lower() == "bearer" and "realm" in fields
             and set(fields) <= {"realm", "service", "scope"}, OCI_ERROR)
    realm_value = fields["realm"]
    _require(not any(character.isspace() for character in realm_value), OCI_ERROR)
    realm = urlsplit(realm_value)
    _require(realm.scheme == "https" and realm.netloc == HOST and not realm.query and not realm.fragment
             and re.fullmatch(r"/[A-Za-z0-9_/-]{1,128}", realm.path)
             and "//" not in realm.path and not realm_value.endswith(("?", "#")), OCI_ERROR)
    scope = "repository:" + repository + ":pull"
    _require(fields.get("scope", scope) == scope, OCI_ERROR)
    params = {"scope": scope}
    if "service" in fields:
        _require(re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", fields["service"]), OCI_ERROR)
        params["service"] = fields["service"]
    return f"https://{HOST}{realm.path}?{urlencode(params)}"


class Registry:
    def __init__(self, account, api_token):
        _require(ACCOUNT.fullmatch(account) and API_TOKEN.fullmatch(api_token),
                 "The protected Cloudflare account or Containers credential is missing or malformed.")
        self._account = account
        self._api_token = api_token
        self.repository = f"{account}/{provider.SERVICE}"
        self._opener = build_opener(ProxyHandler({}), github._NoRedirect())
        self._read_authorization = None

    def mint(self, *, push=False):
        error = "Cloudflare did not issue the expected short-lived registry credential."
        permissions = ["pull", "push"] if push else ["pull"]
        request = Request(f"{API_ORIGIN}/accounts/{self._account}/containers/registries/{HOST}/credentials",
                          data=json.dumps({"expiration_minutes": 15, "permissions": permissions}).encode("ascii"),
                          headers={"Authorization": "Bearer " + self._api_token,
                                   "Accept": "application/json", "Content-Type": "application/json"}, method="POST")
        status, _, data = _response(request, self._opener, error)
        _require(status == 200, error)
        response = github._parse_object(data, error)
        result = response.get("result")
        _require(response.get("success") is True and isinstance(result, dict)
                 and result.get("account_id") == self._account and result.get("registry_host") == HOST, error)
        user, password = result.get("username"), result.get("password")
        _require(isinstance(user, str) and USERNAME.fullmatch(user) and isinstance(password, str)
                 and len(password) <= 4096 and JWT.fullmatch(password), error)
        return user, password

    def manifest(self, reference, credentials, *, allow_missing=False):
        _require(TAG.fullmatch(reference) or MANIFEST_DIGEST.fullmatch(reference), OCI_ERROR)
        url = f"https://{HOST}/v2/{self.repository}/manifests/{reference}"
        headers = {"Accept": provider.OCI_MANIFEST, "Cache-Control": "no-cache"}
        if self._read_authorization is None:
            ping = Request(f"https://{HOST}/v2/", headers={"Cache-Control": "no-cache"})
            status, challenge_headers, _ = _response(ping, self._opener, OCI_ERROR)
            if status == 200:
                status, challenge_headers, _ = _response(Request(url, headers=headers), self._opener, OCI_ERROR)
            challenges = challenge_headers.get_all("WWW-Authenticate", [])
            _require(status == 401 and len(challenges) == 1, OCI_ERROR)
            auth_url = _challenge(challenges[0], self.repository)
            authorization = "Basic " + _basic(credentials)
            if auth_url is not None:
                auth = Request(auth_url, headers={"Authorization": authorization, "Accept": "application/json"})
                status, _, data = _response(auth, self._opener, OCI_ERROR)
                _require(status == 200, OCI_ERROR)
                token_data = github._parse_object(data, OCI_ERROR)
                token = token_data.get("token", token_data.get("access_token"))
                _require(isinstance(token, str) and BEARER.fullmatch(token)
                         and token_data.get("access_token", token) == token, OCI_ERROR)
                authorization = "Bearer " + token
            self._read_authorization = authorization

        headers["Authorization"] = self._read_authorization
        status, result_headers, data = _response(Request(url, headers=headers), self._opener, OCI_ERROR)
        if status == 404 and allow_missing:
            errors = github._parse_object(data, OCI_ERROR).get("errors")
            _require(isinstance(errors, list) and len(errors) == 1 and isinstance(errors[0], dict)
                     and errors[0].get("code") in ("MANIFEST_UNKNOWN", "NAME_UNKNOWN"), OCI_ERROR)
            return None
        _require(status == 200 and data and result_headers.get_content_type() == provider.OCI_MANIFEST, OCI_ERROR)
        claimed = result_headers.get_all("Docker-Content-Digest", [])
        digest = sha256(data).hexdigest()
        _require(not claimed or claimed == ["sha256:" + digest], OCI_ERROR)
        return digest


def _write_auth(path, credentials, repository):
    with provenance._write_private(path) as output:
        output.write(json.dumps({"auths": {f"{HOST}/{repository}": {"auth": _basic(credentials)}}}).encode("ascii"))
    return path


def _skopeo_env(scratch):
    return {"PATH": "/usr/bin:/bin", "HOME": str(scratch), "TMPDIR": str(scratch),
            "XDG_CONFIG_HOME": str(scratch), "XDG_RUNTIME_DIR": str(scratch), "LC_ALL": "C"}


def _copy(scratch, archive, tag_reference, authfile, expected):
    _copy_image(scratch, archive, "docker://" + tag_reference, authfile, expected)


def _copy_image(scratch, archive, destination, authfile, expected):
    digest_file = scratch / "copied-digest"
    error = "Skopeo did not confirm the exact copied OCI manifest digest."
    try:
        subprocess.run([SKOPEO, "copy", "--quiet", "--preserve-digests", "--retry-times=0",
                        "--dest-tls-verify=true", "--dest-authfile", str(authfile),
                        "--digestfile", str(digest_file), "oci-archive:" + str(archive),
                        destination],
                       env=_skopeo_env(scratch), stdin=subprocess.DEVNULL,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True, timeout=240)
        with digest_file.open("rb") as output:
            _require(output.read(80) in (expected.encode("ascii"), (expected + "\n").encode("ascii")), error)
    except (OSError, subprocess.SubprocessError):
        raise PublicationError(error) from None


def _limit_inspect_output():
    resource.setrlimit(resource.RLIMIT_FSIZE, (HTTP_LIMIT, HTTP_LIMIT))


def _config(scratch, digest_reference, authfile):
    return _inspect_digest(scratch, "docker://" + digest_reference, authfile, config=True)


def _inspect_digest(scratch, image, authfile, *, config=False):
    error = "Skopeo could not read the exact OCI config." if config else "Skopeo could not read the exact OCI manifest."
    args = [SKOPEO, "inspect", "--raw", "--tls-verify=true", "--retry-times=0", "--authfile", str(authfile)]
    if config:
        args.append("--config")
    try:
        with tempfile.TemporaryFile(dir=scratch) as output:
            subprocess.run([*args, image],
                           env=_skopeo_env(scratch), stdin=subprocess.DEVNULL, stdout=output,
                           stderr=subprocess.DEVNULL, check=True, timeout=30, preexec_fn=_limit_inspect_output)
            output.seek(0)
            data = output.read(HTTP_LIMIT + 1)
        _require(0 < len(data) <= HTTP_LIMIT, error)
        return sha256(data).hexdigest()
    except (OSError, subprocess.SubprocessError):
        raise PublicationError(error) from None


def _publish(registry, scratch, archive, evidence):
    expected_manifest = evidence["ociManifestSha256"]
    expected_config = evidence["ociConfigSha256"]
    tag = f"git-{evidence['revision']}-{expected_manifest[:12]}"
    digest = "sha256:" + expected_manifest
    repo = f"{HOST}/{registry.repository}"
    collision = "The provider revision tag already points to a different manifest."
    pull = registry.mint()
    current = registry.manifest(tag, pull, allow_missing=True)
    status = "adopted"
    if current is None:
        push = registry.mint(push=True)
        push_auth = _write_auth(scratch / "push-auth.json", push, registry.repository)
        current = registry.manifest(tag, pull, allow_missing=True)
        if current is None:
            _guard_main(evidence)
            _copy(scratch, archive, f"{repo}:{tag}", push_auth, digest)
            status = "published"
        else:
            _require(current == expected_manifest, collision)
    else:
        _require(current == expected_manifest, collision)
    pull_auth = _write_auth(scratch / "pull-auth.json", pull, registry.repository)
    _require(registry.manifest(digest, pull) == expected_manifest
             and _config(scratch, f"{repo}@{digest}", pull_auth) == expected_config
             and registry.manifest(tag, pull) == expected_manifest,
             "The published tag, digest or OCI config did not match the verified build.")
    _guard_main(evidence)
    return {**evidence, "tag": tag, "status": status}


def publish():
    revision = os.environ.get("GITHUB_SHA", "")
    run_id = os.environ.get("SUBS_BOT_PROVIDER_CI_RUN_ID", "")
    runner_temp = Path(os.environ.get("RUNNER_TEMP", ""))
    _require(os.environ.get("GITHUB_REPOSITORY") == github.REPOSITORY
             and os.environ.get("GITHUB_REF") == github.MAIN_REF
             and os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
             and provider.REVISION.fullmatch(revision) and provider.DECIMAL.fullmatch(run_id)
             and runner_temp.is_absolute(),
             "Provider registry publication requires a protected dispatch from the exact main revision.")
    account = os.environ.get("SUBS_BOT_CF_PROVIDER_ACCOUNT_ID", "")
    _require(ACCOUNT.fullmatch(account) and sha256(account.encode("ascii")).hexdigest() == TARGET_ACCOUNT_SHA256,
             "The protected Cloudflare account does not match the isolation target.")
    archive, evidence = _verified_input(runner_temp, revision, run_id)
    _guard_main(evidence)
    registry = Registry(account, os.environ.get("SUBS_BOT_CF_PROVIDER_CONTAINER_TOKEN", ""))
    with tempfile.TemporaryDirectory(prefix=".subs-bot-provider-registry-", dir=runner_temp) as directory:
        return _publish(registry, Path(directory), archive, evidence)


if __name__ == "__main__":
    try:
        print(json.dumps(publish(), sort_keys=True))
    except (PublicationError, github.ArtifactError) as error:
        raise SystemExit(str(error)) from None
    except provider.VERIFICATION_ERRORS:
        raise SystemExit("Provider registry publication could not be completed safely.") from None
