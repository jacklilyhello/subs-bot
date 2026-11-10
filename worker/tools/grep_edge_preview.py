"""Run one fixed public fixture using a token-gated Cloudflare edge preview."""

from hashlib import sha256
from http.client import HTTPException
from io import BytesIO
import json
import os
from pathlib import Path
import re
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import ProxyHandler, Request, build_opener
from uuid import uuid4
from zipfile import BadZipFile, ZipFile

from cloudflare_isolation import API_ORIGIN, NAMESPACE
import prepare_isolation_artifact as github
from publish_provider_registry import ACCOUNT, API_TOKEN, TARGET_ACCOUNT_SHA256


NAME = "subs-bot-grep-edge-probe"
COMPATIBILITY = "2026-07-30"
MODULE = "probe.mjs"
MAX_MODULE_BYTES = 64 * 1024
MAX_RESPONSE_BYTES = 32 * 1024
IDENTITY_HEADER = "X-Subs-Bot-Grep-Preview"
DENIED = {401, 403, 404}


class ProbeError(ValueError):
    pass


def require(condition):
    if not condition:
        raise ProbeError()


def matches(pattern, value):
    return isinstance(value, str) and re.fullmatch(pattern, value) is not None


def read_json(body):
    return github._parse_object(body, "Invalid diagnostic JSON.")


def verified_artifact(revision):
    token = github._github_token()
    run = os.environ.get("GITHUB_RUN_ID", "")
    artifact_id = os.environ.get("PROBE_ARTIFACT_ID", "")
    digest = os.environ.get("PROBE_ARTIFACT_SHA256", "")
    require(all(matches(r"[1-9][0-9]{0,19}", value) for value in (run, artifact_id))
            and matches(r"[a-f0-9]{64}", digest))
    info = github._get_json(f"/actions/artifacts/{artifact_id}", token)
    source = info.get("workflow_run")
    require(str(info.get("id")) == artifact_id and info.get("name") == f"subs-bot-grep-edge-{revision}-1"
            and info.get("expired") is False and info.get("digest") == f"sha256:{digest}"
            and isinstance(source, dict) and str(source.get("id")) == run
            and (source.get("repository_id"), source.get("head_repository_id")) == (github.REPOSITORY_ID,) * 2
            and (source.get("head_branch"), source.get("head_sha")) == ("main", revision))
    archive = github._download(artifact_id, token)
    require(len(archive) <= 128 * 1024 and sha256(archive).hexdigest() == digest)
    with ZipFile(BytesIO(archive)) as bundle:
        members = github._zip_members(bundle)
        require(set(members) == {MODULE} and 0 < members[MODULE].file_size <= MAX_MODULE_BYTES)
        return bundle.read(members[MODULE])


def request(opener, url, *, method="GET", headers=None, body=None, timeout=10):
    req = Request(url, headers={"Accept": "application/json", "Accept-Encoding": "identity",
                                "Cache-Control": "no-store", "User-Agent": "subs-bot-grep-edge-probe/1.0",
                                **(headers or {})}, method=method, data=body)
    try:
        response = opener.open(req, timeout=timeout)
    except HTTPError as error:
        response = error
    with response:
        raw = response.read(MAX_RESPONSE_BYTES + 1)
        require(len(raw) <= MAX_RESPONSE_BYTES)
        return response.code, response.headers, raw


def cf_result(status, raw, *, upload=False):
    envelope = read_json(raw)
    require((status == 200 or (upload and status == 201)) and envelope.get("success") is True
            and envelope.get("errors") in (None, []) and isinstance(envelope.get("result"), dict))
    return envelope["result"]


def require_absent(status, raw):
    envelope = read_json(raw)
    errors = envelope.get("errors")
    require(status == 404 and envelope.get("success") is False and envelope.get("result") is None
            and isinstance(errors, list) and len(errors) == 1 and isinstance(errors[0], dict)
            and type(errors[0].get("code")) is int and errors[0]["code"] == 10007)


def header_token(value):
    require(matches(r"[!-~]{1,8192}", value))
    return value


def exchange_url(value):
    # The signed exchange URL comes from the authenticated Cloudflare API. Only
    # another single-label host in the verified project workers.dev namespace is valid.
    require(matches(r"[!-~]{1,8192}", value) and "\\" not in value)
    url = urlsplit(value)
    require(url.scheme == "https" and not url.fragment
            and matches(rf"[a-z0-9](?:[a-z0-9-]{{0,61}}[a-z0-9])?\.{re.escape(NAMESPACE)}\.workers\.dev", url.netloc))
    return value


def multipart(module):
    boundary = f"subsbot-{uuid4().hex}"
    metadata = {"main_module": MODULE, "bindings": [], "compatibility_date": COMPATIBILITY,
                "compatibility_flags": [], "logpush": False, "tail_consumers": [],
                "observability": {"enabled": False, "logs": {"enabled": False, "invocation_logs": False},
                                  "traces": {"enabled": False}}}
    parts = []
    for disposition, content_type, value in (
        ('name="metadata"; filename="metadata.json"', "application/json", json.dumps(metadata).encode("ascii")),
        (f'name="{MODULE}"; filename="{MODULE}"', "application/javascript+module", module),
        ('name="wrangler-session-config"', "text/plain", b'{"workers_dev":true}'),
    ):
        parts.extend([f"--{boundary}\r\nContent-Disposition: form-data; {disposition}\r\n"
                      f"Content-Type: {content_type}\r\n\r\n".encode("ascii"), value, b"\r\n"])
    return f"multipart/form-data; boundary={boundary}", b"".join(parts) + f"--{boundary}--\r\n".encode("ascii")


def validated_report(raw):
    report = read_json(raw)
    require(set(report) == {"version", "mode", "phases", "authorizationCheck", "grepElapsedMs", "projection",
                            "repository", "elapsedMs"}
            and type(report["version"]) is int and report["version"] == 1 and report["mode"] == "worker-runtime-shape"
            and type(report["authorizationCheck"]) is bool)

    def duration(value):
        return type(value) is int and 0 <= value <= 30_000

    def status(value):
        return value is None or (type(value) is int and 100 <= value <= 599)

    phases = report["phases"]
    stages = ("initialize", "notifications/initialized", "tools/call")
    require(isinstance(phases, list) and len(phases) <= len(stages)
            and duration(report["grepElapsedMs"]) and duration(report["elapsedMs"]))
    for phase, stage in zip(phases, stages):
        require(isinstance(phase, dict) and set(phase) == {"stage", "status", "media", "sessionHeader", "headersMs", "outcome"}
                and phase["stage"] == stage and status(phase["status"]) and phase["media"] in (None, "sse", "json", "other")
                and type(phase["sessionHeader"]) is bool and duration(phase["headersMs"])
                and phase["outcome"] in ("response", "timeout", "transport-error"))
    counts = report["projection"]
    require(isinstance(counts, dict) and set(counts) == {"blocks", "textBlocks", "fixtureMetadata", "canonicalLinks", "knownPathMatches"}
            and all(type(value) is int and 0 <= value <= 20 for value in counts.values()))
    repo = report["repository"]
    require(isinstance(repo, dict) and set(repo) == {"status", "outcome", "elapsedMs"} and status(repo["status"])
            and duration(repo["elapsedMs"]) and repo["outcome"] in ("timeout", "response-rejected", "body-limit",
                "confirmed-public", "public-not-confirmed", "transport-or-body-error"))
    return report


def run(stage, revision, module, account, deploy_token, *, guard=github.require_current_main, transport=None):
    require(matches(ACCOUNT.pattern, account) and sha256(account.encode("ascii")).hexdigest() == TARGET_ACCOUNT_SHA256
            and matches(API_TOKEN.pattern, deploy_token))
    if transport is None:
        opener = build_opener(ProxyHandler({}), github._NoRedirect())

        def transport(url, **kwargs):
            return request(opener, url, **kwargs)

    root = f"{API_ORIGIN}/accounts/{account}/workers"
    script = f"{root}/scripts/{NAME}"
    origin = f"https://{NAME}.{NAMESPACE}.workers.dev/"
    api = {"Authorization": f"Bearer {deploy_token}"}
    stage("namespace")
    code, _, raw = transport(f"{root}/subdomain", headers=api)
    require(cf_result(code, raw).get("subdomain") == NAMESPACE)

    def confirm_absence():
        code, _, raw = transport(f"{root}/workers/{NAME}", headers=api)
        require_absent(code, raw)
        code, headers, _ = transport(origin)
        require(code in DENIED and headers.get(IDENTITY_HEADER) is None)

    stage("absence-before")
    confirm_absence()
    try:
        stage("session")
        guard(revision)
        # The two edge-preview calls follow the official Wrangler legacy remote-dev
        # flow. Only this POST uploads code. No deployment, routes, settings or tail.
        code, _, raw = transport(f"{script}/subdomain/edge-preview", headers=api)
        session = cf_result(code, raw)
        token = header_token(session.get("token"))
        if session.get("exchange_url") is not None:
            stage("exchange")
            code, _, raw = transport(exchange_url(session["exchange_url"]))
            require(code == 200)
            token = header_token(read_json(raw).get("token"))
        stage("upload")
        content_type, body = multipart(module)
        guard(revision)
        code, _, raw = transport(f"{script}/edge-preview", method="POST", body=body, headers={
            **api, "Content-Type": content_type, "CF-Preview-Upload-Config-Token": token,
        })
        # Discard tail_url and all other response values.
        preview_token = header_token(cf_result(code, raw, upload=True).get("preview_token"))
        stage("anonymous-denial")
        code, headers, _ = transport(origin)
        require(code in DENIED and headers.get(IDENTITY_HEADER) is None)
        stage("invoke")
        code, headers, raw = transport(origin, method="POST", timeout=15,
                                      headers={"CF-Workers-Preview-Token": preview_token})
        require(code == 200 and headers.get(IDENTITY_HEADER) == revision
                and {part.strip().lower() for part in headers.get("Cache-Control", "").split(",")} == {"private", "no-store"}
                and headers.get("Content-Type", "").split(";", 1)[0].lower() == "application/json")
        stage("report")
        report = validated_report(raw)
        guard(revision)
    finally:
        try:
            confirm_absence()
        except (OSError, ValueError, HTTPException):
            stage("absence-after")
            raise
    return report


def main():
    phase = "artifact"

    def stage(label):
        nonlocal phase
        phase = label

    try:
        revision = os.environ.get("GITHUB_SHA", "")
        require(os.environ.get("GITHUB_REPOSITORY") == github.REPOSITORY
                and os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
                and os.environ.get("GITHUB_REF") == github.MAIN_REF
                and os.environ.get("GITHUB_RUN_ATTEMPT") == "1"
                and matches(r"[a-f0-9]{40}", revision))
        github.require_current_main(revision)
        module = verified_artifact(revision)
        digest = sha256(module).hexdigest()
        require(digest == os.environ.get("PROBE_MODULE_SHA256"))
        stage("scope")
        target = read_json(os.environ.get("SUBS_BOT_CF_ISOLATION_TARGET_JSON", ""))
        require(target.get("namespace") == NAMESPACE)
        result = run(stage, revision, module, target.get("accountId"), os.environ.get("SUBS_BOT_CF_DEPLOY_TOKEN"))
        print(json.dumps({"mode": "cloudflare-edge-preview", "moduleSha256": digest, "previewIsolated": True,
                          "report": result}, separators=(",", ":")))
    except (OSError, ValueError, HTTPException, BadZipFile):
        print(f"Cloudflare Grep edge preview could not be confirmed at {phase}.")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
