"""Observe two fixed public search endpoints from a credential-free hosted runner."""

from contextlib import closing
from dataclasses import dataclass, field
from http.client import HTTPException, HTTPSConnection
import json
import re
import signal
import sys
from time import monotonic
from urllib.parse import urlencode


GITHUB, GREP = "api.github.com", "mcp.grep.app"
REPO, PATH = "jquery/jquery", "src/attributes/classes.js"
POSITIVE = "addClass"
NEGATIVE = "subsbotcapabilitynomatch7ab540f1e3844f6f9a95f8b15392037e"
MCP_VERSION = "2025-06-18"
LEGACY_VERSIONS = {"2025-03-26", MCP_VERSION, "2025-11-25"}
MAX_BODY = 256 * 1024
FIXTURE_LINK = re.compile(rf"https://github\.com/{REPO}/blob/([A-Za-z0-9._/-]{{1,128}})/{re.escape(PATH)}")


class ProbeError(RuntimeError):
    """A fixed diagnostic label independent of upstream content."""


@dataclass(frozen=True)
class Reply:
    status: int | None
    media: str | None = None
    value: object = field(default=None, repr=False)
    session: str | None = field(default=None, repr=False)
    fault: str | None = None


def _unique(pairs):
    result = dict(pairs)
    if len(result) != len(pairs):
        raise ValueError()
    return result


def _decode(raw):
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_unique)
    except (ValueError, RecursionError):
        raise ProbeError("malformed") from None


def _sse(response):
    remaining, data, event = MAX_BODY, [], b"message"
    while line := response.readline(remaining + 1):
        remaining -= len(line)
        if remaining < 0:
            raise ProbeError("body-limit")
        line = line.rstrip(b"\r\n")
        if not line:
            if any(data):
                if event != b"message":
                    raise ProbeError("unsupported-sse-event")
                return _decode(b"\n".join(data))
            data, event = [], b"message"
        elif line.startswith(b"data:"):
            data.append(line[5:].removeprefix(b" "))
        elif line.startswith(b"event:"):
            event = line[6:].removeprefix(b" ") or b"message"
    raise ProbeError("malformed")


def _exchange(host, path, method, headers, body, *, deadline):
    status = media = None
    try:
        remaining = deadline - monotonic()
        if remaining <= 0:
            raise TimeoutError()
        with closing(HTTPSConnection(host, timeout=min(5, remaining))) as connection:
            connection.request(method, path, body=body, headers={
                "User-Agent": "subs-bot-public-search-probe/1.0", "Accept-Encoding": "identity",
                "Cache-Control": "no-store", **headers,
            })
            with closing(connection.getresponse()) as response:
                status = response.status
                if status == 202:
                    return Reply(status, fault="malformed" if response.read(1) else None)
                if status != 200:
                    limited = status == 403 and (response.getheader("X-RateLimit-Remaining") == "0"
                                                or response.getheader("Retry-After") is not None)
                    return Reply(status, fault="rate-limited" if limited else None)
                content_type = response.getheader("Content-Type", "").split(";", 1)[0].strip().lower()
                media = {"application/json": "json", "application/vnd.github+json": "json", "text/event-stream": "sse"}.get(content_type)
                if media is None or response.getheader("Content-Encoding", "identity").lower() != "identity":
                    raise ProbeError("unsupported-content")
                if media == "sse":
                    value = _sse(response)
                else:
                    raw = response.read(MAX_BODY + 1)
                    if len(raw) > MAX_BODY:
                        raise ProbeError("body-limit")
                    value = _decode(raw)
                return Reply(status, media, value, response.getheader("Mcp-Session-Id"))
    except ProbeError as error:
        return Reply(status, media, fault=str(error))
    except TimeoutError:
        return Reply(status, media, fault="timeout")
    except (HTTPException, OSError, ValueError):
        return Reply(status, media, fault="transport-error")


def _failure(reply):
    if reply.fault:
        return reply.fault
    if reply.status is not None and 300 <= reply.status < 400:
        return "redirect"
    return {401: "auth-required", 403: "forbidden", 404: "endpoint-unavailable",
            422: "validation-rejected", 429: "rate-limited"}.get(reply.status, "http-error")


def _fixture_link(value):
    match = FIXTURE_LINK.fullmatch(value) if isinstance(value, str) else None
    return match is not None and all(part not in {"", ".", ".."} for part in match[1].split("/"))


def _github_case(exchange, keyword):
    folder, _, name = PATH.rpartition("/")
    query = f"{keyword} in:file repo:{REPO} path:{folder} filename:{name}"
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2026-03-10"}
    reply = exchange(GITHUB, "/search/code?" + urlencode({"q": query, "per_page": 1}), "GET", headers, None)
    result = {"status": reply.status, "outcome": "malformed", "verifiedMatches": 0}
    if reply.status != 200 or reply.fault:
        result["outcome"] = _failure(reply)
        return result
    if reply.media != "json" or not isinstance(reply.value, dict):
        return result
    total, partial, items = (reply.value.get(key) for key in ("total_count", "incomplete_results", "items"))
    if type(total) is not int or total < 0 or type(partial) is not bool or not isinstance(items, list) or len(items) > 1:
        return result
    if partial:
        result["outcome"] = "incomplete"
    elif total == 0 and not items:
        result["outcome"] = "empty"
    elif total > 0 and items:
        item = items[0] if isinstance(items[0], dict) else {}
        repo = item.get("repository")
        if (isinstance(repo, dict) and repo.get("full_name") == REPO and repo.get("private") is False
                and repo.get("visibility", "public") == "public" and item.get("path") == PATH and _fixture_link(item.get("html_url"))):
            result.update(outcome="match", verifiedMatches=1)
        else:
            result["outcome"] = "unverified-match"
    return result


def probe_github(exchange):
    positive = _github_case(exchange, POSITIVE)
    return {"positive": positive, "negative": _github_case(exchange, NEGATIVE) if positive["outcome"] == "match" else None}


def _rpc_result(reply, request_id):
    if reply.status != 200 or reply.fault:
        raise ProbeError(_failure(reply))
    envelope = reply.value
    if (not isinstance(envelope, dict) or envelope.get("jsonrpc") != "2.0" or type(envelope.get("id")) is not int
            or envelope["id"] != request_id or ("error" in envelope) == ("result" in envelope)):
        raise ProbeError("malformed-rpc")
    if "error" in envelope:
        error = envelope["error"]
        raise ProbeError("method-unavailable" if isinstance(error, dict) and error.get("code") == -32601 else "rpc-error")
    if not isinstance(envelope["result"], dict):
        raise ProbeError("malformed-rpc")
    return envelope["result"]


def _grep_hit(text):
    lines = text.splitlines()
    if len(lines) < 5:
        return False
    return (lines[0] == f"Repository: {REPO}" and lines[1] == f"Path: {PATH}" and lines[2].startswith("URL: ")
            and _fixture_link(lines[2][5:]) and lines[3].startswith("License: ")
            and next((line for line in lines[4:7] if line), "") == "Snippets:")


def _grep_case(call, request_id, keyword):
    reply = call("tools/call", request_id, {"name": "searchGitHub", "arguments": {
        "query": keyword, "repo": REPO, "path": PATH, "useRegexp": False,
    }})
    result = {"status": reply.status, "media": reply.media, "outcome": "malformed", "verifiedMatches": 0}
    try:
        value = _rpc_result(reply, request_id)
    except ProbeError as error:
        result["outcome"] = str(error)
        return result
    content = value.get("content")
    if value.get("isError") is True:
        result["outcome"] = "tool-error"
    elif "structuredContent" in value:
        result["outcome"] = "unconfirmed-structured"
    elif (value.get("isError", False) is False and isinstance(content, list) and len(content) <= 20
          and all(isinstance(item, dict) and item.get("type") == "text" and isinstance(item.get("text"), str) for item in content)):
        matches = sum(_grep_hit(item["text"]) for item in content)
        result.update(verifiedMatches=matches, outcome="match" if matches else "opaque-text" if content else "empty-content")
    return result


def probe_grep(exchange):
    report = {"stage": "initialize", "outcome": "not-attempted", "status": None, "protocol": None,
              "media": None, "sessionMode": None, "positive": None, "negative": None}
    version = session = None

    def call(method, request_id=None, params=None):
        message = {"jsonrpc": "2.0", "method": method}
        if request_id is not None:
            message.update(id=request_id, params=params)
        headers = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
        if version is not None:
            headers["MCP-Protocol-Version"] = version
        if session is not None:
            headers["Mcp-Session-Id"] = session
        return exchange(GREP, "/", "POST", headers, json.dumps(message).encode("utf-8"))

    try:
        reply = call("initialize", 1, {"protocolVersion": MCP_VERSION, "capabilities": {},
                     "clientInfo": {"name": "subs-bot-public-search-probe", "version": "1.0.0"}})
        report.update(status=reply.status, media=reply.media)
        version, session = _rpc_result(reply, 1).get("protocolVersion"), reply.session
        if not isinstance(version, str) or version not in LEGACY_VERSIONS:
            raise ProbeError("unsupported-protocol")
        if session is not None and not re.fullmatch(r"[!-~]{1,256}", session):
            raise ProbeError("malformed-session")
        report.update(stage="initialized", protocol=version, sessionMode="present" if session else "none")
        reply = call("notifications/initialized")
        report["status"] = reply.status
        if reply.status != 202 or reply.fault:
            raise ProbeError(_failure(reply))
        report["stage"] = "tools-list"
        reply = call("tools/list", 2, {})
        report["status"] = reply.status
        listing = _rpc_result(reply, 2)
        tools = listing.get("tools")
        if not isinstance(tools, list) or len(tools) > 32 or not all(isinstance(tool, dict) for tool in tools):
            raise ProbeError("malformed-tool-list")
        matching = [tool for tool in tools if tool.get("name") == "searchGitHub"]
        if not matching:
            raise ProbeError("tool-list-incomplete" if listing.get("nextCursor") is not None else "tool-absent")
        if len(matching) != 1 or not isinstance(matching[0].get("inputSchema"), dict):
            raise ProbeError("unconfirmed-tool-schema")
        report.update(stage="tool-calls", outcome="tool-present")
        report["positive"] = _grep_case(call, 3, POSITIVE)
        if report["positive"]["outcome"] == "match":
            report["negative"] = _grep_case(call, 4, NEGATIVE)
    except ProbeError as error:
        report["outcome"] = str(error)
    return report


def _on_timeout(_signal, _frame):
    raise TimeoutError()


def _bounded_probe(probe, seconds):
    deadline = monotonic() + seconds
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        return probe(lambda *args: _exchange(*args, deadline=deadline))
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)


def main():
    signal.signal(signal.SIGALRM, _on_timeout)
    try:
        report = {"version": 1, "github": _bounded_probe(probe_github, 8), "grep": _bounded_probe(probe_grep, 20)}
        print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    except Exception:
        print("Public search capability probe could not be confirmed safely.", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
