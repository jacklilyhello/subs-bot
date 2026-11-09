"""HTTP checks for a fixed synthetic legacy selected aggregate cohort.

Call from the protected fixture workflow after the exact active release and
resource readbacks. This module cannot provision, publish or retire fixtures.
"""

from hashlib import sha256
import json
import re
from time import monotonic

from capacity_probe import ProbeError, _check_headers, _request, _small_body
from legacy_typed_short_smoke import EXPECTED_CLASH
from telegram_aggregate_smoke import expected_fixture_exports


CODE = re.compile(r"[A-Za-z0-9_-]{12}")
LINKS = ("marked", "marked-empty", "ordinary", "ordinary-empty")
STAGES = ("published", "member-retired", "cohort-retired")
TEXT = "text/plain; charset=utf-8"
YAML = "text/yaml; charset=utf-8"
SINGBOX = "application/json; charset=utf-8"
NOT_FOUND = b"Not found."
EMPTY_SINGBOX = json.dumps({"outbounds": [
    {"type": "selector", "tag": "proxy", "outbounds": ["direct"]},
    {"type": "direct", "tag": "direct"},
]}, indent=2).encode("ascii")
EMPTY_SURGE = b"[Proxy]\n\n[Proxy Group]\nProxy = select, DIRECT\n\n[Rule]\nFINAL,Proxy\n"


def fixture_node(label):
    server = {"alpha": "203.0.113.10", "beta": "203.0.113.20"}[label]
    name = "legacy-selected-" + label
    return {"name": name, "type": "ss", "server": server, "port": 8388, "cipher": "aes-256-gcm",
            "password": "fixture", "share": f"ss://YWVzLTI1Ni1nY206Zml4dHVyZQ@{server}:8388#{name}"}


def _probe_pair(path, label, deadline, status, content_type, body, *, location=None):
    result = {"status": status, "bodyBytes": len(body), "bodySha256": sha256(body).hexdigest()}
    media = content_type.split(";", 1)[0] if content_type else None
    for method in ("GET", "HEAD"):
        with _request(method, path, deadline, label) as response:
            _check_headers(response, status, label, media, location=location)
            if content_type and response.getheader("Content-Type") != content_type:
                raise ProbeError(f"Exact response content type differs for {label}.")
            length = response.getheader("Content-Length")
            if method == "HEAD":
                # An edge can omit the representation length for a null-body HEAD.
                if response.read(1) or length not in (None, "0", str(len(body))):
                    raise ProbeError(f"HEAD framing differs for {label}.")
                result["headContentLength"] = int(length) if length is not None else None
            else:
                if _small_body(response) != body:
                    raise ProbeError(f"Exact response bytes differ for {label}.")
                if (length not in (None, str(len(body))) or (status == 200 and body
                        and (length is None or response.getheader("Transfer-Encoding") is not None))):
                    raise ProbeError(f"GET representation length differs for {label}.")
    return result


def verify_legacy_selected_http(codes, stage):
    """Verify only known synthetic links and return safe response evidence.

    The marked selection is [beta, alpha, beta]. The ordinary control is
    [beta, alpha]. Both empty links point to the same marked legacy empty
    subscription. A fixture writer flips only the beta watch between the
    published and member-retired stages. It retires all four links last.
    """
    if (stage not in STAGES or not isinstance(codes, dict) or set(codes) != set(LINKS)
            or not all(isinstance(code, str) and CODE.fullmatch(code) for code in codes.values())
            or len(set(codes.values())) != len(LINKS)):
        raise ProbeError("Legacy selected fixture inputs differ.")
    deadline = monotonic() + 90
    report = {}

    def export(link, suffix, status, content_type, body):
        label = f"{link}/{suffix}"
        report[label] = _probe_pair(f"/agg/{codes[link]}/{suffix}", label, deadline, status, content_type, body)

    def redirect(link, active):
        label = f"{link} redirect"
        code = codes[link]
        report[label] = _probe_pair(f"/s/{code}", label, deadline, 302 if active else 404,
                                    None if active else TEXT, b"" if active else NOT_FOUND,
                                    location=f"/agg/{code}/clash" if active else None)

    if stage == "cohort-retired":
        for link in LINKS:
            redirect(link, False)
            export(link, "base64", 404, TEXT, NOT_FOUND)
        return report

    alpha, beta = (fixture_node(label) for label in ("alpha", "beta"))
    ordinary = expected_fixture_exports([beta, alpha])
    export("ordinary", "base64", 200, TEXT, ordinary["base64"])
    redirect("marked", True)
    if stage == "member-retired":
        export("marked", "base64", 200, TEXT, expected_fixture_exports([alpha])["base64"])
        return report

    # Clash allocates a new display label for the repeated Beta proxy. The
    # raw Base64 representation retains the original share URI twice.
    repeated = dict(beta, name=beta["name"] + " (2)")
    marked = expected_fixture_exports([beta, alpha, repeated])
    for suffix in ("base64", "v2ray", "mixed"):
        export("marked", suffix, 200, TEXT, marked["base64"])
    for suffix in ("clash", "unknown-format"):
        export("marked", suffix, 200, YAML, marked["clash"])
    redirect("marked-empty", True)
    for suffix, media, body in (
        ("clash", YAML, EXPECTED_CLASH), ("unknown-format", YAML, EXPECTED_CLASH),
        ("singbox", SINGBOX, EMPTY_SINGBOX), ("sing-box", SINGBOX, EMPTY_SINGBOX),
        ("surge", TEXT, EMPTY_SURGE),
        *((suffix, TEXT, b"") for suffix in ("base64", "v2ray", "mixed", "qx", "quantumult", "quantumultx")),
    ):
        export("marked-empty", suffix, 200, media, body)
    export("ordinary", "unknown-format", 406, TEXT, b"Export format unavailable.")
    export("ordinary-empty", "base64", 404, TEXT, NOT_FOUND)
    return report
