"""Bounded monitor outputs for an independently configured alert receiver.

This module sends nothing and receives no notification or write credentials.
The complete alert list and failing check are never filtered.
"""
from hashlib import sha256
import json
import os
import re
from pathlib import Path

from production_target import require

ALERT = re.compile(r"[a-z][a-z0-9-]{0,79}")


def prepare(report, selector):
    require(isinstance(report, dict) and report.get("status") in {"ok", "alert"}
            and isinstance(report.get("alerts"), list) and len(report["alerts"]) <= 64
            and all(isinstance(item, str) and ALERT.fullmatch(item) for item in report["alerts"]))
    selector = selector or "*"
    if selector == "*":
        selected = None
    else:
        items = selector.split(",") if isinstance(selector, str) else []
        if not items or len(items) > 64 or not all(ALERT.fullmatch(item) for item in items) or len(set(items)) != len(items):
            report["alerts"] = sorted(set(report["alerts"]) | {"notification-config-invalid"})
            report["status"] = "alert"
            selected = None
            selector = "invalid"
        else:
            selected = set(items)
    # An unknown monitor or invalid configuration must never be silently routed away.
    essential = {"monitor-unknown", "live-capacity-unknown", "notification-config-invalid"}
    relevant = any(selected is None or alert in selected or alert in essential or alert.endswith("-unknown")
                   for alert in report["alerts"])
    report["notification"] = "github-check-only"
    report["notificationFilter"] = selector
    report["notificationRelevant"] = relevant
    return report


def write(report, destination, output_path=None):
    body = json.dumps(report, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
    path = Path(destination)
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "wb") as stream:
        stream.write(body)
    digest = sha256(body).hexdigest()
    if output_path:
        alerts = json.dumps(report["alerts"], separators=(",", ":"))
        with open(output_path, "a", encoding="utf-8") as stream:
            stream.write("status=" + report["status"] + "\nalerts_json=" + alerts + "\nreport_sha256=" + digest
                         + "\nnotification_relevant=" + str(report["notificationRelevant"]).lower() + "\n")
    return digest
