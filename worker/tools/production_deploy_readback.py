"""Bounded visibility readback after one explicitly recorded deployment response.

The caller supplies a GET-only reader and the existing complete desired-release
verifier. Only the exact independently verified predecessor can be transient.
No exception from either callback is caught, and this module performs no writes.
"""

from copy import deepcopy
from datetime import date
import json
import re
from time import sleep


FIELDS = frozenset({"revision", "moduleSha256", "versionId", "deploymentId", "bindings", "compatibilityDate"})
UUID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")
REVISION = re.compile(r"[0-9a-f]{40}")
DIGEST = re.compile(r"[0-9a-f]{64}")
DELAYS = (1, 3)
KINDS = frozenset({"invalid-contract", "invalid-observation", "unexpected-deployment",
                   "invalid-verification-result", "previous-still-visible"})


class ReadbackError(ValueError):
    def __init__(self, kind, *, attempts=0):
        if kind not in KINDS or type(attempts) is not int or not 0 <= attempts <= 3:
            kind, attempts = "invalid-contract", 0
        super().__init__("Production deployment readback was not confirmed.")
        self.kind, self.attempts = kind, attempts


def _matches(pattern, value):
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def _snapshot(value, *, kind, attempts=0):
    if not isinstance(value, dict) or set(value) != FIELDS or not isinstance(value["bindings"], dict):
        raise ReadbackError(kind, attempts=attempts)
    identities = (value["versionId"], value["deploymentId"])
    empty = all(value[name] is None for name in FIELDS - {"bindings"}) and value["bindings"] == {}
    if not empty:
        if not (all(_matches(UUID, item) for item in identities)
                and _matches(REVISION, value["revision"]) and _matches(DIGEST, value["moduleSha256"])
                and isinstance(value["compatibilityDate"], str) and len(value["compatibilityDate"]) == 10
                and 1 <= len(value["bindings"]) <= 50):
            raise ReadbackError(kind, attempts=attempts)
        try:
            if date.fromisoformat(value["compatibilityDate"]).isoformat() != value["compatibilityDate"]:
                raise ValueError()
        except ValueError:
            raise ReadbackError(kind, attempts=attempts) from None
        for name, binding in value["bindings"].items():
            if (not isinstance(name, str) or not isinstance(binding, dict) or binding.get("name") != name
                    or not isinstance(binding.get("type"), str)
                    or binding.get("type") == "secret_text" and "text" in binding):
                raise ReadbackError(kind, attempts=attempts)
    try:
        # Canonical JSON preserves booleans versus numbers, unlike dict equality.
        raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                         allow_nan=False)
        snapshot = deepcopy(value)
    except (TypeError, ValueError, RecursionError):
        raise ReadbackError(kind, attempts=attempts) from None
    return snapshot, raw


def wait_for_deployment(read, *, previous, desired_version, desired_deployment, verify_desired, pause=sleep):
    """Read immediately, then at most twice after 1s/3s of exact-old visibility.

    ``previous`` must be the full already verified active response, including its
    binding metadata, or the exact empty active response. ``desired_deployment``
    is the ID returned by the single deployment POST, never a name or latest-ID
    lookup. The verifier must return None and raise on any unconfirmed desired
    field/dependency; it is never retried. Reader failures are never retried.
    """
    if (not all(callable(callback) for callback in (read, verify_desired, pause))
            or not _matches(UUID, desired_version) or not _matches(UUID, desired_deployment)):
        raise ReadbackError("invalid-contract")
    frozen_previous, previous_json = _snapshot(previous, kind="invalid-contract")
    desired = (desired_version, desired_deployment)
    if desired == (frozen_previous["versionId"], frozen_previous["deploymentId"]):
        raise ReadbackError("invalid-contract")
    for attempt in range(1, 4):
        observed, observed_json = _snapshot(read(), kind="invalid-observation", attempts=attempt)
        if (observed["versionId"], observed["deploymentId"]) == desired:
            if verify_desired(observed) is not None:
                raise ReadbackError("invalid-verification-result", attempts=attempt)
            return observed
        if observed_json != previous_json:
            raise ReadbackError("unexpected-deployment", attempts=attempt)
        if attempt == 3:
            raise ReadbackError("previous-still-visible", attempts=attempt)
        pause(DELAYS[attempt - 1])
