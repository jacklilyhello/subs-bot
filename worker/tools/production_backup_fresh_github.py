"""Fresh conditional reads for the fixed scheduled-backup liveness endpoints."""
import re
from hashlib import sha256
from urllib.error import HTTPError, URLError
from http.client import HTTPException

import prepare_isolation_artifact as github
from production_target import require


class FreshConditionalJSON:
    """Revalidate on the network every time; retain bytes only within one job."""

    def __init__(self):
        self._cached = {}
        self._poisoned = set()

    def get(self, path, *, verify):
        require(path == "/git/ref/heads/main" or re.fullmatch(r"/actions/jobs/[1-9][0-9]{0,19}", path)
                or re.fullmatch(r"/actions/runs/[1-9][0-9]{0,19}(?:/attempts/1)?", path),
                "The requested liveness endpoint is not permitted.")
        require(callable(verify) and path not in self._poisoned,
                "A failed liveness read requires independent reconciliation.")
        try:
            return self._read(path, verify)
        except Exception:
            self._cached.pop(path, None)
            self._poisoned.add(path)
            raise

    def _read(self, path, verify):
        token = github._github_token()
        request = github._api_request(path, token)
        previous = self._cached.get(path)
        if previous is not None:
            request.add_header("If-None-Match", previous[0])
        try:
            with github._OPENER.open(request, timeout=20) as response:
                require(response.status == 200)
                etag = response.headers.get("ETag", "")
                require(isinstance(etag, str) and re.fullmatch(r'(?:W/)?"[!#-~]{1,255}"', etag),
                        "The live GitHub response lacks a bounded validator.")
                body = github._bounded_read(response, github._MAX_JSON)
                value = github._parse_object(body, "The live GitHub response is invalid.")
                require(verify(value) is True, "The live GitHub identity is not confirmed.")
                self._cached[path] = (etag, body, sha256(body).hexdigest())
                return value
        except HTTPError as error:
            try:
                observed = error.headers.get("ETag", "")
                normalized = lambda value: value[2:] if value.startswith("W/") else value
                require(error.code == 304 and previous is not None
                        and isinstance(observed, str) and re.fullmatch(r'(?:W/)?"[!#-~]{1,255}"', observed)
                        and normalized(observed) == normalized(previous[0])
                        and sha256(previous[1]).hexdigest() == previous[2] and not error.read(1),
                        "The conditional liveness response is not confirmed.")
                value = github._parse_object(previous[1], "The verified live response is invalid.")
                require(verify(value) is True, "The live GitHub identity is no longer confirmed.")
                return value
            finally:
                error.close()
        except (URLError, OSError, HTTPException):
            require(False, "The live GitHub liveness check is unavailable.")
