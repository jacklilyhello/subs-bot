"""Hosted-only SIGTERM budget checks against the exact loaded OCI process.

The holder runs inside the network-disabled container. No debug endpoint or
production server configuration is introduced by these fixtures.
"""
from http.client import HTTPConnection
import json
import os
from pathlib import Path
import re
import select
import socket
import subprocess
import sys
from time import monotonic, monotonic_ns, sleep

MODES = ("idle", "incomplete", "active")
EXIT_BUDGET = 8


def require(value):
    if not value:
        raise RuntimeError("The hosted OCI shutdown fixture did not verify.")


def request(path, payload=None):
    connection = HTTPConnection("127.0.0.1", 8080, timeout=0.3)
    headers = {"Host": "container"}
    if payload is not None:
        headers["Content-Type"] = "application/json"
    try:
        connection.request("POST" if payload is not None else "GET", path,
                           None if payload is None else json.dumps(payload), headers)
        with connection.getresponse() as response:
            return response.status, json.loads(response.read(1025))
    finally:
        connection.close()


def hold(revision, mode):
    require(mode in MODES and re.fullmatch(r"[0-9a-f]{40}", revision))
    deadline = monotonic() + 30
    while True:
        try:
            require(request("/ready") == (200, {"ok": True, "revision": revision}))
            break
        except OSError:
            require(monotonic() < deadline)
            sleep(0.05)
    busy = False
    if mode == "idle":
        connection = HTTPConnection("127.0.0.1", 8080, timeout=1)
        connection.request("GET", "/ready", headers={"Host": "container"})
        response = connection.getresponse()
        require(response.status == 200 and response.version == 11 and not response.will_close
                and json.loads(response.read(1025)) == {"ok": True, "revision": revision}
                and connection.sock is not None)
        held = connection
        opened = monotonic_ns()
    else:
        held = socket.create_connection(("127.0.0.1", 8080), timeout=1)
        opened = monotonic_ns()
        head = b"POST /v1/fetch HTTP/1.1\r\nHost: container\r\nContent-Type: application/json\r\nContent-Length: 4096\r\n"
        # Incomplete headers have no handler. Complete headers plus a partial
        # body enter the real server's bounded request.read() await.
        held.sendall(head if mode == "incomplete" else head + b"\r\n{")
        if mode == "active":
            while monotonic_ns() - opened < 900_000_000:
                if request("/v1/fetch", {"url": "http://127.0.0.1/"}) == (429, {"error": "busy"}):
                    busy = True
                    break
                sleep(0.01)
            require(busy)
        held.settimeout(0.05)
        try:
            held.recv(1)
        except TimeoutError:
            pass
        else:
            require(False)
    require(monotonic_ns() - opened < 1_000_000_000)
    print(json.dumps({"mode": mode, "revision": revision, "openedAtNs": opened, "busyProof": busy}), flush=True)
    # Keep the actual connection open until PID 1 exits. Docker then terminates
    # this auxiliary exec process; its exit status is not the server's status.
    sleep(20)
    require(False)


def docker(*args, timeout=15):
    result = subprocess.run(["docker", *args], check=True, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=timeout, text=True)
    return result.stdout.strip()


def verify(image, revision):
    require(os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
            and os.environ.get("GITHUB_ACTIONS") == "true"
            and os.environ.get("GITHUB_REPOSITORY") == "jacklilyhello/subs-bot"
            and revision == os.environ.get("BUILD_REVISION")
            and re.fullmatch(r"sha256:[0-9a-f]{64}", image) and re.fullmatch(r"[0-9a-f]{40}", revision))
    source = Path(__file__).read_text("utf-8")
    for mode in MODES:
        name, holder = "provider-shutdown-" + mode, None
        try:
            docker("run", "--detach", "--name", name, "--network", "none", "--read-only", "--cap-drop", "ALL",
                   "--security-opt", "no-new-privileges", "--memory", "256m", "--cpus", "0.0625", image)
            holder = subprocess.Popen(["docker", "exec", "-i", name, "python", "-B", "-", "hold", revision, mode],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            require(holder.stdin is not None and holder.stdout is not None)
            holder.stdin.write(source)
            holder.stdin.close()
            require(select.select([holder.stdout], [], [], 35)[0])
            marker = json.loads(holder.stdout.readline(1025))
            require(isinstance(marker, dict) and set(marker) == {"mode", "revision", "openedAtNs", "busyProof"}
                    and marker["mode"] == mode and marker["revision"] == revision
                    and type(marker["openedAtNs"]) is int and marker["busyProof"] is (mode == "active")
                    and 0 <= monotonic_ns() - marker["openedAtNs"] < 1_000_000_000
                    and holder.poll() is None)
            started = monotonic()
            docker("kill", "--signal=TERM", name, timeout=3)
            fixture_to_signal_ms = (monotonic_ns() - marker["openedAtNs"]) // 1_000_000
            # The real partial-body handler has a three-second read deadline.
            # A slow Docker CLI must fail rather than turn its expiry into an
            # idle-connection shutdown that is mislabeled as an active test.
            require(mode != "active" or fixture_to_signal_ms < 2000)
            exit_code = docker("wait", name, timeout=EXIT_BUDGET)
            elapsed = monotonic() - started
            require(exit_code == "0" and elapsed < EXIT_BUDGET
                    and docker("inspect", "--format", "{{.State.ExitCode}} {{.State.Running}}", name) == "0 false")
            print(json.dumps({"case": mode, "signal": 15, "exitCode": 0, "running": False,
                              "busyHandlerProved": marker["busyProof"], "elapsedMs": int(elapsed * 1000),
                              "fixtureToSignalMs": fixture_to_signal_ms,
                              "activeSignalMaximumMs": 2000 if mode == "active" else None,
                              "maximumMs": EXIT_BUDGET * 1000}), flush=True)
        finally:
            # Cleanup is outside the acceptance check; a forced removal cannot
            # manufacture a successful PID 1 exit or a passing budget result.
            subprocess.run(["docker", "rm", "-f", name], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=10, check=False)
            if holder is not None:
                try:
                    holder.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    holder.kill()
                    holder.wait(timeout=5)
                if holder.stdout is not None:
                    holder.stdout.close()


if __name__ == "__main__":
    try:
        if len(sys.argv) == 4 and sys.argv[1] == "hold":
            hold(sys.argv[2], sys.argv[3])
        else:
            require(len(sys.argv) == 3)
            verify(sys.argv[1], sys.argv[2])
    except Exception:
        raise SystemExit("The hosted OCI SIGTERM shutdown budget was not verified.") from None
