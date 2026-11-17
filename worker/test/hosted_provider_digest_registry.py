"""Exercise digest publication against a disposable loopback OCI fixture only.

This is not evidence of Cloudflare Registry support or of cloud authorization.
It is invoked by GitHub hosted CI after building the exact Provider OCI archive.
"""

from hashlib import sha256
from io import BytesIO
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
from unittest.mock import Mock, patch
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import production_provider as control
import provider_digest_publish as publish
from test_prepare_provider_artifact import oci_fixture
from test_production_provider import config


def get(port, path, *, missing=False):
    request = Request(f"http://127.0.0.1:{port}/v2/{path}", headers={
        "Accept": "application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json"})
    try:
        with urlopen(request, timeout=10) as response:
            return response.read()
    except HTTPError as error:
        if missing and error.code == 404:
            return None
        raise


def copy(source, destination, scratch, *, pull=False):
    auth = scratch / "empty-auth.json"
    auth.write_text('{"auths":{}}', encoding="ascii")
    args = [control.publication.SKOPEO, "copy", "--quiet", "--preserve-digests", "--retry-times=0",
            ("--src-tls-verify=false" if pull else "--dest-tls-verify=false"),
            ("--src-authfile" if pull else "--dest-authfile"), str(auth), source, destination]
    subprocess.run(args, env=control.publication._skopeo_env(scratch), stdin=subprocess.DEVNULL,
                   timeout=180, check=True)


def tags(port, repo):
    return json.loads(get(port, f"{repo}/tags/list"))


def sentinel_archive():
    # The synthetic test helper emits root-owned tar headers. Skopeo extracts
    # the outer OCI archive as the unprivileged runner and cannot chown files
    # to root. Normalize only those outer headers; every OCI blob stays intact.
    output = BytesIO()
    with tarfile.open(fileobj=BytesIO(oci_fixture()), mode="r:") as source, \
            tarfile.open(fileobj=output, mode="w:") as destination:
        # Explicit parents prevent Skopeo from creating implicit root-owned
        # directory headers while extracting the synthetic archive.
        for name in ("blobs", "blobs/sha256"):
            directory = tarfile.TarInfo(name)
            directory.type = tarfile.DIRTYPE
            directory.mode = 0o755
            directory.uid, directory.gid = os.getuid(), os.getgid()
            directory.uname = directory.gname = ""
            destination.addfile(directory)
        for member in source:
            assert member.isfile()
            member.uid, member.gid = os.getuid(), os.getgid()
            member.uname = member.gname = ""
            destination.addfile(member, source.extractfile(member))
    return output.getvalue()


def check_closure(port, repo, digest, expected_config):
    manifest = get(port, f"{repo}/manifests/sha256:{digest}")
    assert sha256(manifest).hexdigest() == digest
    parsed = json.loads(manifest)
    assert parsed["config"]["digest"] == "sha256:" + expected_config
    assert parsed["layers"], "fixture must exercise layer readback"
    for entry in [parsed["config"], *parsed["layers"]]:
        algorithm, expected = entry["digest"].split(":", 1)
        assert algorithm == "sha256" and len(expected) == 64
        body = get(port, f"{repo}/blobs/{entry['digest']}")
        assert len(body) == entry["size"] and sha256(body).hexdigest() == expected


def run(registry, artifact, revision, root):
    build = json.loads((artifact / "provider-release.json").read_text())
    image = artifact / "provider-image.tar"
    manifest = build["ociManifestSha256"]
    config_digest = build["ociConfigSha256"]
    assert control.provider.verify_image(image, revision) == (manifest, config_digest)
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    conf = root / "registry.yml"
    conf.write_text(f"version: 0.1\nlog:\n  level: error\nstorage:\n  filesystem:\n    rootdirectory: {root}/data\n"
                    f"http:\n  addr: 127.0.0.1:{port}\n", encoding="utf-8")
    process = subprocess.Popen([str(registry), "serve", str(conf)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(100):
            if process.poll() is not None:
                raise RuntimeError("Local registry exited before becoming ready")
            try:
                get(port, "")
                break
            except URLError:
                time.sleep(0.1)
        else:
            raise RuntimeError("Local registry did not become ready")

        sentinel = root / "sentinel.tar"
        sentinel.write_bytes(sentinel_archive())
        repo = "fixture/provider"
        host = f"127.0.0.1:{port}"
        copy("oci-archive:" + str(sentinel), f"docker://{host}/{repo}:sentinel", root)
        before = tags(port, repo)
        before_manifest = get(port, f"{repo}/manifests/sentinel")
        assert before["tags"] == ["sentinel"]
        assert get(port, f"{repo}/manifests/sha256:{manifest}", missing=True) is None
        copy("oci-archive:" + str(image), f"docker://{host}/{repo}@sha256:{manifest}", root)
        assert tags(port, repo) == before
        assert get(port, f"{repo}/manifests/sentinel") == before_manifest
        check_closure(port, repo, manifest, config_digest)
        readback = root / "readback.tar"
        copy(f"docker://{host}/{repo}@sha256:{manifest}", "oci-archive:" + str(readback), root, pull=True)
        assert control.provider.verify_image(readback, revision) == (manifest, config_digest)

        # The fixture commits the real local write, then simulates losing the
        # response. The production helper must fail without another copy.
        target = config(active=True)
        target["build"].update({"revision": revision, "ociArchiveSha256": sha256(image.read_bytes()).hexdigest(),
                                "ociManifestSha256": manifest, "ociConfigSha256": config_digest})
        target["smoke"]["healthRevision"] = revision
        state = {"dependencySha256": "1" * 64, "manifestSha256": None, "tagsSha256": "4" * 64}
        refs = [{"fixture": "loopback only"}]
        with patch.dict(os.environ, {}, clear=True):
            intent = publish.intent(target, refs, state, "101", "b" * 40)
        env = {"RUNNER_TEMP": str(root), "GITHUB_RUN_ID": "101", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_SHA": "b" * 40,
               "SUBS_BOT_PROVIDER_DIGEST_APPROVAL": intent["approvalSha256"]}
        writer, reader = Mock(), Mock()
        writer.repository = "fixture/unused"
        reader.manifest.return_value = None
        calls = []
        def lost_response(_scratch, source, destination, _auth, expected):
            calls.append(destination)
            assert destination.endswith("@sha256:" + manifest) and expected == "sha256:" + manifest
            copy("oci-archive:" + str(source), f"docker://{host}/fixture/unknown@{expected}", root)
            raise control.ProviderError("fixture response lost after write")
        with patch.dict(os.environ, env, clear=True), patch.object(control, "guard_sources"), \
                patch.object(publish, "observe", return_value=state), patch.object(control, "Registry", side_effect=[writer, reader]), \
                patch.object(control.publication, "_write_auth", return_value=root / "unused"), \
                patch.object(control.publication, "_copy_image", side_effect=lost_response), \
                patch.object(control.publication, "_config") as postcheck:
            try:
                publish.publish_once(target, refs, image, intent, control.digest(intent), "fixture", "fixture", "fixture")
            except control.ProviderError:
                pass
            else:
                raise AssertionError("Lost response was incorrectly treated as success")
            assert len(calls) == 1
            postcheck.assert_not_called()
        check_closure(port, "fixture/unknown", manifest, config_digest)
        print("Loopback OCI fixture passed: digest copy, layers, tags, and response-loss refusal; not Cloudflare evidence.")
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="provider-oci-fixture-", dir=os.environ["RUNNER_TEMP"]) as temporary:
        run(Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3], Path(temporary))
