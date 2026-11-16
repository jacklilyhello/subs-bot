"""Private complete ProviderFetch source loading and an exact GET-only reader."""

from hashlib import sha256
from urllib.parse import parse_qsl, urlencode

import archive_production_provider as archive
import production_control as lifecycle
import production_provider as provider
from production_target import validate_target

ERROR = "The complete private application ProviderFetch source or exact read scope was not verified."


def require(value):
    provider.require(value, ERROR)


def load_provider(runner, run_id, attempt, manifest_sha256):
    """Load only a complete, unbound rehearsal dependency; never adopt partial proof."""
    require(provider.match(provider.provider.DECIMAL, run_id) and provider.match(provider.provider.DECIMAL, attempt)
            and provider.match(provider.provider.HEX, manifest_sha256))
    store = archive.PrivateProofStore(runner.original, runner.env.get("SUBS_BOT_CF_BOOTSTRAP_TOKEN", ""), run_id, attempt)
    verified = archive.verify_archive(store, manifest_sha256)
    raw = store.read("manifest.json")
    require(isinstance(raw, bytes) and len(raw) <= 65536 and sha256(raw).hexdigest() == manifest_sha256)
    manifest = provider.github._parse_object(raw, ERROR)
    require(type(manifest.get("version")) is int and manifest["version"] == 1
            and manifest.get("kind") == "subs-bot-provider-source-proof"
            and manifest.get("runId") == run_id and manifest.get("runAttempt") == attempt)
    proof = provider.github._parse_object(archive.read_record(store, manifest, "provider-rehearsal-proof.json"), ERROR)
    target = provider.github._parse_object(archive.read_record(store, manifest, "provider-rehearsal-target.json"), ERROR)
    journal_raw = archive.read_record(store, manifest, "provider-rehearsal-journal.json")
    journal = provider.github._parse_object(journal_raw, ERROR)
    config = provider.validate_config(target)
    require(config["environment"] == "rehearsal" and config["service"] == provider.SERVICES["rehearsal"]
            and config["caller"] is None and all(config[key] is not None
                for key in ("worker", "versionId", "activation", "container", "workflow")))
    provider.fields(proof, {"version", "controllerRevision", "runId", "runAttempt", "status", "target", "binding", "steps",
                            "journalSha256", "productionMutation"})
    require(type(proof["version"]) is int and proof["version"] == 1 and proof["status"] == "complete"
            and proof["productionMutation"] is False and proof["runId"] == run_id and proof["runAttempt"] == attempt
            and proof["controllerRevision"] == manifest["controllerRevision"]
            and provider.canonical(proof["target"]) == provider.canonical(config)
            and provider.digest(proof) == manifest["proofSha256"]
            and proof["journalSha256"] == sha256(journal_raw).hexdigest())
    binding = proof["binding"]
    provider.fields(binding, {"service", "entrypoint", "revision", "imageSha256", "callerState", "proofSha256"})
    require(binding["service"] == config["service"] and binding["entrypoint"] == "ProviderFetch"
            and binding["revision"] == config["build"]["revision"]
            and binding["imageSha256"] == config["build"]["ociManifestSha256"] and binding["callerState"] == "unbound"
            and provider.match(provider.provider.HEX, binding["proofSha256"]))
    require(type(journal.get("version")) is int and journal["version"] == 2
            and journal.get("completion") == "complete" and journal.get("controllerRevision") == proof["controllerRevision"]
            and journal.get("runId") == run_id and journal.get("runAttempt") == attempt
            and journal.get("targetSha256") == provider.digest(config)
            and provider.canonical(journal.get("source")) == provider.canonical(config["build"])
            and isinstance(proof["steps"], list) and provider.canonical(proof["steps"]) == provider.canonical(journal.get("steps")))
    intent = journal.get("currentIntent")
    require(intent is None or isinstance(intent, dict) and intent.get("status") in {"confirmed", "skipped"})
    expected_files = {"provider-source-archive.zip": config["build"]["archiveSha256"],
        "source/provider-worker.js": config["build"]["workerSha256"], "source/provider-image.tar": config["build"]["ociArchiveSha256"]}
    require(all(manifest["files"][name]["sha256"] == digest for name, digest in expected_files.items()))
    require(store.read("manifest.json") == raw)
    store.verify()
    return {"config": config, "proof": proof, "evidence": {
        "sourceRunId": run_id, "sourceRunAttempt": attempt, "manifestSha256": manifest_sha256,
        "targetSha256": provider.digest(config), "proofSha256": provider.digest(proof),
        "sourceRevision": config["build"]["revision"], "files": verified["files"], "chunks": verified["chunks"],
        "bytes": verified["bytes"], "readback": "R2-only-complete"}}


class DependencyReadOnly:
    """Permit only the exact dependency verifier's scoped GET request grammar."""

    def __init__(self, target, token, config):
        self.target = validate_target(target.data if hasattr(target, "data") else target)
        self.config = provider.validate_config(config)
        require(self.config["environment"] == self.target.environment
                and self.config["accountId"] == self.target.account_id
                and self.config["caller"] in (None, {"id": self.target.data["workerId"], "name": self.target.data["workerName"]})
                and all(self.config[key] is not None for key in ("worker", "versionId", "activation", "container", "workflow")))
        self._api = lifecycle.API(self.target, token)
        self.root = "/accounts/" + self.target.account_id
        self._paths, self._namespace_roots = set(), {}
        self._do_actors, self._container_actors, self._cursors = {}, {}, {}
        service = self.config["service"]
        worker_id = self.config["worker"]["workerId"]
        beta = self.root + "/workers/workers/" + worker_id
        script = self.root + "/workers/scripts/" + service
        workflow = self.root + "/workflows/" + service + "-smoke"
        self._paths.update({self.root + "/workers/workers/" + service, beta,
            beta + "/versions?page=1&per_page=10", script + "/deployments?page=1&per_page=100",
            self.root + "/workers/durable_objects/namespaces?page=1&per_page=1000",
            self.root + "/containers/applications?per_page=500", workflow,
            workflow + "/versions?page=1&per_page=10", workflow + "/instances?page=1&per_page=10"})
        for release in provider.releases(self.config):
            if release["versionId"] is not None:
                self._paths.add(beta + "/versions/" + release["versionId"] + "?include=modules")
                self._paths.add(script + "/versions/" + release["versionId"])
            if release["activation"] is not None:
                self._paths.add(script + "/deployments/" + release["activation"]["deploymentId"])
                namespace = release["activation"]["namespaceId"]
                objects = self.root + "/workers/durable_objects/namespaces/" + namespace + "/objects"
                app = self.root + "/containers/applications/" + namespace
                self._namespace_roots[namespace] = (objects, app)
                self._paths.update({objects + "?limit=10", app,
                    app + "/instances-v2?per_page=2", app + "/instances-v2?per_page=2&state=active"})
            if release["workflow"] is not None:
                self._paths.add(workflow + "/versions/" + release["workflow"]["versionId"])
                self._paths.add(workflow + "/instances/provider-release-" + release["build"]["revision"] + "?simple=true")

    def request(self, method, path, payload=None, *, envelope=False):
        require(method == "GET" and payload is None and type(envelope) is bool and isinstance(path, str)
                and path.isascii() and 0 < len(path) <= 8192 and "%" not in path.partition("?")[0])
        allowed = path in self._paths
        for namespace, (objects, app) in self._namespace_roots.items():
            if path.startswith(objects + "?") and path != objects + "?limit=10":
                try:
                    pairs = parse_qsl(path.partition("?")[2], strict_parsing=True, keep_blank_values=True)
                except ValueError:
                    pairs = []
                allowed = (len(pairs) == 2 and pairs[0] == ("limit", "10") and pairs[1][0] == "cursor"
                    and provider.match(provider.legacy.ACTOR_CURSOR, pairs[1][1])
                    and self._cursors.get(namespace) == pairs[1][1]
                    and path == objects + "?" + urlencode(pairs))
            if path.startswith(app + "/instances/"):
                actor = path[len(app + "/instances/"):]
                allowed = provider.match(provider.legacy.ACTOR, actor) \
                    and actor in self._do_actors.get(namespace, set()) and actor in self._container_actors.get(namespace, set())
        require(allowed)
        result = self._api("GET", path, envelope=True)
        require(isinstance(result, dict) and result.get("success") is True and "result" in result)
        for namespace, (objects, app) in self._namespace_roots.items():
            if path.startswith(objects + "?"):
                rows, cursor = provider.legacy._actor_page(result)
                require(all(isinstance(row, dict) and provider.match(provider.legacy.ACTOR, row.get("id"))
                            and type(row.get("hasStoredData")) is bool for row in rows))
                if path == objects + "?limit=10":
                    self._do_actors[namespace] = set()
                    self._cursors.pop(namespace, None)
                self._do_actors[namespace] = self._do_actors.get(namespace, set()) | {row["id"] for row in rows if row["hasStoredData"]}
                if cursor:
                    self._cursors[namespace] = cursor
            if path == app + "/instances-v2?per_page=2":
                rows = provider.legacy._page(result, result["result"], 1, cursor=True)
                require(all(isinstance(row, dict) and provider.match(provider.legacy.ACTOR, row.get("id"))
                            and row.get("application_id") == namespace for row in rows))
                self._container_actors[namespace] = {row["id"] for row in rows}
        return result if envelope else result["result"]
