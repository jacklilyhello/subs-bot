"""Synthetic hosted coverage for the dormant legacy authorization plan."""

from contextlib import closing, redirect_stderr, redirect_stdout
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import sqlite3
import stat
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import legacy_authorization_inventory as inventory
import legacy_authorization_reconcile as tool


def line(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"


class LegacyAuthorizationReconcileTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.backup = self.root / "legacy.sqlite"
        self.inventory = self.root / "inventory"
        self.config = self.root / "effective.json"
        self.target = self.root / "target.json"
        self.output = self.root / "output"
        self.target_sha = self.write_document(self.target, {
            "version": 1, "botId": "105", "adminId": "101", "memberId": "102",
        })

    def write_document(self, path, value):
        raw = line(value)
        path.write_bytes(raw)
        path.chmod(0o600)
        return sha256(raw).hexdigest()

    def make_source(self, rows=(), *, present=True):
        with closing(sqlite3.connect(self.backup)) as db, db:
            db.execute("CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT)")
            if present:
                db.execute("""CREATE TABLE auth_overrides (
                    user_id INTEGER PRIMARY KEY, allowed INTEGER NOT NULL,
                    created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
                )""")
                db.executemany("INSERT INTO auth_overrides VALUES (?, ?, ?, ?)", rows)
        self.backup.chmod(0o600)
        self.source_sha = sha256(self.backup.read_bytes()).hexdigest()
        inventory.seal_inventory(self.backup, self.inventory, self.source_sha)
        self.inventory_sha = sha256((self.inventory / inventory.MANIFEST).read_bytes()).hexdigest()

    def write_config(self, allowed, admins, *, bot="105", sqlite_sha=None):
        self.config_sha = self.write_document(self.config, {
            "version": 1,
            "source": {"botId": bot, "revision": "a" * 40, "deploymentSha256": "b" * 64,
                       "sqliteSha256": self.source_sha if sqlite_sha is None else sqlite_sha},
            "allowedUserIds": allowed, "adminUserIds": admins,
        })

    def write_general_target(self, groups, **fields):
        self.target_sha = self.write_document(self.target, {
            "version": 1, "scope": "general-dormant", "botId": "105", "groupChatIds": groups, **fields,
        })

    def run_cli(self, *, source_sha=None, inventory_sha=None, config_sha=None, target_sha=None, general=False):
        arguments = [str(path) for path in (self.backup, self.inventory, self.config, self.target, self.output)]
        arguments += [source_sha or self.source_sha, inventory_sha or self.inventory_sha,
                      config_sha or self.config_sha, target_sha or self.target_sha]
        if general:
            arguments.insert(0, "preview-general")
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            status = tool.main(arguments)
        return status, stdout.getvalue(), stderr.getvalue()

    def read_report(self, *, general=False):
        success = tool.GENERAL_SUCCESS if general else tool.SUCCESS
        self.assertEqual(self.run_cli(general=general), (0, success + "\n", ""))
        raw = (self.output / inventory.MANIFEST).read_bytes()
        report = json.loads(raw)
        self.assertEqual((self.output / inventory.SEAL).read_text(), sha256(raw).hexdigest() + "\n")
        self.assertEqual({entry.name for entry in self.output.iterdir()},
                         {inventory.MANIFEST, inventory.SEAL, inventory.SIDECAR, tool.PRINCIPALS})
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o700)
        for entry in self.output.iterdir():
            self.assertEqual(stat.S_IMODE(entry.stat().st_mode), 0o600)
        descriptors = []
        for name in (inventory.SIDECAR, tool.PRINCIPALS):
            body = (self.output / name).read_bytes()
            descriptors.append({"file": name, "bytes": len(body), "sha256": sha256(body).hexdigest()})
        self.assertEqual(report["files"], descriptors)
        rows = [json.loads(row) for row in (self.output / tool.PRINCIPALS).read_bytes().splitlines()]
        self.assertEqual(report["principalRows"], len(rows))
        self.assertEqual([int(row["userId"]) for row in rows], sorted(int(row["userId"]) for row in rows))
        return report, {row["userId"]: row for row in rows}

    def assert_rejected(self, **pins):
        self.assertEqual(self.run_cli(**pins), (2, "", tool.FAILURE + "\n"))
        self.assertFalse(self.output.exists())

    def test_preserves_exact_rows_and_legacy_role_precedence(self):
        maximum = str(inventory.MAX_USER_ID)
        self.make_source(((101, 0, 10, 20), (102, 0, 12, 25), (103, 1, 15, 30),
                          (105, 1, 18, 32), (int(maximum), 1, 20, 40)))
        self.write_config(["101", "102", "104"], ["101"])
        report, rows = self.read_report()

        self.assertEqual((report["scope"], report["adminMode"], report["unlistedDefault"]),
                         ("offline-dormant", "explicit", "denied"))
        self.assertEqual((report["sourceSha256"], report["inventoryManifestSha256"], report["configSha256"], report["targetSha256"]),
                         (self.source_sha, self.inventory_sha, self.config_sha, self.target_sha))
        self.assertEqual(report["overrideRows"], 5)
        self.assertEqual((self.output / inventory.SIDECAR).read_bytes(), (self.inventory / inventory.SIDECAR).read_bytes())
        self.assertEqual(rows["101"], {"userId": "101", "legacyRole": "admin", "basis": "administrator",
                                       "allowlisted": True, "targetRole": "admin", "blockers": []})
        self.assertEqual((rows["102"]["legacyRole"], rows["102"]["basis"], rows["102"]["allowlisted"]), ("denied", "override-deny", True))
        self.assertEqual(rows["102"]["blockers"], ["member-denial-needs-baseline"])
        self.assertEqual((rows["103"]["legacyRole"], rows["103"]["basis"], rows["103"]["blockers"]),
                         ("member", "override-allow", ["outside-target"]))
        self.assertEqual(rows["104"]["basis"], "allowlist")
        self.assertEqual(rows["105"]["blockers"], ["reserved-identity"])
        self.assertEqual(rows[maximum]["blockers"], ["outside-target", "id-out-of-range"])
        self.assertEqual({key: count for key, count in report["blockers"].items() if count}, {
            "outside-target": 3, "id-out-of-range": 1, "reserved-identity": 1, "member-denial-needs-baseline": 1,
        })

    def test_unset_and_explicit_empty_admins_and_public_default_are_distinct(self):
        self.make_source(present=False)
        cases = (
            ("inherited", ["101"], None, "administrator", "default-deny", "denied", "105"),
            ("explicit", ["101"], [], "allowlist", "default-deny", "denied", "105"),
            ("explicit", [], [], "public", "public", "public", "106"),
            ("explicit", ["101", "102"], ["101", "102"], "administrator", "administrator", "denied", "105"),
        )
        for index, (mode, allowed, admins, admin_basis, member_basis, default, bot) in enumerate(cases):
            with self.subTest(index=index):
                self.output = self.root / f"reconciled-{index}"
                self.write_config(allowed, admins, bot=bot)
                report, rows = self.read_report()
                self.assertFalse(report["overrideTablePresent"])
                self.assertEqual((report["adminMode"], report["unlistedDefault"]), (mode, default))
                self.assertEqual((rows["101"]["basis"], rows["102"]["basis"]), (admin_basis, member_basis))
                self.assertEqual(report["blockers"]["different-bot"], int(bot != "105"))
                self.assertEqual(report["blockers"]["public-default"], int(default == "public"))
                self.assertEqual(report["blockers"]["target-admin-mismatch"], int(admin_basis != "administrator"))
                self.assertEqual(report["blockers"]["target-member-admin"], int(member_basis == "administrator"))

    def test_rejects_wrong_pins_source_linkage_and_noncanonical_target(self):
        self.make_source()
        self.write_config(["101"], None)
        for name in ("source_sha", "inventory_sha", "config_sha", "target_sha"):
            with self.subTest(name=name):
                self.assert_rejected(**{name: "0" * 64})
        self.write_config(["101"], None, sqlite_sha="c" * 64)
        self.assert_rejected()
        self.write_config(["101", "101"], None)
        self.assert_rejected()
        self.write_config(["101"], None)
        self.target_sha = self.write_document(self.target, {"version": 1, "botId": "105", "adminId": "105", "memberId": "102"})
        self.assert_rejected()

    def test_rejects_inventory_alias_and_resealed_substitution(self):
        self.make_source(((102, 0, 12, 25),))
        self.write_config([], ["101"])
        extra = self.inventory / "extra"
        extra.touch()
        self.assert_rejected()
        extra.unlink()
        sidecar = self.inventory / inventory.SIDECAR
        alias = self.root / "alias"
        os.link(sidecar, alias)
        self.assert_rejected()
        alias.unlink()

        alternate = line({"userId": "102", "allowed": 1, "createdAt": 12, "updatedAt": 25})
        sidecar.write_bytes(alternate)
        manifest_path = self.inventory / inventory.MANIFEST
        manifest = json.loads(manifest_path.read_bytes())
        manifest["authOverrides"].update(allowedRows=1, deniedRows=0, bytes=len(alternate), sha256=sha256(alternate).hexdigest())
        self.inventory_sha = self.write_document(manifest_path, manifest)
        (self.inventory / inventory.SEAL).write_text(self.inventory_sha + "\n")
        self.assert_rejected()

    def test_incomplete_output_leaves_no_seal_and_existing_output_is_preserved(self):
        self.make_source()
        self.write_config([], [])
        write = inventory._write_private

        def interrupt(path, raw):
            if path.name == inventory.SEAL:
                raise OSError("synthetic-private-sentinel")
            write(path, raw)

        with patch.object(inventory, "_write_private", side_effect=interrupt):
            self.assert_rejected()
        self.output.mkdir(mode=0o700)
        self.assertEqual(self.run_cli(), (2, "", tool.FAILURE + "\n"))
        self.assertEqual(list(self.output.iterdir()), [])

    def test_refuses_output_inside_the_sealed_inventory(self):
        self.make_source()
        self.write_config([], [])
        self.output = self.inventory / "reconciliation"
        self.assert_rejected()
        self.assertEqual({entry.name for entry in self.inventory.iterdir()},
                         {inventory.MANIFEST, inventory.SEAL, inventory.SIDECAR})

    def test_general_preview_preserves_multiple_admins_denials_and_exact_topology(self):
        unsupported_id = tool.GENERAL_MAX_ID + 1
        self.make_source(((101, 0, 10, 20), (102, 0, 12, 25), (103, 1, 15, 30),
                          (105, 1, 18, 32), (unsupported_id, 1, 20, 40)))
        self.write_config(["101", "102", "104"], ["101", "106"])
        self.write_general_target(["-100200", "-100100"])
        self.assert_rejected()
        report, rows = self.read_report(general=True)
        self.assertEqual((report["version"], report["kind"], report["scope"], report["unlistedDefault"]),
                         (1, "legacy-general-authorization-preview", "offline-dormant", "denied"))
        self.assertIs(report["activationAllowed"], False)
        self.assertEqual(report["target"], json.loads(self.target.read_bytes()))
        self.assertEqual((report["sourceSha256"], report["inventoryManifestSha256"], report["configSha256"], report["targetSha256"]),
                         (self.source_sha, self.inventory_sha, self.config_sha, self.target_sha))
        self.assertEqual((self.output / inventory.SIDECAR).read_bytes(), (self.inventory / inventory.SIDECAR).read_bytes())
        self.assertEqual({user: (row["legacyRole"], row["basis"]) for user, row in rows.items()}, {
            "101": ("admin", "administrator"), "102": ("denied", "override-deny"), "103": ("member", "override-allow"),
            "104": ("member", "allowlist"), "105": ("member", "override-allow"), "106": ("admin", "administrator"),
            str(unsupported_id): ("member", "override-allow"),
        })
        self.assertEqual(rows["105"]["blockers"], ["reserved-identity"])
        self.assertEqual(rows[str(unsupported_id)]["blockers"], ["id-out-of-range"])
        self.assertEqual({key: count for key, count in report["blockers"].items() if count},
                         {"reserved-identity": 1, "id-out-of-range": 1})

    def test_general_preview_distinguishes_admin_inheritance_and_reports_public_without_enabling_it(self):
        self.make_source(((101, 0, 10, 20), (102, 1, 12, 25)))
        self.write_general_target([])
        for index, (allowlist, administrators, role, mode, default) in enumerate((
            (["101"], None, "admin", "inherited", "denied"),
            (["101"], [], "denied", "explicit", "denied"),
            ([], [], "denied", "explicit", "public"),
        )):
            with self.subTest(index=index):
                self.output = self.root / f"general-{index}"
                self.write_config(allowlist, administrators, bot="106")
                report, rows = self.read_report(general=True)
                self.assertIs(report["activationAllowed"], False)
                self.assertEqual(report["target"]["groupChatIds"], [])
                self.assertEqual((rows["101"]["legacyRole"], rows["102"]["basis"]), (role, "override-allow"))
                self.assertEqual((report["adminMode"], report["unlistedDefault"]), (mode, default))
                self.assertEqual(report["blockers"]["public-default-requires-approval"], int(default == "public"))
                self.assertEqual(report["blockers"]["different-bot"], 1)

    def test_general_preview_rejects_unpinned_or_unbounded_inputs(self):
        self.make_source(((103, 1, 10, 20),))
        self.write_config(["101"], ["102"])
        self.assert_rejected(general=True)  # The two-user target cannot enter the general profile.
        for groups in ("-100", ["1"], ["-0"], ["-01"], ["-2", "-2"], ["-1", "-2"], [f"-{tool.GENERAL_MAX_ID + 1}"],
                       [str(-group) for group in range(tool.GENERAL_MAX_GROUPS + 1, 0, -1)]):
            with self.subTest(groups=groups):
                self.write_general_target(groups)
                self.assert_rejected(general=True)
        self.write_general_target([], activationAllowed=True)
        self.assert_rejected(general=True)
        self.write_general_target([], scope="isolation")
        self.assert_rejected(general=True)
        self.write_general_target([])
        self.assert_rejected(general=True, target_sha="0" * 64)
        with patch.object(tool, "MAX_CONFIG_IDS", 2):
            self.assert_rejected(general=True)


if __name__ == "__main__":
    unittest.main()
