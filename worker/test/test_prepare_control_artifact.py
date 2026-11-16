"""Source release provenance stays separate from current operational code."""
import os
from pathlib import Path
import sys
from unittest import TestCase
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import prepare_control_artifact as control


class ControlArtifactTests(TestCase):
    def exercise(self, action, source_revision, comparison=None, changing=False):
        current = "b" * 40
        def metadata(path, token):
            if path.startswith("/actions/runs/"):
                return {"head_sha": source_revision}
            return comparison
        selected = ("1", "123", "c" * 64)
        with patch.dict(os.environ, {"GITHUB_SHA": current, "GITHUB_REF": "refs/heads/main", "RUNNER_TEMP": "/tmp"}), \
             patch.object(control.source, "require_current_main") as guard, \
             patch.object(control.source, "_github_token", return_value="synthetic"), \
             patch.object(control.source, "_get_json", side_effect=metadata), \
             patch.object(control.source, "_select_artifact", side_effect=[selected, ("2", "123", "d"*64)] if changing else None,
                          return_value=selected), \
             patch.object(control.source, "_download", return_value=b"verified-by-unpack"), \
             patch.object(control.source, "_unpack") as unpack:
            result = control.prepare(action, run_id="456")
            self.assertEqual(result["revision"], source_revision)
            self.assertEqual(guard.call_count, 2)
            self.assertEqual(unpack.call_args.args[2], source_revision)
            return result

    def test_current_main_deployment_uses_exact_source_archive(self):
        self.exercise("deploy", "b"*40)

    def test_pause_can_use_an_explicit_reviewed_ancestor_without_rebuilding(self):
        old = "a"*40
        self.exercise("pause", old, {"status": "ahead", "base_commit": {"sha": old}, "merge_base_commit": {"sha": old}})

    def test_deployment_never_implicitly_downgrades_to_older_main(self):
        with self.assertRaises(control.source.ArtifactError):
            self.exercise("deploy", "a"*40)

    def test_unrelated_source_and_mutated_artifact_are_rejected(self):
        with self.assertRaises(control.source.ArtifactError):
            self.exercise("pause", "a"*40, {"status": "diverged"})
        with self.assertRaises(control.source.ArtifactError):
            self.exercise("inspect", "b"*40, changing=True)
