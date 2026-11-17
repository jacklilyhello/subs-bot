"""Hosted checks that release and provisioning credentials stay separate."""
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import release_isolation as release
import scoped_r2
from production_target import ContractError


class ReleaseCredentialRoutes(unittest.TestCase):
    def test_only_exact_bucket_metadata_uses_the_metadata_reader(self):
        target = {"accountId": "a" * 32}
        bucket = "/accounts/" + target["accountId"] + "/r2/buckets/" + release.WORKER_NAME
        data, metadata = Mock(), Mock()
        with patch.dict(os.environ, {"SUBS_BOT_CF_R2_METADATA_READ_TOKEN": "metadata-reader"}, clear=True), \
                patch.object(release, "CloudflareClient", side_effect=[data, metadata]) as clients:
            api = release.isolation_data_client(target, "d1-writer")
            for suffix in ("", "/domains/managed", "/domains/custom"):
                api("GET", bucket + suffix)
            self.assertEqual(metadata.call_count, 3)
            query = "/accounts/" + target["accountId"] + "/d1/database/example/query"
            api("POST", query, {"sql": "SELECT 1"})
            data.assert_called_once_with("POST", query, {"sql": "SELECT 1"})
            for method, payload in (("POST", None), ("GET", {})):
                with self.assertRaises(release.CloudflareError):
                    api(method, bucket, payload)
            self.assertEqual(metadata.call_count, 3)
            self.assertEqual(clients.call_args_list[0].args, ("d1-writer",))
            self.assertEqual(clients.call_args_list[1].args, ("metadata-reader",))

    def test_scoped_storage_never_substitutes_d1_for_provisioning(self):
        for key in ("SUBS_BOT_SCOPED_R2_READ_JSON", "SUBS_BOT_SCOPED_R2_WRITE_JSON", "SUBS_BOT_CF_R2_METADATA_READ_TOKEN"):
            with self.subTest(key=key), self.assertRaises(ContractError):
                scoped_r2.creation_token("d1-writer", {key: "configured"})
        self.assertEqual(scoped_r2.creation_token("legacy", {}), "legacy")
        self.assertEqual(scoped_r2.creation_token("d1-writer", {
            "SUBS_BOT_CF_R2_METADATA_READ_TOKEN": "metadata-reader",
            "SUBS_BOT_CF_R2_CREATE_TOKEN": "approved-provisioner"}), "approved-provisioner")

    def test_missing_metadata_is_rejected_before_constructing_cloud_requests(self):
        with patch.dict(os.environ, {"SUBS_BOT_SCOPED_R2_READ_JSON": "configured"}, clear=True), \
                patch.object(release, "CloudflareClient") as client:
            with self.assertRaises(ContractError):
                release.isolation_data_client({"accountId": "a" * 32}, "d1-writer")
            client.return_value.assert_not_called()


if __name__ == "__main__":
    unittest.main()
