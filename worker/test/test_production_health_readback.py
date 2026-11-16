"""Hosted tests for exact, bounded and sanitized production HTTPS readback."""
from copy import deepcopy
from email.message import Message
from http.client import HTTPException
from io import BytesIO
from pathlib import Path
import socket
import ssl
import sys
import unittest
from unittest.mock import Mock, call, patch
from urllib.error import HTTPError, URLError

WORKER = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WORKER / "tools"))
import production_control as control
import production_target as contract
from test_production_control import REVISION, fixture

SECRET = "synthetic-private-response-must-not-be-logged"


class Response:
    def __init__(self, value=None, *, raw=None, status=200, headers=None):
        self.status = status
        self.headers = Message()
        values = {"Content-Type": "application/json; charset=utf-8", "Cache-Control": "private, no-store",
            "Referrer-Policy": "no-referrer", "X-Content-Type-Options": "nosniff"} if headers is None else headers
        for key, value_ in values.items():
            self.headers[key] = value_
        self.stream = BytesIO(contract.canonical(value) if raw is None else raw)

    def read(self, size):
        return self.stream.read(size)

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.stream.close()


class HealthReadbackTests(unittest.TestCase):
    def controller(self, *, production=False):
        target, _ = fixture()
        if production:
            value = deepcopy(target.data)
            service, backup, hostname = contract.NAMES["production"]
            value.update(environment="production", workerName=service, d1Name=service, bucketName=service,
                backupBucketName=backup, hostname=hostname, botUsername="SyntheticFormalBot")
            target = contract.validate_target(value)
        worker = Mock()
        if production:
            worker.return_value = [{"hostname": target.data["hostname"], "service": target.data["workerName"],
                "zone_id": target.data["zoneId"], "environment": "production"}]
        else:
            worker.return_value = {"subdomain": {"enabled": True, "url": "https://" + target.data["hostname"]}}
        return control.Controller(target, Mock(), worker, WORKER,
            {"revision": REVISION, "bundleSha256": "a" * 64})

    def health(self):
        return {"ok": True, "service": "subs-bot", "revision": REVISION}

    def http_error(self, status, raw=None):
        return HTTPError("https://untrusted-response.invalid/" + SECRET, status, SECRET, Message(),
            BytesIO(raw if raw is not None else ("error code: 1010\n" + SECRET).encode()))

    def test_exact_target_and_body_use_existing_readback_headers_without_credentials(self):
        for production in (False, True):
            with self.subTest(production=production):
                controller = self.controller(production=production)
                opener = Mock()
                opener.open.return_value = Response(self.health())
                with patch.object(control, "build_opener", return_value=opener) as build, patch.object(control, "sleep") as sleep:
                    result = controller.verify_domain()
                self.assertEqual(result, {"domainVerified": True, "healthReadbackAttempts": 1})
                request = opener.open.call_args.args[0]
                self.assertEqual(request.full_url, "https://" + controller.target.data["hostname"] + "/health")
                self.assertEqual(request.get_method(), "GET")
                self.assertEqual(request.get_header("Accept"), "application/json")
                self.assertEqual(request.get_header("User-agent"), control.ISOLATION_RELEASE_USER_AGENT)
                self.assertIsNone(request.get_header("Authorization"))
                self.assertEqual(opener.open.call_args.kwargs, {"timeout": 10})
                self.assertEqual(build.call_args.args[0].proxies, {})
                self.assertIsInstance(build.call_args.args[1], control.NoRedirect)
                self.assertEqual(len(build.call_args.args), 2, "No TLS-verification override is installed")
                controller.data.assert_not_called()
                sleep.assert_not_called()

    def test_wrong_registered_domain_is_rejected_before_any_http_request(self):
        for production in (False, True):
            controller = self.controller(production=production)
            controller.worker.return_value = ([{"hostname": controller.target.data["hostname"], "service": "wrong-service",
                "zone_id": controller.target.data["zoneId"], "environment": "production"}] if production else
                {"subdomain": {"enabled": True, "url": "https://wrong-target.invalid"}})
            with patch.object(control, "build_opener") as build:
                with self.assertRaises(contract.ContractError):
                    controller.verify_domain()
            build.assert_not_called()

    def test_denial_and_redirect_are_never_retried_or_reported_as_passed(self):
        for status in (301, 302, 401, 403, 404):
            controller = self.controller()
            opener = Mock()
            denied = self.http_error(status)
            opener.open.side_effect = denied
            with self.subTest(status=status), patch.object(control, "build_opener", return_value=opener), patch.object(control, "sleep") as sleep:
                with self.assertRaises(control.OperationError) as caught:
                    controller.verify_domain()
            error = caught.exception
            self.assertEqual(error.http_status, status)
            self.assertEqual(error.category, "http")
            self.assertEqual(error.codes, (1010,))
            self.assertIn("attempts=1", str(error))
            self.assertNotIn(SECRET, str(error))
            self.assertNotIn("https://", str(error))
            self.assertFalse(error.uncertain)
            self.assertEqual(opener.open.call_count, 1)
            self.assertTrue(denied.fp.closed)
            sleep.assert_not_called()

    def test_transient_http_is_bounded_and_only_an_exact_subsequent_read_can_pass(self):
        opener = Mock()
        opener.open.side_effect = [self.http_error(503), Response(self.health())]
        with patch.object(control, "build_opener", return_value=opener), patch.object(control, "sleep") as sleep:
            self.assertEqual(self.controller().verify_domain()["healthReadbackAttempts"], 2)
        self.assertEqual(opener.open.call_count, 2)
        self.assertEqual(sleep.call_args_list, [call(1)])
        opener.open.reset_mock(side_effect=True)
        opener.open.side_effect = [self.http_error(503, b'{"errors":[{"code":1101}]}') for _ in range(3)]
        with patch.object(control, "build_opener", return_value=opener), patch.object(control, "sleep") as sleep:
            with self.assertRaises(control.OperationError) as caught:
                self.controller().verify_domain()
        self.assertEqual(opener.open.call_count, 3)
        self.assertEqual(sleep.call_args_list, [call(1), call(3)])
        self.assertEqual(caught.exception.codes, (1101,))
        self.assertIn("attempts=3", str(caught.exception))

    def test_transport_categories_do_not_expose_exception_details_or_disable_tls(self):
        cases = [(URLError(ssl.SSLCertVerificationError(SECRET)), "tls", 1),
            (ssl.SSLError(SECRET), "tls", 1),
            (URLError(socket.gaierror(socket.EAI_NONAME, SECRET)), "dns", 1),
            (URLError(socket.gaierror(socket.EAI_AGAIN, SECRET)), "dns", 3),
            (URLError(TimeoutError(SECRET)), "timeout", 3),
            (TimeoutError(SECRET), "timeout", 3),
            (HTTPException(SECRET), "protocol", 1)]
        for failure, category, attempts in cases:
            opener = Mock()
            opener.open.side_effect = failure
            with self.subTest(category=category, attempts=attempts), patch.object(control, "build_opener", return_value=opener), patch.object(control, "sleep"):
                with self.assertRaises(control.OperationError) as caught:
                    self.controller().verify_domain()
            self.assertEqual(caught.exception.category, category)
            self.assertEqual(opener.open.call_count, attempts)
            self.assertNotIn(SECRET, str(caught.exception))
            self.assertNotIn("https://", str(caught.exception))

    def test_wrong_or_unbounded_response_is_not_retried_or_accepted(self):
        responses = [Response({**self.health(), "revision": "c" * 40}), Response({**self.health(), "ok": 1}),
            Response({**self.health(), "extra": SECRET}), Response(raw=SECRET.encode()),
            Response(raw=b'{"ok":true,"ok":true}'), Response(raw=b"x" * 1025),
            Response(self.health(), headers={"Content-Type": "text/html"}),
            Response(self.health(), headers={"Content-Type": "application/json"})]
        for response in responses:
            opener = Mock()
            opener.open.return_value = response
            with patch.object(control, "build_opener", return_value=opener), patch.object(control, "sleep") as sleep:
                with self.assertRaises(control.OperationError) as caught:
                    self.controller().verify_domain()
            self.assertIn(caught.exception.category, ("body", "response"))
            self.assertEqual(caught.exception.http_status, 200)
            self.assertNotIn(SECRET, str(caught.exception))
            self.assertEqual(opener.open.call_count, 1)
            sleep.assert_not_called()


if __name__ == "__main__":
    unittest.main()
