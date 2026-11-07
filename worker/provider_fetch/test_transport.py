"""Exercise policy, bounded decoding and real pinned sockets on a hosted runner."""

import asyncio
from base64 import b64encode
from contextlib import ExitStack, suppress
import ipaddress
import os
from pathlib import Path
import socket
import ssl
import subprocess
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch
import zlib

import dns.exception
from multidict import CIMultiDict

import transport


LOOPBACK = ipaddress.ip_address("127.0.0.1")
PROVIDER = "provider.example"
OTHER = "second.example"


class PolicyTests(unittest.IsolatedAsyncioTestCase):
    async def test_rejects_invalid_authorities_and_disallowed_ports_before_network(self):
        with patch.object(transport, "_dns_addresses", new_callable=AsyncMock) as dns:
            for url in ("ftp://provider.example/", "https://user:password@provider.example/",
                        "https://provider.example:8443/", "http://provider.example:443/", "https://localhost/",
                        "http://127.1/", "http://0177.0.0.1/", "https://[2001:db8::1]ignored/",
                        "http://[fe80::1%25eth0]/", "http://host.local/", "https://provider.example/\r\n",
                        "https://provider.example\\@attacker.example/", "https://provider.example/?bad=%g"):
                self.assertEqual(await transport.fetch_provider(url), transport.FetchFailure("invalid-url"))
            for url in ("http://127.0.0.1/", "http://169.254.169.254/", "http://224.0.0.1/",
                        "http://100.64.0.1/", "http://[::ffff:8.8.8.8]/", "https://[64:ff9b::808:808]/",
                        "http://[2002:7f00:1::1]/", "http://[2001:db8::1]/"):
                self.assertEqual(await transport.fetch_provider(url), transport.FetchFailure("blocked-address"))
            basic = transport.BasicCredentials("fixture", "private")
            self.assertEqual(await transport.fetch_provider("http://provider.example/", basic=basic),
                             transport.FetchFailure("invalid-auth"))
            dns.assert_not_called()

    async def test_api_probe_rejects_insecure_endpoints_and_keys_before_dns(self):
        with patch.object(transport, "_dns_addresses", new_callable=AsyncMock) as dns:
            for url in ("http://provider.example/v1/models", "https://provider.example/v1/models?x=1",
                        "https://provider.example/v1/models#", "https://provider.example/v1/other",
                        "https://user@provider.example/v1/models"):
                self.assertEqual(await transport.probe_api_status(url, "synthetic-key"), transport.FetchFailure("invalid-url"))
            for key in ("", "x" * 513, "synthetic key", "synthetic\r\nX-Test: other", "密钥"):
                self.assertEqual(await transport.probe_api_status("https://provider.example/v1/models", key),
                                 transport.FetchFailure("invalid-auth"))
            self.assertEqual(await transport.probe_api_status("https://[::1]/v1/models", "synthetic-key"),
                             transport.FetchFailure("blocked-address"))
            dns.assert_not_called()

    async def test_queries_both_absolute_types_and_refuses_mixed_answers(self):
        resolver = SimpleNamespace(resolve=AsyncMock(side_effect=[
            SimpleNamespace(rrset=[SimpleNamespace(address="1.1.1.1")]),
            SimpleNamespace(rrset=[SimpleNamespace(address="fc00::1")]),
        ]))
        with (patch.object(transport.dns.asyncresolver, "Resolver", return_value=resolver),
              patch.object(transport.aiohttp, "TCPConnector") as connector):
            self.assertEqual(await transport.fetch_provider("https://provider.example/key"),
                             transport.FetchFailure("blocked-address"))
        self.assertEqual([(args, kwargs) for args, kwargs in resolver.resolve.await_args_list],
                         [(("provider.example.", family), {"search": False, "raise_on_no_answer": False})
                          for family in ("A", "AAAA")])
        self.assertIsNone(resolver.cache)
        connector.assert_not_called()

    async def test_missing_rrset_allowed_but_dns_timeout_and_failed_family_stop_the_hop(self):
        public = SimpleNamespace(rrset=[SimpleNamespace(address="1.1.1.1")])
        with patch.object(transport.dns.asyncresolver, "Resolver") as resolver:
            resolver.return_value.resolve = AsyncMock(side_effect=[public, SimpleNamespace(rrset=None)])
            self.assertEqual(await transport._dns_addresses(PROVIDER), (ipaddress.ip_address("1.1.1.1"),))
            for error, code in ((dns.exception.Timeout(), "timeout"),
                                (dns.exception.DNSException("dns secret sentinel"), "dns-failed")):
                resolver.return_value.resolve = AsyncMock(side_effect=[public, error])
                self.assertEqual(await transport.fetch_provider("https://provider.example/private-path"),
                                 transport.FetchFailure(code))

    async def test_total_timeout_includes_a_pending_resolver(self):
        async def pending(_host):
            await asyncio.Event().wait()

        with (patch.object(transport, "_dns_addresses", side_effect=pending),
              patch.object(transport, "TOTAL_SECONDS", 0.04)):
            self.assertEqual(await transport.fetch_provider("https://provider.example/source"),
                             transport.FetchFailure("timeout"))

    async def test_socket_factory_refuses_unpinned_ip_and_unapproved_port(self):
        target = transport._parse_target("https://provider.example/")
        resolver = transport._PinnedResolver(target, (ipaddress.ip_address("1.1.1.1"),))
        for address in (("1.0.0.1", 443), ("1.1.1.1", 8443), ("127.0.0.1", 443)):
            with self.assertRaises(OSError):
                resolver.socket((socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", address))


class BodyTests(unittest.IsolatedAsyncioTestCase):
    async def read(self, content, encoding, *, length=None):
        async def chunks(_size):
            for index in range(len(content)):
                yield content[index:index + 1]

        response = SimpleNamespace(headers=CIMultiDict({"Content-Encoding": encoding}), content_length=length,
                                   content=SimpleNamespace(iter_chunked=chunks))
        return await transport._read_body(response, asyncio.get_running_loop().time() + 2)

    async def test_gzip_zlib_and_raw_deflate_decode_at_exact_cap(self):
        body = "内容🙂".encode() * 64
        with patch.object(transport, "MAX_DECODED_BODY", len(body)):
            for encoding, wbits in (("gzip", 31), ("deflate", 15), ("deflate", -15)):
                compressed = zlib.compress(body, wbits=wbits)
                self.assertEqual(await self.read(compressed, encoding), body)

    async def test_wire_and_expanded_caps_and_malformed_content(self):
        packed = zlib.compress(b"x" * 4096, wbits=31)
        with patch.object(transport, "MAX_WIRE_BODY", len(packed) - 1):
            with self.assertRaisesRegex(transport._Rejected, "body-too-large"):
                await self.read(packed, "gzip")
            with self.assertRaisesRegex(transport._Rejected, "body-too-large"):
                await self.read(b"", "gzip", length=len(packed))
        with patch.object(transport, "MAX_DECODED_BODY", 4095):
            with self.assertRaisesRegex(transport._Rejected, "body-too-large"):
                await self.read(packed, "gzip")
        for malformed, encoding in ((packed[:-1], "gzip"), (packed + b"trailing", "gzip"),
                                    (packed, "gzip, deflate"), (b"", "deflate")):
            with self.assertRaisesRegex(transport._Rejected, "invalid-body"):
                await self.read(malformed, encoding)


class PinnedTLSIntegrationTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        directory = TemporaryDirectory()
        cls.addClassCleanup(directory.cleanup)
        cls.directory = Path(directory.name)
        def openssl(*args):
            subprocess.run(("openssl", *args), cwd=cls.directory, check=True, timeout=15,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-subj", "/CN=Fixture CA",
                "-keyout", "ca.key", "-out", "ca.pem", "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign")
        openssl("req", "-newkey", "rsa:2048", "-nodes", "-subj", f"/CN={PROVIDER}",
                "-keyout", "server.key", "-out", "server.csr")
        (cls.directory / "extensions.cnf").write_text(f"subjectAltName=DNS:{PROVIDER},DNS:{OTHER}\n"
                                                      "extendedKeyUsage=serverAuth\n", encoding="ascii")
        openssl("x509", "-req", "-in", "server.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial",
                "-days", "2", "-extfile", "extensions.cnf", "-out", "server.pem")

    async def asyncSetUp(self):
        self.sni = []
        self.requests = []
        self.hosts = []
        self.handlers = {}
        self.header_delays = {}
        self.connections = set()
        self.tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.tls.load_verify_locations(cafile=self.directory / "ca.pem")
        server_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_tls.load_cert_chain(self.directory / "server.pem", self.directory / "server.key")
        server_tls.set_servername_callback(lambda _, name, context: self.sni.append(name))
        self.server = await asyncio.start_server(self.serve, "127.0.0.1", 0, ssl=server_tls)
        self.addAsyncCleanup(self.close_server)
        self.port = self.server.sockets[0].getsockname()[1]
        self.patches = self.enterContext(ExitStack())
        self.patches.enter_context(patch.dict(transport.PORTS, {"https": self.port}))
        self.patches.enter_context(patch.object(transport, "_public_tls_context", side_effect=lambda: self.tls))
        self.patches.enter_context(patch.object(transport, "_public_ip", side_effect=lambda address: address == LOOPBACK))
        self.patches.enter_context(patch.object(transport, "_dns_addresses", side_effect=self.resolve))
        self.system_dns = self.patches.enter_context(patch.object(asyncio.get_running_loop(), "getaddrinfo",
                                                                  side_effect=AssertionError("unexpected system DNS")))

    async def close_server(self):
        self.server.close()
        await self.server.wait_closed()
        for task in self.connections:
            task.cancel()
        if self.connections:
            await asyncio.gather(*self.connections, return_exceptions=True)

    async def resolve(self, host):
        self.hosts.append(host)
        return (LOOPBACK,)

    def url(self, host, path):
        return f"https://{host}:{self.port}{path}"

    async def serve(self, reader, writer):
        task = asyncio.current_task()
        self.connections.add(task)
        try:
            raw = await reader.readuntil(b"\r\n\r\n")
            method, path, version = raw.split(b"\r\n", 1)[0].decode("ascii").split(" ")
            headers = dict((name.strip().lower(), value.strip()) for name, value in
                           (line.decode("ascii").split(":", 1) for line in raw.split(b"\r\n")[1:-2]))
            self.requests.append((method, path, version, headers, writer.get_extra_info("sockname")[0]))
            status, extra, body = self.handlers[path]
            if status is None:
                return
            if path in self.header_delays:
                await asyncio.sleep(self.header_delays[path])
            response = [f"HTTP/1.1 {status} Fixture", "Connection: close", f"Content-Length: {len(body)}"]
            response.extend(f"{key}: {value}" for key, value in extra.items())
            writer.write(("\r\n".join(response) + "\r\n\r\n").encode("ascii") + body)
            await writer.drain()
        except (OSError, asyncio.IncompleteReadError):
            pass
        finally:
            writer.close()
            with suppress(OSError, TimeoutError):
                await writer.wait_closed()
            self.connections.discard(task)

    async def test_real_host_sni_pin_and_auth_never_crosses_origins_or_returns(self):
        initial = "/start?key=synthetic%2Fprivate+x"
        self.handlers = {
            initial: (302, {"Location": "/again", "Set-Cookie": "fixture=never-forward"}, b"ignored"),
            "/again": (307, {"Location": self.url(OTHER, "/second")}, b""),
            "/second": (302, {"Location": self.url(PROVIDER, "/final")}, b""),
            "/final": (200, {"Content-Encoding": "gzip", "Content-Type": "text/plain",
                             "Subscription-Userinfo": "upload=0; total=1", "X-Secret": "not-returned"},
                       zlib.compress(b"synthetic private body", wbits=31)),
        }
        netrc = self.directory / "fixture.netrc"
        netrc.write_text(f"machine {OTHER} login ambient password never-forward\n", encoding="ascii")
        netrc.chmod(0o600)
        creds = transport.BasicCredentials("fixture-user", "fixture-password")
        with patch.dict(os.environ, {"HTTPS_PROXY": "http://127.0.0.1:1", "HTTP_PROXY": "http://127.0.0.1:1",
                                     "ALL_PROXY": "http://127.0.0.1:1", "NO_PROXY": "", "NETRC": str(netrc)}):
            result = await transport.fetch_provider(self.url(PROVIDER, initial), basic=creds)
        self.assertEqual(result.body, b"synthetic private body")
        self.assertEqual(result.headers, {"content-type": "text/plain", "subscription-userinfo": "upload=0; total=1"})
        self.assertEqual(repr(result), "FetchSuccess()")
        self.assertEqual(self.hosts, [PROVIDER, PROVIDER, OTHER, PROVIDER])
        self.assertEqual(self.sni, self.hosts)
        self.assertEqual([request[1] for request in self.requests], list(self.handlers))
        self.assertEqual([request[3]["host"] for request in self.requests], [f"{host}:{self.port}" for host in self.hosts])
        authorization = "Basic " + b64encode(b"fixture-user:fixture-password").decode("ascii")
        self.assertEqual([request[3].get("authorization") for request in self.requests], [authorization] * 2 + [None] * 2)
        self.assertTrue(all(request[4] == "127.0.0.1" and "cookie" not in request[3] for request in self.requests))
        self.system_dns.assert_not_called()

    async def test_api_probe_uses_pinned_tls_without_body_or_redirect(self):
        self.handlers = {
            "/v1/models": (302, {"Location": self.url(OTHER, "/v1/models"), "Set-Cookie": "fixture=private"},
                           b"synthetic private body"),
            "/v1/chat/completions": (401, {}, b"synthetic private response"),
        }
        with patch.object(transport, "_read_body", side_effect=AssertionError("Unexpected API probe body read.")):
            for path, status in (("/v1/models", 302), ("/v1/chat/completions", 401)):
                observed = await transport.probe_api_status(self.url(PROVIDER, path), "synthetic-key")
                self.assertIsInstance(observed, transport.ApiProbeSuccess)
                self.assertEqual(observed.status, status)
                self.assertTrue(0 <= observed.elapsed_ms < 15000)
                self.assertNotIn("synthetic", repr(observed))
        self.assertEqual(self.hosts, [PROVIDER, PROVIDER])
        self.assertEqual(self.sni, self.hosts)
        self.assertEqual([(r[0], r[1]) for r in self.requests], [("GET", path) for path in self.handlers])
        self.assertTrue(all(r[3]["authorization"] == "Bearer synthetic-key" and r[3]["x-api-key"] == "synthetic-key"
                            and "cookie" not in r[3] for r in self.requests))
        self.system_dns.assert_not_called()

    async def test_api_probe_does_not_replay_after_disconnect(self):
        self.handlers = {"/v1/models": (None, {}, b"")}
        observed = await transport.probe_api_status(self.url(PROVIDER, "/v1/models"), "synthetic-key")
        self.assertEqual(observed, transport.FetchFailure("unavailable"))
        self.assertEqual(len(self.requests), 1)

    async def test_redirect_reresolves_and_stops_private_mixed_results(self):
        self.handlers = {"/start": (302, {"Location": "/rebound"}, b"")}
        with patch.object(transport, "_dns_addresses", side_effect=[(LOOPBACK,), (LOOPBACK, ipaddress.ip_address("fc00::1"))]) as dns:
            result = await transport.fetch_provider(self.url(PROVIDER, "/start"))
        self.assertEqual(result, transport.FetchFailure("blocked-address"))
        self.assertEqual(dns.await_count, 2)
        self.assertEqual(len(self.requests), 1)

    async def test_downgrade_unsafe_redirect_and_non_200_are_fixed_failures(self):
        self.handlers = {
            "/down": (302, {"Location": "http://provider.example/fixture-query-secret"}, b""),
            "/malformed": (302, {"Location": "https://fixture-secret@provider.example/"}, b""),
            "/limited": (302, {"Location": "/limited"}, b""),
            "/status": (429, {"Location": "https://fixture-secret@provider.example/"}, b"fixture-secret"),
        }
        for path, expected in (("/down", transport.FetchFailure("invalid-redirect")),
                               ("/malformed", transport.FetchFailure("invalid-redirect")),
                               ("/limited", transport.FetchFailure("redirect-limit")),
                               ("/status", transport.FetchFailure("http-status", 429))):
            result = await transport.fetch_provider(self.url(PROVIDER, path))
            self.assertEqual(result, expected)
            self.assertNotIn("fixture-secret", repr(result))

    async def test_fixed_probe_policy_can_only_narrow_addresses_and_disable_redirects(self):
        self.handlers = {"/start": (302, {"Location": "/never"}, b"")}
        result = await transport.fetch_provider(self.url(PROVIDER, "/start"), address_policy=lambda _: False)
        self.assertEqual(result, transport.FetchFailure("blocked-address"))
        self.assertEqual(self.requests, [])
        result = await transport.fetch_provider(self.url(PROVIDER, "/start"), follow_redirects=False)
        self.assertEqual(result, transport.FetchFailure("invalid-redirect"))
        self.assertEqual([request[1] for request in self.requests], ["/start"])

    async def test_two_redirect_hops_do_not_each_get_a_fresh_deadline(self):
        self.handlers = {"/first": (302, {"Location": "/second"}, b""), "/second": (200, {}, b"body")}
        self.header_delays = {"/first": 0.35, "/second": 0.35}
        with patch.object(transport, "TOTAL_SECONDS", 0.6):
            result = await transport.fetch_provider(self.url(PROVIDER, "/first"))
        self.assertEqual(result, transport.FetchFailure("timeout"))
        self.assertEqual(self.requests[0][1], "/first")

    async def test_tls_rejects_wrong_hostname_and_untrusted_chain_without_sending_http(self):
        result = await transport.fetch_provider(self.url("mismatch.example", "/fixture-path-secret"))
        self.assertEqual(result, transport.FetchFailure("tls-failed"))
        self.tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        result = await transport.fetch_provider(self.url(PROVIDER, "/fixture-path-secret"))
        self.assertEqual(result, transport.FetchFailure("tls-failed"))
        self.assertEqual(self.sni, ["mismatch.example", PROVIDER])
        self.assertEqual(self.requests, [])
