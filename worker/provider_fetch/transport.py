"""Bounded HTTP(S) provider transport for a direct-egress Python runtime."""

import asyncio
from base64 import b64encode
from dataclasses import dataclass, field
from functools import cache
import ipaddress
import re
import socket
import ssl
from typing import Literal
from urllib.parse import quote, urljoin, urlsplit, urlunsplit
import zlib

import aiohttp
from aiohttp.abc import AbstractResolver
import dns.asyncresolver
import dns.exception
import idna
from yarl import URL


TOTAL_SECONDS = 25
CONNECT_SECONDS = 8
MAX_REDIRECTS = 5
MAX_ADDRESSES = 16
MAX_URL_BYTES = 8192
# The wire cap counts content-coded entity bytes after HTTP transfer framing.
MAX_WIRE_BODY = 10 * 1024 * 1024
MAX_DECODED_BODY = 10 * 1024 * 1024
CHUNK_BYTES = 64 * 1024
PUBLIC_CA_FILE = "/etc/ssl/certs/ca-certificates.crt"
PORTS = {"http": 80, "https": 443}
REDIRECTS = {301, 302, 303, 307, 308}
METADATA_HEADERS = ("content-type", "content-disposition", "profile-title", "subscription-userinfo")
DOMAIN_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
INVALID_URL_CHAR = re.compile(r"[\s\\\x00-\x1f\x7f-\x9f]")
IP = ipaddress.IPv4Address | ipaddress.IPv6Address
PUBLIC_IPV6 = ipaddress.IPv6Network("2000::/3")
SPECIAL_IPV6 = tuple(ipaddress.IPv6Network(cidr) for cidr in ("2001::/23", "2002::/16", "3fff::/20"))
FailureCode = Literal["invalid-url", "invalid-auth", "blocked-address", "dns-failed", "tls-failed", "unavailable",
                      "timeout", "invalid-redirect", "redirect-limit", "http-status", "body-too-large", "invalid-body"]


@dataclass(frozen=True, repr=False)
class BasicCredentials:
    username: str
    password: str


@dataclass(frozen=True)
class FetchSuccess:
    body: bytes = field(repr=False)
    headers: dict[str, str] = field(repr=False)


@dataclass(frozen=True)
class FetchFailure:
    code: FailureCode
    upstream_status: int | None = None


class _Rejected(ValueError):
    def __init__(self, code: FailureCode):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, repr=False)
class _Target:
    url: URL
    host: str
    port: int
    literal: IP | None

    @property
    def origin(self):
        return self.url.scheme, self.host, self.port


def _valid_url_text(value):
    return (isinstance(value, str) and bool(value) and len(value) <= MAX_URL_BYTES
            and not INVALID_URL_CHAR.search(value) and len(value.encode("utf-8")) <= MAX_URL_BYTES
            and not re.search(r"%(?![0-9a-fA-F]{2})", value))


def _parse_target(raw):
    try:
        if not _valid_url_text(raw):
            raise ValueError()
        parts = urlsplit(raw)
        port = PORTS.get(parts.scheme)
        host = parts.hostname
        authority = parts.netloc
        if not port or not host or "@" in authority or "%" in authority:
            raise ValueError()
        bracketed = authority.startswith("[")
        pattern = r"\[[^\[\]]+\](?::[0-9]+)?" if bracketed else r"[^:\[\]]+(?::[0-9]+)?"
        if not re.fullmatch(pattern, authority) or parts.port not in {None, port}:
            raise ValueError()
        try:
            literal = ipaddress.ip_address(host)
        except ValueError:
            literal = None
        if bracketed:
            if not isinstance(literal, ipaddress.IPv6Address):
                raise ValueError()
            host = str(literal)
        elif literal is not None:
            host = str(literal)
        else:
            host = idna.encode(host, uts46=True).decode("ascii")
            labels = host.removesuffix(".").split(".")
            if (len(labels) < 2 or not labels[-1][0:1].isalpha() or not all(DOMAIN_LABEL.fullmatch(label) for label in labels)
                    or labels[-1] in {"localhost", "local", "internal", "onion"} or labels[-2:] == ["home", "arpa"]):
                raise ValueError()
        authority = f"[{host}]" if bracketed else host
        if parts.port is not None:
            authority += f":{port}"
        path = quote(parts.path or "/", safe="/:@!$&'()*+,;=-._~%")
        query = quote(parts.query, safe="/?:@!$&'()*+,;=-._~%")
        return _Target(URL(urlunsplit((parts.scheme, authority, path, query, "")), encoded=True), host, port, literal)
    except (ValueError, UnicodeError):
        raise _Rejected("invalid-url") from None


def _public_ip(address):
    if not address.is_global or address.is_multicast or address.is_reserved:
        return False
    if isinstance(address, ipaddress.IPv6Address):
        return address in PUBLIC_IPV6 and not any(address in network for network in SPECIAL_IPV6)
    return True


async def _dns_addresses(host):
    try:
        resolver = dns.asyncresolver.Resolver()
        resolver.cache = None
        fqdn = host.removesuffix(".") + "."
        answers = await asyncio.gather(*(resolver.resolve(fqdn, kind, search=False, raise_on_no_answer=False)
                                         for kind in ("A", "AAAA")), return_exceptions=True)
        if any(isinstance(answer, dns.exception.Timeout) for answer in answers):
            raise _Rejected("timeout")
        if any(isinstance(answer, BaseException) for answer in answers):
            raise _Rejected("dns-failed")
        return tuple(ipaddress.ip_address(record.address) for answer in answers if answer.rrset is not None
                     for record in answer.rrset)
    except _Rejected:
        raise
    except (dns.exception.DNSException, ValueError, OSError):
        raise _Rejected("dns-failed") from None


async def _checked_addresses(target):
    addresses = (target.literal,) if target.literal is not None else await _dns_addresses(target.host)
    if not addresses:
        raise _Rejected("dns-failed")
    if not all(_public_ip(address) for address in addresses):
        raise _Rejected("blocked-address")
    addresses = tuple(dict.fromkeys(addresses))
    if len(addresses) > MAX_ADDRESSES:
        raise _Rejected("dns-failed")
    return addresses


class _PinnedResolver(AbstractResolver):
    def __init__(self, target, addresses):
        self.target = target
        self.addresses = addresses

    async def resolve(self, host, port=0, family=socket.AF_UNSPEC):
        if (host, port, family) != (self.target.host, self.target.port, socket.AF_UNSPEC):
            raise OSError("Provider connection target differs from the approved hop.")
        return [{"hostname": host, "host": str(address), "port": port,
                 "family": socket.AF_INET if address.version == 4 else socket.AF_INET6,
                 "proto": socket.IPPROTO_TCP, "flags": socket.AI_NUMERICHOST} for address in self.addresses]

    async def close(self):
        pass

    def socket(self, info):
        family, kind, protocol, _, address = info
        host, port, *scope = address
        ip = ipaddress.ip_address(host)
        expected_family = socket.AF_INET if ip.version == 4 else socket.AF_INET6
        if (ip not in self.addresses or port != self.target.port or family != expected_family
                or any(scope) or kind != socket.SOCK_STREAM or protocol != socket.IPPROTO_TCP):
            raise OSError("Provider socket address differs from the approved hop.")
        return socket.socket(family, kind, protocol)


@cache
def _public_tls_context():
    # Explicit trust roots avoid environment-selected roots and TLS key logging.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cafile=PUBLIC_CA_FILE)
    return context


def _authorization(credentials):
    if credentials is None:
        return None
    if (not isinstance(credentials, BasicCredentials) or not isinstance(credentials.username, str)
            or not credentials.username or ":" in credentials.username or not isinstance(credentials.password, str)):
        raise _Rejected("invalid-auth")
    value = f"{credentials.username}:{credentials.password}"
    if len(value) > 1024 or re.search(r"[\x00-\x1f\x7f-\x9f]", value):
        raise _Rejected("invalid-auth")
    try:
        data = value.encode("utf-8")
    except UnicodeError:
        raise _Rejected("invalid-auth") from None
    if len(data) > 1024:
        raise _Rejected("invalid-auth")
    return "Basic " + b64encode(data).decode("ascii")


def _redirect(target, headers):
    values = headers.getall("Location", [])
    try:
        if len(values) != 1 or not _valid_url_text(values[0]):
            raise ValueError()
        location = urlsplit(values[0])
        if location.scheme and not location.netloc:
            raise ValueError()
        following = _parse_target(urljoin(str(target.url), values[0]))
        if target.url.scheme == "https" and following.url.scheme != "https":
            raise ValueError()
    except (ValueError, UnicodeError):
        raise _Rejected("invalid-redirect") from None
    return following


def _check_deadline(deadline):
    if asyncio.get_running_loop().time() >= deadline:
        raise TimeoutError()


def _append_decoded(body, decoded):
    if len(body) + len(decoded) > MAX_DECODED_BODY:
        raise _Rejected("body-too-large")
    body.extend(decoded)


async def _read_body(response, deadline):
    values = response.headers.getall("Content-Encoding", [])
    encoding = values[0].strip().lower() if len(values) == 1 else "identity" if not values else ""
    if encoding not in {"identity", "gzip", "deflate"}:
        raise _Rejected("invalid-body")
    transfer = response.headers.getall("Transfer-Encoding", [])
    if transfer and (len(transfer) != 1 or transfer[0].strip().lower() != "chunked"):
        raise _Rejected("invalid-body")
    if response.content_length is not None and response.content_length > MAX_WIRE_BODY:
        raise _Rejected("body-too-large")
    body = bytearray()
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS) if encoding == "gzip" else None
    deflate_prefix = bytearray()
    wire_bytes = 0
    async for data in response.content.iter_chunked(CHUNK_BYTES):
        _check_deadline(deadline)
        wire_bytes += len(data)
        if wire_bytes > MAX_WIRE_BODY:
            raise _Rejected("body-too-large")
        if encoding == "identity":
            _append_decoded(body, data)
            continue
        if decoder is None:
            deflate_prefix.extend(data)
            if len(deflate_prefix) < 2:
                continue
            cmf, flags = deflate_prefix[:2]
            wrapped = (cmf & 0x0f) == 8 and (cmf >> 4) <= 7 and ((cmf << 8) | flags) % 31 == 0
            decoder = zlib.decompressobj(zlib.MAX_WBITS if wrapped else -zlib.MAX_WBITS)
            data = bytes(deflate_prefix)
            deflate_prefix.clear()
        while True:
            _check_deadline(deadline)
            limit = min(CHUNK_BYTES, MAX_DECODED_BODY - len(body) + 1)
            decoded = decoder.decompress(data, limit)
            _append_decoded(body, decoded)
            if decoder.unused_data:
                raise _Rejected("invalid-body")
            data = decoder.unconsumed_tail
            if not data and (decoder.eof or len(decoded) < limit):
                break
    if encoding != "identity" and (decoder is None or not decoder.eof):
        raise _Rejected("invalid-body")
    return bytes(body)


def _metadata(headers):
    result = {}
    for key in METADATA_HEADERS:
        values = headers.getall(key, [])
        if len(values) == 1 and not re.search(r"[\x00-\x1f\x7f-\x9f\ud800-\udfff]", values[0]):
            result[key] = values[0]
    return result


async def fetch_provider(url: str, *, basic: BasicCredentials | None = None) -> FetchSuccess | FetchFailure:
    """Fetch one private subscription source. Failure results contain only fixed categories/status."""
    deadline = asyncio.get_running_loop().time() + TOTAL_SECONDS
    try:
        async with asyncio.timeout_at(deadline):
            target = _parse_target(url)
            authorization = _authorization(basic)
            if authorization is not None and target.url.scheme != "https":
                raise _Rejected("invalid-auth")
            for hop in range(MAX_REDIRECTS + 1):
                _check_deadline(deadline)
                addresses = await _checked_addresses(target)
                resolver = _PinnedResolver(target, addresses)
                connector = aiohttp.TCPConnector(resolver=resolver, socket_factory=resolver.socket,
                                                 ssl=_public_tls_context(), use_dns_cache=False, force_close=True)
                headers = {"User-Agent": "clash-meta/1.18.0", "Accept": "*/*", "Accept-Encoding": "gzip, deflate"}
                if authorization is not None:
                    headers["Authorization"] = authorization
                timeout = aiohttp.ClientTimeout(total=None, sock_connect=CONNECT_SECONDS)
                async with aiohttp.ClientSession(connector=connector, trust_env=False, cookie_jar=aiohttp.DummyCookieJar(),
                                                 auto_decompress=False, timeout=timeout, read_bufsize=CHUNK_BYTES,
                                                 max_headers=32) as session:
                    async with session.get(target.url, headers=headers, allow_redirects=False, proxy=None,
                                           server_hostname=target.host.removesuffix(".") if target.url.scheme == "https" else None) as response:
                        _check_deadline(deadline)
                        if response.status in REDIRECTS:
                            if hop == MAX_REDIRECTS:
                                raise _Rejected("redirect-limit")
                            following = _redirect(target, response.headers)
                            if following.origin != target.origin:
                                authorization = None
                            target = following
                        elif response.status == 200:
                            body = await _read_body(response, deadline)
                            _check_deadline(deadline)
                            return FetchSuccess(body, _metadata(response.headers))
                        elif 100 <= response.status <= 599:
                            return FetchFailure("http-status", response.status)
                        else:
                            return FetchFailure("unavailable")
    except _Rejected as error:
        return FetchFailure(error.code)
    except TimeoutError:
        return FetchFailure("timeout")
    except (aiohttp.ClientSSLError, ssl.SSLError):
        return FetchFailure("tls-failed")
    except (aiohttp.ClientPayloadError, zlib.error):
        return FetchFailure("invalid-body")
    except (aiohttp.ClientError, OSError, ValueError):
        return FetchFailure("unavailable")
