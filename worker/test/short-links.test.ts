import assert from "node:assert/strict";
import { test } from "node:test";
import { canonicalShortDestination, ISOLATION_PUBLIC_ORIGIN } from "../src/short-links.ts";

test("keeps safe external HTTP(S) redirects canonical without losing path, query or fragment", () => {
  for (const [input, expected] of [
    ["HTTPS://BÜCHER.Example.COM:443/a%20b?cap=synthetic%2Bcode#原", "https://xn--bcher-kva.example.com/a%20b?cap=synthetic%2Bcode#%E5%8E%9F"],
    ["http://example.org:8080", "http://example.org:8080/"],
    ["http://8.8.8.8/a", "http://8.8.8.8/a"],
    ["https://[2606:4700:0000::1]:443/a", "https://[2606:4700::1]/a"],
  ]) assert.equal(canonicalShortDestination(input), expected);
});

test("rejects ambiguous, local, project and special-purpose redirect destinations", () => {
  for (const input of [
    "javascript:alert(1)", "//example.com/a", "https:///example.com", "https://",
    "https://@example.com", "https://synthetic:fixture@example.com", "https://example.com@other.example.com",
    "https://ex%61mple.com", "https://example.com:", "https://example.com:0", "https://example.com:65536",
    "https://example.com\\@fixture.invalid", "https://example.com/a%5Cb", "https://example.com/%0d%0aX",
    "https://example.com/#%E2%80%AE", "https://example.com/\r", "https://example.com/%XX", "https://example.com/%FF",
    "https://exa_mple.com", "https://bad..example.com", "http://intranet/path", "https://a.localhost", "https://localhost.localdomain",
    "http://home.arpa", "https://a.home.arpa", "http://metadata.google.internal", "http://192.168.0.10",
    "http://2130706433", "http://0x7f.1", "http://127.1", "http://010.010.010.010", "http://0x08080808",
    "http://127.0.0.1", "http://169.254.169.254", "http://100.64.0.1", "http://224.0.0.1", "http://203.0.113.1",
    "http://[::1]/", "http://[::ffff:127.0.0.1]/", "http://[fc00::1]/", "http://[fe80::1]/", "http://[2001:db8::1]/",
    "http://[2002:7f00:1::1]/", "http://[3fff::1]/",
    ISOLATION_PUBLIC_ORIGIN + "/s/synthetic12_", "https://SUBS-BOT.LILYYA.TOP./%73/synthetic12_",
    "https://example.com/" + "a".repeat(2049),
  ]) assert.equal(canonicalShortDestination(input), null, input);
});
