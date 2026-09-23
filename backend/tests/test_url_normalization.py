"""URL normalization: bare input must parse consistently with its explicit form.

Guards the normalize_url contract that the API and feature extractor both rely
on — a bare domain submitted without a scheme must produce the same parsed
fields (scheme, host, port, path) as the equivalent https:// URL.
"""

from __future__ import annotations

import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_DIR))

import pytest  # noqa: E402

from app.core.url_parser import normalize_url, parse_url  # noqa: E402


@pytest.mark.parametrize(
    ("bare", "explicit"),
    [
        ("example.com", "https://example.com"),
        ("example.com/login", "https://example.com/login"),
        ("example.com?q=1", "https://example.com?q=1"),
        ("example.com:8080", "https://example.com:8080"),
        ("example.com:8080/admin", "https://example.com:8080/admin"),
        ("192.168.1.5/admin", "https://192.168.1.5/admin"),
    ],
)
def test_bare_domain_matches_explicit_form(bare, explicit):
    """A bare domain parses identically to the https://-prefixed form."""
    assert normalize_url(bare) == explicit

    b = parse_url(bare)
    e = parse_url(explicit)
    assert not b.parse_error, b.parse_error
    assert (b.scheme, b.hostname, b.port, b.path) == (e.scheme, e.hostname, e.port, e.path)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        # port must stay a port, not become a scheme
        ("example.com:8080", "https://example.com:8080"),
        # scheme-relative input
        ("//example.com/x", "https://example.com/x"),
        # malformed authority separators
        ("https:/example.com", "https://example.com"),
        ("https:///example.com", "https://example.com"),
        # well-formed input is untouched
        ("https://example.com", "https://example.com"),
        ("http://example.com:8080/x", "http://example.com:8080/x"),
        # double slashes inside the path are preserved
        ("https://example.com/a//b", "https://example.com/a//b"),
    ],
)
def test_normalize_repairs_and_preserves(raw, expected):
    assert normalize_url(raw) == expected


def test_normalize_is_idempotent():
    for raw in ["example.com", "//example.com/x", "https:/example.com", "example.com:8080"]:
        once = normalize_url(raw)
        assert normalize_url(once) == once


@pytest.mark.parametrize("rejected", ["ftp://example.com", "mailto:a@b.com", "example.com:abc"])
def test_non_web_schemes_are_not_silently_rescued(rejected):
    """Unknown schemes stay untouched and are rejected downstream (422)."""
    assert normalize_url(rejected) == rejected
    p = parse_url(rejected)
    assert p.parse_error, "expected the parser to reject the untouched scheme"


def test_dangerous_scheme_untouched():
    assert normalize_url("javascript:alert(1)") == "javascript:alert(1)"
    assert parse_url("javascript:alert(1)").parse_error.startswith("dangerous_scheme")


def test_bare_host_with_port_parses_port():
    p = parse_url("example.com:8080/admin")
    assert not p.parse_error
    assert p.scheme == "https"
    assert p.hostname == "example.com"
    assert p.port == 8080
    assert p.path == "/admin"
