"""
Feature extraction — the single source of truth for the ML feature vector.

CONTRACT: both the training pipeline (backend/training/train.py) and the
inference service (backend/app/core/inference.py) import THIS module, so
training and serving features can never drift apart. Do not duplicate this
logic anywhere else.

Guarantees:
- Pure string/structure analysis: no HTTP request is ever made here. The only
  network side-effect in the pipeline is the DNS existence check, which the
  CALLER performs and passes in via `dns_exists` — keeping this module
  network-free and trivially testable.
- Never crashes: malformed/missing input yields the neutral zero vector,
  never an exception.
- Deterministic: the same input string always produces the same output dict.
- Named vector: keys are exactly FEATURE_NAMES (see feature_names()), and
  extract_features_dataframe() returns that as a labeled DataFrame.

Feature groups (42 features): lexical counts, structural indicators,
entropy/ratio measures, content indicators (keywords / scam tokens / brand
tokens / impersonation rules), and two pipeline-meta features (dns_exists,
guardrail_flag_count). Every feature is documented in docs/FEATURES.md.
"""

from __future__ import annotations

import logging
import math
import re

from app.core.brand_impersonation import analyze_brand_impersonation
from app.core.url_parser import SUSPICIOUS_TLDS, parse_url

logger = logging.getLogger("app.features")

FEATURE_NAMES: list[str] = [
    # --- lexical counts -------------------------------------------------
    "url_length",
    "hostname_length",
    "path_length",
    "query_length",
    "fragment_length",
    "count_dots",
    "count_hyphens",
    "count_underscores",
    "count_digits",
    "count_special_chars",
    "count_encoded_chars",
    "count_at",
    # --- structural indicators -------------------------------------------
    "subdomain_depth",
    "count_params",
    "path_depth",
    "has_fragment",
    "is_ip_host",
    "has_https",
    "has_explicit_port",
    "has_unusual_port",
    "has_credentials_in_url",
    "is_shortener",
    "is_free_host",
    "suspicious_tld",
    "double_slash_in_path",
    # --- entropy / ratios -------------------------------------------------
    "hostname_entropy",
    "url_entropy",
    "path_entropy",
    "hostname_digit_ratio",
    "path_digit_ratio",
    "digit_ratio",
    "special_char_ratio",
    "max_consecutive_chars",
    "max_consecutive_digits",
    # --- content indicators ------------------------------------------------
    "keyword_hits",
    "suspicious_token_count",
    "brand_token_count",
    "brand_impersonation_score",
    "brand_embedded",
    "punycode_host",
    # --- pipeline meta -------------------------------------------------------
    "dns_exists",
    "guardrail_flag_count",
]

# Keyword lexicon: ONE input among 42 features (never a verdict by itself).
# Counted as DISTINCT keywords present (substring match) in the full URL.
SUSPICIOUS_KEYWORDS: tuple[str, ...] = (
    "login", "signin", "verify", "verification", "secure", "security",
    "account", "update", "confirm", "billing", "password", "wallet",
    "webscr", "recover", "suspended", "unlock", "session", "auth",
)

# Scam/lure vocabulary counted as whole TOKENS (delimiter-bounded), disjoint
# from SUSPICIOUS_KEYWORDS. Captures urgency + abuse-of-trust phrasing that
# keyword substrings miss.
SUSPICIOUS_TOKENS: frozenset[str] = frozenset({
    "invoice", "payment", "payments", "refund", "banking", "promotion",
    "winner", "winners", "lottery", "bonus", "freegift", "claim", "urgent",
    "important", "alert", "limited", "support", "helpdesk", "customer",
    "webmail", "drive", "docs", "sharefile",
})

# Well-known brand tokens appearing OUTSIDE their official domains are a
# classic impersonation lure (e.g. 'paypal' in 'paypal-secure-login.xyz').
BRAND_TOKENS: frozenset[str] = frozenset({
    "google", "microsoft", "apple", "appleid", "icloud", "paypal", "amazon",
    "netflix", "facebook", "instagram", "whatsapp", "linkedin", "twitter",
    "outlook", "hotmail", "office", "coinbase", "binance", "metamask",
    "blockchain", "dhl", "fedex", "usps", "royalmail", "hsbc", "barclays",
    "chase", "citibank", "wellsfargo", "santander", "lloyds", "sparkasse",
    "revolut", "stripe", "github", "dropbox",
})

UNUSUAL_PORTS: frozenset[int] = frozenset(
    {4443, 8888, 8080, 8443, 8000, 3000, 5000, 9000, 1337, 6666, 7777}
)

PUNYCODE_MARKER = "xn--"

_TOKEN_SPLIT_RE = re.compile(r"[^a-z0-9]+")

# Shannon entropy is pure and deterministic; memoize to keep bulk training fast.
_ENTROPY_CACHE: dict[str, float] = {}
_ENTROPY_CACHE_LIMIT = 200_000


def _shannon_entropy(text: str) -> float:
    """Entropy (bits/char) of the string; 0.0 for empty input. Memoized."""
    if not text:
        return 0.0
    cached = _ENTROPY_CACHE.get(text)
    if cached is not None:
        return cached
    freq: dict[str, int] = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(text)
    value = -sum((c / n) * math.log2(c / n) for c in freq.values())
    if len(_ENTROPY_CACHE) >= _ENTROPY_CACHE_LIMIT:
        _ENTROPY_CACHE.clear()
    _ENTROPY_CACHE[text] = value
    return value


def _keyword_hits(lowered_url: str) -> int:
    return sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in lowered_url)


def _token_hits(tokens: set[str], vocabulary: frozenset[str]) -> int:
    return len(tokens & vocabulary)


def _max_runs(text: str) -> tuple[int, int]:
    """(longest run of one repeated character, longest run of digits)."""
    best = best_digit = cur = cur_digit = 0
    prev = ""
    for ch in text:
        cur = cur + 1 if ch == prev else 1
        if ch.isdigit():
            cur_digit = cur_digit + 1 if prev.isdigit() else 1
        else:
            cur_digit = 0
        best = max(best, cur)
        best_digit = max(best_digit, cur_digit)
        prev = ch
    return best, best_digit


def _ratio(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0.0


def _zero_features() -> dict[str, float]:
    """Neutral vector for catastrophic/missing input (never expected)."""
    z = {name: 0.0 for name in FEATURE_NAMES}
    z["dns_exists"] = 0.5  # neutral 'unknown'
    return z


def extract_features(
    url: str,
    dns_exists: int | None = None,
    guardrail_flag_count: int = 0,
) -> dict[str, float]:
    """
    Build the named feature dict for one URL.

    dns_exists: 1 (resolves), 0 (verifiably no records), None (unknown /
    check disabled) — passed in by the caller so the network side-effect
    stays explicit and testable; None maps to the neutral 0.5.

    guardrail_flag_count: number of deterministic pattern guardrail flags
    raised for this URL (brand impersonation, fabricated domain). Caller
    supplies it; 0 when guardrails are disabled.

    Never raises: any internal failure returns the neutral zero vector.
    """
    if not isinstance(url, str):
        url = "" if url is None else str(url)
    try:
        return _extract(url, dns_exists, guardrail_flag_count)
    except Exception:  # noqa: BLE001 - features must never break serving
        logger.warning("Feature extraction fell back to neutral vector for %r", url[:120])
        return _zero_features()


def _extract(url: str, dns_exists: int | None, guardrail_flag_count: int) -> dict[str, float]:
    p = parse_url(url, strict=False)

    full_text = p.normalized or url
    lowered = full_text.lower()
    host = p.hostname or ""
    path = p.path or ""
    query = p.query or ""
    fragment = p.fragment or ""

    # Brand impersonation (pattern rules; safe: never visits the URL)
    if host and not p.parse_error:
        brand = analyze_brand_impersonation(p)
    else:
        brand = {"confidence": 0.0, "is_impersonation": False, "techniques": []}

    if dns_exists is None:
        dns_feat = 0.5  # neutral when unknown (resolver failure / disabled)
    else:
        dns_feat = 1.0 if dns_exists else 0.0

    tokens = {t for t in _TOKEN_SPLIT_RE.split(lowered) if t}
    max_run, max_digit_run = _max_runs(lowered)

    return {
        # --- lexical counts -------------------------------------------------
        "url_length": float(len(full_text)),
        "hostname_length": float(len(host)),
        "path_length": float(len(path)),
        "query_length": float(len(query)),
        "fragment_length": float(len(fragment)),
        "count_dots": float(lowered.count(".")),
        "count_hyphens": float(lowered.count("-")),
        "count_underscores": float(lowered.count("_")),
        "count_digits": float(sum(c.isdigit() for c in lowered)),
        "count_special_chars": float(sum(not c.isalnum() for c in lowered)),
        "count_encoded_chars": float(lowered.count("%")),
        "count_at": float(lowered.count("@")),
        # --- structural indicators -------------------------------------------
        "subdomain_depth": float(len(p.subdomains)) if not p.is_ip else 0.0,
        "count_params": float(len(p.query_params)),
        "path_depth": float(max(0, path.count("/"))),
        "has_fragment": 1.0 if fragment else 0.0,
        "is_ip_host": 1.0 if p.is_ip else 0.0,
        "has_https": 1.0 if p.scheme == "https" else 0.0,
        "has_explicit_port": 1.0 if (p.port is not None and not p.default_port) else 0.0,
        "has_unusual_port": 1.0 if (
            p.port is not None and not p.default_port and p.port in UNUSUAL_PORTS
        ) else 0.0,
        "has_credentials_in_url": 1.0 if p.userinfo else 0.0,
        "is_shortener": 1.0 if p.is_shortener else 0.0,
        "is_free_host": 1.0 if p.is_free_host else 0.0,
        "suspicious_tld": 1.0 if (not p.is_ip and p.tld in SUSPICIOUS_TLDS) else 0.0,
        "double_slash_in_path": 1.0 if "//" in path else 0.0,
        # --- entropy / ratios -------------------------------------------------
        "hostname_entropy": _shannon_entropy(host),
        "url_entropy": _shannon_entropy(lowered),
        "path_entropy": _shannon_entropy(path),
        "hostname_digit_ratio": _ratio(sum(c.isdigit() for c in host), len(host)),
        "path_digit_ratio": _ratio(sum(c.isdigit() for c in path), len(path)),
        "digit_ratio": _ratio(sum(c.isdigit() for c in lowered), len(lowered)),
        "special_char_ratio": _ratio(sum(not c.isalnum() for c in lowered), len(lowered)),
        "max_consecutive_chars": float(max_run),
        "max_consecutive_digits": float(max_digit_run),
        # --- content indicators ------------------------------------------------
        "keyword_hits": float(_keyword_hits(lowered)),
        "suspicious_token_count": float(_token_hits(tokens, SUSPICIOUS_TOKENS)),
        "brand_token_count": float(_token_hits(tokens, BRAND_TOKENS)),
        "brand_impersonation_score": float(brand.get("confidence", 0.0)),
        "brand_embedded": 1.0 if any(
            "embedded" in t or "referenced" in t for t in brand.get("techniques", [])
        ) else 0.0,
        "punycode_host": 1.0 if (host.startswith(PUNYCODE_MARKER) or f".{PUNYCODE_MARKER}" in host) else 0.0,
        # --- pipeline meta -------------------------------------------------------
        "dns_exists": dns_feat,
        "guardrail_flag_count": float(guardrail_flag_count),
    }


def feature_names() -> list[str]:
    """Ordered feature list — the contract between training and serving."""
    return list(FEATURE_NAMES)


def extract_features_dataframe(urls, dns_exists=None):
    """
    Named pandas DataFrame (one row per URL, columns == feature_names()).
    Used by the training pipeline so the model consumes labeled columns.

    dns_exists: None (neutral for all), a scalar applied to every URL, or a
    sequence matching `urls` length.
    """
    import pandas as pd

    urls = list(urls)
    if dns_exists is None or isinstance(dns_exists, (bool, int, float)):
        dns_values = [dns_exists] * len(urls)
    else:
        dns_values = list(dns_exists)
        if len(dns_values) != len(urls):
            raise ValueError("dns_exists sequence length must match urls length")
    rows = [extract_features(u, dns_exists=d) for u, d in zip(urls, dns_values)]
    return pd.DataFrame(rows, columns=feature_names())
