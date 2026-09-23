"""
Unit tests for the shared feature extraction module (app.core.features).

The suite pins the CONTRACT: named 42-feature vector, deterministic output,
never crashes on malformed input, identical train/serve builder, and the
phishing-indicative behavior of each feature family on representative URLs.
No network access happens anywhere in this file.
"""

from __future__ import annotations

import math
import sys
from pathlib import Path
from unittest.mock import patch

import numpy as np
import pandas as pd
import pytest

BACKEND_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_DIR))

from app.core.features import (  # noqa: E402
    BRAND_TOKENS,
    FEATURE_NAMES,
    SUSPICIOUS_KEYWORDS,
    SUSPICIOUS_TOKENS,
    _shannon_entropy,
    extract_features,
    extract_features_dataframe,
    feature_names,
)


# --------------------------------------------------------------------------- #
# Contract
# --------------------------------------------------------------------------- #
def test_feature_vector_is_named_and_complete():
    fv = extract_features("https://example.com/")
    assert len(fv) == 42
    assert set(fv.keys()) == set(FEATURE_NAMES)
    assert feature_names() == FEATURE_NAMES
    assert len(set(FEATURE_NAMES)) == len(FEATURE_NAMES), "duplicate feature names"
    assert all(isinstance(v, float) for v in fv.values())


def test_feature_names_order_is_stable():
    assert FEATURE_NAMES[0] == "url_length"
    assert FEATURE_NAMES[-1] == "guardrail_flag_count"


def test_deterministic_output():
    url = "http://login.paypal.com.verify-billing-secure.xyz/signin.php?id=42"
    assert extract_features(url) == extract_features(url)


# --------------------------------------------------------------------------- #
# Robustness: never crash, handle missing/odd values
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("bad_input", [
    "", "//", "http://", "https://ex ample.com", "http://user@:80",
    "https://例え.テスト/", "%zz", "http://[::1", "file:///etc/passwd",
    "https://" + "a" * 3000, "https://not a url at all", ":::",
    "https://" + "x" * 1800 + ".example.com",
])
def test_never_crashes_on_malformed_input(bad_input):
    fv = extract_features(bad_input)
    assert len(fv) == 42
    assert all(np.isfinite(v) for v in fv.values())


def test_missing_values_none_and_nan():
    assert len(extract_features(None)) == 42          # None -> empty URL
    fv = extract_features(float("nan"))               # NaN stringified, finite out
    assert all(np.isfinite(v) for v in fv.values())


def test_internal_failure_returns_neutral_zero_vector():
    with patch("app.core.features.parse_url", side_effect=RuntimeError("boom")):
        fv = extract_features("https://example.com/")
    assert fv["url_length"] == 0.0
    assert fv["dns_exists"] == 0.5, "unknown DNS must stay neutral"
    assert set(fv.keys()) == set(FEATURE_NAMES)


def test_dns_exists_neutral_and_explicit():
    neutral = extract_features("https://example.com/", dns_exists=None)["dns_exists"]
    yes = extract_features("https://example.com/", dns_exists=1)["dns_exists"]
    no = extract_features("https://example.com/", dns_exists=0)["dns_exists"]
    assert neutral == 0.5 and yes == 1.0 and no == 0.0


def test_guardrail_flag_count_is_passed_through():
    fv = extract_features("https://example.com/", guardrail_flag_count=2)
    assert fv["guardrail_flag_count"] == 2.0


# --------------------------------------------------------------------------- #
# Lexical counts
# --------------------------------------------------------------------------- #
def test_lexical_counts_component_wise():
    fv = extract_features("https://www.example-corp.com/path_a/x1?q=search%20term#top")
    assert fv["url_length"] == len("https://www.example-corp.com/path_a/x1?q=search%20term#top")
    assert fv["hostname_length"] == len("www.example-corp.com")
    assert fv["path_length"] == len("/path_a/x1")
    assert fv["query_length"] == len("q=search%20term")
    assert fv["fragment_length"] == len("top")
    assert fv["count_dots"] == 2          # separators between www | example-corp | com
    assert fv["count_hyphens"] == 1
    assert fv["count_underscores"] == 1
    assert fv["count_encoded_chars"] == 1  # %20
    assert fv["has_fragment"] == 1.0
    assert fv["path_depth"] == 2


def test_digit_and_special_counts():
    url = "https://ex4mple.com/a1b2?x=!@#"
    fv = extract_features(url)
    assert fv["count_digits"] == 3.0      # 4, 1, 2
    assert fv["digit_ratio"] == pytest.approx(3 / len(url))
    assert fv["count_special_chars"] == sum(not c.isalnum() for c in url)


# --------------------------------------------------------------------------- #
# Structural indicators
# --------------------------------------------------------------------------- #
def test_subdomain_depth_etld_aware():
    assert extract_features("https://a.b.c.example.com/")["subdomain_depth"] == 3
    # 'co.uk' is part of the public suffix, not a subdomain level
    assert extract_features("https://www.bbc.co.uk/news")["subdomain_depth"] == 1
    assert extract_features("https://example.co.uk/")["subdomain_depth"] == 0


def test_ip_host_detection():
    fv = extract_features("http://192.168.12.3/login")
    assert fv["is_ip_host"] == 1.0
    assert fv["subdomain_depth"] == 0.0
    assert extract_features("https://example.com/")["is_ip_host"] == 0.0


def test_https_and_ports():
    assert extract_features("https://example.com/")["has_https"] == 1.0
    assert extract_features("http://example.com/")["has_https"] == 0.0
    # default ports are NOT flagged as explicit
    assert extract_features("http://example.com/")["has_explicit_port"] == 0.0
    assert extract_features("https://example.com:443/")["has_explicit_port"] == 0.0
    fv = extract_features("http://example.com:8080/")
    assert fv["has_explicit_port"] == 1.0
    assert fv["has_unusual_port"] == 1.0


def test_at_symbol_and_credentials():
    fv = extract_features("http://admin.example.com@evil.example/")
    assert fv["count_at"] == 1.0
    assert fv["has_credentials_in_url"] == 1.0
    assert extract_features("https://example.com/")["count_at"] == 0.0


def test_query_params_and_fragment_presence():
    fv = extract_features("https://example.com/x?a=1&b=2&c=")
    assert fv["count_params"] == 3.0
    assert extract_features("https://example.com/")["has_fragment"] == 0.0


def test_shortener_free_host_suspicious_tld():
    assert extract_features("https://bit.ly/3xYz")["is_shortener"] == 1.0
    assert extract_features("https://user.github.io/repo/")["is_free_host"] == 1.0
    assert extract_features("https://myblog.blogspot.com/")["is_free_host"] == 1.0
    assert extract_features("https://shop-cheap.xyz/")["suspicious_tld"] == 1.0
    assert extract_features("https://example.com/")["suspicious_tld"] == 0.0


# --------------------------------------------------------------------------- #
# Entropy / ratios / repetition
# --------------------------------------------------------------------------- #
def test_entropy_ranks_dga_like_hostnames_higher():
    human = extract_features("https://example.com/")
    dga = extract_features("https://accounts-google.verify.example.com/sso/login")
    assert dga["hostname_entropy"] > human["hostname_entropy"]
    assert dga["url_entropy"] != human["url_entropy"]
    assert 0 < human["url_entropy"] < 8  # bits/char bounds


def test_digit_ratios_by_component():
    fv = extract_features("http://1.2.3.4/")
    assert fv["hostname_digit_ratio"] == pytest.approx(4 / 7)
    assert fv["path_digit_ratio"] == 0.0
    fv = extract_features("https://www.example.com/id/8842")
    assert fv["hostname_digit_ratio"] == 0.0
    assert fv["path_digit_ratio"] == pytest.approx(4 / 8)


def test_repeated_character_runs():
    fv = extract_features("http://r.example.com/aaaaaa111111")
    assert fv["max_consecutive_chars"] == 6.0
    assert fv["max_consecutive_digits"] == 6.0


def test_entropy_helper_direct():
    assert _shannon_entropy("") == 0.0
    assert _shannon_entropy("aaaa") == 0.0
    assert _shannon_entropy("abab") == pytest.approx(1.0)
    assert _shannon_entropy("abcd") == pytest.approx(2.0)
    assert _shannon_entropy("abcd") == _shannon_entropy("abcd")  # memoized


# --------------------------------------------------------------------------- #
# Content indicators
# --------------------------------------------------------------------------- #
def test_keyword_hits_distinct_keywords():
    fv = extract_features("https://secure-login.example.com/verify/account")
    assert fv["keyword_hits"] == 4.0  # secure, login, verify, account
    assert extract_features("https://weather.example.com/")["keyword_hits"] == 0.0


def test_token_vocabularies_are_disjoint():
    assert not (set(SUSPICIOUS_TOKENS) & set(BRAND_TOKENS)), \
        "overlap would double-count a token in two features"


def test_suspicious_tokens():
    fv = extract_features("https://payment.example.com/invoice/refund")
    assert fv["suspicious_token_count"] == 3.0  # payment, invoice, refund
    assert extract_features("https://example.com/q=reimburse")["suspicious_token_count"] == 0.0


def test_brand_tokens():
    assert extract_features("https://docs.google.com/forms")["brand_token_count"] == 1.0
    # brand token OUTSIDE the official domain + scam structure
    fv = extract_features("http://login.paypal.com.verify-billing-secure.xyz/signin.php")
    assert fv["brand_token_count"] >= 1.0
    assert fv["brand_impersonation_score"] > 0.0


def test_punycode_detection():
    assert extract_features("https://xn--80ak6aa92e.com/")["punycode_host"] == 1.0
    assert extract_features("https://shop.xn--p1ai/")["punycode_host"] == 1.0
    assert extract_features("https://example.com/")["punycode_host"] == 0.0


# --------------------------------------------------------------------------- #
# Named DataFrame helper
# --------------------------------------------------------------------------- #
def test_dataframe_shape_and_columns():
    df = extract_features_dataframe(["https://example.com", "not a url"])
    assert isinstance(df, pd.DataFrame)
    assert df.shape == (2, 42)
    assert list(df.columns) == FEATURE_NAMES
    assert np.isfinite(df.to_numpy()).all()


def test_dataframe_dns_semantics():
    scalar = extract_features_dataframe(["https://a.com", "https://b.com"], dns_exists=1)
    assert (scalar["dns_exists"] == 1.0).all()
    seq = extract_features_dataframe(["https://a.com", "https://b.com"],
                                     dns_exists=[None, 0])
    assert seq["dns_exists"].tolist() == [0.5, 0.0]
    with pytest.raises(ValueError):
        extract_features_dataframe(["https://a.com"], dns_exists=[1, 0])


# --------------------------------------------------------------------------- #
# Phishing vs legitimate smoke separation (model-agnostic sanity)
# --------------------------------------------------------------------------- #
def test_obvious_phishing_scores_higher_on_risk_features():
    phish = extract_features("http://login.paypal.com.verify-billing-secure.xyz/signin.php")
    legit = extract_features("https://en.wikipedia.org/wiki/Machine_learning")
    risk_features = (
        "suspicious_tld", "brand_impersonation_score", "keyword_hits",
        "count_hyphens", "subdomain_depth",
    )
    for f in risk_features:
        assert phish[f] > legit[f], f"feature {f} should favor the phishing URL"


def test_entropy_cache_is_bounded_and_correct():
    assert _shannon_entropy("abcdefgh") == pytest.approx(3.0)
    assert _shannon_entropy("a" * 10**6) == 0.0
    assert len(_ENTROPY_CACHE := __import__("app.core.features", fromlist=["x"])._ENTROPY_CACHE) < 1_000_000
