"""
Adversarial / error-path testing through the FULL model path
(extract_features -> fitted model -> verdict logic, with DNS mocked).

Covers the nine requested URL classes:
  legitimate, suspicious, IP-based, long, subdomain-heavy, @-trick,
  Unicode/IDN, special-character, and reserved .invalid test URLs.

Every call must return a well-formed result — the model may classify either
way, but the pipeline must never crash, never leak a 5xx, and must apply the
SSRF/structural policy. No URL-specific expectations: assertions are on
behavioral invariants and general risk indicators only.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

BACKEND_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_DIR))

from fastapi.testclient import TestClient  # noqa: E402

from app.core.inference import InferenceEngine  # noqa: E402
from app.main import app  # noqa: E402


@pytest.fixture(scope="module", autouse=True)
def _model():
    if not InferenceEngine.instance().load():
        pytest.fail("Model bundle missing — run backend/training/train.py first")


@pytest.fixture()
def client():
    with patch("app.core.dns_verifier.cached_domain_exists",
               return_value={"checked": True, "exists": True, "records": ["A 93.184.216.34"],
                             "registrable": "example.org"}):
        with TestClient(app) as c:
            yield c


def _analyze(client, url):
    r = client.post("/api/v1/predict", json={"url": url})
    assert r.status_code == 200, f"{url!r} -> HTTP {r.status_code}: {r.text[:200]}"
    body = r.json()
    # Response-contract invariants for EVERY class
    assert body["prediction"] in ("LEGITIMATE", "SUSPICIOUS", "PHISHING")
    assert 0 <= body["risk_score"] <= 100
    assert 0 <= body["confidence"] <= 100
    assert 0 <= body["probability_phishing"] <= 1
    assert body["contributing_features"], f"{url!r}: SHAP contributions must not be empty"
    assert isinstance(body["guardrail_flags"], list)
    assert body["model_version"]
    return body


# Representative URLs for the nine classes (safe, well-known or reserved).
URL_CLASSES = {
    "legitimate": [
        "https://en.wikipedia.org/wiki/Phishing",
        "https://www.python.org/downloads/",
        "https://www.mozilla.org/en-US/",
    ],
    "suspicious": [
        "http://secure-update.example-site.xyz/login",
        "https://account-verify.signin-info.cfd/session",
    ],
    "ip_based": [
        "http://93.184.216.34/download",           # public IP host
        "http://212.47.228.169:8080/admin",        # public IP + unusual port
    ],
    "long": [
        "https://example.org/" + "a" * 900 + "/resource",
        "https://shop.example-cfd.xyz/catalog?" + "ref=" + "x" * 400 + "&id=9",
    ],
    "subdomain_heavy": [
        "https://a.b.c.d.e.f.g.h.sso.en.wikipedia.org/login",
        "https://secure.login.account.verify.update.www.example.com/session",
    ],
    "at_trick": [
        # Real host is a public IP after '@' — userinfo spoofing must be
        # detected WITHOUT tripping the SSRF policy (the SSRF policy applies
        # to the parsed host, i.e. what comes AFTER '@').
        "https://www.wikipedia.org@93.184.216.34/login",
        "http://google.com@metricrulexyz.top/pay",
    ],
    "unicode_idn": [
        "https://xn--80ak6aa92e.com/",             # punycode 'аррle'-style
        "https://xn--e1afmkfd.xn--p1ai/",          # Cyrillic .рф
    ],
    "special_characters": [
        "https://example.org/p%3Fa%3D1%26b=2",
        "https://example.org/search?q=%24%25%5E%26%26%2A%28%29",
    ],
    "reserved_invalid": [
        "https://shop.invalid/",                   # RFC 2606 reserved TLD
        "http://api.test.example/checkout",        # RFC 6761 reserved
    ],
}


# --------------------------------------------------------------------------- #
# Per-class behavioral expectations
# --------------------------------------------------------------------------- #
def test_legitimate_class_verdicts_safe(client):
    for url in URL_CLASSES["legitimate"]:
        body = _analyze(client, url)
        assert body["prediction"] == "LEGITIMATE", f"{url} -> {body['prediction']} (FP)"
        assert body["risk_score"] <= 20


def test_suspicious_class_scores_moderate_or_high(client):
    for url in URL_CLASSES["suspicious"]:
        body = _analyze(client, url)
        assert body["risk_score"] >= 35, f"{url} risk too low: {body['risk_score']}"


def test_ip_based_flagged_or_elevated(client):
    for url in URL_CLASSES["ip_based"]:
        body = _analyze(client, url)
        assert body["risk_score"] >= 35, f"{url} risk too low: {body['risk_score']}"


def test_long_urls_never_break_and_score_reasonably(client):
    for url in URL_CLASSES["long"]:
        body = _analyze(client, url)
        assert body["risk_score"] <= 100
        # Length evidence must be visible to the explanation (the length
        # feature family: total/host/path/query — whichever dominates).
        feats = {c["feature"] for c in body["contributing_features"]}
        length_family = {"url_length", "hostname_length", "path_length", "query_length"}
        assert feats & length_family or body["risk_score"] < 50


def test_subdomain_heavy_flagged_or_elevated(client):
    for url in URL_CLASSES["subdomain_heavy"]:
        body = _analyze(client, url)
        assert body["risk_score"] >= 35, f"{url} risk too low: {body['risk_score']}"


def test_at_trick_urls_flagged_or_elevated(client):
    for url in URL_CLASSES["at_trick"]:
        body = _analyze(client, url)
        assert body["risk_score"] >= 35, f"{url} risk too low: {body['risk_score']}"


def test_unicode_idn_handled_safely(client):
    for url in URL_CLASSES["unicode_idn"]:
        body = _analyze(client, url)
        # punycode hosts must not crash and should lean suspicious
        assert body["risk_score"] >= 20, f"{url} risk too low: {body['risk_score']}"


def test_special_characters_handled_safely(client):
    for url in URL_CLASSES["special_characters"]:
        body = _analyze(client, url)
        assert body["risk_score"] <= 100


def test_reserved_invalid_tlds_fail_closed_as_phishing(client):
    """RFC 6761/2606 reserved names (*.invalid, *.test, *.example) are
    guaranteed NXDOMAIN — the realistic DNS answer for this class is
    exists=False, which must trip the DNS guardrail and fail closed."""
    with patch("app.core.dns_verifier.cached_domain_exists",
               return_value={"checked": True, "exists": False, "records": [],
                             "registrable": "reserved.invalid"}):
        for url in URL_CLASSES["reserved_invalid"]:
            body = _analyze(client, url)
            assert body["prediction"] == "PHISHING", f"{url} must not validate as safe"
            assert body["risk_score"] >= 85
            assert any("no DNS records" in f for f in body["guardrail_flags"])


# --------------------------------------------------------------------------- #
# Cross-class invariants
# --------------------------------------------------------------------------- #
def test_determinism_across_classes(client):
    """Repeating the SAME URL must produce identical scores (cache effects
    such as the DNS memo must not change the verdict)."""
    for urls in URL_CLASSES.values():
        a = _analyze(client, urls[0])
        b = _analyze(client, urls[0])
        assert (a["risk_score"], a["probability_phishing"]) == \
               (b["risk_score"], b["probability_phishing"]), \
               f"non-deterministic result for {urls[0]!r}"


def test_normalized_url_differs_from_trick_input(client):
    body = _analyze(client, URL_CLASSES["at_trick"][0])
    # the userinfo trick must not survive normalization as the apparent host:
    # the real host (after '@') is the network target, the brand prefix is
    # display-only and must never become the parsed host.
    assert body["normalized_url"].startswith("https://")
    assert "@" in body["normalized_url"]
    real_host = body["normalized_url"].rsplit("@", 1)[-1].split("/", 1)[0]
    assert real_host == "93.184.216.34", \
        f"parsed host must be the post-'@' target, got {real_host!r}"
    assert "contributing_features" in body and isinstance(body["dns_check"], dict)


def test_ssrf_and_dangerous_schemes_rejected(client):
    for url in ("http://127.0.0.1:8000/health", "http://169.254.169.254/latest/meta-data",
                "http://192.168.1.5/", "javascript:alert(1)", "data:text/html,x"):
        r = client.post("/api/v1/predict", json={"url": url})
        assert r.status_code in (400, 422), f"{url} -> {r.status_code}"


def test_malformed_inputs_structured_422(client):
    for url in ("", "ab", "https://ex ample.com", "https://" + "x" * 3000):
        r = client.post("/api/v1/predict", json={"url": url})
        assert r.status_code == 422, f"{url!r} -> {r.status_code}"
        assert "detail" in r.json()


def test_requests_are_not_rate_limited(client):
    """Rate limiting was removed: a burst far past the old 30/minute budget
    must never be throttled. Covers the history endpoint the analytics view
    leans on, plus predict."""
    history_codes = {
        client.get("/api/v1/history", params={"page": 1, "page_size": 1}).status_code
        for _ in range(45)
    }
    assert history_codes == {200}, f"history was throttled: {history_codes}"

    predict_codes = [
        client.post("/api/v1/predict", json={"url": "https://en.wikipedia.org/"}).status_code
        for _ in range(5)
    ]
    assert predict_codes == [200] * 5, f"predict was throttled: {predict_codes}"
