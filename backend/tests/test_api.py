"""
API test suite. DNS lookups are mocked (no network dependency); the model
bundle must exist (run backend/training/train.py once before testing).
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

BACKEND_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_DIR))

from app.core.inference import InferenceEngine  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402


@pytest.fixture(scope="module", autouse=True)
def _model():
    if not InferenceEngine.instance().load():
        pytest.fail("Model bundle missing — run backend/training/train.py first")


@pytest.fixture()
def client():
    # Deterministic DNS: everything "exists" unless a test says otherwise.
    with patch("app.core.dns_verifier.cached_domain_exists",
               return_value={"checked": True, "exists": True, "records": ["A 1.2.3.4"],
                             "registrable": "example.com"}):
        with TestClient(app) as c:
            yield c


# --------------------------------------------------------------------------- #
# Health & model-info
# --------------------------------------------------------------------------- #
def test_health(client):
    r = client.get("/api/v1/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] in ("ok", "degraded")
    assert body["model_loaded"] is True


def test_model_info(client):
    r = client.get("/api/v1/model-info")
    assert r.status_code == 200
    body = r.json()
    assert body["model_name"] in ("Logistic Regression", "Random Forest", "XGBoost")
    assert len(body["comparison"]) == 3
    for m in body["comparison"]:
        assert {"accuracy", "precision", "recall", "f1_score", "roc_auc", "confusion_matrix"} <= set(m)
    assert body["thresholds"]["phishing_threshold"] > body["thresholds"]["suspicious_threshold"]
    assert len(body["feature_names"]) == 42


# --------------------------------------------------------------------------- #
# Prediction
# --------------------------------------------------------------------------- #
def test_predict_response_contract(client):
    r = client.post("/api/v1/predict", json={"url": "https://en.wikipedia.org/wiki/Machine_learning"})
    assert r.status_code == 200
    body = r.json()
    for key in ("prediction", "confidence", "risk_score", "contributing_features",
                "model_version", "probability_phishing"):
        assert key in body
    assert body["prediction"] in ("LEGITIMATE", "SUSPICIOUS", "PHISHING")
    assert 0 <= body["risk_score"] <= 100
    assert body["contributing_features"], "SHAP contributions must not be empty"


def test_predict_records_history(client):
    r = client.post("/api/v1/predict", json={"url": "https://docs.python.org/3/"})
    assert r.status_code == 200
    assert isinstance(r.json().get("scan_id"), int)


def test_known_phishing_pattern(client):
    url = "http://login.paypal.com.verify-billing-secure.xyz/signin.php"
    r = client.post("/api/v1/predict", json={"url": url})
    body = r.json()
    assert body["prediction"] in ("PHISHING", "SUSPICIOUS")
    assert body["risk_score"] >= 35


def test_brand_impersonation_guardrail(client):
    url = "https://login.paypal.com.session-928431.xyz/login?cmd=account-login"
    r = client.post("/api/v1/predict", json={"url": url})
    body = r.json()
    assert body["prediction"] == "PHISHING"
    assert any("impersonation" in f.lower() for f in body["guardrail_flags"])


def test_dns_nonexistent_guardrail(client):
    with patch("app.core.dns_verifier.cached_domain_exists",
               return_value={"checked": True, "exists": False, "records": [],
                             "registrable": "kzxqv7n2m4plt8w3d.com"}):
        r = client.post("/api/v1/predict", json={"url": "https://kzxqv7n2m4plt8w3d.com/services"})
    body = r.json()
    assert body["prediction"] == "PHISHING"
    assert body["risk_score"] >= 85
    assert any("no DNS records" in f for f in body["guardrail_flags"])


def test_dns_unknown_fails_open(client):
    # Resolver outage -> neutral feature + no override, never a hard block.
    with patch("app.core.dns_verifier.cached_domain_exists",
               return_value={"checked": False, "exists": None, "records": [],
                             "registrable": "example.com"}):
        r = client.post("/api/v1/predict", json={"url": "https://example.com/"})
    assert r.status_code == 200
    assert r.json()["prediction"] in ("LEGITIMATE", "SUSPICIOUS", "PHISHING")


# --------------------------------------------------------------------------- #
# Validation & SSRF
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("bad_url", [
    "javascript:alert(1)",
    "data:text/html,hi",
    "ab",
    "https://ex ample.com",
])
def test_invalid_urls_rejected(client, bad_url):
    r = client.post("/api/v1/predict", json={"url": bad_url})
    assert r.status_code in (400, 422), f"{bad_url!r} -> {r.status_code}"


@pytest.mark.parametrize("ssrf_url", [
    "http://192.168.1.5/admin",
    "http://127.0.0.1:8000/health",
    "http://10.0.0.1/",
    "http://localhost/",
    "http://169.254.169.254/latest/meta-data",
    # obfuscated loopback/private literals: inet_aton short forms, hex parts,
    # decimal-encoded integers, userinfo-hidden targets, IPv6 loopback
    "http://127.1/",
    "http://10.1/",
    "http://0x7f.1/",
    "http://2130706433/",
    "http://user@169.254.169.254/",
    "http://[::1]/",
    "http://[fe80::1]/",
    "http://0.0.0.0/",
])
def test_ssrf_targets_rejected(client, ssrf_url):
    r = client.post("/api/v1/predict", json={"url": ssrf_url})
    assert r.status_code == 400, f"{ssrf_url!r} -> {r.status_code}"
    assert "annot be analyzed" in r.json()["detail"]


def test_empty_body_rejected(client):
    r = client.post("/api/v1/predict", json={"other": "x"})
    assert r.status_code == 422


# --------------------------------------------------------------------------- #
# Feature contract (training/serving parity)
# --------------------------------------------------------------------------- #
def test_feature_names_stable():
    from app.core.features import FEATURE_NAMES, feature_names

    assert feature_names() == FEATURE_NAMES
    assert len(FEATURE_NAMES) == 42


def test_train_serve_parity():
    """The bundle's feature list must equal the live builder's output order."""
    bundle = InferenceEngine.instance().bundle
    from app.core.features import feature_names

    assert bundle["feature_names"] == feature_names()


def test_no_hardcoded_url_verdicts():
    """Guardrail modules must not contain URL-literal verdict tables."""
    import re

    import app.core.guardrails as g
    import app.core.inference as inf

    src = Path(inspect := __import__("inspect").getsourcefile(g)).read_text()
    src2 = Path(__import__("inspect").getsourcefile(inf)).read_text()
    for text in (src, src2):
        assert not re.search(r"https?://[a-z0-9.-]+\.(com|net|org|xyz|top)", text), \
            "hardcoded URL found in verdict logic"
