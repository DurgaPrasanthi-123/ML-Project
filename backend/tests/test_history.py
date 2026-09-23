"""
Integration tests for GET /api/v1/history (paginated scan history) and the
url_hash persistence contract, using an isolated per-module SQLite database
(the same SQLAlchemy code path serves PostgreSQL).
"""

from __future__ import annotations

import hashlib
import os
import sys
import uuid
from pathlib import Path
from unittest.mock import patch

import pytest

BACKEND_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_DIR))

from app.config import get_settings  # noqa: E402
from app.core.inference import InferenceEngine  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.db import database  # noqa: E402
from app.main import app  # noqa: E402


@pytest.fixture(scope="module", autouse=True)
def _isolated_db(tmp_path_factory):
    """Point DATABASE_URL at a throwaway SQLite DB for this module only."""
    db_path = tmp_path_factory.mktemp("history") / "history_test.db"
    old = os.environ.get("DATABASE_URL")
    os.environ["DATABASE_URL"] = f"sqlite:///{db_path}"
    get_settings.cache_clear()
    database.reset_engine()
    yield
    if old is None:
        os.environ.pop("DATABASE_URL", None)
    else:
        os.environ["DATABASE_URL"] = old
    get_settings.cache_clear()
    database.reset_engine()


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


def _scan(client, url):
    r = client.post("/api/v1/predict", json={"url": url})
    assert r.status_code == 200
    return r.json()


def _get(client, **params):
    return client.get("/api/v1/history", params=params or None)


# --------------------------------------------------------------------------- #
# Empty state & pagination
# --------------------------------------------------------------------------- #
def test_history_empty(client):
    r = _get(client)
    assert r.status_code == 200
    body = r.json()
    assert body["items"] == []
    assert body["total"] == 0
    assert body["page"] == 1
    assert body["pages"] == 1


def test_history_pagination(client):
    for i in range(5):
        _scan(client, f"https://example.org/page/{i}")
    r = _get(client, page=1, page_size=2)
    body = r.json()
    assert body["total"] >= 5
    assert len(body["items"]) == 2
    assert body["page"] == 1 and body["page_size"] == 2
    pages = -(-body["total"] // 2)
    assert body["pages"] == pages
    # newest first: ids strictly decreasing across pages
    r2 = _get(client, page=2, page_size=2)
    ids = [i["id"] for i in body["items"]] + [i["id"] for i in r2.json()["items"]]
    assert ids == sorted(ids, reverse=True)
    # page beyond the end is empty, not an error
    r3 = _get(client, page=10_000, page_size=2)
    assert r3.status_code == 200
    assert r3.json()["items"] == []


# --------------------------------------------------------------------------- #
# Stored row contract: url_hash + all required fields
# --------------------------------------------------------------------------- #
def test_history_row_contract(client):
    _scan(client, "https://example.org/contract")
    r = _get(client, page_size=1)
    row = r.json()["items"][0]
    for key in ("id", "url", "normalized_url", "url_hash", "prediction", "confidence",
                "risk_score", "probability_phishing", "model_name", "model_version",
                "created_at"):
        assert key in row, f"missing {key} in history item"
    assert row["prediction"] in ("LEGITIMATE", "SUSPICIOUS", "PHISHING")
    assert 0 <= row["risk_score"] <= 100
    assert 0 <= row["confidence"] <= 100
    assert row["model_version"]
    assert row["created_at"].endswith("Z") or "+" in row["created_at"] or "T" in row["created_at"]


def test_predict_stores_matching_url_hash(client):
    result = _scan(client, "https://example.org/hash-check")
    expected = hashlib.sha256(result["normalized_url"].encode()).hexdigest()
    r = _get(client, page_size=1)
    row = r.json()["items"][0]
    assert row["url_hash"] == expected
    assert len(row["url_hash"]) == 64


# --------------------------------------------------------------------------- #
# Filters & validation
# --------------------------------------------------------------------------- #
def test_history_prediction_filter(client):
    _scan(client, "https://example.org/filter-legit")
    r = _get(client, prediction="PHISHING")
    body = r.json()
    assert all(i["prediction"] == "PHISHING" for i in body["items"])
    assert body["total"] == len(body["items"])


def test_history_invalid_prediction_filter_rejected(client):
    r = _get(client, prediction="HACKED")
    assert r.status_code == 422


@pytest.mark.parametrize("params, status", [
    ({"page": 0}, 422),
    ({"page": -1}, 422),
    ({"page_size": 0}, 422),
    ({"page_size": 101}, 422),
])
def test_history_pagination_validation(client, params, status):
    assert _get(client, **params).status_code == status


def test_history_page_size_capped(client):
    _scan(client, "https://example.org/cap")
    r = _get(client, page_size=100)
    assert r.status_code == 200


# --------------------------------------------------------------------------- #
# Disabled history
# --------------------------------------------------------------------------- #
def test_history_disabled_returns_503(client, monkeypatch):
    monkeypatch.setattr(get_settings(), "history_enabled", False)
    r = _get(client)
    assert r.status_code == 503
    assert "disabled" in r.json()["detail"]
    monkeypatch.undo()


# --------------------------------------------------------------------------- #
# Migrations: idempotency + legacy-row backfill
# --------------------------------------------------------------------------- #
def test_migrations_idempotent():
    v1 = database.run_migrations()
    v2 = database.run_migrations()
    assert v1 == v2 == database.LATEST_SCHEMA_VERSION


def test_legacy_rows_get_url_hash_backfilled(client):
    engine = database.get_engine()
    from sqlalchemy import text

    normalized = "https://example.org/legacy-row"
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO scan_history (url, normalized_url, url_hash, prediction, "
                "confidence, risk_score, probability_phishing, model_name, model_version, created_at) "
                "VALUES (:u, :n, '', 'LEGITIMATE', 90.0, 10, 0.1, 'XGBoost', '3.0.0', :ts)"
            ),
            {"u": normalized, "n": normalized, "ts": "2026-01-01 00:00:00"},
        )
    database.run_migrations()
    expected = hashlib.sha256(normalized.encode()).hexdigest()
    with engine.begin() as conn:
        stored = conn.execute(
            text("SELECT url_hash FROM scan_history WHERE normalized_url = :n"),
            {"n": normalized},
        ).scalar_one()
    assert stored == expected


def test_repeat_scan_same_hash(client):
    a = _scan(client, "https://example.org/repeat")
    b = _scan(client, "https://example.org/repeat")
    assert a["normalized_url"] == b["normalized_url"]
    r = _get(client, page_size=2)
    hashes = {i["url_hash"] for i in r.json()["items"]}
    assert hashlib.sha256(a["normalized_url"].encode()).hexdigest() in hashes


# --------------------------------------------------------------------------- #
# Analytics aggregate (/history/stats)
# --------------------------------------------------------------------------- #
def _stats(client):
    r = client.get("/api/v1/history/stats")
    assert r.status_code == 200, r.text
    return r.json()


def _insert_row(normalized: str, prediction: str, risk_score: int) -> None:
    """Insert one row with an exact verdict/risk score (bypasses the model so
    band boundaries are deterministic)."""
    from sqlalchemy import text

    with database.get_engine().begin() as conn:
        conn.execute(
            text(
                "INSERT INTO scan_history (url, normalized_url, url_hash, prediction, "
                "confidence, risk_score, probability_phishing, model_name, model_version, created_at) "
                "VALUES (:u, :n, :h, :p, 90.0, :r, 0.1, 'XGBoost', '3.0.0', :ts)"
            ),
            {
                "u": normalized,
                "n": normalized,
                "h": database.url_hash(normalized),
                "p": prediction,
                "r": risk_score,
                "ts": "2026-01-01 00:00:00",
            },
        )


def test_history_stats_shape_and_single_request(client):
    """Analytics needs one request — no page/page_size parameters involved."""
    body = _stats(client)
    assert set(body) == {"total", "counts", "risk_bands"}
    assert set(body["counts"]) == {"LEGITIMATE", "SUSPICIOUS", "PHISHING"}
    assert set(body["risk_bands"]) == {"low", "medium", "high"}


def test_history_stats_counts_match_the_database(client):
    """Figures are aggregated from the table, never from constants."""
    from sqlalchemy import text

    with database.get_engine().begin() as conn:
        db_total = conn.execute(text("SELECT COUNT(*) FROM scan_history")).scalar_one()
        db_phish = conn.execute(
            text("SELECT COUNT(*) FROM scan_history WHERE prediction = 'PHISHING'")
        ).scalar_one()

    body = _stats(client)
    assert body["total"] == db_total
    assert body["counts"]["PHISHING"] == db_phish
    assert body["counts"]["LEGITIMATE"] + body["counts"]["SUSPICIOUS"] + body["counts"]["PHISHING"] == db_total
    # Every scan falls in exactly one risk band.
    assert sum(body["risk_bands"].values()) == db_total


def test_history_stats_tracks_new_scans(client):
    """A real scan through /predict moves the analytics counters."""
    before = _stats(client)
    _scan(client, "https://en.wikipedia.org/wiki/Phishing")
    after = _stats(client)

    assert after["total"] == before["total"] + 1
    moved = [
        p
        for p in ("LEGITIMATE", "SUSPICIOUS", "PHISHING")
        if after["counts"][p] == before["counts"][p] + 1
    ]
    assert len(moved) == 1, "exactly one verdict bucket should gain the new scan"
    assert sum(after["risk_bands"].values()) == after["total"]


def test_history_stats_risk_band_boundaries(client):
    """Band edges: 34/35 and 74/75 split low|medium|high exactly."""
    before = _stats(client)
    for i, (prediction, risk) in enumerate(
        [("LEGITIMATE", 0), ("LEGITIMATE", 34), ("SUSPICIOUS", 35), ("SUSPICIOUS", 74),
         ("PHISHING", 75), ("PHISHING", 100)]
    ):
        _insert_row(f"https://example.org/band-{i}", prediction, risk)
    after = _stats(client)

    assert after["total"] == before["total"] + 6
    assert after["counts"]["LEGITIMATE"] == before["counts"]["LEGITIMATE"] + 2
    assert after["counts"]["SUSPICIOUS"] == before["counts"]["SUSPICIOUS"] + 2
    assert after["counts"]["PHISHING"] == before["counts"]["PHISHING"] + 2
    assert after["risk_bands"]["low"] == before["risk_bands"]["low"] + 2
    assert after["risk_bands"]["medium"] == before["risk_bands"]["medium"] + 2
    assert after["risk_bands"]["high"] == before["risk_bands"]["high"] + 2


def test_history_stats_disabled_returns_503(client, monkeypatch):
    monkeypatch.setattr(get_settings(), "history_enabled", False)
    r = client.get("/api/v1/history/stats")
    assert r.status_code == 503
    assert "disabled" in r.json()["detail"]
    monkeypatch.undo()