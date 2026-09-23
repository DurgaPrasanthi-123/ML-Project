"""API v1 routes: /predict, /history, /history/stats, /health, /model-info.

There is no request throttling: every endpoint is unlimited. The remaining
protections are unchanged — input validation, SSRF target rejection, bounded
history pagination, and the DNS/brand guardrails.
"""

from __future__ import annotations

import logging
import math

from fastapi import APIRouter, HTTPException, Query, Request

from app.config import get_settings
from app.core.inference import InferenceEngine
from app.db import database
from app.api.v1.schemas import (
    HealthResponse,
    ModelInfoResponse,
    PredictRequest,
    PredictResponse,
    ScanHistoryItem,
    ScanHistoryResponse,
    ScanHistoryStatsResponse,
)

logger = logging.getLogger("app.api")
router = APIRouter()

VALID_PREDICTIONS = ("LEGITIMATE", "SUSPICIOUS", "PHISHING")


@router.post("/predict", response_model=PredictResponse)
def predict(request: Request, payload: PredictRequest):
    engine = InferenceEngine.instance()
    try:
        result = engine.analyze_url(payload.url)
    except ValueError as exc:
        message = str(exc)
        if message.startswith("ssrf_target"):
            raise HTTPException(
                status_code=400,
                detail="Private, reserved, or internal network addresses cannot be analyzed.",
            )
        raise HTTPException(status_code=422, detail=f"Invalid URL: {message.split(':', 1)[-1].strip()}")
    except RuntimeError:
        raise HTTPException(status_code=503, detail="Model is not loaded. Run the training pipeline first.")

    client_ip = request.client.host if request.client else None
    scan_id = database.record_scan(result, client_ip=client_ip)
    if scan_id:
        result["scan_id"] = scan_id
    return result


@router.get("/history", response_model=ScanHistoryResponse)
def history(
    page: int = Query(1, ge=1, le=10_000, description="1-indexed page number"),
    page_size: int = Query(20, ge=1, le=100, description="Rows per page (max 100)"),
    prediction: str | None = Query(None, description="Filter: LEGITIMATE | SUSPICIOUS | PHISHING"),
):
    """Paginated scan history, newest first."""
    settings = get_settings()
    if not settings.history_enabled:
        raise HTTPException(status_code=503, detail="Scan history is disabled.")
    if prediction is not None and prediction not in VALID_PREDICTIONS:
        raise HTTPException(
            status_code=422,
            detail=f"prediction must be one of {', '.join(VALID_PREDICTIONS)}",
        )
    rows, total = database.list_history(page=page, page_size=page_size, prediction=prediction)
    return ScanHistoryResponse(
        items=[
            ScanHistoryItem(
                id=r.id,
                url=r.url,
                normalized_url=r.normalized_url,
                url_hash=r.url_hash,
                prediction=r.prediction,
                confidence=r.confidence,
                risk_score=r.risk_score,
                probability_phishing=r.probability_phishing,
                model_name=r.model_name,
                model_version=r.model_version,
                created_at=r.created_at,
            )
            for r in rows
        ],
        total=total,
        page=page,
        page_size=page_size,
        pages=max(1, math.ceil(total / page_size)) if total else 1,
    )


@router.get("/history/stats", response_model=ScanHistoryStatsResponse)
def history_stats():
    """Aggregate statistics over every stored scan, computed in the database.

    One grouped query per dimension instead of paging the whole history to the
    client, so the numbers cover the full table regardless of its size.
    """
    settings = get_settings()
    if not settings.history_enabled:
        raise HTTPException(status_code=503, detail="Scan history is disabled.")
    return ScanHistoryStatsResponse(**database.history_aggregate())


@router.get("/health", response_model=HealthResponse)
def health():
    settings = get_settings()
    engine = InferenceEngine.instance()
    db_status = "disabled" if not settings.history_enabled else "connected"
    if settings.history_enabled:
        try:
            database.get_engine()
            database.history_stats()  # exercises a real query
        except Exception:  # noqa: BLE001
            db_status = "unavailable"
    return HealthResponse(
        status="ok" if engine.is_ready else "degraded",
        model_loaded=engine.is_ready,
        database=db_status,
        environment=settings.environment,
    )


@router.get("/model-info", response_model=ModelInfoResponse)
def model_info():
    engine = InferenceEngine.instance()
    if not engine.is_ready:
        raise HTTPException(status_code=503, detail="Model is not loaded.")

    bundle = engine.bundle
    settings = get_settings()
    return ModelInfoResponse(
        model_name=bundle.get("best_model", "unknown"),
        model_version=bundle.get("model_version", "unknown"),
        trained_at=bundle.get("trained_at", "unknown"),
        dataset=bundle.get("dataset", {}),
        metrics=bundle.get("metrics", {}),
        comparison=bundle.get("comparison", []),
        thresholds={
            "phishing_threshold": settings.phishing_threshold,
            "suspicious_threshold": settings.suspicious_threshold,
        },
        feature_names=bundle.get("feature_names", []),
        global_feature_importance=bundle.get("global_feature_importance", []),
        history=database.history_stats(),
    )
