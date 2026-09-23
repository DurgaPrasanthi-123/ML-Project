"""Pydantic request/response schemas for API v1."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field, field_validator

MAX_URL_LENGTH = 2048


class PredictRequest(BaseModel):
    url: str = Field(..., min_length=4, max_length=MAX_URL_LENGTH, description="The URL to analyze")

    @field_validator("url")
    @classmethod
    def url_must_be_http_s(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("url must not be empty")
        lower = v.lower()
        # Only web schemes are in scope; script/data schemes are rejected.
        if lower.startswith(("javascript:", "data:", "vbscript:", "file:")):
            raise ValueError("url scheme is not allowed")
        if " " in v:
            raise ValueError("url must not contain whitespace")
        return v


class FeatureContribution(BaseModel):
    feature: str
    impact: float
    direction: str


class PredictResponse(BaseModel):
    url: str
    normalized_url: str
    prediction: str  # LEGITIMATE | SUSPICIOUS | PHISHING
    confidence: float
    risk_score: int  # 0-100
    risk_level: str
    probability_phishing: float
    contributing_features: list[FeatureContribution]
    guardrail_flags: list[str]
    dns_check: dict
    model_version: str
    model_name: str
    scan_id: int | None = None


class ScanHistoryItem(BaseModel):
    id: int
    url: str
    normalized_url: str
    url_hash: str
    prediction: str
    confidence: float
    risk_score: int
    probability_phishing: float
    model_name: str
    model_version: str
    created_at: datetime


class ScanHistoryResponse(BaseModel):
    items: list[ScanHistoryItem]
    total: int
    page: int
    page_size: int
    pages: int


class PredictionCounts(BaseModel):
    """Scan totals per verdict, aggregated over the whole history."""

    LEGITIMATE: int
    SUSPICIOUS: int
    PHISHING: int


class RiskBands(BaseModel):
    """Scan totals per risk-score band; the three sum to the table total."""

    low: int  # 0-34
    medium: int  # 35-74
    high: int  # 75-100


class ScanHistoryStatsResponse(BaseModel):
    total: int
    counts: PredictionCounts
    risk_bands: RiskBands


class HealthResponse(BaseModel):
    status: str
    model_loaded: bool
    database: str
    environment: str


class ModelInfoResponse(BaseModel):
    model_name: str
    model_version: str
    trained_at: str
    dataset: dict
    metrics: dict
    comparison: list[dict]
    thresholds: dict
    feature_names: list[str]
    global_feature_importance: list[dict] = []
    history: dict
