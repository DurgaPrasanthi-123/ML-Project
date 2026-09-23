"""
Inference engine: loads the trained bundle once, exposes a single
`analyze_url()` used by the API. Owns thresholding, guardrail fusion,
risk scoring, and explanation assembly.
"""

from __future__ import annotations

import logging
import threading
from pathlib import Path

import numpy as np

from app.config import get_settings
from app.core import features as feature_module
from app.core.explain import top_contributions
from app.core.url_parser import is_ssrf_target, normalize_url, parse_url  # noqa: F401 (parse_url re-exported for tests)

logger = logging.getLogger("app.inference")


class InferenceEngine:
    """Thread-safe singleton wrapper around the serialized model bundle."""

    _instance: "InferenceEngine | None" = None
    _lock = threading.Lock()

    def __init__(self) -> None:
        self.bundle: dict | None = None
        self._load_lock = threading.Lock()

    @classmethod
    def instance(cls) -> "InferenceEngine":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    # ------------------------------------------------------------------ #
    # Model loading
    # ------------------------------------------------------------------ #
    def load(self) -> bool:
        """Load the bundle; returns True when a model is ready to serve."""
        with self._load_lock:
            settings = get_settings()
            path: Path = settings.model_bundle_path
            if not path.exists():
                logger.error("Model bundle not found at %s", path)
                self.bundle = None
                return False
            import joblib

            self.bundle = joblib.load(path)
            logger.info(
                "Model bundle loaded: %s v%s (features=%d)",
                self.bundle.get("best_model", "?"),
                self.bundle.get("model_version", "?"),
                len(self.bundle.get("feature_names", [])),
            )
            return True

    @property
    def is_ready(self) -> bool:
        return self.bundle is not None

    # ------------------------------------------------------------------ #
    # Prediction
    # ------------------------------------------------------------------ #
    def analyze_url(self, raw_url: str) -> dict:
        """
        Full analysis for one URL. Raises ValueError on structurally invalid
        or SSRF-targeting input (caller maps to HTTP 400/422).
        """
        if not self.is_ready:
            raise RuntimeError("Model is not loaded")

        settings = get_settings()
        normalized = normalize_url(raw_url)
        p = parse_url(normalized, strict=True)
        if p.parse_error:
            raise ValueError(f"invalid_url: {p.parse_error}")
        if is_ssrf_target(p):
            raise ValueError("ssrf_target: private, reserved, or internal addresses cannot be analyzed")

        # DNS existence (explicit, mockable side-effect)
        dns_exists: int | None = None
        if settings.dns_check_enabled and not p.is_ip:
            from app.core.dns_verifier import cached_domain_exists

            res = cached_domain_exists(p.hostname, settings.dns_timeout_seconds)
            dns_exists = None if res["exists"] is None else int(res["exists"])

        # Guardrail fusion (pattern classes only; never URL-specific). Runs
        # BEFORE feature building so its flag count enters the feature vector
        # (at training time every row has 0 flags — the same builder, no flags).
        guard = {"flags": [], "boost": 0.0, "impersonation": {}, "dns": {}}
        if settings.brand_impersonation_enabled or settings.dns_check_enabled:
            from app.core.guardrails import evaluate_guardrails

            guard = evaluate_guardrails(
                normalized, dns_check_enabled=settings.dns_check_enabled
            )

        # Features (identical builder to training) and model probability.
        # The named DataFrame preserves sklearn feature names end-to-end and
        # keeps the model's fitted-name validation quiet and meaningful.
        fv = feature_module.extract_features(
            normalized,
            dns_exists=dns_exists,
            guardrail_flag_count=len(guard["flags"]),
        )
        import pandas as pd

        names = self.bundle["feature_names"]
        X = pd.DataFrame([[fv[n] for n in names]], columns=names)

        model = self.bundle["model"]
        proba = float(model.predict_proba(X)[0][1])
        if guard["boost"] > 0:
            proba = max(proba, guard["boost"])

        # Thresholding -> three-class verdict
        if proba >= settings.phishing_threshold:
            prediction = "PHISHING"
        elif proba >= settings.suspicious_threshold:
            prediction = "SUSPICIOUS"
        else:
            prediction = "LEGITIMATE"

        confidence = round(proba * 100, 2) if prediction == "PHISHING" else round((1 - proba) * 100, 2)
        risk_score = int(round(proba * 100))

        contributions = top_contributions(model, [fv[n] for n in names], names)

        return {
            "url": raw_url,
            "normalized_url": normalized,
            "prediction": prediction,
            "confidence": confidence,
            "risk_score": risk_score,
            "probability_phishing": round(proba, 4),
            "risk_level": prediction.title() if prediction != "SUSPICIOUS" else "Medium",
            "contributing_features": contributions,
            "guardrail_flags": guard["flags"],
            "dns_check": {"checked": guard["dns"].get("checked", False),
                          "exists": guard["dns"].get("exists")},
            "model_version": self.bundle.get("model_version", "unknown"),
            "model_name": self.bundle.get("best_model", "unknown"),
        }
