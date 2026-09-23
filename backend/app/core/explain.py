"""
Per-feature explanations for the served model.

Two model families, one contract — top_contributions() returns the top-k
signed contributions pushing the verdict toward PHISHING (positive) or
LEGITIMATE (negative), most influential first:

- Tree ensembles (Random Forest, XGBoost): SHAP TreeExplainer values.
- Linear models (Logistic Regression, optionally behind a StandardScaler
  Pipeline): coef_j * x_j (or coef_j * (x_j - mean) / scale_j when scaled).
  This is exactly the SHAP LinearExplainer decomposition for a linear model
  — same additive attribution, computed without building an explainer.

Explanation failures are logged and degraded to an empty list: explainability
must never break serving.
"""

from __future__ import annotations

import logging
from threading import Lock

logger = logging.getLogger("app.explain")

_lock = Lock()
_explainer_cache: dict[int, object] = {}


def _tree_explainer(model):
    import shap

    with _lock:
        key = id(model)
        if key not in _explainer_cache:
            _explainer_cache[key] = shap.TreeExplainer(model)
        return _explainer_cache[key]


def _final_estimator(model):
    """Final estimator of a sklearn Pipeline, or the model itself."""
    if hasattr(model, "named_steps") and len(model.named_steps):
        return list(model.named_steps.values())[-1]
    return model


def _tree_pairs(model, X, feature_names: list[str]) -> list[tuple[str, float]]:
    """SHAP TreeExplainer contributions as (name, value) pairs."""
    explainer = _tree_explainer(model)
    shap_values = explainer.shap_values(X)

    # xgboost binary:logistic shap returns (n, features); some versions
    # return a list per class or (n, features, 2).
    if isinstance(shap_values, list):
        sv = shap_values[-1][0]
    else:
        arr = shap_values[0]
        sv = arr[:, -1] if arr.ndim == 2 and arr.shape[-1] == 2 and arr.shape[0] == arr.shape[1] else arr
    if hasattr(sv, "ndim") and sv.ndim > 1:
        sv = sv.reshape(sv.shape[0], -1)[:, -1] if sv.shape[-1] > 1 else sv.ravel()

    return list(zip(feature_names, (float(v) for v in sv)))


def _linear_pairs(model, X, feature_names: list[str]) -> list[tuple[str, float]]:
    """Signed linear-model contributions: coef_j * transformed_x_j.

    Handles a StandardScaler-in-Pipeline by attributing against the
    standardized input (mean/scale taken from the fitted scaler).
    """
    import numpy as np

    scaler = None
    clf = model
    if hasattr(model, "named_steps"):
        for step in model.named_steps.values():
            if hasattr(step, "mean_") and hasattr(step, "scale_"):
                scaler = step
        clf = _final_estimator(model)

    coef = np.asarray(clf.coef_, dtype=float).ravel()
    x = X[0]
    if scaler is not None:
        scale = np.where(np.asarray(scaler.scale_) == 0, 1.0, np.asarray(scaler.scale_))
        contrib = coef * (x - np.asarray(scaler.mean_)) / scale
    else:
        contrib = coef * x
    return list(zip(feature_names, (float(v) for v in contrib)))


def top_contributions(model, feature_vector, feature_names: list[str], top_k: int = 8) -> list[dict]:
    """Top-k signed contributions, most influential first."""
    try:
        import numpy as np

        X = np.asarray([feature_vector], dtype=float)
        final = _final_estimator(model)
        if hasattr(final, "coef_"):
            pairs = _linear_pairs(model, X, feature_names)
        else:
            pairs = _tree_pairs(model, X, feature_names)

        pairs.sort(key=lambda t: abs(t[1]), reverse=True)
        return [
            {"feature": name, "impact": round(value, 4),
             "direction": "phishing" if value > 0 else "legitimate"}
            for name, value in pairs[:top_k]
        ]
    except Exception as exc:  # noqa: BLE001 - explainability must never break serving
        logger.warning("Contribution computation failed (non-fatal): %s", exc)
        return []
