"""
Model evaluation helpers shared by the training pipeline and reports.

All metrics treat class 1 as the positive (phishing) class and consume
model PROBABILITIES (predict_proba[:, 1]) so that threshold-dependent
metrics (precision/recall/F1/confusion matrix) and threshold-free ones
(ROC-AUC, PR-AUC) are computed consistently.

Degenerate inputs (single-class y_true) return None for AUCs instead of
raising — evaluation must never crash on edge-case folds.
"""

from __future__ import annotations

from typing import Sequence

import math

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)


def binary_metrics(y_true, proba, threshold: float = 0.5) -> dict:
    """Full metric suite for a binary classifier at one operating threshold.

    y_true: labels with 1 = phishing (positive class).
    proba:  predicted probability of the positive class.
    """
    y_true = np.asarray(y_true).astype(int)
    p = np.asarray(proba, dtype=float)
    pred = (p >= threshold).astype(int)

    tn, fp, fn, tp = confusion_matrix(y_true, pred, labels=[0, 1]).ravel()
    return {
        "threshold": round(float(threshold), 4),
        "accuracy": round(float(accuracy_score(y_true, pred)), 4),
        "precision": round(float(precision_score(y_true, pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y_true, pred, zero_division=0)), 4),
        "f1_score": round(float(f1_score(y_true, pred, zero_division=0)), 4),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        **(
            {"roc_auc": _auc_or_none(roc_auc_score, y_true, p),
             "pr_auc": _auc_or_none(average_precision_score, y_true, p)}
            if len(np.unique(y_true)) >= 2
            else {"roc_auc": None, "pr_auc": None}  # AUCs undefined for one class
        ),
    }


def _auc_or_none(scorer, y_true, p):
    try:
        val = float(scorer(y_true, p))
    except ValueError:  # single-class y_true
        return None
    return None if math.isnan(val) else round(val, 4)


def pick_threshold_for_target_recall(
    y_true, proba, target_recall: float = 0.95, grid=None
) -> float:
    """
    Highest threshold whose recall >= target_recall (tie-break: best F1).
    Phishing triage wants to miss as few phishes as possible, so we anchor on
    recall and let precision follow. Falls back to 0.5 when the target is
    unreachable on the score distribution.
    """
    y_true = np.asarray(y_true).astype(int)
    p = np.asarray(proba, dtype=float)
    if len(np.unique(y_true)) < 2:
        return 0.5
    prec, rec, thr = precision_recall_curve(y_true, p)
    if grid is None:
        grid = thr
    best_thr, best_f1 = 0.5, -1.0
    for t in grid:
        pred = (p >= t).astype(int)
        r = recall_score(y_true, pred, zero_division=0)
        if r < target_recall:
            continue
        f1 = f1_score(y_true, pred, zero_division=0)
        if r >= 0 and (f1 > best_f1 or (f1 == best_f1 and t > best_thr)):
            best_thr, best_f1 = float(t), f1
    return best_thr


def roc_curve_points(y_true, proba, max_points: int = 200) -> list[dict]:
    """Downsampled ROC curve for reports (fpr/tpr/threshold)."""
    y_true = np.asarray(y_true).astype(int)
    p = np.asarray(proba, dtype=float)
    if len(np.unique(y_true)) < 2:
        return []
    try:
        fpr, tpr, thr = roc_curve(y_true, p)
    except ValueError:
        return []
    idx = np.linspace(0, len(fpr) - 1, min(max_points, len(fpr))).astype(int)
    return [
        {"fpr": round(float(fpr[i]), 4), "tpr": round(float(tpr[i]), 4),
         "threshold": round(float(thr[i]), 4)}
        for i in idx
    ]


def sweep_thresholds(y_true, proba, thresholds: Sequence[float]) -> list[dict]:
    """Metric rows across thresholds (for the validation sweep report)."""
    y_true = np.asarray(y_true).astype(int)
    p = np.asarray(proba, dtype=float)
    rows = []
    for t in thresholds:
        pred = (p >= t).astype(int)
        rows.append({
            "threshold": round(float(t), 4),
            "accuracy": round(float(accuracy_score(y_true, pred)), 4),
            "precision": round(float(precision_score(y_true, pred, zero_division=0)), 4),
            "recall": round(float(recall_score(y_true, pred, zero_division=0)), 4),
            "f1_score": round(float(f1_score(y_true, pred, zero_division=0)), 4),
        })
    return rows
