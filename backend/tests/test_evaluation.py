"""
Unit tests for backend/evaluation/metrics.py.

Pure in-memory checks of the metric suite, threshold picking, ROC export,
and degenerate-input handling. No model training involved.
"""

from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pytest

BACKEND_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_DIR))

from evaluation.metrics import (  # noqa: E402
    binary_metrics,
    pick_threshold_for_target_recall,
    roc_curve_points,
    sweep_thresholds,
)


def test_perfect_classifier():
    y = [0, 0, 0, 1, 1, 1]
    p = [0.05, 0.1, 0.2, 0.8, 0.9, 0.95]
    m = binary_metrics(y, p, threshold=0.5)
    assert m["accuracy"] == 1.0
    assert m["precision"] == 1.0
    assert m["recall"] == 1.0
    assert m["f1_score"] == 1.0
    assert m["confusion_matrix"] == {"tn": 3, "fp": 0, "fn": 0, "tp": 3}
    assert m["roc_auc"] == 1.0
    assert m["pr_auc"] == 1.0


def test_known_confusion_matrix_and_metrics():
    # threshold 0.5 -> preds [1,1,1,1,1,0,0,0,0,0]
    y = [1, 1, 1, 1, 1, 0, 0, 0, 0, 0]
    p = [0.9, 0.8, 0.7, 0.6, 0.55, 0.45, 0.4, 0.3, 0.2, 0.1]
    m = binary_metrics(y, p, threshold=0.5)
    assert m["confusion_matrix"] == {"tn": 5, "fp": 0, "fn": 0, "tp": 5}
    assert m["accuracy"] == 1.0


def test_precision_recall_arithmetic():
    y = [0, 0, 0, 0, 1, 1, 1, 1, 1, 1]
    p = [0.9, 0.8, 0.3, 0.2, 0.7, 0.6, 0.5, 0.4, 0.1, 0.05]
    m = binary_metrics(y, p, threshold=0.5)
    # pred=1: idx 0,1 (both 0), 4,5,6 -> tp=3, fp=2, fn=3, tn=2
    assert m["confusion_matrix"] == {"tn": 2, "fp": 2, "fn": 3, "tp": 3}
    assert m["precision"] == pytest.approx(3 / 5)
    assert m["recall"] == pytest.approx(3 / 6)
    assert m["f1_score"] == pytest.approx(2 * (0.6 * 0.5) / (0.6 + 0.5), abs=1e-3)


def test_roc_auc_ordering_invariance_and_range():
    y = [0, 0, 1, 1]
    m1 = binary_metrics(y, [0.1, 0.2, 0.8, 0.9])
    m2 = binary_metrics(y, [0.11, 0.21, 0.81, 0.91])
    assert m1["roc_auc"] == m2["roc_auc"] == 1.0
    m3 = binary_metrics(y, [0.9, 0.8, 0.2, 0.1])  # fully inverted
    assert m3["roc_auc"] == 0.0


def test_single_class_y_true_returns_none_aucs():
    m = binary_metrics([1, 1, 1], [0.9, 0.8, 0.7])
    assert m["roc_auc"] is None
    assert m["pr_auc"] is None
    assert m["accuracy"] == 1.0  # thresholded metrics still fine


def test_pick_threshold_for_target_recall():
    y = [0] * 50 + [1] * 50
    rng = np.random.RandomState(0)
    p = np.where(y, np.clip(rng.beta(8, 2, 100), 0, 1), np.clip(rng.beta(2, 8, 100), 0, 1))
    thr = pick_threshold_for_target_recall(y, p, target_recall=0.98)
    pred = (np.asarray(p) >= thr).astype(int)
    rec = (pred & np.asarray(y)).sum() / sum(y)
    assert rec >= 0.98, f"picked threshold {thr} missed the recall target"


def test_pick_threshold_falls_back_when_unreachable():
    y = [0, 0, 0, 1, 1, 1]
    p = [0.9, 0.8, 0.7, 0.4, 0.3, 0.2]  # best recall = 1.0 at t <= 0.2
    thr = pick_threshold_for_target_recall(y, p, target_recall=0.999,
                                           grid=np.linspace(0.0, 1.0, 101))
    pred = (np.asarray(p) >= thr).astype(int)
    assert ((pred == 1) | (np.asarray(y) == 0)).all(), "must reach full recall"


def test_roc_curve_points_shape_and_bounds():
    y = [0] * 20 + [1] * 20
    p = list(np.linspace(0.01, 0.5, 20)) + list(np.linspace(0.5, 0.99, 20))
    pts = roc_curve_points(y, p, max_points=10)
    assert 0 < len(pts) <= 10
    for pt in pts:
        assert 0.0 <= pt["fpr"] <= 1.0
        assert 0.0 <= pt["tpr"] <= 1.0
    assert roc_curve_points([1, 1], [0.9, 0.8]) == []  # degenerate


def test_sweep_thresholds_rows():
    y = [0, 0, 1, 1]
    rows = sweep_thresholds(y, [0.2, 0.4, 0.6, 0.8], [0.3, 0.5, 0.7])
    assert [r["threshold"] for r in rows] == [0.3, 0.5, 0.7]
    assert rows[2]["recall"] == pytest.approx(0.5)  # at 0.7 only the 0.8 positive fires
    assert all({"accuracy", "precision", "recall", "f1_score"} <= set(r) for r in rows)
