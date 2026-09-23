"""
Training pipeline: Logistic Regression vs Random Forest vs XGBoost.

Protocol (leakage-safe by construction):
  1. FIT on the TRAINING split only.
  2. TUNE/SELECT on the VALIDATION split only — per-model threshold sweep,
     recall-anchored operating point, and model selection by documented
     validation metrics.
  3. The TEST split is evaluated exactly ONCE, after the winner is frozen.

Class imbalance: class_weight="balanced" (LR/RF) and scale_pos_weight
(XGBoost) computed from the training split only.

Uses the SAME feature builder as the inference service (app.core.features)
— the training/serving contract. DNS lookups are disabled during bulk
training (dns_exists=0.5 neutral; guardrail_flag_count=0), so training needs
no network while serving adds that evidence at inference time.

Artifacts (all under backend/):
  models/            model.pkl, metadata.json, preprocessing.pkl per model
  evaluation/        validation/test metric JSONs (incl. threshold sweeps, ROC)
  reports/           comparison.json, training_report.md
  artifacts/         model_bundle.joblib (single serving bundle for the API)
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier

BACKEND_DIR = Path(__file__).resolve().parent.parent
ROOT_DIR = BACKEND_DIR.parent
sys.path.insert(0, str(BACKEND_DIR))

from app.core import features as feature_module  # noqa: E402
from evaluation.metrics import (  # noqa: E402
    binary_metrics,
    pick_threshold_for_target_recall,
    roc_curve_points,
    sweep_thresholds,
)

# --------------------------------------------------------------------------- #
# Configuration (documented, reproducible)
# --------------------------------------------------------------------------- #
PROCESSED_DIR = ROOT_DIR / "data" / "processed"           # small/smoke splits
PHIUSIIL_DIR = ROOT_DIR / "data" / "phiusiil_processed"   # real PhiUSIIL splits
COMBINED_DIR = ROOT_DIR / "data" / "combined"             # PhiUSIIL + synthetic merge
ARTIFACTS = BACKEND_DIR / "artifacts"
MODELS_DIR = BACKEND_DIR / "models"
EVALUATION_DIR = BACKEND_DIR / "evaluation"
REPORTS_DIR = BACKEND_DIR / "reports"

MODEL_VERSION = "3.0.0"
RANDOM_STATE = 42
TARGET_RECALL = 0.95          # operating-point anchor on validation
GRID = np.round(np.arange(0.05, 0.96, 0.05), 2)  # threshold sweep grid

# Source-label -> binary target. Anything else (e.g. "suspicious") is dropped
# and reported: SUSPICIOUS is a threshold decision, not a third trained class.
LABEL_MAP: dict[str, int] = {
    "legitimate": 0, "0": 0, "0.0": 0,
    "phishing": 1, "1": 1, "1.0": 1,
}
SPLIT_FILES = ("train.csv", "validation.csv", "test.csv")


def resolve_split_dir() -> Path:
    """Combined PhiUSIIL+synthetic splits when present, else per-source splits.

    The combined directory is preferred: PhiUSIIL alone contains almost no
    legitimate deep links (its legit class is bare homepages), which teaches
    every model 'has path => phishing'. The merged splits restore realistic
    legitimate URL shapes while keeping PhiUSIIL's phishing diversity.
    """
    if all((COMBINED_DIR / f).exists() for f in SPLIT_FILES):
        return COMBINED_DIR
    if all((PHIUSIIL_DIR / f).exists() for f in SPLIT_FILES):
        return PHIUSIIL_DIR
    if all((PROCESSED_DIR / f).exists() for f in SPLIT_FILES):
        return PROCESSED_DIR
    raise SystemExit(
        "[ERROR] No prepared splits found. Run data/prepare_dataset.py first "
        "(outputs data/processed/ and/or data/phiusiil_processed/), then "
        "data/merge_datasets.py to build data/combined/."
    )


def to_binary_labels(df: pd.DataFrame, split_name: str) -> pd.DataFrame:
    """Map source labels to 0/1; drop and report anything else."""
    raw = df["label"].astype(str).str.strip().str.lower()
    mapped = raw.map(LABEL_MAP)
    dropped = int(mapped.isna().sum())
    if dropped:
        print(f"[WARN] {split_name}: dropping {dropped} rows with non-binary labels "
              f"(e.g. suspicious={int((raw == 'suspicious').sum())}) — "
              f"SUSPICIOUS is a threshold decision, not a third trained class.")
    out = df.loc[mapped.notna()].copy()
    out["label"] = mapped.loc[mapped.notna()].astype(int)
    return out


def build_feature_matrix(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.Series]:
    """Feature matrix via the SHARED builder (no network, neutral meta)."""
    print(f"[INFO] Extracting features for {len(df):,} rows with the shared builder...")
    X = feature_module.extract_features_dataframe(df["url"].astype(str), dns_exists=None)
    y = df["label"].astype(int)
    return X, y


def global_shap_importance(model, X_val: pd.DataFrame, max_rows: int = 3000) -> list[dict]:
    """
    Global feature importance via SHAP: mean(|SHAP value|) per feature over a
    validation subsample (the model never saw these rows for fitting; using
    validation — not test — keeps test fully isolated for final evaluation).
    Returns the full ranked list, most important first.
    """
    import shap

    sub = X_val.sample(n=min(max_rows, len(X_val)), random_state=RANDOM_STATE)
    try:
        explainer = shap.TreeExplainer(model)
        sv = explainer.shap_values(sub)
        if isinstance(sv, list):          # per-class list -> positive class
            sv = sv[-1]
        arr = np.asarray(sv)
        if arr.ndim == 3:                 # (n, features, classes)
            arr = arr[:, :, -1]
        mean_abs = np.abs(arr).mean(axis=0)
    except Exception as exc:  # noqa: BLE001 - reporting must not break training
        print(f"[WARN] global SHAP importance failed (non-fatal): {exc}")
        return []
    ranked = sorted(zip(X_val.columns, (float(v) for v in mean_abs)),
                    key=lambda t: t[1], reverse=True)
    return [{"feature": name, "mean_abs_shap": round(v, 6)} for name, v in ranked]


def main() -> None:
    split_dir = resolve_split_dir()
    train_df = to_binary_labels(pd.read_csv(split_dir / "train.csv"), "train")
    val_df = to_binary_labels(pd.read_csv(split_dir / "validation.csv"), "validation")
    test_df = to_binary_labels(pd.read_csv(split_dir / "test.csv"), "test")

    X_train, y_train = build_feature_matrix(train_df)
    X_val, y_val = build_feature_matrix(val_df)
    X_test, y_test = build_feature_matrix(test_df)
    feature_names = list(X_train.columns)
    print(f"[INFO] train={len(X_train):,}  validation={len(X_val):,}  test={len(X_test):,}  "
          f"features={len(feature_names)}  (splits: {split_dir.name})")

    # ---- class imbalance handling (training split only) -------------------- #
    n_pos = int((y_train == 1).sum())
    n_neg = int((y_train == 0).sum())
    spw = n_neg / max(n_pos, 1)
    print(f"[INFO] imbalance: negatives={n_neg:,} positives={n_pos:,} "
          f"-> scale_pos_weight={spw:.3f}")

    candidates = {
        "Logistic Regression": Pipeline([
            ("scaler", StandardScaler()),
            ("clf", LogisticRegression(
                max_iter=2000, random_state=RANDOM_STATE,
                class_weight="balanced",
            )),
        ]),
        "Random Forest": RandomForestClassifier(
            n_estimators=200, max_depth=18, random_state=RANDOM_STATE, n_jobs=-1,
            class_weight="balanced_subsample",
        ),
        "XGBoost": XGBClassifier(
            n_estimators=300, max_depth=6, learning_rate=0.15,
            subsample=0.9, colsample_bytree=0.9, eval_metric="logloss",
            random_state=RANDOM_STATE, n_jobs=-1,
            scale_pos_weight=spw,
        ),
    }

    MODELS_DIR.mkdir(exist_ok=True)
    EVALUATION_DIR.mkdir(exist_ok=True)
    REPORTS_DIR.mkdir(exist_ok=True)

    # ------------------ fit on TRAIN, tune on VALIDATION -------------------- #
    validation_results: list[dict] = []
    fitted: dict[str, object] = {}
    for name, model in candidates.items():
        print(f"[FIT] {name} (training split only)...")
        model.fit(X_train, y_train)
        fitted[name] = model

        val_proba = model.predict_proba(X_val)[:, 1]
        sweep = sweep_thresholds(y_val, val_proba, GRID)
        threshold = pick_threshold_for_target_recall(y_val, val_proba, TARGET_RECALL, grid=GRID)
        val_at_thr = binary_metrics(y_val, val_proba, threshold=threshold)
        validation_results.append({
            "model": name, "threshold": threshold,
            "validation": {**val_at_thr, "threshold_sweep": sweep},
        })
        print(f"      val@{threshold:.2f}: recall={val_at_thr['recall']:.4f} "
              f"precision={val_at_thr['precision']:.4f} f1={val_at_thr['f1_score']:.4f} "
              f"auc={val_at_thr['roc_auc']}")

    # ---- model selection: documented, validation-only ----------------------- #
    # Anchor on phishing RECALL at the recall-target threshold (primary),
    # tie-break on precision, then F1, then ROC-AUC.
    def selection_key(r: dict):
        v = r["validation"]
        return (v["recall"], v["precision"], v["f1_score"], v["roc_auc"] or 0.0)

    winner = max(validation_results, key=selection_key)
    print(f"\n[SELECTED] {winner['model']}  (validation "
          f"recall={winner['validation']['recall']:.4f} @ thr {winner['threshold']:.2f})")

    # ------------------ one-shot TEST evaluation ------------------------------ #
    test_results = []
    for r in validation_results:
        name = r["model"]
        proba = fitted[name].predict_proba(X_test)[:, 1]
        m = binary_metrics(y_test, proba, threshold=r["threshold"])
        test_results.append({
            "model": name,
            "threshold": r["threshold"],
            "metrics": m,
            "roc_curve": roc_curve_points(y_test, proba),
        })
        print(f"[TEST] {name}: acc={m['accuracy']:.4f} P={m['precision']:.4f} "
              f"R={m['recall']:.4f} F1={m['f1_score']:.4f} AUC={m['roc_auc']}")

    final = next(r for r in test_results if r["model"] == winner["model"])
    fm = final["metrics"]

    # ------------------ real-world-only test evaluation ----------------------- #
    # The combined test set mixes real (PhiUSIIL) and synthetic rows. When the
    # split carries per-row provenance, report the selected model's metrics on
    # the REAL subset separately — the honest estimate of production behavior.
    real_only_metrics = None
    if "source" in test_df.columns:
        real_mask = (test_df["source"].astype(str).str.lower() != "synthetic").to_numpy()
        if 0 < int(real_mask.sum()) < len(real_mask):
            w_proba = fitted[winner["model"]].predict_proba(X_test)[:, 1]
            real_only_metrics = binary_metrics(
                np.asarray(y_test)[real_mask], w_proba[real_mask],
                threshold=winner["threshold"],
            )
            print(f"[TEST][real-only] {winner['model']}: acc={real_only_metrics['accuracy']:.4f} "
                  f"P={real_only_metrics['precision']:.4f} R={real_only_metrics['recall']:.4f} "
                  f"F1={real_only_metrics['f1_score']:.4f} AUC={real_only_metrics['roc_auc']} "
                  f"CM={real_only_metrics['confusion_matrix']}")

    # Global SHAP importance of the selected model (validation subsample)
    global_importance = global_shap_importance(fitted[winner["model"]], X_val)
    if global_importance:
        print("[SHAP] top global drivers: "
              + ", ".join(f"{g['feature']}={g['mean_abs_shap']:.3f}"
                          for g in global_importance[:5]))

    # ------------------ persist everything ------------------------------------ #
    for name, model in fitted.items():
        slug = name.lower().replace(" ", "_")
        joblib.dump(model, MODELS_DIR / f"{slug}.pkl")
        meta = {
            "model_name": name,
            "model_version": MODEL_VERSION,
            "trained_at": datetime.now(timezone.utc).isoformat(),
            "random_state": RANDOM_STATE,
            "feature_names": feature_names,
            "label_encoder": {"0": "legitimate", "1": "phishing"},
            "preprocessing": ("StandardScaler -> LogisticRegression (class_weight=balanced)"
                              if name == "Logistic Regression" else
                              "class_weight=balanced_subsample" if name == "Random Forest"
                              else f"scale_pos_weight={spw:.4f}"),
            "selected_threshold": next(r["threshold"] for r in validation_results
                                       if r["model"] == name),
            "dataset": {
                "splits_dir": str(split_dir),
                "train_rows": int(len(X_train)),
                "validation_rows": int(len(X_val)),
                "test_rows": int(len(X_test)),
                "n_features": len(feature_names),
            },
        }
        with open(MODELS_DIR / f"{slug}_metadata.json", "w") as f:
            json.dump(meta, f, indent=2)

    # preprocessing artifact: the fitted scaler (LR also carries it in-Pipeline)
    joblib.dump(fitted["Logistic Regression"].named_steps["scaler"],
                MODELS_DIR / "preprocessing.pkl")

    with open(EVALUATION_DIR / "validation_metrics.json", "w") as f:
        json.dump(validation_results, f, indent=2)
    with open(EVALUATION_DIR / "test_metrics.json", "w") as f:
        json.dump(test_results, f, indent=2)

    comparison = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "model_version": MODEL_VERSION,
        "protocol": {
            "fit_split": "train",
            "selection_split": "validation",
            "test_evaluation": "one-shot after selection",
            "target_recall": TARGET_RECALL,
            "random_state": RANDOM_STATE,
            "imbalance": {
                "logistic_regression": "class_weight=balanced",
                "random_forest": "class_weight=balanced_subsample",
                "xgboost": f"scale_pos_weight={spw:.4f}",
            },
        },
        "validation": [
            {"model": r["model"], "threshold": r["threshold"],
             **{k: r["validation"][k] for k in
                ("accuracy", "precision", "recall", "f1_score", "roc_auc", "pr_auc",
                 "confusion_matrix")}}
            for r in validation_results
        ],
        "test": [
            {"model": r["model"], "threshold": r["threshold"], **r["metrics"]}
            for r in test_results
        ],
        "selection_rule": ("max validation recall at the recall-target threshold; "
                           "tie-break precision, then F1, then ROC-AUC"),
        "selected_model": winner["model"],
        "selected_threshold": winner["threshold"],
    }
    comparison["real_world_only_metrics"] = real_only_metrics
    with open(REPORTS_DIR / "comparison.json", "w") as f:
        json.dump(comparison, f, indent=2)

    # ------------------ serving bundle (API contract) -------------------------- #
    ARTIFACTS.mkdir(exist_ok=True)
    bundle = {
        "model": fitted[winner["model"]],
        "best_model": winner["model"],
        "model_version": MODEL_VERSION,
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "feature_names": feature_names,
        "preprocessing": ("StandardScaler inside Pipeline"
                          if winner["model"] == "Logistic Regression"
                          else "none (tree model)"),
        "dataset": {
            "total": int(len(X_train) + len(X_val) + len(X_test)),
            "train": int(len(X_train)),
            "test": int(len(X_test)),
            "legitimate": int((y_train == 0).sum() + (y_val == 0).sum() + (y_test == 0).sum()),
            "phishing": int((y_train == 1).sum() + (y_val == 1).sum() + (y_test == 1).sum()),
            "n_features": len(feature_names),
            "splits_dir": str(split_dir),
        },
        "metrics": {**fm, "name": winner["model"]},
        "comparison": [{"model": r["model"], **r["metrics"]} for r in test_results],
        "real_world_only_metrics": real_only_metrics,
        "selection": {
            "split": "validation",
            "rule": comparison["selection_rule"],
            "target_recall": TARGET_RECALL,
            "validation_recall": winner["validation"]["recall"],
            "validation_precision": winner["validation"]["precision"],
        },
        "operating_threshold": winner["threshold"],
        "global_feature_importance": global_importance,
    }
    joblib.dump(bundle, ARTIFACTS / "model_bundle.joblib")

    # ------------------ serving-bundle snapshot (model_metrics.json) ----------- #
    # Kept in lockstep with the bundle: same keys, same confusion-matrix format,
    # same selection info. /model-info serves the joblib bundle; this JSON is a
    # human-readable snapshot for reports/CI (a full-bundle load is not needed).
    metrics_snapshot = {
        "best_model": bundle["best_model"],
        "model_version": bundle["model_version"],
        "trained_at": bundle["trained_at"],
        "feature_names": feature_names,
        "preprocessing": bundle["preprocessing"],
        "dataset": bundle["dataset"],
        "metrics": bundle["metrics"],
        "comparison": bundle["comparison"],
        "real_world_only_metrics": real_only_metrics,
        "selection": {
            "split": "validation",
            "rule": comparison["selection_rule"],
            "target_recall": TARGET_RECALL,
            "validation_recall": winner["validation"]["recall"],
            "validation_precision": winner["validation"]["precision"],
            "selected_threshold": winner["threshold"],
        },
    }
    with open(ARTIFACTS / "model_metrics.json", "w") as f:
        json.dump(metrics_snapshot, f, indent=2)

    # Standalone copy for reports (kept next to the other evaluation JSONs)
    with open(REPORTS_DIR / "global_feature_importance.json", "w") as f:
        json.dump({"model": winner["model"], "importance": global_importance}, f, indent=2)

    # ------------------ human-readable report ---------------------------------- #
    vr = {r["model"]: r["validation"] for r in validation_results}
    tm = {r["model"]: r["metrics"] for r in test_results}
    thr = {r["model"]: r["threshold"] for r in validation_results}
    lines = [
        "# Training Report", "",
        f"- Generated: {comparison['generated_at']}",
        f"- Data: `{split_dir}` — train {len(X_train):,} / validation {len(X_val):,} / "
        f"test {len(X_test):,}, {len(feature_names)} features (shared builder, no network)",
        f"- Protocol: fit=train, select=validation (target recall {TARGET_RECALL:.0%}), "
        f"test evaluated once after selection; random_state={RANDOM_STATE}",
        f"- Imbalance: LR `class_weight=balanced`, RF `balanced_subsample`, "
        f"XGBoost `scale_pos_weight={spw:.3f}`", "",
        "## Model comparison", "",
        "| Model | thr | val R | val P | val F1 | val AUC | test acc | test P | test R | test F1 | test AUC |",
        "|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for name in candidates:
        v, t = vr[name], tm[name]
        lines.append(
            f"| {name} | {thr[name]:.2f} | {v['recall']:.4f} | {v['precision']:.4f} | "
            f"{v['f1_score']:.4f} | {v['roc_auc'] if v['roc_auc'] is not None else 'n/a'} | "
            f"{t['accuracy']:.4f} | {t['precision']:.4f} | {t['recall']:.4f} | "
            f"{t['f1_score']:.4f} | {t['roc_auc'] if t['roc_auc'] is not None else 'n/a'} |"
        )
    cm = fm["confusion_matrix"]
    shap_lines = []
    if global_importance:
        shap_lines = ["", "## Global feature importance (mean |SHAP|, validation subsample)", "",
                      "| Rank | Feature | mean \u2502SHAP\u2502 |", "|---|---|---|"]
        shap_lines += [f"| {i + 1} | {g['feature']} | {g['mean_abs_shap']:.4f} |"
                       for i, g in enumerate(global_importance[:15])]
    lines += [
        "", f"## Selected model: {winner['model']}", "",
        f"Chosen by validation recall at the recall-target operating point "
        f"(ties broken by precision, F1, AUC). Test confusion matrix at the "
        f"selected threshold {final['threshold']:.2f}:",
        "", "| | pred legit | pred phish |", "|---|---|---|",
        f"| **actual legit** | {cm['tn']} | {cm['fp']} |",
        f"| **actual phish** | {cm['fn']} | {cm['tp']} |", "",
        "Artifacts: `backend/models/`, `backend/evaluation/`, `backend/reports/`, "
        "serving bundle `backend/artifacts/model_bundle.joblib`.",
    ]
    if real_only_metrics:
        cm_r = real_only_metrics["confusion_matrix"]
        lines += ["", "## Real-world-only test metrics (non-synthetic rows)", "",
                  f"acc={real_only_metrics['accuracy']:.4f} P={real_only_metrics['precision']:.4f} "
                  f"R={real_only_metrics['recall']:.4f} F1={real_only_metrics['f1_score']:.4f} "
                  f"AUC={real_only_metrics['roc_auc']}", "",
                  "| | pred legit | pred phish |", "|---|---|---|",
                  f"| **actual legit** | {cm_r['tn']} | {cm_r['fp']} |",
                  f"| **actual phish** | {cm_r['fn']} | {cm_r['tp']} |"]
    lines += shap_lines + [
        "", "Artifacts: `backend/models/`, `backend/evaluation/`, `backend/reports/`, "
        "serving bundle `backend/artifacts/model_bundle.joblib`.",
    ]
    with open(REPORTS_DIR / "training_report.md", "w") as f:
        f.write("\n".join(lines) + "\n")

    print(f"[SUCCESS] models/, evaluation/, reports/ written; "
          f"serving bundle -> {ARTIFACTS / 'model_bundle.joblib'}")


if __name__ == "__main__":
    main()
