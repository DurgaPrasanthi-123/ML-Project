"""
Model Training & Evaluation Pipeline for Phishing Website Detection.

1. Loads the balanced URL dataset.
2. Extracts 17 lexical and structural features via utils/feature_extraction.py.
3. Splits into stratified train and test partitions (80/20).
4. Trains and rigorously compares 4 ML algorithms:
   - Logistic Regression
   - Decision Tree Classifier
   - Random Forest Classifier
   - Support Vector Machine (Linear SVM with probability calibration)
5. Computes Accuracy, Precision, Recall, F1-Score, and ROC-AUC.
6. Generates high-resolution visualization charts (model comparison, confusion matrix, ROC).
7. Serializes the best model (phishing_model.pkl), feature config, and metrics JSON.
"""

import os
import sys
import json
import joblib
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg') # Headless backend for server execution
import matplotlib.pyplot as plt

from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import LinearSVC
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, roc_curve
)

# Add parent directory to path so utils can be imported
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.abspath(os.path.join(CURRENT_DIR, ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from utils.feature_extraction import extract_features_dict, get_feature_names


def load_or_create_dataset(data_path: str) -> pd.DataFrame:
    """Load dataset or invoke dataset generator if not found."""
    if not os.path.exists(data_path):
        print(f"[INFO] Dataset not found at {data_path}. Generating new dataset...")
        from data.generate_dataset import build_dataset
        df = build_dataset(5000)
        os.makedirs(os.path.dirname(data_path), exist_ok=True)
        df.to_csv(data_path, index=False)
        print(f"[SUCCESS] Dataset generated with {len(df)} samples.")
    else:
        df = pd.read_csv(data_path)
        print(f"[INFO] Loaded existing dataset from {data_path} with {len(df)} records.")
    return df


def extract_features_dataframe(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.Series]:
    """Extract features for all URLs in the dataset into a DataFrame."""
    print("[INFO] Extracting features from URLs (this uses strictly passive heuristics)...")
    feature_names = get_feature_names()
    
    feature_rows = []
    for url in df["url"]:
        feats = extract_features_dict(str(url))
        feature_rows.append(feats)
        
    X = pd.DataFrame(feature_rows, columns=feature_names)
    y = df["label"]
    return X, y


def evaluate_model(name: str, model, X_train, y_train, X_test, y_test) -> dict:
    """Train and compute all classification metrics for a model."""
    print(f"[TRAINING] Training {name}...")
    model.fit(X_train, y_train)
    
    train_pred = model.predict(X_train)
    test_pred = model.predict(X_test)
    
    # Probabilities for ROC-AUC
    if hasattr(model, "predict_proba"):
        test_proba = model.predict_proba(X_test)[:, 1]
    elif hasattr(model, "decision_function"):
        d = model.decision_function(X_test)
        test_proba = (d - d.min()) / (d.max() - d.min() + 1e-9)
    else:
        test_proba = test_pred

    train_acc = float(accuracy_score(y_train, train_pred))
    test_acc = float(accuracy_score(y_test, test_pred))
    prec = float(precision_score(y_test, test_pred, zero_division=0))
    rec = float(recall_score(y_test, test_pred, zero_division=0))
    f1 = float(f1_score(y_test, test_pred, zero_division=0))
    auc = float(roc_auc_score(y_test, test_proba))
    cm = confusion_matrix(y_test, test_pred).tolist()

    print(f"   -> {name}: Test Accuracy = {test_acc:.4f} | F1 = {f1:.4f} | AUC = {auc:.4f}")

    return {
        "name": name,
        "train_accuracy": round(train_acc * 100, 2),
        "test_accuracy": round(test_acc * 100, 2),
        "precision": round(prec * 100, 2),
        "recall": round(rec * 100, 2),
        "f1_score": round(f1 * 100, 2),
        "roc_auc": round(auc * 100, 2),
        "confusion_matrix": cm,
        "model_object": model,
        "test_proba": test_proba
    }


def generate_visualizations(models_metrics: list, best_model_info: dict, X_test, y_test, images_dir: str):
    """Generate high-contrast minimal black/white comparison plots."""
    os.makedirs(images_dir, exist_ok=True)
    
    # Configure minimal dark theme for matplotlib
    plt.rcParams.update({
        'figure.facecolor': '#0c0c0c',
        'axes.facecolor': '#0c0c0c',
        'axes.edgecolor': '#27272a',
        'axes.labelcolor': '#ffffff',
        'xtick.color': '#a1a1aa',
        'ytick.color': '#a1a1aa',
        'text.color': '#ffffff',
        'grid.color': '#1f1f23',
        'grid.linestyle': '--',
        'grid.alpha': 0.6
    })

    # 1. Model Comparison Bar Chart (Minimal Monochrome)
    fig, ax = plt.subplots(figsize=(10, 6))
    names = [m["name"] for m in models_metrics]
    metrics = ["test_accuracy", "precision", "recall", "f1_score"]
    metric_labels = ["Accuracy", "Precision", "Recall", "F1-Score"]
    colors = ["#ffffff", "#d4d4d8", "#a1a1aa", "#71717a"]

    x = np.arange(len(names))
    width = 0.18

    for i, (metric, label, color) in enumerate(zip(metrics, metric_labels, colors)):
        vals = [m[metric] for m in models_metrics]
        rects = ax.bar(x + (i - 1.5) * width, vals, width, label=label, color=color, edgecolor="#27272a")
        for rect in rects:
            height = rect.get_height()
            ax.annotate(f'{height:.1f}%',
                        xy=(rect.get_x() + rect.get_width() / 2, height),
                        xytext=(0, 3), textcoords="offset points",
                        ha='center', va='bottom', fontsize=8, rotation=45, color="#ffffff")

    ax.set_title("Machine Learning Algorithms Performance Comparison", fontsize=14, fontweight='bold', pad=15, color="#ffffff")
    ax.set_ylabel("Score (%)", fontsize=11, color="#a1a1aa")
    ax.set_xticks(x)
    ax.set_xticklabels(names, fontsize=10, fontweight='bold', color="#ffffff")
    ax.set_ylim(0, 115)
    ax.grid(True, axis='y')
    ax.legend(loc='lower right', facecolor="#141414", edgecolor="#27272a", labelcolor="#ffffff")
    plt.tight_layout()
    comparison_path = os.path.join(images_dir, "model_comparison.png")
    fig.savefig(comparison_path, dpi=200, facecolor=fig.get_facecolor(), edgecolor='none')
    plt.close(fig)
    print(f"[SUCCESS] Saved {comparison_path}")

    # 2. Confusion Matrix Heatmap (Monochrome)
    best_cm = np.array(best_model_info["confusion_matrix"])
    fig, ax = plt.subplots(figsize=(7, 6))
    cax = ax.matshow(best_cm, cmap="Greys", alpha=0.9)
    fig.colorbar(cax)

    classes = ["Legitimate (0)", "Phishing (1)"]
    ax.set_xticks([0, 1])
    ax.set_yticks([0, 1])
    ax.set_xticklabels(classes, fontsize=10, color="#ffffff")
    ax.set_yticklabels(classes, fontsize=10, color="#ffffff")
    ax.set_xlabel("Predicted Label", fontsize=11, fontweight='bold', labelpad=10, color="#ffffff")
    ax.set_ylabel("Actual Ground Truth", fontsize=11, fontweight='bold', labelpad=10, color="#ffffff")
    ax.set_title(f"Confusion Matrix ({best_model_info['name']})", fontsize=13, fontweight='bold', pad=18, color="#ffffff")

    tn, fp, fn, tp = best_cm.ravel()
    labels = [[f"TN\n{tn}", f"FP\n{fp}"], [f"FN\n{fn}", f"TP\n{tp}"]]
    for i in range(2):
        for j in range(2):
            val = best_cm[i, j]
            text_color = "black" if val > (best_cm.max() / 2) else "white"
            ax.text(j, i, labels[i][j], ha="center", va="center", color=text_color, fontsize=13, fontweight='bold')

    plt.tight_layout()
    cm_path = os.path.join(images_dir, "confusion_matrix.png")
    fig.savefig(cm_path, dpi=200, facecolor=fig.get_facecolor(), edgecolor='none')
    plt.close(fig)
    print(f"[SUCCESS] Saved {cm_path}")

    # 3. ROC Curves (Monochrome Lines)
    fig, ax = plt.subplots(figsize=(8, 6))
    line_styles = ['-', '--', '-.', ':']
    line_colors = ['#ffffff', '#e4e4e7', '#a1a1aa', '#71717a']
    for idx, m in enumerate(models_metrics):
        fpr, tpr, _ = roc_curve(y_test, m["test_proba"])
        ax.plot(fpr, tpr, label=f"{m['name']} (AUC = {m['roc_auc']:.1f}%)",
                lw=2, color=line_colors[idx % len(line_colors)], linestyle=line_styles[idx % len(line_styles)])

    ax.plot([0, 1], [0, 1], color='#3f3f46', lw=1.5, linestyle=':', label="Random Guess (50%)")
    ax.set_xlim([0.0, 1.0])
    ax.set_ylim([0.0, 1.05])
    ax.set_xlabel("False Positive Rate (1 - Specificity)", fontsize=11, color="#a1a1aa")
    ax.set_ylabel("True Positive Rate (Sensitivity / Recall)", fontsize=11, color="#a1a1aa")
    ax.set_title("ROC Curves Comparison Across Algorithms", fontsize=13, fontweight='bold', color="#ffffff")
    ax.grid(True)
    ax.legend(loc="lower right", facecolor="#141414", edgecolor="#27272a", labelcolor="#ffffff")
    plt.tight_layout()
    roc_path = os.path.join(images_dir, "roc_curve.png")
    fig.savefig(roc_path, dpi=200, facecolor=fig.get_facecolor(), edgecolor='none')
    plt.close(fig)
    print(f"[SUCCESS] Saved {roc_path}")


def main():
    data_path = os.path.join(ROOT_DIR, "data", "dataset.csv")
    images_dir = os.path.join(ROOT_DIR, "static", "images")
    
    # 1. Load data
    df = load_or_create_dataset(data_path)
    
    # 2. Extract features
    X, y = extract_features_dataframe(df)
    feature_names = list(X.columns)
    
    # 3. Train/Test Split (80/20 stratified)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    print(f"[INFO] Training set size: {len(X_train)} samples | Test set size: {len(X_test)} samples")
    
    # 4. Define candidate models
    models = {
        "Logistic Regression": LogisticRegression(max_iter=1000, random_state=42),
        "Decision Tree": DecisionTreeClassifier(max_depth=12, min_samples_split=5, random_state=42),
        "Random Forest": RandomForestClassifier(n_estimators=120, max_depth=16, random_state=42, n_jobs=-1),
        "Support Vector Machine": CalibratedClassifierCV(
            LinearSVC(random_state=42, max_iter=2500, dual=False), cv=3
        )
    }
    
    # 5. Evaluate all models
    results = []
    for name, model in models.items():
        metrics = evaluate_model(name, model, X_train, y_train, X_test, y_test)
        results.append(metrics)
        
    # 6. Identify best model (prefer Random Forest if tied, due to smooth ensemble probability calibration)
    priority = {"Random Forest": 4, "Decision Tree": 3, "Support Vector Machine": 2, "Logistic Regression": 1}
    best_model_info = max(results, key=lambda m: (m["f1_score"], m["test_accuracy"], priority.get(m["name"], 0)))
    best_model = best_model_info["model_object"]
    print("\n" + "="*60)
    print(f"  [BEST MODEL SELECTED]: {best_model_info['name']}")
    print(f"  Test Accuracy: {best_model_info['test_accuracy']}%")
    print(f"  Precision:     {best_model_info['precision']}%")
    print(f"  Recall:        {best_model_info['recall']}%")
    print(f"  F1-Score:      {best_model_info['f1_score']}%")
    print("="*60 + "\n")
    
    # 7. Generate Visualizations
    generate_visualizations(results, best_model_info, X_test, y_test, images_dir)
    
    # 8. Save artifacts
    model_dir = os.path.join(ROOT_DIR, "model")
    os.makedirs(model_dir, exist_ok=True)
    
    model_save_path = os.path.join(model_dir, "phishing_model.pkl")
    joblib.dump(best_model, model_save_path)
    print(f"[SUCCESS] Trained model saved to: {model_save_path}")
    
    config_save_path = os.path.join(model_dir, "feature_config.pkl")
    joblib.dump({
        "feature_names": feature_names,
        "n_features": len(feature_names),
        "best_algorithm": best_model_info["name"]
    }, config_save_path)
    print(f"[SUCCESS] Feature config saved to: {config_save_path}")
    
    # Clean results for JSON serialization (remove model_object & numpy arrays)
    serializable_results = []
    for r in results:
        r_clean = {k: v for k, v in r.items() if k not in ["model_object", "test_proba"]}
        serializable_results.append(r_clean)
        
    metrics_save_path = os.path.join(model_dir, "model_metrics.json")
    with open(metrics_save_path, "w") as f:
        json.dump({
            "dataset": {
                "total_samples": len(df),
                "train_samples": len(X_train),
                "test_samples": len(X_test),
                "num_features": len(feature_names),
                "features_list": feature_names,
                "legitimate_count": int((y == 0).sum()),
                "phishing_count": int((y == 1).sum())
            },
            "best_model": {
                "name": best_model_info["name"],
                "train_accuracy": best_model_info["train_accuracy"],
                "test_accuracy": best_model_info["test_accuracy"],
                "precision": best_model_info["precision"],
                "recall": best_model_info["recall"],
                "f1_score": best_model_info["f1_score"],
                "roc_auc": best_model_info["roc_auc"],
                "confusion_matrix": best_model_info["confusion_matrix"]
            },
            "comparison": serializable_results
        }, f, indent=4)
    print(f"[SUCCESS] Real evaluated metrics exported to: {metrics_save_path}")


if __name__ == "__main__":
    main()
