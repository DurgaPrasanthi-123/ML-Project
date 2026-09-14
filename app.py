"""
Flask Application & REST API for Phishing Website Detection System.

Provides:
- Web routes for Home, Detector, About, and How-It-Works pages.
- REST API endpoint `POST /predict` for classifying URLs.
- REST API endpoint `GET /api/metrics` for real training and evaluation statistics.
- Strict passive heuristic evaluation (never executes or visits the URL).
- Graceful error handling with clean, secure JSON responses.
"""

import os
import json
import logging
import joblib
import pandas as pd
from urllib.parse import urlparse
from flask import Flask, request, jsonify, render_template

from utils.feature_extraction import (
    extract_features_dict,
    explain_features,
    get_feature_names,
    clean_url
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("PhishingDetectorApp")

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False

# Paths to model artifacts
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "model", "phishing_model.pkl")
CONFIG_PATH = os.path.join(BASE_DIR, "model", "feature_config.pkl")
METRICS_PATH = os.path.join(BASE_DIR, "model", "model_metrics.json")

# Global model state
model = None
feature_config = None
model_metrics = None


def load_model_artifacts():
    """Load the trained machine learning model and configuration."""
    global model, feature_config, model_metrics
    try:
        if os.path.exists(MODEL_PATH) and os.path.exists(CONFIG_PATH):
            model = joblib.load(MODEL_PATH)
            feature_config = joblib.load(CONFIG_PATH)
            logger.info("Machine Learning model and feature config loaded successfully.")
        else:
            logger.warning(
                "Model files not found. Please execute `python model/train_model.py` to train the model."
            )

        if os.path.exists(METRICS_PATH):
            with open(METRICS_PATH, "r") as f:
                model_metrics = json.load(f)
            logger.info("Model evaluation metrics loaded.")
        else:
            logger.warning("Metrics file not found at %s", METRICS_PATH)
    except Exception as e:
        logger.error(f"Error loading model artifacts: {str(e)}")


# Load artifacts at startup
load_model_artifacts()


def validate_url(url_string: str) -> tuple[bool, str]:
    """
    Validate basic URL format without network access.
    Returns (is_valid, error_message).
    """
    if not url_string or not isinstance(url_string, str):
        return False, "URL cannot be empty."

    trimmed = url_string.strip()
    if len(trimmed) < 4:
        return False, "URL is too short to be valid."

    if len(trimmed) > 2048:
        return False, "URL exceeds maximum permissible length of 2048 characters."

    # Reject dangerous script schemes
    lower = trimmed.lower()
    if lower.startswith("javascript:") or lower.startswith("data:") or lower.startswith("vbscript:"):
        return False, "Invalid URL scheme provided."

    # Parse structure
    cleaned = clean_url(trimmed)
    parsed = urlparse(cleaned)
    if not parsed.netloc and not parsed.path:
        return False, "Invalid domain or hostname format."

    return True, ""


# ==========================================
# Web Routes (Frontend Pages)
# ==========================================

@app.route("/")
def index():
    """Render the Home landing page."""
    return render_template("index.html", metrics=model_metrics)


@app.route("/detector")
def detector():
    """Render the dedicated URL Detection page."""
    return render_template("detector.html", metrics=model_metrics)


@app.route("/about")
def about():
    """Render the About Project page with ML details."""
    return render_template("about.html", metrics=model_metrics)


@app.route("/how-it-works")
def how_it_works():
    """Render the How-It-Works visual explanation page."""
    return render_template("how-it-works.html")


# ==========================================
# REST API Endpoints
# ==========================================

@app.route("/api/metrics", methods=["GET"])
def get_metrics():
    """Return genuine model evaluation statistics and dataset metrics."""
    global model_metrics
    if model_metrics is None and os.path.exists(METRICS_PATH):
        try:
            with open(METRICS_PATH, "r") as f:
                model_metrics = json.load(f)
        except Exception:
            pass

    if model_metrics:
        return jsonify({
            "status": "success",
            "metrics": model_metrics
        }), 200
    else:
        return jsonify({
            "status": "error",
            "message": "Metrics not yet available. Model needs training."
        }), 404


@app.route("/predict", methods=["POST"])
def predict():
    """
    REST API endpoint to analyze a URL and return phishing prediction.

    Expected JSON request:
    {
        "url": "https://example.com"
    }

    Returns:
    {
        "prediction": "Legitimate" | "Phishing",
        "confidence": 95.4,
        "is_phishing": false,
        "risk_level": "Low" | "Medium" | "High",
        "features": { ... },
        "reasons": [ ... ],
        "status": "success"
    }
    """
    global model, feature_config

    # Reload model if it was just trained while app was running
    if model is None:
        load_model_artifacts()

    if model is None:
        return jsonify({
            "status": "error",
            "message": "Model is not loaded or training pipeline has not been executed."
        }), 503

    # Validate JSON payload
    if not request.is_json:
        return jsonify({
            "status": "error",
            "message": "Request payload must be formatted as valid JSON."
        }), 400

    data = request.get_json()
    if not data or "url" not in data:
        return jsonify({
            "status": "error",
            "message": "Missing 'url' parameter in JSON request."
        }), 400

    raw_url = data.get("url")

    # Validate input URL
    is_valid, error_msg = validate_url(raw_url)
    if not is_valid:
        return jsonify({
            "status": "error",
            "message": error_msg
        }), 400

    target_url = raw_url.strip()

    try:
        # Extract features
        features_dict = extract_features_dict(target_url)
        feature_names = feature_config.get("feature_names", get_feature_names())

        # Construct single-row DataFrame with explicit column names
        feature_row = pd.DataFrame([features_dict], columns=feature_names)

        # Generate ML prediction (0: Legitimate, 1: Phishing)
        raw_pred = model.predict(feature_row)[0]
        prediction_label = "Phishing" if raw_pred == 1 else "Legitimate"
        is_phishing = bool(raw_pred == 1)

        # Compute confidence / probability score
        confidence = 90.0  # fallback
        if hasattr(model, "predict_proba"):
            probabilities = model.predict_proba(feature_row)[0]
            # Probability corresponding to the predicted class
            prob_val = probabilities[1] if is_phishing else probabilities[0]
            confidence = round(float(prob_val) * 100, 2)
        elif hasattr(model, "decision_function"):
            score = float(model.decision_function(feature_row)[0])
            confidence = round(min(max(abs(score) * 20 + 50, 50.0), 99.5), 2)

        # Categorize risk level
        if is_phishing:
            risk_level = "High" if confidence > 80 else "Medium"
        else:
            risk_level = "Low" if confidence > 75 else "Medium"

        # Generate human-readable explanations & safety indicators
        reasons = explain_features(features_dict, prediction_label)

        logger.info(f"URL: '{target_url}' -> Prediction: {prediction_label} ({confidence}%)")

        return jsonify({
            "status": "success",
            "url": target_url,
            "prediction": prediction_label,
            "confidence": confidence,
            "is_phishing": is_phishing,
            "risk_level": risk_level,
            "features": features_dict,
            "reasons": reasons
        }), 200

    except Exception as err:
        logger.error(f"Internal prediction error: {str(err)}", exc_info=True)
        return jsonify({
            "status": "error",
            "message": "An error occurred while analyzing the URL features. Please try again."
        }), 500


@app.errorhandler(404)
def page_not_found(e):
    return render_template("index.html", error="Page not found"), 404


@app.errorhandler(500)
def server_error(e):
    return jsonify({
        "status": "error",
        "message": "Internal server error occurred."
    }), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print("\n" + "="*65)
    print(" [SERVER] PHISHING WEBSITE DETECTION SYSTEM - STARTING")
    print(f" [URL]    Access Web Portal at: http://127.0.0.1:{port}")
    print(f" [API]    Predict Endpoint:     POST http://127.0.0.1:{port}/predict")
    print(f" [STATS]  Metrics Endpoint:     GET  http://127.0.0.1:{port}/api/metrics")
    print("="*65 + "\n")
    app.run(host="127.0.0.1", port=port, debug=True)
