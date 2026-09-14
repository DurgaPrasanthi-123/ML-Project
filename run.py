"""
Convenient One-Click Application Launcher for Phishing Website Detection System.

Checks for trained model artifacts, automatically initiates training if needed,
and launches the local Flask web development server.
"""

import os
import sys

def main():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    model_path = os.path.join(base_dir, "model", "phishing_model.pkl")

    if not os.path.exists(model_path):
        print("[INFO] Trained model not detected. Initiating automated training pipeline...")
        from model.train_model import main as train_main
        train_main()
        print("[SUCCESS] Model trained and serialized.")

    print("\n" + "="*70)
    print(" [PROJECT] PHISHING WEBSITE DETECTION SYSTEM")
    print(" [STATUS]  College Final Project / Capstone")
    print("="*70)
    print(" [WEB]     Web Application URL : http://127.0.0.1:5000")
    print(" [SCANNER] Direct Scanner URL   : http://127.0.0.1:5000/detector")
    print(" [GUIDE]   Detection Pipeline   : http://127.0.0.1:5000/how-it-works")
    print(" [ABOUT]   ML Model Benchmark   : http://127.0.0.1:5000/about")
    print(" [API]     REST API Predict     : POST http://127.0.0.1:5000/predict")
    print(" [STATS]   REST API Metrics     : GET  http://127.0.0.1:5000/api/metrics")
    print("="*70)
    print(" Press Ctrl+C in terminal to stop the server.\n")

    from app import app
    app.run(host="127.0.0.1", port=5000, debug=True)

if __name__ == "__main__":
    main()
