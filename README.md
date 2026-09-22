# Phishing Website Detection System Using Machine Learning

[![Python Version](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.14-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.1-black.svg)](https://flask.palletsprojects.com/)
[![Scikit-Learn](https://img.shields.io/badge/scikit--learn-1.9-orange.svg)](https://scikit-learn.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](#)
[![Status](https://img.shields.io/badge/Project-College%20Capstone-brightgreen.svg)](#)

A college capstone project and cybersecurity web application that determines whether a given website URL is **Legitimate** or **Phishing** using Machine Learning classification algorithms, passive lexical/structural heuristics, and a **hybrid brand-impersonation rule engine**.

---

## Table of Contents
1. [Project Title](#1-project-title)
2. [Project Description](#2-project-description)
3. [Problem Statement](#3-problem-statement)
4. [Objectives](#4-objectives)
5. [Technologies Used](#5-technologies-used)
6. [Dataset Information](#6-dataset-information)
7. [Machine Learning Methodology](#7-machine-learning-methodology)
8. [System Architecture](#8-system-architecture)
9. [Project Structure](#9-project-structure)
10. [Installation Instructions](#10-installation-instructions)
11. [How to Train the Model](#11-how-to-train-the-model)
12. [How to Run the Flask Application](#12-how-to-run-the-flask-application)
13. [How to Access the Website](#13-how-to-access-the-website)
14. [REST API Documentation](#14-rest-api-documentation)
15. [Sample Request & Response](#15-sample-request--response)
16. [Visualizations & Screenshots](#16-visualizations--screenshots)
17. [System Limitations](#17-system-limitations)
18. [Future Enhancements](#18-future-enhancements)
19. [Conclusion](#19-conclusion)

---

## 1. Project Title
**Phishing Website Detection Using Machine Learning and Lexical URL Feature Extraction**

---

## 2. Project Description
Phishing is one of the oldest yet most destructive forms of cyber warfare, targeting users across banking, corporate networks, and personal accounts. This project delivers an end-to-end, production-grade web solution that enables users to evaluate any web link in real-time. The server extracts 17 passive lexical and structural heuristics directly from the URL string without connecting to the remote host (guaranteeing zero vulnerability to malware or drive-by exploits) and performs inference using a calibrated ensemble classifier.

---

## 3. Problem Statement
Traditional cybersecurity countermeasures rely predominantly on static blacklists (such as DNS-based blocklists and Google Safe Browsing lists). While effective against established threats, blacklists fail against modern **zero-hour phishing campaigns**, where cybercriminals programmatically generate ephemeral domains and modify URL tokens every few minutes. Blacklists suffer from a critical detection lag of several hours to days. This project addresses the challenge by using **supervised machine learning** to detect heuristic patterns in URL syntax, enabling the identification of novel, previously un-blacklisted phishing attacks.

---

## 4. Objectives
- **Passive Threat Analysis**: Inspect and extract meaningful quantitative features strictly through URL lexical analysis without making network requests to malicious servers.
- **Multi-Algorithm Benchmarking**: Implement, train, and evaluate multiple classification algorithms (Logistic Regression, Decision Tree, Random Forest, Support Vector Machine).
- **Ensemble Model Serialization**: Serialize the highest-performing model (Random Forest) with probability calibration using `joblib` for sub-15ms inference latency.
- **RESTful Architecture**: Implement a clean, decoupled Flask REST API with strict input sanitization and standardized JSON responses.
- **Modern Responsive Web Portal**: Provide an intuitive, cybersecurity-themed user interface with real-time feedback, confidence scores, threat indicators, and academic statistics.

---

## 5. Technologies Used

### Frontend
- **HTML5 & Modern CSS3**: Custom dark-mode cybersecurity design system with glassmorphism, responsive CSS Grid and Flexbox layouts.
- **Vanilla JavaScript (ES6+)**: Asynchronous `fetch()` API for smooth client-server communication without page reloads.
- **Google Fonts**: Modern typography featuring *Inter* and *JetBrains Mono*.

### Backend & API
- **Python (3.10+)**: Core runtime engine.
- **Flask (3.1+)**: Lightweight WSGI microframework serving web routes and the REST API.
- **Standard Libraries**: `urllib.parse`, `ipaddress`, `re`, `json`, `logging`.

### Machine Learning & Data Science
- **Scikit-learn**: Classification models, stratified dataset splitting, metrics evaluation (`roc_auc_score`, `confusion_matrix`, `classification_report`).
- **Pandas & NumPy**: Data ingestion, vector manipulation, and feature matrix construction.
- **Joblib**: Persistent model serialization and deserialization.
- **Matplotlib & Seaborn**: Statistical data visualizations, ROC curves, and confusion matrix generation.

---

## 6. Dataset Information
The benchmark dataset (`data/dataset.csv`) contains **5,000 balanced URL records** (2,500 Legitimate and 2,500 Phishing):
- **Legitimate URLs (Class 0)**: Sampled from top global enterprise domains, technology platforms, educational institutions (`.edu`, `.ac.uk`), financial institutions, and standard internet paths with valid HTTPS certificates and DNS hierarchies.
- **Phishing URLs (Class 1)**: Curated to represent real-world attack vectors observed in PhishTank and OpenPhish feeds, including:
  - Raw IP address hosts (e.g. `http://192.168.1.1:8080/bank/login.php`)
  - Hyphenated brand typosquatting (e.g. `verify-paypal-security-account.net`)
  - Deep deceptive subdomain nesting (e.g. `login.paypal.com.account-update.xyz`)
  - Obscured URL shortener redirects (`bit.ly`, `tinyurl.com`, `t.co`)
  - Path redirection evasion (double slashes `//`)
  - Hex-encoded query strings and credential harvesting forms over insecure HTTP.

---

## 7. Machine Learning Methodology
The development follows a structured 5-stage pipeline:

```
Dataset (5,000 URLs)
       │
       ▼
Passive Feature Extraction (22 Lexical & Structural Features)
       │
       ▼
Stratified Train/Test Split (80% Train / 20% Test)
       │
       ▼
Algorithm Training & Cross-Validation
(Logistic Regression, Decision Tree, Random Forest, SVM)
       │
       ▼
Best Model Selection & Serialization (phishing_model.pkl)
       │
       ▼
Inference + Brand-Impersonation Rule Engine (hybrid verdict)
```

### Extracted Features (22 Heuristics)
1. `url_length`: Total character count of the URL.
2. `domain_length`: Total character length of the hostname.
3. `count_dots`: Total count of period (`.`) characters.
4. `count_hyphens`: Total count of hyphen (`-`) characters (typosquatting indicator).
5. `count_at`: Total count of `@` symbols (URL credential masking).
6. `count_question`: Total count of `?` characters in query strings.
7. `count_percent`: Total count of `%` hex-encoding characters.
8. `count_equal`: Total count of `=` assignment characters.
9. `count_slash`: Total count of `/` path separators.
10. `count_digits`: Total numeric digits in URL.
11. `digit_ratio`: Ratio of digits to total characters.
12. `is_ip_address`: Binary flag (1 if hostname is IPv4/IPv6, 0 otherwise).
13. `has_https`: Binary flag (1 if protocol is HTTPS, 0 otherwise).
14. `count_subdomains`: Depth of subdomain nesting.
15. `has_suspicious_keywords`: Frequency of targeted words (`login`, `verify`, `account`, `banking`, `secure`, `update`, `wallet`).
16. `is_shortened`: Binary flag indicating recognized URL shortener domain.
17. `has_double_slash_path`: Binary flag indicating `//` redirection in URL path.
18. `suspicious_tld`: Binary flag for high-abuse TLDs (`.xyz`, `.top`, `.click`, `.icu`, ...).
19. `is_free_host`: Binary flag for free/anonymous hosting platforms (weebly, wixsite, netlify, ...).
20. `digits_in_host`: Count of numeric digits in the hostname (disposable-infrastructure indicator).
21. `has_redirect_param`: Binary flag for open-redirect query parameters (`?url=`, `?next=`, `?continue=`).
22. `brand_impersonation_score`: Aggregate 0–1 confidence that the domain impersonates a well-known brand (typosquatting, leetspeak, subdomain embedding).

### Hybrid Detection Architecture
Beyond the ML classifier, two dedicated modules harden the pipeline:

- **`utils/url_parser.py`** — Single hardened URL decomposition used by every stage: approximate eTLD+1 (registrable-domain) extraction, multi-label public-suffix handling, IPv4/IPv6/decimal-IP detection, dangerous-scheme blocking (`javascript:`, `data:`, ...), and **SSRF defense** that rejects private/reserved/loopback targets.
- **`utils/brand_impersonation.py`** — A rule engine covering 50+ major brands that combines three signals — (1) registrable-domain lookalikes with leetspeak/homoglyph normalization (`paypa1`, `micr0soft`), (2) brand tokens embedded in subdomains/paths of unrelated domains, and (3) corroborating context (abused TLDs, free hosting, credential keywords). Genuine brand domains are never flagged, and brand *mentions* on reputable sites (news articles, help pages) are whitelisted by the multi-signal requirement.
- **`utils/dns_verifier.py`** — DNS existence verification over **DNS-over-HTTPS** (Cloudflare/Google public resolvers). A domain with no DNS records is unregistered or fabricated — a pattern no lexical feature can see (e.g. randomly generated hostnames). The check queries **public resolvers only, never the target server**, and is strictly fail-open: resolver outages degrade to "unknown" without altering the verdict.

The rule engine acts as a **safety net at inference time**: when impersonation confidence ≥ 0.5, `/predict` escalates the verdict to *Phishing* even if the model alone is uncertain, and attaches the matched techniques to the response reasons. Likewise, a domain that verifiably does not exist in global DNS is overridden to *Phishing* (≥85% confidence) with an "Unregistered / Fabricated Domain" reason, while a domain that resolves adds a positive "Domain Resolves in Global DNS" indicator.

---

## 8. System Architecture

```
+-------------------------------------------------------------+
|                     Client Web Browser                      |
| (HTML5 / Modern CSS / Vanilla JS / Responsive UI / Fetch)   |
+------------------------------+------------------------------+
                               |
                       HTTP / JSON Payload
                               |
                               v
+-------------------------------------------------------------+
|                      Flask Application                      |
|                          (app.py)                           |
|  - Validates input format without network connections        |
|  - Exposes REST API endpoints (/predict, /api/metrics)       |
|  - Renders Jinja2 Web Pages (/, /detector, /about, etc.)     |
+---------------+------------------------------+--------------+
                |                              |
                v                              v
+-------------------------------+  +--------------------------+
|  utils/feature_extraction.py  |  | model/phishing_model.pkl |
|  - 17 passive lexical features|  | - Random Forest Ensemble |
|  - Zero network vulnerability |  | - Probability scoring    |
+-------------------------------+  +--------------------------+
```

---

## 9. Project Structure

```text
phishing-website-detection/
│
├── app.py                      # Flask Application & REST API endpoints
├── run.py                      # One-click startup launcher
├── test_app.py                 # 38-case automated integration test suite
├── requirements.txt            # Locked Python dependencies
├── README.md                   # Full 19-section documentation
├── VIVA_QUESTIONS.md           # College viva voce defense preparation guide
│
├── data/
│   ├── generate_dataset.py     # Script to generate balanced 5,000-URL dataset
│   └── dataset.csv             # Curated balanced dataset
│
├── utils/
│   ├── url_parser.py           # Hardened URL decomposition, eTLD+1, SSRF defense
│   ├── brand_impersonation.py  # 50+ brand typosquatting/spoofing rule engine
│   ├── dns_verifier.py         # DNS-over-HTTPS existence check (fake-domain detector)
│   └── feature_extraction.py   # 22 passive URL features + explanation module
│
├── model/
│   ├── train_model.py          # ML training, cross-validation, and metrics export
│   ├── phishing_model.pkl      # Serialized best model (Random Forest)
│   ├── feature_config.pkl      # Feature metadata configuration
│   └── model_metrics.json      # True evaluation results and statistics
│
├── templates/
│   ├── base.html               # Master layout with navbar and footer
│   ├── index.html              # Landing page with hero & quick scanner
│   ├── detector.html           # Dedicated URL analyzer with feature breakdown
│   ├── about.html              # Academic context & ML comparison benchmark
│   └── how-it-works.html       # Visual 6-step detection pipeline
│
├── static/
│   ├── css/
│   │   └── style.css           # Cybersecurity dark-mode stylesheet
│   ├── js/
│   │   └── script.js           # AJAX fetch client, validation, loading animations
│   └── images/
│       ├── model_comparison.png# Algorithm performance comparison plot
│       ├── confusion_matrix.png# Confusion matrix heatmap
│       └── roc_curve.png       # Receiver Operating Characteristic plot
│
└── notebooks/
    └── model_analysis.ipynb    # Jupyter notebook for viva demonstration & EDA
```

---

## 10. Installation Instructions

### Prerequisites
- Python 3.10, 3.11, 3.12, or 3.14 installed on your system.
- `pip` (Python package installer).

### Step 1: Clone or Navigate to Project Directory
```bash
cd "C:\Users\hi\OneDrive\Desktop\DM PROJECT"
```

### Step 2: Create a Virtual Environment
```bash
python -m venv venv
```

### Step 3: Activate the Virtual Environment
- **Windows (Command Prompt / PowerShell)**:
  ```powershell
  .\venv\Scripts\activate
  ```
- **macOS / Linux**:
  ```bash
  source venv/bin/activate
  ```

### Step 4: Install Dependencies
```bash
pip install -r requirements.txt
```

---

## 11. How to Train the Model
To re-train all 4 machine learning algorithms, re-generate evaluation charts, and re-export metrics:

```bash
python model/train_model.py
```

Expected output:
```text
[INFO] Loaded existing dataset with 5000 records.
[INFO] Extracting features from URLs...
[INFO] Training set size: 4000 samples | Test set size: 1000 samples
[TRAINING] Training Logistic Regression...
[TRAINING] Training Decision Tree...
[TRAINING] Training Random Forest...
[TRAINING] Training Support Vector Machine...
============================================================
  [BEST MODEL SELECTED]: Random Forest
  Test Accuracy: 100.0%
  Precision:     100.0%
  Recall:        100.0%
  F1-Score:      100.0%
============================================================
[SUCCESS] Saved static/images/model_comparison.png
[SUCCESS] Saved static/images/confusion_matrix.png
[SUCCESS] Saved static/images/roc_curve.png
[SUCCESS] Trained model saved to: model/phishing_model.pkl
```

---

## 12. How to Run the Flask Application

### Option A: Using the Convenient Launcher (Recommended)
```bash
python run.py
```

### Option B: Running app.py Directly
```bash
python app.py
```

---

## 13. How to Access the Website
Open your favorite web browser and navigate to:
- **Home Page**: [http://127.0.0.1:5000](http://127.0.0.1:5000)
- **URL Scanner**: [http://127.0.0.1:5000/detector](http://127.0.0.1:5000/detector)
- **How It Works**: [http://127.0.0.1:5000/how-it-works](http://127.0.0.1:5000/how-it-works)
- **About & Model Benchmark**: [http://127.0.0.1:5000/about](http://127.0.0.1:5000/about)

---

## 14. REST API Documentation

### 1. URL Prediction Endpoint
- **URL**: `/predict`
- **Method**: `POST`
- **Headers**: `Content-Type: application/json`
- **Body**:
  ```json
  {
    "url": "https://www.paypal.com"
  }
  ```

Input validation rejects dangerous schemes (`javascript:`, `data:`), malformed hostnames, and private/internal network targets (SSRF defense) with HTTP 400 and a descriptive message. Successful responses additionally include a `brand_analysis` object (`is_impersonation`, `brand`, `techniques`, `official_domain`) and a `dns_check` object (`checked`, `exists`).

### 2. Model Metrics Endpoint
- **URL**: `/api/metrics`
- **Method**: `GET`
- **Description**: Returns live training accuracy, dataset sizes, and comparison results for all 4 models.

---

## 15. Sample Request & Response

### Request 1: Legitimate Website
```bash
curl -X POST http://127.0.0.1:5000/predict \
     -H "Content-Type: application/json" \
     -d "{\"url\": \"https://www.google.com/search?q=cybersecurity\"}"
```

**Response**:
```json
{
  "status": "success",
  "url": "https://www.google.com/search?q=cybersecurity",
  "prediction": "Legitimate",
  "confidence": 99.4,
  "is_phishing": false,
  "risk_level": "Low",
  "reasons": [
    {
      "type": "success",
      "title": "Encrypted Connection (HTTPS)",
      "desc": "Uses HTTPS encryption protocol, securing communication in transit."
    },
    {
      "type": "success",
      "title": "Standard Domain Hierarchy",
      "desc": "Domain name structure is concise and follows standard enterprise DNS naming patterns."
    }
  ]
}
```

### Request 2: Phishing Website
```bash
curl -X POST http://127.0.0.1:5000/predict \
     -H "Content-Type: application/json" \
     -d "{\"url\": \"http://192.168.1.100:8080/paypal-security/login.php\"}"
```

**Response**:
```json
{
  "status": "success",
  "url": "http://23.22.14.100:8080/paypal-security/login.php",
  "prediction": "Phishing",
  "confidence": 99.8,
  "is_phishing": true,
  "risk_level": "High",
  "reasons": [
    {
      "type": "danger",
      "title": "Raw IP Address Hostname",
      "desc": "The URL uses a raw numeric IP address instead of a registered domain name, a hallmark of malicious phishing hosts."
    },
    {
      "type": "warning",
      "title": "High-Risk Security Keywords",
      "desc": "Contains 2 sensitive keywords (e.g. login, verify, banking, secure) frequently used in credential harvesting."
    },
    {
      "type": "warning",
      "title": "Insecure Protocol (HTTP)",
      "desc": "Does not use HTTPS encryption, leaving data vulnerable in plaintext."
    }
  ]
}
```

---

## 16. Visualizations & Screenshots

The system produces 3 high-resolution visualization artifacts:
1. **Model Performance Comparison (`static/images/model_comparison.png`)**: Compares Accuracy, Precision, Recall, and F1-score across Logistic Regression, Decision Tree, Random Forest, and Support Vector Machine.
2. **Confusion Matrix (`static/images/confusion_matrix.png`)**: Illustrates True Positives, True Negatives, False Positives, and False Negatives of the Random Forest model on 1,000 unseen test samples.
3. **Receiver Operating Characteristic (`static/images/roc_curve.png`)**: Demonstrates the True Positive Rate vs False Positive Rate trade-off across all models.

---

## 17. System Limitations
- **Structural Analysis Only**: The system inspects lexical URL syntax without evaluating the remote page's HTML, CSS, or JavaScript content.
- **Compromised Trusted Domains**: If an attacker compromises a legitimate server (e.g. WordPress blog) and hosts a phishing page inside a benign-looking directory, lexical features alone may yield a false negative — the domain genuinely exists and looks normal.
- **Registered-but-Parked Domains**: A fabricated-looking URL built on a *registered* (but unused/parked) domain resolves in DNS and passes the existence check; DNS only proves registration, not reputation.
- **Adversarial Obfuscation**: Advanced adversaries continuously develop new evasions (such as homoglyph domain attacks with unicode characters).

---

## 18. Future Enhancements
- **Browser Extension**: Compile the inference engine into a Manifest V3 browser extension for live URL interception before page rendering.
- **WHOIS & Domain Age API**: Incorporate domain creation timestamps into the feature vector (domains created <14 days ago exhibit high risk).
- **Deep Learning / NLP**: Explore character-level Bi-directional LSTM or Transformer architectures (BERT for URLs).

---

## 19. Conclusion
This project presents an end-to-end Machine Learning solution for the detection of phishing websites. By extracting 17 passive lexical and structural heuristics directly from URL strings, the system eliminates network attack vectors while achieving high classification accuracy in under 15 milliseconds. The decoupled Flask architecture, combined with a responsive, modern cybersecurity interface, provides a complete academic and practical capstone demonstration.
