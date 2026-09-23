# Phish.ML — ML-Based Phishing URL Detection System

Classifies URLs as **LEGITIMATE / SUSPICIOUS / PHISHING** using Logistic Regression, Random Forest, and XGBoost, with SHAP explainability, a FastAPI backend, a React frontend, and PostgreSQL scan history.

**Safety invariants:** the system never visits submitted URLs, never fetches target pages, contains no SSRF-prone fetching, and uses no hardcoded per-URL verdicts. The only outbound calls are to public DNS-over-HTTPS resolvers (existence check only, fail-open).

## Architecture

```
frontend/            React 18 + Vite (Phish.ML web UI)
backend/
  app/
    api/v1/          routes + Pydantic schemas  (/predict /health /model-info)
    core/
      features.py    SINGLE source of truth for the 26-feature vector
                     (imported identically by training AND serving)
      url_parser.py  hardened parsing, eTLD+1, SSRF target detection
      brand_impersonation.py   pattern-based brand-spoof guardrail
      dns_verifier.py          DNS-over-HTTPS existence check (fail-open)
      guardrails.py  deterministic safety-net fusion
      inference.py   thresholding, risk score, SHAP contributions
      explain.py     SHAP TreeExplainer wrapper
    db/              SQLAlchemy scan history (PostgreSQL / SQLite fallback)
    main.py          FastAPI app factory, CORS
  training/train.py  LR vs RF vs XGBoost benchmark + bundle serialization
  artifacts/         model_bundle.joblib, model_metrics.json
```

## Feature contract (training = serving)

26 lexical/structural features (lengths, character counts, digit ratio, subdomain depth, IP host, HTTPS, credentials, unusual port, shortener, free host, abused TLD, double-slash redirect, keyword hits, brand-impersonation score, brand embedding, DNS existence). Keyword hits are 1 of 26 features — never a verdict. `backend/app/core/features.py` is the only feature implementation; the test suite asserts the bundle's feature list matches it exactly.

## API (v1)

| Method | Path | Description |
|---|---|---|
| POST | `/api/v1/predict` | `{ "url": "..." }` → prediction, confidence, risk score (0-100), contributing features, model version |
| GET | `/api/v1/health` | liveness + model + DB status |
| GET | `/api/v1/history` | paginated scan history (newest first); `page`, `page_size` (max 100), `prediction` filter |
| GET | `/api/v1/history/stats` | totals per verdict and per risk band, aggregated over the whole table in one request |
| GET | `/api/v1/model-info` | model name/version, dataset, metrics (accuracy, precision, recall, F1, confusion matrix, ROC-AUC), thresholds, feature list, scan counters |

Input validation rejects non-http(s) schemes, whitespace, and oversized input (422); private/reserved/loopback targets are rejected as SSRF risks (400) — including obfuscated literals (inet_aton short forms like `127.1`, hex/octal/decimal encodings, userinfo-hidden hosts, IPv6 loopback). URLs are never fetched; the only outbound call is the DNS-over-HTTPS existence check (fail-open). There is no rate limiting: every endpoint is unlimited.

Verdict thresholds: P(phishing) ≥ 0.75 → PHISHING, ≥ 0.35 → SUSPICIOUS, else LEGITIMATE.

## Run locally

```bash
# 1. Backend
python3 -m venv venv && venv/bin/pip install -r backend/requirements.txt
venv/bin/python data/generate_dataset.py                      # synthetic benchmark: 60k realistic URLs
venv/bin/python data/prepare_dataset.py                       # PhiUSIIL -> data/phiusiil_processed (add --numeric-label-polarity 1=legitimate)
venv/bin/python data/prepare_dataset.py \
    --input data/dataset.csv --output-dir data/processed \
    --numeric-label-polarity 0=legitimate                     # benchmark -> data/processed
venv/bin/python data/merge_datasets.py \
    --phiusiil-legit-keep 0.45                                # union -> data/combined (leakage-checked)
venv/bin/python backend/training/train.py                     # LR vs RF vs XGBoost: fit=train, select=validation, one-shot test
cd backend && ../venv/bin/uvicorn app.main:app --port 8000

# 2. Frontend
cd frontend && npm install && npm run dev     # http://localhost:5173 (proxies /api → :8000)
```

Default storage is SQLite; set `DATABASE_URL=postgresql+psycopg2://user:pass@host/db` for PostgreSQL.

### Why the merge stage exists

PhiUSIIL's legitimate class is almost entirely **bare homepages** (no path,
no query). Trained on it alone, every model learns "has path ⇒ phishing" and
false-positives on every deep link — the dominant legitimate URL shape. The
synthetic benchmark contributes realistic legitimate deep links and diverse
phishing attack classes; `merge_datasets.py` pools both sources and re-splits
the union group-aware (verified 0 domain/URL overlap across splits), with an
optional seeded subsample of the homepage-legit rows
(`--phiusiil-legit-keep`) to rebalance the legitimate shape distribution.
Training artifacts land in `backend/models/` (per-model pkl + metadata + scaler), `backend/evaluation/` (validation/test metrics, threshold sweeps, ROC points), `backend/reports/` (comparison.json, training_report.md), and `backend/artifacts/model_bundle.joblib` (serving bundle; `model_metrics.json` is kept in lockstep).

## Docker

```bash
docker compose up --build      # api :8000 + postgres + web :5173
```

## Cloud deployment

A Render blueprint is included (`render.yaml`): Docker web service + free PostgreSQL, wired via `DATABASE_URL`, health check on `/api/v1/health`.

## Configuration (env vars)

`DATABASE_URL`, `PHISHING_THRESHOLD` (0.75), `SUSPICIOUS_THRESHOLD` (0.35), `DNS_CHECK_ENABLED` (true), `BRAND_IMPERSONATION_ENABLED` (true), `CORS_ORIGINS`, `HISTORY_ENABLED`, `ENVIRONMENT`.

## Tests

```bash
cd backend && ../venv/bin/python -m pytest tests/ -q
```

Covers the response contract, verdict banding, brand/DNS guardrails (mocked DNS, fail-open), SSRF rejection (incl. obfuscated loopback literals), input validation, history persistence, adversarial URL classes (legitimate, suspicious, IP-based, long, subdomain-heavy, @-trick, Unicode/IDN, special characters, reserved .invalid), and the training/serving feature-parity guarantee.
