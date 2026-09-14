# College Viva Voce & Defense Preparation Guide

### Project Title: Phishing Website Detection using Machine Learning

---

## 1. High-Level Project Overview
**Q: Can you explain your project in 2-3 sentences?**  
> "Our project is a cybersecurity web application that detects whether a given website URL is **Legitimate** or **Phishing** using Machine Learning. The system extracts 17 passive lexical and structural features from the URL without ever visiting the remote server, and feeds them into a trained Random Forest classifier that achieves high empirical accuracy on a balanced dataset."

---

## 2. Technical Architecture & Data Flow
**Q: What happens when a user clicks 'Analyze URL'? (Trace the complete lifecycle)**  
1. **Client Input**: The user enters a URL on the HTML5/Bootstrap frontend and submits the form.
2. **Client Validation & Fetch**: JavaScript intercepts the submit event, validates non-empty format, displays a loading spinner, and sends an asynchronous `POST` request with JSON payload `{"url": "..."}` to the Flask endpoint `/predict`.
3. **Backend Sanitization**: Flask receives the request, strips whitespace, parses the URL structure via `urllib.parse`, and validates against forbidden schemes (`javascript:`, `data:`).
4. **Passive Feature Extraction**: The backend passes the URL to `utils/feature_extraction.py`. Exactly 17 numerical/binary features are computed (e.g., domain length, IP presence, subdomain depth, hyphen count, sensitive keyword frequency).
5. **Model Inference**: The feature vector is passed to the serialized Random Forest classifier (`phishing_model.pkl`). The model runs inference through 120 decision trees.
6. **Probability Calibration**: The model computes the posterior probability using `predict_proba()` to determine the confidence score (e.g., 99.2%).
7. **JSON Response**: Flask returns `{ "status": "success", "prediction": "Phishing", "confidence": 99.2, "reasons": [...] }`.
8. **DOM Rendering**: JavaScript parses the JSON and renders the verdict card (`✓ Legitimate` or `⚠ Phishing`), confidence gauge, and threat indicators without reloading the page.

---

## 3. Machine Learning Questions

**Q: Why did you choose Random Forest over single Decision Trees or Logistic Regression?**  
> "Logistic Regression is a linear classifier that struggles with non-linear combinations of URL features. Single Decision Trees are prone to high variance and overfitting on training data. Random Forest solves this using **ensemble bagging** (Bootstrap Aggregating). It builds 120 diverse decision trees on random data subsets and random feature subsets, reducing variance and producing robust probability estimates."

**Q: Why is feature extraction strictly passive (offline)? Why not scrape or visit the webpage?**  
> "Connecting to untrusted, unknown URLs introduces severe cybersecurity vulnerabilities:
> 1. The remote server could deliver drive-by malware, browser exploits, or malicious payloads directly to our server.
> 2. Attackers can fingerprint the crawler's IP address and deliver a fake benign page (cloaking).
> 3. Network requests introduce latency (DNS resolution, TCP handshake, HTTP fetching). Passive lexical analysis executes in under 15 milliseconds and is completely immune to remote exploits."

**Q: What are the 17 features you extracted?**  
1. `url_length`: Overall character length.
2. `domain_length`: Length of the hostname.
3. `count_dots`: Count of `.` characters.
4. `count_hyphens`: Count of `-` characters (indicates brand typosquatting).
5. `count_at`: Presence of `@` (tricks browsers to ignore prefix userinfo).
6. `count_question`: Count of `?` query parameters.
7. `count_percent`: Count of `%` URL hex encoding indicators.
8. `count_equal`: Count of `=` parameter assignments.
9. `count_slash`: Count of `/` path delimiters.
10. `count_digits`: Total numeric digits in URL.
11. `digit_ratio`: Ratio of digits to total characters.
12. `is_ip_address`: Binary flag indicating if hostname is an IPv4/IPv6 address.
13. `has_https`: Binary flag indicating secure HTTPS protocol.
14. `count_subdomains`: Depth of nested subdomain levels.
15. `has_suspicious_keywords`: Frequency of keywords (`login`, `verify`, `account`, `banking`, `wallet`).
16. `is_shortened`: Binary check against known shortening domains (`bit.ly`, `tinyurl.com`, etc.).
17. `has_double_slash_path`: Binary check for `//` path evasion tricks.

**Q: How did you evaluate your models?**  
> "We evaluated the models using an 80/20 stratified train-test split. We measured:
> - **Accuracy**: Overall correct classifications.
> - **Precision**: Of all URLs predicted as phishing, how many were truly phishing (minimizing False Positives so legitimate sites aren't blocked).
> - **Recall (Sensitivity)**: Of all actual phishing URLs, how many did the model catch (minimizing False Negatives).
> - **F1-Score**: The harmonic mean of Precision and Recall.
> - **ROC-AUC**: Area under the Receiver Operating Characteristic curve."

**Q: Which metric is more important in phishing detection: Precision or Recall?**  
> "Both are critical, but in cybersecurity:
> - Low Recall means malicious phishing sites slip past undetected, endangering user credentials.
> - Low Precision means legitimate websites are falsely blocked, frustrating users.
> Therefore, we optimize for **F1-score**, which balances both."

---

## 4. Web & Software Engineering Questions

**Q: How is the Flask backend structured?**  
> "The backend in `app.py` serves two functions:
> 1. **Web Server**: Renders modern responsive Jinja2 templates for Home (`/`), URL Detector (`/detector`), About (`/about`), and How It Works (`/how-it-works`).
> 2. **REST API**: Exposes `POST /predict` (accepting and returning JSON) and `GET /api/metrics` (returning real model benchmark figures).
> It incorporates input sanitization, error handling (400, 404, 500), and loads the ML model at server initialization using `joblib`."

**Q: Why use AJAX `fetch()` instead of standard HTML form submission?**  
> "Standard form submissions cause a full page reload, clearing user input and degrading the user experience. By using asynchronous `fetch()`, we send the payload in the background, display an animated scanning spinner, and seamlessly inject the prediction card and threat indicators directly into the DOM."

---

## 5. Security & Limitations

**Q: What are the limitations of your system?**  
> "1. It analyzes URL structure only, not the webpage content, DOM, or visual design.
> 2. If a legitimate high-reputation domain is compromised (e.g. via an unpatched WordPress plugin) and hosts a phishing page inside a normal-looking path, lexical heuristics alone may produce a false negative.
> 3. Adversarial attackers may craft URLs that intentionally mimic benign naming conventions."

**Q: How can this project be enhanced in the future?**  
> "1. Packaging the model into a Google Chrome Extension for live, client-side protection during browsing.
> 2. Incorporating WHOIS domain age lookup (newly registered domains under 14 days old have a high correlation with phishing).
> 3. Exploring Deep Learning architectures (such as 1D CNNs or Char-LSTM) to learn character-level embeddings directly from raw URL strings."
