"""
Temporary reproduction script (step 18 of the audit requirement).
Traces one URL through: frontend-style input -> validate_url -> feature
extraction -> model -> response, and prints intermediate values.
Run: python reproduce_bug.py
"""

import pandas as pd
import joblib
import json
from app import app, validate_url, model, feature_config
from utils.feature_extraction import extract_features_dict, get_feature_names

# The class of URLs that were misclassified as LEGITIMATE by the old model:
# subdomain_spoof with brand in subdomain, few dots/hyphens in registrable part,
# https, short path, no '@', no shortener, no '//'.
CASES = [
    # (url, expected)
    ("https://login.paypal.com.session-928431.xyz/login?cmd=account-login", "Phishing"),
    ("https://www.chase.com/personal/banking", "Legitimate"),
    ("http://paypal.com.verify-id1982.top/signin/verify.php", "Phishing"),
    ("https://en.wikipedia.org/wiki/Machine_learning", "Legitimate"),
]

print("=" * 78)
print(" REPRODUCTION: tracing URLs through the existing pipeline")
print("=" * 78)

for url, expected in CASES:
    ok, msg = validate_url(url)
    print(f"\nURL: {url}")
    print(f"  validate_url -> ({ok}, {msg!r})")
    if not ok:
        print("  !! rejected by validation, cannot trace further")
        continue
    feats = extract_features_dict(url)
    row = pd.DataFrame([feats], columns=feature_config.get("feature_names", get_feature_names()))
    prob = model.predict_proba(row)[0]
    pred = int(model.predict(row)[0])
    print(f"  features      -> {json.dumps(feats)}")
    print(f"  P(legit)={prob[0]:.4f}  P(phish)={prob[1]:.4f}  predict()={pred}")
    print(f"  EXPECTED={expected}  ACTUAL={'Phishing' if pred == 1 else 'Legitimate'}"
          f"  {'OK' if (pred == 1) == (expected == 'Phishing') else '  <-- MISCLASSIFIED'}")
