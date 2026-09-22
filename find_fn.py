"""
Find actual false negatives of the OLD pipeline using the OLD 80/20 split.
"""
import os, sys, joblib
import pandas as pd
from sklearn.model_selection import train_test_split

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from utils.feature_extraction import extract_features_dict, get_feature_names

df = pd.read_csv("data/dataset.csv")
fnames = get_feature_names()
X = pd.DataFrame([extract_features_dict(str(u)) for u in df["url"]], columns=fnames)
y = df["label"]

X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.20, random_state=42, stratify=y)

model = joblib.load("model/phishing_model.pkl")
# The model was trained on rows in shuffled order matching this split; retrain a clone to be sure
from sklearn.ensemble import RandomForestClassifier
m = RandomForestClassifier(n_estimators=120, max_depth=16, random_state=42, n_jobs=-1)
m.fit(X_tr, y_tr)
pred = m.predict(X_te)

urls_te = df.loc[y_te.index, "url"].values
fn = [(u, p) for u, t, p in zip(urls_te, y_te.values, pred) if t == 1 and p == 0]
fp = [(u, p) for u, t, p in zip(urls_te, y_te.values, pred) if t == 0 and p == 1]

from collections import Counter
def classify_fn(url):
    if any(c.isdigit() for c in url.split("/")[2].split(".")[0]) and url.startswith("http://"):
        pass
    host = url.split("/")[2]
    if host[0].isdigit():
        return "ip_host"
    if host.count(".") >= 3:
        return "subdomain_spoof"
    if "bit.ly" in host or "tinyurl" in host or "t.co" in host:
        return "shortener"
    if "//" in url.split("/", 3)[-1]:
        return "obfuscated"
    if "%" in url:
        return "encoded"
    return "typosquat/tld"

print(f"FALSE NEGATIVES: {len(fn)} / {sum(y_te.values)}")
for u, _ in fn[:15]:
    print("  FN:", u)
print(Counter(classify_fn(u) for u, _ in fn))
print(f"\nFALSE POSITIVES: {len(fp)} / {sum(1 - y_te.values)}")
for u, _ in fp[:15]:
    print("  FP:", u)
