"""
Probe the DEPLOYED model with realistic phishing/suspicious URLs whose patterns
are NOT in the synthetic generator's repertoire -> find real false negatives.
"""
import joblib
import pandas as pd
from app import model, feature_config
from utils.feature_extraction import extract_features_dict, get_feature_names

PROBES = [
    # (url, expected, why)
    ("https://www.paypal.com/signin", "Legit", "real brand + login path (should be legit)"),
    ("https://www.netflix.com/login", "Legit", "real brand + login path"),
    ("https://github.com/login", "Legit", "real brand + login path"),
    ("https://steamcommunity.com/openid/login?l=english", "Legit", "openid login path"),
    ("https://outlook.office365.com/owa/", "Legit", "office365"),
    ("https://accounts.google.com/v3/Signin/challenge/pwd/Universal?continue=https%3A%2F%2Fmail.google.com", "Legit", "google signin w/ encoding"),
    ("https://www.wellsfargo.com/checking/", "Legit", "bank product page"),
    ("https://editorial.ipsusa.org/docs/ContactUs/LoginPage.aspx?ReturnUrl=%2f_includes%2fassets%2fjs%2findex.php", "Phish", "real-world phishkit style: subdomain imposter + ReturnUrl=// redirect"),
    ("https://diakonia-kenya.org/wp-content/plugins/onefile/Confirmation/instruction/confirm.php", "Phish", "compromised legit-domain path phish"),
    ("https://docusign-demo-user1.auth-verify1.click/signing/?utm_source=test", "Phish", "docusign brand on .click TLD"),
    ("https://mail-suspended-account.weebly.com/", "Phish", "brand keyword on free host"),
    ("https://3509662731.urelay.co/mf/verify.php?token=8d8f637e5b3ec", "Phish", "numeric host + verify path (real feodo pattern)"),
    ("https://www.rbcroyalbank.com", "Legit", "plain bank domain"),
    ("http://esunbank.com.tw.box1229.sin1.v.vivomall999.top/", "Phish", "legit bank embedded in subdomain of evil domain"),
    ("https://pure-blood-mu.b-cdn.net/wp-content/themes/twentyfifteen/vpostal/verify.php", "Phish", "CDN host + verify path"),
    ("https://user-paypal-support.ueniweb.com/", "Phish", "paypal keyword subdomain on free host"),
    ("https://ref7.brownellsteam.com/?email=verify%40gmail.com", "Phish", "encoded email + verify param"),
    ("https://app-us1.mailed-by-verify.com/c/60000000/verify-account", "Phish", "verify in hostname chain"),
    ("https://www.bankofamerica.com/", "Legit", "plain bank"),
    ("https://ww1.streamhub-appleid.xyz/", "Phish", "appleid typo domain + ww1"),
]

fnames = feature_config.get("feature_names", get_feature_names())
print(f"{'EXPECTED':<8} {'PRED':<11} {'P(phish)':<9} URL")
fn_count = 0
for url, expected, why in PROBES:
    feats = extract_features_dict(url)
    row = pd.DataFrame([feats], columns=fnames)
    prob = model.predict_proba(row)[0]
    pred = "Phishing" if prob[1] > 0.5 else "Legitimate"
    is_fn = (expected == "Phish" and pred == "Legitimate")
    is_fp = (expected == "Legit" and pred == "Phishing")
    flag = " <-- FN" if is_fn else (" <-- FP" if is_fp else "")
    if is_fn:
        fn_count += 1
    print(f"{expected:<8} {pred:<11} {prob[1]:.3f}    {url}{flag}")
    if is_fn or is_fp:
        print(f"         why: {why}")
print(f"\nFALSE NEGATIVES: {fn_count}")
