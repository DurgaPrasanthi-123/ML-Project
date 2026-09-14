"""
Feature Extraction Module for Phishing Website Detection.

Extracts lexical, structural, and heuristic features from URLs strictly
using passive string and syntax analysis. No network connections are made
to the target URL, guaranteeing safety and high performance.
"""

import re
import ipaddress
from urllib.parse import urlparse

# List of known URL shortening domains
SHORTENING_SERVICES = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "bit.do", "cutt.ly", "rb.gy", "shorturl.at",
    "tiny.cc", "lnkd.in", "rebrand.ly", "soo.gd", "s.id"
}

# Suspicious keywords commonly observed in phishing attempts
SUSPICIOUS_KEYWORDS = [
    "login", "verify", "verification", "account", "banking", "secure",
    "update", "signin", "sign-in", "confirm", "confirmation", "wallet",
    "paypal", "admin", "recover", "password", "authenticate", "webscr",
    "billing", "ebay", "support", "service", "suspended", "validation"
]

FEATURE_NAMES = [
    "url_length",
    "domain_length",
    "count_dots",
    "count_hyphens",
    "count_at",
    "count_question",
    "count_percent",
    "count_equal",
    "count_slash",
    "count_digits",
    "digit_ratio",
    "is_ip_address",
    "has_https",
    "count_subdomains",
    "has_suspicious_keywords",
    "is_shortened",
    "has_double_slash_path"
]


def get_feature_names():
    """Return the ordered list of feature names used by models."""
    return list(FEATURE_NAMES)


def clean_url(url: str) -> str:
    """Ensure URL has a scheme for standard parsing."""
    url = url.strip()
    if not url.startswith("http://") and not url.startswith("https://"):
        # Default to http:// if scheme omitted
        url = "http://" + url
    return url


def is_ip(hostname: str) -> int:
    """Check if the hostname is a valid IPv4 or IPv6 address."""
    if not hostname:
        return 0
    # Strip port if present in hostname
    host_clean = hostname.split(":")[0]
    try:
        ipaddress.ip_address(host_clean)
        return 1
    except ValueError:
        return 0


def count_subdomain_levels(hostname: str) -> int:
    """
    Calculate number of subdomain levels.
    e.g., example.com -> 0
    sub.example.com -> 1
    a.b.example.com -> 2
    """
    if not hostname:
        return 0
    parts = hostname.split(".")
    # Basic check for typical domain (subdomains + domain + TLD)
    if len(parts) <= 2:
        return 0
    return len(parts) - 2


def extract_features_dict(url: str) -> dict:
    """
    Extract a dictionary of numerical features and metadata from a URL.
    """
    cleaned = clean_url(url)
    parsed = urlparse(cleaned)

    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""
    full_url = cleaned.lower()

    # 1. Length features
    url_length = len(full_url)
    domain_length = len(hostname)

    # 2. Character counts
    count_dots = full_url.count(".")
    count_hyphens = full_url.count("-")
    count_at = full_url.count("@")
    count_question = full_url.count("?")
    count_percent = full_url.count("%")
    count_equal = full_url.count("=")
    count_slash = full_url.count("/")

    # 3. Digit metrics
    digits = sum(c.isdigit() for c in full_url)
    digit_ratio = round(digits / url_length, 4) if url_length > 0 else 0.0

    # 4. Hostname characteristics
    ip_flag = is_ip(hostname)
    https_flag = 1 if parsed.scheme.lower() == "https" else 0
    subdomain_count = count_subdomain_levels(hostname)

    # 5. Suspicious keywords count in path, query, or hostname
    keyword_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in full_url)

    # 6. URL Shortening check
    shortened_flag = 1 if hostname in SHORTENING_SERVICES else 0

    # 7. Redirection indicator (// in path)
    double_slash_path = 1 if "//" in path else 0

    return {
        "url_length": url_length,
        "domain_length": domain_length,
        "count_dots": count_dots,
        "count_hyphens": count_hyphens,
        "count_at": count_at,
        "count_question": count_question,
        "count_percent": count_percent,
        "count_equal": count_equal,
        "count_slash": count_slash,
        "count_digits": digits,
        "digit_ratio": digit_ratio,
        "is_ip_address": ip_flag,
        "has_https": https_flag,
        "count_subdomains": subdomain_count,
        "has_suspicious_keywords": keyword_count,
        "is_shortened": shortened_flag,
        "has_double_slash_path": double_slash_path,
    }


def extract_features_vector(url: str, feature_names=None):
    """
    Extract features as an ordered list matching feature_names.
    """
    if feature_names is None:
        feature_names = FEATURE_NAMES

    feat_dict = extract_features_dict(url)
    return [feat_dict[name] for name in feature_names]


def explain_features(features: dict, prediction: str) -> list:
    """
    Generate human-interpretable reasons and safety indicators for the prediction.
    Useful for college presentations and user transparency.
    """
    explanations = []

    if features.get("is_ip_address") == 1:
        explanations.append({
            "type": "danger",
            "title": "Raw IP Address Hostname",
            "desc": "The URL uses a raw numeric IP address instead of a registered domain name, a hallmark of malicious phishing hosts."
        })

    if features.get("count_at", 0) > 0:
        explanations.append({
            "type": "danger",
            "title": "Use of '@' Symbol",
            "desc": "The '@' symbol causes web browsers to ignore preceding text, often tricking users about the actual destination domain."
        })

    if features.get("is_shortened") == 1:
        explanations.append({
            "type": "warning",
            "title": "URL Shortener Service",
            "desc": "URL is shortened through a redirect service, which obscures the genuine final destination domain."
        })

    if features.get("has_double_slash_path") == 1:
        explanations.append({
            "type": "danger",
            "title": "Redirection '//' in Path",
            "desc": "Presence of '//' inside the URL path indicates an attempt to redirect traffic to an external malicious server."
        })

    if features.get("has_suspicious_keywords", 0) > 1:
        explanations.append({
            "type": "warning",
            "title": "High-Risk Security Keywords",
            "desc": f"Contains {features.get('has_suspicious_keywords')} sensitive keywords (e.g. login, verify, banking, secure) frequently used in credential harvesting."
        })

    if features.get("count_subdomains", 0) >= 3:
        explanations.append({
            "type": "warning",
            "title": "Excessive Subdomain Nesting",
            "desc": f"The domain has {features.get('count_subdomains')} nested subdomain levels, often used to spoof legitimate brand structures."
        })

    if features.get("count_hyphens", 0) >= 3:
        explanations.append({
            "type": "warning",
            "title": "Multiple Hyphens in Domain",
            "desc": "Frequent hyphens are commonly used in typo-squatting attacks (e.g. 'paypal-update-account-center')."
        })

    if features.get("url_length", 0) > 85:
        explanations.append({
            "type": "warning",
            "title": "Abnormally Long URL",
            "desc": f"URL length is {features.get('url_length')} characters, which is typical for query strings hiding malicious tracking tokens."
        })

    # Positive safety indicators
    if features.get("has_https") == 1:
        explanations.append({
            "type": "success",
            "title": "Encrypted Connection (HTTPS)",
            "desc": "Uses HTTPS encryption protocol, securing communication in transit."
        })
    else:
        explanations.append({
            "type": "warning",
            "title": "Insecure Protocol (HTTP)",
            "desc": "Does not use HTTPS encryption, leaving data vulnerable in plaintext."
        })

    if features.get("count_subdomains", 0) <= 1 and features.get("count_hyphens", 0) == 0 and features.get("count_at", 0) == 0:
        explanations.append({
            "type": "success",
            "title": "Standard Domain Hierarchy",
            "desc": "Domain name structure is concise and follows standard enterprise DNS naming patterns."
        })

    return explanations
