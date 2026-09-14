"""
Dataset Generator for Phishing Website Detection.

Generates a realistic, balanced, and diverse benchmark dataset containing
both Legitimate and Phishing URLs across various industries (Banking, Tech,
Social Media, E-commerce, University, Cloud Services, and Generic Web).

Includes realistic edge-cases (e.g. legitimate domains with hyphens/queries,
and advanced HTTPS phishing URLs) to mirror real-world threat landscapes.

Labels:
- 0: Legitimate URL
- 1: Phishing URL
"""

import os
import random
import pandas as pd

# Set fixed seed for reproducibility
random.seed(42)

LEGITIMATE_DOMAINS = [
    # Search & Tech
    "google.com", "microsoft.com", "apple.com", "github.com", "gitlab.com",
    "stackoverflow.com", "wikipedia.org", "mozilla.org", "w3schools.com",
    "python.org", "apache.org", "kernel.org", "docker.com", "kubernetes.io",
    "cloudflare.com", "aws.amazon.com", "digitalocean.com", "oracle.com",
    "ibm.com", "salesforce.com", "slack.com", "atlassian.com", "zoom.us",
    "developer.android.com", "docs.github.com", "cloud.google.com",
    # Universities & Education
    "mit.edu", "stanford.edu", "harvard.edu", "cam.ac.uk", "ox.ac.uk",
    "berkeley.edu", "cmu.edu", "columbia.edu", "princeton.edu", "yale.edu",
    "cornell.edu", "caltech.edu", "toronto.edu", "ethz.ch", "iitb.ac.in",
    "iitd.ac.in", "coursera.org", "edx.org", "khanacademy.org", "udemy.com",
    # Finance & E-Commerce (Legitimate official domains)
    "paypal.com", "chase.com", "bankofamerica.com", "wellsfargo.com", "citibank.com",
    "americanexpress.com", "visa.com", "mastercard.com", "stripe.com", "shopify.com",
    "amazon.com", "ebay.com", "walmart.com", "target.com", "bestbuy.com",
    "etsy.com", "aliexpress.com", "flipkart.com", "ikea.com", "target.com",
    # News, Media & Social
    "bbc.com", "cnn.com", "nytimes.com", "theguardian.com", "reuters.com",
    "bloomberg.com", "forbes.com", "nature.com", "sciencedirect.com", "arxiv.org",
    "reddit.com", "linkedin.com", "youtube.com", "netflix.com", "spotify.com",
    "medium.com", "quora.com", "instagram.com", "pinterest.com", "vimeo.com"
]

LEGIT_PATHS = [
    "", "/", "/about", "/contact", "/terms", "/privacy", "/features",
    "/docs/quickstart", "/explore", "/articles/overview", "/library/archive",
    "/profile/settings", "/products/catalog", "/news/2026/03/update",
    "/courses/computer-science", "/research/publications", "/community/forum",
    "/api/v2/reference", "/support/help-center", "/download/latest-release",
    "/search?q=machine+learning&lang=en", "/category/technology?sort=recent",
    "/blog/post?id=1024&category=ai", "/pricing/enterprise-plan", "/team/leadership",
    # Realistic legitimate security & account paths
    "/login", "/account/overview", "/security/settings", "/auth/callback"
]

PHISHING_BRANDS = [
    "paypal", "chase", "bankofamerica", "wellsfargo", "appleid", "microsoft-support",
    "netflix-verify", "amazon-security", "facebook-recovery", "google-security",
    "instagram-badge", "coinbase-auth", "binance-wallet", "metamask-io",
    "dhl-tracking", "fedex-delivery", "usps-redelivery", "irs-tax-refund",
    "steam-community", "ebay-resolution", "dropbox-share", "outlook-exchange"
]

SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".cc", ".cfd", ".work", ".click", ".buzz", ".live",
    ".space", ".site", ".online", ".icu", ".monster", ".info", ".tk", ".ga"
]

PHISHING_PATHS = [
    "/login.php", "/secure-signin.html", "/verify-account.asp", "/wallet/confirm.php",
    "/security/update-credentials.htm", "/auth/recover-password.php", "/webscr?cmd=_login",
    "/account/identity-verification", "/update/billing-information.php",
    "/signin?token=9284028394819&redirect=secure", "/client/portal/validation.html",
    "/cgi-bin/account-unlock.cgi", "/service/confirmation?ref=urgent",
    "/banking/2fa-verification.php", "/session/expired-login.html"
]

SHORTENER_PREFIXES = [
    "https://bit.ly/", "https://tinyurl.com/", "https://t.co/", "https://is.gd/",
    "https://cutt.ly/", "https://rb.gy/", "https://shorturl.at/"
]

def generate_legitimate_url():
    """Generate a realistic legitimate URL with valid structure."""
    domain = random.choice(LEGITIMATE_DOMAINS)
    # 90% legitimate sites use HTTPS today
    scheme = "https://" if random.random() < 0.90 else "http://"
    
    # 35% chance of valid subdomain
    sub = ""
    if random.random() < 0.35:
        sub_prefix = random.choice(["www.", "support.", "api.", "docs.", "en.", "m.", "blog.", "dev.", "account."])
        sub = sub_prefix
    
    path = random.choice(LEGIT_PATHS)
    return f"{scheme}{sub}{domain}{path}"


def generate_phishing_url():
    """
    Generate a realistic phishing URL utilizing known evasion tactics:
    - IP address hosts
    - Brand typosquatting with hyphens
    - Excessive deceptive subdomains
    - Suspicious TLDs
    - Shortened redirection links
    - Path double-slashes and URL encoding
    """
    attack_type = random.choice([
        "ip_address", "typosquatting", "subdomain_spoof", "tld_abuse",
        "shortener", "obfuscated_path", "encoded_query"
    ])
    brand = random.choice(PHISHING_BRANDS)
    path = random.choice(PHISHING_PATHS)
    
    if attack_type == "ip_address":
        ip = f"{random.randint(11, 215)}.{random.randint(1, 250)}.{random.randint(1, 250)}.{random.randint(2, 254)}"
        port = f":{random.choice([8080, 8000, 8888, 3000, 8443])}" if random.random() < 0.35 else ""
        return f"http://{ip}{port}/{brand}{path}"
        
    elif attack_type == "typosquatting":
        tld = random.choice(SUSPICIOUS_TLDS + [".com", ".net", ".org"])
        prefix = random.choice(["verify-", "secure-", "update-", "auth-", "login-", "my-", "alert-", "service-"])
        suffix = random.choice(["-center", "-portal", "-security", "-manage", "-check", "-alert", "-online", ""])
        domain = f"{prefix}{brand}{suffix}{tld}"
        scheme = "http://" if random.random() < 0.65 else "https://"
        return f"{scheme}{domain}{path}"
        
    elif attack_type == "subdomain_spoof":
        legit_target = random.choice(["paypal.com", "bankofamerica.com", "apple.com", "netflix.com", "chase.com"])
        evil_domain = f"security-check{random.randint(10, 999)}{random.choice(SUSPICIOUS_TLDS)}"
        scheme = "http://" if random.random() < 0.60 else "https://"
        return f"{scheme}login.{legit_target}.{evil_domain}{path}"
        
    elif attack_type == "shortener":
        token = "".join(random.choices("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=7))
        return f"{random.choice(SHORTENER_PREFIXES)}{token}?brand={brand}"
        
    elif attack_type == "obfuscated_path":
        domain = f"{brand}-verification{random.choice(SUSPICIOUS_TLDS)}"
        return f"http://{domain}/redirect//{brand}/login.php?session_id={random.randint(100000, 999999)}"
        
    elif attack_type == "encoded_query":
        domain = f"{brand}-account-center.com"
        token = "%20" + "".join(random.choices("0123456789abcdef", k=16)) + "%3D%3D"
        return f"http://{domain}{path}?token={token}&ref=security_alert&auth=true"
        
    else: # tld_abuse
        tld = random.choice(SUSPICIOUS_TLDS)
        domain = f"{brand}{random.randint(10, 99)}{tld}"
        scheme = "https://" if random.random() < 0.40 else "http://"
        return f"{scheme}{domain}{path}"


def build_dataset(total_samples: int = 5000) -> pd.DataFrame:
    """Build a balanced dataset of legitimate (0) and phishing (1) URLs."""
    half = total_samples // 2
    
    legitimate_records = []
    seen_legit = set()
    while len(legitimate_records) < half:
        url = generate_legitimate_url()
        if url not in seen_legit:
            seen_legit.add(url)
            legitimate_records.append({
                "url": url,
                "label": 0,
                "label_name": "Legitimate"
            })
            
    phishing_records = []
    seen_phish = set()
    while len(phishing_records) < half:
        url = generate_phishing_url()
        if url not in seen_phish:
            seen_phish.add(url)
            phishing_records.append({
                "url": url,
                "label": 1,
                "label_name": "Phishing"
            })
            
    combined = legitimate_records + phishing_records
    random.shuffle(combined)
    
    df = pd.DataFrame(combined)
    return df


if __name__ == "__main__":
    current_dir = os.path.dirname(os.path.abspath(__file__))
    output_path = os.path.join(current_dir, "dataset.csv")
    
    print("Generating balanced dataset of 5,000 URLs...")
    df = build_dataset(5000)
    df.to_csv(output_path, index=False)
    
    print(f"[SUCCESS] Dataset generated and saved to: {output_path}")
    print(f"Total Records: {len(df)}")
    print("Class Distribution:")
    print(df['label_name'].value_counts())
