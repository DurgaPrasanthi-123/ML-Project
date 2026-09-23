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

# Free/anonymous hosting platforms frequently abused for phishing kits
FREE_HOSTS = [
    "weebly.com", "wixsite.com", "000webhostapp.com", "infinityfreeapp.com",
    "rf.gd", "unaux.com", "ueniweb.com", "jimdofree.com", "glitch.me",
    "netlify.app", "vercel.app", "firebaseapp.com", "blogspot.com",
    "github.io", "byethost.com", "b-cdn.net", "herokuapp.com"
]

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

# Subdomain prefixes that are NORMAL on legitimate multi-service domains
LEGIT_SUBDOMAINS = [
    "www", "support", "api", "docs", "en", "m", "blog", "dev", "account",
    "mail", "shop", "help", "portal", "app", "cdn", "assets", "img",
    "news", "forum", "wiki", "store", "pay", "secure", "login", "auth",
    "accounts", "billing", "sandbox", "staging", "test", "beta"
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
    "/login", "/account/overview", "/security/settings", "/auth/callback",
    # Very short deep links (1-2 char segments) — common on real sites and a
    # historic FP trigger: models must learn short paths are class-neutral.
    "/3/", "/e/", "/x1", "/a/b", "/p/42", "/d/3", "/id/7", "/en/us",
    "/downloads/", "/en-US/", "/blog/", "/wiki/", "/docs/", "/api/",
    # Hyphenated, underscored and numeric-path shapes (neutral in real traffic)
    "/user-guide/manual", "/about-us/team", "/products/sale_items",
    "/year/2026/page/12", "/post/2024/10/15/notes", "/v1/users/8842",
    # Trailing-slash and bare-directory variants
    "/jobs/", "/help/", "/archive/2025/", "/shop/catalog/",
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
    
    # 45% chance of valid subdomain (incl. deep but genuine hierarchies)
    sub = ""
    if random.random() < 0.45:
        depth = random.choice([1, 1, 1, 2])
        subs = [random.choice(LEGIT_SUBDOMAINS) for _ in range(depth)]
        sub = ".".join(subs) + "."
    
    path = random.choice(LEGIT_PATHS)

    # 15% of legit URLs carry tracking/query parameters (utm, session ids)
    if random.random() < 0.15 and path:
        sep = "&" if "?" in path else "?"
        tracking = random.choice([
            "utm_source=google&utm_medium=cpc",
            "utm_source=newsletter&id=88213",
            "ref=homepage&session=abc123",
            "lang=en&region=us",
        ])
        path = f"{path}{sep}{tracking}"

    # 8% of legit URLs use a numeric-but-plausible host (e.g. mirror nodes)
    if random.random() < 0.08:
        host = domain.split("/")[0]
        domain = domain.replace(host, f"{host}", 1) if not host[0].isdigit() else domain

    return f"{scheme}{sub}{domain}{path}"


def generate_legitimate_brand_mention_url():
    """
    Generate a LEGITIMATE URL that merely *mentions* a security brand in its
    path/query (news article, help page, merchant listing). These must NOT be
    flagged: the brand appears on an official multi-label domain, never in a
    subdomain of an unrelated registrable domain.
    """
    domain = random.choice(LEGITIMATE_DOMAINS)
    brand_topic = random.choice([
        "paypal", "stripe", "coinbase", "docusign", "netflix", "amazon",
        "apple", "microsoft", "google", "facebook"
    ])
    path = random.choice([
        f"/news/2026/{brand_topic}-announces-new-features",
        f"/articles/how-to-use-{brand_topic}-safely",
        f"/compare/{brand_topic}-vs-competitors",
        f"/support/does-{brand_topic}-support-2fa",
        f"/wiki/{brand_topic}",
        f"/blog/merchant-guide?provider={brand_topic}",
        f"/reviews/{brand_topic}-alternative",
    ])
    scheme = "https://" if random.random() < 0.9 else "http://"
    sub = "www." if random.random() < 0.5 else ""
    return f"{scheme}{sub}{domain}{path}"


def generate_phishing_url():
    """
    Generate a realistic phishing URL utilizing known evasion tactics:
    - IP address hosts (incl. https and numeric-heavy hosts)
    - Brand typosquatting with hyphens
    - Excessive deceptive subdomains (varied, not one fixed template)
    - Free/anonymous hosting with brand-branded subdomains
    - Suspicious TLDs
    - Shortened redirection links
    - Path double-slashes and URL encoding
    - Brand token in hostname chain (docusign-demo.auth-verify.click)
    """
    attack_type = random.choice([
        "ip_address", "typosquatting", "subdomain_spoof", "tld_abuse",
        "shortener", "obfuscated_path", "encoded_query",
        "free_host", "https_subdomain_spoof", "brand_token_host"
    ])
    brand = random.choice(PHISHING_BRANDS)
    path = random.choice(PHISHING_PATHS)
    
    if attack_type == "ip_address":
        ip = f"{random.randint(11, 215)}.{random.randint(1, 250)}.{random.randint(1, 250)}.{random.randint(2, 254)}"
        port = f":{random.choice([8080, 8000, 8888, 3000, 8443])}" if random.random() < 0.35 else ""
        scheme = "http://" if random.random() < 0.8 else "https://"
        return f"{scheme}{ip}{port}/{brand}{path}"
        
    elif attack_type == "typosquatting":
        tld = random.choice(SUSPICIOUS_TLDS + [".com", ".net", ".org"])
        prefix = random.choice(["verify-", "secure-", "update-", "auth-", "login-", "my-", "alert-", "service-"])
        suffix = random.choice(["-center", "-portal", "-security", "-manage", "-check", "-alert", "-online", ""])
        domain = f"{prefix}{brand}{suffix}{tld}"
        scheme = "http://" if random.random() < 0.65 else "https://"
        return f"{scheme}{domain}{path}"
        
    elif attack_type == "subdomain_spoof":
        legit_target = random.choice(["paypal.com", "bankofamerica.com", "apple.com", "netflix.com", "chase.com",
                                      "wellsfargo.com", "amazon.com", "microsoft.com", "google.com", "coinbase.com"])
        evil_domains = [
            f"security-check{random.randint(10, 999)}{random.choice(SUSPICIOUS_TLDS)}",
            f"session-{random.randint(100000, 999999)}{random.choice(SUSPICIOUS_TLDS)}",
            f"{brand}-update{random.randint(10, 99)}{random.choice(SUSPICIOUS_TLDS)}",
            f"account-verify-{random.randint(1000, 9999)}{random.choice(SUSPICIOUS_TLDS)}",
            f"cdn-auth{random.randint(10, 99)}{random.choice(SUSPICIOUS_TLDS)}",
        ]
        prefixes = ["login.", "secure.", "account.", "verify.", "auth.", "signin.", "", "my."]
        scheme = "http://" if random.random() < 0.60 else "https://"
        return f"{scheme}{random.choice(prefixes)}{legit_target}.{random.choice(evil_domains)}{path}"
        
    elif attack_type == "free_host":
        # Brand keyword as subdomain on a free host: mail-suspended-account.weebly.com
        host = random.choice(FREE_HOSTS)
        sub = random.choice([
            f"{brand}-support", f"user-{brand}", f"{brand}-login",
            f"mail-{brand}-account", f"{brand}-verification",
        ])
        scheme = "https://" if random.random() < 0.75 else "http://"
        return f"{scheme}{sub}.{host}/{random.choice(['', 'verify.php', 'login.html', 'confirm-account'])}"

    elif attack_type == "https_subdomain_spoof":
        # The hardest FN class: HTTPS + clean-looking brand subdomain + short path
        legit_target = random.choice(["paypal.com", "chase.com", "apple.com", "netflix.com", "docusign.com"])
        evil_tld = random.choice([".xyz", ".top", ".click", ".icu", ".cfd", ".live"])
        style = random.choice([
            f"login.{legit_target}.session-{random.randint(100000,999999)}{evil_tld}",
            f"{legit_target}.verify-id{random.randint(1000,9999)}{evil_tld}",
            f"secure-login.{legit_target}.account-update{evil_tld}",
            f"{legit_target}.{random.choice(['auth-verify1', 'support-centre', 'client-portal'])}{evil_tld}",
        ])
        return f"https://{style}{random.choice(['/login', '/signin/verify.php', '/', '/confirm'])}"

    elif attack_type == "brand_token_host":
        # Brand token embedded in a hyphenated hostname chain
        tld = random.choice(SUSPICIOUS_TLDS + [".click", ".com"])
        host = random.choice([
            f"app-us1.mailed-by-verify{tld}",
            f"{brand}-demo-user1.auth-verify{random.randint(1,9)}{tld}",
            f"ww1.{brand}id{tld}",
            f"ref{random.randint(1,9)}.{brand}-steam{tld}",
        ])
        scheme = "https://" if random.random() < 0.7 else "http://"
        return f"{scheme}{host}{path}"
        
    elif attack_type == "shortener":
        token = "".join(random.choices("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=7))
        # Half of shortener phish carry a brand/credential context param
        if random.random() < 0.5:
            return f"{random.choice(SHORTENER_PREFIXES)}{token}?brand={brand}"
        return f"{random.choice(SHORTENER_PREFIXES)}{token}"
        
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


def build_dataset(total_samples: int = 60000) -> pd.DataFrame:
    """Build a balanced dataset of legitimate (0) and phishing (1) URLs.

    Default 60,000 rows: when merged with PhiUSIIL (~233K rows of bare
    homepage legit URLs), this share of deep-link legitimate traffic is large
    enough to prevent path/query-bearing URLs from being learned as phishing
    indicators, while keeping the source's real-world phishing diversity.
    """
    half = total_samples // 2
    
    legitimate_records = []
    seen_legit = set()
    while len(legitimate_records) < half:
        # 12% of legitimate side: brand *mentions* on reputable domains
        if random.random() < 0.12:
            url = generate_legitimate_brand_mention_url()
        else:
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

    print("Generating balanced dataset of 60,000 URLs...")
    df = build_dataset(60000)
    df.to_csv(output_path, index=False)
    
    print(f"[SUCCESS] Dataset generated and saved to: {output_path}")
    print(f"Total Records: {len(df)}")
    print("Class Distribution:")
    print(df['label_name'].value_counts())
