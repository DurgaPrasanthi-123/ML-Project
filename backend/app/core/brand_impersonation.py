"""
Brand impersonation detection module.

Detects phishing domains that imitate well-known services using:
1. Character-level similarity of the REGISTRABLE DOMAIN against a curated
   brand list (leetspeak/typosquatting: paypa1, micr0soft, g00gle, faceb00k,
   amaz0n, netf1ix, app1e ...).
2. Brand names appearing in SUBDOMAINS or PATHS of an unrelated registrable
   domain (paypal-login.example.com, microsoft-security.example.com) or in the
   registrable domain as a prefix/suffix compound (secure-paypal-login.net).

Key safety property: if the registrable domain IS the brand's official domain,
nothing is flagged. A brand merely *mentioned* (e.g. a news article about
PayPal) on a reputable domain is not impersonation — multiple signals are
combined (brand presence + credential context + suspicious hosting) before
raising the risk weight.
"""

import re
from difflib import SequenceMatcher
from functools import lru_cache

from app.core.url_parser import ParsedURL

# Official registrable domains of well-known brands.
BRAND_DOMAINS = {
    "paypal": ["paypal.com"],
    "stripe": ["stripe.com"],
    "chase": ["chase.com"],
    "wellsfargo": ["wellsfargo.com"],
    "bankofamerica": ["bankofamerica.com"],
    "citibank": ["citi.com", "citibank.com"],
    "americanexpress": ["americanexpress.com"],
    "hsbc": ["hsbc.com"],
    "barclays": ["barclays.co.uk"],
    "santander": ["santander.com"],
    "rbc": ["rbcroyalbank.com"],
    "coinbase": ["coinbase.com"],
    "binance": ["binance.com"],
    "metamask": ["metamask.io"],
    "ledger": ["ledger.com"],
    "microsoft": ["microsoft.com", "live.com", "office.com", "office365.com", "outlook.com"],
    "office365": ["office.com", "office365.com", "microsoft.com"],
    "outlook": ["outlook.com", "live.com", "microsoft.com"],
    "onedrive": ["onedrive.live.com", "microsoft.com"],
    "google": ["google.com", "googlemail.com", "youtube.com", "android.com"],
    "gmail": ["google.com", "googlemail.com"],
    "youtube": ["youtube.com"],
    "apple": ["apple.com", "icloud.com"],
    "icloud": ["icloud.com", "apple.com"],
    "amazon": ["amazon.com", "amazon.co.uk", "amazon.de", "aws.amazon.com"],
    "aws": ["aws.amazon.com", "amazon.com"],
    "netflix": ["netflix.com"],
    "facebook": ["facebook.com", "fb.com"],
    "instagram": ["instagram.com"],
    "whatsapp": ["whatsapp.com"],
    "twitter": ["twitter.com", "x.com"],
    "linkedin": ["linkedin.com"],
    "tiktok": ["tiktok.com"],
    "docusign": ["docusign.com", "docusign.net"],
    "adobe": ["adobe.com"],
    "dropbox": ["dropbox.com"],
    "zoom": ["zoom.us"],
    "steam": ["steampowered.com", "steamcommunity.com"],
    "roblox": ["roblox.com"],
    "fedex": ["fedex.com"],
    "ups": ["ups.com"],
    "dhl": ["dhl.com"],
    "usps": ["usps.com"],
    "royalmail": ["royalmail.com"],
    "irs": ["irs.gov"],
    "hmrc": ["gov.uk"],
    "revolut": ["revolut.com"],
    "washingtonfederal": ["wafdbank.com"],
    "sparkasse": ["sparkasse.de"],
    "anpost": ["anpost.ie"],
    "telstra": ["telstra.com.au"],
    "nab": ["nab.com.au"],
    "commsec": ["commsec.com.au"],
}

# Leetspeak normalization: common character substitutions used to evade
# naive string matching while preserving visual appearance.
LEET_TABLE = str.maketrans({
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t",
    "8": "b", "9": "g", "@": "a", "$": "s", "!": "i", "|": "l",
    "\u0131": "i",  # dotless i
    "\u0456": "i",  # cyrillic і
    "\u0430": "a",  # cyrillic a
    "\u0435": "e",  # cyrillic e
    "\u043e": "o",  # cyrillic o
    "\u0440": "p",  # cyrillic p
    "\u0441": "c",  # cyrillic c
    "\u0443": "y",  # cyrillic y
    "\u04bb": "h",  # cyrillic h
    "\u0391": "a", "\u0395": "e", "\u039f": "o", "\u03a1": "p",
})


def _clean(label: str) -> str:
    """Normalize a label for comparison: lowercase, strip non-alphanumerics,
    undo leetspeak and homoglyphs."""
    s = re.sub(r"[^a-z0-9]", "", label.lower())
    return s.translate(LEET_TABLE)


@lru_cache(maxsize=4096)
def _best_brand_match(clean_label: str) -> tuple[str | None, float]:
    """Return (brand, similarity) of the closest brand for a cleaned label."""
    if len(clean_label) < 4:
        return None, 0.0
    best, best_score = None, 0.0
    for brand in BRAND_DOMAINS:
        b = brand
        if clean_label == b:
            return brand, 1.0
        # substring containment both ways counts as a match candidate
        if b in clean_label or clean_label in b:
            score = SequenceMatcher(None, clean_label, b).ratio()
        else:
            score = SequenceMatcher(None, clean_label, b).ratio()
            if score < 0.80:
                continue
        if score > best_score:
            best, best_score = brand, score
    return best, best_score


def _official_domains(brand: str) -> set:
    return {d.lower() for d in BRAND_DOMAINS.get(brand, [])}


def analyze_brand_impersonation(p: ParsedURL) -> dict:
    """
    Analyze a parsed URL for brand impersonation. Returns a structured result:

    {
      "is_impersonation": bool,
      "brand": str | None,
      "techniques": [ ... ],
      "confidence": float,   # 0..1 aggregate
      "official_domain": bool  # the URL belongs to the brand itself
    }
    """
    result = {
        "is_impersonation": False,
        "brand": None,
        "techniques": [],
        "confidence": 0.0,
        "official_domain": False,
    }
    if not p.hostname or p.is_ip:
        return result

    reg_domain = p.registrable_domain or p.hostname
    reg_clean = _clean(reg_domain.split(".")[0] if reg_domain else "")

    # ------------------------------------------------------------------ #
    # Step 1: does the registrable domain itself belong to a known brand?
    # ------------------------------------------------------------------ #
    owner = None
    for brand, domains in BRAND_DOMAINS.items():
        if reg_domain in domains or p.hostname in domains:
            owner = brand
            break
    if owner:
        result["official_domain"] = True
        return result  # genuine brand property: never an impersonator

    # ------------------------------------------------------------------ #
    # Step 2: typosquat / leetspeak lookalike of the registrable label
    # ------------------------------------------------------------------ #
    label = p.domain_label or reg_domain.split(".")[0]
    brand, score = _best_brand_match(_clean(label))
    if brand and score >= 0.80:
        # Not an official domain, but closely resembles one
        tech = f"domain lookalike of '{brand}' (similarity {score:.0%})"
        result["brand"] = brand
        result["techniques"].append(tech)
        result["confidence"] = max(result["confidence"], 0.55 if score < 0.95 else 0.8)

    # ------------------------------------------------------------------ #
    # Step 3: brand embedded in subdomains / path of an unrelated domain
    # ------------------------------------------------------------------ #
    sub_text = ".".join(p.subdomains).lower()
    path_text = (p.decoded_path or "").lower()
    query_text = (p.decoded_query or "").lower()

    # ------------------------------------------------------------------ #
    # Step 2.5: brand displayed in USERINFO (everything before '@' is what
    # browsers render; the real host comes after it) — classic visual spoof
    # such as http://google.com@evil.top/. Class rule, never URL-specific.
    # ------------------------------------------------------------------ #
    if p.userinfo:
        ui_tokens = {t for t in re.split(r"[^a-z0-9]+", p.userinfo.lower()) if t}
        ui_brand = next((b for b in BRAND_DOMAINS if len(b) >= 5 and b in ui_tokens), None)
        if ui_brand:
            if result["brand"] is None:
                result["brand"] = ui_brand
            result["techniques"].append(
                f"brand '{ui_brand}' displayed in userinfo before '@' (real host: '{reg_domain}')")
            result["confidence"] = max(result["confidence"], 0.6)

    embedded_brand = None
    for brand in BRAND_DOMAINS:
        b = brand
        if len(b) < 5:
            continue
        # Brand token in subdomain (paypal-login.example.com)
        if re.search(rf"(?:^|[.\-_0-9]){re.escape(b)}(?:[.\-_0-9]|$)", sub_text):
            embedded_brand = brand
            result["techniques"].append(
                f"brand '{brand}' embedded in subdomain of unrelated domain '{reg_domain}'")
            break
        # Brand token in path with credential context
        if re.search(rf"(?:^|[/\-_0-9]){re.escape(b)}(?:[/\-_0-9]|$)", path_text + query_text):
            embedded_brand = brand
            result["techniques"].append(
                f"brand '{brand}' referenced in path of unrelated domain '{reg_domain}'")
            break

    if embedded_brand and result["brand"] is None:
        result["brand"] = embedded_brand
        result["confidence"] = max(result["confidence"], 0.45)

    # ------------------------------------------------------------------ #
    # Step 4: aggregate decision — require corroboration, not one signal
    # ------------------------------------------------------------------ #
    # Corroborating factors that raise confidence when combined with a brand hit
    corroboration = 0.0
    if p.tld in {"xyz", "top", "click", "buzz", "icu", "cfd", "live", "site", "online", "shop", "store", "vip", "cyou", "sbs", "quest", "cam"}:
        corroboration += 0.15
    if p.is_free_host:
        corroboration += 0.2
    cred_words = {"login", "signin", "sign-in", "verify", "verification", "account",
                  "secure", "security", "update", "confirm", "password", "unlock",
                  "suspended", "billing", "recover", "session", "wallet", "auth"}
    text = " ".join(p.subdomains + [path_text, query_text]).lower()
    cred_hits = sum(1 for w in cred_words if re.search(rf"(?:^|[^a-z]){re.escape(w)}(?:[^a-z]|$)", text))
    if cred_hits >= 1:
        corroboration += 0.1 + 0.1 * min(cred_hits, 3)
    if any(c.isdigit() for c in p.hostname):
        corroboration += 0.05

    if result["techniques"]:
        result["confidence"] = min(1.0, result["confidence"] + corroboration)
        result["is_impersonation"] = result["confidence"] >= 0.5

    return result
