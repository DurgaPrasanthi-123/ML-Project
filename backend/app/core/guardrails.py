"""
Guardrails: deterministic, pattern-based safety nets applied on top of the ML
verdict. These are NEVER URL-specific (no hardcoded domains) — they detect
general classes: brand impersonation and provably-nonexistent domains.
"""

from __future__ import annotations

import logging

from app.core.brand_impersonation import analyze_brand_impersonation
from app.core.dns_verifier import dns_verdict
from app.core.url_parser import ParsedURL, parse_url

logger = logging.getLogger("app.guardrails")


def evaluate_guardrails(normalized_url: str, dns_check_enabled: bool = True) -> dict:
    """
    Run pattern-based guardrails for one URL.

    Returns {
        "impersonation": {...brand analysis...},
        "dns": {...dns verdict...},
        "flags": [human-readable strings],
        "boost": float  # additive evidence in [0, 1] combined by the caller
    }
    """
    p: ParsedURL = parse_url(normalized_url, strict=True)
    flags: list[str] = []
    boost = 0.0

    brand = analyze_brand_impersonation(p) if p.hostname and not p.parse_error else {
        "is_impersonation": False, "brand": None, "techniques": [],
        "confidence": 0.0, "official_domain": False,
    }
    if brand["is_impersonation"]:
        flags.append("Brand impersonation: " + "; ".join(brand["techniques"]))
        boost = max(boost, brand["confidence"])

    dns = {"checked": False, "exists": None, "suspicious": False, "reason": "", "registrable": ""}
    if dns_check_enabled and p.hostname and not p.parse_error and not p.is_ip:
        dns = dns_verdict(p)
        if dns["suspicious"]:
            flags.append(dns["reason"])
            boost = max(boost, 0.85)

    return {
        "impersonation": brand,
        "dns": dns,
        "flags": flags,
        "boost": boost,
    }
