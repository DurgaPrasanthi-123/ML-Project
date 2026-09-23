"""
DNS existence verification via DNS-over-HTTPS (DoH).

Purpose: catches lexically-clean FAKE domains (e.g. randomly generated
hostnames like 'shop.amdns.com') that no passive lexical feature can detect.
A domain that has no record in global DNS is unregistered, expired, or
ephemeral — a strong indicator of a fabricated URL.

IMPORTANT SAFETY PROPERTY: this module never contacts the submitted URL's
server. It only asks a public DNS resolver (Cloudflare / Google DoH endpoints)
"does this domain exist?" — so there is no attack surface from a malicious
target, no content fetching, and no information leak beyond the domain name
itself (which any recursive resolver would see anyway).

Behavior is strictly fail-open: resolver outages, timeouts, and parse errors
degrade to "unknown" and never block or alter a verdict on their own.
"""

import ipaddress
import logging
import re

logger = logging.getLogger("PhishingDetectorApp.dns")

# DNS-over-HTTPS endpoints (JSON API). Cloudflare primary, Google fallback.
DOH_ENDPOINTS = (
    "https://cloudflare-dns.com/dns-query?name={name}&type={type}",
    "https://dns.google/resolve?name={name}&type={type}",
)

# Candidate record types to probe, in order. A domain is considered
# "existing" if ANY of these returns a usable answer.
_PROBE_TYPES = ("A", "AAAA", "NS", "CNAME", "MX")

# Domains that are DNS-reserved by RFC 6761 / special-use registries and must
# never be treated as evidence either way.
SPECIAL_USE_DOMAINS = {
    "localhost", "invalid", "test", "example", "example.com",
    "example.net", "example.org",
}

_CACHE_MAX = 8192
_definitive_cache: dict = {}

# Lazily created HTTP session (urllib; no extra dependency).
_session = None


def _get_session():
    """Create a minimal shared opener with a short timeout."""
    global _session
    if _session is None:
        import urllib.request
        import ssl

        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        _session = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
    return _session


def _doh_query(endpoint: str, name: str, rtype: str, timeout: float) -> dict | None:
    """Issue one DoH JSON query. Returns parsed JSON or None on any failure."""
    import json as _json
    import urllib.request
    import urllib.error

    url = endpoint.format(name=name, type=rtype)
    try:
        req = urllib.request.Request(
            url,
            headers={"Accept": "application/dns-json", "User-Agent": "PhishDetector/1.0"},
        )
        with _get_session().open(req, timeout=timeout) as resp:
            return _json.loads(resp.read().decode("utf-8", errors="replace"))
    except Exception as exc:  # noqa: BLE001 - fail-open by design
        logger.debug("DoH query failed for %s %s via %s: %s", name, rtype, endpoint, exc)
        return None


def _is_routable_answer(answer: list) -> bool:
    """True when DoH answer records contain a non-bogus value."""
    for rec in answer or []:
        data = str(rec.get("data", "")).strip().strip('"')
        if not data:
            continue
        # NXDOMAIN-targeted CNAMEs / bogus placeholders
        if data.lower() in SPECIAL_USE_DOMAINS or data.lower().endswith(".invalid"):
            continue
        if rec.get("type") == 1:  # A record -> must parse as global IPv4
            try:
                ip = ipaddress.ip_address(data)
                if ip.version == 4 and not (ip.is_private or ip.is_reserved
                                            or ip.is_loopback or ip.is_link_local):
                    return True
            except ValueError:
                continue
        else:  # AAAA / NS / CNAME / MX — presence of any record counts
            return True
    return False


def _registrable_of(hostname: str) -> str:
    """Reuse the pipeline's eTLD+1 logic without a circular import."""
    from app.core.url_parser import get_registrable_domain
    return get_registrable_domain(hostname) or hostname


def check_domain_exists(hostname: str, timeout: float = 3.0) -> dict:
    """
    Check whether a hostname exists in global DNS via public DoH resolvers.

    Returns {
        "checked":     bool,  # a query was actually attempted
        "exists":      bool | None,  # None = unknown (resolver failure)
        "registrable": str,   # the eTLD+1 that was probed
        "records":     [str], # human-readable hits, e.g. "A 93.184.216.34"
    }
    """
    result = {"checked": False, "exists": None, "registrable": "", "records": []}

    if not hostname:
        return result
    host = hostname.lower().rstrip(".").strip()
    if not host or host in SPECIAL_USE_DOMAINS:
        return result
    # IP-literal hosts are not DNS names; skip them entirely.
    try:
        ipaddress.ip_address(host.strip("[]"))
        return result
    except ValueError:
        pass
    if not re.fullmatch(r"[a-z0-9.\-]+", host):
        return result

    target = _registrable_of(host)
    result["registrable"] = target

    for rtype in _PROBE_TYPES:
        answer_found = False
        got_response = False
        nxdomain = False
        for endpoint in DOH_ENDPOINTS:
            data = _doh_query(endpoint, target, rtype, timeout)
            if data is None:
                continue  # try fallback resolver
            got_response = True
            status = data.get("Status", -1)
            if status == 0 and _is_routable_answer(data.get("Answer")):
                result["records"].append(
                    f"{rtype} " + "; ".join(str(r.get("data", "")) for r in data["Answer"][:2])
                )
                answer_found = True
                break
            # Status 3 = NXDOMAIN: authoritative "name does not exist".
            # For DNS names this is conclusive across ALL record types.
            if status == 3:
                nxdomain = True
                break
        if answer_found:
            result["checked"] = True
            result["exists"] = True
            return result
        if nxdomain:
            # Name does not exist at all — no point probing other types.
            result["checked"] = True
            result["exists"] = False
            return result
        if got_response:
            result["checked"] = True

    # All record types probed without a hit: exists=False if any resolver
    # answered authoritatively; None if the network simply failed.
    result["exists"] = False if result["checked"] else None
    return result


def cached_domain_exists(hostname: str, timeout: float = 3.0) -> dict:
    """Memoized wrapper. Only DEFINITIVE results (exists True/False) are
    cached — "unknown" outcomes from resolver outages are never memoized,
    so later requests retry the network. A small TTL-free cache keeps
    repeated API calls instant within a process lifetime."""
    if hostname in _definitive_cache:
        return _definitive_cache[hostname]
    res = check_domain_exists(hostname, timeout)
    if res["exists"] is not None:
        if len(_definitive_cache) >= _CACHE_MAX:
            _definitive_cache.clear()  # crude bound; fine for this workload
        _definitive_cache[hostname] = res
    return res


def dns_verdict(p) -> dict:
    """
    High-level helper for the Flask app: given a ParsedURL, decide whether the
    domain is fabricated. Never raises; fails open to exists=None.
    """
    out = {"checked": False, "exists": None, "suspicious": False, "reason": "", "registrable": ""}
    if p is None or p.parse_error or p.is_ip:
        return out  # IP hosts and invalid URLs are handled elsewhere
    try:
        res = cached_domain_exists(p.hostname)
    except Exception as exc:  # noqa: BLE001 - absolute fail-open guarantee
        logger.warning("DNS verification errored (fail-open): %s", exc)
        return out

    out["checked"] = res["checked"]
    out["exists"] = res["exists"]
    out["registrable"] = res.get("registrable", "")
    if res["exists"] is False:
        out["suspicious"] = True
        out["reason"] = (f"Domain '{res['registrable']}' has no DNS records — "
                         "it appears unregistered or fabricated")
    return out
