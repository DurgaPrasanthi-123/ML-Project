"""
Robust URL parsing and normalization for the phishing detection pipeline.

Design goals:
- Strict, hardened parsing (never trusts user input; bounds-checked).
- A single source of truth for URL decomposition so that feature extraction,
  the rule engine, and threat intelligence all see exactly the same fields.
- Separates the registrable domain (eTLD+1) from subdomains and path, which is
  essential to avoid flagging genuine brand domains as impersonators.

No network access happens in this module.
"""

import re
import ipaddress
from dataclasses import dataclass, field
from urllib.parse import urlparse, unquote, parse_qsl

MAX_URL_LENGTH = 2048

DANGEROUS_SCHEMES = {"javascript", "data", "vbscript", "file", "blob", "about"}
KNOWN_SUFFIXES = None  # populated lazily via publicsuffix handling below

# A compact set of multi-label public suffixes (covering the common cases;
# the full PSL is used when available via the bundled list in suffixes.py).
MULTI_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk", "sch.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au",
    "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
    "co.in", "net.in", "org.in", "firm.in", "gen.in", "ac.in", "res.in",
    "com.br", "net.br", "org.br", "gov.br", "com.mx", "com.ar", "com.sg",
    "com.tr", "com.cn", "net.cn", "org.cn", "gov.cn", "com.tw", "com.hk",
    "co.kr", "or.kr", "co.za", "com.my", "com.ph", "com.vn", "co.id",
    "com.pl", "com.ua", "com.ru", "net.ru", "org.ru", "com.sa", "com.eg",
    "com.ng", "com.gh", "com.pk", "com.bd", "co.il", "org.il", "net.il",
    "com.co", "com.pe", "com.uy", "com.ve", "com.do", "com.gt",
    "app.github.io", "github.io", "gitlab.io", "herokuapp.com",
    "weebly.com", "wixsite.com", "webnode.com", "web.app", "firebaseapp.com",
    "vercel.app", "netlify.app", "pages.dev", "workers.dev", "glitch.me",
    "blogspot.com", "wordpress.com", "tumblr.com", "livefilestore.com",
}

# Free/anonymous hosting and builder platforms frequently abused for phishing
FREE_HOSTING = {
    "weebly.com", "wixsite.com", "webnode.com", "000webhostapp.com",
    "infinityfreeapp.com", "rf.gd", "unaux.com", "20m.com",
    "github.io", "gitlab.io", "glitch.me", "replit.app", "netlify.app",
    "vercel.app", "firebaseapp.com", "web.app", "blogspot.com",
    "sites.google.com", "docs.google.com", "drive.google.com",
    "ueniweb.com", "jimdofree.com", "byethost.com", "mywebcommunity.org",
    "b-cdn.net", "storage.googleapis.com", "herokuapp.com",
}

# URL shortening services (used as a signal, never a verdict)
SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "bit.do", "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc",
    "lnkd.in", "rebrand.ly", "soo.gd", "s.id", "bl.ink", "v.gd", "tiny.ie",
    "shrtco.de", "loxy.in", "clck.ru", "u.to", "qr.ae", "t.ly", "shorte.st",
}

SUSPICIOUS_TLDS = {
    "xyz", "top", "cc", "cfd", "click", "buzz", "live", "space", "site",
    "online", "icu", "monster", "info", "tk", "ga", "cf", "ml", "gq", "work",
    "rest", "fit", "surf", "bar", "pw", "ro", "su", "cn", "ru", "cam", "quest",
    "sbs", "zip", "mov", "lol", "cyou", "shop", "store", "vip", "app",
}

PORT_RULES = {
    # (port, severity) — ports that are unusual for public web traffic
    "unusual": {4443, 8888, 8080, 8443, 8000, 3000, 5000, 9000, 1337, 6666, 7777},
}

PRIVATE_HINTS = {
    "localhost", "local", "internal", "intranet", "lan", "host", "dmz",
    "router", "gateway", "admin", "home",
}


@dataclass
class ParsedURL:
    """Normalized, security-oriented decomposition of a submitted URL."""
    raw: str
    normalized: str
    scheme: str = ""
    hostname: str = ""            # lowercased, port stripped
    port: int | None = None
    default_port: bool = False
    path: str = ""
    query: str = ""
    fragment: str = ""
    userinfo: str = ""
    registrable_domain: str = ""  # eTLD+1 (approximate, PSL-lite)
    subdomains: list = field(default_factory=list)
    domain_label: str = ""        # label immediately left of the TLD
    tld: str = ""
    is_ip: bool = False
    ip_address: str | None = None
    is_private_ip: bool = False
    is_shortener: bool = False
    is_free_host: bool = False
    decoded_path: str = ""
    decoded_query: str = ""
    query_params: list = field(default_factory=list)
    parse_error: str = ""

    # ------------------------------------------------------------------ #
    def public_surface(self) -> dict:
        """Safe subset for API responses / logs (never echo full raw URL back)."""
        return {
            "scheme": self.scheme,
            "host": self.hostname,
            "registrable_domain": self.registrable_domain,
            "tld": self.tld,
            "path": self.path[:120],
        }


def _has_scheme(url: str) -> bool:
    m = re.match(r"^\s*([a-zA-Z][a-zA-Z0-9+.\-]*)\s*:", url)
    return bool(m)


def normalize_url(raw_url: str) -> str:
    """
    Make a user-supplied URL parseable. Adds https:// when no scheme present
    (safer default than http). Trims whitespace and control characters.
    """
    if raw_url is None:
        return ""
    u = str(raw_url).strip()
    # strip embedded control characters and zero-width chars
    u = re.sub(r"[\x00-\x1f\x7f\u200b\u200c\u200d\u2060\ufeff]", "", u)
    if not u:
        return ""
    if not _has_scheme(u):
        u = "https://" + u
    return u


def split_host_port(hostport: str) -> tuple[str, int | None]:
    """Split 'host:port', respecting IPv6 [..] notation."""
    if not hostport:
        return "", None
    if hostport.startswith("["):  # IPv6 literal
        end = hostport.find("]")
        if end == -1:
            return hostport, None
        host = hostport[: end + 1]
        rest = hostport[end + 1:]
        port = None
        if rest.startswith(":"):
            try:
                port = int(rest[1:])
            except ValueError:
                port = None
        return host, port
    if hostport.count(":") == 1:
        host, _, p = hostport.partition(":")
        try:
            return host, int(p)
        except ValueError:
            return hostport, None
    return hostport, None


def get_registrable_domain(hostname: str) -> str:
    """
    Approximate eTLD+1 using a curated multi-label suffix set.
    e.g. 'login.paypal.com' -> 'paypal.com'
         'a.b.co.uk'        -> 'b.co.uk'
         'x.y.github.io'    -> 'y.github.io'
    """
    if not hostname:
        return ""
    host = hostname.rstrip(".")
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    # try the longest multi-label suffix that matches
    for i in range(len(parts) - 2):
        candidate = ".".join(parts[i:])
        if candidate in MULTI_LABEL_SUFFIXES:
            return candidate
    # fall back to last two labels
    return ".".join(parts[-2:])


def parse_ip(host: str) -> tuple[bool, bool, str | None]:
    """Return (is_ip, is_private_or_reserved, ip_string)."""
    h = host
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        # handle decimal/hex/octal IP obfuscation like 2130706433 or 0x7f.0.0.1
        if re.fullmatch(r"\d{8,12}", h):
            try:
                ip = ipaddress.ip_address(int(h))
            except ValueError:
                return False, False, None
            return True, ip.is_private or ip.is_reserved, str(ip)
        return False, False, None
    return True, (ip.is_private or ip.is_reserved or ip.is_loopback or ip.is_link_local), str(ip)


def parse_url(raw_url: str, strict: bool = False) -> ParsedURL:
    """
    Parse a URL into a ParsedURL. Always returns an object; when parsing fails
    ``parse_error`` is set (callers decide how to handle it — no silent
    default-feature fallbacks).
    """
    p = ParsedURL(raw=raw_url or "", normalized=normalize_url(raw_url or ""))

    if not p.normalized:
        p.parse_error = "empty"
        return p
    if len(p.normalized) > MAX_URL_LENGTH:
        p.parse_error = "too_long"
        return p

    try:
        parsed = urlparse(p.normalized)
    except ValueError as exc:
        p.parse_error = f"parse_failed: {exc}"
        return p

    p.scheme = (parsed.scheme or "").lower()
    if p.scheme in DANGEROUS_SCHEMES:
        p.parse_error = f"dangerous_scheme: {p.scheme}"
        return p
    if p.scheme not in ("http", "https"):
        p.parse_error = f"unsupported_scheme: {p.scheme}"
        return p

    hostport = parsed.netloc
    userinfo = ""
    if "@" in hostport:
        userinfo, _, hostport = hostport.rpartition("@")
    p.userinfo = userinfo

    host, port = split_host_port(hostport)
    p.hostname = (host or "").lower().rstrip(".")

    # Port
    if port is not None:
        p.port = port
    elif p.scheme == "https":
        p.port = 443
        p.default_port = True
    elif p.scheme == "http":
        p.port = 80
        p.default_port = True

    if not p.hostname:
        p.parse_error = "missing_host"
        return p

    # Hostname sanity: allow letters, digits, hyphens, dots, brackets(IPv6)
    if not re.fullmatch(r"[a-z0-9.\-]+|\[[0-9a-f:]+\]|\[[0-9a-f:.]+\]", p.hostname):
        p.parse_error = "invalid_hostname_characters"
        return p
    if len(p.hostname) > 253:
        p.parse_error = "hostname_too_long"
        return p
    if p.hostname.lstrip("._-") == "":
        p.parse_error = "invalid_hostname"
        return p

    p.path = parsed.path or ""
    p.query = parsed.query or ""
    p.fragment = parsed.fragment or ""

    try:
        p.decoded_path = unquote(p.path)
        p.decoded_query = unquote(p.query)
        p.query_params = parse_qsl(p.query, keep_blank_values=True)
    except Exception:
        p.decoded_path = p.path
        p.decoded_query = p.query
        p.query_params = []

    is_ip, is_private, ip_str = parse_ip(p.hostname)
    p.is_ip = is_ip
    p.ip_address = ip_str
    p.is_private_ip = is_private

    if not is_ip:
        p.registrable_domain = get_registrable_domain(p.hostname)
        parts = p.hostname.split(".")
        rd_parts = p.registrable_domain.split(".")
        p.subdomains = parts[: len(parts) - len(rd_parts)] if len(parts) > len(rd_parts) else []
        p.domain_label = rd_parts[0] if rd_parts else ""
        p.tld = rd_parts[-1] if len(rd_parts) > 1 else (parts[-1] if parts else "")
        p.is_free_host = p.registrable_domain in FREE_HOSTING or p.hostname in FREE_HOSTING
        p.is_shortener = p.hostname in SHORTENERS or p.registrable_domain in SHORTENERS
    else:
        p.registrable_domain = p.hostname
        p.domain_label = ""
        p.tld = ""

    # hostname-only private hints (e.g. http://intranet/)
    if not is_ip and "." not in p.hostname:
        p.is_private_ip = True

    return p


def is_ssrf_target(p: ParsedURL) -> bool:
    """True when the URL targets a private/reserved/internal address."""
    if p.is_private_ip:
        return True
    if not p.is_ip and "." not in p.hostname:
        return True
    host = p.hostname.lstrip("[").rstrip("]")
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_reserved or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False


# --------------------------------------------------------------------------- #
# Redirect / open-redirect parameter analysis (structural, no network)
# --------------------------------------------------------------------------- #
REDIRECT_PARAM_NAMES = {
    "url", "uri", "redirect", "redirect_url", "redirect_uri", "return",
    "returnurl", "return_url", "next", "continue", "dest", "destination",
    "goto", "target", "rurl", "redir", "link", "out", "view", "callback",
    "continueaction", "ret", "u", "forward", "go", "to", "window", "data",
}

SCHEME_RELATIVE_RE = re.compile(r"^(?:https?:)?//", re.IGNORECASE)


def find_redirect_params(p: ParsedURL) -> list[str]:
    """
    Return descriptions of redirect-style parameters whose value looks like an
    absolute or scheme-relative URL (open-redirect / covert-channel indicator).
    """
    hits = []
    for name, value in p.query_params:
        if name.lower() not in REDIRECT_PARAM_NAMES:
            continue
        v = unquote(value)
        if SCHEME_RELATIVE_RE.match(v):
            hits.append(f"parameter '{name}' carries an absolute URL")
        elif re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*:%", v) or re.match(r"^[a-z][a-z0-9+.\-]*:", v, re.IGNORECASE):
            hits.append(f"parameter '{name}' carries a scheme-prefixed value")
    return hits
