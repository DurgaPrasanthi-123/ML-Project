# Feature Documentation — URL Feature Extractor

`backend/app/core/features.py` is the **single source of truth** for the ML
feature vector. The training pipeline (`backend/training/train.py`) and the
inference service (`backend/app/core/inference.py`) both import it, so
training and serving can never drift apart. This document explains every
feature and why it is useful for phishing detection.

## Contract and guarantees

- **42 named features**, always returned in `FEATURE_NAMES` order.
  `extract_features(url)` returns a `dict[str, float]`;
  `extract_features_dataframe(urls)` returns a pandas DataFrame whose columns
  are exactly `FEATURE_NAMES` (used for training).
- **No network access.** Features are pure string/structure analysis of the
  URL. The two pipeline-meta features (`dns_exists`, `guardrail_flag_count`)
  are supplied by the *caller*: at training time every row carries the neutral
  `dns_exists=0.5` and `0` flags; at inference the DNS existence check and the
  deterministic guardrails run first and feed their results in.
- **Never crashes.** Malformed, empty, oversized, or non-string input yields
  finite values; a catastrophic internal failure returns the neutral zero
  vector instead of raising.
- **Deterministic.** The same input string always produces the same output.
- **No hardcoded per-URL verdicts.** Keyword/token/brand lists are generic
  classes of evidence combined with 41 other features — never a verdict on
  their own.

### Changes from the previous 26-feature set

The four separate query punctuation counters (`count_question`,
`count_percent`, `count_equal`, `count_slashes`) were consolidated into
component lengths + `count_special_chars` + `count_encoded_chars`, and the
set was extended with path/query/fragment lengths, underscore/encoded-char
counts, per-component entropies and digit ratios, repeated-character runs,
scam-token and brand-token counters, and a punycode indicator. The four
dropped counters remain represented through these more general measures.

---

## 1. Lexical counts (12 features)

| Feature | Measures | Why it helps |
|---|---|---|
| `url_length` | Characters in the normalized URL | Phishing URLs average longer; extra length hides deceptive hostnames and tracking/query junk. |
| `hostname_length` | Characters in the hostname | Long hostnames pack brand words into subdomains (`login.paypal.com.verify…`). |
| `path_length` | Characters in the path | Long deep paths accompany credential-harvest kits and multi-hop lure pages. |
| `query_length` | Characters in the query string | Long queries often carry redirect targets, encoded payloads, or tracking noise. |
| `fragment_length` | Characters after `#` | Fragments are client-side only; abnormally long ones can hide instructions or mislead users. |
| `count_dots` | `.` occurrences in the whole URL | More dots ⇒ deeper nesting; deceptive subdomain chains inflate this. |
| `count_hyphens` | `-` occurrences | Hyphens glue brand words into look-alike domains (`verify-paypal-account.net`); rare in established brands' own domains. |
| `count_underscores` | `_` occurrences | Underscores appear in throwaway/staged content and are unusual in polished legitimate hosts. |
| `count_digits` | Digit characters in the whole URL | Random digits betray generated/expiring phishing hosts and fake session IDs. |
| `count_special_chars` | Non-alphanumeric characters | Overall symbol noise: obfuscation, parameter abuse, padding. |
| `count_encoded_chars` | `%` occurrences | Percent-encodings hide redirects, credentials, or homoglyph tricks from users and filters. |
| `count_at` | `@` occurrences | Anything before `@` is ignored by browsers — a classic "real brand first" visual trick (`https://paypal.com@evil…`). |

## 2. Structural indicators (13 features)

| Feature | Measures | Why it helps |
|---|---|---|
| `subdomain_depth` | Subdomain labels above the registrable domain (eTLD+1-aware) | `secure.login.paypal.com.evil.xyz` is deep by design; depth is one of the strongest single lexical signals. |
| `count_params` | Number of query parameters | Parameter-heavy URLs are typical of kit-generated lure pages. |
| `path_depth` | `/` separators in the path | Deep paths mimic real directory structures to look legitimate. |
| `has_fragment` | Fragment present (0/1) | Fragments in phishing lures can carry pre-rendered content or instructions. |
| `is_ip_host` | Hostname is an IPv4/IPv6 literal (0/1) | Legitimate consumer sites are never addressed by raw IP; almost always malicious in phishing. |
| `has_https` | Scheme is `https` (0/1) | Weak signal alone (most phishing is now HTTPS too) but essential context — e.g. HTTPS + impersonation is the modern norm. |
| `has_explicit_port` | Non-default port written in the URL (0/1) | `:8080`-style ports indicate staged servers, not production sites. |
| `has_unusual_port` | Port in the known-unusual set (4443, 8080, 8000, 8443, …) | Stronger version of the above; odd ports correlate with disposable hosting. |
| `has_credentials_in_url` | `user:pass@` userinfo present (0/1) | Almost exclusively used to disguise the real host; effectively always suspicious. |
| `is_shortener` | Host is a known URL shortener (0/1) | Shorteners hide the true destination — legitimate in social media, but heavily abused in lures. |
| `is_free_host` | Host is free/anonymous hosting or a customer subdomain of one (0/1) | Phishing kits live on free builders (`*.github.io`, `*.blogspot.com`, `000webhostapp.com`…). |
| `suspicious_tld` | TLD in the high-abuse set (`xyz`, `top`, `click`, `icu`, …) (0/1) | Certain TLD registries see disproportionate phishing; cheap registration enables throwaway domains. |
| `double_slash_in_path` | `//` inside the path (0/1) | A path-level `//` mimics a second scheme (`http://bank.com//evil.com`) — an obfuscation staple. |

## 3. Entropy, ratios, and repetition (9 features)

| Feature | Measures | Why it helps |
|---|---|---|
| `hostname_entropy` | Shannon entropy (bits/char) of the hostname | Randomized/DGA domains have near-maximal entropy; human brand names are far more predictable. |
| `url_entropy` | Entropy of the whole lowercased URL | Overall randomness of generated URLs and encoded blobs. |
| `path_entropy` | Entropy of the path | Kit paths (`/a8f3b2c/session.php`) are much less structured than human-written ones. |
| `hostname_digit_ratio` | Fraction of hostname characters that are digits | Digit-heavy hostnames indicate generated or IP-like addressing. |
| `path_digit_ratio` | Fraction of path characters that are digits | Numeric pad paths (`/2024/09/8842/…`) mimic CMS archives to look real. |
| `digit_ratio` | Digit fraction over the whole URL | Length-normalized digit abuse, robust to URL length. |
| `special_char_ratio` | Non-alphanumeric fraction of the whole URL | Length-normalized symbol noise; separates obfuscated URLs from clean ones. |
| `max_consecutive_chars` | Longest run of one repeated character | `aaaa…` padding evades naive filters and fills space in generated links. |
| `max_consecutive_digits` | Longest run of digits | Long digit strings = IDs, obfuscated IPs, or random session tokens. |

## 4. Content indicators (6 features)

| Feature | Measures | Why it helps |
|---|---|---|
| `keyword_hits` | Distinct suspicious **keywords** present (substring) from the lexicon below | Credential-lure vocabulary (`login`, `verify`, `secure`, `webscr`, …) clusters in phishing URLs; counted, never used alone. |
| `suspicious_token_count` | Delimiter-bounded **scam tokens** from the token set below | Catches urgency/abuse-of-trust lures (`invoice`, `refund`, `winner`, `urgent`, `helpdesk`) that keyword substrings miss; token boundaries prevent false hits inside ordinary words. |
| `brand_token_count` | Delimiter-bounded well-known **brand tokens** anywhere in the URL | The brand name appearing at all (especially outside its official domain) is the core lure of impersonation. |
| `brand_impersonation_score` | Confidence (0–1) from the pattern-rule impersonation engine | Combines brand-in-subdomain, hyphenated brand look-alikes, and unrelated-TLD placement into one graded signal. |
| `brand_embedded` | Impersonation technique is brand embedding/referencing (0/1) | Binary focus on the strongest, most actionable impersonation class. |
| `punycode_host` | Hostname contains `xn--` (0/1) | IDN/homoglyph attacks render `аррle.com` (Cyrillic) as the real brand; punycode exposes the trick. |

## 5. Pipeline meta (2 features)

| Feature | Measures | Why it helps |
|---|---|---|
| `dns_exists` | Caller-supplied: 1 resolves, 0 verifiably no records, **0.5 unknown/disabled** | Fabricated domains have no DNS records; a resolvable domain is real infrastructure. Neutral-by-unknown keeps resolver outages from distorting the model. |
| `guardrail_flag_count` | Number of deterministic guardrail flags raised (brand impersonation, fabricated domain) | Lets the model weigh rule evidence alongside lexical evidence; 0 at training time (no flags computed there), so the model treats it as pure extra evidence at serving time. |

---

## Vocabularies

**`SUSPICIOUS_KEYWORDS`** (substring, 18): login, signin, verify,
verification, secure, security, account, update, confirm, billing, password,
wallet, webscr, recover, suspended, unlock, session, auth.

**`SUSPICIOUS_TOKENS`** (whole tokens, disjoint from keywords): invoice,
payment(s), refund, banking, promotion, winner(s), lottery, bonus, freegift,
claim, urgent, important, alert, limited, support, helpdesk, customer,
webmail, drive, docs, sharefile.

**`BRAND_TOKENS`** (whole tokens): google, microsoft, apple, appleid, icloud,
paypal, amazon, netflix, facebook, instagram, whatsapp, linkedin, twitter,
outlook, hotmail, office, coinbase, binance, metamask, blockchain, dhl,
fedex, usps, royalmail, hsbc, barclays, chase, citibank, wellsfargo,
santander, lloyds, sparkasse, revolut, stripe, github, dropbox.

The token sets are deliberately **disjoint** (enforced by a unit test) so a
matched string can never be double-counted into two features.

## Usage

```python
from app.core.features import extract_features, extract_features_dataframe, feature_names

fv = extract_features("http://login.paypal.com.verify-billing-secure.xyz/signin.php")
# {'url_length': 60.0, 'subdomain_depth': 3.0, 'brand_impersonation_score': 0.9, 'keyword_hits': 5.0, ...}

X = extract_features_dataframe(urls, dns_exists=None)   # training: named DataFrame
```

Unit tests: `backend/tests/test_features.py` (contract, determinism,
robustness, per-feature behavior on representative URLs, DataFrame helper).
Parser-level behavior these features depend on: `backend/app/core/url_parser.py`.
