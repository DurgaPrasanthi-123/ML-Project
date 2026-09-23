/** Small formatting helpers shared across pages. */

export function fmtPct(value, digits = 1) {
  const n = Number(value);
  if (!Number.isFinite(n)) return "—";
  return `${n.toFixed(digits)}%`;
}

export function fmtInt(value) {
  const n = Number(value);
  return Number.isFinite(n) ? n.toLocaleString() : "—";
}

export function fmtDate(iso) {
  try {
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return String(iso);
    return d.toLocaleString(undefined, {
      year: "numeric",
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  } catch {
    return String(iso);
  }
}

/**
 * Feature name -> display name. All 42 model features are coverable; anything
 * unrecognized falls through with a tidied-up version of the raw name.
 */
const FEATURE_LABELS = {
  url_length: "URL length",
  hostname_length: "Hostname length",
  path_length: "Path length",
  query_length: "Query length",
  fragment_length: "Fragment length",
  count_dots: "Count dots",
  count_hyphens: "Count hyphens",
  count_underscores: "Count underscores",
  count_digits: "Count digits",
  count_special_chars: "Special characters",
  count_encoded_chars: "Encoded chars (%)",
  count_at: "@ symbols",
  subdomain_depth: "Subdomain depth",
  count_params: "Query parameters",
  path_depth: "Path depth",
  has_fragment: "Has fragment",
  is_ip_host: "IP address host",
  has_https: "HTTPS",
  has_explicit_port: "Explicit port",
  has_unusual_port: "Unusual port",
  has_credentials_in_url: "Credentials in URL",
  is_shortener: "URL shortener",
  is_free_host: "Free hosting",
  suspicious_tld: "Suspicious TLD",
  double_slash_in_path: "Double slash in path",
  hostname_entropy: "Hostname entropy",
  url_entropy: "URL entropy",
  path_entropy: "Path entropy",
  hostname_digit_ratio: "Hostname digit ratio",
  path_digit_ratio: "Path digit ratio",
  digit_ratio: "Digit ratio",
  special_char_ratio: "Special char ratio",
  max_consecutive_chars: "Max repeated chars",
  max_consecutive_digits: "Max repeated digits",
  keyword_hits: "Phishing keywords",
  suspicious_token_count: "Suspicious tokens",
  brand_token_count: "Brand tokens",
  brand_impersonation_score: "Brand impersonation",
  brand_embedded: "Brand embedded",
  punycode_host: "Punycode/IDN host",
  dns_exists: "DNS exists",
  guardrail_flag_count: "Guardrail flags",
};

export function featureLabel(name) {
  return FEATURE_LABELS[name] || String(name).replace(/_/g, " ");
}

/** Prediction -> tailwind-free class suffix + display color group. */
export const PREDICTION_CLASS = {
  LEGITIMATE: "ok",
  SUSPICIOUS: "warn",
  PHISHING: "bad",
};

export function verdictClass(prediction) {
  return PREDICTION_CLASS[prediction] || "muted";
}
