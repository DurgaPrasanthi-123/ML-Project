"""
Dataset preparation pipeline for phishing URL detection.

Scope (frozen): load -> identify columns -> normalize labels -> clean ->
normalize URLs safely -> deduplicate -> leakage checks -> stratified
group-aware train/val/test split -> write artifacts + statistics.

Guarantees:
- No ML model is trained here.
- No labels are invented: labels are only mapped from source labels via an
  explicit, documented synonym table; unmapped labels are reported and dropped.
- No synthetic URLs are added.
- URL normalization is conservative and preserves phishing indicators
  (path/query case, double slashes, fragments, encoded characters).

Usage:
    python data/prepare_dataset.py --input data/dataset.csv --output-dir data/processed
    python data/prepare_dataset.py --input mydata.csv --url-column URLs --label-column class
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

import pandas as pd

REPO_ROOT = Path(__file__).resolve().parent.parent
BACKEND_DIR = REPO_ROOT / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.core.url_parser import MULTI_LABEL_SUFFIXES, get_registrable_domain  # noqa: E402

# --------------------------------------------------------------------------- #
# Label normalization — explicit synonyms only. Nothing else is invented.
# Extend with --label-map '{"mysource": {"weird label": "phishing"}}' if needed.
# --------------------------------------------------------------------------- #
LABEL_SYNONYMS: dict[str, str] = {
    # legitimate
    "legitimate": "legitimate", "legit": "legitimate", "benign": "legitimate",
    "good": "legitimate", "safe": "legitimate", "ham": "legitimate",
    "normal": "legitimate", "valid": "legitimate", "ok": "legitimate",
    "genuine": "legitimate", "trusted": "legitimate",
    "non-phishing": "legitimate", "nonphishing": "legitimate",
    # phishing
    "phishing": "phishing", "phish": "phishing", "phising": "phishing",
    "malicious": "phishing", "bad": "legitimate_or_phishing_invalid",
    "fraud": "phishing", "fraudulent": "phishing", "scam": "phishing",
    "yes": "phishing",
    "phishing_url": "phishing", "phish_url": "phishing",
    # suspicious — only kept when the SOURCE explicitly provides such labels
    "suspicious": "suspicious", "suspect": "suspicious", "unknown": "suspicious",
    "questionable": "suspicious", "gray": "suspicious", "grey": "suspicious",
    "dubious": "suspicious", "2": "suspicious", "2.0": "suspicious",
}
VALID_TARGETS = {"legitimate", "phishing", "suspicious"}

LABEL_SYNONYMS = {k: v for k, v in LABEL_SYNONYMS.items() if v in VALID_TARGETS}

MAX_URL_LENGTH = 2048
HOSTNAME_RE = re.compile(r"^[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?$")
CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f\u200b\u200c\u200d\u2060\ufeff]")


# --------------------------------------------------------------------------- #
# Column identification
# --------------------------------------------------------------------------- #
URL_COLUMN_HINTS = ("url", "uri", "link", "website", "address", "domain")
LABEL_COLUMN_HINTS = ("label", "class", "type", "category", "result", "status", "target", "phishing")


def identify_url_column(df: pd.DataFrame) -> str:
    cols = [c for c in df.columns if pd.api.types.is_string_dtype(df[c])]
    # 1) exact / hinted name match (case-insensitive)
    lowered = {c.lower().strip(): c for c in cols}
    for hint in URL_COLUMN_HINTS:
        if hint in lowered:
            return lowered[hint]
    # 2) fallback: column whose values look most like URLs
    best, best_score = None, -1.0
    for c in cols:
        sample = df[c].dropna().astype(str).head(500)
        if sample.empty:
            continue
        score = sample.str.contains(r"\.", regex=False).mean()
        score -= sample.str.contains(" ").mean()
        # Strong bonus for scheme-like prefixes (ties e.g. '521848.txt' vs a URL column)
        score += 0.5 * sample.str.contains(r"^[a-z][a-z0-9+.-]*://", case=False, regex=True).mean()
        if score > best_score:
            best, best_score = c, score
    if best is None or best_score <= 0:
        raise SystemExit("[ERROR] Could not identify a URL column. Use --url-column.")
    return best


def identify_label_column(df: pd.DataFrame, url_column: str,
                          synonyms: dict[str, str] | None = None) -> tuple[str, dict]:
    """Pick the most reliably mappable label column.

    All hinted columns are scored by the fraction of values the EFFECTIVE
    synonym table (base + numeric polarity + extra maps) can map. The best
    (highest mappable fraction; hint order as tie-break) wins; every other
    usable candidate is CROSS-CHECKED against it and disagreements are
    reported — never silently resolved (no labels are invented).
    """
    synonyms = synonyms if synonyms is not None else LABEL_SYNONYMS
    lowered = {c.lower().strip(): c for c in df.columns}
    candidates: list[tuple[str, str]] = []
    for hint in LABEL_COLUMN_HINTS:
        col = lowered.get(hint)
        if col and col != url_column and col not in {c for _, c in candidates}:
            candidates.append((hint, col))
    if not candidates:
        raise SystemExit("[ERROR] Could not identify a label column. Use --label-column.")

    def mappable_fraction(col: str) -> float:
        vals = df[col].astype(str).str.strip().str.lower()
        return float(vals.isin(synonyms.keys()).mean())

    scored = sorted(
        ((mappable_fraction(col), -i, hint, col) for i, (hint, col) in enumerate(candidates)),
        reverse=True,
    )
    frac, _, _, label_col = scored[0]
    if frac == 0.0:
        raise SystemExit(
            f"[ERROR] Label column(s) {[c for _, c in candidates]} contain no mappable labels. "
            f"Use --label-column or extend the synonym table."
        )

    cross_check: dict = {"candidates": {c: round(mappable_fraction(c), 4) for _, c in candidates}}
    for other_frac, _, other_hint, other_col in scored[1:]:
        if other_frac == 0.0:
            continue
        a = df[label_col].astype(str).str.strip().str.lower().map(synonyms)
        b = df[other_col].astype(str).str.strip().str.lower().map(synonyms)
        both = a.notna() & b.notna()
        disagreements = int((a[both] != b[both]).sum())
        cross_check[f"vs:{other_col}"] = {"comparable_rows": int(both.sum()), "disagreements": disagreements}
        if disagreements:
            print(f"[LABELS] '{label_col}' and '{other_col}' disagree on {disagreements} rows "
                  f"— keeping '{label_col}' (higher mappable fraction); conflicts reported")
    return label_col, cross_check


# --------------------------------------------------------------------------- #
# URL validation + safe normalization
# --------------------------------------------------------------------------- #
def normalize_url(url: str) -> tuple[str | None, list[str]]:
    """Return (normalized_url, applied_rules) or (None, reason) when invalid.

    Conservative by design — phishing indicators are preserved:
    - path/query/fragment case kept, double slashes kept, encoding kept
    - only scheme/host case, default ports, surrounding quotes/junk change
    """
    if url is None or (isinstance(url, float) and pd.isna(url)):
        return None, ["empty"]
    s = str(url).strip().strip("'\"")
    if not s:
        return None, ["empty"]
    if CONTROL_CHARS_RE.search(s):
        s = CONTROL_CHARS_RE.sub("", s).strip()
        if not s:
            return None, ["empty"]
    if len(s) > MAX_URL_LENGTH:
        return None, ["too_long"]
    if " " in s:
        return None, ["whitespace"]

    applied: list[str] = []
    original = s

    # Scheme handling: record absence, normalize casing only
    m = re.match(r"^([a-zA-Z][a-zA-Z0-9+.-]*)://", s)
    has_scheme = bool(m)
    if m and m.group(1).lower() not in ("http", "https"):
        return None, [f"unsupported_scheme:{m.group(1).lower()}"]
    if not has_scheme:
        applied.append("scheme_added")
        s = "http://" + s

    lowered = s.lower()
    if lowered != s:
        applied.append("scheme_host_lowercased")
        s = lowered

    # Split scheme://rest and clean the host part only
    scheme, rest = s.split("://", 1)
    host_part, sep, path_part = rest.partition("/")
    if host_part.endswith("."):
        host_part = host_part.rstrip(".")
        applied.append("trailing_dot_removed")
    if host_part.startswith("www."):
        applied.append("www_present")  # recorded, NOT stripped (indicator)

    # Remove explicit default ports
    port_m = re.search(r":([0-9]{1,5})$", host_part)
    if port_m:
        port = int(port_m.group(1))
        if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
            host_part = host_part[: port_m.start()]
            applied.append("default_port_removed")

    if not host_part or not HOSTNAME_RE.match(host_part):
        return None, ["invalid_host"]
    if len(host_part) > 253:
        return None, ["host_too_long"]

    normalized = f"{scheme}://{host_part}{sep}{path_part}"
    if normalized != original or applied:
        return normalized, (applied or ["unchanged"])
    return normalized, ["unchanged"]


# --------------------------------------------------------------------------- #
# Pipeline
# --------------------------------------------------------------------------- #
def prepare(input_path: Path, output_dir: Path, url_column: str | None,
            label_column: str | None, fractions: tuple[float, float, float],
            seed: int, extra_label_map: dict[str, str] | None = None,
            numeric_polarity: str | None = None) -> dict:
    synonyms = dict(LABEL_SYNONYMS)
    for src, tgt in (extra_label_map or {}).items():
        if tgt not in VALID_TARGETS:
            raise SystemExit(f"[ERROR] --label-map target '{tgt}' is not one of {sorted(VALID_TARGETS)}")
        synonyms[str(src).lower()] = tgt
    if numeric_polarity is not None:
        if numeric_polarity not in ("0=legitimate", "1=legitimate"):
            raise SystemExit("[ERROR] --numeric-label-polarity must be '0=legitimate' or '1=legitimate'")
        # Numeric source labels are NOT self-describing: the meaning of 0/1 is
        # dataset-specific (UCI PhiUSIIL, e.g., encodes 1=legitimate). The
        # operator must assert the mapping explicitly; nothing is assumed.
        zero, one = ("legitimate", "phishing") if numeric_polarity == "0=legitimate" else ("phishing", "legitimate")
        synonyms.update({"0": zero, "0.0": zero, "1": one, "1.0": one})

    stats: dict = {"input_file": str(input_path)}

    # 1. Load
    try:
        df = pd.read_csv(input_path)
    except UnicodeDecodeError:
        df = pd.read_csv(input_path, encoding="latin-1")
    stats["total_records"] = int(len(df))
    print(f"[LOAD] {len(df)} rows, columns: {list(df.columns)}")

    # 2. Identify columns (using the EFFECTIVE synonym table, incl. polarity)
    url_col = url_column or identify_url_column(df)
    if label_column:
        label_col, cross_check = label_column, {}
    else:
        label_col, cross_check = identify_label_column(df, url_col, synonyms)
    print(f"[COLUMNS] url='{url_col}'  label='{label_col}'")
    stats["url_column"], stats["label_column"] = url_col, label_col
    if cross_check:
        stats["label_cross_check"] = cross_check
        conflicts = sum(v.get("disagreements", 0) for v in cross_check.values() if isinstance(v, dict))
        if conflicts:
            stats["label_column_conflicts"] = conflicts

    # 3. Label normalization (no invented labels — unmapped -> dropped+reported)
    def map_label(v):
        s = str(v).strip().lower()
        return synonyms.get(s)

    df["_label"] = df[label_col].map(map_label)
    invalid_mask = df["_label"].isna()
    stats["invalid_label_count"] = int(invalid_mask.sum())
    unmapped_values = df.loc[invalid_mask, label_col].astype(str).str.strip().str.lower().value_counts()
    if not unmapped_values.empty:
        print(f"[LABELS] unmapped values dropped: {dict(unmapped_values)}")
        stats["unmapped_label_values"] = {k: int(v) for k, v in unmapped_values.items()}
    # Numeric 0/1 labels are ambiguous across datasets — never guess silently.
    numeric_hits = sum(int(unmapped_values.get(v, 0)) for v in ("0", "1", "0.0", "1.0"))
    if numeric_polarity is None and numeric_hits > 0.5 * int(invalid_mask.sum()) and numeric_hits > 0:
        raise SystemExit(
            "[ERROR] The label column is numeric (0/1) and its meaning is dataset-specific "
            "(e.g. UCI PhiUSIIL uses 1=legitimate). Re-run with --numeric-label-polarity "
            "('0=legitimate' or '1=legitimate') or pass an explicit --label-map."
        )
    df = df[~invalid_mask].copy()
    stats["label_distribution_source"] = {
        str(k): int(v) for k, v in df[label_col].astype(str).str.strip().str.lower().value_counts().items()
    }

    # 4/5. URL validation + safe normalization
    norm_results = df[url_col].map(normalize_url)
    df["_url"] = [n for n, _ in norm_results]
    df["_norm_rules"] = [r for _, r in norm_results]
    bad_url_mask = df["_url"].isna()
    stats["invalid_url_count"] = int(bad_url_mask.sum())
    invalid_reasons = Counter(r[0] for r in df.loc[bad_url_mask, "_norm_rules"])
    stats["invalid_url_reasons"] = dict(invalid_reasons)
    df = df[~bad_url_mask].copy()

    # URL-level derived fields (leakage grouping + audit)
    df["url"] = df["_url"]
    df["label"] = df["_label"]
    df["registrable_domain"] = df["url"].map(
        lambda u: get_registrable_domain(u.split("://", 1)[-1].split("/", 1)[0])
    )
    df["scheme"] = df["url"].str.split("://", n=1).str[0]
    df["url_length"] = df["url"].str.len()
    df["source_row"] = df.index + 2  # +2: header + 1-based pandas index

    # 6. Deduplicate (exact + host-variant), report conflicts
    before = len(df)
    df["_dedup_key"] = df["url"].str.replace(r"://www\.", "://", regex=True).str.rstrip("/")
    dup_mask = df.duplicated(subset="_dedup_key", keep="first")
    stats["duplicate_count"] = int(dup_mask.sum())
    df = df[~dup_mask].copy()

    conflict_keys = df.groupby("_dedup_key")["label"].nunique()
    conflicting_urls = conflict_keys[conflict_keys > 1]
    stats["url_label_conflicts"] = int(len(conflicting_urls))
    if len(conflicting_urls):
        df = df[~df["_dedup_key"].isin(conflicting_urls.index)].copy()
        print(f"[LEAKAGE] {len(conflicting_urls)} URLs carried conflicting labels -> dropped")

    # Domain-level label overlap (same domain, both classes) — kept, reported,
    # and handled at split time via domain grouping (never split a domain).
    dom_labels = df.groupby("registrable_domain")["label"].nunique()
    overlap_domains = dom_labels[dom_labels > 1]
    stats["domains_with_both_classes"] = int(len(overlap_domains))
    if len(overlap_domains):
        sample = ", ".join(sorted(overlap_domains.index)[:10])
        print(f"[LEAKAGE] {len(overlap_domains)} domains contain BOTH classes "
              f"(e.g. {sample}) — grouped splitting keeps each domain in one split")

    stats["cleaned_records"] = int(len(df))
    stats["dropped_records"] = stats["total_records"] - len(df)
    stats["unique_domains"] = int(df["registrable_domain"].nunique())
    stats["class_distribution"] = {k: int(v) for k, v in df["label"].value_counts().items()}
    stats["normalization_rules_applied"] = dict(
        Counter(rule for rules in df["_norm_rules"] for rule in rules)
    )

    clean_columns = ["url", "label", "registrable_domain", "scheme",
                     "url_length", "source_row"]
    clean_df = df[clean_columns].reset_index(drop=True)

    # 8/9/10. Stratified + group-aware split (domain = group)
    train_df, val_df, test_df = stratified_group_split(
        clean_df, label_col="label", group_col="registrable_domain",
        fractions=fractions, seed=seed,
    )
    split_total = len(train_df) + len(val_df) + len(test_df)
    stats["achieved_fractions"] = {
        "train": round(len(train_df) / split_total, 4),
        "validation": round(len(val_df) / split_total, 4),
        "test": round(len(test_df) / split_total, 4),
    }
    stats["split_sizes"] = {"train": len(train_df), "validation": len(val_df), "test": len(test_df)}
    stats["split_class_distribution"] = {
        "train": {k: int(v) for k, v in train_df["label"].value_counts().items()},
        "validation": {k: int(v) for k, v in val_df["label"].value_counts().items()},
        "test": {k: int(v) for k, v in test_df["label"].value_counts().items()},
    }

    # 7. Leakage verification on the actual splits
    overlap = {
        "train_validation_domain_overlap": len(set(train_df.registrable_domain) & set(val_df.registrable_domain)),
        "train_test_domain_overlap": len(set(train_df.registrable_domain) & set(test_df.registrable_domain)),
        "val_test_domain_overlap": len(set(val_df.registrable_domain) & set(test_df.registrable_domain)),
        "train_validation_url_overlap": len(set(train_df.url) & set(val_df.url)),
        "train_test_url_overlap": len(set(train_df.url) & set(test_df.url)),
        "val_test_url_overlap": len(set(val_df.url) & set(test_df.url)),
    }
    stats["leakage_checks"] = overlap

    # Write artifacts
    output_dir.mkdir(parents=True, exist_ok=True)
    clean_df.to_csv(output_dir / "clean_dataset.csv", index=False)
    train_df.to_csv(output_dir / "train.csv", index=False)
    val_df.to_csv(output_dir / "validation.csv", index=False)
    test_df.to_csv(output_dir / "test.csv", index=False)
    with open(output_dir / "dataset_statistics.json", "w") as f:
        json.dump(stats, f, indent=2)

    return stats


def stratified_group_split(df: pd.DataFrame, label_col: str, group_col: str,
                           fractions: tuple[float, float, float], seed: int):
    """
    Domain-group-aware split that honors the requested row fractions.

    Whole groups (registrable domains) are assigned to train/validation/test so
    that no domain ever spans two splits. A seeded greedy pass walks the groups
    in random order and hands each one to the pool whose remaining per-class
    need best matches the group's class composition (needs are normalized by
    pool size and may go negative once a pool is over-allocated, pushing
    further groups elsewhere). This approximates stratification while keeping
    every domain intact — unlike fold-based tricks, it hits the requested
    fractions regardless of how group sizes are distributed.

    Falls back to a plain stratified split only when there are too few groups
    for grouping to be meaningful.
    """
    import numpy as np
    from sklearn.model_selection import train_test_split

    train_frac, val_frac, test_frac = fractions
    assert abs(train_frac + val_frac + test_frac - 1.0) < 1e-9

    n_groups = df[group_col].nunique()
    if n_groups < 10:
        train_df, temp_df = train_test_split(df, test_size=(1 - train_frac),
                                             random_state=seed, stratify=df[label_col])
        rel_val = val_frac / (val_frac + test_frac)
        val_df, test_df = train_test_split(temp_df, test_size=(1 - rel_val),
                                           random_state=seed, stratify=temp_df[label_col])
        print("[SPLIT] fallback plain stratified split (too few unique domains for grouping)")
        return (train_df.reset_index(drop=True), val_df.reset_index(drop=True),
                test_df.reset_index(drop=True))

    classes = sorted(df[label_col].unique())
    n_classes = len(classes)
    y = df[label_col].map({c: i for i, c in enumerate(classes)}).to_numpy()
    group_codes, _ = pd.factorize(df[group_col], sort=False)
    n_groups = len(_)

    class_totals = np.bincount(y, minlength=n_classes).astype(float)
    group_totals = np.bincount(group_codes, minlength=n_groups).astype(float)
    group_class_counts = np.vstack([
        np.bincount(group_codes[y == ci], minlength=n_groups) for ci in range(n_classes)
    ]).T.astype(float)

    # Per-class row targets; the test pool absorbs rounding remainders so the
    # three targets always sum to the class totals.
    targets = {
        "train": np.round(class_totals * train_frac),
        "validation": np.round(class_totals * val_frac),
    }
    targets["test"] = class_totals - targets["train"] - targets["validation"]

    pools = ("train", "validation", "test")
    need = {p: targets[p].copy() for p in pools}
    pool_index = {p: i for i, p in enumerate(pools)}

    # Assign whole groups with a seeded greedy pass (pure-python inner loop:
    # ~n_groups x n_pools x n_classes float ops, no per-row work).
    group_pool = np.empty(n_groups, dtype=np.int8)
    gcc = group_class_counts.tolist()          # per-group per-class counts
    gtot = group_totals.tolist()
    need_l = {p: need[p].tolist() for p in pools}
    tgt_sum = {p: max(float(targets[p].sum()), 1.0) for p in pools}
    pools_list = list(pools)
    rng = np.random.RandomState(seed)
    for gi in rng.permutation(n_groups):
        counts = gcc[gi]
        total_g = gtot[gi]
        comp = [c / total_g for c in counts] if total_g else [0.0] * n_classes
        best_pool, best_score = 0, -np.inf
        for pi, p in enumerate(pools_list):
            nd = need_l[p]
            s = sum(comp[k] * nd[k] for k in range(n_classes)) / tgt_sum[p]
            if s > best_score:
                best_pool, best_score = pi, s
        group_pool[gi] = best_pool
        nd = need_l[pools_list[best_pool]]
        for k in range(n_classes):
            nd[k] -= counts[k]

    # Expand per-group pools to per-row pools and gather (3 x O(n) passes).
    row_pool = group_pool[group_codes]
    out: dict[str, pd.DataFrame] = {}
    for p in pools:
        rows = np.flatnonzero(row_pool == pool_index[p])
        out[p] = df.iloc[rows].sample(frac=1, random_state=seed).reset_index(drop=True)

    sizes = {p: len(out[p]) for p in pools}
    total = sum(sizes.values())
    print(f"[SPLIT] group-aware greedy (groups={n_groups}, group_col={group_col}): "
          f"train={sizes['train']} val={sizes['validation']} test={sizes['test']} "
          f"-> fractions {{{', '.join(f'{p}: {sizes[p] / total:.3f}' for p in pools)}}} "
          f"(requested {fractions})")
    return out["train"], out["validation"], out["test"]


def print_report(stats: dict) -> None:
    print("\n" + "=" * 64)
    print(" DATASET PREPARATION REPORT")
    print("=" * 64)
    print(f" Input file            : {stats['input_file']}")
    print(f" Total records         : {stats['total_records']}")
    print(f" Invalid labels        : {stats.get('invalid_label_count', 0)}")
    print(f" Invalid URLs          : {stats.get('invalid_url_count', 0)}  {stats.get('invalid_url_reasons', {})}")
    print(f" Duplicates removed    : {stats.get('duplicate_count', 0)}")
    print(f" Label conflicts       : {stats.get('url_label_conflicts', 0)}")
    print(f" Label column conflicts: {stats.get('label_column_conflicts', 0)}")
    print(f" Cleaned records       : {stats['cleaned_records']}")
    print(f" Unique domains        : {stats['unique_domains']}")
    print(f" Domains w/ both labels: {stats.get('domains_with_both_classes', 0)}")
    print(f" Class distribution    : {stats['class_distribution']}")
    print(f" Splits                : {stats['split_sizes']}")
    print(f" Achieved fractions    : {stats.get('achieved_fractions', {})}")
    print(f" Split class balance   : {stats['split_class_distribution']}")
    print(f" Leakage checks        : {stats['leakage_checks']}")
    print("=" * 64)


def main() -> None:
    ap = argparse.ArgumentParser(description="Phishing URL dataset preparation")
    ap.add_argument("--input", default=str(REPO_ROOT / "data" / "dataset.csv"))
    ap.add_argument("--output-dir", default=str(REPO_ROOT / "data" / "processed"))
    ap.add_argument("--url-column", default=None)
    ap.add_argument("--label-column", default=None)
    ap.add_argument("--train-frac", type=float, default=0.70)
    ap.add_argument("--val-frac", type=float, default=0.15)
    ap.add_argument("--test-frac", type=float, default=0.15)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--label-map", default=None,
                    help='JSON dict of extra source-label -> target mappings')
    ap.add_argument("--numeric-label-polarity", default=None,
                    choices=["0=legitimate", "1=legitimate"],
                    help="How to interpret numeric labels 0/1 (dataset-specific; "
                         "required for numeric labels — e.g. PhiUSIIL uses 1=legitimate)")
    args = ap.parse_args()

    if abs(args.train_frac + args.val_frac + args.test_frac - 1.0) > 1e-9:
        raise SystemExit("[ERROR] --train-frac + --val-frac + --test-frac must equal 1.0")

    stats = prepare(
        input_path=Path(args.input),
        output_dir=Path(args.output_dir),
        url_column=args.url_column,
        label_column=args.label_column,
        fractions=(args.train_frac, args.val_frac, args.test_frac),
        seed=args.seed,
        extra_label_map=json.loads(args.label_map) if args.label_map else None,
        numeric_polarity=args.numeric_label_polarity,
    )
    print_report(stats)
    print(f"\n[SUCCESS] Artifacts written to {args.output_dir}/")


if __name__ == "__main__":
    main()
