"""
Merge two prepared split directories into one combined, leakage-free split set.

Purpose: PhiUSIIL's legitimate class consists almost entirely of bare
homepages (no path, no query, <= ~51 chars), so models trained on it alone
learn "URL has a path/query => phishing" and false-positive on every deep
link (e.g. wikipedia.org/wiki/Phishing). The synthetic generator produces
realistic legitimate deep links (paths, queries, fragments, multi-label
subdomains) and diverse phishing attack classes. Merging rebalances the
legitimate class with the realistic URL shapes the serving path sees.

Why a full re-split: the two sources share real registrable domains
(wikipedia.org, paypal.com, ...) that each source's own split assigned to
different pools, so concatenating per-split would straddle domains across
splits. Instead ALL rows are pooled and the union is re-split with the same
domain-group-aware, stratified splitter used by prepare_dataset.py — every
domain lands in exactly one split of the combined output.

Scope (frozen):
- Consumes ONLY prepared split CSVs (url, label, registrable_domain) —
  no labels invented, no URLs synthesized.
- Splits are verified disjoint (domain + URL overlap must be 0) or it refuses
  to write.
- Deterministic for a given --seed.

Usage:
    python data/merge_datasets.py \
        --primary data/phiusiil_processed --secondary data/processed \
        --output-dir data/combined
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import pandas as pd

REPO_ROOT = Path(__file__).resolve().parent.parent
BACKEND_DIR = REPO_ROOT / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from prepare_dataset import stratified_group_split  # noqa: E402  (repo-local module)

SPLIT_FILES = ("train.csv", "validation.csv", "test.csv")
KEEP_COLUMNS = ["url", "label", "registrable_domain", "scheme", "url_length",
                "source_row", "source"]


def load_split(base: Path, name: str, source_tag: str) -> pd.DataFrame:
    df = pd.read_csv(base / name)
    missing = [c for c in ("url", "label") if c not in df.columns]
    if missing:
        raise SystemExit(f"[ERROR] {base / name} lacks required columns {missing}")
    df["label"] = df["label"].astype(str).str.strip().str.lower()
    unknown = sorted(set(df["label"].unique()) - {"legitimate", "phishing"})
    if unknown:
        raise SystemExit(f"[ERROR] {base / name} has non-binary labels {unknown}; "
                         "run prepare_dataset.py first (no labels are invented here).")
    if "registrable_domain" not in df.columns:
        from app.core.url_parser import get_registrable_domain

        df["registrable_domain"] = df["url"].map(
            lambda u: get_registrable_domain(str(u).split("://", 1)[-1].split("/", 1)[0])
        )
    for col in ("scheme", "url_length", "source_row"):
        if col not in df.columns:
            df[col] = df["url"].str.len() if col == "url_length" else -1
    df["source"] = source_tag
    return df[KEEP_COLUMNS]


def main() -> None:
    ap = argparse.ArgumentParser(description="Merge prepared phishing/legit split directories")
    ap.add_argument("--primary", default=str(REPO_ROOT / "data" / "phiusiil_processed"),
                    help="Main prepared split dir (e.g. PhiUSIIL)")
    ap.add_argument("--secondary", default=str(REPO_ROOT / "data" / "processed"),
                    help="Supplementary prepared split dir (e.g. synthetic benchmark)")
    ap.add_argument("--output-dir", default=str(REPO_ROOT / "data" / "combined"))
    ap.add_argument("--phiusiil-legit-keep", type=float, default=1.0,
                    help="Fraction of the PRIMARY source's legitimate rows to keep "
                         "(0 < f <= 1). PhiUSIIL's legitimate class is almost entirely "
                         "bare homepages; keeping every row teaches models that "
                         "path/query-bearing URLs are phishing (systematic deep-link "
                         "false positives). Subsampling rebalances the legitimate shape "
                         "distribution toward production traffic. Seeded, deterministic.")
    ap.add_argument("--train-frac", type=float, default=0.70)
    ap.add_argument("--val-frac", type=float, default=0.15)
    ap.add_argument("--test-frac", type=float, default=0.15)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    if abs(args.train_frac + args.val_frac + args.test_frac - 1.0) > 1e-9:
        raise SystemExit("[ERROR] fractions must sum to 1.0")

    primary = Path(args.primary)
    secondary = Path(args.secondary)
    for base in (primary, secondary):
        if not all((base / f).exists() for f in SPLIT_FILES):
            raise SystemExit(f"[ERROR] {base} is missing split files; "
                             "run data/prepare_dataset.py for both sources first.")

    # ---- pool every row from both sources, with provenance ------------------ #
    frames = []
    for base, tag in ((primary, "phiusiil"), (secondary, "synthetic")):
        for name in SPLIT_FILES:
            df = load_split(base, name, tag)
            frames.append(df)
            print(f"[LOAD] {base.name}/{name}: {len(df):,} rows ({tag})")
    pool = pd.concat(frames, ignore_index=True)
    dist = pool["label"].value_counts().to_dict()
    src = pool["source"].value_counts().to_dict()
    print(f"[POOL] {len(pool):,} rows  classes={dist}  sources={src}")

    # ---- optional legitimate-shape rebalance --------------------------------- #
    if args.phiusiil_legit_keep < 1.0:
        if not 0 < args.phiusiil_legit_keep <= 1:
            raise SystemExit("[ERROR] --phiusiil-legit-keep must be in (0, 1]")
        mask = (pool["source"] == "phiusiil") & (pool["label"] == "legitimate")
        keep_n = int(mask.sum() * args.phiusiil_legit_keep)
        keep_idx = pool[mask].sample(n=keep_n, random_state=args.seed).index
        pool = pd.concat([pool[~mask], pool.loc[keep_idx]], ignore_index=True)
        pool = pool.sample(frac=1.0, random_state=args.seed).reset_index(drop=True)
        dist = pool["label"].value_counts().to_dict()
        src = pool["source"].value_counts().to_dict()
        print(f"[REBALANCE] kept {keep_n:,}/{int(mask.sum()):,} primary legit rows "
              f"(frac={args.phiusiil_legit_keep}) -> {len(pool):,} rows  classes={dist}")

    # ---- one group-aware re-split over the union ----------------------------- #
    train_df, val_df, test_df = stratified_group_split(
        pool, label_col="label", group_col="registrable_domain",
        fractions=(args.train_frac, args.val_frac, args.test_frac), seed=args.seed,
    )
    merged = {"train.csv": train_df, "validation.csv": val_df, "test.csv": test_df}

    # ---- leakage verification on the COMBINED splits ------------------------- #
    def col_sets(df, col):
        return set(df[col])

    overlap = {
        f"{a}_{b}_{kind}_overlap": len(col_sets(merged[fa], kind) & col_sets(merged[fb], kind))
        for (a, fa), (b, fb) in (
            (("train", "train.csv"), ("validation", "validation.csv")),
            (("train", "train.csv"), ("test", "test.csv")),
            (("validation", "validation.csv"), ("test", "test.csv")),
        )
        for kind in ("registrable_domain", "url")
    }
    bad = {k: v for k, v in overlap.items() if v}
    if bad:
        raise SystemExit(f"[ERROR] leakage detected: {bad} — refusing to write.")

    stats = {
        "sources": {"primary": str(primary), "secondary": str(secondary)},
        "seed": args.seed,
        "fractions": {"train": args.train_frac, "validation": args.val_frac,
                      "test": args.test_frac},
        "pooled_rows": int(len(pool)),
        "pooled_class_distribution": {k: int(v) for k, v in dist.items()},
        "splits": {
            n: {"rows": int(len(df)),
                "class_distribution": {k: int(v) for k, v in df["label"].value_counts().items()},
                "by_source": {k: int(v) for k, v in df["source"].value_counts().items()}}
            for n, df in merged.items()
        },
        "leakage_checks": overlap,
    }

    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)
    for name, df in merged.items():
        df.sample(frac=1.0, random_state=args.seed).reset_index(drop=True).to_csv(out / name, index=False)
    with open(out / "dataset_statistics.json", "w") as f:
        json.dump(stats, f, indent=2)

    print(json.dumps(stats, indent=2))
    print(f"[SUCCESS] Combined splits written to {out}/")


if __name__ == "__main__":
    main()
