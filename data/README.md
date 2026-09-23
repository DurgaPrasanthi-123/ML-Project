# Dataset Preparation — Phishing URL Detection

Stage 1 of the pipeline: turns a raw phishing/legitimate URL dataset into
leakage-checked, domain-grouped train/validation/test splits.

**Scope guarantees**

- No ML model is trained here.
- No labels are invented: labels are only mapped from source labels via an
  explicit synonym table; unmapped values are reported and dropped.
- No synthetic URLs are added.
- Nothing is fetched from the network; the pipeline never visits any URL.
- URL normalization is conservative and preserves phishing indicators
  (path/query case, double slashes, fragments, percent-encoding are kept).

## Usage

```bash
# Default: data/dataset.csv -> data/processed/
venv/bin/python data/prepare_dataset.py --numeric-label-polarity 0=legitimate

# Explicit input/output and columns
venv/bin/python data/prepare_dataset.py \
    --input /path/to/PhiUSIIL_Phishing_URL_Dataset.csv \
    --output-dir data/phiusiil_processed \
    --url-column URL --label-column label \
    --numeric-label-polarity 1=legitimate \
    --train-frac 0.70 --val-frac 0.15 --test-frac 0.15 --seed 42
```

Numeric labels are ambiguous (PhiUSIIL uses 1=phishing; the local synthetic
benchmark uses 0=legitimate/1=phishing) — the pipeline refuses to guess and
requires `--numeric-label-polarity` (or an explicit `--label-map`).

Optional: `--label-map '{"mySource": {"weird label": "phishing"}}'` extends the
synonym table for one run. Fractions must sum to 1.0.

## Pipeline steps

1. **Load** — CSV read (falls back to `latin-1` on Unicode errors).
2. **Column identification** — URL column by hinted name (`url`, `uri`,
   `link`, …) or by a URL-likeness score over values (scheme prefixes get a
   strong bonus); label column by hinted name (`label`, `class`, …). If
   several label-like columns exist, all are scored by the fraction of values
   the synonym table can map, the best wins, and every other usable column is
   **cross-checked** against it — disagreements are reported, never silently
   resolved.
3. **Label normalization** — explicit synonyms only
   (`phishing/phish/malicious/1/… → phishing`,
   `legitimate/benign/0/… → legitimate`,
   `suspicious/unknown/2/… → suspicious` when the source really provides
   them). Unmapped values are reported and dropped.
4. **URL validation + safe normalization** — drops empties, whitespace,
   >2048-char URLs, unsupported schemes, invalid hosts; adds a scheme when
   missing, lowercases scheme/host, strips trailing host dots and explicit
   default ports. Everything else (path case, `//`, encodings) is preserved.
5. **Deduplication** — exact duplicates after `www.`-insensitive,
   trailing-slash-insensitive keying. URLs carrying **conflicting labels**
   are dropped and reported.
6. **Leakage controls** — `registrable_domain` (eTLD+1, multi-label-suffix
   aware: `a.b.co.uk → b.co.uk`) is computed for every row. Domains whose
   rows carry both classes are reported, kept, and handled by group-aware
   splitting.
7. **Split** — see below.
8. **Verification** — domain and URL overlap are measured between every pair
   of splits and written to the statistics file; all must be 0.

## Splitting: stratified where appropriate, grouped where it matters

Domains are the unit of assignment, because multiple URLs of the same domain
must never straddle train/test. A seeded greedy pass walks the registrable
domains in random order and hands each whole domain to the pool whose
remaining per-class need best matches that domain's class composition
(needs are normalized by pool size and may go negative once a pool is
over-allocated, pushing later domains elsewhere). This hits the requested
row fractions closely while keeping every domain intact:

- No domain appears in two splits.
- Per-class row targets are computed from the requested fractions; the test
  pool absorbs rounding remainders.
- Falls back to a plain stratified row split only when there are fewer than
  10 unique domains (grouping would be meaningless).

The result is deterministic for a given `--seed`.

## Outputs (`--output-dir`)

| File | Content |
|---|---|
| `clean_dataset.csv` | all cleaned rows: `url, label, registrable_domain, scheme, url_length, source_row` |
| `train.csv` / `validation.csv` / `test.csv` | the three splits, same columns |
| `dataset_statistics.json` | full run report (counts, distributions, reasons, leakage checks) |

`source_row` preserves the 1-based input-file row (+2 counting the header)
so every record can be traced back to the raw CSV.

## Run report — PhiUSIIL_Phishing_URL_Dataset.csv

235,795 rows × 56 columns; labels `1=phishing`, `0=legitimate`. The 54
pre-computed page-content columns are intentionally **not** carried into the
outputs: model features are derived from the URL alone by the shared feature
builder at training time, keeping this stage storage-only.

```
Total records         : 235795
Invalid labels        : 0
Invalid URLs          : 25   {'invalid_host': 17, 'too_long': 8}
Duplicates removed    : 2058
Label conflicts       : 0
Cleaned records       : 233712
Unique domains        : 186002
Domains w/ both labels: 240  (shared hosters; kept, split whole)
Class distribution    : {'phishing': 134849, 'legitimate': 98863}

Splits                : {'train': 163137, 'validation': 35614, 'test': 34961}
Achieved fractions    : {'train': 0.698, 'validation': 0.1524, 'test': 0.1496}
Split class balance   : train      {phishing: 94394, legitimate: 68743}
                        validation {phishing: 20227, legitimate: 15387}
                        test       {phishing: 20228, legitimate: 14733}

Leakage checks        : domain overlap train/val, train/test, val/test = 0
                        URL overlap   train/val, train/test, val/test = 0
```

Phishing rows land exactly on the 70/15/15 targets
(94,394 = 0.70 × 134,849; 20,227 + 20,228 split the remainder); legitimate
rows drift ≤ 0.4 pp because whole domains are moved atomically — the
deliberate cost of leak-free grouping.

## Downstream contract

`backend/training/train.py` prefers `data/combined/` (built by
`data/merge_datasets.py` from `data/phiusiil_processed/` +
`data/processed/`), falls back to either single source, and derives its
feature matrix through `backend/app/core/features.py` — the same builder used
at inference. This stage never computes model features itself.

## Stage 1b — merging sources (`data/merge_datasets.py`)

PhiUSIIL's legitimate class is almost entirely **bare homepages** (no path,
no query, ≤ ~51 chars). Trained on it alone, every model learns "has path ⇒
phishing" and false-positives on every deep link (`wikipedia.org/wiki/X`,
`python.org/downloads/`, …) — the dominant legitimate URL shape in real
traffic. The local synthetic generator provides realistic legitimate deep
links (paths, queries, fragments, subdomains, hyphen/numeric segments) plus
varied phishing attack classes.

```bash
# PhiUSIIL + 60k synthetic benchmark, single leakage-checked re-split
venv/bin/python data/merge_datasets.py

# Optional: subsample PhiUSIIL's bare-homepage legit rows to rebalance the
# legitimate shape distribution (0.45 ≈ legit deep-link share of ~30%)
venv/bin/python data/merge_datasets.py --phiusiil-legit-keep 0.45
```

The merge pools ALL rows from both sources (per-row `source` provenance),
then re-splits the union with the same domain-group-aware stratified splitter
as `prepare_dataset.py`. Per-source concatenation is NOT enough: shared real
domains (wikipedia.org, paypal.com, …) would straddle splits. Outputs land in
`data/combined/` (`train/validation/test.csv` + `dataset_statistics.json`),
verified domain- and URL-disjoint — the merge refuses to write on any overlap.

- No labels are invented; only prepared split CSVs are consumed.
- `--phiusiil-legit-keep` is a seeded, class-level (not URL-level) subsample
  — documented preprocessing, never a per-URL decision.
- Deterministic for a given `--seed`.
