# Correlation Engine Overhaul — Phase A Design

**Date:** 2026-05-22
**Author:** Siddharth Naman
**Status:** SHIPPED (Phase 13 A–C). Retained as the design rationale for the current matcher; see `KNOWLEDGE_TRANSFER.md` §2.3 for as-built behaviour.
**Scope:** Phase A of a phased correlation-engine overhaul (Approach 3)

---

## 1. Background

Evedoo correlates detected software to CVEs through a three-layer matching
engine in `evedoo/src/matcher/cpe.rs`:

1. **Layer 1 — Curated mapping table** (`KNOWN_MAPPINGS`, 210 entries):
   token-scored lookup with publisher verification.
2. **Layer 2 — Publisher → vendor correlation** (`PUBLISHER_VENDORS`, 130 entries).
3. **Layer 3 — Product-only exact match** (fallback, Medium confidence).

Layer 1 scoring (`score_curated_match`):

```
base                = 0.70
- 0.25 per extra meaningful (non-numeric) name token beyond the pattern
+ 0.25 if publisher vendor == CPE vendor
+ 0.05 if CPE vendor string appears in the name tokens
clamp to [0.0, 1.0]
```

Thresholds: `>= 0.90` Exact, `>= 0.75` High, `>= 0.55` Medium, `< 0.60` rejected
(`CURATED_MIN_SCORE`).

### Problems identified

- **False negatives from extra tokens.** "Adobe Acrobat Reader DC" tokenises to
  `[adobe, acrobat, reader, dc]`. The only matching pattern is "Adobe Reader"
  → `[adobe, reader]`. Two extra tokens (`acrobat`, `dc`) cost −0.50, dropping
  the score to 0.50 — below the 0.60 threshold. The product is silently missed.
- **Wrong-product matches.** Loose patterns can match the wrong CPE product
  (to be enumerated and locked down via the accuracy gate).
- **Coverage gaps.** 210 curated entries leave many common applications falling
  through to lower-confidence layers or matching nothing.
- **Confidence feels unreliable.** The single hand-tuned formula doesn't always
  align with intuition.

### Constraint

Fully offline. All matching intelligence must live in the local SQLite database
and compiled tables. No network calls during scanning.

---

## 2. Phased Overhaul Context (Approach 3)

The full overhaul is decomposed into independently shippable phases. This spec
covers **Phase A only**. Later phases get their own spec → plan → implementation
cycles.

| Phase | Title | Purpose |
|---|---|---|
| **A** | Alias system + qualifier-aware scoring | Foundation; fixes FN/FP from token penalties, expands curated table |
| B | Expanded accuracy gate | Grow frozen fixture to 50+ TP / 50+ TN as a regression guard |
| C | CPE dictionary integration | Ingest ~1M NVD CPE titles for broad coverage |
| D | N-gram fuzzy index + multi-signal confidence | Core redesign: trigram matching, weighted multi-signal model, negative mappings |
| E | Explainability + auto-curation | "Why it matched" strings; propose new curated entries |

---

## 3. Phase A Design

### 3.1 Data model — grouped alias struct

Replace the flat 3-tuple `KNOWN_MAPPINGS` with a grouped struct so one CPE
identity can carry multiple display-name patterns.

```rust
struct CuratedMapping {
    /// Display-name patterns that all resolve to the same CPE identity.
    aliases: &'static [&'static str],
    vendor: &'static str,
    product: &'static str,
}

const KNOWN_MAPPINGS: &[CuratedMapping] = &[
    CuratedMapping {
        aliases: &["Adobe Acrobat Reader DC", "Adobe Reader", "Acrobat Reader"],
        vendor: "adobe",
        product: "acrobat_reader_dc",
    },
    // ...
];
```

**Impact:**
- `lookup_curated_mapping` iterates the alias list within each entry, scoring
  each alias and keeping the best.
- The `product_mappings` seeding loop in `CveMatcher::new()` inserts one row per
  alias (vendor/product repeated per alias row — unchanged table schema).
- Tests referencing the tuple shape are updated to the struct.

### 3.2 Qualifier-aware scoring

Classify each *extra* token (present in the name, absent from the pattern) into
three buckets with different penalties:

| Bucket | Examples | Penalty |
|---|---|---|
| **Core** | `launcher`, `acrobat`, `server`, `studio` | −0.25 (unchanged) |
| **Qualifier** | `pro`, `professional`, `enterprise`, `standard`, `home`, `ultimate`, `premium`, `community`, `lts`, `dc`, `edition` | −0.05 |
| **Noise** | `redistributable`, `runtime`, `update`, `installer`, `setup`, `version`, `build` | 0.0 |

Numeric-only tokens remain ignored (current behaviour).

The −0.25 core penalty is retained because it is the precision mechanism that
correctly rejects e.g. "Python Launcher" against the `python` pattern.

**Implementation:** add a `classify_token(&str) -> TokenClass` helper plus
`QUALIFIERS` and `NOISE` const slices in `normalize/tokens.rs`, alongside the
existing `STOPWORDS`. The scorer in `cpe.rs` consumes `classify_token` so the
classification has one source of truth for later phases.

### 3.3 Worked correctness check

With aliases + the new penalties, publisher = Adobe (resolves to `adobe`):

| Name | Pattern | Subset? | Extra tokens | Score | Result |
|---|---|---|---|---|---|
| Adobe Acrobat Reader DC | Adobe Acrobat Reader DC (alias) | yes | none | 0.70 +0.25 +0.05 = **1.00** | `acrobat_reader_dc` ✓ |
| Adobe Acrobat Reader DC | Adobe Acrobat | yes | `reader` (core −0.25), `dc` (qual −0.05) | 0.70 −0.30 +0.25 +0.05 = **0.70** | loses to alias 1.00 ✓ |
| Adobe Acrobat | Adobe Acrobat Reader DC (alias) | no (`reader`,`dc` absent) | — | 0.00 | stays `acrobat` ✓ |
| Python Launcher | Python | yes | `launcher` (core −0.25) | 0.70 −0.25 +0.05 = **0.50** | rejected (< 0.60) ✓ |

No cross-contamination between Acrobat and Acrobat Reader DC; existing
precision behaviour preserved.

### 3.4 Curated table expansion (210 → 500+)

Data work, two kinds of additions:
- **New products** not currently mapped (coverage gap).
- **Aliases** for existing entries (precision / false-negative gap).

Categories: enterprise/security agents (EDR, VPN, backup, password managers),
dev tools (JetBrains IDEs, language runtimes, container/k8s tooling, DB
clients), Adobe Creative Cloud suite with DC/Pro/CC aliases, Microsoft Office
per-app + 365 + Server + VC++ year aliases, common consumer apps (media
players, comms, browsers with edition aliases).

Every new vendor/product pair is verified to exist against the live
`cpe_matches` table in the user's database during implementation (a quick
verification query, not guesswork).

### 3.5 Tests

- **`classify_token` unit tests** — each qualifier/noise/core word lands in the
  correct bucket.
- **Scoring regression tests** — Acrobat DC resolves to `acrobat_reader_dc`;
  Pro/Enterprise variants resolve to the base product; "Python Launcher"
  rejection still holds.
- **Alias lookup tests** — multiple aliases resolve to one identity; the
  most-specific alias wins on score.
- **Accuracy-gate seed** — add identified wrong-product false positives as
  explicit true-negative fixtures (bridge into Phase B).

### Acceptance criteria

- The existing 169 tests stay green; new Phase A tests pass.
- `cargo clippy --workspace --all-targets -- -D warnings` clean.
- A re-scan resolves "Adobe Acrobat Reader DC" to a finding with High/Exact
  confidence.
- Curated table count >= 500 entries (including aliases).

---

## 4. Out of scope (Phase A)

- CPE dictionary ingestion (Phase C).
- N-gram fuzzy matching and the multi-signal confidence model (Phase D).
- Match explanations and auto-curation (Phase E).
- Any change to the offline-only constraint.
