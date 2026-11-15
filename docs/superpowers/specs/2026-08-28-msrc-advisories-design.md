# Authoritative Vendor Advisories (MSRC) — Design

**Task:** `P21-N5` (Phase 21, Enterprise Accuracy & Reachability)
**Status:** SHIPPED — implemented as `cve-db-builder/src/msrc/` + `evedoo/src/msrc_override.rs` (`P21-N5`, closed 2026-08-28). Two plan steps remain deliberately open: no sync has been run against the live API, and the suppression measurement gate was never recorded. See `docs/superpowers/plans/2026-08-28-msrc-advisories.md`.
**Spec IDs introduced:** `FR-89` … `FR-96`, `NFR-10`, `SEC-9`, `DC-8`
**Depends on:** `DC-1` (CVE database schema), `FR-63`..`FR-66` (risk scoring)

---

## 1. Problem

NVD's CPE ranges are useless for Microsoft products. Measured against the live
database:

```
microsoft:edge CVE records:            763
  ...carrying no version bounds:       723   (95%)
```

An unbounded CPE record matches *any* version, so version comparison does
almost nothing for Microsoft software. Correctness collapses onto a single
question — *is this software actually that product?* — and Evedoo answers it
from a Windows registry display name, which is a string a vendor chose for a
Programs-and-Features list, not a product identifier. The mitigations are a
curated alias table and a hand-maintained negative list of eight entries; the
existence of that list is the tell, since every entry on it is a case where a
display name lied.

MSRC publishes the authoritative answer. Verified against the live API
(`2026-Aug`, 1202 vulnerabilities, 282 products):

```
CVE-2026-42976
  KB:         5121003
  FixedBuild: 10.0.26200.9168
  ProductID:  20438
  product:    Windows 11 Version 25H2 for x64-based Systems
  CPE:        cpe:2.3:o:microsoft:windows_11_25H2:10.0.26200.9168:*:*:*:*:*:x64:*
```

Three things NVD does not give: an **exact fixed build**, an **exact KB
article**, and an **authoritative CPE per product**. `os_version.rs` already
collects `10.0.<build>.<UBR>`, which compares directly against `FixedBuild`.

The CPE bridge is verified to work. Every MSRC product string resolves in the
existing NVD dictionary after lowercasing:

| MSRC product string | rows in the NVD CPE data |
|---|---|
| `windows_11_25H2` | 2,102 |
| `windows_10_22H2` | 4,633 |
| `windows_server_2012` | 9,412 |
| `.net_framework` | 2,360 |

## 2. Licensing — the constraint that shapes delivery

The Microsoft APIs Terms of Use (last updated October 2025) contain two
operative clauses:

> **§3(b)(4)** You may NOT "Scrape, build databases or otherwise create copies
> of any data accessed or obtained using the Microsoft APIs, *except as
> necessary to enable an intended usage scenario for your Application*"

> **§3(b)(14)** You may NOT "Redistribute or resell, or sublicense access to,
> the Microsoft APIs, any data obtained using the Microsoft APIs…"

**§3(b)(14) is decisive: Evedoo must never ship a database containing
MSRC-derived data.** The existing architecture already satisfies this —
`cve-db-builder` runs on the user's machine and builds their own
`vulndb.sqlite`, and the project distributes no CVE data.

§3(b)(4)'s carve-out covers the local cache: an offline scanner caching
advisory data for local matching is squarely "an intended usage scenario",
which is what the API is published for.

**Applicability is genuinely ambiguous and is recorded as such rather than
resolved.** §1(d) enumerates the governed APIs — Graph, Azure AD, Office 365,
Outlook.com, email protocols, Intune, Project Rome — and MSRC CVRF is not among
them, while §1(b)'s broad definition arguably sweeps it in. No MSRC-specific
accompanying terms could be located. The general Microsoft website ToU is more
restrictive still ("personal and non-commercial use").

Therefore the feature is **opt-in**, so that accepting the API terms is an
affirmative act by the operator rather than a side effect of running a sync.

- **FR-89** — MSRC ingestion SHALL be off by default and require an explicit
  `--enable-msrc` flag, which SHALL print a notice identifying the Microsoft
  APIs Terms of Use before any request is made.
- **FR-94** — No build, release, or distribution of Evedoo SHALL contain
  MSRC-derived data. The data exists only in a database the operator syncs.

## 3. Ingestion

Two endpoints, neither requiring authentication:

```
GET /cvrf/v3.0/updates          → [{ ID, Alias, CurrentReleaseDate, CvrfUrl }]
GET /cvrf/v3.0/cvrf/{ID}        → one monthly CVRF document (~7 MB JSON)
```

The full archive is roughly 120 documents. Documents are revised after
publication, so `CurrentReleaseDate` is the change signal: a document is
re-fetched only when its `CurrentReleaseDate` differs from what was ingested.

- **FR-90** — The sync SHALL ingest every document the `updates` endpoint
  lists, and SHALL re-fetch a document only when its `CurrentReleaseDate`
  differs from the recorded value.
- **FR-95** — A failed or malformed document SHALL be logged and skipped
  without aborting the sync, and SHALL NOT be recorded as ingested, so the next
  run retries it. Partial progress SHALL be committed per document so an
  interrupted sync resumes rather than restarting.

## 4. What is stored

- **DC-8** — Three new tables in the CVE database:

```sql
CREATE TABLE msrc_products (
    product_id  TEXT PRIMARY KEY,   -- MSRC ProductID, e.g. "20438"
    name        TEXT NOT NULL,      -- "Windows 11 Version 25H2 for x64-based Systems"
    cpe         TEXT,               -- full CPE 2.3 string as published
    vendor      TEXT,               -- parsed from CPE, LOWERCASED
    product     TEXT                -- parsed from CPE, LOWERCASED
);

CREATE TABLE msrc_fixes (
    cve_id      TEXT NOT NULL,
    product_id  TEXT NOT NULL,
    kb_article  TEXT,               -- "5121003"
    fixed_build TEXT,               -- "10.0.26200.9168"
    document_id TEXT NOT NULL,      -- "2026-Aug"
    PRIMARY KEY (cve_id, product_id, kb_article)
);

CREATE TABLE msrc_sync (
    document_id     TEXT PRIMARY KEY,
    current_release TEXT NOT NULL,  -- drives FR-90's re-fetch decision
    ingested_at     TEXT NOT NULL
);
```

`vendor` and `product` are stored **lowercased** because MSRC publishes mixed
case (`windows_10_21H2`) while the NVD dictionary is lowercase. Normalising at
write time means the join never depends on a caller remembering to fold case.

- **FR-96** — MSRC CPE vendor and product components SHALL be lowercased on
  ingest, and the join to NVD CPE identities SHALL be case-insensitive.

## 5. Precedence — MSRC wins, but only where it speaks

For a given `(cve_id, product)` pair:

- **MSRC has a row** → MSRC decides. The installed version is compared against
  `fixed_build`; at or above it the finding is suppressed, below it the finding
  stands and carries the exact KB.
- **MSRC has no row** → the NVD/CPE match stands unchanged.

The fallback direction is the safety property. Absence of MSRC data can only
leave a finding at NVD precision; it can never delete one. A blanket "MSRC
replaces NVD for all Microsoft products" rule would suppress real findings
wherever MSRC coverage is thinner than assumed, which is the failure mode this
project has twice spent a phase eliminating.

- **FR-91** — Where MSRC has a verdict for a `(CVE, product)` pair, that
  verdict SHALL override the NVD/CPE match. Where it has none, the NVD match
  SHALL stand unchanged.
- **FR-92** — Suppression SHALL require a successful version comparison against
  `fixed_build`. An unparseable `fixed_build` or installed version SHALL leave
  the NVD finding standing rather than suppressing it.

### Measurement gate

The override changes finding counts, so its effect SHALL be measured on the
reference machine and recorded: findings before, findings after, and how many
were suppressed by an MSRC verdict. A suppression rate above roughly 50% of
Microsoft findings SHALL be investigated before the change is accepted, on the
grounds that it more likely indicates a matching bug than a genuinely
well-patched machine.

## 6. Reporting

- **FR-93** — Where an MSRC verdict produced a finding, the report SHALL name
  the exact KB article and fixed build, e.g.
  `Fix: KB5121003 (fixed in 10.0.26200.9168)`.

This flows through the existing `Remediation` fields — `kb_articles` and
`fixed_version` — so every output format carries it without new plumbing. The
existing NVD-reference KB extraction remains for non-Microsoft findings.

## 7. Security and non-functional

- **SEC-9** — The sync SHALL use HTTPS only, send no credentials or user data,
  and bound each response so a hostile or corrupted endpoint cannot exhaust
  memory. Document IDs from the `updates` listing SHALL be validated against a
  conservative pattern before being interpolated into a URL path.
- **NFR-10** — A full first sync is roughly 850 MB of downloads. It SHALL
  report progress per document, and SHALL be resumable: a re-run after
  interruption fetches only what is missing or changed.
- The scanner (`evedoo`) performs no network I/O — all fetching lives in
  `cve-db-builder`, preserving NFR-7.

## 8. Module boundaries

```
cve-db-builder/src/msrc/
  mod.rs      — sync orchestration, incremental decision, progress
  fetch.rs    — the two HTTP calls, size bounds, ID validation
  parse.rs    — CVRF document → (products, fixes); pure, fully testable
  store.rs    — the three tables and their upserts
```

`parse.rs` holds everything that can be wrong about interpreting MSRC's format
and is testable against a saved fixture with no network. `fetch.rs` is a thin
transport. In `evedoo`, the override lives beside the existing matcher rather
than inside it, so the NVD path is unchanged when MSRC data is absent.

## 9. Testing

Parsing is tested against a **trimmed real CVRF document** committed as a
fixture — real structure, a handful of vulnerabilities, no 7 MB blob in git.

| # | Behaviour | Mutation that must fail the test |
|---|---|---|
| 1 | ProductID → name + CPE, vendor/product lowercased | Store the CPE case verbatim; the NVD join stops matching |
| 2 | CVE → KB + FixedBuild extracted from Remediations | Read `SubType` instead of `Description.Value` for the KB |
| 3 | Unchanged `CurrentReleaseDate` skips re-fetch | Always re-fetch; the incremental test sees two fetches |
| 4 | A malformed document is skipped, not recorded ingested | Record it anyway; the retry test stops retrying |
| 5 | MSRC verdict suppresses only at/above `fixed_build` | Suppress unconditionally; the below-build finding vanishes |
| 6 | Absence of an MSRC row leaves the NVD finding standing | Suppress on absence; the no-data test loses its finding |
| 7 | Unparseable `fixed_build` leaves the finding standing | Treat unparseable as "patched" |

## 10. Out of scope

- Enumerating installed KB articles. The scanner does not collect them today
  ([registry.rs:154](../../evedoo/src/registry.rs) explicitly skips `KB*`
  entries), and build/UBR comparison answers the patch question without them.
- Shipping any MSRC-derived data (FR-94 forbids it).
- MSRC's Vulnerability `Threats`, `CVSSScoreSets`, and acknowledgements — NVD
  and EPSS already supply scoring.
- Non-Microsoft advisories from other vendors.
