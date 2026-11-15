# Cross-Asset Remediation Aggregation — Design

**Task:** `P21-N7` (Phase 21, Enterprise Accuracy & Reachability)
**Status:** SHIPPED — implemented as `evedoo/src/aggregate.rs` + `evedoo fleet report` (`P21-N7`, closed 2026-08-28). Note the CLI surface as built is `--tag`, `--limit`, and `--json`; there is no `--format` flag.
**Spec IDs introduced:** `FR-83` … `FR-88`, `DC-7`
**Depends on:** `FR-63`..`FR-66` (risk scoring), `DC-5` (`scan_findings`), `FR-65` (fleet tags)

---

## 1. Problem

Evedoo answers "what should I fix on *this* machine" — the HTML report's Top
Solutions tab groups a host's findings by software and ranks them by impact.
It cannot answer "what should I fix *across my fleet*", which is the question
an operator with more than one asset actually has. Rapid7's Remediations view
answers it as "47 assets need Chrome updated", ranked by aggregate risk.

The data is already there. `scan_findings` is keyed
`(hostname, cve_id, software_name)` and accumulates across every scan of every
host. Nothing reads it across hosts.

## 2. The constraint that shapes everything

`scan_findings` stores **no severity, CVSS, EPSS, or risk**. Its columns are
`hostname, cve_id, software_name, software_version, first_seen, last_seen,
status`. Any ranking "by aggregate risk" must therefore obtain risk from
somewhere else.

**Risk is derived at report time from the current CVE database, never stored.**

This is not merely convenient. `reassess` exists precisely because a finding's
risk changes when the CVE data changes — an EPSS score moves, a CVE joins KEV.
P20 deliberately declined to persist risk for that reason. If a fleet rollup
ranked by scores frozen at scan time, `fleet report` and `reassess` would
disagree about the same finding, and the older command would be the wrong one.

The cost is that `fleet report` requires the CVE database. That is the correct
trade: a stale ranking presented as current is worse than a command that asks
for one more argument.

- **FR-83** — The scanner SHALL produce a fleet-wide remediation rollup that
  groups stored findings across all hosts and ranks them by aggregate risk.
- **FR-84** — Risk for a rollup SHALL be computed at report time from the
  current CVE database. Risk SHALL NOT be persisted to `scan_findings`.

## 3. What gets aggregated

**Grouping is by software name, lowercased — not by name and version.**

Different hosts run different vulnerable versions of the same product, and a
single upgrade action fixes all of them. "47 assets need Chrome updated" is one
action, not one action per version observed. Each group reports the range of
versions actually seen so the operator knows what they are upgrading from.

Findings with status `Resolved` or `NoLongerApplicable` are excluded: a resolved
finding needs no remediation, and including it would inflate every rollup with
work already done.

- **FR-85** — Rollups SHALL group by lowercased software name and SHALL exclude
  findings whose status is `Resolved` or `NoLongerApplicable`.

## 4. Ranking

```
total_risk_removed = Σ risk_score(finding) for every finding this upgrade resolves
```

summed across every affected asset. Groups are ordered by that value,
descending.

This weights breadth and depth together without a hand-tuned formula: fifty
moderate findings across fifty hosts can outrank one critical finding on one
host, which is the behaviour a *fleet* view should have and the opposite of what
the per-asset `cve_count × max_cvss` formula produces.

Each finding is scored with the existing pipeline:

```rust
risk::assess(
    &vulnerability,          // from the CVE DB, at report time
    has_exploit_ref,
    risk::criticality_for(&tags_for(hostname)),   // FR-65, per host
    Reachability::Unknown,                        // FR-82 — never persisted
)
```

`criticality` is resolved **per host**, not once for the rollup: a finding on a
`prod`-tagged asset contributes more than the same finding on a `lab`-tagged
one, which is the whole point of fleet tags.

`Reachability::Unknown` is structural, not a shortcut. FR-82 forbids persisting
reachability because it is point-in-time, so a stored finding cannot carry it.
Per FR-78 the `Unknown` factor is exactly 1.0, so this neither inflates nor
deflates any rollup.

- **FR-86** — Groups SHALL be ranked by the sum of the risk scores of the
  findings the upgrade would resolve. Criticality SHALL be resolved per host
  from that host's fleet tags.

## 5. Findings that cannot be scored

A stored `cve_id` may be absent from the current CVE database — an older
database, a withdrawn CVE, or a database built from a different feed. Such a
finding cannot be scored.

**It is excluded from the rollup and the exclusion is disclosed**, e.g.
`3 findings excluded: CVE not present in the database`.

Scoring an unscoreable finding as zero would silently understate every rollup
containing one, and understating risk is the failure mode this project has
twice spent a phase eliminating. Dropping it silently is the same defect
without the arithmetic. Disclosure follows the same pattern as the reachability
coverage line: say what was not measured.

- **FR-87** — Findings whose CVE is absent from the database SHALL be excluded
  from rollups, and the excluded count SHALL be disclosed in the output.

## 6. Filtering and surface

```
evedoo fleet report [--db scan_history.db] [-d vulndb.sqlite]
                      [--tag <tag>] [--limit N] [--json]
```

`--tag` filters to assets carrying that fleet tag, reusing
`FleetManager::list_assets(Some(tag))`. Hosts present in `scan_findings` but
absent from `fleet_assets` are included when no tag filter is given (they were
scanned, so they are real) and excluded when one is, since an unregistered host
carries no tags to match.

- **FR-88** — `fleet report` SHALL support filtering by fleet tag, and SHALL
  include unregistered scanned hosts only when no tag filter is applied.

## 7. Data contract

- **DC-7** — `fleet report --json` emits an object with `generated_at`,
  `assets_covered`, `findings_excluded`, and `remediations`: an array of
  `{ software_name, affected_assets, affected_hostnames, cve_count,
  total_risk_removed, max_risk_score, kev_count, versions_seen,
  fixed_version, upgrade_command }`, ordered by `total_risk_removed`
  descending.

## 8. Module boundaries

```
evedoo/src/aggregate.rs   — the rollup type, grouping, ranking, and the
                              scan_findings read; all unit-testable
```

Changes elsewhere are minimal by design:

- `matcher/cpe.rs` — `get_cve_details` becomes `pub(crate)`. It already returns
  a complete `Vulnerability` with CVSS, EPSS, and KEV in one query; this is a
  visibility change, not new code.
- `main.rs` — the `fleet report` subcommand and its output rendering.

Per-CVE lookups are memoised in a `HashMap<String, Option<Vulnerability>>`, so
a CVE affecting forty hosts costs one query rather than forty. The `None` case
is cached too — a missing CVE must not be re-queried once per host.

## 9. Testing

The aggregation logic is exercised against a **synthetic multi-host fixture**
written into a temporary `scan_history.db`. This machine has one scanned host,
so a synthetic fleet is the only way to test cross-asset behaviour at all; the
fixture is explicit about being synthetic.

| # | Behaviour | Mutation that must fail the test |
|---|---|---|
| 1 | Findings group across hosts by name | Group by `(name, version)` — one Chrome row becomes three |
| 2 | Ranked by summed risk, not count | Rank by `cve_count` — the many-hosts-moderate group drops below the one-host-critical group |
| 3 | Resolved findings excluded | Include them — affected asset count inflates |
| 4 | Criticality resolved per host | Use a single fixed 1.0 — the `prod`-tagged host stops contributing more |
| 5 | Unscoreable CVEs excluded and counted | Score them as 0.0 — the excluded count reads 0 while the rollup silently shrinks |
| 6 | `--tag` excludes unregistered hosts | Include them — an untagged host appears under a tag filter |

## 10. Out of scope

- Writing rollups to any table; this is a read-only view.
- HTML or SBOM output for the rollup (text and JSON only).
- Scheduling, ticketing, or executing the upgrades.
- Changing the per-asset Top Solutions ranking to match this one — the two
  answer different questions and are deliberately allowed to differ.
