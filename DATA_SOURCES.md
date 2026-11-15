# Data sources

Evedoo's code is Apache-2.0. The vulnerability data it downloads belongs to its publishers and is governed by their terms. This page lists every source `cve-db-builder` fetches, when it is fetched, and the attribution each asks for.

This is a description of what the tool does, not legal advice. If you redistribute a database built by `cve-db-builder`, check each publisher's current terms yourself.

## Fetched by default

| Source | What it provides | Publisher | Notes |
|---|---|---|---|
| NVD CVE data, via the [FKIE-CAD mirror](https://github.com/fkie-cad/nvd-json-data-feeds) | CVE records and the product versions they affect | NIST (data), Fraunhofer FKIE (mirror) | No API key. Each download is checked against the mirror's SHA-256 file |
| [NVD API](https://nvd.nist.gov/developers) | The same CVE data directly (`--no-mirror`), and the CPE product dictionary | NIST | An API key is optional and raises the rate limit |
| [EPSS](https://www.first.org/epss/) | Probability that a CVE will be exploited | FIRST.org | Refreshed daily by the publisher |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | CVEs known to be exploited | CISA | |

**NVD notice:** This product uses the NVD API but is not endorsed or certified by the NVD.

## Opt-in

These are off unless you pass the flag. The data is fetched for use on your own machine.

| Flag | Source | Publisher | Notes |
|---|---|---|---|
| `--enable-msrc` | Microsoft Security Response Center update data | Microsoft | Subject to the Microsoft APIs Terms of Use. Do not redistribute a database that contains it |
| `--enable-ubuntu` | Ubuntu security notices | Canonical | Experimental. Published under Canonical's terms; do not redistribute a database that contains it |

`cve-db-builder` prints the relevant terms notice when one of these flags is used.

## Not implemented

Earlier documents in this repository described Red Hat, Debian, SUSE, Alpine, GitHub Advisory and Homebrew data as sources. None of them is fetched by the current code.

## Bundled content

The configuration-audit checks in `evedoo/src/audit/builtin.rs` are written by the Evedoo contributors and licensed Apache-2.0 with the rest of the code. They are derived from, and cross-reference, the DISA Security Technical Implementation Guides and NIST SP 800-53 control identifiers. They are not copies of those documents. Evedoo is not an official DISA product and is not endorsed by DISA or the U.S. Department of Defense.
