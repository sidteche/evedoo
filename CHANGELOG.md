# Changelog

Notable changes to Evedoo. The project is pre-1.0; anything may change between releases.

## Unreleased

First public version. The project was previously developed privately under the name Toonable.

### Changed

- **Renamed to Evedoo.** Commands, crate names, environment variables (`EVEDOO_*`), the scheduled-task prefix and the GUI settings folder all use the new name. The old names are not recognised.
- `evedoo audit` chooses the bundled checks for the detected Windows version when `--benchmark` is not given, and refuses to run a Windows benchmark on Linux or macOS.
- `--benchmark` names a bundled benchmark only; files are read only through `--policy`.
- The bundled audit checks are described as "derived from" the DISA STIGs, with a disclaimer and a statement of how many checks the pass rate covers.
- A mistyped `--severity`, `--min-confidence`, `--min-priority` or `--target-os` value is now an error. It used to be accepted and silently change what the report showed.
- `--rootfs` scans open the RPM database read-only and immutable.
- `cve-db-builder --enable-ubuntu` is labelled experimental and fails with an error when the feed cannot be read, instead of reporting success with no records.
- Release builds strip symbols and enable overflow checks.

### Fixed

- The RPM scanner could not read a real `rpmdb.sqlite` and returned no packages on RHEL 9 and Fedora hosts.
- A crafted ELF, Mach-O or Mac App Store receipt file could crash the scan.
- Linux distribution advisories were applied without checking the host's distribution or release, which could hide real vulnerabilities.
- The `--serve` report server accepted its access token as a substring of any request; the token is now checked exactly and is longer.
- Passwords and paths containing typographic quote characters could break out of the PowerShell commands used for remote scans and elevation.
- The Studio development server accepted requests from any web page open in the developer's browser.
- Linux and macOS builds failed on a helper used only on Windows.

### Removed

- `cve-db-builder --enable-redhat`. It never stored any data.
- The invented fleet hosts and placeholder numbers in Studio's live mode.
- `EULA.md`. Evedoo is licensed under Apache-2.0 with no additional terms; data-source terms are in `DATA_SOURCES.md`.

### Security

- Scan reports and `cve-db-builder` carry the notice required by the NVD terms of use.
- CI checks dependency licences and advisories, scans for secrets, and refuses tracked database or `.env` files.
