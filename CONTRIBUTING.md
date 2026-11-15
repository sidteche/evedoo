# Contributing to Evedoo

Thanks for your interest. Evedoo is maintained by one person, so small, focused changes are the easiest to review.

## Build and test

You need a stable Rust toolchain. From the repository root:

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

On Linux and macOS add `--exclude evedoo-gui` to both commands; the GUI is Windows-only.

The Studio web UI is a separate npm project:

```bash
cd evedoo-studio
npm ci
npm run build
```

CI runs all of the above on Windows, Linux and macOS, plus a licence check and a secret scan. A pull request must pass it.

## Branches

- `dev` is where work happens. Open pull requests against `dev`.
- `main` holds stable code and is updated only by pull request from `dev`.

## What a good change looks like

- **A bug fix comes with a test that fails without it.** Say in the pull request what the test showed before the fix.
- **Clippy is clean.** Warnings are errors in CI, on all three operating systems. Code used only on one platform must not become dead code on the others.
- **No panics on untrusted input.** The parsers for binaries and package databases read files an attacker may control. Use checked arithmetic and `get(..)`, not indexing with offsets taken from the file.
- **Database queries are parameterised.** No SQL built by string concatenation.
- **Diagnostics use `tracing`** (`info!`, `debug!`, `warn!`), not the `log` crate.
- **Say what you did not test.** If you could only build on one platform, write that in the pull request.

## Dependencies and licensing

Evedoo is Apache-2.0 and its dependencies must be permissively licensed (MIT, Apache-2.0, BSD, ISC and similar). GPL, LGPL, AGPL and MPL dependencies are not accepted. The exact list is in [deny.toml](deny.toml) and is enforced by `cargo deny check` in CI.

Prefer no new dependency where a few lines of code will do.

By submitting a contribution you agree that it is licensed under Apache-2.0, the licence of this project.

## Reporting a wrong or missing finding

Matching installed software to CVEs is the hardest part of the tool, and reports of mistakes are valuable. Please include:

- the product name and exact version as the scanner shows them (`evedoo scan --show-unmatched` lists what was inventoried but not matched);
- the CVE you expected, or the one reported wrongly;
- your operating system.

Do **not** attach a full scan report or `scan_history.db`. They describe the weaknesses of your machine. Copy only the lines for the product in question.

## Security problems

Do not open a public issue for a vulnerability in Evedoo itself. See [SECURITY.md](SECURITY.md).

## Conduct

Be respectful and assume good faith. See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
