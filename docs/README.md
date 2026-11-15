# Documentation

| Document | What it covers | Kept current? |
|---|---|---|
| [cli-reference.md](cli-reference.md) | Commands and flags | Yes. `--help` is the authority if they differ |
| [architecture.md](architecture.md) | How the scanner, matcher and database fit together | No. Written before the public release; see the note at its top |
| [spec.md](spec.md) | Numbered requirements the code refers to (`FR-`, `SEC-`, `DC-`) | Partly. The identifiers are stable; some wording predates the public release |
| [roadmap.md](roadmap.md) | Phases shipped before the public release | No |
| [license-audit.md](license-audit.md) | A manual dependency licence review from August 2026 | No. `deny.toml` in CI is the current check |

## Historical material

The following were written while the project was developed privately under the name Toonable. They record decisions and are kept for context. They are **not** maintained: where they disagree with the README or the code, the code is right. Some describe features that were planned and never built, or that have since been removed.

- [design/](design/): a case study on reducing false positives.
- [security/](security/): an internal security review from August 2026. Its findings F-1, F-2 and F-5 have since been fixed.
- [superpowers/](superpowers/): design specs and implementation plans.
- [history/](history/): logs of AI-assisted development sessions.
- [agent-state/](agent-state/): the task ledger used to coordinate AI coding agents.
