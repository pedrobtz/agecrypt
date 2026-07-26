# Agent documentation

Root [`AGENTS.md`](../AGENTS.md) is the authoritative entry point for coding
agents. This directory contains the detailed references linked from it.

## Document map

| Document | Read when |
|---|---|
| [architecture.md](architecture.md) | Changing the R/C boundary, I/O, identity storage, native build, or concurrency behavior |
| [package-design.md](package-design.md) | Changing the public API, supported features, defaults, or roadmap |
| [conventions.md](conventions.md) | Editing R or C code, documentation, build files, or vendored sources |
| [testing.md](testing.md) | Adding coverage, regenerating fixtures, testing interoperability, or fuzzing |
| [release-process.md](release-process.md) | Preparing checks, CRAN metadata, or a release |
| [vendoring-agec.md](vendoring-agec.md) | Updating `src/agec/` or working with the `pedrobtz/agec` mirror |
| [decisions/](decisions/README.md) | Reviewing the rationale behind durable architecture and API choices |

## Maintenance rules

- Put mandatory, frequently needed instructions in root `AGENTS.md`.
- Put detailed explanations in exactly one document here and link to them.
- Update the relevant document in the same change when implementation or policy
  makes it inaccurate.
- Record a new ADR for a durable choice that reverses or materially extends an
  existing decision. Do not rewrite an accepted ADR as though the old decision
  never existed.
- Keep generated API reference material in roxygen and `man/`, not here.
