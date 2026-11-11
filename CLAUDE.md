# CLAUDE.md

<!-- markdownlint-disable-next-line MD013 -->
This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Shared conventions

The portfolio's shared rules are synced into `.claude/shared/` from
`pedrobtz/packages:claude/shared/`. Never edit them here. Where this file and
a shared file disagree, this file wins for this package.

@.claude/shared/workflow.md
@.claude/shared/r-package.md
@.claude/shared/ci.md
@.claude/shared/native-code.md
@.claude/shared/correctness.md
@.claude/shared/assurance.md

## What this is

`agecrypt` is an R package implementing the
[age v1 file-encryption format](https://age-encryption.org/v1) through a
vendored copy of the 0BSD C implementation
[`agec`](https://git.sr.ht/~min/agec). It encrypts and decrypts raw vectors,
strings and files for X25519 recipients or with a scrypt passphrase, with
optional ASCII armor. It has no external C library dependencies, draws
randomness from the operating system, and interoperates with the reference
`age` implementation. Hard R dependencies are zero; `askpass` is optional and
used only for secure interactive prompting.

SSH keys, plugins, hardware recipients and post-quantum recipients require
native stanza support and are intentionally out of scope. Do not add them as
superficial R glue. The full out-of-scope list is in
[package-design.md](.agents/package-design.md#out-of-scope).

The detailed agent documentation is indexed in
[`.agents/README.md`](.agents/README.md) and outranks this file:

- [Architecture](.agents/architecture.md)
- [Package design](.agents/package-design.md)
- [Development conventions](.agents/conventions.md)
- [Testing](.agents/testing.md)
- [Release process](.agents/release-process.md)
- [Vendoring agec](.agents/vendoring-agec.md)
- [Architecture decisions](.agents/decisions/README.md)

Treat these documents and [`inst/COPYRIGHTS`](inst/COPYRIGHTS) as sources of
truth. Update them when a change makes them inaccurate. Inspect the worktree
before editing and preserve unrelated user changes
([conventions.md](.agents/conventions.md#working-tree-discipline)).

`AGENTS.md` carries the same package instructions for other coding agents.
Keep the package-specific facts in the two files consistent.

## Current state

Verified 2026-11-11: 0.1.1 is on CRAN, published 2026-10-21. `main` still
carries `Version: 0.1.1`, with no `.9000` bump yet. Planned but not built:
encrypted R-object helpers, R connection streaming and an `age_version()`
introspection function
([package-design.md](.agents/package-design.md#planned-work)).

## Versions and dependents

The current version's parent issue is
[`#9`](https://github.com/pedrobtz/agecrypt/issues/9) for `v0.1.1`, still
open although 0.1.1 is published. Sibling packages that depend on this one:
none recorded.

agecrypt has no `cran-release.yaml`, so `CRAN-SUBMISSION` is git-ignored and
the release tag, GitHub release and `.9000` bump are done by hand with
`pkg-post-cran`. This is a deviation from `.claude/shared/workflow.md`.

## Commands

Beyond the shared `devtools` commands:

```sh
Rscript -e 'pkgbuild::compile_dll()'              # rebuild src/ only
Rscript tools/gen-interop-fixtures.R              # regenerate interop fixtures
Rscript fuzz/gen-corpus.R                         # local fuzz corpus
fuzz/build.sh                                     # fuzz targets, ASan+UBSan
tools/update-vendored-agec.sh <ref> <full-sha>    # re-vendor agec
```

Regenerate the committed interoperability fixtures only when intentionally
updating them; the command requires `age` or `rage` on `PATH`.
`fuzz/gen-corpus.R` needs `dev/agec` and an installed package; see
[`fuzz/README.md`](fuzz/README.md).

## Architecture

`R/` is organised by I/O shape (`raw.R`, `text.R`, `file.R`, `passphrase.R`,
`identity.R`, `recipients.R`, `conditions.R`). `src/binding.c` holds the
`.Call` entry points registered in `src/init.c`, which call the package-owned
library core extracted from agec's CLI (`src/agec/agecore.c`). Raw-vector
operations go through negative virtual file descriptors in `src/memio.c`;
file operations stream real descriptors in 64 KiB chunks through
`src/fileio.c`. `src/platform.c` replaces upstream's randomness.
[architecture.md](.agents/architecture.md) has the details, the list of
package-owned files and the Makevars layout.

## Invariants that are easy to break

- Use age terminology and prefix public functions with `age_`.
- Keep recipient and passphrase APIs as separate functions.
- Raw APIs return raw vectors, including armored ciphertext.
- File APIs stream through native file descriptors; do not load whole files
  into R vectors.
- Every native entry point returns `(status, payload)`. C must clean up and
  return an error suffix; it must not call `Rf_error()` mid-operation.
- Keep native error suffixes aligned with the `age_error_*` R condition
  classes.
- The backend is not reentrant. Run it on R's main thread, one operation at a
  time.
- Keep identity secrets in opaque, scrubbed native allocations. Do not print,
  coerce, or expose secret bytes. Key files are read and scrubbed in C:
  reading them in R interns the secret lines in R's global string cache.
- Never silently overwrite files or remove input/output collision checks.
- Use operating-system CSPRNGs only. Compiled code must not call `exit()` or
  `abort()` or write to standard streams.
- The reference `age` or `rage` CLI is a test oracle, never a runtime backend.
- `src/Makevars` and `src/Makevars.win` list objects explicitly. Update both
  when compiled files change: their `clean` targets remove `$(OBJECTS)`, so a
  stale list leaks object files into the source tarball. Keep
  `all: $(SHLIB)` as the first rule, or `clean` becomes make's default goal,
  and preserve `-iquote` so agec's `io.h` does not shadow the Windows system
  header.

## Testing

- **Oracles.** A curated subset of the C2SP CCTV vectors in
  `tests/testthat/fixtures/vectors/`, and fixtures produced by the reference
  `age`/`rage` CLI in `tests/testthat/fixtures/interop/`, which give
  reference-to-R coverage without a CLI at test time. Passphrase
  interoperability relies on the C2SP scrypt vectors, because the reference
  CLI reads passphrases from a TTY.
- `tests/testthat/helper-age.R` provides `new_pair()` (a fresh identity and
  its recipient) and `read_vector()` (parses a CCTV-style fixture).
- `test-binding-hardening.R` calls the registered native symbols directly:
  C must never crash, leak or reach undefined behaviour on bad input, with
  the R layer as defence in depth only.
- For native changes, cover boundary sizes, authentication failures, cleanup
  paths, vectors, interoperability and fuzzing as applicable. The required
  behaviour matrix is in
  [testing.md](.agents/testing.md#required-behavior-matrix).

## Continuous integration

- `R-CMD-check.yaml` calls r-actions' `r-cmd-check.yml@v1`;
  `native-checks.yaml` calls `sanitizers`, `valgrind`, `lto`, `gctorture`,
  `rchk`, `analyzers` and `cran-special`; `coverage.yaml` calls
  `coverage.yml`, pinned to a commit.
- Both callers run quick on pull requests, full with the `full-ci` label, and
  full on every push to `main`, a deviation from `.claude/shared/ci.md`,
  whose callers run quick there. ASan and valgrind run only in the full
  profile, so a native change takes `full-ci`.
- `fuzz.yaml` is the package's own: libFuzzer under ASan+UBSan over the two
  decrypt targets, 120 s on pushes and pull requests that touch `src/` or
  `fuzz/`, 900 s weekly. It gates with a `paths` filter rather than
  `changes.yml`.
- `pkgdown.yaml` is r-lib's example workflow, not an r-actions caller.
- Valgrind suppressions in `tools/valgrind.supp` cover only leaks in
  third-party libraries loaded by the test suite, never agecrypt's own code.

## Vendored native code

Most files under `src/agec/` are upstream agec sources (0BSD), including the
transitive third-party code in `src/agec/crypto/`. Do not edit them
opportunistically. Put upstreamable fixes on `fix/*` branches in
[`pedrobtz/agec`](https://github.com/pedrobtz/agec), import an immutable
`vendor-YYYY-MM-DD` tag, and record all provenance and `[package-only]`
changes in `inst/COPYRIGHTS`. The current snapshot is `vendor-2026-09-30`
on SourceHut 1.0.0; the update procedure is in
[vendoring-agec.md](.agents/vendoring-agec.md).
