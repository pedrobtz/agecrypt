# AGENTS.md

Repository-wide instructions for coding agents working on `agecrypt`.

## Project

`agecrypt` is an R package implementing the
[age v1 file-encryption format](https://age-encryption.org/v1) through a
vendored copy of the 0BSD C implementation
[`agec`](https://git.sr.ht/~min/agec). It has no external C library
dependencies, draws randomness from the operating system, and interoperates
with the reference `age` implementation.

Detailed agent documentation is indexed in
[`.agents/README.md`](.agents/README.md):

- [Architecture](.agents/architecture.md)
- [Package design](.agents/package-design.md)
- [Development conventions](.agents/conventions.md)
- [Testing](.agents/testing.md)
- [Release process](.agents/release-process.md)
- [Vendoring agec](.agents/vendoring-agec.md)
- [Architecture decisions](.agents/decisions/README.md)

Treat these documents and [`inst/COPYRIGHTS`](inst/COPYRIGHTS) as sources of
truth. Update them when a change makes them inaccurate.

## Common commands

Run from the package root:

```sh
Rscript -e 'devtools::load_all()'
Rscript -e 'devtools::document()'
Rscript -e 'devtools::test()'
Rscript -e 'devtools::test(filter = "roundtrip")'
Rscript -e 'devtools::check()'
Rscript -e 'pkgbuild::compile_dll()'
air format .
```

Regenerate committed reference fixtures with
`Rscript tools/gen-interop-fixtures.R` only when intentionally updating them;
the command requires `age` or `rage` on `PATH`.

## Non-negotiable invariants

- Use age terminology and prefix public functions with `age_`.
- Keep recipient and passphrase APIs as separate functions.
- Raw APIs return raw vectors, including armored ciphertext.
- File APIs stream through native file descriptors; do not load whole files into
  R vectors.
- Every native entry point returns `(status, payload)`. C must clean up and
  return an error suffix; it must not call `Rf_error()` mid-operation.
- Keep native error suffixes aligned with the `age_error_*` R condition classes.
- The backend is not reentrant. Run it on R's main thread, one operation at a
  time.
- Keep identity secrets in opaque, scrubbed native allocations. Do not print,
  coerce, or expose secret bytes.
- Never silently overwrite files or remove input/output collision checks.
- Use operating-system CSPRNGs only. Compiled code must not call `exit()` or
  `abort()` or write to standard streams.
- The reference `age` or `rage` CLI is a test oracle, never a runtime backend.

## Vendored native code

Most files under `src/agec/` are upstream sources. Do not edit them
opportunistically. Put upstreamable fixes in `pedrobtz/agec`, import an immutable
vendor tag, and record all provenance and package-only changes in
`inst/COPYRIGHTS`.

Follow [`.agents/vendoring-agec.md`](.agents/vendoring-agec.md) for updates:

```sh
tools/update-vendored-agec.sh <ref> <full-sha>
```

`src/Makevars` and `src/Makevars.win` list objects explicitly. Update both when
compiled files change, and preserve `-iquote` so agec's `io.h` does not shadow
the Windows system header.

## Working expectations

- Inspect the worktree and preserve unrelated user changes.
- Use roxygen as the source for `man/` and `NAMESPACE`.
- Add focused testthat coverage for behavior changes.
- For native changes, cover boundary sizes, authentication failures, cleanup
  paths, vectors, interoperability, and fuzzing as applicable.
- Keep hard R dependencies at zero unless a documented design change justifies
  one.
- SSH keys, plugins, hardware recipients, and post-quantum recipients require
  native stanza support and are intentionally out of scope.

See [`.agents/conventions.md`](.agents/conventions.md) and
[`.agents/testing.md`](.agents/testing.md) for the detailed rules.
