# Development conventions

These conventions apply to changes throughout the repository. Root
[`AGENTS.md`](../AGENTS.md) contains the mandatory summary.

## R code

- Use age terminology: `recipient`, `identity`, `armor`, and `passphrase`.
- Prefix exported functions with `age_` and choose explicit verbs.
- Keep recipient and passphrase operations as separate functions.
- Use base R condition signalling and S3; do not add a hard dependency for
  behavior already implemented in base R.
- Use the base pipe `|>`, not `%>%`.
- Use `\() ...` for a single-line anonymous function and
  `function() { ... }` for longer bodies.
- Format R code with `air format .`.

## Documentation

- Write roxygen comments as the source for `man/` and `NAMESPACE`.
- Wrap roxygen comments at 80 characters.
- Run `Rscript -e 'devtools::document()'` after changing roxygen.
- Add new exported documentation topics to `_pkgdown.yml`.
- Put exact function signatures and argument behavior in roxygen documentation.
  Keep `.agents/` focused on architecture, rationale, and workflows.
- Link to an existing source of truth instead of copying it into another file.

## Native code

- Preserve the `(status, payload)` return contract described in
  [architecture.md](architecture.md#native-call-contract).
- Do not call `Rf_error()` or longjmp from the middle of a native operation.
- Clean up memory and file descriptors before returning an error status.
- Keep condition suffixes synchronized with the R condition hierarchy.
- Compiled code must not call `exit()` or `abort()` or write to standard
  streams.
- Keep cryptographic randomness in `src/platform.c` and use operating-system
  CSPRNGs only.
- The backend is not reentrant; do not introduce threaded or callback re-entry.

## Vendored sources

Treat package-owned and vendored files differently. The ownership list is in
[architecture.md](architecture.md#source-ownership-and-build-layout), and exact
provenance is in [`inst/COPYRIGHTS`](../inst/COPYRIGHTS).

- Avoid opportunistic edits to vendored agec files.
- Put generally useful fixes on focused branches in `pedrobtz/agec`, then
  import an immutable vendor tag.
- Mark deliberate package-only changes in place and record them in
  `inst/COPYRIGHTS`.
- Follow [vendoring-agec.md](vendoring-agec.md) for every vendor update.
- When compiled source files change, update the explicit `OBJECTS` lists in both
  `src/Makevars` and `src/Makevars.win`. The `clean` targets remove `$(OBJECTS)`,
  so an out-of-date list also leaks object files into the source tarball.
- Keep `all: $(SHLIB)` as the first rule in both files. It is what stops the
  `clean` target from becoming make's default goal during `R CMD SHLIB`.
- Preserve `-iquote`; replacing it with `-I` can make agec's `io.h` shadow the
  Windows system header.

## Security and file safety

- Never print, format, or coerce secret identity bytes.
- Finalizers and explicit free paths must scrub secret allocations.
- Do not silently overwrite output files.
- Preserve input/output collision checks in file operations.
- Treat ciphertext parsing and all file paths as untrusted input.
- Keep scrypt work factors bounded to prevent attacker-controlled resource use.

## Tests

- Add focused testthat coverage beside similar tests for behavior changes.
- Assert the documented condition class and relevant boundary cases.
- For native changes, cover cleanup and failure paths as well as successful
  round trips.
- Use the reference `age` or `rage` CLI only as a test oracle.
- Follow [testing.md](testing.md) for the required verification matrix.

## Dependencies and scope

- Keep hard R dependencies at zero unless a concrete requirement justifies a
  design change.
- `askpass` remains optional and is used only for secure interactive prompting.
- Do not implement unsupported recipient types as superficial R glue; they
  require native stanza support.

## Working-tree discipline

- Inspect the worktree before editing.
- Preserve unrelated user changes and untracked files.
- Do not discard, rewrite, or commit work you did not create.
- Keep edits focused on the requested task.
