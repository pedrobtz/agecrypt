# Release process

Use this checklist for a CRAN-facing release. Routine development does not need
every release-only check.

## 1. Confirm release metadata

- Update `DESCRIPTION` version and metadata as appropriate.
- Add user-facing changes to `NEWS.md`; do not add bullets for internal
  refactors or small documentation-only edits.
- Update `cran-comments.md` with the current submission status, environments,
  and check results.
- Verify `LICENSE`, `LICENSE.md`, and `inst/COPYRIGHTS`.
- If vendored sources changed, complete
  [vendoring-agec.md](vendoring-agec.md) first and record both the upstream base
  and immutable vendor snapshot.

## 2. Regenerate derived package files

```sh
air format .
Rscript -e 'devtools::document()'
```

Review changes to `NAMESPACE` and `man/`. If public documentation topics changed,
also check the pkgdown reference index:

```sh
Rscript -e 'pkgdown::check_pkgdown()'
```

## 3. Run local verification

```sh
Rscript -e 'pkgbuild::compile_dll()'
Rscript -e 'devtools::test()'
Rscript -e 'devtools::check()'
```

Investigate every error, warning, note, sanitizer diagnostic, or unexpected
skip. Record justified CRAN notes in `cran-comments.md`.

For protocol-facing or native parser changes, also follow the vector,
interoperability, and fuzzing checks in [testing.md](testing.md).

## 4. Run CRAN-specific extra checks

After `devtools::check()` is clean, run the repository's CRAN extra-check
workflow. Review at least:

- `DESCRIPTION` fields and spelling;
- URLs and third-party provenance;
- examples and package documentation;
- compiled-code portability and prohibited calls;
- bundled-source licensing and copyright notices;
- file writes, temporary files, and user-library behavior.

Use win-builder or the configured CI Windows job for Windows-specific native
code. The normal GitHub Actions matrix covers Windows release, macOS release,
and Ubuntu devel/release variants.

## 5. Review generated and bundled artifacts

- Confirm committed interoperability fixtures are intentional and contain no
  real secrets.
- Regenerate fixtures only when the reference outputs themselves need updating.
- Confirm the C2SP fixture provenance remains accurate in `inst/COPYRIGHTS`.
- Ensure compiled objects, shared libraries, fuzz corpora, and crash reproducers
  are not included in the source package.
- Build from a clean source tree when performing the final release check.

## 6. Final review

- Re-read root [`AGENTS.md`](../AGENTS.md) and this checklist for drift.
- Confirm CI is green on the release commit.
- Check that `cran-comments.md` matches the final check output.
- Inspect the source-package contents before submission.

Release issue creation and repository publication are separate actions. Perform
them only when explicitly requested.
