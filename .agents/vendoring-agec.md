# Vendoring agec

This document explains how the original agec project, the `pedrobtz/agec`
repository, and `agecrypt` relate, and defines the update procedure for
`src/agec/`.

## Repository relationship

The canonical upstream project is
[`git.sr.ht/~min/agec`](https://git.sr.ht/~min/agec).
[`github.com/pedrobtz/agec`](https://github.com/pedrobtz/agec) is an imported
upstream-tracking mirror and staging repository:

- `master` is kept as a pristine mirror of SourceHut `master`.
- focused `fix/*` branches hold upstreamable corrections;
- `main` integrates the fixes used by this package and is the GitHub
  repository's default branch;
- immutable `vendor-YYYY-MM-DD` tags identify snapshots imported into
  `agecrypt`.

`agecrypt` copies the selected snapshot into `src/agec/`, excludes upstream CLI
and platform drivers, and applies the package-only integration changes recorded
in [`inst/COPYRIGHTS`](../inst/COPYRIGHTS).

The sibling `../agec` checkout normally uses:

```text
upstream/master       pristine SourceHut upstream
origin/master         GitHub mirror of upstream/master
fix/<specific-bug>    one focused upstreamable fix per branch
origin/main           package integration branch and repository default
vendor-YYYY-MM-DD     immutable package snapshot tag
```

## Current snapshot

```text
Repository:    git@github.com:pedrobtz/agec.git
Reference:     vendor-2026-07-09
Commit:        5c95fe5b7bc0d9888333709eb7443a3a92fe5be7
Upstream base: 19777bc35420f5a3fdc657c223cafb9f76b05754
               (SourceHut 0.1.0-15-g19777bc)
```

The snapshot is the upstream base plus the focused fix branches. The
`ageread()`/`agewrite()` routing and `scryptstanzacost()` integration are applied
inside `agecrypt` on top of that snapshot.

Keep this block synchronized with `inst/COPYRIGHTS` and
`tools/update-vendored-agec.sh`.

## Package-owned files

Do not overwrite these package-owned files during an update:

- `src/agec/agec.h`
- `src/agec/agecore.c`
- `src/agec/agecore.h`
- `src/agec/memio.h`
- `src/agec/fileio.h`

The package also owns the adapters in `src/memio.c`, `src/fileio.c`, and
`src/platform.c`.

## Update procedure

### 1. Refresh the pristine mirror

`master` must remain an exact replica of upstream. Do not commit or merge into
it. Advance it with a direct refspec:

```sh
git -C ../agec fetch upstream
git -C ../agec push origin upstream/master:master
```

Use `--force-with-lease` only if upstream rewrote history, and investigate the
rewrite before proceeding.

Rebase the focused fix branches onto the updated `master`, update `main`, and
create a new immutable `vendor-YYYY-MM-DD` tag.

### 2. Resolve the snapshot

Record the selected reference and full commit SHA:

```sh
git -C ../agec rev-parse <ref>^{commit}
```

### 3. Run the vendoring helper

From the package root:

```sh
tools/update-vendored-agec.sh <ref> <full-sha>
```

The helper defaults to `git@github.com:pedrobtz/agec.git`, verifies the exact
commit, and copies only compiled upstream sources. It excludes `agec.c`,
`agecgen.c`, `unix/`, and `plan9/`; the package provides its own library core,
randomness, memory I/O, and file helpers.

For the currently recorded snapshot, the command is:

```sh
tools/update-vendored-agec.sh vendor-2026-07-09 \
  5c95fe5b7bc0d9888333709eb7443a3a92fe5be7
```

### 4. Reapply package-only changes

Reapply only the modifications marked `[package-only]` in `inst/COPYRIGHTS`:

- route vendored reads and writes through `ageread()` and `agewrite()`;
- expose `scryptstanzacost()` so R's `log_n` reaches the backend.

Upstreamable fixes should already be present in `main` and the vendor tag.

### 5. Update provenance

Update `inst/COPYRIGHTS` with:

- the new SourceHut base commit;
- the GitHub vendor tag and full commit;
- which modifications are in the snapshot and which remain package-only;
- any changes to transitive third-party sources in `src/agec/crypto/`.

Review the imported diff:

```sh
git diff -- src/agec inst/COPYRIGHTS
```

### 6. Rebuild and verify

```sh
Rscript -e 'pkgbuild::clean_dll(); pkgbuild::compile_dll()'
Rscript -e 'devtools::test()'
Rscript -e 'devtools::check()'
```

For parser changes, also run the sanitizer/fuzzing workflow in
[testing.md](testing.md#fuzzing).
