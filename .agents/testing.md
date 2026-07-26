# Testing

`agecrypt` uses testthat for R-facing behavior, committed interoperability
fixtures for unconditional compatibility coverage, and sanitizer-backed fuzzing
for the untrusted decrypt surface.

## Common commands

Run from the package root:

```sh
Rscript -e 'devtools::load_all()'
Rscript -e 'devtools::test()'
Rscript -e 'devtools::test(filter = "roundtrip")'
Rscript -e 'pkgbuild::compile_dll()'
Rscript -e 'devtools::check()'
```

Use `devtools::test(filter = "<name>")` for a focused
`tests/testthat/test-<name>.R` file.

## Test layout

| File | Responsibility |
|---|---|
| `test-roundtrip.R` | Raw, text, and file round trips |
| `test-passphrase.R` | Scrypt operations, limits, and mode separation |
| `test-identity.R` | Identity parsing, public keys, and opaque-object behavior |
| `test-validation.R` | R argument validation |
| `test-errors.R` | Structured error classes and authentication failures |
| `test-file-safety.R` | Defaults, overwrite protection, and path collisions |
| `test-interop-fixtures.R` | Reference `age`/`rage` compatibility |
| `test-vectors.R` | Curated C2SP CCTV vectors |
| `test-native-safety.R` | Native cleanup and prohibited behavior |

## Required behavior matrix

Test applicable combinations of:

- raw, text, and file I/O;
- binary and ASCII-armored ciphertext;
- empty, short, STREAM-boundary, and multi-chunk payloads;
- one and multiple recipients;
- multiple identities where only one matches;
- recipient and passphrase encryption;
- wrong identities and passphrases;
- truncated headers and payload authentication failures;
- invalid inputs and existing output files.

Recipient ciphertext must not decrypt through passphrase functions, and
passphrase ciphertext must not decrypt through recipient functions.

## C2SP CCTV vectors

A curated subset of the age testkit is committed under
`tests/testthat/fixtures/vectors/`. Tests read ciphertext into raw vectors,
decrypt it, and compare the expected payload or error without using temporary
plaintext files.

Known-answer vectors must decrypt. Malformed inputs must raise
`age_error_decrypt`, including excessive scrypt work factors.

## Interoperability fixtures

Committed fixtures produced by the reference implementation live under
`tests/testthat/fixtures/interop/`. They provide unconditional reference-to-R
coverage without requiring a CLI at test time.

Regenerate them only when deliberately updating fixtures:

```sh
Rscript tools/gen-interop-fixtures.R
```

This requires `age` or `rage` on `PATH`. Live interoperability tests may cover
both directions when a reference binary is available, but the CLI must never
become a runtime backend.

Passphrase interoperability relies on C2SP scrypt vectors because the reference
CLI reads passphrases from a TTY.

## Fuzzing

The decrypt path processes attacker-controlled binary and armored ciphertext.
Fuzz targets under `fuzz/` exercise recipient and passphrase decryption with
AddressSanitizer and UndefinedBehaviorSanitizer.

```sh
Rscript fuzz/gen-corpus.R
fuzz/build.sh
```

See [`fuzz/README.md`](../fuzz/README.md) for corpus requirements, standalone
smoke tests, coverage-guided runs, reproducer handling, and CI behavior.

## Change-specific expectations

- R validation changes: focused testthat tests and condition snapshots where
  appropriate.
- Native parser or crypto orchestration changes: full test suite, vector tests,
  interoperability coverage, and sanitizer/fuzz verification.
- File I/O changes: overwrite, collision, cleanup, and multi-chunk coverage.
- Build-system or vendoring changes: clean DLL compilation on the local platform
  plus the full test suite; rely on CI for the supported platform matrix.

Release verification is documented in
[release-process.md](release-process.md).
