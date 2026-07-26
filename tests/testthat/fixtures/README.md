# Test fixtures — provenance

## `vectors/`

A curated subset of the official **age test vectors** from the C2SP CCTV
project (the "testkit"):

- <https://age-encryption.org/testkit>
- <https://github.com/C2SP/CCTV/tree/main/age>

They were taken from the vendored `agec` test suite
(`test/vectors/dec/`, <https://git.sr.ht/~min/agec>), which mirrors the testkit.
Each file is a `key: value` metadata header, a blank line, then the raw
ciphertext body; `test-vectors.R` parses that format and uses the files as
known-answer (success) and malformed-input (failure) tests to check spec
compliance. This is a small subset covering X25519 and scrypt, success and
failure cases; the full set lives upstream.

Licence: the CCTV vectors are Copyright (c) 2022 The age Authors and are
available under your choice of Zero-Clause BSD, CC0 1.0, or the Unlicense — see
the upstream `age/README.md`. Their redistribution here is compatible with this
package's licensing (see `inst/COPYRIGHTS`).

## `interop/`

Ciphertexts and a throwaway key file generated locally with the **reference age
implementation** (FiloSottile/age v1.3.1,
<https://github.com/FiloSottile/age>). `test-interop-fixtures.R` uses them to
confirm that this package decrypts files produced by an independent
implementation (binary, ASCII-armored, and a sub-probe-size payload). `key.txt`
is a disposable identity created only for these tests and protects nothing.

`sweep/` holds reference-age ciphertexts of `strrep("A", n)` for `n` in
`{0, 5, 34, 35, 100, 70000}`, both binary (`size-<n>-bin.age`) and ASCII-armored
(`size-<n>-arm.age`), to the same `key.txt` recipient. The sizes straddle the
35-byte armor-detection probe and the 64 KiB STREAM chunk boundary (70000 spans
two chunks). The payload is reconstructed from the file name, so only the
ciphertext is committed.

These files are checked in and **the reference `age` binary is only used to
create them, never at test time** — the suite runs entirely offline, which is
required on CRAN check machines. Regenerate (or refresh against a newer `age`)
with `tools/gen-interop-fixtures.R`, which also asserts the reverse direction —
that reference `age` decrypts ciphertext this package produces — as a one-time
offline check that cannot be captured as a static fixture.
