# Fuzzing agecrypt

Fuzz targets for the untrusted-input surface: the **decrypt** path, where the
vendored C parses attacker-controlled ciphertext (ASCII armor, base64, bech32,
header stanzas, the header MAC, and the STREAM payload).

Targets (libFuzzer `LLVMFuzzerTestOneInput` entry points):

| target | drives | fixed secret |
|---|---|---|
| `fuzz_decrypt.c` | `age_decipher()` (X25519) | a C2SP vector identity |
| `fuzz_passphrase.c` | `age_decipher_passphrase()` (scrypt) | passphrase `"password"` |

Everything runs under **AddressSanitizer + UndefinedBehaviorSanitizer**, which
are the actual bug detectors (out-of-bounds, use-after-free, integer overflow,
misaligned access); the targets just drive inputs.

## Build and run

```sh
Rscript fuzz/gen-corpus.R     # build the seed corpus (needs dev/agec vectors)
fuzz/build.sh                 # compile the targets under ASan+UBSan
```

`build.sh` uses **libFuzzer** if the toolchain has it (`-fsanitize=fuzzer`),
otherwise it links `standalone.c`, a small non-coverage-guided mutation driver
so the harness can still be smoke-tested locally (Apple clang ships the flag but
not the libFuzzer runtime).

Coverage-guided run (libFuzzer):

```sh
fuzz/fuzz_decrypt -dict=fuzz/age.dict -max_len=131072 fuzz/corpus/decrypt
fuzz/fuzz_passphrase -dict=fuzz/age.dict fuzz/corpus/passphrase
```

Standalone smoke test (no libFuzzer):

```sh
fuzz/fuzz_decrypt    fuzz/corpus/decrypt    2000000
fuzz/fuzz_passphrase fuzz/corpus/passphrase 500000
# reproducible: AGE_FUZZ_SEED=1 fuzz/fuzz_decrypt fuzz/corpus/decrypt
```

A crash aborts with an ASan/UBSan report; libFuzzer also writes a
`crash-<hash>` reproducer you can replay with `fuzz/fuzz_decrypt crash-<hash>`.

## Seed corpus

- `seeds/` — a small, committed corpus (valid files encrypted to the harness's
  fixed identity / passphrase). It has no dependencies, so CI and a fresh
  checkout can fuzz immediately; libFuzzer mutates outward from it.
- `corpus/` — a richer *local* corpus that `gen-corpus.R` builds from the
  vendored C2SP CCTV vectors (well-formed and malformed) plus generated files.
  It is git-ignored and needs `dev/agec` and an installed package.

## Continuous fuzzing

`.github/workflows/fuzz.yaml` runs both targets as coverage-guided libFuzzer
binaries under ASan+UBSan on GitHub Actions: a short bounded pass on pushes/PRs
that touch `src/` or `fuzz/`, a longer pass weekly, and on demand
(`workflow_dispatch`). A crash fails the job and uploads the reproducer, which
you can replay locally with `fuzz/fuzz_decrypt crash-decrypt-<hash>`.

To seed from the full real vector set without committing third-party files, the
workflow fetches the C2SP CCTV age testdata at runtime and extracts the
ciphertext bodies. C2SP/CCTV is untagged, so it is pinned to an immutable commit
SHA in the workflow (bump it to refresh the vectors); a fetch failure degrades
to the committed `seeds/`.

The local standalone driver is a smoke test only; coverage-guided fuzzing (which
actually explores deep states) is the CI/OSS-Fuzz job.
