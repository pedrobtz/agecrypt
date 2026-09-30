## Submission notes

This is an update of agecrypt 0.1.0 (published 2026-08-05) that fixes a silent
data-loss bug: payloads of about 8 KB were truncated on encryption or
decryption, and both operations reported success. NEWS.md tells users who
created ciphertexts of that size with 0.1.0 to verify them.

The vendored 'agec' C library is updated to upstream version 1.0.0. Provenance
and all local changes are recorded in inst/COPYRIGHTS.

The package now depends on R (>= 3.5.0), for R_UnwindProtect().

## Test environments

* local: macOS 26.6 (arm64), R 4.6.1
* GitHub Actions: macOS, Windows, and Ubuntu (R release), Ubuntu (R oldrel-1)
* R-hub containers: clang23, ubuntu-clang, ubuntu-gcc16 (with CRAN's
  `-std=gnu23 -pedantic`), nosuggests
* clang and gcc UBSan (`-fsanitize=undefined`, and `bounds-strict` on gcc),
  clang-asan and gcc-asan, valgrind, gctorture, rchk, LTO, gcc `-fanalyzer`
* CRAN's additional checks: rcnst, rlibro, vnu
* win-builder: R-devel and R-release

## R CMD check results

0 errors | 0 warnings | 0 notes

## Reverse dependencies

There are no reverse dependencies.
