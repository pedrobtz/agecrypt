## Submission notes

This is an update of agecrypt 0.1.0 (published 2026-08-05). It fixes a silent
data-loss bug: payloads of about 8 KB were truncated on encryption or
decryption without an error. Users who created ciphertexts of that size with
0.1.0 should verify them, and NEWS.md says so.

The vendored 'agec' C library is updated to upstream version 1.0.0; provenance
and local changes are recorded in inst/COPYRIGHTS.

## Test environments

<!-- TODO(#18): confirm each environment below is green on the release commit. -->


* local: macOS (aarch64), R 4.6.1
* GitHub Actions: macOS, Windows, and Ubuntu (R release and oldrel-1)
* R-hub containers: clang23, ubuntu-clang, ubuntu-gcc16, nosuggests
* Sanitizers: clang and gcc UBSan, clang-asan and gcc-asan, valgrind
* rchk, LTO, and CRAN's rcnst, rlibro, and vnu checks
* win-builder: R-devel and R-release (TODO before submission)

## R CMD check results

0 errors | 0 warnings | 0 notes
