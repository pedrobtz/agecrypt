## Submission notes

This is a new submission.

* The package bundles a copy of the `agec` C implementation of the age file
  encryption format (0BSD). The exact upstream revision, the transitive
  third-party sources it contains (all public domain), and the local
  modifications made to it are recorded in `inst/COPYRIGHTS`.

* There are no external library dependencies. Cryptographic randomness is
  drawn from the operating system (`getentropy()` / `arc4random_buf()` on
  Unix and macOS, `BCryptGenRandom()` on Windows).

* The compiled code writes only to user-specified file paths, never to the
  standard streams, and does not call `exit()` or `abort()`.

## Test environments

* local: macOS Sequoia 15.7.7 (x86_64-apple-darwin20), R 4.5.2
* GitHub Actions (R-CMD-check workflow):
  * Windows (release)
  * macOS (release)
  * Ubuntu (devel, release, oldrel-1)

The native code was additionally run under AddressSanitizer and
UndefinedBehaviorSanitizer over the test suite (including the malformed C2SP
test vectors) with no diagnostics.

## R CMD check results

0 errors | 0 warnings | 1 notes

* This is a new submission.
