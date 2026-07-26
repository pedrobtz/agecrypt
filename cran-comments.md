## Submission notes

This is a new submission.

* The "apparent object files/libraries" NOTE is resolved: `src/Makevars` and
  `src/Makevars.win` now define a `clean` target, so `R CMD build` also removes
  the objects compiled into the `src/agec/` subdirectories.

## R CMD check results

0 errors | 0 warnings | 1 notes


